//! Health-ranked endpoint pool: the fan-out over a chain's HTTP endpoints.
//!
//! This replaces alloy's `FallbackLayer`, which ranked endpoints only by
//! its own call history. An endpoint it had never called scored the same
//! as one that had only failed, and a stable sort kept configured order on
//! ties, so endpoints after the first `active_transport_count` were never
//! called (#527).
//!
//! Each call ranks endpoints with [`HealthRegistry::selection_order`],
//! which the probe loop and live call outcomes both feed. The top
//! [`RACE_WIDTH`] endpoints are raced in parallel and the first success
//! wins, as before. What happens when that whole window fails depends on
//! the request:
//!
//! - **Reads** move on to the next window of the ranking, until an
//!   endpoint answers or every configured endpoint has failed.
//! - **Submissions** (any method named `<namespace>_send…`, such as
//!   `eth_sendRawTransaction`) stay in the first window. They are offered
//!   to at most [`RACE_WIDTH`] endpoints, the same count as before this
//!   pool existed, so a failed broadcast is never re-sent to further
//!   endpoints. Reconciliation after an ambiguous send stays the caller's
//!   job. Methods whose parallel results can disagree
//!   (`eth_sendRawTransactionSync`, `eth_sendTransactionSync`) are tried
//!   one endpoint at a time within that window, as alloy did.
//!
//! A batch containing any submission is dispatched as a submission.
//!
//! A response that carries a JSON-RPC error payload is a successful
//! transport round trip: it is returned as is and counts as a success for
//! endpoint health. Only transport errors (connection failures, HTTP error
//! statuses, exhausted retries) count as endpoint failures.

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::transports::{BoxTransport, TransportError, TransportErrorKind, TransportFut};
use futures::stream::{FuturesUnordered, StreamExt};
use tower::Service;
use tracing::{debug, warn};

use crate::health::{CooldownDecision, HealthRegistry};

/// Endpoints raced in parallel per window. Two balances tail latency
/// against duplicate load on public endpoints, and is the count every
/// submission was already offered to.
pub(crate) const RACE_WIDTH: usize = 2;

/// Methods that must be tried one endpoint at a time because parallel
/// attempts can return different results (for example a receipt from one
/// endpoint and "already known" from another). Mirrors alloy's default
/// sequential set.
const SEQUENTIAL_METHODS: [&str; 2] = ["eth_sendRawTransactionSync", "eth_sendTransactionSync"];

/// How a request may be spread across endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    /// Race each window in turn until an endpoint answers.
    Read,
    /// Race the first window only.
    Submission,
    /// Try the first window's endpoints one at a time.
    SequentialSubmission,
}

impl Dispatch {
    fn of(req: &RequestPacket) -> Self {
        let mut dispatch = Self::Read;
        for method in req.method_names() {
            if SEQUENTIAL_METHODS.contains(&method) {
                return Self::SequentialSubmission;
            }
            if is_submission(method) {
                dispatch = Self::Submission;
            }
        }
        dispatch
    }
}

/// True for methods that submit something to the network rather than read
/// from it: `eth_sendRawTransaction`, `eth_sendBundle`,
/// `personal_sendTransaction` and the like.
fn is_submission(method: &str) -> bool {
    method
        .split_once('_')
        .is_some_and(|(_, name)| name.starts_with("send"))
}

/// One HTTP endpoint in the pool. Its position matches its index in the
/// [`HealthRegistry`].
pub(crate) struct PoolEndpoint {
    /// Redacted URL, safe to log.
    pub(crate) label: String,
    pub(crate) transport: BoxTransport,
}

/// The fan-out over a chain's HTTP endpoints. Cheap to clone.
#[derive(Clone)]
pub(crate) struct EndpointPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    chain: String,
    endpoints: Vec<PoolEndpoint>,
    health: HealthRegistry,
    race_width: usize,
}

impl EndpointPool {
    /// Build a pool over `endpoints`. `health` must track the same
    /// endpoints in the same order.
    pub(crate) fn new(chain: String, endpoints: Vec<PoolEndpoint>, health: HealthRegistry) -> Self {
        debug_assert_eq!(endpoints.len(), health.len());
        let race_width = RACE_WIDTH.min(endpoints.len()).max(1);
        Self {
            inner: Arc::new(PoolInner {
                chain,
                endpoints,
                health,
                race_width,
            }),
        }
    }

    /// Endpoints raced in parallel per window.
    pub(crate) fn race_width(&self) -> usize {
        self.inner.race_width
    }
}

impl PoolInner {
    async fn dispatch(&self, req: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let order: Vec<usize> = self
            .health
            .selection_order()
            .into_iter()
            .filter(|&idx| idx < self.endpoints.len())
            .collect();
        let dispatch = Dispatch::of(&req);
        let windows: Vec<&[usize]> = match dispatch {
            Dispatch::Read => order.chunks(self.race_width).collect(),
            Dispatch::Submission | Dispatch::SequentialSubmission => {
                order.chunks(self.race_width).take(1).collect()
            }
        };

        let mut last_error = None;
        for (n, window) in windows.iter().enumerate() {
            if n > 0 {
                debug!(
                    chain = %self.chain,
                    endpoints = ?window,
                    "rpc.pool.failover"
                );
            }
            let result = match dispatch {
                Dispatch::SequentialSubmission => self.sequential(window, &req).await,
                Dispatch::Read | Dispatch::Submission => self.race(window, &req).await,
            };
            match result {
                Ok(response) => return Ok(response),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| TransportErrorKind::custom_str("no RPC endpoints available")))
    }

    /// Call every endpoint in `window` in parallel and return the first
    /// success. Calls still in flight when one succeeds are dropped.
    async fn race(
        &self,
        window: &[usize],
        req: &RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        let mut in_flight: FuturesUnordered<_> = window
            .iter()
            .map(|&idx| self.call_endpoint(idx, req.clone()))
            .collect();
        let mut last_error = None;
        while let Some(result) = in_flight.next().await {
            match result {
                Ok(response) => return Ok(response),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| TransportErrorKind::custom_str("no RPC endpoints available")))
    }

    /// Call the endpoints in `window` one at a time and return the first
    /// success.
    async fn sequential(
        &self,
        window: &[usize],
        req: &RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        let mut last_error = None;
        for &idx in window {
            match self.call_endpoint(idx, req.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| TransportErrorKind::custom_str("no RPC endpoints available")))
    }

    /// Hand `req` to one endpoint now, and return a future that records
    /// the outcome in the health registry when it resolves. The request is
    /// handed over before the future is first polled, so every endpoint in
    /// a race is offered the request even if another answers first.
    fn call_endpoint(
        &self,
        idx: usize,
        req: RequestPacket,
    ) -> impl Future<Output = Result<ResponsePacket, TransportError>> + '_ {
        let endpoint = &self.endpoints[idx];
        let mut transport = endpoint.transport.clone();
        let started = Instant::now();
        let call = transport.call(req);
        async move {
            let result = call.await;
            match &result {
                Ok(_) => self.health.record_success(idx, started.elapsed(), None),
                Err(err) => {
                    let decision = self.health.record_failure(idx, true, None);
                    debug!(
                        chain = %self.chain,
                        idx,
                        url = %endpoint.label,
                        error = %err,
                        "rpc.pool.endpoint_failed"
                    );
                    emit_cooldown_event(&self.chain, idx, &endpoint.label, decision);
                }
            }
            result
        }
    }
}

impl Service<RequestPacket> for EndpointPool {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.dispatch(req).await })
    }
}

/// Log a cooldown armed by a probe or a live call. `label` must already be
/// redacted.
pub(crate) fn emit_cooldown_event(
    chain: &str,
    idx: usize,
    label: &str,
    decision: CooldownDecision,
) {
    match decision {
        CooldownDecision::None => {}
        CooldownDecision::Fresh(d) => {
            warn!(
                chain = %chain,
                idx,
                url = %label,
                cooldown_secs = d.as_secs(),
                "rpc.health.cooldown_set"
            );
        }
        CooldownDecision::Chronic(d) => {
            warn!(
                chain = %chain,
                idx,
                url = %label,
                cooldown_secs = d.as_secs(),
                "rpc.health.chronic_failer_escalated"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use alloy::rpc::json_rpc::{Id, Request, Response, ResponsePayload};

    /// A transport that counts its calls and either answers `"0x1"` or
    /// fails with a transport error.
    #[derive(Clone)]
    struct MockEndpoint {
        healthy: bool,
        calls: Arc<AtomicUsize>,
    }

    impl MockEndpoint {
        fn new(healthy: bool) -> Self {
            Self {
                healthy,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Service<RequestPacket> for MockEndpoint {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: RequestPacket) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let healthy = self.healthy;
            Box::pin(async move {
                if !healthy {
                    return Err(TransportErrorKind::custom_str("connection refused"));
                }
                let id = req
                    .requests()
                    .first()
                    .map(|r| r.id().clone())
                    .unwrap_or(Id::None);
                let payload = serde_json::value::to_raw_value("0x1").unwrap();
                Ok(ResponsePacket::Single(Response {
                    id,
                    payload: ResponsePayload::Success(payload),
                }))
            })
        }
    }

    fn pool_of(mocks: &[MockEndpoint]) -> (EndpointPool, HealthRegistry) {
        let health = HealthRegistry::new((0..mocks.len()).map(|i| format!("http://mock/{i}")));
        let endpoints = mocks
            .iter()
            .enumerate()
            .map(|(i, m)| PoolEndpoint {
                label: format!("http://mock/{i}"),
                transport: BoxTransport::new(m.clone()),
            })
            .collect();
        (
            EndpointPool::new("test".into(), endpoints, health.clone()),
            health,
        )
    }

    fn request(method: &'static str) -> RequestPacket {
        RequestPacket::Single(Request::new(method, Id::Number(1), ()).serialize().unwrap())
    }

    async fn send(
        pool: &EndpointPool,
        method: &'static str,
    ) -> Result<ResponsePacket, TransportError> {
        pool.clone().call(request(method)).await
    }

    #[test]
    fn submissions_are_recognised_by_method_name() {
        assert_eq!(Dispatch::of(&request("eth_blockNumber")), Dispatch::Read);
        assert_eq!(Dispatch::of(&request("eth_call")), Dispatch::Read);
        assert_eq!(
            Dispatch::of(&request("eth_sendRawTransaction")),
            Dispatch::Submission
        );
        assert_eq!(
            Dispatch::of(&request("eth_sendBundle")),
            Dispatch::Submission
        );
        assert_eq!(
            Dispatch::of(&request("eth_sendRawTransactionSync")),
            Dispatch::SequentialSubmission
        );
        let batch: RequestPacket = [
            Request::new("eth_blockNumber", Id::Number(1), ())
                .serialize()
                .unwrap(),
            Request::new("eth_sendRawTransaction", Id::Number(2), ())
                .serialize()
                .unwrap(),
        ]
        .into_iter()
        .collect();
        assert_eq!(Dispatch::of(&batch), Dispatch::Submission);
    }

    #[tokio::test]
    async fn read_reaches_third_endpoint_when_first_two_fail() {
        // Regression for #527.
        let mocks = [
            MockEndpoint::new(false),
            MockEndpoint::new(false),
            MockEndpoint::new(true),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_chainId")
            .await
            .expect("third endpoint answers");
        assert_eq!(
            mocks.iter().map(MockEndpoint::calls).collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
    }

    #[tokio::test]
    async fn later_reads_start_from_the_endpoint_that_answered() {
        let mocks = [
            MockEndpoint::new(false),
            MockEndpoint::new(false),
            MockEndpoint::new(true),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_chainId").await.unwrap();
        send(&pool, "eth_chainId").await.unwrap();
        // The second read races endpoint 2, now proven, with the first
        // failing endpoint (0), and never reaches endpoint 1.
        assert_eq!(
            mocks.iter().map(MockEndpoint::calls).collect::<Vec<_>>(),
            vec![2, 1, 2]
        );
    }

    #[tokio::test]
    async fn read_fails_only_after_every_endpoint_fails() {
        let mocks = [
            MockEndpoint::new(false),
            MockEndpoint::new(false),
            MockEndpoint::new(false),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_chainId")
            .await
            .expect_err("no endpoint answers");
        assert_eq!(
            mocks.iter().map(MockEndpoint::calls).collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
    }

    #[tokio::test]
    async fn submission_is_not_offered_past_the_race_width() {
        let mocks = [
            MockEndpoint::new(false),
            MockEndpoint::new(false),
            MockEndpoint::new(true),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_sendRawTransaction")
            .await
            .expect_err("the first window failed and submissions stop there");
        assert_eq!(
            mocks.iter().map(MockEndpoint::calls).collect::<Vec<_>>(),
            vec![1, 1, 0]
        );
    }

    #[tokio::test]
    async fn sequential_submission_stops_at_the_first_success() {
        let mocks = [
            MockEndpoint::new(true),
            MockEndpoint::new(true),
            MockEndpoint::new(true),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_sendRawTransactionSync").await.unwrap();
        assert_eq!(
            mocks.iter().map(MockEndpoint::calls).collect::<Vec<_>>(),
            vec![1, 0, 0]
        );
    }

    #[tokio::test]
    async fn healthy_later_endpoint_is_selected_on_its_measurements() {
        let mocks = [
            MockEndpoint::new(true),
            MockEndpoint::new(true),
            MockEndpoint::new(true),
        ];
        let (pool, health) = pool_of(&mocks);
        // Probe results: endpoint 2 is the fastest, endpoint 1 the slowest.
        health.record_success(0, Duration::from_millis(900), None);
        health.record_success(1, Duration::from_millis(1_500), None);
        health.record_success(2, Duration::from_millis(50), None);
        send(&pool, "eth_chainId").await.unwrap();
        assert_eq!(mocks[1].calls(), 0, "the slowest endpoint is not raced");
        assert_eq!(mocks[2].calls(), 1, "the fastest endpoint is raced");
    }

    #[tokio::test]
    async fn cooled_down_endpoint_is_tried_after_healthy_ones() {
        let mocks = [
            MockEndpoint::new(true),
            MockEndpoint::new(true),
            MockEndpoint::new(true),
        ];
        let (pool, health) = pool_of(&mocks);
        for _ in 0..5 {
            health.record_failure(0, true, None);
        }
        assert_eq!(health.cooled_down_indices(), vec![0]);
        send(&pool, "eth_chainId").await.unwrap();
        assert_eq!(mocks[0].calls(), 0, "the cooled-down endpoint waits");
    }

    #[tokio::test]
    async fn single_endpoint_pool_races_alone() {
        let mocks = [MockEndpoint::new(true)];
        let (pool, _) = pool_of(&mocks);
        assert_eq!(pool.race_width(), 1);
        send(&pool, "eth_chainId").await.unwrap();
        assert_eq!(mocks[0].calls(), 1);
    }
}
