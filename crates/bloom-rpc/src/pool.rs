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
//! [`RACE_WIDTH`] endpoints are raced in parallel, as before. What happens
//! when that whole window fails depends on the request:
//!
//! - **Reads** move on to the next window of the ranking, until an
//!   endpoint answers or every configured endpoint has failed. An
//!   endpoint that never answers fails when its HTTP request times out
//!   (`REQUEST_TIMEOUT` in `transport.rs`), so it can delay a read but
//!   not stall it.
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
//! An endpoint that replies with a JSON-RPC error (a revert, "nonce too
//! low", an unknown block) has answered. The retry layer below the pool
//! passes that reply up as a response, as if it were a result, so the pool
//! turns it into `TransportError::ErrorResp`, as alloy's RPC client reports
//! it to the caller anyway. The pool treats it as the endpoint's answer,
//! not as a failure:
//!
//! - It is not recorded in endpoint health, for or against. A revert says
//!   nothing about the endpoint, while a reply such as "invalid project
//!   id" says the endpoint is unusable; the probe loop, which sends only
//!   `eth_blockNumber`, tells the two apart. Counting every reply as a
//!   success would rank an endpoint that answers everything with an error
//!   above working ones.
//! - A read takes the first answer in its race, a result or an error
//!   reply, as alloy's `FallbackLayer` does, and that answer ends the read.
//!   Waiting past an error reply for a result would hold every revert until
//!   the slowest endpoint in the window answered or timed out, and would
//!   let a lagging node's result override the revert an up-to-date node
//!   reported. Moving on would only send the same request to more
//!   endpoints.
//! - So a read reports an error reply rather than a transport error from
//!   the same window: a revert the node sends as a JSON-RPC reply is never
//!   reported as an unreachable endpoint. Callers rely on this: a
//!   pre-broadcast simulation reads a transport error as "simulation
//!   unavailable" and lets the transaction through. A JSON-RPC error sent
//!   with a 4xx HTTP status, or a revert sent with any status, is an error
//!   reply too (see `EndpointHttp`).
//! - A submission waits for every endpoint in its window, since one may
//!   return the transaction hash while another refuses. If none does, it
//!   reports, in this order of preference: a reply saying the node already
//!   has the transaction, which proves it was accepted; a transport error,
//!   since the endpoint that failed may have accepted the transaction
//!   before its reply was lost, so the outcome is unknown and a refusal
//!   from the other endpoint must not make it look definite; and only then
//!   a refusal. Callers finalize an already known send, reconcile an
//!   unknown one, and set aside an attempt that a node refused.
//!
//! Only transport errors (connection failures, timeouts, HTTP error
//! statuses without a JSON-RPC answer in the body, retries exhausted on
//! rate limits) count against an endpoint and move a read on.

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::transports::{BoxTransport, TransportError, TransportErrorKind, TransportFut};
use futures::stream::{FuturesUnordered, StreamExt};
use tower::Service;
use tracing::{debug, warn};

use crate::health::{CooldownDecision, HealthRegistry};
use crate::reply::is_already_known;

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

/// True when the endpoint answered with a JSON-RPC error rather than
/// failing to answer at all.
fn is_error_reply(err: &TransportError) -> bool {
    err.as_error_resp().is_some()
}

/// A single response carrying a JSON-RPC error, as
/// `TransportError::ErrorResp`. alloy's retry layer passes such a response
/// up as a success, and without this the pool would take a revert or a
/// refusal for a result: a race would end on it as if it had succeeded,
/// and the endpoint would be recorded as working. A batch is left as it
/// is, so each of its requests gets its own response.
fn error_reply_as_err(response: ResponsePacket) -> Result<ResponsePacket, TransportError> {
    match &response {
        ResponsePacket::Single(_) => match response.as_error() {
            Some(payload) => Err(TransportError::ErrorResp(payload.clone())),
            None => Ok(response),
        },
        ResponsePacket::Batch(_) => Ok(response),
    }
}

/// The errors one window produced, kept so the right one is returned.
#[derive(Default)]
struct WindowOutcome {
    /// The first error reply, other than "already known".
    error_reply: Option<TransportError>,
    /// A reply saying the node already has the transaction.
    already_known: Option<TransportError>,
    transport_error: Option<TransportError>,
}

impl WindowOutcome {
    fn record(&mut self, err: TransportError) {
        match err.as_error_resp() {
            None => self.transport_error = Some(err),
            Some(payload) if is_already_known(payload) => {
                self.already_known.get_or_insert(err);
            }
            Some(_) => {
                self.error_reply.get_or_insert(err);
            }
        }
    }

    /// The error that reports the window. A read reports an error reply,
    /// since that is the answer to what it asked. A submission reports
    /// "already known" if it got it, since the transaction was accepted;
    /// then a transport error, since that endpoint may have accepted the
    /// transaction and the outcome is unknown; then a refusal.
    fn into_error(self, dispatch: Dispatch) -> TransportError {
        let reported = match dispatch {
            Dispatch::Read => self
                .error_reply
                .or(self.already_known)
                .or(self.transport_error),
            Dispatch::Submission | Dispatch::SequentialSubmission => self
                .already_known
                .or(self.transport_error)
                .or(self.error_reply),
        };
        reported.unwrap_or_else(|| TransportErrorKind::custom_str("no RPC endpoints available"))
    }
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
                Dispatch::Read | Dispatch::Submission => self.race(window, &req, dispatch).await,
            };
            match result {
                Ok(response) => return Ok(response),
                // An endpoint answered. Asking more endpoints would only
                // repeat the request, which alloy never did either.
                Err(err) if is_error_reply(&err) => return Err(err),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| TransportErrorKind::custom_str("no RPC endpoints available")))
    }

    /// Call every endpoint in `window` in parallel. A read returns the
    /// first answer, a result or an error reply. A submission returns the
    /// first success, since another endpoint may still return the hash
    /// after one refuses. Calls still in flight when the race ends are
    /// dropped. If no endpoint answers (or, for a submission, none
    /// succeeds), `dispatch` decides which error reports the window (see
    /// [`WindowOutcome::into_error`]).
    async fn race(
        &self,
        window: &[usize],
        req: &RequestPacket,
        dispatch: Dispatch,
    ) -> Result<ResponsePacket, TransportError> {
        let mut in_flight: FuturesUnordered<_> = window
            .iter()
            .map(|&idx| self.call_endpoint(idx, req.clone()))
            .collect();
        let mut outcome = WindowOutcome::default();
        while let Some(result) = in_flight.next().await {
            match result {
                Ok(response) => return Ok(response),
                Err(err) if dispatch == Dispatch::Read && is_error_reply(&err) => return Err(err),
                Err(err) => outcome.record(err),
            }
        }
        Err(outcome.into_error(dispatch))
    }

    /// Call the endpoints in `window` one at a time and return the first
    /// success. As in alloy, an error reply moves on to the next endpoint,
    /// which may return the receipt. If none does, the window is reported
    /// as a submission's is (see [`WindowOutcome::into_error`]).
    async fn sequential(
        &self,
        window: &[usize],
        req: &RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        let mut outcome = WindowOutcome::default();
        for &idx in window {
            match self.call_endpoint(idx, req.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => outcome.record(err),
            }
        }
        Err(outcome.into_error(Dispatch::SequentialSubmission))
    }

    /// Return a future that calls one endpoint and records the outcome in
    /// the health registry. Nothing is sent until the future is polled,
    /// and a race drops the calls still pending once one endpoint answers,
    /// so an endpoint that loses a race may never see the request and its
    /// outcome is not recorded.
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
            let result = call.await.and_then(error_reply_as_err);
            match &result {
                Ok(_) => self.health.record_success(idx, started.elapsed(), None),
                // The endpoint answered, but whether the reply reflects on
                // the endpoint (an invalid API key) or only on the request
                // (a revert) is the probe loop's to judge.
                Err(err) if is_error_reply(err) => {}
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

    use alloy::rpc::json_rpc::{ErrorPayload, Id, Request, Response, ResponsePayload};
    use alloy::transports::IntoBoxTransport;
    use tower::ServiceBuilder;

    use crate::transport::{DEFAULT_CU_PER_SEC, retry_layer};

    /// What a [`MockEndpoint`] does with each request.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Answers `"0x1"`.
        Answers,
        /// Fails with a transport error, like a refused connection.
        Down,
        /// Replies with a JSON-RPC error, like a node reporting a revert.
        Reverts,
        /// Refuses a transaction with a JSON-RPC error, as a node does when
        /// a replacement is underpriced.
        Refuses,
        /// Says it already has the transaction.
        AlreadyKnown,
    }

    /// A transport that counts the calls it receives and handles each as
    /// its [`Behaviour`] says, optionally after a delay.
    #[derive(Clone)]
    struct MockEndpoint {
        behaviour: Behaviour,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl MockEndpoint {
        fn new(healthy: bool) -> Self {
            Self::with(if healthy {
                Behaviour::Answers
            } else {
                Behaviour::Down
            })
        }

        fn with(behaviour: Behaviour) -> Self {
            Self {
                behaviour,
                delay: Duration::ZERO,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn after(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
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
            let (behaviour, delay) = (self.behaviour, self.delay);
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let id = req
                    .requests()
                    .first()
                    .map(|r| r.id().clone())
                    .unwrap_or(Id::None);
                let payload = match behaviour {
                    Behaviour::Down => {
                        return Err(TransportErrorKind::custom_str("connection refused"));
                    }
                    Behaviour::Answers => {
                        ResponsePayload::Success(serde_json::value::to_raw_value("0x1").unwrap())
                    }
                    Behaviour::Reverts => ResponsePayload::Failure(revert_payload()),
                    Behaviour::Refuses => ResponsePayload::Failure(refusal_payload()),
                    Behaviour::AlreadyKnown => ResponsePayload::Failure(
                        serde_json::from_str(r#"{"code":-32000,"message":"already known"}"#)
                            .unwrap(),
                    ),
                };
                Ok(ResponsePacket::Single(Response { id, payload }))
            })
        }
    }

    fn revert_payload() -> ErrorPayload {
        serde_json::from_str(r#"{"code":3,"message":"execution reverted","data":"0x"}"#).unwrap()
    }

    fn refusal_payload() -> ErrorPayload {
        serde_json::from_str(r#"{"code":-32000,"message":"replacement transaction underpriced"}"#)
            .unwrap()
    }

    /// Each mock as the pool's transport, as is.
    fn pool_of(mocks: &[MockEndpoint]) -> (EndpointPool, HealthRegistry) {
        pool_with(mocks, BoxTransport::new)
    }

    /// Each mock behind the production retry layer, which retries rate
    /// limits and passes every other JSON-RPC error reply up as a response.
    fn pool_behind_retry_layer(mocks: &[MockEndpoint]) -> (EndpointPool, HealthRegistry) {
        pool_with(mocks, |mock| {
            ServiceBuilder::new()
                .layer(retry_layer(DEFAULT_CU_PER_SEC))
                .service(mock)
                .into_box_transport()
        })
    }

    fn pool_with(
        mocks: &[MockEndpoint],
        transport: impl Fn(MockEndpoint) -> BoxTransport,
    ) -> (EndpointPool, HealthRegistry) {
        let health = HealthRegistry::new((0..mocks.len()).map(|i| format!("http://mock/{i}")));
        let endpoints = mocks
            .iter()
            .enumerate()
            .map(|(i, m)| PoolEndpoint {
                label: format!("http://mock/{i}"),
                transport: transport(m.clone()),
            })
            .collect();
        (
            EndpointPool::new("test".into(), endpoints, health.clone()),
            health,
        )
    }

    fn calls(mocks: &[MockEndpoint]) -> Vec<usize> {
        mocks.iter().map(MockEndpoint::calls).collect()
    }

    /// The JSON-RPC error code a failed call carries, if it was an error
    /// reply rather than a transport error.
    fn error_reply_code(result: Result<ResponsePacket, TransportError>) -> Option<i64> {
        result
            .expect_err("the call fails")
            .as_error_resp()
            .map(|payload| payload.code)
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

    #[tokio::test]
    async fn revert_ends_a_read_and_is_not_masked_by_a_dead_later_endpoint() {
        // Two endpoints report the revert; the third is down. Moving on to
        // it would turn the revert into a connection error, which a
        // pre-broadcast simulation reads as "unavailable".
        let mocks = [
            MockEndpoint::with(Behaviour::Reverts),
            MockEndpoint::with(Behaviour::Reverts),
            MockEndpoint::with(Behaviour::Down),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        assert_eq!(error_reply_code(send(&pool, "eth_call").await), Some(3));
        assert_eq!(mocks[2].calls(), 0, "the read stopped at the revert");
    }

    #[tokio::test]
    async fn revert_is_returned_over_a_slower_transport_error() {
        let mocks = [
            MockEndpoint::with(Behaviour::Reverts),
            MockEndpoint::with(Behaviour::Down).after(Duration::from_millis(50)),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        assert_eq!(error_reply_code(send(&pool, "eth_call").await), Some(3));
    }

    #[tokio::test]
    async fn a_read_takes_the_first_answer() {
        // A revert does not wait for a slower endpoint's result: that
        // endpoint may be lagging behind the state that reverts, or may not
        // answer until it times out.
        let mocks = [
            MockEndpoint::with(Behaviour::Reverts),
            MockEndpoint::with(Behaviour::Answers).after(Duration::from_secs(5)),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        let started = Instant::now();
        assert_eq!(error_reply_code(send(&pool, "eth_call").await), Some(3));
        assert!(started.elapsed() < Duration::from_secs(1));

        // A result that comes first wins the same way.
        let mocks = [
            MockEndpoint::with(Behaviour::Reverts).after(Duration::from_millis(50)),
            MockEndpoint::with(Behaviour::Answers),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        let response = send(&pool, "eth_call").await.expect("the result wins");
        assert!(response.as_error().is_none());
    }

    #[tokio::test]
    async fn a_submission_waits_past_a_refusal_for_the_hash() {
        // One node refuses the transaction that another accepts.
        let mocks = [
            MockEndpoint::with(Behaviour::Refuses),
            MockEndpoint::with(Behaviour::Answers).after(Duration::from_millis(50)),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        let response = send(&pool, "eth_sendRawTransaction")
            .await
            .expect("the hash wins");
        assert!(response.as_error().is_none());
    }

    #[tokio::test]
    async fn already_known_reports_a_submission() {
        // The node has the transaction, so it was accepted, whatever the
        // other endpoint says and in either order.
        for other in [Behaviour::Down, Behaviour::Refuses] {
            for known_first in [true, false] {
                let (known, other) = (
                    MockEndpoint::with(Behaviour::AlreadyKnown),
                    MockEndpoint::with(other),
                );
                let mocks = if known_first {
                    [known, other.after(Duration::from_millis(50))]
                } else {
                    [other, known.after(Duration::from_millis(50))]
                };
                let (pool, _) = pool_behind_retry_layer(&mocks);
                let err = send(&pool, "eth_sendRawTransaction")
                    .await
                    .expect_err("no hash");
                let payload = err.as_error_resp().expect("an error reply");
                assert_eq!(payload.message, "already known");
            }
        }
    }

    #[test]
    fn a_batch_keeps_each_response() {
        let failure = Response {
            id: Id::Number(1),
            payload: ResponsePayload::Failure(revert_payload()),
        };
        let success = Response {
            id: Id::Number(2),
            payload: ResponsePayload::Success(serde_json::value::to_raw_value("0x1").unwrap()),
        };
        let batch = ResponsePacket::Batch(vec![failure.clone(), success]);
        let kept = error_reply_as_err(batch).expect("a batch passes through");
        assert_eq!(kept.responses().len(), 2);

        let single = ResponsePacket::Single(failure);
        let err = error_reply_as_err(single).expect_err("a single error reply");
        assert_eq!(err.as_error_resp().map(|payload| payload.code), Some(3));
    }

    #[tokio::test]
    async fn error_replies_leave_health_to_the_probes() {
        let mocks = [
            MockEndpoint::with(Behaviour::Reverts),
            MockEndpoint::with(Behaviour::Reverts),
        ];
        let (pool, health) = pool_behind_retry_layer(&mocks);
        // The probe loop has put endpoint 0 in cooldown.
        for _ in 0..5 {
            health.record_failure(0, true, None);
        }
        for _ in 0..10 {
            send(&pool, "eth_call").await.expect_err("reverts");
        }
        // Replies neither clear endpoint 0's cooldown nor arm one for
        // endpoint 1.
        assert_eq!(health.cooled_down_indices(), vec![0]);
        assert!(calls(&mocks).iter().sum::<usize>() >= 10);
    }

    #[tokio::test]
    async fn submission_reports_an_unknown_outcome_over_a_refusal() {
        // The endpoint that failed may have taken the transaction before
        // its reply was lost, in either order.
        for mocks in [
            [
                MockEndpoint::with(Behaviour::Refuses),
                MockEndpoint::with(Behaviour::Down).after(Duration::from_millis(50)),
            ],
            [
                MockEndpoint::with(Behaviour::Down),
                MockEndpoint::with(Behaviour::Refuses).after(Duration::from_millis(50)),
            ],
        ] {
            let (pool, _) = pool_behind_retry_layer(&mocks);
            let result = send(&pool, "eth_sendRawTransaction").await;
            assert_eq!(error_reply_code(result), None, "a transport error");
        }

        // Refused everywhere, the refusal is the answer.
        let mocks = [
            MockEndpoint::with(Behaviour::Refuses),
            MockEndpoint::with(Behaviour::Refuses),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        assert_eq!(
            error_reply_code(send(&pool, "eth_sendRawTransaction").await),
            Some(-32000)
        );
    }

    #[tokio::test]
    async fn sequential_submission_moves_past_an_error_reply() {
        // Another endpoint may still return the receipt.
        let mocks = [
            MockEndpoint::with(Behaviour::Refuses),
            MockEndpoint::with(Behaviour::Answers),
            MockEndpoint::with(Behaviour::Answers),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        send(&pool, "eth_sendRawTransactionSync").await.unwrap();
        assert_eq!(calls(&mocks), vec![1, 1, 0]);

        // With no receipt anywhere, the endpoint that failed may have taken
        // the transaction, so the outcome is unknown.
        let mocks = [
            MockEndpoint::with(Behaviour::Refuses),
            MockEndpoint::with(Behaviour::Down),
        ];
        let (pool, _) = pool_behind_retry_layer(&mocks);
        assert_eq!(
            error_reply_code(send(&pool, "eth_sendRawTransactionSync").await),
            None
        );
    }

    #[tokio::test]
    async fn live_failures_arm_a_cooldown() {
        let mocks = [MockEndpoint::new(false), MockEndpoint::new(false)];
        let (pool, health) = pool_of(&mocks);
        for _ in 0..5 {
            send(&pool, "eth_chainId").await.expect_err("both down");
        }
        assert_eq!(health.cooled_down_indices(), vec![0, 1]);
    }

    #[tokio::test]
    async fn live_successes_clear_a_cooldown() {
        let mocks = [MockEndpoint::new(true), MockEndpoint::new(false)];
        let (pool, health) = pool_of(&mocks);
        for _ in 0..5 {
            health.record_failure(0, true, None);
        }
        assert_eq!(health.cooled_down_indices(), vec![0]);
        // Endpoint 1 fails each race, so endpoint 0 answers both reads.
        for _ in 0..2 {
            send(&pool, "eth_chainId").await.unwrap();
        }
        assert!(health.cooled_down_indices().is_empty());
    }

    #[tokio::test]
    async fn sequential_submission_stays_in_the_first_window() {
        let mocks = [
            MockEndpoint::new(false),
            MockEndpoint::new(false),
            MockEndpoint::new(true),
        ];
        let (pool, _) = pool_of(&mocks);
        send(&pool, "eth_sendRawTransactionSync")
            .await
            .expect_err("the first window failed and submissions stop there");
        assert_eq!(calls(&mocks), vec![1, 1, 0]);
    }

    #[tokio::test]
    async fn cooled_down_endpoint_is_still_tried_when_the_others_fail() {
        let mocks = [
            MockEndpoint::new(true),
            MockEndpoint::new(false),
            MockEndpoint::new(false),
        ];
        let (pool, health) = pool_of(&mocks);
        for _ in 0..5 {
            health.record_failure(0, true, None);
        }
        assert_eq!(health.cooled_down_indices(), vec![0]);
        send(&pool, "eth_chainId")
            .await
            .expect("the cooled-down endpoint answers last");
        assert_eq!(calls(&mocks), vec![1, 1, 1]);
    }

    #[tokio::test]
    async fn live_calls_do_not_set_last_block() {
        let mocks = [MockEndpoint::new(true), MockEndpoint::new(true)];
        let (pool, health) = pool_of(&mocks);
        send(&pool, "eth_blockNumber").await.unwrap();
        assert!(health.snapshot().iter().all(|s| s.last_block.is_none()));
    }
}
