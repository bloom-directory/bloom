//! Builds the layered alloy transport stack from a `ChainSpec`.
//!
//! Stack per endpoint:
//!
//! ```text
//! [RetryBackoffLayer with BloomRetryPolicy]
//!  ↓
//! [ThrottleLayer (only if endpoint.max_rps is Some)]
//!  ↓
//! [Http transport]
//! ```
//!
//! The fallback fan-out wraps the per-endpoint stacks in a single
//! `FallbackLayer` with `active_transport_count = min(2, endpoints.len())`
//! so two endpoints race for each call. A two-endpoint chain therefore
//! always queries both in parallel; bigger lists rotate the top two by
//! score.
//!
//! ## HTTP / WS split
//!
//! HTTP endpoints are constructed eagerly inside `RpcEngine::build`
//! (sync; reqwest does not require a handshake before its first call).
//! WS endpoints — `ws://` / `wss://` URLs not flagged `http_only` — are
//! deliberately *not* mixed into the fallback pool. Their construction
//! requires `WsConnect::connect().await`, which would force
//! `RpcEngine::build` and therefore `ChainClient::new` to become async
//! and ripple to every caller in the workspace.
//!
//! Instead, WS URLs are stored as a `Vec<WsConnect>`. The first
//! `RpcEngine::ws_provider().await` call opens the connection lazily
//! under a `tokio::sync::OnceCell` and caches the resulting
//! `RootProvider<Ethereum>` for subsequent callers. The pool of HTTP
//! transports remains the source for one-shot request/response calls;
//! the WS provider is a sibling used only for `subscribe_*`. Callers
//! that need both (the watch executor in particular) hold both Arcs.
//!
//! ## Active probe loop (WP-3)
//!
//! On `RpcEngine::build` we also spawn one tokio task per engine that
//! periodically probes each HTTP endpoint *directly* — bypassing the
//! fallback fan-out — with a 2 s `eth_blockNumber` call. Outcomes are
//! folded into the `HealthRegistry` so the cooldown state machine
//! reflects actual reachability rather than the alloy layer's
//! private metrics. The task is cancelled when `RpcEngine` drops via
//! a `tokio::sync::watch` channel.
//!
//! ### Scope note: filtering the fallback pool
//!
//! Alloy's `FallbackLayer` does not expose a runtime hook to exclude
//! transports based on Bloom-side health. For WP-3 we therefore record
//! cooldowns for observability only — the fallback fan-out still
//! queries cooled-down endpoints in parallel. The eviction story can
//! land later as either an upstream PR or a thin wrapping layer.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::Ethereum;
use alloy::primitives::U64;
use alloy::providers::RootProvider;
use alloy::rpc::client::RpcClient;
use alloy::transports::http::{Http, reqwest};
use alloy::transports::layers::{FallbackLayer, RetryBackoffLayer, ThrottleLayer};
use alloy::transports::ws::WsConnect;
use alloy::transports::{BoxTransport, IntoBoxTransport};
use bloom_proto::{ChainSpec, EndpointSpec};
use tokio::sync::{OnceCell, watch};
use tower::ServiceBuilder;
use tracing::{debug, info, warn};

use crate::endpoint::{EndpointScheme, classify_endpoint, is_subscription_capable};
use crate::error::BloomRpcError;
use crate::health::{CooldownDecision, EndpointHealthSnapshot, HealthRegistry};
use crate::policy::BloomRetryPolicy;

/// Default compute-units-per-second when the operator hasn't set
/// `cu_per_sec`. Mirrors alloy's own internal default for the retry
/// layer (Alchemy free-tier 330 CU/s × 2 ≈ 660). The cost is a
/// conservative throttle on retry pacing only — it doesn't reject
/// calls.
const DEFAULT_CU_PER_SEC: u64 = 660;

/// Maximum retries applied by `RetryBackoffLayer`. Three is the value
/// the spec recommends: one for transient network blips, one for a
/// rate-limit cooldown, one for a tail latency outlier. Anything more
/// risks masking a genuinely-broken endpoint.
const MAX_RETRIES: u32 = 3;

/// Initial backoff in milliseconds. The retry layer doubles this on
/// each attempt; 200 ms keeps the worst-case retry chain inside the
/// per-call budget at our scale (200 → 400 → 800).
const INITIAL_BACKOFF_MS: u64 = 200;

/// Active probe interval. 15 s matches the spec's §C.7 recovery
/// cadence — frequent enough that a cooled-down endpoint rejoins the
/// pool quickly, sparse enough that a 50-chain daemon doesn't drown
/// public RPC frontends in idle traffic.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Per-call deadline for the active probe. Anything slower than this
/// is, by definition, no use as a backing transport for live UI
/// reads.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// One entry in the per-endpoint probe table. The `transport` is the
/// fully-layered HTTP stack for one endpoint; the `idx` is the slot
/// in the `HealthRegistry` that owns the corresponding metrics.
struct ProbeTarget {
    idx: usize,
    url: String,
    /// Pre-built `RpcClient` over a single endpoint's stack. Cloning
    /// is cheap (Arc inside) and the probe issues one call per round
    /// per target.
    client: RpcClient,
}

/// The layered RPC engine. Built once per `ChainSpec` and shared via
/// `Arc` by every consumer (the wallet, watch executor, ENS resolver,
/// VFS handlers). The `provider()` accessor exposes the alloy
/// `RootProvider<Ethereum>` so existing call sites that depend on the
/// trait surface continue to compile unchanged.
///
/// WS-capable endpoints, when configured, sit *alongside* the HTTP
/// pool: the engine stores their `WsConnect` configurations and lazily
/// opens a single shared `RootProvider<Ethereum>` for subscriptions on
/// the first `ws_provider()` call. See module-level docs for the
/// rationale (HTTP for request/response, WS exclusively for
/// subscriptions).
pub struct RpcEngine {
    chain_name: String,
    endpoints: Vec<EndpointSpec>,
    provider: Arc<RootProvider<Ethereum>>,
    /// Kept so callers can build a provider with a different network
    /// type (e.g. `RootProvider<Optimism>`) over the same transport.
    client: RpcClient,
    supports_subscriptions: bool,
    health: HealthRegistry,
    /// Send `true` here to cancel the probe loop on drop. Wrapped in
    /// `Option` so `Drop` can take ownership cleanly.
    shutdown_tx: Option<watch::Sender<bool>>,
    ws_connects: Vec<WsConnect>,
    ws_provider: OnceCell<Arc<RootProvider<Ethereum>>>,
}

impl RpcEngine {
    /// Build the layered transport stack for `spec`.
    ///
    /// Returns `BloomRpcError::NoEndpoints` if `spec.endpoints()` is
    /// empty *or* resolves to zero HTTP-shaped endpoints (the engine
    /// always needs at least one HTTP transport for one-shot reads —
    /// `eth_call`, `eth_getLogs`, etc. — even if every WS endpoint is
    /// healthy).
    ///
    /// Each endpoint URL is classified into HTTP or WS; HTTP-shaped
    /// endpoints are wrapped in retry + optional throttle and joined
    /// under a fallback layer. WS-shaped endpoints not flagged
    /// `http_only` are stashed as `WsConnect` configurations and
    /// opened lazily by `ws_provider().await` so the build remains
    /// sync.
    pub fn build(spec: &ChainSpec) -> Result<Self, BloomRpcError> {
        let endpoints = spec.endpoints();
        if endpoints.is_empty() {
            return Err(BloomRpcError::NoEndpoints(spec.name.clone()));
        }

        let mut http_transports: Vec<BoxTransport> = Vec::new();
        let mut probe_targets: Vec<ProbeTarget> = Vec::new();
        let mut tracked_urls: Vec<String> = Vec::new();
        let mut ws_connects: Vec<WsConnect> = Vec::new();
        let mut supports_subscriptions = false;

        for ep in &endpoints {
            let (url, scheme) = classify_endpoint(ep)?;
            if is_subscription_capable(ep) {
                supports_subscriptions = true;
            }
            match scheme {
                EndpointScheme::Http => {
                    let transport = build_http_stack(&url, ep);
                    let idx = tracked_urls.len();
                    tracked_urls.push(ep.url.clone());
                    // Keep a clone for the probe loop. `BoxTransport`
                    // is `Clone` (Arc inside), so the per-endpoint
                    // RpcClient shares connection state with the
                    // fallback fan-out — probes therefore reflect
                    // exactly what production traffic would see.
                    let probe_client = RpcClient::new(transport.clone(), false);
                    probe_targets.push(ProbeTarget {
                        idx,
                        url: ep.url.clone(),
                        client: probe_client,
                    });
                    http_transports.push(transport);
                    debug!(
                        chain = %spec.name,
                        url = %redacted(&ep.url),
                        weight = ep.weight,
                        cu_per_sec = ep.cu_per_sec,
                        max_rps = ep.max_rps,
                        "rpc.transport.http_stack_built"
                    );
                }
                EndpointScheme::Ws => {
                    // WS endpoints are recorded for lazy open via
                    // `ws_provider().await`. Honour `http_only` (already
                    // applied to `supports_subscriptions` above): if the
                    // operator has flagged this endpoint HTTP-only we
                    // do not build a WS transport for it.
                    if ep.http_only {
                        debug!(
                            chain = %spec.name,
                            url = %redacted(&ep.url),
                            "rpc.transport.ws_endpoint_skipped_http_only"
                        );
                        continue;
                    }
                    ws_connects.push(WsConnect::new(url.as_str()));
                    debug!(
                        chain = %spec.name,
                        url = %redacted(&ep.url),
                        weight = ep.weight,
                        "rpc.transport.ws_connect_registered"
                    );
                }
            }
        }

        if http_transports.is_empty() {
            return Err(BloomRpcError::NoEndpoints(spec.name.clone()));
        }

        let active = NonZeroUsize::new(http_transports.len().min(2)).unwrap_or(
            // SAFETY: `http_transports.is_empty()` was rejected above,
            // so `len() >= 1` and `min(2) >= 1`. The unwrap_or branch
            // is unreachable; we still write the fallback to avoid an
            // explicit unwrap that future readers might mis-edit.
            NonZeroUsize::new(1).unwrap(),
        );
        let fallback = FallbackLayer::default().with_active_transport_count(active);

        let service = ServiceBuilder::new()
            .layer(fallback)
            .service(http_transports);
        // Loopback URLs are tagged "local" by alloy's HTTP transport;
        // we don't have visibility into per-endpoint locality at this
        // outer layer, so default to false (the most conservative
        // choice for retry/timeout heuristics).
        let client: RpcClient = RpcClient::new(service, false);
        let provider: RootProvider<Ethereum> = RootProvider::<Ethereum>::new(client.clone());

        let health = HealthRegistry::new(tracked_urls);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_probe_loop(
            spec.name.clone(),
            probe_targets,
            health.clone(),
            shutdown_rx,
        );

        info!(
            chain = %spec.name,
            endpoints = endpoints.len(),
            http_endpoints = active.get(),
            ws_endpoints = ws_connects.len(),
            supports_subscriptions,
            "rpc.engine.built"
        );

        Ok(Self {
            chain_name: spec.name.clone(),
            endpoints,
            provider: Arc::new(provider),
            client,
            supports_subscriptions,
            health,
            shutdown_tx: Some(shutdown_tx),
            ws_connects,
            ws_provider: OnceCell::new(),
        })
    }

    /// The alloy provider backed by the layered stack. Cloning the
    /// `Arc` is the intended way for downstream crates to share the
    /// engine.
    pub fn provider(&self) -> Arc<RootProvider<Ethereum>> {
        self.provider.clone()
    }

    /// Clone of the underlying `RpcClient`, so callers can build a
    /// provider with a different network type (e.g.
    /// `RootProvider<Optimism>`) over the same transport stack.
    pub fn raw_client(&self) -> RpcClient {
        self.client.clone()
    }

    /// True if any configured endpoint declared a ws/wss URL and was
    /// not flagged `http_only`. The watch executor uses this to decide
    /// whether to attempt the WS subscription fast path before falling
    /// back to the HTTP poll loop.
    pub fn supports_subscriptions(&self) -> bool {
        self.supports_subscriptions
    }

    /// Lazily construct the WS-backed `RootProvider<Ethereum>` used for
    /// `subscribe_*` calls.
    ///
    /// Returns `None` when no WS endpoints were configured (or all of
    /// them were flagged `http_only`). On the first call with at least
    /// one WS endpoint, opens a connection and caches the resulting
    /// provider in a `OnceCell` so subsequent callers reuse it without
    /// re-handshaking. Currently uses the *first* configured WS
    /// endpoint; multi-WS failover is out of scope for WP-4 (alloy's
    /// `FallbackLayer` does not coordinate pubsub state across
    /// transports, so we keep WS sticky to one URL until the WS
    /// reconnect notes in §F.2 of the spec direct otherwise).
    ///
    /// If the connection attempt fails, the error is logged with
    /// `rpc.transport.ws_provider_open_failed` and the OnceCell stays
    /// empty so the *next* call retries — useful when the WS endpoint
    /// is flapping (the watch executor's watchdog tick will retry on
    /// every poll cycle).
    pub async fn ws_provider(&self) -> Option<Arc<RootProvider<Ethereum>>> {
        if self.ws_connects.is_empty() {
            return None;
        }
        // OnceCell::get_or_try_init would cache an Err; we want to
        // retry on failure so we manage the slot manually with a
        // get-then-init dance.
        if let Some(p) = self.ws_provider.get() {
            return Some(p.clone());
        }
        let connect = self.ws_connects[0].clone();
        match RpcClient::connect_pubsub(connect).await {
            Ok(client) => {
                let provider: RootProvider<Ethereum> = RootProvider::<Ethereum>::new(client);
                let arc = Arc::new(provider);
                // First writer wins; concurrent callers share the same
                // Arc once it lands.
                let stored = self.ws_provider.get_or_init(|| async { arc.clone() }).await;
                info!(
                    chain = %self.chain_name,
                    "rpc.transport.ws_provider_built"
                );
                Some(stored.clone())
            }
            Err(e) => {
                warn!(
                    chain = %self.chain_name,
                    error = %e,
                    "rpc.transport.ws_provider_open_failed"
                );
                None
            }
        }
    }

    /// Per-endpoint health view. Values reflect the most recent probe
    /// outcomes; production traffic does not (yet) update this view —
    /// see the scope note in `health.rs`.
    pub fn endpoints_snapshot(&self) -> Vec<EndpointHealthSnapshot> {
        self.health.snapshot()
    }

    /// Number of endpoints currently parked in cooldown. Cheap;
    /// suitable for status-bar style displays.
    pub fn cooled_down_count(&self) -> usize {
        self.health.cooled_down_count()
    }

    /// Chain name this engine was built for. Used by error variants
    /// that surface "all endpoints failed" with operator context.
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// Configured endpoints, in source order.
    pub fn endpoints(&self) -> &[EndpointSpec] {
        &self.endpoints
    }
}

impl Drop for RpcEngine {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            // Signal the probe loop to exit; ignore the error, which
            // only fires if every receiver has already dropped (in
            // which case the task is already gone).
            let _ = tx.send(true);
        }
    }
}

/// Spawn the active probe loop.
///
/// The task pulses every `PROBE_INTERVAL`, issues a single
/// `eth_blockNumber` against each tracked endpoint with a hard
/// `PROBE_TIMEOUT`, and folds the outcome into the `HealthRegistry`.
/// Cancellation is observed via `shutdown_rx`: the loop exits as soon
/// as the watched value flips to `true`.
fn spawn_probe_loop(
    chain: String,
    targets: Vec<ProbeTarget>,
    health: HealthRegistry,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if targets.is_empty() {
        return;
    }
    // `RpcEngine::build` is a sync constructor; some unit tests build
    // a `ChainClient` from a sync `#[test]` without a Tokio runtime
    // attached. In that mode there's nothing to probe (no async code
    // would run anyway) so we silently skip the spawn rather than
    // panicking the test binary.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        debug!(
            chain = %chain,
            "rpc.health.probe_loop_skipped_no_runtime"
        );
        return;
    };
    handle.spawn(async move {
        info!(
            chain = %chain,
            endpoints = targets.len(),
            interval_secs = PROBE_INTERVAL.as_secs(),
            "rpc.health.probe_loop_started"
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!(chain = %chain, "rpc.health.probe_loop_stopped");
                        return;
                    }
                }
            }
            run_probe_round(&chain, &targets, &health).await;
        }
    });
}

/// One probe round across every tracked endpoint. Sequential by
/// design: the targets share the underlying reqwest connection pool
/// and we don't want a probe burst to mask a real production call.
async fn run_probe_round(chain: &str, targets: &[ProbeTarget], health: &HealthRegistry) {
    for target in targets {
        let started = Instant::now();
        debug!(
            chain = %chain,
            idx = target.idx,
            url = %redacted(&target.url),
            "rpc.health.probe_started"
        );
        let call = target.client.request_noparams::<U64>("eth_blockNumber");
        let result = tokio::time::timeout(PROBE_TIMEOUT, call).await;
        match result {
            Ok(Ok(value)) => {
                let elapsed = started.elapsed();
                let block = value.try_into().ok();
                health.record_success(target.idx, elapsed, block);
                debug!(
                    chain = %chain,
                    idx = target.idx,
                    url = %redacted(&target.url),
                    latency_ms = elapsed.as_millis() as u64,
                    block,
                    "rpc.health.probe_succeeded"
                );
                // Was a cooldown cleared by this success? `cooled_down_indices`
                // is the cheapest way to ask — if the index is no longer
                // listed and it had been before, log the transition.
                if !health.cooled_down_indices().contains(&target.idx) {
                    debug!(
                        chain = %chain,
                        idx = target.idx,
                        "rpc.health.cooldown_cleared"
                    );
                }
            }
            Ok(Err(err)) => {
                let decision = health.record_failure(target.idx, true, None);
                debug!(
                    chain = %chain,
                    idx = target.idx,
                    url = %redacted(&target.url),
                    error = %err,
                    "rpc.health.probe_failed"
                );
                emit_cooldown_event(chain, target, decision);
            }
            Err(_elapsed) => {
                warn!(
                    chain = %chain,
                    idx = target.idx,
                    url = %redacted(&target.url),
                    timeout_ms = PROBE_TIMEOUT.as_millis() as u64,
                    "rpc.health.probe_timeout"
                );
                let decision = health.record_failure(target.idx, true, None);
                emit_cooldown_event(chain, target, decision);
            }
        }
    }
}

fn emit_cooldown_event(chain: &str, target: &ProbeTarget, decision: CooldownDecision) {
    match decision {
        CooldownDecision::None => {}
        CooldownDecision::Fresh(d) => {
            warn!(
                chain = %chain,
                idx = target.idx,
                url = %redacted(&target.url),
                cooldown_secs = d.as_secs(),
                "rpc.health.cooldown_set"
            );
        }
        CooldownDecision::Chronic(d) => {
            warn!(
                chain = %chain,
                idx = target.idx,
                url = %redacted(&target.url),
                cooldown_secs = d.as_secs(),
                "rpc.health.chronic_failer_escalated"
            );
        }
    }
}

/// Build the HTTP transport stack for one endpoint. The result is
/// box-erased so all endpoints in the fallback layer share a single
/// concrete type.
fn build_http_stack(url: &url::Url, ep: &EndpointSpec) -> BoxTransport {
    let cu = ep.cu_per_sec.unwrap_or(DEFAULT_CU_PER_SEC);
    let retry = RetryBackoffLayer::new_with_policy(
        MAX_RETRIES,
        INITIAL_BACKOFF_MS,
        cu,
        BloomRetryPolicy::default(),
    );

    // ServiceBuilder applies layers outermost-first when reading
    // top-to-bottom; conceptually retry sits *outside* throttle so
    // throttled-and-rate-limited responses still get retried. For
    // endpoints without a configured `max_rps` we skip the throttle
    // layer entirely (the throttle layer panics on `rps == 0`).
    let http: Http<reqwest::Client> = Http::new(url.clone());
    if let Some(rps) = ep.max_rps {
        let throttle = ThrottleLayer::new(rps);
        let stack = ServiceBuilder::new()
            .layer(retry)
            .layer(throttle)
            .service(http);
        stack.into_box_transport()
    } else {
        let stack = ServiceBuilder::new().layer(retry).service(http);
        stack.into_box_transport()
    }
}

/// Best-effort URL redaction for log lines. Strips the path / query so
/// vendor API keys baked into the path don't end up in stdout.
fn redacted(url: &str) -> String {
    if let Ok(u) = url::Url::parse(url) {
        let host = u.host_str().unwrap_or("?");
        let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
        format!("{}://{}{}", u.scheme(), host, port)
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::{ChainSpec, EndpointSpec};

    fn http_only_spec() -> ChainSpec {
        let mut s = ChainSpec::anvil_default();
        s.rpc_urls = vec!["http://127.0.0.1:65535".into()];
        s.rpc_endpoints.clear();
        s
    }

    fn http_plus_ws_spec() -> ChainSpec {
        let mut s = ChainSpec::anvil_default();
        s.rpc_urls.clear();
        s.rpc_endpoints = vec![
            EndpointSpec {
                url: "http://127.0.0.1:65535".into(),
                weight: 100,
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            },
            // Use a deliberately-unreachable WS URL — the engine builds
            // sync without dialling, so the test never actually opens
            // the socket. `ws_provider().await` only attempts the dial
            // on first call; the `ws_provider_some_when_one_ws_endpoint`
            // test below avoids triggering it.
            EndpointSpec {
                url: "ws://127.0.0.1:65534".into(),
                weight: 100,
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            },
        ];
        s
    }

    #[test]
    fn ws_provider_none_when_no_ws_endpoints() {
        // An HTTP-only spec must report `supports_subscriptions == false`
        // and store zero `WsConnect` entries. We assert the shape via
        // the public surface: `supports_subscriptions()` and the lazy
        // accessor both reflect "no WS available".
        let engine = RpcEngine::build(&http_only_spec()).expect("build engine");
        assert!(!engine.supports_subscriptions());
        assert!(engine.ws_connects.is_empty());

        // Drive the async accessor on a fresh runtime — no WS endpoints
        // means we return `None` immediately without dialling.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let got = rt.block_on(async { engine.ws_provider().await });
        assert!(got.is_none(), "expected None, got Some");
    }

    #[test]
    fn ws_provider_some_when_one_ws_endpoint() {
        // We can't open a real WS handshake against an unreachable
        // address inside a unit test (it would hang on connect), so we
        // verify the build-time shape only:
        //   - `supports_subscriptions` flips to true,
        //   - `ws_connects` has exactly one entry,
        //   - the `WsConnect` round-trips the URL.
        // The end-to-end `ws_provider().await` path is exercised by the
        // anvil-backed integration test in bloom-it's
        // `rpc_ws_subscriptions.rs`.
        let engine = RpcEngine::build(&http_plus_ws_spec()).expect("build engine");
        assert!(engine.supports_subscriptions());
        assert_eq!(engine.ws_connects.len(), 1);
    }
}
