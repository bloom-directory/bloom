# RPC Robustness — Design Spec

Status: ratified — implementation in progress
Date: 2026-05-09
Workspace: `bloom` (root `/home/joshua/code/bloom`)

## Decisions ratified

These overrides win over any conflicting recommendation later in the document:

1. **New crate `crates/bloom-rpc`** — not a submodule in `bloom-chain`. All paths
   under `crates/bloom-chain/src/rpc/` in §C.1 and §E read instead as
   `crates/bloom-rpc/src/`. `bloom-chain` adds `bloom-rpc` as a workspace dep.
2. **Tx-staging sessions are always-on.** No `[backends] tx_session` config knob.
   `TxEngine::stage_*` unconditionally opens a session.
3. **Reorg-dedupe ring buffer in `bloom-watch`** — last 64 blocks of
   `(blockHash, logIndex)`. Applies on both WS and poll paths so handover is
   transparent.
4. **`transport-throttle` feature enabled** — `governor` enters the build.
   Per-endpoint `max_rps` defaults to `None` (no-op until a config sets it).

## Goal

Replace the current single-URL HTTP-only `ChainClient` with a transport
layer that supports:

1. Multiple endpoints per chain with automatic failover and load
   balancing.
2. WebSocket subscriptions where available, with poll fallback.
3. Rate-limit detection (HTTP 429, JSON-RPC error codes, vendor
   `Retry-After` / `backoff_seconds`) with cooldowns and recovery probes.
4. Cross-provider state-drift handling so a logical operation does not
   silently observe a different chain head when a request fails over.

The work must keep `ChainClient`'s public API stable for the dozens of
call sites in `bloom-vfs`, `bloom-tx`, `bloom-watch`, `bloom-ens`,
`bloom-revert`, `bloom-defi`, `bloom-daemon`. Behind that API the transport
becomes a stack: `RpcClient` over `tower::ServiceBuilder` of
`(retry → fallback → throttle? → http|ws)` plus a thin Bloom-side
"session" layer for state pinning.

---

## A. Current state audit

### A.1 `crates/bloom-chain/src/lib.rs`

**Construction (line 125–144).** `ChainClient::new(spec: ChainSpec)`:

- Validates `spec.rpc_urls` is non-empty (`ChainError::NoEndpoints`).
- Takes `rpc_urls.first()`, parses to `url::Url`, builds
  `RootProvider::<Ethereum>::new_http(url)`.
- All other URLs are silently dropped. The doc comment at the top of
  the file claims "the pool layer is a thin wrapper that walks
  `rpc_urls` in priority order on call failure" — that wrapper does not
  exist. Only `primary` is used.
- `cached_chain_id: Arc<RwLock<Option<u64>>>` is the only health/cache
  state. There is no per-endpoint metric, no timeout, no retry.

**Stored type:** `primary: Arc<RootProvider<Ethereum>>`.

**Public API surface** (call sites depend on these signatures):

```rust
ChainClient::new(spec) -> Result<Self, ChainError>
ChainClient::spec() -> &ChainSpec
ChainClient::id() -> ChainId
ChainClient::provider() -> Arc<RootProvider<Ethereum>>     // <- exposed!
ChainClient::chain_id() / block_number() / balance() / nonce()
ChainClient::code() / block_by_number() / block_latest()
ChainClient::tx_by_hash() / receipt() / trace_revert()
ChainClient::eth_call_capture_revert() / gas_price() / estimate_gas()
ChainClient::fee_history() / send_raw()
ChainClient::erc20_decimals/balance/allowance/symbol()
ChainClient::supports_interface() / nft_detect()
ChainClient::erc721_owner_of/balance_of/get_approved/token_uri/name/symbol/total_supply()
ChainClient::erc1155_balance_of/uri()
ChainClient::is_approved_for_all()
ChainClient::eth_get_storage_at()
ChainClient::get_logs()
ChainClient::eth_call_with_overrides()
ChainClient::eth_call_at_block()
ChainClient::debug_trace_call()
```

`provider()` is a leak: the watch executor calls
`client.provider().get_logs(&filter)` directly (executor.rs:406). The
ENS crate calls `self.provider.provider()` five times. Any new
abstraction must keep `provider()` returning *something* that satisfies
`alloy::providers::Provider<Ethereum>` — a trait, not a concrete type.

**Errors.** `ChainError` already has `Transport`, `Rpc`, `NotFound`,
`Url`, `Decode`, `NoEndpoints`. We can extend with one more variant
(`AllEndpointsFailed`) without breaking matchers — every match on the
type uses `Err(_)` or wildcards.

**No retry/timeout/backoff** lives in `bloom-chain`. The only existing
timeout is in `bloom-vfs/src/handlers/status.rs:191` (a `PING_TIMEOUT`
guard around `client.block_number()` for the status probe). That probe
caches per-chain in a 5-minute TTL.

### A.2 `crates/bloom-watch/src/executor.rs`

The polling loop:

- `WatchExecutor::start()` spawns one tokio task running a
  `tokio::time::interval(self.tick)` (default 2 s, `MissedTickBehavior::Delay`).
- Each tick, `tick_once` walks every `WatchSpec` from the registry and
  dispatches to `process_spec`.
- `process_spec` per kind:
  - `Balance`: `client.balance(addr)` and diffs against in-memory map.
  - `Block`: `client.block_number()`, then writes one record per advanced
    block.
  - `GasPrice`: `client.gas_price()`, diffs.
  - `Event`: `client.block_number()` followed by
    `client.provider().get_logs(&Filter)` from `last_seen + 1` to head.

What WS would replace:

| Watch kind   | Today (poll)                                 | WS subscription |
|--------------|----------------------------------------------|-----------------|
| `Block`      | `eth_blockNumber` every 2 s                   | `newHeads`      |
| `Event`      | `block_number` then `eth_getLogs(from..to)`   | `logs(filter)`  |
| `Balance`    | `eth_getBalance` every 2 s                    | (no WS) — keep poll, but trigger on `newHeads` |
| `GasPrice`   | `eth_gasPrice` every 2 s                      | (no WS) — keep poll, but trigger on `newHeads` |

Both `Balance` and `GasPrice` should hang off a shared `newHeads`
subscription rather than spinning their own tickers; if WS isn't
available the executor stays on the wall-clock interval.

### A.3 Provider/transport instantiation across the workspace

```
crates/bloom-chain/src/lib.rs:138    RootProvider::<Ethereum>::new_http(url)   // sole real instantiation
```

`grep` finds no other `ProviderBuilder::new`, `WsConnect`, `new_ws`,
or `connect_ws` anywhere in `crates/`. Every chain consumer goes
through `ChainClient` — confirmed by the call-site grep showing 27 hits
for `ChainClient::new` and 7 hits for `.provider()`. This is a clean
choke-point: changing what `RootProvider<Ethereum>` is built from
flows everywhere.

### A.4 Existing health / timeout / retry handling

- **None inside `bloom-chain`.**
- `bloom-vfs/src/handlers/status.rs` has its own `probe_chain` with a
  `PING_TIMEOUT` and 5-minute cache. This is observation only, not a
  health driver.
- `bloom-etherscan/src/lib.rs` configures a `request_timeout` on its
  reqwest client (15 s default). That is not RPC-relevant.
- Daemon (`crates/bloom-daemon/src/lib.rs:90-100`) builds clients in a
  loop and `warn!` skips on error. After construction nothing else
  monitors them.
- Watch executor only logs `warn!("watch.spec.error")` and continues —
  no exponential backoff, no per-endpoint awareness.

---

## B. Library evaluation

### B.1 What alloy 2.0.4 ships (workspace pins `alloy = "2"`, lockfile resolves to 2.0.4)

`alloy::transports::layers` (re-export from `alloy_transport`):

| Layer                 | Function | Already in workspace via `full` feature |
|-----------------------|----------|------|
| `RetryBackoffLayer`   | Tower layer that retries on `is_retryable()` errors with backoff and respects `backoff_hint()`. Ships with `RateLimitRetryPolicy` (429, -32007 quicknode, "rate limited, try again in 4ms", Infura `data.rate.backoff_seconds`, `null` resp). Composable: `RateLimitRetryPolicy.or(closure)`. | yes |
| `FallbackLayer`       | Tower layer over `Vec<Transport>` that scores each transport (70% stability, 30% latency, 10-sample rolling window) and queries the top-N in parallel. Returns first success. Has a `sequential_methods` carve-out for `eth_sendRawTransactionSync` style RPCs. | yes |
| `ThrottleLayer`       | `governor`-backed token-bucket throttle. Behind `transport-throttle` feature (NOT in `full`). | no — needs feature toggle |

`alloy::providers::ProviderBuilder` accepts arbitrary tower layers
via `.layer(...)` and a `connect_*()` family that produces an
`RpcClient`. WS subscriptions use `alloy_transport_ws::WsConnect`
behind `provider-ws` (in `full`).

**Subscription primitives** (provider trait):

- `subscribe_blocks() -> GetSubscription<.., HeaderResponse>` — newHeads.
- `subscribe_logs(&Filter)` — eth_subscribe(logs, filter).
- `subscribe_pending_transactions()`.
- HTTP-only fallback siblings: `watch_blocks()`, `watch_logs()`,
  `watch_headers()` use `eth_newFilter` + `eth_getFilterChanges` polling
  under the hood and return a `FilterPollerBuilder`.

The key alloy gap is: **fallback only at the transport layer**. The
`FallbackService` queries the top-N transports in parallel for the
*same* JSON-RPC call. It picks "first success" by latency, but it does
**not** coordinate semantic state across calls. If you call
`get_block_number()` (provider A wins, returns 100), then
`get_balance(addr)` a moment later (provider B wins, sees block 99),
you observe a regression. alloy makes no guarantee here.

### B.2 Gaps alloy does not cover

1. **Vendor-specific health labels.** `RateLimitRetryPolicy` already
   covers the common patterns, but: Infura's `-32005` daily-cap, the
   Alchemy CU-exhaustion error string, public-RPC 503 patterns are
   inconsistently surfaced across providers. We need to layer Bloom
   policy on top of `RateLimitRetryPolicy.or(...)`.
2. **State drift / cross-provider consistency.** No primitive. Must be
   a Bloom-owned layer.
3. **Sticky sessions.** `FallbackService` re-evaluates the top-N every
   call. We want a way to say "stick to one transport for these N
   calls" for read consistency.
4. **Active health probes.** Layer is passive: it only learns from
   real traffic. A provider that sees zero traffic stays at score
   `0.0` (initial neutral). We want a periodic `eth_blockNumber`
   probe so we don't fail over to a dead URL on the first user call.
5. **WS lifecycle.** WS reconnect is built into `alloy-pubsub` for
   transient drops, but Bloom needs to *demote* a provider to poll if
   WS is permanently broken (not just every reconnect).
6. **Per-provider weights.** alloy fallback doesn't accept weights,
   only top-N count.

### B.3 Recommendation: extend with a wrapping layer in a new module

**Pick:** Add a new module `crates/bloom-chain/src/rpc/` (no new crate
yet). Build the alloy layer stack inside `ChainClient::new`. Add a
**`Session` type** for state-drift control. Defer a separate
`bloom-rpc` crate until we either (a) want pub use beyond bloom, or
(b) the module exceeds ~1500 lines.

Rationale:

- `bloom-chain` is already the only consumer of `RootProvider`.
  Extracting now creates a circular concern: `bloom-chain` would
  re-export the new crate's types verbatim because the call sites
  call `client.balance()`, not `pool.balance()`.
- Putting the pool inside `bloom-chain` keeps the diff small. The new
  module pattern (file per concern: `rpc/transport.rs`,
  `rpc/health.rs`, `rpc/session.rs`) signals "this could be its own
  crate" if usage grows.
- The user gave us an explicit out: "if [state drift] is too hard we
  may need a custom crate that aggregates rpc providers and acts as a
  single source of truth." The phased plan in §E gates the new-crate
  decision on whether the session abstraction works for callers.

Tradeoffs:

| Approach                     | Pro | Con |
|------------------------------|-----|-----|
| Use alloy `FallbackLayer` directly, no Bloom code | minimum work, ~50 LOC change | no state-drift solution; rate-limit policy stuck on default; no active probes |
| Wrapping module in `bloom-chain` (recommended) | one place to evolve; reuses alloy primitives where they suffice | mixes "RPC engine" concerns into a crate that also has chain semantics |
| New `bloom-rpc` crate | clean boundary, reusable | premature; forces every other crate to add a dep just for `Provider` shape |

---

## C. Proposed architecture

### C.1 Module / file layout

```
crates/bloom-chain/src/
├── lib.rs                       // ChainClient (slimmed: kept signatures, body delegates to rpc::*)
└── rpc/
    ├── mod.rs                   // pub use's; the "engine" surface
    ├── transport.rs             // builds the alloy ServiceBuilder stack per chain
    ├── endpoint.rs              // EndpointSpec, parsing, scheme detection (http/https/ws/wss)
    ├── health.rs                // EndpointHealth, scoring, cooldowns, probe loop
    ├── policy.rs                // BloomRetryPolicy: extends RateLimitRetryPolicy.or(...)
    ├── session.rs               // Session type for block-pinned reads
    └── tests.rs                 // unit tests against MockTransport
```

`crates/bloom-watch/src/`
- `executor.rs` — gain a fast-path that prefers `subscribe_blocks` /
  `subscribe_logs` when the chain's primary transport is WS-capable;
  the existing tick loop becomes the fallback.

`crates/bloom-proto/src/chain.rs`
- Extend `ChainSpec` with optional `rpc_endpoints: Vec<EndpointSpec>`
  (richer schema), keeping `rpc_urls: Vec<String>` for backward
  compatibility — see §C.7.

### C.2 Type sketches

#### `EndpointSpec` (in `bloom-proto/src/chain.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSpec {
    /// `http://`, `https://`, `ws://`, `wss://`, or `ipc:///path`.
    pub url: String,
    /// Higher number = preferred. Defaults to a stable order from input.
    #[serde(default = "default_endpoint_weight")]
    pub weight: u32,
    /// Compute-units-per-second budget (Alchemy/Infura convention).
    /// Used by RetryBackoffLayer for per-endpoint pacing.
    #[serde(default)]
    pub cu_per_sec: Option<u64>,
    /// Optional throttle ceiling. None = disabled.
    #[serde(default)]
    pub max_rps: Option<u32>,
    /// If true, this endpoint is excluded from `subscribe_*` and only
    /// used for HTTP RPC. Useful when a vendor charges WS separately.
    #[serde(default)]
    pub http_only: bool,
}

fn default_endpoint_weight() -> u32 { 100 }
```

`ChainSpec` stays source-compatible:

```rust
pub struct ChainSpec {
    pub name: String,
    pub chain_id: u64,
    /// Legacy: flat URL list. If `rpc_endpoints` is empty, every entry
    /// here is mapped to a default `EndpointSpec` and ordered by index.
    pub rpc_urls: Vec<String>,
    /// New: rich endpoint schema. Wins over `rpc_urls` when non-empty.
    #[serde(default)]
    pub rpc_endpoints: Vec<EndpointSpec>,
    // ... rest unchanged
}

impl ChainSpec {
    /// Single source of truth for the rpc layer.
    pub fn endpoints(&self) -> Vec<EndpointSpec> {
        if !self.rpc_endpoints.is_empty() {
            return self.rpc_endpoints.clone();
        }
        self.rpc_urls
            .iter()
            .enumerate()
            .map(|(i, u)| EndpointSpec {
                url: u.clone(),
                weight: 100u32.saturating_sub(i as u32), // earlier wins
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            })
            .collect()
    }
}
```

#### `EndpointHealth` (in `rpc/health.rs`)

```rust
pub struct EndpointHealth {
    /// Cooldown imposed on the endpoint (e.g. 429 with backoff hint).
    cooldown_until: Option<Instant>,
    /// EWMA latency.
    avg_latency: Duration,
    /// Sliding success rate (10 samples, like alloy's FallbackService).
    sample_window: VecDeque<bool>,
    /// Last observed `eth_blockNumber` (for state-drift coordination).
    last_block: Option<u64>,
    /// Last successful response time.
    last_ok: Option<Instant>,
}
```

Note: alloy's `FallbackService` already tracks success/latency
internally, but those metrics are private to the layer. Bloom keeps a
parallel `EndpointHealth` view because:

- We want active probes (alloy's metrics only update on traffic).
- We want to show health in `status/chains/<name>/endpoints/*` VFS
  paths so operators see what's happening.
- We want a `cooldown_until` field that disables an endpoint
  unconditionally (alloy's failover continues to query a hot endpoint
  in parallel).

#### `BloomRetryPolicy` (in `rpc/policy.rs`)

```rust
use alloy::transports::layers::{RateLimitRetryPolicy, RetryPolicy};

#[derive(Debug, Clone, Default)]
pub struct BloomRetryPolicy {
    inner: RateLimitRetryPolicy,
}

impl RetryPolicy for BloomRetryPolicy {
    fn should_retry(&self, e: &TransportError) -> bool {
        if self.inner.should_retry(e) { return true; }
        // Vendor-specific patterns alloy doesn't already cover:
        // - Alchemy CU exhaustion → "exceeded its compute units"
        // - Infura `-32005` data.rate (covered by alloy already, retain belt-and-braces)
        // - QuickNode -32007 (covered)
        // - Public RPC 503 (covered as is_temporarily_unavailable)
        // - 408 timeout (alloy currently doesn't retry these)
        if let TransportError::Transport(TransportErrorKind::HttpError(h)) = e {
            if h.status == 408 || h.status == 502 || h.status == 504 { return true; }
        }
        if let TransportError::ErrorResp(p) = e {
            // Alchemy free-tier compute-unit cap.
            if p.message.contains("exceeded its compute units") { return true; }
            // Generic "capacity" rejection used by some public endpoints.
            if p.message.contains("over rate limit") || p.message.contains("capacity") { return true; }
        }
        false
    }
    fn backoff_hint(&self, e: &TransportError) -> Option<Duration> {
        self.inner.backoff_hint(e)
    }
}
```

#### `Session` (in `rpc/session.rs`)

This is the state-drift escape hatch.

```rust
/// A short-lived handle that pins reads to a specific block hash so
/// multi-call operations stay self-consistent across a fallback event.
pub struct Session<'a> {
    client: &'a ChainClient,
    /// Block number captured when the session opened.
    pinned_number: u64,
    /// Block hash captured when the session opened.
    pinned_hash: BlockHash,
    /// Identifier of the transport that served the open call. Failover
    /// to a different transport mid-session is allowed *only if* the
    /// pinned hash is reachable there (gated by a small trial call).
    transport_id: TransportId,
    /// Toggled on if the session falls back to a degraded mode (e.g.,
    /// pinned hash unavailable on every other endpoint).
    degraded: bool,
}

impl ChainClient {
    /// Open a new pinned read session at `latest`. Inside the session
    /// every `*_at_session()` method passes `pinned_hash` as the
    /// `block` parameter so the answer doesn't drift if the underlying
    /// transport changes.
    pub async fn open_session(&self) -> Result<Session<'_>, ChainError>;
}

impl<'a> Session<'a> {
    pub fn block_number(&self) -> u64 { self.pinned_number }
    pub fn block_hash(&self) -> BlockHash { self.pinned_hash }
    pub fn is_degraded(&self) -> bool { self.degraded }

    pub async fn balance(&self, addr: Address) -> Result<U256, ChainError>;
    pub async fn nonce(&self, addr: Address) -> Result<u64, ChainError>;
    pub async fn code(&self, addr: Address) -> Result<Vec<u8>, ChainError>;
    pub async fn eth_call(&self, req: TransactionRequest) -> Result<Bytes, ChainError>;
    pub async fn get_storage_at(&self, addr: Address, slot: U256) -> Result<B256, ChainError>;
    // Note: NOT exposed at session — broadcast & block-tag-conflicting calls.
    //   send_raw, gas_price (latest by definition), estimate_gas (against pending).
}
```

### C.3 Consumer impact: `ChainClient` signature changes

Goal: keep the existing 30+ method signatures **identical**. Only
internals change.

- `pub fn provider(&self) -> Arc<RootProvider<Ethereum>>` —
  break-glass: keep but switch the inner type to a `BoxTransport`
  layered with the alloy stack. `RootProvider<Ethereum>` is generic
  over `T: Transport`; the workspace currently uses the default. A
  layered `RpcClient` is still a valid backing for `RootProvider::new(client)`.
- `pub fn new(spec: ChainSpec)` — body becomes "build endpoints,
  build per-endpoint transports, layer with retry, wrap in fallback,
  install into RpcClient, build RootProvider". Same signature.
- New convenience methods (additive):
  - `pub async fn open_session(&self) -> Result<Session<'_>, ChainError>`
  - `pub fn endpoints(&self) -> Vec<EndpointHealth>` — for the
    `status/chains/<n>/endpoints` VFS path.
  - `pub fn supports_subscriptions(&self) -> bool` — `true` if any
    endpoint is `ws://` or `wss://`.

Call sites in `bloom-watch`, `bloom-tx`, `bloom-vfs`, `bloom-ens`,
`bloom-defi`, `bloom-revert` do not change.

### C.4 `bloom-watch` WS fast path

```rust
// Pseudocode for executor::start_block_subscription
async fn run_block_loop(client: ChainClient, registry: Arc<WatchRegistry>, ...) {
    if client.supports_subscriptions() {
        match client.provider().subscribe_blocks().await {
            Ok(mut sub) => {
                while let Ok(header) = sub.recv().await {
                    self.on_new_head(header).await;
                }
                // Stream ended — fall through to poll loop.
                warn!("watch.subscribe_blocks.ended_falling_back_to_poll");
            }
            Err(e) => warn!(?e, "watch.subscribe_blocks.unavailable"),
        }
    }
    // Poll loop (existing logic).
    self.run_poll_loop().await;
}
```

Logs subscription:

- For each `WatchKind::Event` spec, allocate one `subscribe_logs(filter)`
  stream when `supports_subscriptions()` and the filter is "open-ended"
  (no fixed `to_block`).
- On stream end or error: revert to `eth_getLogs(from..head)` polling
  on the next tick. Use `last_seen_block + 1` as the resume point so
  we never lose logs across the transition.

Balance / GasPrice watch kinds keep polling but become reactive: when
a `newHeads` arrives they re-fetch immediately. The 2 s ticker becomes
a watchdog (max staleness when WS is dead) rather than the primary
clock.

### C.5 Rate-limit detection strategy

The transport stack per endpoint:

```
[RetryBackoffLayer with BloomRetryPolicy]
 ↓
[ThrottleLayer (only if endpoint.max_rps is Some)]
 ↓
[Http or Ws transport]
```

The fallback fan-out wraps a `Vec<S>` of these stacks:

```
[FallbackLayer with active_transport_count = min(2, endpoints.len())]
 ↓
[ Vec<endpoint stack #0>, Vec<endpoint stack #1>, ... ]
```

Detection signals (all consumed by `BloomRetryPolicy::should_retry`):

| Signal | Source | Action |
|--------|--------|--------|
| HTTP 429                              | `HttpError::is_rate_limit_err` | retry with `backoff_hint` (parsed from body or default 1 s) |
| HTTP 503                              | `HttpError::is_temporarily_unavailable` | retry |
| HTTP 408 / 502 / 504                  | new in `BloomRetryPolicy`       | retry |
| JSON-RPC `-32005` (`rate limited`)    | alloy `is_retry_err`           | retry, parse `try again in Xms` |
| JSON-RPC `-32007` (QuickNode rate)    | alloy                          | retry |
| JSON-RPC `429`                        | alloy                          | retry |
| Infura `data.rate.backoff_seconds`    | alloy `backoff_hint`           | sleep then retry |
| Alchemy "exceeded its compute units"  | new in `BloomRetryPolicy`       | retry once, then mark cooldown |
| Generic "over rate limit"             | new                            | retry |

Cooldowns (Bloom-side, separate from alloy's per-call retry):

- After **N** rate-limit events from one endpoint within window **W**
  (defaults: N=3, W=10 s), set
  `EndpointHealth::cooldown_until = now + 30 s`.
- The fallback fan-out filter excludes endpoints whose cooldown has
  not expired before sorting by score.
- Half-open recovery: every 15 s, the active-probe task issues a
  single `eth_blockNumber` against each cooled-down endpoint. Two
  consecutive successes clear the cooldown.

### C.6 State-drift strategy: hybrid (block-pinning + sticky sessions)

We commit to one of the four options the task laid out. **Pick:
hybrid.**

- **Default for one-shot reads:** stay with `FallbackLayer`'s
  parallel-top-N. State drift between two consecutive reads is
  expected; that's the same semantics every alloy user gets today.
  Most Bloom read paths (VFS leaf reads, watch sampling) tolerate
  this — they look at one number and present it.
- **Read sessions** (block-pinning): `ChainClient::open_session()`
  freezes a `(block_number, block_hash)` pair. All session-scoped
  calls pass `block_id = pinned_hash`. Failover *during* a session is
  allowed because hashes are universal — if the pinned hash is in a
  different provider's chain, the call will error out cleanly with
  `eth_blockHash not found` and we mark the session degraded.
  Use this for any logical operation that fans out to >1 RPC call:
    - `bloom-tx::TxEngine::stage_*` — pin once, read nonce + balance +
      gas-price + chain-id + code from the same block.
    - `simulate.rs::eth_call` chains.
    - `bloom-vfs/handlers/chains.rs` aggregate "address summary" pages.
- **Sticky tail** (sticky session): when `bloom-watch` opens a
  `subscribe_blocks` stream, the resulting `WatchTail` sticks to that
  transport. Failover happens only at stream re-establishment, not on
  every event. This avoids reordering and missed-log races where two
  providers return different `logIndex` values for the same block.

**Rejected options:**

- *Block-tag pinning alone* — doesn't help live tailing.
- *Sticky-provider sessions alone* — sticky is fine for streams but
  for read fanout it pessimizes latency (one-fast-one-slow loses the
  parallel benefit).
- *Aggregator/quorum* — too expensive and orthogonal to the user's
  primary need (correct balance reads). It is the user's stated
  fallback if pinning is "too hard"; pinning isn't too hard, so we
  defer this. Captured as Future Work.

The **degraded** flag on `Session` is the user-visible escape: if a
session can no longer find its pinned hash on any healthy endpoint
(can happen if all endpoints are rate-limited, or when reorgs evict
the hash), the session falls back to `latest` and surfaces
`is_degraded() == true`. Callers that care about strict consistency
can re-open; callers that don't can proceed.

### C.7 Health checking: passive + active

**Passive.** Every call updates the corresponding `EndpointHealth`:

- success → push `true` into `sample_window`, update EWMA latency.
- failure → push `false`. If `should_retry()` returns true and the
  error has a backoff hint, set `cooldown_until = now + hint`.

**Active probe loop** (one tokio task per `ChainClient`, spawned in
`new`):

```
loop {
    sleep(15s);
    for ep in self.endpoints.iter() {
        // Direct probe — bypass fallback; talks to this endpoint only.
        let res = timeout(2s, ep.transport.call(eth_blockNumber)).await;
        update health(ep, res);
        // Eviction: 5 consecutive failures sets cooldown 60s.
        // Recovery: 2 consecutive successes during cooldown clears it.
    }
}
```

Eviction policy:

- 5 consecutive failures → cooldown 60 s.
- 1 success during cooldown → reset failure counter.
- 2 consecutive successes → clear cooldown.
- 3 strikes within 5 minutes after recovery → cooldown 10 minutes
  (chronic-failer escalation).

### C.8 Configuration shape

The user's `~/.bloom/config.toml` today:

```toml
[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["https://mainnet.base.org", "https://base.publicnode.com"]
allow_broadcast = false
```

After the change, both forms work:

```toml
# Legacy (still valid)
[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["https://mainnet.base.org", "https://base.publicnode.com"]
allow_broadcast = false

# Rich
[chains.base]
name = "base"
chain_id = 8453
allow_broadcast = false
rpc_urls = []  # tolerated when rpc_endpoints is non-empty

[[chains.base.rpc_endpoints]]
url = "wss://base-mainnet.g.alchemy.com/v2/$KEY"
weight = 200
cu_per_sec = 660

[[chains.base.rpc_endpoints]]
url = "https://base.publicnode.com"
weight = 100
max_rps = 25

[[chains.base.rpc_endpoints]]
url = "https://mainnet.base.org"
weight = 50
http_only = true
```

`Config::validate` updates: an `rpc_urls` empty list is allowed iff
`rpc_endpoints` is non-empty, and vice versa. At least one healthy
URL/endpoint must exist.

### C.9 `provider()` accessor

The current `pub fn provider(&self) -> Arc<RootProvider<Ethereum>>` is
called by `bloom-ens` and `bloom-watch`. Keep the signature. The new
internals build `RootProvider::new(rpc_client)` where `rpc_client` was
constructed from a layered `ServiceBuilder`. `RootProvider<Ethereum>`
is a `pub struct` parameterised by network — its concrete type doesn't
change, only the inner transport.

---

## D. Test strategy

### D.1 Unit (no network)

Located in `crates/bloom-chain/src/rpc/tests.rs`. Use alloy's
`MockTransport` (the same testing tool `alloy-transport`'s own
`fallback.rs` uses).

- `endpoint_spec_back_compat`: a `ChainSpec` with only `rpc_urls`
  yields the same endpoint vector as one with the equivalent
  `rpc_endpoints`.
- `retry_policy_handles_alchemy_cu`: a mocked
  `TransportError::ErrorResp(message="exceeded its compute units")`
  returns `should_retry == true`.
- `retry_policy_passes_through_alloy_default`: 429 / -32005 cases the
  alloy policy already covers still trigger `should_retry == true`
  (regression sentinel).
- `endpoint_health_records_success_failure`: passive metric updates
  shape correctly under simulated traffic.
- `cooldown_evicts_endpoint_from_fallback_pool`: `top_transports()`
  override skips endpoints with active cooldown.
- `session_pins_block_hash`: a mock returns block 100 on
  `eth_blockNumber`, 99 on the next call. A session opened at the
  first call and used to read `balance` passes `pinned_hash` and
  receives 100's balance, not 99's.

### D.2 Integration against anvil

Anvil supports HTTP and WS. `crates/bloom-it/tests/` already runs
real anvil for several scenarios (`anvil_e2e.rs`, `erc20_e2e.rs`).

New test files:

- `crates/bloom-it/tests/rpc_failover.rs`:
  - Spawn two anvil instances, each on its own port.
  - Build `ChainSpec` with both URLs.
  - Issue 50 sequential `block_number()` calls.
  - Halfway through, kill anvil #1 with `Child::kill`.
  - Assert the next call still succeeds (hits anvil #2) within < 1 s.
  - Assert `client.endpoints()` shows anvil #1 cooled down.

- `crates/bloom-it/tests/rpc_ws_subscriptions.rs`:
  - Spawn anvil with `--port 0`, get the ws URL.
  - `subscribe_blocks()`, mine 3 blocks via anvil RPC (`anvil_mine`),
    assert 3 headers received within 5 s.
  - Drop anvil, re-spawn; assert subscription either reconnects (if
    in-scope) or surfaces a `BackendGone` and the watch loop falls
    back to poll.

- `crates/bloom-it/tests/rpc_state_drift.rs`:
  - Spawn anvil A and B. Mine 5 blocks on A, 3 on B.
  - Build a `ChainSpec` with both. Open a session.
  - Assert `session.block_number()` matches whichever anvil "won" the
    open call (record the value).
  - Read `balance` 10 times within the session — every result is at
    the pinned block (verify by checking `block_id` matches across
    all calls; do this with an instrumented MockTransport sandwiched
    in if anvil doesn't expose enough).
  - Mine more blocks on the winning anvil. The session-scoped reads
    must still return the pinned-block balance, not the new head.

### D.3 Rate-limit fake transport

A `FakeRateLimitTransport` in `rpc/tests.rs` that returns 429 for the
first M calls, then succeeds. Test:

- The retry layer keeps the call alive until success.
- Over the cooldown threshold the endpoint is evicted from the
  fallback pool — the fan-out goes to the second endpoint instantly.
- After the cooldown plus 2 successful active probes the endpoint
  rejoins the pool.

### D.4 WS subscription flap test

Anvil 0.2 doesn't ship a "drop ws" knob; simulate by killing anvil
mid-subscription. Assert the watch executor:

- Does not panic.
- Logs `watch.subscribe_blocks.ended_falling_back_to_poll`.
- Resumes block tracking in the poll loop within 1 tick after the
  subscription died (block height monotonic, no missed blocks).

### D.5 State-drift test against two anvil instances at different heights

Covered by `rpc_state_drift.rs` above. Key assertion: even when the
underlying fallback layer flip-flops between transports, the session
methods see one consistent block.

---

## E. Phased implementation plan

Five work packages. Targets ~30 min each for a focused agent. Order
matters where called out; otherwise parallelisable.

### WP-1: Endpoint schema + back-compat shim — INDEPENDENT, START FIRST

**Touches:**
- `crates/bloom-proto/src/chain.rs`: add `EndpointSpec`, add
  `ChainSpec::rpc_endpoints`, add `ChainSpec::endpoints()` derivation.
- `crates/bloom-proto/src/config.rs::Config::validate`: relax the
  "rpc_urls non-empty" check to "either rpc_urls or rpc_endpoints".
- `crates/bloom-proto/src/chain.rs` tests: add round-trip tests for
  the new field, including a TOML containing only `rpc_endpoints`,
  only `rpc_urls`, and both.

**Tests added:** `chain_spec_endpoints_back_compat`,
`config_validates_with_only_endpoints`, `endpoints_round_trip_toml`.

**Leaves alone:** `ChainClient::new`, every consumer that uses
`spec.rpc_urls.first()` (they are read-only on the proto type).

**Why first:** every other package wants `ChainSpec::endpoints()`.

### WP-2: alloy stack + multi-endpoint failover — DEPENDS ON WP-1

**Touches:**
- `crates/bloom-chain/src/rpc/mod.rs`, `transport.rs`, `policy.rs`,
  `endpoint.rs`, `health.rs` (new files; `health.rs` here is a stub —
  full implementation in WP-3).
- `crates/bloom-chain/src/lib.rs::ChainClient::new`: replace
  `RootProvider::<Ethereum>::new_http(url)` with the layered stack.
- `crates/bloom-chain/Cargo.toml`: enable `transport-throttle` feature
  on `alloy` (workspace `alloy.features`). Confirm `governor` pulls
  cleanly under the workspace toolchain.

**Tests added:** in `rpc/tests.rs`: `retry_policy_extends_alloy`,
`fallback_with_two_endpoints`. In
`crates/bloom-it/tests/rpc_failover.rs`: full anvil-killed scenario.

**Leaves alone:** every method body on `ChainClient` (signatures
unchanged), `bloom-watch`, `bloom-tx`, `bloom-vfs`.

### WP-3: active health + cooldown observability — DEPENDS ON WP-2

**Touches:**
- `crates/bloom-chain/src/rpc/health.rs`: full `EndpointHealth`,
  scoring, cooldown state machine, active probe loop spawned in
  `ChainClient::new`.
- `crates/bloom-chain/src/lib.rs`: add `pub fn endpoints(&self) ->
  Vec<EndpointHealthSnapshot>`.
- `crates/bloom-vfs/src/handlers/status.rs`: new VFS leaves
  `chains/<n>/endpoints/<idx>/{url,score,cooldown_until,latency_ms,success_rate}`.
  Existing `chains/<n>/{rpc_url,connected,block_number}` keep working
  by reading from the first/winning endpoint.

**Tests added:** `cooldown_eviction`, `recovery_after_two_probes`,
`status_endpoints_leaf`.

**Leaves alone:** the alloy stack from WP-2; only adds a sibling probe
task that doesn't intercept calls.

### WP-4: WebSocket subscriptions in `bloom-watch` — INDEPENDENT OF WP-3, NEEDS WP-2

**Touches:**
- `crates/bloom-chain/src/lib.rs`: add
  `pub fn supports_subscriptions(&self) -> bool`.
- `crates/bloom-watch/src/executor.rs`: split `start` into
  `start_block_loop`, `start_log_loop`, etc., each one preferring
  `subscribe_*` then falling back to the existing tick path. Reuse
  the existing `process_spec` body for the poll fallback.
- `crates/bloom-watch/Cargo.toml`: no new deps (alloy `full` already
  has `pubsub`).

**Tests added:**
- `crates/bloom-it/tests/rpc_ws_subscriptions.rs`.
- Unit: a test that uses a fake `RpcClient` reporting
  `supports_subscriptions == false` and asserts the existing poll
  loop kicks in unchanged.

**Leaves alone:** `WatchKind::Balance`, `WatchKind::GasPrice`'s actual
sampling code (they keep the poll body but become triggered by
`newHeads` when WS works).

### WP-5: `Session` for state-pinned reads — DEPENDS ON WP-2, OPTIONALLY WP-3

**Touches:**
- `crates/bloom-chain/src/rpc/session.rs`: full `Session` impl.
- `crates/bloom-chain/src/lib.rs`: `pub async fn open_session(&self)`.
- `crates/bloom-tx/src/tx_engine.rs::TxEngine::stage_*`: opt-in
  conversion of the multi-call bundle (`nonce + balance + gas_price +
  code + chain_id`) to use a session. Behind a feature flag /
  config toggle, defaulted on. The user can revert to the current
  best-effort semantics by setting `[backends] tx_session = false`
  (new optional field).
- `crates/bloom-it/tests/rpc_state_drift.rs`: new integration test.

**Tests added:** `session_pins_hash_across_calls`,
`session_degrades_when_hash_unavailable`,
`tx_engine_stages_are_consistent_across_provider_failover`.

**Leaves alone:** `bloom-watch` (uses sticky-stream, not sessions),
read paths in `bloom-vfs` that don't span calls.

### Sequencing diagram

```
WP-1 (endpoint schema) ──┬──> WP-2 (alloy stack) ──┬──> WP-3 (health probes / VFS leaves)
                          │                          ├──> WP-4 (ws subscriptions)
                          │                          └──> WP-5 (session)
                          └──> [config tests, no other deps]
```

WP-3, WP-4, WP-5 can run in parallel after WP-2 lands.

---

## F. Risks and unknowns

### F.1 Decisions the user owns

1. **New crate or stay in `bloom-chain`?** Recommendation: stay in
   `bloom-chain` under `rpc/` for the first cut. If the module exceeds
   ~1500 LOC or `bloom-defi` / `bloom-ens` start wanting it standalone,
   extract to `bloom-rpc` later. Either path works; downstream code
   doesn't care because everyone goes through `ChainClient`.
2. **Aggregator/quorum mode.** Punted to Future Work. The user
   accepted this would only be triggered if pinning was too hard.
   Pinning is straightforward; quorum stays as a documented escape
   hatch.
3. **Per-feature backend toggle for sessions.** WP-5 proposes a
   `[backends] tx_session = true|false` knob. This is opinionated —
   the user might want sessions on by default with no opt-out. Call
   out before implementing.
4. **Throttle layer on by default?** `alloy-transport`'s throttle
   needs `governor` and the `transport-throttle` feature. Cheap to
   add but adds compile time. Recommendation: enable, keep
   `EndpointSpec::max_rps = None` as default (no-op).

### F.2 Unknowns from the source

- **`subscribe_logs` reorg semantics on alloy 2.0.4.** alloy claims
  to surface logs as they arrive but does not offer chain-reorg
  re-emission. `WatchKind::Event` consumers may need to handle the
  same `(blockHash, logIndex)` arriving twice during a reorg. The
  current poll loop deduplicates implicitly because it pulls from
  `last_seen + 1` and the reorged blocks resolve before re-query.
  Decision needed: do we keep dedup state in the watch executor's
  `state.event_block` map across the WS path, or do we trust alloy?
  Suggested: keep our own `(blockHash, logIndex)` set with a small
  ring buffer (last 64 blocks) regardless.
- **`RootProvider<Ethereum>` exposure stability.** alloy 2.x is
  pre-1.0. If alloy bumps and `RootProvider` becomes `RootProvider<N,
  T>`, our `pub fn provider() -> Arc<RootProvider<Ethereum>>` will
  break the leak we exposed to `bloom-ens` and `bloom-watch`. Consider
  hiding behind a sealed trait `pub trait BloomProvider:
  alloy::providers::Provider<Ethereum>` so we can change the
  underlying type without API churn. **Not required for v1**, but
  worth a docstring warning.
- **Anvil WS reconnect.** In tests we kill anvil mid-stream. Need to
  validate empirically that alloy's pubsub front-end surfaces a
  closed-stream error rather than hanging — quick verification step
  during WP-4.
- **`is_local()` heuristic.** alloy tags HTTP transports as "local"
  when the URL is loopback. Our anvil-based tests should confirm the
  fallback layer does not deprioritise local endpoints in surprising
  ways, since several integration tests run with one anvil URL.
- **`debug_traceCall` failover safety.** Some endpoints (Alchemy free
  tier, Infura) reject `debug_traceCall` with `method not supported`.
  The fallback layer treats this as a failure and rotates. Per
  `BloomRetryPolicy`, "method not supported" should NOT be retried —
  it's deterministic. Audit the alloy policy: by default it does
  not retry method-not-supported, so we are safe, but worth a unit
  test to pin behaviour.

### F.3 Migration risks

- `ChainSpec::rpc_urls` is read in 18 sites (test fixtures, status
  handler, audit). All of these should be migrated to
  `ChainSpec::endpoints()` for forward compatibility, but doing so is
  a separate cleanup that doesn't block functional work. Status
  handler's `redact_url` becomes "redact each endpoint URL" — easy.
- `crates/bloom-chain/src/lib.rs::tests::missing_endpoints_error`
  expects an error when `rpc_urls` is empty. After WP-1, with
  `rpc_endpoints` also empty, the same error fires. Update assertion
  to test both paths.

---

## Future work (out of scope for v1)

- **Aggregator/quorum mode** for chains where the user is willing to
  trade latency for cross-provider consistency. Needs a new
  `AggregatedTransport` that fans every call to N transports and
  reconciles by median of `eth_blockNumber`, equality vote on
  receipts, etc. Worth doing if the user runs alongside untrusted
  public RPC fleets.
- **Per-method routing.** Some methods (`debug_traceCall`,
  `trace_filter`) are only available on archive endpoints. A future
  router can match `endpoint.capabilities` (a bitfield in
  `EndpointSpec`) and skip non-archive endpoints for archive-only
  methods.
- **IPC transport.** Alloy ships it; trivial to add to
  `EndpointSpec`'s URL parser. Useful for self-hosted reth.
- **Persistent health log.** Today `EndpointHealth` lives in memory.
  A future patch can write a small jsonl history into
  `~/.bloom/rpc-health/<chain>.jsonl` so operators can audit
  flap patterns across daemon restarts.
- **Operator-driven cooldown override.** A VFS write to
  `chains/<n>/endpoints/<idx>/cooldown` that pauses an endpoint for
  N seconds without restarting the daemon.
