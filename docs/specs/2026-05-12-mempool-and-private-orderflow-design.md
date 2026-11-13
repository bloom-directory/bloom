# bloom-eth: Mempool, Private Orderflow, Gas-Bump & MEV Warnings

**Status:** draft
**Date:** 2026-05-12
**Owners:** —
**Addresses:** README.md:167 ("Mempool surface not implemented") and the
v1 non-goal at `docs/specs/2026-05-08-bloom-eth-design.md:78`
("MEV / Flashbots bundles, private mempool").

## 1. Goals

Bring five currently-deferred subsystems online and stitch them through
the existing VFS, tx engine, and policy surfaces:

1. **Mempool observability** — a `chains/<chain>/mempool/` read tree
   backed by a pluggable `MempoolProvider` (Alchemy adapter shipped
   first; generic `eth_subscribe` shipped alongside as a portable
   fallback).
2. **Nonce-conflict detection & external-pending visibility** for
   managed wallets — derived from the mempool index.
3. **Gas-bump suggestions** — a background scanner that surfaces an
   advisory `bump.tx` next to any stuck `sent/<hash>/` entry. The
   artefact describes the recommended replacement (bumped fees, same
   nonce) but is not directly stage-able as a `RawIntent` today;
   stage-ability would require extending `RawIntent` with explicit
   fee overrides (a follow-up). Never auto-broadcasts; same
   stage-confirm invariant as every other tx.
4. **Private orderflow** — per-wallet `private.enabled = true` flag
   that routes broadcast through a `PrivateRpcProvider` (MEV-Blocker
   default, Flashbots Protect second). Mainnet-only — enforced by
   the trait's `supported_chains()`, not a config knob.
5. **Stage-time MEV/sandwich heuristic** — pure function over a staged
   DEX swap that flags slippage exposure. Surfaces as
   `pending/<id>/mev_risk.json` and a line in `plan.md`.

## 2. Non-goals (still STRETCH for v1)

- Multi-tx Flashbots/MEV-Share **bundles** (`eth_sendBundle`,
  `mev_sendBundle`). The spec assumes single-tx private submission
  only.
- **Auto-bumping** — the daemon never resubmits a tx on its own. The
  bump scanner only writes an advisory artefact (see §6 — not directly
  stageable as `RawIntent` today; an agent reads the advice and
  synthesises a fresh send-style intent).
- **Post-broadcast MEV detection** — no fingerprinting of mined blocks
  for sandwich evidence. Heuristic is stage-time-only.
- **Cross-pending-cross-check** — the MEV heuristic does not consult
  the mempool stream for opposing swaps in flight. Pure local check.
- L2 sequencer integrations beyond what the chain's standard RPC
  exposes. Base and Optimism already use private sequencer mempools;
  on those chains the mempool tree returns a clear "not applicable"
  status by default.

## 3. Background

### 3.1 Existing infrastructure we build on

- **`bloom-rpc` already classifies WS endpoints** (`endpoint.rs:18`,
  `is_subscription_capable`) and the watch executor already maintains
  a `subscribe_*` long-poll task with WS-to-HTTP-poll fallback
  (`bloom-watch/src/executor.rs:444`). We re-use the same pattern.
- **`bloom-tx::outbox` already implements** `replace` and `cancel`
  state transitions (lines 240–281). The bump scanner produces inputs
  to those transitions; it doesn't duplicate them.
- **`policy_engine.rs` already gates staging** with per-tx ETH/USD
  caps and `auto_confirm_below_eth`. We add `[private]`, `[mev]`,
  `[bump]` tables alongside.
- **`status/backends/<feature>`** is the existing self-declaration
  surface for "what's wired where" (README §[backends]). We add
  `mempool` and `private_rpc` to it.

### 3.2 Provider-landscape research (2026-05-12)

A May 2025 published benchmark (arXiv 2505.19708, *Private MEV
Protection RPCs: Benchmark Study*) compares MEV-Blocker, Flashbots
Protect, Blink, and Merkle. Findings:

- **MEV-Blocker wins on inclusion rate, time-to-inclusion, execution
  quality, and rebates.** Flashbots Protect is competitive on
  inclusion but ~21 bps worse on execution price (statistically
  significant in the study) and pays ~half the rebate.
- **Merkle and Blink** lag on inclusion (~70 %) because their per-tx
  fee models distort builder behaviour.
- **MEV-Blocker** was acquired by Consensys Special Mechanisms Group
  in January 2026 — institutional backing.
- Best-practice guidance from the broader community: **diversify**
  (rotate between providers; keep a public RPC as fallback).

bloom-eth's response: ship MEV-Blocker as the default
`PrivateRpcProvider` and Flashbots Protect as a second adapter,
behind a trait that accommodates future additions and a future
rotate-mode without re-architecting.

## 4. Architecture

### 4.1 Crate layout

One new crate, three existing crates extended.

```
bloom-mempool (NEW)
├── provider.rs       MempoolProvider trait + adapters
│                       - AlchemyProvider (full bodies, alchemy_pendingTransactions)
│                       - GenericEthSubscribeProvider (hashes only; follows up via RpcPool)
├── private.rs        PrivateRpcProvider trait + adapters
│                       - MevBlockerProvider (rpc.mevblocker.io)
│                       - FlashbotsProvider (rpc.flashbots.net/fast)
├── index.rs          PendingTxIndex — in-memory, keyed by hash and (addr, nonce)
├── stream.rs         MempoolStream task: subscribe + reconnect + dedupe + fan-out
├── heuristic.rs      Stage-time MEV/sandwich heuristic (pure fn)
└── lib.rs

bloom-rpc (EXTEND)
└── endpoint.rs       Add EndpointKind::PrivateRpc so the pool can route
                      a signed raw tx via a non-pool endpoint.

bloom-tx (EXTEND)
├── tx_engine.rs      Wire MEV heuristic into stage()
                      Wire nonce-conflict check against PendingTxIndex
                      Wire private routing into broadcast()
├── outbox.rs         New artefacts:
                        pending/<id>/mev_risk.json
                        pending/<id>/nonce_conflict.json
                        sent/<hash>/bump.tx
                        sent/<hash>/bump_advice.json
                        sent/<hash>/cancel.tx
├── policy_engine.rs  New TOML tables: [private], [mev], [bump]
└── bump.rs (NEW)     BumpScanner: detects stuck txs, writes advisory bump.tx artefacts

bloom-vfs (EXTEND)
└── handlers/
    └── chains_mempool.rs (NEW)
                      chains/<chain>/mempool/{status.json, live, recent.jsonl,
                                              by_address/<a>/..., by_pool/<a>/...,
                                              <tx_hash>/...}
```

**Why one new crate, not two:** read-side (mempool stream + index)
and the heuristic / private-RPC trait don't depend on `bloom-tx`.
Keeping them in `bloom-mempool` means `bloom-tx` depends on
`bloom-mempool` (cleanly), but not the other way. Two crates would
force a circular dep or an unproductive leaf-node split.

### 4.2 Lifecycle

1. Daemon startup builds a `PendingTxIndex` per configured chain.
2. For each chain with a `[mempool.<chain>]` provider config, a
   `MempoolStream` task spawns, subscribes via the configured
   `MempoolProvider`, and pushes observed pending txs into both the
   index and a `tokio::sync::broadcast` channel.
3. `tx_engine::stage` consults the index for `(wallet_addr, chain)`
   nonce conflicts and runs the MEV heuristic if the calldata decodes
   as a known DEX swap.
4. `tx_engine::broadcast` routes via `RpcPool::send_raw_transaction`
   normally, OR via `PrivateRpcProvider::submit` when the wallet's
   policy has `private.enabled = true` AND the chain is mainnet.
5. A background `BumpScanner` walks `outbox/sent/` per wallet; for
   each tx still in mempool past the policy threshold or with base
   fee climbed past `maxFeePerGas`, writes an advisory
   `sent/<hash>/bump.tx` describing the recommended replacement.
   Never auto-broadcasts.

## 5. VFS Surface

### 5.1 Read surface — `chains/<chain>/mempool/`

```
chains/<chain>/mempool/
├── status.json                  # {provider, subscribed, observed_pending,
                                    uptime_sec, dropped_count, evictions_total,
                                    stale_for_secs}
├── live                         # long-poll tail (JSONL, follows watch.rs cursor pattern)
├── recent.jsonl                 # last ~500 observed pending txs (ring buffer)
├── by_address/<addr>/
│   ├── pending.jsonl            # txs in mempool from-or-to this address
│   └── nonces.json              # {"next_unused": N, "observed": [N, N+1, …]}
├── by_pool/<pool_addr>/
│   └── recent.jsonl             # pending swaps touching this DEX pool
└── <tx_hash>/                   # JIT — appears only if observed
    ├── tx.json
    ├── decoded.json             # ABI-decoded if the contract has a cached ABI; else null
    └── status                   # "pending" | "dropped" | "mined:<block>"
```

`by_pool/<pool_addr>/` requires the stream to decode swap calldata
against a known-router registry (Uniswap V2/V3/V4, Aerodrome, Curve
in v1). Unknown calldata still surfaces in `live`/`recent.jsonl`
with `decoded: null`.

If no `[mempool.<chain>]` provider is configured, the whole tree
returns a clear `"mempool provider not configured for <chain>"`
error on read (no crash, no WARN spam — matches existing handler
style).

### 5.2 Wallet-side artefacts

```
wallets/<w>/chains/<c>/
├── pending_external.jsonl       # NEW — mempool txs from this wallet's
                                   address that the daemon did NOT stage
└── nonce_conflicts.json         # NEW — derived: external nonce overlaps
                                   a pending outbox entry

wallets/<w>/outbox/
├── pending/<id>/
│   ├── mev_risk.json            # NEW — stage-time heuristic result
│   ├── nonce_conflict.json      # NEW — present only if a conflict was detected
│   └── … (existing artefacts)
└── sent/<hash>/
    ├── bump.tx                  # NEW — advisory: describes the recommended
                                   replacement (bumped fees, same nonce). Not
                                   directly stage-able as RawIntent; the agent
                                   reads the advisory and synthesizes a fresh
                                   send-style intent via outbox/new.tx.
    ├── bump_advice.json         # NEW — why a bump is suggested
    ├── cancel.tx                # NEW — advisory: alternative 0-value self-send
                                   at bumped fees, same shape as bump.tx
    └── … (existing artefacts)
```

### 5.3 Status surface

```
status/
├── backends/
│   ├── mempool                  # NEW — {chain: {provider, subscribed, fallback_to}}
│   └── private_rpc              # NEW — {chain: {provider: health_status}}
└── private_rpc/<provider>       # NEW — last-probe result for each configured provider
```

## 6. Provider Abstractions

### 6.1 `MempoolProvider`

```rust
#[async_trait]
pub trait MempoolProvider: Send + Sync {
    fn id(&self) -> &'static str;             // "alchemy" | "generic_eth_subscribe"

    /// Open a long-lived subscription. Returns a stream the daemon
    /// owns; provider drops it on close.
    async fn subscribe(&self) -> Result<BoxStream<'static, PendingTx>, MempoolError>;

    /// True = stream already includes full tx fields; False = caller
    /// must follow up with eth_getTransactionByHash via the RpcPool.
    fn delivers_bodies(&self) -> bool;
}

pub struct PendingTx {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub fees: TxFees,         // 1559 vs legacy normalised
    pub input: Bytes,
    pub observed_at: SystemTime,
}
```

Initial impls: `AlchemyProvider`, `GenericEthSubscribeProvider`. Both
share a thin reconnect-with-backoff wrapper that mirrors the
WS-to-poll handover in `bloom-watch/src/executor.rs:444`.

### 6.2 `PrivateRpcProvider`

```rust
#[async_trait]
pub trait PrivateRpcProvider: Send + Sync {
    fn id(&self) -> &'static str;              // "mev_blocker" | "flashbots"
    fn supported_chains(&self) -> &'static [ChainId];

    /// Submit a signed raw tx privately. MUST return the tx hash on
    /// success. MUST NOT silently fall back to the public mempool.
    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError>;

    /// Cheap probe (e.g. eth_blockNumber) for status surface and
    /// daemon health.
    async fn health(&self) -> Result<HealthStatus, PrivateRpcError>;
}
```

Initial impls: `MevBlockerProvider` (POST to `rpc.mevblocker.io`, no
auth), `FlashbotsProvider` (POST to `rpc.flashbots.net/fast`, no
auth required for Protect). Both speak `eth_sendRawTransaction` over
the same JSON-RPC surface, so the shared HTTP layer is tiny.

### 6.3 Wiring

- `bloom-daemon` builds
  `BTreeMap<ChainId, Arc<dyn MempoolProvider>>` and
  `BTreeMap<(ChainId, ProviderId), Arc<dyn PrivateRpcProvider>>`
  from config at startup.
- `tx_engine::broadcast` already takes a `&Daemon` reference;
  private routing is one branch keyed off `wallet.policy.private`.
- `MempoolStream` is a tokio task spawned per chain that has a
  configured provider; it owns the `PendingTxIndex` for that chain
  and broadcasts to a `tokio::sync::broadcast` channel the VFS
  `live` handlers tail.

### 6.4 Failure modes

- **Mempool provider disconnect** → stream task logs
  `mempool.<chain>.disconnected`, retries with exponential backoff
  (1 s → 30 s cap). `status.json` flips `subscribed: false`. Reads
  return stale-but-served data with a `stale_for_secs` field. No
  silent failure.
- **Private RPC submit failure** → tx is **not** auto-fallen-back to
  public. The outbox entry transitions to `failed/<id>/` with
  `error.txt` quoting the provider response. The agent must
  explicitly retry without `private = true` to use the public path.

## 7. Tx-Engine Integration

### 7.1 Nonce-conflict detection (`tx_engine::stage`)

After resolving the wallet's current chain nonce via
`eth_getTransactionCount(addr, "pending")`, query
`PendingTxIndex::lookup_by_addr_nonce(chain, addr, nonce)`. If a
match exists, write `pending/<id>/nonce_conflict.json`:

```json
{
  "conflict_nonce": 42,
  "external_hash": "0x…",
  "external_observed_at": "2026-05-12T15:36:12Z",
  "advice": "use --nonce 43 or wait for 0x… to mine/drop"
}
```

`stage` does not refuse — the conflict might resolve before
broadcast. The agent reads `nonce_conflict.json` and decides. Hard
rejection is one bool flag away if we need it later.

### 7.2 MEV heuristic (`bloom-mempool::heuristic::evaluate`)

Pure function. Two cheap checks:

1. **Decoded-swap slippage exposure** — if calldata decodes against
   a known DEX router (Uniswap V2/V3/V4, Aerodrome, Curve in v1),
   extract `amountOutMin` and `path`. Fetch current quote via the
   existing `prices` crate or a direct `eth_call` to the router's
   quoter. If `(quoted - amountOutMin) / quoted > policy.mev.max_slippage_bps`,
   flag `risk: "high"`.
2. **Large-value swap without slippage cap** — if `amountOutMin == 0`
   and `amountIn` exceeds a USD threshold (default 1 ETH-equivalent),
   flag `risk: "high"` regardless.

Result lands at `pending/<id>/mev_risk.json`:

```json
{
  "risk": "low|medium|high",
  "checks": ["slippage_exposure", "amount_out_min_zero"],
  "advice": "amountOutMin set to 95% of quote — consider 99% or use a private RPC"
}
```

If `policy.mev.fail_on_high_risk = true` and result is `"high"`,
stage fails into `outbox/failed/<id>/` (existing path). Otherwise,
the result is just an artefact + a line appended to `plan.md`.

### 7.3 Private routing (`tx_engine::broadcast`)

```rust
let raw = sign(&staged)?;
let hash = if wallet.policy.private.enabled && chain.is_mainnet() {
    let provider_id = wallet.policy.private.provider.as_str();
    let provider = daemon.private_rpc(chain.id, provider_id)
        .ok_or(BroadcastError::PrivateProviderNotConfigured)?;
    provider.submit(&raw).await?
} else {
    rpc_pool.send_raw_transaction(&raw).await?
};
```

Non-mainnet + `private.enabled = true` → returns
`BroadcastError::PrivateNotSupportedOnChain` with a message naming
the chain.

### 7.4 Bump scanner (`bloom-tx::bump::BumpScanner`)

Background task running every 30 s (configurable). For each
`outbox/<wallet>/<chain>/sent/<hash>/` entry without `mined.json`:

- Check the `PendingTxIndex`: is `<hash>` still in mempool? Age?
- Read current `chains/<c>/gas/current.json` and compare to the tx's
  `maxFeePerGas`.
- Trigger rules:
  `dwell_secs > policy.bump.stuck_after_secs`
  OR
  `current_basefee > maxFeePerGas * (1 + policy.bump.basefee_overrun_pct/100)`.

On trigger, write an advisory tx file (descriptive shape, NOT a
directly-stageable `RawIntent` today — see Limitations below) to
`sent/<hash>/bump.tx` with `maxFeePerGas` and `maxPriorityFeePerGas`
each bumped by **+12.5 %** (EIP-1559 `MIN_REPLACEMENT_FEE_INCREASE`,
rounded up) over the original, same `nonce`. Sibling
`bump_advice.json` explains why. Sibling `cancel.tx` is the same
shape with `to = wallet_address`, `value = 0`, `data = "0x"`, same
`nonce`, same bumped fees — a self-send replacement that lets the
agent reclaim the nonce slot instead of pushing the original tx
through.

**Limitation (advisory-only today):** `RawIntent` does not currently
accept explicit fee overrides, so an agent cannot simply copy
`bump.tx` into `outbox/new.tx` and expect identical fees on the wire.
Today the agent reads `bump.tx` for the recommended fees + nonce,
then synthesises a fresh send-style intent via the normal staging
path. Direct stage-ability (extending `RawIntent` with explicit
`maxFeePerGas` / `maxPriorityFeePerGas` overrides) is a follow-up.
This keeps stage-confirm intact.

## 8. Streaming & Watch Wiring

The mempool stream and the existing watch executor share WS
infrastructure but stay decoupled.

**Why not extend `WatchSpec` with a `Mempool` kind?** Watches are
per-subscription user state with rotated history under
`watch/<id>/`. The mempool stream is a singleton per chain, owned by
the daemon, fanning out to many readers. Different lifecycle,
different storage. Forcing it through `WatchSpec` would either bloat
every watch with the firehose or special-case `Mempool` everywhere.

**Topology** (per chain with a configured provider):

```
              MempoolProvider::subscribe()
                       │ BoxStream<PendingTx>
                       ▼
              ┌────────────────┐
              │ MempoolStream  │  one task per chain
              │  - reconnect   │
              │  - dedupe      │
              │  - bound LRU   │
              └───────┬────────┘
                      │
        ┌─────────────┼──────────────┐
        ▼             ▼              ▼
  PendingTxIndex   broadcast::Sender   ring buffer (recent.jsonl)
        │             │
        ▼             ├─► chains/<c>/mempool/live    (long-poll readers)
   tx_engine::stage   ├─► wallets/<w>/.../inbox      (filtered)
   BumpScanner        └─► nonce-conflict watchers   (filtered)
```

**Behaviour**:

- Bounded `broadcast::channel(capacity = 4096)`. Slow readers get
  `RecvError::Lagged` and a synthetic
  `{"kind":"lagged", "skipped": N}` line surfaced in the JSONL
  stream — never silent drop.
- Dedup via `(hash, observed_at_block_height)` cache to suppress
  replays after reconnect.
- Bounded LRU at `max_index_size` (default 50 000). Eviction emits
  `mempool.<chain>.evicted`; `status.json` surfaces
  `evictions_total`.

**Long-poll `live` handlers** follow the existing pattern from
`bloom-vfs/src/handlers/watch.rs` and the per-handler cursor in
`events/<name>/live`: per-reader cursor in memory, no on-disk
state, no replay on reconnect.

**Private RPC streams nothing.** Health-checked every 60 s; result
rolls into `status/private_rpc/<provider>` and `status/health`.

**Shutdown**: `Daemon::shutdown` sends a cancel token to every
`MempoolStream` task; tasks drain their broadcast channels, close
the upstream WS cleanly, and exit.

## 9. Policy & Config

### 9.1 Per-wallet (`wallets/<w>/policy.toml`)

```toml
[private]
enabled = false              # opt-in; mainnet-only
provider = "mev_blocker"     # "mev_blocker" | "flashbots"

[mev]
max_slippage_bps = 100       # warn if stage-time DEX swap exceeds this
fail_on_high_risk = false    # if true: stage refuses; if false: warn only

[bump]
stuck_after_secs = 90
basefee_overrun_pct = 20
```

### 9.2 Daemon (`~/.bloom-eth/config.toml`)

```toml
[mempool.<chain>]
provider = "alchemy"         # "alchemy" | "generic_eth_subscribe"
ws_url = "wss://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
max_index_size = 50_000

[private_rpc.<chain>]        # only the mainnet section has an effect in v1;
                             # other chains are rejected by supported_chains()
mev_blocker_url = "https://rpc.mevblocker.io"
flashbots_url   = "https://rpc.flashbots.net/fast"

[backends]
mempool = "rpc"              # "rpc" (provider) | "indexer" (reserved)
```

Absent `[mempool.<chain>]` → the tree returns the same kind of
clear "not configured" error other absent-backend trees do.

## 10. Testing Strategy

### 10.1 Feature flags (Cargo, on `bloom-mempool`)

| Feature | Pulls | Default? |
|---|---|---|
| `default = ["alchemy", "mev_blocker", "flashbots"]` | all v1 providers | yes |
| `alchemy` | alloy-pubsub + WS transport | yes |
| `generic_eth_subscribe` | WS transport only | always on |
| `mev_blocker` / `flashbots` | reqwest client + URL constants | yes |
| `live-providers` | unlocks network-touching tests | **no** |

### 10.2 Layers

1. **Pure-function unit tests** (in-crate, the bulk of LoC):
   - `heuristic::evaluate` — table-driven over hand-crafted swap
     calldata fixtures for each supported DEX router.
   - `bump::compute_replacement_fees` — EIP-1559 +12.5 % math and
     rounding edge cases (1 wei, large gas, legacy txs).
   - `PendingTxIndex` — insert/evict/lookup, LRU bound,
     `(addr, nonce)` collision detection.
   - `provider_test_suite!()` macro — any `MempoolProvider` impl
     must pass subscribe → mock stream → 100 PendingTx → assert
     delivered + dedupe.

2. **In-process integration** (extend `bloom-it`):
   - `MockMempoolProvider` (fixture-fed stream) for VFS handler
     end-to-end tests.
   - `MockPrivateRpcProvider` (captures submitted raw txs) for
     broadcast routing assertions and the non-mainnet error path.
   - Nonce-conflict scenario: stage at nonce N → inject external
     pending tx at nonce N → assert `nonce_conflict.json`.
   - Bump scanner: simulate a sent tx pending 120 s with base fee
     30 % over `maxFeePerGas`; assert `bump.tx` with exactly +12.5 %
     fees.

3. **Docker fork-mode** (extend `tests/docker/`):
   - Add `--mempool-mock` mode: anvil + in-Docker WS server
     emulating `alchemy_pendingTransactions`. Verifies the
     observed-pending → `mempool/live` reader → MEV heuristic →
     bump scanner pipeline end-to-end, on the real NFS mount.
   - Verifies tailing `mempool/live` produces no WARN spam — the
     `Attrs.change` lever already in `MEMORY.md` applies here too.

4. **Live-network smoke** (`--features live-providers`, **opt-in,
   not in CI**):
   - `tests/it/mempool_alchemy_smoke.rs` — gated on
     `ALCHEMY_API_KEY`; 30 s subscription, asserts ≥ N observations.
   - `tests/it/private_rpc_health.rs` — gated on
     `RUN_PRIVATE_RPC_HEALTH=1`; pings MEV-Blocker and Flashbots
     health endpoints. Read-only.

### 10.3 CI matrix (extends existing `ci.yml`)

- `cargo build --workspace --no-default-features`
- `cargo build --workspace` (default features)
- `cargo test --workspace --lib`
- `cargo test --workspace --test '*'`
- `tests/docker/run.sh --mempool-mock` on the fork-mode runner

### 10.4 Not in CI (documented in `docs/AUDIT.md`)

- Live Alchemy mempool subscription (rate-limited, key-bound).
- Live mainnet broadcast through MEV-Blocker / Flashbots (would cost
  real ETH and risk builder reputation systems).
- Reorg simulation deeper than what fork-mode anvil provides.

## 11. Implementation Phasing

Built so phases land independently — each is a useful PR that
doesn't depend on later phases shipping.

**Phase 1 — Foundation (no external deps yet)**
1. New crate `bloom-mempool` skeleton (Cargo, lib.rs, error types).
2. `PendingTxIndex` + `provider_test_suite!()` macro.
3. `MempoolProvider` trait + `MockMempoolProvider` (fixture-fed).
4. `PrivateRpcProvider` trait + `MockPrivateRpcProvider`.
5. `heuristic::evaluate` + DEX router fixtures + unit tests.
6. `bump::compute_replacement_fees` + unit tests.

**Phase 2 — VFS surface**
1. `bloom-vfs/src/handlers/chains_mempool.rs` with the read tree.
2. Wallet-side artefacts: `pending_external.jsonl`,
   `nonce_conflicts.json`, `mev_risk.json`, `nonce_conflict.json`,
   `bump.tx`, `bump_advice.json`, `cancel.tx`.
3. Status surface entries: `status/backends/mempool`,
   `status/backends/private_rpc`, `status/private_rpc/<provider>`.
4. In-process integration tests using the mocks from Phase 1.

**Phase 3 — Tx-engine integration**
1. Policy schema additions: `[private]`, `[mev]`, `[bump]`.
2. Nonce-conflict check in `tx_engine::stage`.
3. MEV heuristic call in `tx_engine::stage`.
4. Private routing branch in `tx_engine::broadcast`.
5. `BumpScanner` task spawned by `bloom-daemon`.
6. End-to-end mock integration tests for each path.

**Phase 4 — Real providers**
1. `AlchemyProvider` impl + reconnect-with-backoff wrapper.
2. `GenericEthSubscribeProvider` impl.
3. `MevBlockerProvider` impl + health probe.
4. `FlashbotsProvider` impl + health probe.
5. Daemon wiring: build provider maps from config at startup.
6. Live-providers feature-gated smoke tests.

**Phase 5 — Docker fork-mode + docs**
1. `tests/docker/run.sh --mempool-mock` with the in-Docker WS
   server emulator.
2. README + `docs/AUDIT.md` updates: remove the "Mempool surface
   not implemented" limitation, add the per-section
   implementation map.
3. Quickstart additions for the new paths.

## 12. Open Questions

These are deliberately not blocked on for the spec but worth
revisiting once Phase 4 is real.

- **Rotation mode for `PrivateRpcProvider`** — the research suggests
  diversifying. The trait accommodates a `RotatingPrivateRpc` wrapper
  later without re-architecting; deferring to a follow-up unless
  Phase 4 reveals a clear win.
- **Per-pool nonce-conflict semantics** — the current detector keys
  on `(addr, nonce)`. A wallet shared across multiple processes
  (e.g., bloom-eth + MetaMask on the same key) will see frequent
  conflicts. Worth a config flag `[nonce] external_conflict =
  "warn" | "reject"` if real-world usage exposes pain.
- **L2 mempool semantics** — Base and Optimism sequencers expose
  private mempools; `eth_subscribe("newPendingTransactions")` returns
  nothing useful on them today. The spec ships a clear status
  message ("not applicable on this chain") but a future
  sequencer-direct integration would be its own design.
- **MEV-Share bundles** — out of scope for v1, but the
  `PrivateRpcProvider` trait does not preclude a future
  `mev_sendBundle` adapter; that would need a new `submit_bundle`
  method and a `wallets/<w>/outbox/bundles/` subtree.
