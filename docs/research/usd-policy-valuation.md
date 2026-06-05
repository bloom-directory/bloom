# Research: USD valuation for policy caps on token swaps & arbitrary calldata

Status: open research topic · Owner: TBD · Created: 2026-05-29

## 1. Problem statement

bloom wallet policies expose dollar-denominated caps:

- `caps.per_tx_usd` — hard per-transaction ceiling.
- `caps.require_confirm_above_usd` — soft threshold; above it, confirming requires the override token.
- `caps.per_day_usd` — rolling 24h ceiling.

These work for **native-asset sends** but are silently **inert for ERC‑20 swaps** (Enso routes) and,
more broadly, for any contract call that moves value through calldata rather than the tx `value`
field. In that case the policy engine emits a single advisory warn:

```
caps.usd  warn  "USD caps configured but no price quote available; rule skipped"
```

and confirming requires the override token regardless of the real dollar size.

**Why this matters (security):** a user who sets `require_confirm_above_usd = 5` reasonably believes
large swaps will be gated. Today a $50,000 USDC→ETH swap and a $5 one are treated identically — both
"unpriced → warn → override". The cap is effectively unenforced for the most common DeFi action, and
the failure is *silent* (a warn, not a denial). This is the crux: a control users trust is not
actually applied.

Live repro (this session): `minnow-passkey` swap `4.226422 USDC → ETH` on Base.
`outbox/.../policy_check.json` showed `caps.max_value_eth: pass (value 0)` and
`caps.usd: warn (no price quote available)`. The "~$4.23" figure came from the **Enso quote**, never
from bloom's policy valuation.

## 2. Root cause

USD value is computed only from the transaction's **native value**:

`crates/bloom-tx/src/tx_engine.rs` (~line 915):
```rust
policy_ctx.usd_value = if needs_usd && value_wei > U256::ZERO {
    self.price_oracle.native_usd(&spec.name, value_wei, native_decimals).await
} else { None };
```

`crates/bloom-tx/src/policy_engine.rs` (~line 188): when any `*_usd` rule is configured but
`usd_value` is `None`, it pushes the `caps.usd` **Warn** (by design: "an absent oracle is the
operator's problem, not a license to skip the rule").

An Enso swap is a `RawIntentBody::Raw` with `value_wei = 0` — the input token is pulled inside the
router's opaque calldata (Permit2 / `transferFrom`). So the `value_wei > 0` guard short-circuits to
`None` and the oracle is never even consulted. Pricing has nothing to act on, because bloom does not
extract ERC‑20 amounts from arbitrary calldata.

## 3. Existing infrastructure (reusable)

- `bloom_prices::PricesClient` already prices **ERC‑20s by contract address** via
  `CoinId::Erc20 { chain, address }` (DefiLlama, which serves CoinGecko data) —
  `crates/bloom-prices/src/lib.rs:55-93`, client at `:222`, `current(coin).price`.
- The policy path only reaches `PriceOracle::native_usd` — `crates/bloom-tx/src/oracle.rs` (trait),
  `crates/bloom-daemon/src/price_oracle.rs` (`PricesOracle` adapter), wired at
  `crates/bloom-daemon/src/lib.rs:290`.
- `RawIntent` already carries an optional `gas_limit_hint` (`crates/bloom-proto/src/intent.rs:118`),
  a precedent for plumbing a `usd_value_hint`.
- The DeFi handler already simulates routes via `eth_call` —
  `crates/bloom-vfs/src/handlers/defi.rs::simulate_session` (`eth_call_capture_revert`). It captures
  return data, **not** balance deltas (relevant to Option B below).

So token pricing exists; it simply isn't surfaced to, or fed into, the policy USD-cap path.

## 4. Design options

### Option A — Input-leg pricing (minimal, swap-aware)
Price the **input amount we specified** with the oracle and plumb it to the engine.
- Add `PriceOracle::token_usd(chain, token, raw_amount, decimals)`, implemented in `PricesOracle`
  via `CoinId::Erc20`.
- Add `usd_value_hint: Option<f64>` to `RawIntent`.
- In `defi.rs::create_session` (which knows `token_in` + `amount_in` before they become opaque
  calldata), compute the input USD and set the hint.
- `tx_engine::stage` prefers `usd_value_hint`, else falls back to `native_usd`. Also price plain
  `RawIntentBody::Token` sends directly.

Pros: small, reuses everything, unblocks the common case (swaps confirm with `y`; large swaps gate
correctly). Cons: only covers intents bloom constructs (Enso/Token); does **not** generalize to
arbitrary user-supplied `Raw` calldata; values the input leg only (ignores received side).

### Option B — Simulation-delta valuation (general)
Derive value from the **actual token-balance deltas** of a simulated execution.
- Use a state-diff / prestate trace (e.g. `debug_traceCall` prestate tracer or `trace_call`
  stateDiff), or a sequence of balance reads around an `eth_call`, to learn every ERC‑20 (and native)
  balance change for `from`.
- Price each touched token via `token_usd`; the cap can then use spend (negative deltas), receive
  (positive), or max.

Pros: works for **any** contract call, not just recognized swaps; self-consistent with what will
execute; immune to "trust the router's numbers." Cons: needs trace support on the RPC (not all
endpoints expose it), more latency, multi-token pricing, and careful handling of intermediate hops.

### Option C — Protocol-reported amounts (Enso) — cross-check only
Read `amount_in`/`amount_out` from the Enso `RouteResponse`. Rejected as the primary source: it asks
the protocol we're gating to self-report its size (circular). Acceptable only as a sanity
cross-check against an independent oracle.

## 5. Cross-cutting questions to resolve

- **Semantic of the cap:** does `require_confirm_above_usd` mean value *spent* (input), value
  *received* (output), or `max(in, out)`? Document and make consistent.
- **Slippage / price impact:** value the quoted amount or the slippage-protected minimum? How does
  price impact feed in?
- **Safe failure mode (security default):** when a token can't be priced, do we `warn→override`
  (current, fail-open-ish) or `deny` (fail-closed)? Consider per-rule: hard `per_tx_usd` might
  fail-closed, soft `require_confirm_above_usd` fail-warn.
- **Oracle robustness:** DefiLlama/CoinGecko rate limits, price staleness, caching/TTL, and fallback
  ordering; what staleness is acceptable for a spend cap?
- **Where valuation lives:** intent compiler (`defi.rs`), the engine (`stage`), or a dedicated
  post-simulation step. Option B argues for a simulation-time component.
- **Coverage:** multi-token routes, LP add/remove, approvals (value = 0 but risk ≠ 0), aToken/NFT.
- **Determinism / audit:** record the price source, timestamp, and computed `usd_value` in the
  outbox `intent.json` / `audit.jsonl` so a confirm decision is reconstructable.

## 6. Recommendation & phasing

- **Phase 1 (tactical):** Option A — input-leg pricing for Enso/Token intents. Restores enforcement
  for the common path with minimal surface. Keep `warn→override` as the unpriced fallback.
- **Phase 2 (strategic):** Option B — simulation-delta valuation for general calldata coverage,
  gated on RPC trace availability with graceful degradation to Phase 1 / warn.
- Decide the failure-mode policy (§5) before shipping either, since it changes the security posture.

## 7. References

- `crates/bloom-tx/src/tx_engine.rs:915` — native-only `usd_value` computation.
- `crates/bloom-tx/src/policy_engine.rs:110-196` — USD-cap rules and the `caps.usd` warn.
- `crates/bloom-tx/src/oracle.rs` — `PriceOracle` trait (`native_usd` only).
- `crates/bloom-daemon/src/price_oracle.rs`, `crates/bloom-daemon/src/lib.rs:290` — adapter + wiring.
- `crates/bloom-prices/src/lib.rs:55-93,222` — `CoinId::Erc20` + `PricesClient`.
- `crates/bloom-vfs/src/handlers/defi.rs` — Enso route build (`create_session`) and `eth_call`
  simulation (`simulate_session`).
- `crates/bloom-proto/src/intent.rs:118` — `RawIntent` / `gas_limit_hint` precedent.
- Live repro: `~/.bloom/keystore/minnow-passkey` swap `0002-82415`, `policy_check.json` `caps.usd` warn.
