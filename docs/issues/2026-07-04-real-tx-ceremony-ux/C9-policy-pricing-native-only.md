# C9 — the policy engine can only price native-token sends

**Severity:** High · **Category:** Architectural / Functional
**Observed:** 2026-07-04, inferred from code analysis during the real-tx ceremony
UX review. Confirmed by tracing the staging → authorization path end-to-end.

---

## What happened

The policy engine exists to let agents execute transactions autonomously within
bounded USD limits (`max_tx_usd`, `max_day_usd`, etc.) under `under_policy`
autonomy. But the USD valuation path only prices **native-token value** (ETH,
MATIC). ERC-20 transfers, ERC-20 approvals, NFT transfers, and contract calls
(swaps, staking, etc.) all carry their value in calldata rather than the tx's
native `value` field, so their `value_wei` is zero, and the oracle is never
invoked. These transactions end up unpriced (`usd_value = None`), which makes
them **Denied** at authorization time — the policy engine treats them as having
unknown value and refuses to auto-broadcast.

In practice, `under_policy` autonomy can only autonomously approve plain
native-token sends. For a wallet whose primary use case is DeFi (swaps,
transfers, funding), this means virtually every meaningful operation still
requires a ceremony.

## Why it happens

### The oracle is gated on native value only

At staging time (`crates/bloom-tx/src/tx_engine.rs:1184-1197`):

```rust
policy_ctx.usd_value = intent.usd_value_hint.as_deref()
    .and_then(|s| s.parse::<f64>().ok())
    .filter(|v| v.is_finite() && *v >= 0.0);
if policy_ctx.usd_value.is_none() && needs_usd && value_wei > U256::ZERO {
    policy_ctx.usd_value = if let Some(oracle) = &self.price_oracle {
        oracle.native_usd(&spec.name, value_wei, spec.native_decimals).await
    } else {
        None
    };
}
```

The oracle call is guarded on `value_wei > U256::ZERO`. Every non-native intent
sets `value_wei = U256::ZERO` because the amount travels in calldata:

- ERC-20 `Send`: `tx_engine.rs:694` → `(token_addr, U256::ZERO, calldata, ...)`
- ERC-20 `Approve`: `tx_engine.rs:736` → `(token_addr, U256::ZERO, calldata, ...)`
- NFT `Transfer`: `tx_engine.rs:812` → `(contract_addr, U256::ZERO, calldata, ...)`

So the oracle is structurally unreachable for any calldata-based tx.

### The `PriceOracle` trait is native-only

`crates/bloom-tx/src/oracle.rs:24-30`:

```rust
#[async_trait]
pub trait PriceOracle: Send + Sync {
    async fn native_usd(
        &self,
        chain_name: &str,
        value_wei: U256,
        native_decimals: u8,
    ) -> Option<f64>;
}
```

The trait has a single method for native assets. There is no ERC-20 pricing
method on this trait. The production implementation
(`crates/bloom-daemon/src/price_oracle.rs:42-59`) maps the chain to a DefiLlama
coin id (ETH or MATIC), scales wei to units, and multiplies by the spot price.

### `value_moving` is over-broad — ERC-20 approves are "value-moving"

`crates/bloom-tx/src/tx_engine.rs:2722-2731`:

```rust
let value_wei = U256::from_str_radix(&staged.value_wei, 10).unwrap_or(U256::ZERO);
let data_nonempty = staged.data_hex.trim_start_matches("0x").bytes().any(|b| b != b'0');
let value_moving = value_wei > U256::ZERO
    || staged.token.is_some()
    || staged.nft.is_some()
    || data_nonempty;
```

`value_moving` is `true` if **any** of: native value present, token ref present,
NFT ref present, or **any non-zero calldata byte**. An ERC-20 `approve` produces
ABI-encoded calldata (selector `0x095ea7b3…`), so `data_nonempty = true`, so
`value_moving = true` — even though an approve grants spending permission and
moves no value. There is no approve-vs-transfer distinction.

### Unpriced + value-moving → Denied

At authorization time (`crates/bloom-proto/src/policy.rs:734-766`):

```rust
// Non-value-moving short-circuits to autonomous approval (debit 0).
if !subject.value_moving {
    return AutonomyDecision::ApprovedAutonomous { ... };
}
// ...
// UnderPolicy + unpriced + value-moving => DENIED
let Some(value) = subject.total_value_usd_micro else {
    return AutonomyDecision::Denied {
        reason: "USD valuation unavailable".into(),
    };
};
```

And for policy sessions (`crates/bloom-tx/src/session.rs:129-145`):

```rust
let debit = match tx_micro_usd {
    Some(v) => { /* check against cap, debit */ }
    None if value_moving => continue,  // fail-closed: no session covers it
    None => 0,                          // value-neutral: debit 0
};
```

So an unpriced value-moving tx is Denied under `under_policy` autonomy and
cannot be covered by a policy session. The only escape is passing an explicit
`usd_value_hint` in the intent (parsed at `intent_parser.rs:69,532-546`), which
bypasses the oracle entirely.

## A richer oracle exists but is not wired in

The codebase has a **second** `PriceOracle` trait that can price arbitrary
assets, including ERC-20s:

`crates/bloom-auth-api/src/lib.rs:2646-2653`:

```rust
#[async_trait]
pub trait PriceOracle: Send + Sync {
    async fn quote_usd(
        &self,
        asset_id: &str,
        amount_base_units: &str,
        now_ms: u128,
    ) -> Result<ValuationQuote>;
}
```

Its implementation `BloomPricesOracle` (`crates/bloom-auth/src/lib.rs:2157-2200`)
calls the same DefiLlama `PricesClient`, and `bloom-prices` already supports
ERC-20 coin ids:

```rust
// crates/bloom-prices/src/lib.rs:54-65
pub enum CoinId {
    Erc20 { chain: String, address: Address },
    Native(String),
    Symbol(String),
}
```

But this oracle is invoked **only** from the standing-session reservation
surface (`crates/bloom-auth/src/lib.rs:1276-1314`,
`AuthStore::create_reservation_with_valuation`). It is **not** wired into the
EVM outbox staging/confirm path that populates `usd_value` on `StagedTx`. The
infrastructure to price ERC-20s exists — it is not connected to the policy
engine.

The staging path already has the token contract address available in the
`TokenRef` (`crates/bloom-proto/src/plan.rs:87-98`: `contract`, `decimals`,
`symbol`). So the inputs needed for an ERC-20 price lookup are present at
staging time; the pricing call just isn't made.

## The stablecoin assumption is unimplemented

`ValuationQuote` has a `stablecoin_assumption: bool` field
(`bloom-auth-api/src/lib.rs:2294`), and `ValuationPolicy` distinguishes freshness
windows for volatile (30s) vs stablecoin (120s) assets
(`bloom-auth-api/src/lib.rs:2553-2554`). But `BloomPricesOracle::quote_usd`
**always returns `stablecoin_assumption: false`**
(`crates/bloom-auth/src/lib.rs:2198`). No production code path classifies an
asset as a stablecoin. So even USDC and USDT — which would reasonably be
assumed ≈$1 — are always queried live as volatile assets, with no fallback if
DefiLlama is unavailable.

The bloom-tx native-only oracle path has no stablecoin concept at all.

## Impact

- **`under_policy` autonomy is limited to native sends.** Any ERC-20 transfer,
  swap, approval, or NFT operation under `under_policy` autonomy is Denied
  unless the caller passes a `usd_value_hint`. This makes the autonomy model
  largely theoretical for DeFi — the wallet's primary use case.

- **Policy sessions are undermined.** Sessions debit USD per confirmed tx
  (`session.rs:110-149`), but since most DeFi txs are unpriced, they fail-closed
  and can't be covered by a session. The multi-tx-one-ceremony mechanism (see
  C3) becomes mostly useless for real DeFi flows — you can pre-authorize the
  ids, but the session won't cover unpriced txs.

- **ERC-20 approvals are misclassified as value-moving.** An approve that
  grants unlimited spending permission on a token is classified identically to
  a transfer — and then Denied for lack of USD value. Yet an unlimited approve
  is arguably **more** dangerous than a bounded transfer; the classification
  is both wrong (approve ≠ value-moving) and the denial reason is misleading
  ("USD valuation unavailable" when the real concern is permission grant).

- **The `usd_value_hint` workaround pushes valuation to the caller.** An agent
  must price its own transactions and pass the hint. There is no verification
  that the hint is accurate or current — a stale or manipulated hint would be
  accepted at face value and debited against the session cap.

- **Day/week/month caps degrade silently.** `Outbox::sum_usd_since`
  (`crates/bloom-tx/src/outbox.rs:974-1007`) skips entries without a
  `usd_value`. So the rolling 24h spend total is a best-effort sum of priced
  sends only — unpriced sends contribute zero, understating actual spend.

- **DefiLlama is a single point of failure.** No on-chain oracle, no Chainlink,
  no DEX TWAP fallback (despite the design spec at
  `docs/specs/2026-05-08-bloom-design.md` mentioning CoinGecko + Pyth +
  Uniswap V3 TWAP). If DefiLlama is down, even native sends become unpriced
  and Denied.

## Representative end-to-end outcomes

| Intent | `value_wei` | `value_moving` | Priced? | UnderPolicy decision |
|---|---|---|---|---|
| Send 1 ETH | `1e18` | true | oracle (ETH spot) | priced; `check_limits` runs |
| Send 100 USDC | 0 | true | **no** (unless hint) | **Denied "USD valuation unavailable"** |
| Approve USDC spender | 0 | true (calldata) | **no** | **Denied "USD valuation unavailable"** |
| Transfer NFT | 0 | true | **no** | **Denied "USD valuation unavailable"** |
| Swap via router contract | 0 | true (calldata) | **no** | **Denied "USD valuation unavailable"** |
| ETH send, DefiLlama down | `1e18` | true | **no** (oracle None) | **Denied "USD valuation unavailable"** |
| Empty calldata, zero value | 0 | **false** | n/a | **ApprovedAutonomous** (debit 0) |
