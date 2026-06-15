# Enso Simulation Verification for DeFi Routes

Date: 2026-06-13

Status: in progress. WP0/WP1 and the same-chain receiver calldata consistency
check have landed in `feat/polymarket`. Remaining before unattended DeFi:
simulation min-output policy, durable verification artifacts, and live
destination settlement checks for cross-chain routes.

## Goal

Autonomous DeFi execution must not trust Enso quote metadata alone. Bloom should
simulate the exact transaction, validate the exact bytes immediately before
signing/broadcast, and evaluate policy against verified effects. Cross-chain
dependent actions must still wait for live destination settlement proof.

Until this is complete:

```text
No autonomous DeFi broadcast without simulation. A foreground human review may
authorize a quote-only route only when signed policy explicitly allows that
risk.
```

## Current Findings

WP0 probed `https://quoter.api.enso.build` on 2026-06-14:

- `POST /api/v1/simulate` requires top-level `chainId`,
  `transaction:{chainId,from,to,data,value}`, and array fields `tokenIn`,
  `tokenOut`, `amountIn`.
- `POST /api/v1/validate` accepts `{simulationId, transaction}` and returns
  `checks:{chainId,data,to,value,from}`.
- `/validate` exact-byte binding works: mutating each tx field flips its own
  check and sets `valid:false`.
- `result.status == "Success"` is not enough. An unfunded placeholder sender
  returned success with `amountOut: []`; policy must require non-empty output
  at or above the expected floor.
- `/simulate` does not attribute receiver. Its output is `amountOut: string[]`
  parallel to the requested `tokenOut` array, with no receiver/address field.
- Route calldata does include the requested receiver verbatim in observed
  same-chain and cross-chain routes. Bloom implements
  `RouteResponse::calldata_contains_receiver(addr)` as a consistency check, not
  a malicious-Enso defense.

Autonomous cross-chain DeFi remains denied until both the calldata receiver
consistency check and live destination settlement proof hold. Same-chain routes
may use the calldata consistency check once min-output simulation policy exists.

## Policy

```toml
[approval]
agent_autonomy = "disabled" # or "under_policy"

[defi]
enabled = false
require_simulation = true
require_simulation_validation = true
allow_quote_only_routes = false
```

Rules:

- `agent_autonomy = "disabled"` always requires fresh user review.
- `agent_autonomy = "under_policy"` may act only when signed limits,
  allowlists, simulation, validation, freshness, and settlement requirements all
  pass.
- `allow_quote_only_routes = true` permits only supervised foreground review;
  it never authorizes autonomous VFS/IPC/daemon execution.
- Legacy `require_calldata_verification = true` maps to simulation +
  exact-byte validation; `false` must not silently enable autonomous quote-only
  routes.

## Non-Negotiables

- No autonomous quote-only DeFi.
- Simulation must cover the exact `chainId`, `from`, `to`, `data`, and `value`
  Bloom will sign.
- Validation must run immediately before signing/broadcast; stale simulations
  refuse.
- Policy checks use simulated effects, not route claims.
- `status:"Success"` without non-empty `amountOut` refuses.
- Receiver is not proven by `/simulate`; use route calldata consistency and,
  for cross-chain, live settlement.
- Cross-chain simulation authorizes only the source leg. Dependent actions wait
  for destination balance/receipt proof.
- Risk acceptance belongs in signed policy, not CLI bypass flags.

## Threat Model

Defends against stale/tampered route metadata, swapped route responses, daemon
unlocks signing routes without verified effects, and quote-only routes under
autonomous surfaces.

Does not defend against a malicious local Bloom binary, incorrect/malicious
Enso simulation, Enso returning matching but malicious calldata+simulation, or
bridges that fail after a successful source-chain simulation.

`settlement.json` is cache/audit material. Confirm and dependent actions must
re-check live destination state before treating settlement as proof.

## Implementation Work

### WP1 Quoter Client

Landed in `crates/bloom-defi/src/lib.rs`:

- `QuoterClient`
- `QuoterTx`
- `SimulateRequest` / `SimulateResponse`
- `ValidateRequest` / `ValidateResponse`
- fixtures for successful-empty-output simulation and validate pass/fail
- request serialization test for WP0 wire shape

### WP2 Verification Artifact

Add read-only:

```text
defi/intents/<wallet>/<session>/simulation_verification.json
```

Minimum fields:

- status, simulated/expires timestamps, `simulation_id`
- source chain tx summary and data hash
- token-in/out facts, expected receiver, min floor
- checks for simulation success, non-empty output, min-output, receiver,
  exact-byte validation
- raw validate check booleans

The artifact is cache/review material only. Confirm must re-run or re-check
validation, policy, and freshness.

### WP3 Policy Evaluation

Replace quote/calldata-first facts with:

- `simulation_success`
- `simulation_fresh`
- `validation_success`
- `expected_token_out`
- `amount_out_nonempty`
- `receiver_verified` from route calldata + settlement, not `/simulate`
- `min_output_verified`
- `quote_only`

Default denies: no simulation on autonomous surfaces, expired simulation,
validation failure, empty output, below-floor output, unverified receiver,
quote-only autonomous execution, and missing cross-chain settlement for
dependent actions.

### WP4 VFS Flow

Expose:

```text
/defi/intents/<wallet>/<session>/simulation_verification.json
/defi/intents/<wallet>/<session>/verify
```

Route creation may verify automatically when policy requires it. Writing
`verify` refreshes without staging. Writing `confirm` refreshes or validates
immediately before staging/signing.

### WP5 Settlement Evidence

For cross-chain routes:

- source confirmation is not completion;
- `wait_settlement` must check destination receiver balance increase for the
  expected token;
- dependent actions refuse until live settlement is observed;
- cached settlement artifacts must be rechecked against live state.

### WP6 Policy/Docs Migration

Rename user-facing Enso safety from generic "calldata verification" to
"simulation verification". Keep calldata/data-hash checks as exact-byte
validation and receiver consistency checks; do not require a generic Enso router
decoder.

### WP7 Polymarket Fund Integration

`bloom polymarket fund` must reuse the same verifier:

- output token must be pUSD;
- receiver must be the authoritative deposit wallet/funding address;
- target pUSD amount must be proven by simulated output or settlement;
- quote-only funding is denied for autonomous mode.

Direct pUSD owner-to-deposit transfers are simple ERC-20 transfers and can use
decoded standard calldata plus normal TxEngine policy.

## Required Tests

- Quoter client parses simulate/validate fixtures.
- Validate fails when `data`, `to`, `from`, `value`, or `chainId` changes.
- Policy denies no-simulation route by default.
- Policy denies expired simulation.
- Policy denies success status with empty `amountOut`.
- Policy denies below-floor output.
- Policy denies unverified receiver for autonomous VFS.
- Foreground quote-only path requires explicit signed policy opt-in.
- VFS `confirm` refreshes validation immediately before staging.
- Cross-chain dependent action refuses until live settlement proof exists.

## Minimum Useful PR

1. Quoter client.
2. Empirical fixtures for the WP0 shapes.
3. Verification artifact.
4. Simulation-first policy defaults.
5. VFS confirm refuses quote-only and accepts verified source-leg simulation.
6. Cross-chain dependent actions remain blocked until live settlement proof.

Do not implement a generic Enso calldata decoder, route-planning changes,
scoped capabilities, or unrelated Polymarket order changes in this work.
