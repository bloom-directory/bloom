# Scoped Agent Run Capabilities Roadmap

Date: 2026-06-13

Goal: the user approves one bounded task, then Bloom may execute only matching
actions within signed limits, without a fresh action-review prompt for every
step.

`agent_autonomy = "under_policy"` is a low-level policy result, not the product
UX. The user-facing primitive is a signed, scoped run capability with exact
action matching, expiry, and one-use or bounded spend accounting.

Related docs:

- `docs/plans/2026-06-13-enso-simulation-verification.md`
- `docs/specs/passkey.md`
- `docs/AGENTIC_WALLET.md`
- `docs/polymarket-integration.md`

## UX Modes

```text
Manual approval
Bloom asks before every transaction, trade, or wallet-signing action.

Agent-guided task
The user approves a limited task. Bloom may act without more prompts only inside
that exact signed scope.
```

V1 scope:

- one signed capability;
- one exact Polymarket order action;
- short expiry;
- current wallet policy still passes;
- one-use reservation before signing;
- refusal on edited scope, edited approval, missing/invalid ledger, policy
  digest mismatch, signer unavailable, expiry, revocation, or exact-action
  mismatch.

Out of V1: multi-action task envelopes, bridge/fund/trade graphs, autonomous
Enso funding, generic EVM transaction capabilities, and standing bots.

Passkey wording must stay precise: WebAuthn unlock makes a signer available;
the signed capability authorizes what Bloom may do. A valid capability does not
unlock a cold passkey wallet.

## Current State

Implemented:

- EVM outbox confirms call `evaluate_action_authorization`.
- `agent_autonomy = "under_policy"` can approve EVM actions only when policy
  denies/warnings are absent, route facts are verified, valuation exists, and
  tx/day limits pass.
- Passkey review pages gate WebAuthn behind browser approval and persisted
  review hashes.
- Polymarket order policy exists: enablement, allow/deny lists, price caps,
  per-order/daily caps, and market-state checks.

Not implemented:

- Polymarket order confirm does not use `evaluate_action_authorization`.
- No signed capability store, matcher, spend ledger, or revocation mechanism.
- Editable JSON is not trusted authority until the signed scope is verified.
- Enso funding is not eligible for unattended autonomy until receiver,
  min-output, and settlement checks exist.

## Security Invariants

- Authority comes from a verified signature over canonical scope, not editable
  files.
- Capability signature is checked on every use.
- Current wallet policy still applies; capabilities are narrower than policy.
- `under_policy` alone must not silently enable Polymarket autonomy.
- Capabilities do not unlock passkey wallets.
- Policy warnings require review unless explicitly modeled in signed scope; V1
  should avoid warning auto-acceptance.
- Missing, unreadable, truncated, inconsistent, or schema-invalid ledger state
  refuses autonomy.
- Expired or revoked capabilities refuse.
- Settlement files are cache only; dependent bridge/fund/trade legs require
  fresh live balance/receipt proof.
- Capabilities expose typed actions only, never arbitrary calldata or arbitrary
  CLOB JSON.
- Exact asset caps are preferred over oracle USD caps.
- Capability checks happen at the final signing boundary.
- V1 revocation is local refusal state; short expiry remains the hard limit.

Threat-model ceiling: this protects against editable local state, stale scopes,
parallel agents, and scope-drift bugs. It is not a hardware trusted display and
does not protect against a malicious Bloom binary rendering a false review page.

## Blocking Corrections

- Ledger deletion must not reset spend; missing/invalid ledger refuses.
- `settlement.json` is never proof.
- No generic `evm_tx` in V1; future EVM support must pin exact bytes or use
  typed actions such as `erc20_transfer` / `erc20_approve`.
- Policy digest mismatch disables capability autonomy.
- `reserved` can wedge safely until typed reconciliation or expiry.
- V1 is single-action, especially Polymarket order execution.
- Valid capability plus cold signer fails clearly or enters an explicit unlock
  flow; it must not imply signing is free.

## PR A: Docs And UX Language

Make the current system honest before new autonomy:

- distinguish wallet unlock, action authorization, and scoped task approval;
- remove wording that implies one passkey ceremony per value-moving action is
  inherent forever;
- remove wording that treats `under_policy` as the final UX;
- document that Polymarket orders are policy-gated today but not yet
  capability-autonomous;
- document that Enso funding is foreground/human-reviewed until route facts are
  verified.

## PR B: Polymarket Authorization Rail

Build `AuthorizationSubject` from the final revalidated `OrderDraft`
immediately before signing.

Canonical facts include side, slug, condition id, token id, outcome, order type,
price bounds, spend/size, maker/funder, signature type, neg-risk flag, and CLOB
chain id. Call `evaluate_action_authorization` after market revalidation,
policy evaluation, geoblock, and sell holdings preflight.

PR B must not let `agent_autonomy = "under_policy"` alone approve orders. Fresh
review remains the default until PR C supplies a verified scoped capability.

Tests:

- Polymarket deny checks still block before authorization.
- Policy warnings still require fresh review.
- Subject hash changes when slug, token id, amount, price, funder, or signature
  type changes.
- `under_policy` alone does not approve a Polymarket order.

## PR C: Single-Action Signed Capability

Storage layout:

```text
~/.bloom/capabilities/<wallet>/<cap-id>/scope.json
~/.bloom/capabilities/<wallet>/<cap-id>/approval.json
~/.bloom/capabilities/<wallet>/<cap-id>/ledger.json
~/.bloom/capabilities/<wallet>/<cap-id>/revoked
~/.bloom/capabilities/<wallet>/.lock
```

`scope.json` is canonical signed scope. `approval.json` stores the proof.
`ledger.json` is mutable reservation/spend state and is never authority by
itself.

Signature model: prefer EIP-712; acceptable V1 is domain-separated EIP-191 over
canonical scope bytes. Matcher verifies recovered owner, wallet identity,
policy digest, expiry, revocation, scope hash, approval, and typed action match.

V1 action kind: `polymarket_order`. Later action kinds may include cancel,
redeem, withdraw pUSD, and verified pUSD transfer funding. Do not include
generic `evm_tx` or Enso swap funding in V1.

Ledger state must be serialized under a lock and updated before signing:
`unused`, `reserved`, `succeeded`, `ambiguous`, `revoked`. Reserved/ambiguous
never blindly retry; reconciliation must inspect Polymarket drafts, receipts,
open orders, and CLOB status.

Matcher output:

- `ApprovedCapability { capability_id, debit_micro_usd }`
- `NeedsFreshReview { reason }`
- `Denied { reason }`

Polymarket order matching compares typed facts exactly: slug, condition id,
token id, side, outcome, funder, signature type, price/spend bounds, order type,
and neg-risk allowance.

Revocation creates local refusal state and an audit record; it does not require
the wallet key.

## PR D: Later Settlement-Gated Multi-Step Runs

Multi-step bridge/fund/trade requires explicit dependencies in scope and a
fresh settlement verifier result before dependent actions. A forged or edited
`settlement.json` must not satisfy the matcher.

Tests must cover early trade refusal, matching settlement acceptance, wrong
receiver/token/minimum refusal, missing live read refusal, stale proof refusal,
and forged cache refusal.

## PR E: Later Verified Funding Routes

Autonomous Enso funding requires proof of source chain, destination chain,
sender, router, receiver, token out, minimum output or balance delta, attached
native value, and ERC-20 approval amount/spender.

Acceptable mechanisms:

1. decode known router calldata;
2. simulate with reliable balance-delta assertions;
3. for cross-chain, pair source verification with live destination settlement.

Autonomous funding refuses if receiver, min-output, token, native value, route
protocol, approvals, or policy warnings cannot be verified.

## Order

1. Docs/UX cleanup.
2. Polymarket authorization subject and evaluator rail, autonomy still off.
3. Canonical scope + approval signature + verification.
4. Exact Polymarket matcher + single-use reservation + revocation.
5. Execute one matching order through a verified capability at the final signing
   boundary.
6. Add other single-action Polymarket capabilities only after their matchers are
   specified.
7. Settlement gates for multi-step runs.
8. Verified Enso funding route facts.

## Definition Of Done

V1 is done when the user can approve one task:

```text
spend at most $10,
buy YES only on this exact market,
max price 0.70,
expires in 10 minutes.
```

Bloom may place only that matching order without another action-review prompt
if the signer is already available. It refuses any different market, token id,
side, funder, signature type, price, amount, expired scope, revoked scope,
edited capability file, missing ledger, policy digest mismatch, or overspend.

Multi-step bridge/fund/trade is later and must additionally refuse different
receivers/routes, unverified routes, forged settlement files, missing live
settlement proof, and unsettled dependent legs.
