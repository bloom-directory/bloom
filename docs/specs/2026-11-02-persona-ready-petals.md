# Persona-ready Petals: declared effects, no Petal-specific code outside Petals

**Status:** revision 3, replacing the 2026-11-03 revision of
`docs/specs/2026-11-02-persona-ready-petals.md`
**Date:** 2026-11-04
**Applies to:** Machine #377, Broker #112, Signer #81, SDK #52, Polymarket #26,
Gasless #4 (all open, all unreleased)

## Goal

An owner picks a persona at onboarding: Institutional, Trader or Degen. Under
Trader or Degen, Petals act up to the owner's recurring token limits without
per-action approval. Anything outside a limit, or not declared, falls back to
exact review. Institutional has no automatic tier.

Adding automatic coverage for a Petal must need **only a Petal PR and a catalog
pin**. It must not need a Broker, Signer or Machine source change.

## What changed since revision 2

Revision 2 kept protocol verifiers in Broker (`PolymarketBuyV1`,
`GaslessEip3009V1`) and said a new protocol may need a small Broker verifier.
The owner has rejected that.

| ID | Decision |
|---|---|
| R1 | **No Petal-, protocol-, contract- or operation-class-specific code in Broker.** Broker understands only standards: EIP-712 typed data, EIP-191 text, EVM transactions, ERC-20 and native transfers from the wallet itself, Solana native transfers. |
| R2 | **Broker trusts the pinned, installer-signed Petal's declared effects** for automatic coverage. It does not independently verify that the declaration matches the signed bytes. Byte-level verification of declarations is a later hardening item (see [Later](#later)), not part of this work. |
| R3 | Eligibility is data, not a class list. A route is eligible when its installer-signed provenance enables declared effects and its action either declares a bounded spend within an active grant, or declares zero spend under a Trader or Degen grant (R6). Everything else uses exact review. The hardcoded always-exact class list is removed. |
| R4 | Machine aims for the same rule. Petal knowledge in Machine (default Petals, labels, destinations, setup prompts, route tables) moves out of code branches into catalog data. |
| R5 | The stack is split. The generic infrastructure lands first. Existing Bloom releases are unaffected because all of this is unreleased. |

Decisions kept from revision 2:

| ID | Decision |
|---|---|
| P6 | Allowances limit what can be **signed** per rolling window, not outstanding exposure. Cancels do not refund. |
| P7 | Polymarket SELL keeps exact review. |
| P8 | No ceremony-composition project. Separate approvals, driven through the browser, including rearm. |
| P10 | Budgets stay independent per Petal and account. Onboarding and status show the additive capacity. Wallet-wide ceilings are a separate, later product decision. |
| P4 | ERC-20 approve and consumer calls stay on exact review. |

### Zero-spend actions (R6, accepted 2026-11-04)

Logins (Polymarket ClobAuth, Venice SIWE) and Hyperliquid orders spend no
wallet tokens. Until now a zero debit was never eligible for automatic
coverage.

**Decision:** a declared `Spend::None` action is automatic under Trader and
Degen. Under Institutional (Custodian) it always uses exact review. The
persona decides this; the operation class does not.

Guardrails:

- **Persona decides.** The persona preset sets this. Persona compilation emits
  zero-spend coverage only for Trader and Degen. Broker enforces it from the
  grant, never from the class.
- **Per-Petal consent.** The grant lists the operation classes the Petal
  declared as zero-spend in its installer-signed provenance. The owner sees
  them at onboarding as "these actions move no tokens from your wallet and
  have no spending limit".
- **Rate cap.** Each grant has a cap on zero-spend actions, set by the persona
  preset. Example: Trader 60 per hour, Degen 300 per hour. An action over the
  cap uses exact review.
- **Exactly zero.** `Spend::None` means the action moves no wallet assets. A
  declaration with any debit goes through the normal token-limit path.
  `Spend::Unspecified` is never automatic.

Caveat: a `None` action is bounded only by the rate cap. Hyperliquid orders
risk venue margin that no token budget sees. The onboarding copy says so.

R6 removes Machine's ClobAuth verifier and one-use refresh special case. A
ClobAuth login is a declared zero-spend action, refreshed by the Petal, which
signs again.

## Architecture after this work

**Petal**
- Builds a `PreparedAction` with typed signing input and a review artifact in
  a generic format.
- Declares its spend with `.with_spend(Spend::erc20(...))`, or
  `Spend::None` for actions that move no wallet assets (R6).
- Calls one SDK helper that handles the operation key, retry/resume, outcome
  mapping and the status route.
- Manifest: `economic_effects_schema = 1`, `bloom:sign`, `bloom:sign.status`.

**SDK**
- Typed payload constructors, including `SigningPayload::eip712(typed_data)`,
  which computes the hash and the `bloom.message.review` v1 artifact together.
  A Petal cannot send a review that disagrees with its hash.
- The plumbing that Polymarket and Gasless each wrote by hand:
  - operation-key derivation and an attempt record;
  - `sign_or_resume`, which maps `Signed`, `ApprovalPending` and
    `RecoveryRequired` to one result with standard codes and persists the
    phase;
  - a ready-made `approval.json` status route backed by `signing::status`;
  - an optional check that the signature recovers to the owner;
  - a typed `Spend` with no string chain ids.

**Machine**
- Accepts generic review formats: `bloom.message.review` v1 (EIP-712 or
  EIP-191) and wallet-origin transactions. Removes the Polymarket-specific
  `polymarket.prepared-record` format and the class checks tied to it.
- Persona discovery works on every prepared route, not only the Polymarket
  batch route.
- Removes `gasless.relay`, `hyperliquid.agent_action` and Polymarket branches
  from `persona_sessions.rs`, `bloom-daemon/src/lib.rs` and
  `bloom-machine-client`.
- Reads default Petals, labels, destinations, setup prompts and authority
  route tables from catalog data rather than compiled match arms.

**Broker**
- Keeps the generic infrastructure:
  - raw-token budgets with rolling windows;
  - reservations and the journal;
  - standing grants and rearm that preserves usage;
  - any-recipient ERC-20 for Degen;
  - native EVM and Solana transfer checks;
  - the Signer nonce commitment.
- The declared-effects path (effects-v1) becomes the only automatic path for
  Petal actions. It still checks:
  - installer-signed provenance enables declared effects;
  - payload index, network and spending account match the grant;
  - every declared asset is in the grant's token policy;
  - amounts are positive, use checked uint256 arithmetic, and never net
    across assets;
  - `permission_effect = None`;
  - per-action and rolling limits, reservations, retries and rearm.
- Exact review renders generic formats only. For EIP-712 that includes
  ERC-7739 `TypedDataSign` envelopes, which are ordinary typed data.
- Review and onboarding copy come from package and catalog data: the Petal's
  display name, its declared assets, the persona amounts. Nothing is keyed on
  class prefixes.

**Signer**
- Unchanged beyond #81: structural reusable scopes and rearm that preserves
  counters. No economics.

## Delivery

Each phase leaves every PR green and the stack working end to end.

### Phase 1: mergeable generic stack

Remove Petal-specific code and fix what blocks merging. Most of this phase
deletes code from the current PRs.

**Broker #112**
- Delete:
  - `ReusableEffectsVerifier` and the compiled profile table in
    `bloom-broker-api/src/reusable_profile.rs`, with their addresses and
    labels;
  - the dispatch in `service.rs` (around line 1631);
  - `message_review/polymarket.rs`, `message_review/gasless.rs`,
    `verify_polymarket_session_use` and `validate_order_debit`;
  - the legacy `polygon:pusd` claim shape;
  - the Polymarket-only branch in `validate_selector`;
  - the refusal-only legacy `SystemSession` draft shape;
  - `approved_session_asset`'s hardcoded pUSD (use `tokens.json`).
- Replace the always-exact class lists (`MESSAGE_REVIEW_OPERATION_CLASSES`,
  `POLYMARKET_*`, `message_review_requires_exact`, and the
  `validate_generic_session_profile` refusal around `service.rs:915-945`) with
  R3: eligible only if provenance enables declared effects and the grant
  covers the declared assets.
- Remove Petal-specific copy:
  - `ceremony_assets/app.js`: `describeIntegration`, the `polymarketBuy` and
    `gaslessPayment` branches, and the Relay address in the UI;
  - `ceremony.rs`: the per-class disclosure match;
  - `ceremony_assets/onboarding/*`: default Petals, "Polymarket: pUSD only",
    hardcoded Trader and Degen amounts.

  Render these from data that Machine passes in the onboarding request and
  from the package's display name.
- Implement R6 in the grant and the reservation path:
  - the grant carries the zero-spend operation classes and a rate cap;
  - a `Spend::None` use is accepted only under a Trader or Degen grant that
    lists its class;
  - zero-spend uses are counted against the cap in the same journal
    transaction as other reservations;
  - Institutional grants never carry zero-spend coverage.
- Replace "App-reported amounts could understate spending" with neutral copy:
  "Amounts are reported by <Petal>, a reviewed Bloom package." Do not imply
  that Broker verified them.
- Add a guard test that fails if non-test Broker source contains
  `polymarket|gasless|venice|hyperliquid|near-intents|pendle|privacy-pools|enso|relay`
  (case-insensitive) or a known Petal contract address. Existing master
  occurrences (for example Hyperliquid exact-review field labels) go in an
  allowlist file that may only shrink.
- Rebase onto the updated Signer pin once #81 has CI.

**Machine #377**
- Remove from `prepared_signing.rs`: the two-format allowlist, the
  `polymarket.prepared-record` branch and the Polymarket class checks. Accept
  `bloom.message.review` v1 generically.
- Implement R6: zero-spend coverage is emitted only for Trader and Degen
  personas and carries the persona's rate cap. Delete the ClobAuth verifier
  (`clob_validate` and the `POLYMARKET_CLOB_AUTH_CLASS` handling) and its
  one-use refresh special case.
- Remove the `gasless.relay` branches in `persona_sessions.rs` (around lines
  876, 887 and 1204) and `bloom-daemon/src/lib.rs` (around line 350). Step-up
  to exact review must be class-agnostic.
- Allow persona discovery on all prepared routes.
- Fix CI: the "prepared signing SDK host fixture" job fails with
  `E0463 can't find crate for core`. Run `prepared_actions` in CI instead of
  leaving it `--ignored`.
- Fix the browser flows that block end users:
  - rearm must not require pasting a 64-hex approval hash;
  - onboarding must not tell the user to "repeat activation"; reconcile
    automatically.

**Signer #81**
- Get CI to run on the head. It has no runs.
- Replace the `u64::MAX` expiry sentinel with a typed value if that is cheap.
- Correct the comment in `validate_against_approval` that overstates the
  EVM/SOL split.

**SDK #52**
- Rerun the cancelled macOS builder job.
- Make Polymarket and Gasless agree on one SDK pin. Today they use `3e7ac46`
  and `a285dcd`.

**Petals**
- Polymarket #26:
  - send orders as `bloom.message.review` v1 EIP-712 typed data with the
    `TypedDataSign` primary type instead of `polymarket.prepared-record`;
  - delete `review_witness`, `prepared_order_signing`, the dead
    `prepared_batch_effects` calls and the `polymarket::claim` module they
    keep alive.

  BUY declares the pUSD debit. SELL keeps exact review (P7). ClobAuth login
  declares `Spend::None` and re-signs on refresh, with no Machine special case.
- Gasless #4: already on `bloom.message.review` with an ERC-20 spend. Add
  `bloom:sign.status` and read status through the SDK instead of a private
  approval JSON.

**Phase 1 exit**
- With real isolated Machine, Broker and Signer and the built WASM:
  - a Degen ERC-20 transfer and a Polymarket BUY each sign with zero extra
    ceremonies after onboarding;
  - a Gasless relay payment and a Polymarket login do the same;
  - under Institutional, the same login requires exact review;
  - ledger charges are exact.
- No Broker source names a Petal (guard test).
- All six PRs are green.

### Phase 2: minimal Petal surface

- SDK: `SigningPayload::eip712`, `sign_or_resume`, the attempt record, the
  status route, and typed `Spend`.
- Polymarket and Gasless move onto the SDK helpers and delete their own
  operation-key, outcome-mapping and `approval_projection` code.

  Measured today: about 285 lines of plumbing in Polymarket and about 85 in
  Gasless, against about 115 and 75 lines of domain logic.
- Machine: move `DEFAULT_PETALS`, `petal_label`, `petal_destinations`,
  `POLYMARKET_SETUP` and the `PetalAuthorityRoute` tables in `github_source.rs`
  into catalog data, either the signed release catalog or, as a first step, an
  embedded data file.
**Phase 2 exit:** a fixture Petal that declares an ERC-20 spend gets automatic
coverage end to end with no source change outside the fixture and the catalog.

### Phase 3: further Petals

Each is one Petal PR plus a catalog pin, with no Broker, Signer or Machine
change.

| Petal | Work | Approvals within limits |
|---|---|---|
| venice-x402 | Move off `sign_hash`; top-up declares the USDC debit; SIWE declares `Spend::None` (R6) | 0 under Trader/Degen |
| hyperliquid | `usd_send` and `withdraw` declare debits; orders declare `Spend::None` (R6); the agent-session approval joins onboarding; delete its private `ClaimEffects` and nonce code | 0 per order after onboarding |
| near, pendle, privacy-pools | Prepared-action or outbox coverage with declared spend (outbox matching is separate Machine work) | 0 per covered action |

### Phase 4: end-user pass

- One activation run, with ceremonies driven in the browser.
- Status shows each Petal's remaining capacity and which limit applies.
- Persona copy and presets come from one source keyed by exact asset identity.
- Degen any-recipient chains come from the token catalog rather than
  `[1, 137]`.

## Acceptance for every Petal

- Two distinct covered actions need zero additional ceremonies, with exact
  ledger charges.
- Retries, restart and rearm do not double-charge.
- An over-limit action requires exact review before signing.
- An action with no declaration, or with an asset outside the grant, requires
  exact review.
- Malformed input, invalid provenance, or a review artifact whose hash does
  not match the payload is rejected outright.
- Institutional still requires individual approval, including for zero-spend
  actions.
- Zero-spend actions beyond the rate cap require exact review.

## Later

- **Byte-level verification of declarations.** Broker would check a declared
  debit against the signed bytes, using standards it knows (EIP-3009,
  ERC-20) or data descriptions supplied by the Petal. This is the main
  hardening step after R2.
- Wallet-wide per-asset ceilings (P10).
- Automatic ERC-20 approve and consumer flows (P4).
- Venue assets such as Hyperliquid margin.
- An exposure model for open orders.
