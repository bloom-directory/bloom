# Persona-ready Petals: declared effects, no Petal-specific code outside Petals

**Status:** revision 3, replacing the 2026-11-03 revision of
`docs/specs/2026-11-02-persona-ready-petals.md`
**Date:** 2026-11-04 (Phase 2 expanded 2026-11-05)
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
- Typed payload constructors, including the free function
  `signing::eip712_action(class, typed_data)`, which computes the hash and
  the `bloom.message.review` v1 artifact together. A Petal cannot send a review that disagrees with its
  hash.
- The plumbing that Polymarket and Gasless each wrote by hand (specified in
  [Phase 2](#phase-2-minimal-petal-surface)):
  - an `Attempt` record that freezes the action and derives its operation
    key;
  - `sign_or_resume`, which maps every outcome to one result with standard
    codes;
  - one normalized `AttemptState` read from `signing::status`, plus a helper
    for `approval.json` routes;
  - a typed EVM spend constructor, `signing::erc20_spend`, with no string
    chain ids.
- Signature checks against protocol digests stay in the Petals. Machine
  already verifies every signature against the selected key.

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

Move the signing plumbing that Polymarket #26 and Gasless #4 each wrote by
hand into one small SDK module. A Machine prerequisite ships first:
[a status index and a `NotFound` code](#phase-2-prerequisite-status-index-and-notfound).
After that, the SDK and Petal work needs no Broker, Signer or Machine source
change.

**Not in this delivery:** catalog-table extraction (moved to
[Phase 2b](#phase-2b-catalog-data-not-in-this-delivery)) and any further
Petal integration (Phase 3).

#### Phase 2 prerequisite: status index and NotFound

An ordered prerequisite commit in the existing Machine PR, plus a contract
change in the existing SDK PR, before the SDK and Petal integration commits. It has two parts. Neither touches Broker or Signer.

**Status index.** Today every status read scans the whole `.prepared`
directory and fails once it holds 4096 entries (see Grounding). Replace the
scan with an index:

- Index entries live at
  `.prepared-index/{blake3(package_hash, wallet, operation_key)}.json`. Each
  lists the record paths for that triple. The index sits beside
  `.prepared`, not inside it, and both are guarded by the existing
  `.prepared/.lock`.
- `run_prepared` adds the record's path to the index entry **before** it
  writes a new record. On every call it also repairs a missing entry for an
  existing record. An index entry pointing to a missing record is skipped.
- `status_prepared` reads the one index entry and loads only the records
  listed in it. It applies the existing filters (package hash, wallet,
  operation key, selected key). The outcomes are unchanged: two matches
  return `Conflict "ambiguous operation key"` and none returns `NotFound`.
  Status no longer depends on how many records exist.
- Backfill: if `.prepared-index/.complete` is missing, the first status call
  indexes every existing record under the lock, with no cap, then writes the
  marker. A crash during backfill restarts it. This handles records written
  by Phase 1 builds.
- A missing index entry triggers repair from authoritative records before a
  not-found result is returned. A corrupt entry returns an error or is
  repaired; it never becomes `NotFound`. Known valid entries retain indexed
  lookup; unknown or missing entries may require a full scan. Test missing
  and corrupt entries after backfill has completed.
- Record pruning stays out of scope.

**`NotFound` code.** Add `ErrorCode::NotFound` to
`bloom_petal_contract::prepared`. `status_prepared` returns it, with the same
`"operation not found"` message, in place of `Invalid`. No other path returns
it. Petals built against the previous SDK cannot decode the new variant, so a
not-found status read reports a decode error (`-4`). That fails closed.
Polymarket and Gasless move to the new pin in this delivery. The SDK never
matches the message text.

Prerequisite tests (Machine daemon `prepared_signing`, exercising the real
`status_prepared` implementation):

- **P1** `status_index_ignores_unrelated_records`: seed more than 4096
  unrelated records, plus stray `.tmp` files. Status still finds the
  fixture's record and returns `NotFound` for an unknown key.
- **P2** `status_index_backfills_phase1_records`: records written without an
  index are found after backfill. The marker is written once.
- **P3** `status_index_keeps_ambiguity_and_key_filters`: the same operation key
  from two routes returns `Conflict`, and a record whose selected key changed
  is skipped. Both match today's scan.
- **P4** `status_not_found_uses_code`: an unknown key returns
  `ErrorCode::NotFound`.
- **P5** `status_index_crash_between_index_and_record`: an index entry with no
  record returns `NotFound`. The next sign writes the record, and status then
  finds it.

#### Grounding: what exists today

These facts, from the PR heads named below, constrain the design.

| Fact | Where |
|---|---|
| Machine stores one record per (package hash, route, wallet, `KeyRef`, operation key), holding the frozen `PreparedAction` and its last outcome. Re-sending the same key with a different action returns `Conflict`. A stored `Signed` is verified again and replayed without a new signature or charge. | Machine #377 `prepared_signing.rs` `run_prepared` |
| Status looks up (package hash, wallet, operation key) across all routes. Two routes using one key return `Conflict "ambiguous operation key"`. An unknown key returns `Invalid "operation not found"`. | `status_prepared` |
| An ambiguous Broker result (`OperationIdConflict`, `RECOVERY_REQUIRED`, `signing outcome unknown`) becomes `RecoveryRequired{signing_outcome_ambiguous}`. The outcome is not overwritten. A retry with the same key re-sends the same Broker operation id, and Broker deduplicates it. | `prepared_signing_failure` |
| Expired and cancelled ceremonies are terminal for that key, on both sign and status (`Err(Expired)`, `Err(Cancelled)`). An approved but not yet consumed approval reports `RecoveryRequired{approved_retry}`. A record with no outcome reports `RecoveryRequired{operation_in_progress}`. | `prepared_ceremony_terminal`, `status_prepared` |
| Machine verifies each signature against the selected key before returning it (`prepared_verify`). | `run_prepared` |
| Route error `-2` reaches the agent as a message-less PermissionDenied. `-3` (Invalid) and `-4` (Backend) keep their message. | Machine `bloom-petals/src/router.rs:976` |
| The SDK has `signing::sign`, `signing::status`, the contract DTOs, and `Spend::erc20(network: &str, address: &str, amount: &str)`. It has no EIP-712, attempt or status helpers. | SDK #52 `crates/petal-sdk/src/signing.rs`, `src/prepared.rs` |
| Polymarket `approval.rs` holds `PreparedSigning` (preimage hex, hash, typed data, blake3 digest) and `typed_action`. It derives keys with `operation_identity(key, class, attempt)`, where the attempt suffix is a relayer nonce or login timestamp. `sign_action_for` maps outcomes to `-3`, and `approval_projection` matches `"operation not found"` by string. Six `approval.json` routes rebuild key lists. A relayer-signature cache (`prepared_relayer_signature.json`) duplicates Machine's replay. | Polymarket #26 at `ff9590c` |
| Gasless builds the same EIP-712 review inline and derives its key as `relay:{id}:{request_id}`. It maps a pending approval to `-2`, so Machine drops its message and `retry_write_body`. It persists `approval_required` and `recovery_required` phases, then recomputes them from status with the same `"operation not found"` string match. It reports `approved_retry` as `recovery_required`. Polymarket has the same mismatch. | Gasless #4 at `5ffb9c1` `relay.rs`, `common.rs` |
| Machine's status scan reads `.prepared` with one `read_dir` that is shared by every Petal, wallet and route. It counts every directory entry (`.lock` and `*.tmp` included) before filtering, and returns `Backend "too many prepared signing records"` at the 4097th entry, even when it has already found the requested record. Nothing prunes records. `sign` opens its record by path and is unaffected. | `status_prepared` (`prepared_signing.rs:572`) |
| `Ctx` exposes `package_hash`. The SDK already binds effects claims to it. | SDK #52 `effects.rs` |
| `PreparedAction`, `Spend` and the other DTOs are defined in `bloom-petal-contract` and re-exported by `petal::signing`. The SDK cannot add inherent methods to them. | SDK #52 `signing.rs:4` |

#### SDK API

All additions live in `petal::signing` in `bloom-petal-sdk` as free functions
and SDK-owned types. The contract crate does not change. EIP-712 and typed
EVM amounts sit behind a new `evm` feature, which depends on
`alloy-dyn-abi = "1.6"` (`eip712`) and `alloy-primitives = "1.6"`. Both
Petals already link these crates. Polymarket drops its `=1.6.0` exact pin so
both resolve to one version.

```rust
// Typed construction (feature "evm"), free functions over contract DTOs
/// 0x1901 ‖ domainSeparator ‖ hashStruct, keccak256, and the
/// bloom.message.review v1 {"kind":"eip712","typed_data":…} artifact,
/// from one parsed TypedData. Spend starts Unspecified; add it with the
/// contract's existing PreparedAction::with_spend.
pub fn eip712_action(class: &str, typed_data: &serde_json::Value)
    -> Result<PreparedAction, SigningError>;
/// Same wire DTO as Spend::erc20("evm-<id>", lowercase hex, decimal).
pub fn erc20_spend(chain_id: u64, token: Address, amount: U256)
    -> Result<Spend, SigningError>;

// Host seam: production impl over &Ctx; Petals with mocks implement it.
pub trait SigningHost {
    fn package_hash(&self) -> &str;
    fn store_get(&mut self, key: &str) -> Result<Option<Vec<u8>>, SigningError>;
    /// Create-only. Ok(false) if the key already exists.
    fn store_put_new(&mut self, key: &str, value: &[u8]) -> Result<bool, SigningError>;
    fn sign(&mut self, wallet: &str, action: &PreparedAction, operation_key: &str)
        -> Result<SigningOutcome, SigningError>;
    fn status(&mut self, wallet: &str, operation_key: &str)
        -> Result<SigningOutcome, SigningError>;
    fn now_ms(&mut self) -> Result<u64, SigningError>;
}
pub struct CtxHost<'a>(pub &'a Ctx);

// Attempt persistence. C is Petal-owned context frozen with the action.
pub struct Attempt<C = ()> { /* scope, generation, package_hash, action, context */ }
impl<C: Serialize + DeserializeOwned> Attempt<C> {
    /// Return the latest generation under `scope`. If none exists, call
    /// build() and create generation 0. If another caller created it first,
    /// return theirs (build's result is discarded).
    pub fn open(h: &mut impl SigningHost, scope: &str,
                build: impl FnOnce() -> Result<(PreparedAction, C), SigningError>)
        -> Result<Self, SigningError>;
    pub fn load(h: &mut impl SigningHost, scope: &str) -> Result<Option<Self>, SigningError>;
    pub fn action(&self) -> &PreparedAction;
    pub fn context(&self) -> &C;
    pub fn generation(&self) -> u32;
    pub fn operation_key(&self) -> String;     // "{scope}#{generation}"
    /// Read Machine's state live; never writes.
    pub fn state(&self, h: &mut impl SigningHost, wallet: &str)
        -> Result<AttemptState, SigningError>;
    /// Create generation n+1 if the renewal rules below allow it.
    pub fn renew(self, h: &mut impl SigningHost, wallet: &str,
                 build: impl FnOnce(&Self) -> Result<(PreparedAction, C), SigningError>)
        -> Result<Self, SignHalt>;
}

// Signing and status
pub fn sign_or_resume<C>(h: &mut impl SigningHost, wallet: &str, attempt: &Attempt<C>)
    -> Result<Vec<u8>, SignHalt>;              // Ok = signature bytes
pub enum AttemptState {
    NotStarted, Pending { action_id: String, expires_ms: u64 },
    Approved, Signed, Expired, Cancelled, Denied,
    RecoveryRequired { status: String },
    PackageChanged,
}
pub struct SignHalt { /* state + message */ }
impl From<SignHalt> for DispatchResponse { /* codes below */ }
/// Body of an approval.json route: the first scope (in order) whose
/// latest attempt is not NotStarted, Signed or Denied, as JSON; otherwise
/// -3 "no pending signing approval". Errors from state() return -4.
pub fn approval_read(ctx: &Ctx, wallet: &str, scopes: &[&str]) -> DispatchResponse;
```

**Records.** Each generation is its own create-only store entry at
`{scope}.{n}.json`:
`{"schema":"bloom.petal.attempt.v1","package_hash":…,"generation":n,"action":…,"context":…}`,
parsed with `deny_unknown_fields`. Context is limited to 64 KiB. No entry is
ever overwritten or deleted by the SDK. The latest generation is found by
reading `{scope}.0.json`, `{scope}.1.json`, … until one is missing. There
are at most 32 generations per scope. Past that, `renew` returns `-3` and the
Petal opens a new scope. A record that fails to parse returns `-4` and is
left in place. The record has no phase or outcome cache. Machine holds the
only outcome, and `state()` reads it live.

Context keeps the inputs a Petal needs after signing in the same write as
the action they produced, such as Polymarket's `PreparedOrder`,
`PreparedBatch` or login timestamp. A crash therefore never leaves the
inputs and the frozen action out of step.

**Operation key** = `"{scope}#{generation}"`. Scopes are unique per package
and wallet, which the status lookup requires. The SDK rejects a key longer
than the contract's 256 bytes.

**State normalization:**

| Condition | `AttemptState` |
|---|---|
| record `package_hash` ≠ `ctx.package_hash` (checked first, without calling Machine) | `PackageChanged` |
| `Err(NotFound)` | `NotStarted` |
| `ApprovalPending` | `Pending` (`approval_read` adds `"expired_locally": true` once `now_ms ≥ expires_ms`; renewal still waits for Machine's `Expired`) |
| `RecoveryRequired{approved_retry}` or `{eligibility_approved_retry}` | `Approved`: the next write signs |
| other `RecoveryRequired{s}` | `RecoveryRequired{s}` |
| `Signed` | `Signed` (the signature is never put in JSON) |
| `Err(Expired)` / `Err(Cancelled)` / `Err(Denied)` | `Expired` / `Cancelled` / `Denied` |
| any other error, including `Invalid`, `Backend` and `Conflict "ambiguous operation key"` | returned as `Err`; **never** `NotStarted` |

**`sign_or_resume`** calls `sign` directly; it does not call `status` first.
Machine resumes or replays on its own, so a status failure never blocks
signing. It refuses a `PackageChanged` attempt without calling
Machine.

**Codes from `SignHalt`.** Pending, Approved, Expired, Cancelled,
RecoveryRequired and PackageChanged return `-3` with a message naming the
`action_id` or status and the next step. `-3` because `-2` loses the message.
This fixes the dropped Gasless message. `Denied` returns `-2`.
`Invalid`/`Unsupported` return `-3`. `Conflict` and `Backend` return `-4`.

**Usage.**

```rust
// Polymarket order post (inside the existing trade lock)
let mut h = CtxHost(ctx);
let attempt = Attempt::open(&mut h, &format!("{base}/attempt"), || {
    let order = PreparedOrder::from_draft(&draft, fee_cap_micro)?;
    Ok((order.action(owner, funder, chain_id)?, order))   // Petal: BUY principal + fee cap
})?;
let sig = sign_or_resume(&mut h, wallet, &attempt)?;
let sig = verified_signature(owner, attempt.context().digest(chain_id), &sig)?;

// Any approval.json route
petal::route_file!(spec: petal::store_read_spec().caps(&["bloom:sign.status"]),
    read: |ctx: &petal::Ctx| {
        let (w, id) = match (petal::wallet_param(ctx), petal::param(ctx, "id")) {
            (Ok(w), Ok(id)) => (w, id), (Err(r), _) | (_, Err(r)) => return r };
        petal::signing::approval_read(ctx, w, &[&format!("trade/{w}/drafts/{id}/attempt")])
    });
```

#### Macro decision: none

Do not add a macro. `route_file!` already generates the route. After
`approval_read`, each `approval.json` body is three to four lines. A macro
would save about two lines in each of six files. It would also need
`petal-builder`'s `required_caps` parser, which reads quoted capabilities from
the `route_file!` spec, to learn a second macro, or it would hide the
`bloom:sign.status` capability from that check. Phase 2 adds no macro.

#### Renewal, concurrency and crashes

`renew` is the only way to get a new operation key. It runs these steps in
order:

1. Find the latest generation under the scope. If it is newer than `self`,
   return it unchanged. A stale handle never creates a generation.
2. Read `state()` for that generation. Continue only if it is:
   - `Expired` or `Cancelled`, which Machine keeps terminal for that key; or
   - `Signed` or `PackageChanged`, and only when the action declares
     `Spend::None`.
   For the `Spend::None` exception, the rebuilt action must also declare
   `Spend::None`; renewal must not introduce spending.
   Anything else is refused with `-3`. This includes `NotStarted`, because
   the SDK cannot prove that no concurrent write is about to sign it, and any
   `Err`, such as a `Backend` status failure.
3. Call `build(&latest)` and `store_put_new` generation n+1. If another
   caller won that write, return the winner's record.

**Why no Petal lock is needed.** For a single key, Machine's file lock and
frozen record already allow at most one operation. Two keys can only exist
after a renewal, and renewal requires Machine to have reported the previous
key as terminal, or as signed for zero spend. Nothing can sign that key
afterwards. Competing renewals collide on one create-only write, so every
caller signs the same `#n+1` action. A Petal's own locks, such as the
Polymarket trade lock, only keep its domain inputs consistent. The SDK does
not depend on them.

**Concurrent opens.** The first `store_put_new` wins and every caller gets the
winner's action. A loser's freshly built action is discarded, not
compared. `Conflict` from Machine therefore means the Petal store lost a
record that Machine still holds (see below). It does not come from a race.

**Crash ordering.**

| Crash point | Next write |
|---|---|
| before the generation record is written | no attempt or the previous generation; normal path |
| after the generation record, before Machine writes its record | `NotStarted`; `sign_or_resume` signs the frozen action at the same key |
| after Machine's record, before its outcome | `RecoveryRequired{operation_in_progress}` or `{signing_outcome_ambiguous}`; retry the same key, and Broker deduplicates the operation ID |
| after `Signed`, before the Petal's venue phase | Machine replays the signature; the Petal's venue phase decides whether to submit |

#### State, ownership and the attempt table

| State | Owner | Notes |
|---|---|---|
| Operation outcome, frozen action, signature | Machine (`.prepared` records, namespaced by package hash) | The only authority. Unchanged. |
| Approval, ceremony, journal | Broker | Unchanged. |
| Generation records (action and Petal context) | SDK code, Petal store | Keep retries byte-identical. Derive the operation key. Create-only. |
| Post-signing venue phases (Gasless `submitting`/`submission_unknown`/`submitted`; Polymarket `post_attempt.json`, receipts) | Petal | These remain the protection against double submission. |

| Situation | Machine reports | SDK does | Petal does |
|---|---|---|---|
| First write | not found | `open` freezes the action and context at `#0` and signs | builds the action and declares spend |
| Retry, restart or crash after signing | `Signed` (replayed) | returns the same signature; no new charge | its venue phase decides whether to (re)submit |
| Concurrent writes | one record per key | the losing `open` or `renew` returns the winner's record | nothing |
| Pending approval | `ApprovalPending` | `-3` with `action_id`; `renew` refused | shows `approval.json` |
| Approved, not yet retried | `approved_retry` | `Approved`; the next `sign_or_resume` signs | retries the same write |
| Expiry or cancellation | `Err(Expired/Cancelled)` | `-3`; `renew` allowed, with the same or a rebuilt action | Polymarket renews on retry; Gasless keeps requiring a new transaction ID |
| Policy denial | `Err(Denied)` | `-2`; the same key may be retried; no renew | nothing |
| Ambiguous signing or in progress | `RecoveryRequired{…}` | `-3` "reconcile, retry the same write"; `renew` refused | creates no replacement |
| Signed, but the venue rejected the signature | `Signed` | `renew` allowed **only if the action declares `Spend::None`** (ClobAuth refresh). Otherwise the Petal needs a new scope (new draft or transaction ID), so a second charge is a new, visible action. | ClobAuth `refresh` calls `renew` |
| Inputs changed before signing (Polymarket revalidate) | not found / Expired / Cancelled | no attempt yet: nothing to do. `Expired`/`Cancelled`: `renew` with the rebuilt action. An attempt that is `NotStarted` or in any other state is refused. | revalidates freely until `open`; afterwards, renews or asks for a new draft |
| Status read fails (`Backend`, `Invalid`, decode error) | `Err(…)` | `state()` and `approval_read` return `-4`; `renew` refused; `sign_or_resume` unaffected | surfaces `-4`; Gasless status route returns `-4` |

#### Boundaries: Petal store loss and package upgrades

Neither case is a supported continuation path in this delivery. The SDK fails
closed and never falls back to another package's Machine records.

**Petal store loss.** If a scope's generation records are lost, `open`
starts again at `#0`. That does not recover a later generation. If Machine
holds `#0` with a different action, the write returns `Conflict` (`-4`,
"attempt history lost"). If the rebuilt action is byte-identical, Machine
replays or reports `#0` as it is, and walking forward with `renew` again
hits `Conflict` on any differing action. The SDK can never create a second
operation under a key Machine already holds. Reconciliation is manual:
inspect the wallet's approvals and venue state, then create a new scope
(new draft or transaction ID). Venue-level duplicates after a Petal lost its
own venue phases remain the Petal's concern.

**Package upgrade.** Machine namespaces operations by package hash, so a new
package cannot see or resume the old package's operations. When installation carries the Petal store forward, an attempt created
by a different package hash is `PackageChanged`. Without retained attempt
records this is the store-loss boundary above, not an automatic cross-package
lookup:

- `sign_or_resume` refuses it with `-3` and does not call Machine. Under the
  new hash the key would look unstarted and would sign a second, independently
  charged operation.
- `renew` is allowed only for `Spend::None` actions, such as ClobAuth
  login. This starts a new zero-spend ceremony, which R6 rate-caps.
- For any other spend, the Petal requires a new scope: a new draft or
  transaction ID. `approval_read` reports `retry_state: "package_changed"`.
  The message tells the agent that an earlier approval may still be open in
  Broker until it expires or the owner cancels it, and that an earlier
  signature may already have been charged.
- Bloom provides no wallet-wide duplicate-charge protection across these
  operations. Per-asset wallet ceilings remain deferred (P10).
- **Operator rule (accepted):** upgrade a Petal only when it has no
  bounded- or unspecified-spend attempts that are `Pending`, `Approved`,
  `RecoveryRequired`, or `Signed` and not yet submitted. A later phase may
  define cross-package continuation.

#### Polymarket and Gasless: delete versus retain

| | Delete (replaced by SDK) | Retain in the Petal |
|---|---|---|
| Polymarket | `PreparedSigning` and its digest/preimage checks; `typed_action`, `action_for_prepared`, `sign_action`, `sign_action_for`, `sign_prepared`, `operation_identity`, `relayer_attempt`, `relayer_operation`, `approval_projection`; `onboarding::approval_operations`, `login_signing_attempt`, `LoginAttempt.signed`; the relayer-signature cache in `relayer_batch_signature` (Machine replays `Signed`); the separate `prepared_signing.json` and `prepared_relayer_batch.json` files (now attempt context) | Order construction and `PreparedOrder::validate`; POLY_1271 typed data and wrapping; **BUY spend = `makerAmount + fee_cap_micro` via `erc20_spend(137, PUSD, …)`**; SELL `Unspecified` (P7); ClobAuth `Spend::None`; `verified_signature` against the order, batch or ClobAuth digest; review-intent hashing; the `PreparedOrder`/`PreparedBatch` types; `post_attempt.json`; trade lock; `fund/…/approval.json` (not prepared signing; untouched) |
| Gasless | `operation_key`; the payload and review assembly in `prepared_action`; the `SigningOutcome` match in `gasless_transaction_with_host`; the status match block and `"operation not found"` handling; the `approval_required` and `recovery_required` phase writes; `signing_preimage` outside tests; `Host::sign`/`signing_status` (its `Host` implements `SigningHost`) | `RelayTransactionState` and its `save_new`; Relay quote, order and sign validation; `typed_data` normalization; permit-expiry margin; **USDC spend via `erc20_spend(origin.chain_id, currency, amount_units)`**; `signature_hex` normalization, plus a **new owner check**: recover the
signer from the EIP-3009 digest and require the wallet's owner address,
as Polymarket's `verified_signature` does; submission phases; Relay status projection; the public status vocabulary, mapped from `AttemptState`. Scope `state/relay-transactions/{wallet}/{id}.attempt`, generation 0 only |

Neither Petal adds or removes a route. Polymarket revalidation and signing
routes that inspect an attempt add `bloom:sign.status` so they can enforce
the terminal-state renewal rule; this adds no signing authority. Existing Machine catalog signing tables remain
unchanged. Relayer scopes remain nonce-bound, with a Petal-owned pointer
advanced only after confirmed completion.

#### Measurable reduction

Baseline (non-blank, non-test lines at the heads above): Polymarket
`approval.rs` has 257 lines, plus 47 across five prepared `approval.json`
routes and about 75 in onboarding and relayer glue (about 379 combined). Gasless has about 85 in
`relay.rs` and `common.rs`.

| Check | Target |
|---|---|
| Polymarket signing plumbing (`approval.rs` plus the glue above) | ≤ 60 lines (from about 379) |
| Each prepared `approval.json` route | ≤ 5 lines |
| Gasless signing plumbing | ≤ 25 lines (from about 85) |
| `git grep -nE 'operation_identity\|relayer_attempt\|approval_projection\|PreparedSigning\|login_signing_attempt\|prepared_relayer_signature\|"operation not found"\|relay:\{'` in both `route/` trees | no matches |
| `git grep -n 'SigningOutcome::'` in both `route/src` trees, outside tests | no matches |
| New SDK code (non-test) | ≤ 350 lines |

#### Acceptance tests

SDK (`petal`), unit tests over an in-memory `SigningHost` that can interleave
calls and inject a crash after any store write:

1. **Open race.** Two `open`s on one scope with different builders both
   return the first writer's action, context and key, and only one record
   exists. A corrupt record returns `-4` and is left unchanged.
2. `sign_or_resume` maps every outcome and contract error to the codes above.
   `-3` messages include `action_id` and the status. It never calls `status`.
3. **Normalization.** The `state()` table, including `approved_retry` →
   `Approved`, `NotFound` → `NotStarted`, and a package-hash mismatch →
   `PackageChanged` with no host call. `Invalid "operation not found"` (an
   old-style reply), `Backend` and `Conflict "ambiguous operation key"` stay
   `Err`.
   `state()` and `approval_read` perform no store writes.
4. **Renew matrix.** Allowed for `Expired` and `Cancelled`; for `Signed` and
   `PackageChanged` only with `Spend::None`. Refused for `NotStarted`,
   `Pending`, `Approved`, `Denied`, `RecoveryRequired`, any `Err`, bounded or
   unspecified spend when `Signed`/`PackageChanged`, and generation 32.
5. **Concurrent renewal.** Two handles at `#0`, with `#0` `Expired`, renew
   concurrently using different builders. Exactly one `#1` record exists and
   both handles sign the same `#1` key and action. A stale `#0` handle
   renewing after `#2` exists returns `#2` and writes nothing.
6. **Crash injection.** A crash after each write in `open`, `renew` and
   `sign_or_resume`, followed by a retry, may call `sign` repeatedly but results in at most one underlying signing
   operation and one budget charge per key. A replacement key requires the
   renewal rules above, including the explicit zero-spend exception.
7. **Package change.** `sign_or_resume` on a `PackageChanged` bounded-spend
   attempt returns `-3` without calling `sign`. `approval_read` reports
   `package_changed`.
8. **Status failure.** With the host returning `Backend` from `status`:
   `state()` returns `Err`, `approval_read` returns `-4`, `renew` is refused,
   and `sign_or_resume` still signs.
9. `eip712_action` reproduces Polymarket's ClobAuth and POLY_1271 hashes and
   the Gasless Relay fixture hash from their existing tests. A tampered
   `typed_data` changes the hash. `erc20_spend` equals
   `Spend::erc20("evm-<id>", lowercase, decimal)` on the wire and rejects a
   zero amount.
10. A new conformance fixture route,
    `fixtures/conformance-route/files/prepared-attempt.rs` (ERC-20 declared
    spend, `open` + `renew` + `sign_or_resume`), and an `approval.json`
    companion are built by `fixtures/petal-build.toml`.

Petals:

11. Polymarket: BUY declares principal plus fee cap, and SELL stays
    `Unspecified` (existing tests retained). ClobAuth `refresh` renews only
    after `Signed`. Revalidating a draft whose attempt exists and is not
    `Expired`/`Cancelled` is refused. A relayer write after restart returns
    the replayed signature without a second ceremony (replaces the cache
    test).
12. Gasless: the existing status tests rewritten on `AttemptState`. A pending
    approval returns `-3` and its message contains `retry_write_body`.
    Re-reading status writes nothing (existing test kept). A valid signature
    from a key other than the owner is rejected before submission.

Machine (tests and fixture only):

13. `prepared_actions::sdk_attempt_helpers_resume_and_project_status` uses
    `prepared-attempt.wasm`. Two writes send the same operation key and
    frozen action, and status projects pending → approved → signed.
14. `prepared_actions::sdk_attempt_concurrent_renewal_signs_once` expires
    `#0`, then dispatches two renewing writes concurrently with
    `tokio::join!`. Both reach the host with the same `#1` key and frozen
    action, and the host fixture replays one outcome. This fixture proves
    SDK-to-host identity, not real Broker signing or charge deduplication;
    the real triad acceptance below checks the latter on retries.
15. `prepared_actions::sdk_attempt_upgrade_fails_closed` reinstalls the
    fixture under a different package hash with a retained pending
    bounded-spend attempt. The test explicitly copies the prior attempt
    record; it does not certify installer lineage migration. The write
    returns `-3` and makes no host signing request.
16. Scale coverage is P1 against the actual daemon status implementation,
    not a duplicate test against the SDK fixture's in-memory status map.
17. `scripts/test-polymarket-authorization.sh` `login`, `prepared-buy` and
    `prepared-gasless`, first and `restart` phases, all pass on archives built
    from the new Petal heads. Ledger charges and `owner_sign_count` match the
    Phase 1 baseline.

The CI step that greps for the existing prepared test's `ok` line also greps
for P1 to P5 and tests 13 to 15.

#### Machine pins and fixtures

- Prerequisite commit: the status index and `NotFound` in
  `crates/bloom-daemon/src/prepared_signing.rs`. Bump `bloom-petal-contract`
  to the SDK commit that adds `ErrorCode::NotFound`. Add tests P1 to P5.
- Integration commit: bump `bloom-petal-contract` to the Phase 2 SDK commit. Its
  contract module equals the prerequisite's. CI already checks out that SDK
  revision and builds `fixtures/petal-build.toml`.
- `.github/workflows/ci.yml`: also assert that `prepared-attempt.wasm` exists,
  and run P1 to P5 and tests 13 to 15.
- `crates/bloom-petals/tests/prepared_actions.rs`: add tests 13 to 15. The
  existing mock host is sufficient. Test 15 needs a second package hash for
  the same component, which is a test-harness change only.
- No change to `phase1_acceptance.rs`. It never depends on Petal operation-key
  formats. Rebuild only the `BLOOM_PM80_*_ROOT` archives.
- Polymarket and Gasless pin the same SDK commit (the Phase 1 rule).

**Broker and Signer: no change.** No demonstrated need. The only Machine
source change is the prerequisite. It is a demonstrated limit on how long
Bloom can run, and it was approved for this delivery.

**Phase 2 exit**
- P1 to P5 and tests 1 to 17 pass, and the reduction checks hold.
- Polymarket, Gasless, SDK and Machine PRs are green on one SDK pin.
- No Broker or Signer diff. The only Machine source diff is the
  prerequisite; everything else is tests and the pin.

#### Phase 2 decisions

- One small SDK module of free functions and SDK-owned types:
  `eip712_action`, `erc20_spend`, `Attempt` (create-only generation records
  with frozen Petal context), `sign_or_resume`, `AttemptState`, and
  `approval_read`. There is no workflow engine, no persisted phase cache and
  no macro.
- Machine stays the only outcome authority. Petals own their context and
  their post-signing venue phases.
- A new operation key requires Machine to report the previous one terminal,
  or signed with zero spend. Generation records are create-only. That is
  enough to keep the existing protections against signing or charging twice,
  under races and crashes, without a Petal lock.
- Package mismatches and conflicting reconstructed actions fail closed.
  Store loss can still replay a byte-identical old action; loss of Petal venue
  phases does not guarantee protection against duplicate submission. Automatic
  continuation across store loss or package upgrades is unsupported.
- Protocol construction, spend declarations (including the BUY fee cap) and
  signature checks stay in the Petals. The declared-effects trust model (R2)
  is unchanged.
- Halts use `-3` so the agent sees the retry hint. Only `Denied` uses `-2`.
  Machine's router keeps discarding the message on `-2`. A denial should not
  pass Petal-authored text to the agent as if it came from policy, and `-3`
  already carries retry hints. No router change.
- The status scan becomes an index lookup. `NotFound` becomes a contract
  code. Both ship first in the existing Machine and SDK PRs.
- Gasless adds an owner-recovery check, matching Polymarket. Machine's
  selected-key check stays as well.
- Operators upgrade Petals only with no spending attempts in flight. Continuing
  across a package upgrade is deferred.

#### Phase 2 open questions

None blocking. Deferred items:

- Pruning `.prepared` records, which the index no longer requires.
- Continuing an attempt across a package upgrade.
- Recovering lost Petal stores.

### Phase 2b: catalog data (not in this delivery)

- Machine: move `DEFAULT_PETALS`, `petal_label`, `petal_destinations`,
  `POLYMARKET_SETUP` and the `PetalAuthorityRoute` tables in `github_source.rs`
  into catalog data, either the signed release catalog or, as a first step, an
  embedded data file.

**Phase 2b exit:** a fixture Petal that declares an ERC-20 spend gets automatic
coverage end to end with no source change outside the fixture and the catalog.
Phase 3's "no Machine change" depends on this.

### Phase 3: further Petals

Each is one Petal PR plus a catalog pin, with no Broker, Signer or Machine
change. This requires Phase 2b to be complete first.

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
