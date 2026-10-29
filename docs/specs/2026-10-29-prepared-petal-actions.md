# Prepared Petal actions

**Status:** implemented candidate with local verification  
**Date:** 2026-10-29  
**Initial migration:** Polymarket only

## Purpose

A Petal should prepare a protocol action and ask Bloom to authorize and sign
it. Adding reusable signing must not require a second implementation that
reconstructs protocol objects from JSON, builds economic claim envelopes, or
manages approval continuations inside each Petal.

The integration target is one prepared action, an optional explicit spending
declaration, and one shared signing call. Common infrastructure owns identity
bindings, approval selection, pending requests, signature recovery and claim
serialization. Petals retain protocol construction, review material, domain
state and external submission.

This specification changes the developer boundary. It does not introduce a
universal economic verifier or expand any existing reusable permission. The
[triad architecture](2026-07-23-triad-process-architecture.md),
[wallet boundary](../architecture/Wallet.md), and
[recurring token allowance decisions](2026-10-27-generic-sessions-key-decisions.md)
continue to govern authority, assurance and accounting. The API example below describes the integration boundary; use the canonical
SDK types and result shapes for implementation.

## Required Polymarket shape

Preparation uses the typed order that already exists in the order workflow:

```rust
let order = build_order(&params, timestamp_ms);
validate_supported_order(&order, chain_id, owner, funder)?;

let spend = match order.side {
    0 => Spend::erc20(POLYGON, PUSD, order.makerAmount),
    1 => Spend::erc1155(POLYGON, CTF, order.tokenId, order.makerAmount),
    _ => return Err(unsupported_order_side()),
};

let action = PreparedAction::new(
    ORDER_CLASS,
    SigningPayload::keccak256(
        poly1271_signing_preimage(&order, chain_id, neg_risk),
    ),
    order_review_record(&order, owner, chain_id, neg_risk)?,
)
.with_spend(spend);

match petal::signing::sign(ctx, wallet, &action, operation_key)? {
    SigningOutcome::Signed(signature) => submit_order(&order, signature),
    SigningOutcome::ApprovalPending(review) => show_approval(review),
    SigningOutcome::RecoveryRequired(status) => show_recovery(status),
}
```

Names and result adapters may follow SDK conventions. The ownership and small
integration surface are requirements. The spending match should be roughly ten
lines; it must not hide an order parser or another validation implementation.
`operation_key` identifies an existing durable domain operation, such as a
trade draft. It is not an approval identifier and grants no authority.

The initial shared API signs one payload. It must not expose a batch interface
merely because the underlying ABI supports batches. Polymarket's existing BUY
permission remains restricted to one order per signing operation.

## Prepared action contract

`PreparedAction` is an SDK-owned bounded value containing an operation class,
a typed signing payload, a versioned review artifact, and a spending
declaration. Its constructors compute the payload hash from the selected
cryptographic suite; callers do not independently supply bytes and hashes.
Supported suites retain their current semantics and size limits.

Spending has three explicit states:

- `Unspecified`, the default: no economic interpretation has been supplied.
- `None`: an explicit declaration that this action has no immediate debit.
- `Bounded`: exact network and asset identities with unsigned raw-unit maxima.

These are declarations, not evidence of independently verified effects. They
do not assert successful execution, proceeds, prices, or absence of continuing
authority. An omitted declaration must never become a zero debit. A zero
debit must never make an operation automatically eligible for reusable signing.

The SDK provides typed ERC20 and ERC1155 constructors. Their representations
are chain-qualified and canonical; quantities use checked uint256 arithmetic.
Amounts for different assets never net against one another. Fees must be
covered by the applicable permission or require exact review. The initial
Polymarket reusable profile remains fee-free.

Review artifacts retain the protocol evidence Broker currently requires. An
opaque artifact must carry an explicit format/version; it is not assumed to
be a complete or truthful description of arbitrary signing bytes. The existing
Polymarket prepared-record witness is adapted to its current Broker format in
one place until that format is deliberately versioned.

Petals do not supply package/route provenance, spending KeyRefs, assurance
labels, claim nonces, payload-context indices, approval IDs, or selectors in
this API. The host derives authenticated identity and applies existing policy.

## Ownership

| Owner | Responsibilities |
|---|---|
| Petal | Typed protocol construction and validation; review artifact; optional spending declaration; domain persistence; signature wrapping; venue submission and reconciliation |
| SDK | Small prepared-action API, validated encoding, outcome types and compatibility adapters |
| Machine | Trusted package/route/account context; durable signing-operation records; approval continuation; canonical claims; authenticated Broker requests; signature result validation |
| Broker | Policy and permission selection/validation, owner review, existing protocol checks, accounting, reservation, rearm and revocation |
| Signer | Existing custody, signing, counters and replay protection |

The SDK is guest code. Its validation is useful for correctness but cannot be
an authority boundary; Machine and Broker validate their inputs independently.
Machine never gains signing secrets, local approval authority or a direct
Signer connection.

## Authorization and durable signing

The guest entry point is `sign(ctx, wallet, action, operation_key)`. Its host
request contains the operation key and prepared-action data. Package, route
and account identity come from the executing component context, not serialized
guest fields. Wallet selection must agree with that context and resolve to the
exact authoritative KeyRef. Ambiguous or unavailable authority fails closed.

Machine namespaces the durable operation by exact installed package, route,
wallet/account KeyRef and operation key. It records the canonical action
digest before requesting approval or signing. Concurrent calls for that same
operation serialize. A changed action under a frozen operation key returns a
conflict; it must not silently retire a request and create replacement authority.

Core first checks whether an existing, explicitly activated permission covers
the request under its current scope and assurance rules. Discovery metadata,
an operation-class string and a spending declaration cannot create permission.
If no existing permission applies, core uses the current exact-review path.
After an exact review is approved, resumption must use the same frozen bytes.

An over-limit operation may enter the existing separate exact-approval flow;
it must not sign or broadcast while awaiting review. An exact approval does
not replenish, replace or widen the reusable allowance. The current accounting
rules determine its charges; this refactor must not change them implicitly.

Pending, denied, cancelled, expired and ambiguous outcomes are distinct. An
expired approval may be renewed only through the existing review transition
for that operation. A retry is not a new logical operation. Machine/Broker
retain the existing reservation and ambiguous-signature protocols; persisting
a guest-side success marker is not a substitute for them. Rearm resumes the
same authority and usage without a new budget.

Before returning `Signed`, shared infrastructure checks the expected suite,
signature count and encoding, and verifies the signature against the exact
selected public key and payload. A stable retry must recover an existing
result without another budget charge or unintended new signature. This does
not promise exactly-once venue execution: the Petal still owns its outbox and
submission ambiguity handling.

### Payload refresh is a separate existing permission

Polymarket login currently uses a one-use ClobAuth scope allowing a fresh
server timestamp after approval. Freezing every request's bytes would break
that flow. Preserve it as a narrowly recognized core profile using the
existing verifier, fixed owner/network/attestation/nonce constraints, timestamp
freshness rules and one-use accounting.

The guest does not request a generic mutable-payload or reusable selector.
Only a core-recognized profile may accept the permitted timestamp change under
the same logical operation. Orders, arbitrary messages and credentials do not
inherit that exception. Generic messages supported by the existing Broker
review envelope retain exact review. An unknown artifact format fails with
`Unsupported` before review: displaying arbitrary opaque artifacts requires
the separately reviewed Broker contract extension described below.

## Typed Polymarket preparation and persistence

Introduce a focused, versioned `PreparedOrder` domain record holding typed
order fields, owner, chain, market kind and existing review-intent bindings.
Use a serde-capable domain DTO if the generated `Order` cannot be serialized;
do not implement another field-by-field `serde_json::Value` parser.

One preparation function derives the signing bytes, review witness and spending
declaration from this record. The same function handles initial preparation and
resumption. Persist before initiating signing. On reload, validate the record,
recompute the action and compare it with the frozen signing-operation binding;
deserialization alone does not establish validity. Submission uses that same
order, not a newly constructed order with a new timestamp or salt.

Keep chain, owner/funder, signature-type, side and positive-amount checks in
the Polymarket protocol preparation boundary. Document why maker and signer
are the funder for this format. Metadata and builder fields must be explicit:
the initially supported format requires zero values, and unsupported values
are rejected rather than silently overwritten. Supporting fee-bearing formats
is a separate change. Do not claim an exact-review fallback for a format the
current decoder cannot faithfully represent.

BUY declares the signed maker amount in pUSD; SELL declares the signed share
amount. No price conversion or netting against expected proceeds is involved.
SELL declarations do not grant BUY permission. Broker retains its independent
signed-byte BUY checks, including owner, chain, witness and debit equality.

Other Polymarket signing operations use the same lifecycle API with their
existing exact or recognized login profile. Their domain records remain
protocol-specific. `approval.json` and status endpoints may remain as public
projections of core state; they no longer store Petal-owned approval hints.

## Required deletions and reviewability

Remove `order_debits` and its JSON reconstruction path. Move the existing
`order_from_prepared` consumer in trade posting to the typed prepared-order
record, then remove the parser. Remove Petal-local generic `ApprovalArtifact`,
selector-dependent binding digests, hint expiry/substitution handling,
claim-envelope construction and generic signature-response validation after
their shared replacements are exercised.

The migration must not relocate those functions to a new Polymarket helper
module or leave them behind an apparently small call. Existing domain-specific
intent checks, storage keys, order wrapping and submission recovery remain.
Shared code must have no Polymarket-specific branch except an explicitly owned
adapter to the existing recognized review/login formats.

The implementation PR must show an ownership/deletion map and separate these
reviewable steps: typed order preparation, shared lifecycle, then Petal
migration. Include before/after Polymarket production line counts, excluding
tests, generated output and lockfiles. A large effects-specific addition in
the Petal fails the intended outcome even if all tests pass.

## Implementation ownership map

| Removed Petal responsibility | Replacement |
|---|---|
| `order_debits` and `order_from_prepared` | Typed `PreparedOrder` in Polymarket's order module; bytes, review witness and spending declaration derived from the same validated record |
| `batch_claim` and generic effects serialization | Canonical prepared-action contract and Machine claim construction |
| `ApprovalArtifact`, hint expiry and selector-dependent binding digests | Machine's durable prepared operation and existing exact-signing orchestration |
| Guest selection of reusable signing | Core selection of an existing permission; the recognized one-use ClobAuth exception remains explicit |
| Guest signature verification and result cache | Shared Machine validation and authenticated Broker recovery |
| Petal approval files as local state | Read-only projections using `bloom:sign.status` |

Protocol wrapping, review-intent checks, durable login attempt IDs and relayer
nonces remain in the Petal because they identify domain operations. They are
not replacement approval stores. An expired or ambiguous operation does not
silently acquire a new identity.

## Contract and migration strategy

Add a bounded, versioned prepared-signing host import in the canonical `petal`
repository, with capability negotiation and `Signed`, `ApprovalPending` and
`RecoveryRequired` outcomes plus structured terminal/conflict errors. Keep
`bloom:route@0.1.0`. Generate bindings and builder support from that canonical
contract; never copy WIT or framework code into Polymarket. Existing signing
imports remain available to unmigrated Petals. Missing prepared-signing support
fails clearly before owner review; there is no silent legacy retry fallback.

The host translates the new developer API onto existing Broker/Signer contracts
and effects-v1 claims. The recognized artifact formats are
`polymarket.prepared-record` version 1 and `bloom.message.review` version 1.
The latter carries the existing `bloom.message.review.v1` envelope for exact
EIP-712, personal-message or supported Hyperliquid review; it does not make an
arbitrary artifact human-reviewable. Generic message requests disable reusable
permission discovery regardless of supplied spending declarations. Unknown
artifact formats fail explicitly rather than presenting a digest-only ceremony
as complete review of that artifact.

Do not add a generic verifier framework or change the meaning of existing
assurance labels. If an authority-edge wire change proves
necessary, specify and review it separately before implementation; it is not
authorized implicitly by this API cleanup.

Pin the SDK, builder, Machine and Broker revisions as required by the existing
release workflow. Migrate only Polymarket. Exercise the interface against a
small second-format SDK/host fixture without changing another default Petal.

Retain old packages and records for pending operations. Do not automatically
convert unknown pending approval hints into new authority, reset usage or
rebind existing approvals to a new package hash. Completed records may receive
an explicit tested data conversion; unresolved records remain inspectable and
must be reconciled with their original supported build. Preserve installed
Bloom and the existing disposable wallet/harness during development.

## Acceptance criteria

1. **Small integration:** Polymarket order preparation adds only the explicit
   spending match and prepared-action construction; signing uses one common
   call. No JSON order reconstruction or generic approval bookkeeping remains
   in the migrated Petal. A second-format fixture uses that API without edits
   to SDK dispatch or another application-name branch.
2. **Exact representation:** independent order vectors show unchanged signing
   bytes, signature recovery, review fields, chain, owner/funder and raw debit.
   BUY and SELL are distinct; nonzero metadata/builders, unsupported chains,
   invalid sides and zero/overflow amounts fail explicitly. Canonical claims
   remain compatible with Broker's current decoder and bindings. Document any
   intentional encoding difference rather than silently changing it.
3. **Persistence:** typed-record round trips retain every signed field. A
   changed salt, timestamp, owner, funder, chain, side, amount, asset, witness
   or operation identity cannot resume an approved exact operation. Concurrent
   retries, process crashes, ambiguous signing and SDK store failures neither
   lose a recoverable result nor cause a second charge.
4. **Real reusable BUY:** with the built WASM package and real isolated Machine,
   Broker and Signer, activate a bounded BUY permission, then obtain signatures
   for two distinct covered orders with zero additional ceremonies. Record
   recovered signers and exact ledger charges. Retry/duplicate each operation;
   restart/rearm and sign another covered order with prior usage retained.
   Use controlled venue observations and no live order submission or funds.
5. **Refusals and review:** an over-limit BUY requires separate approval before
   signing; SELL, wrong assets/accounts/routes/packages, credential creation,
   arbitrary messages and token approvals cannot use the BUY permission.
   Declared spend mismatching the signed order is refused by the existing
   verifier. Omitted spend and unsupported formats gain no new permission.
6. **Login and exact flows:** timestamp refresh works only for the existing
   bounded one-use login profile. Onboarding and other exact operations retain
   complete owner review, cancellation and resume semantics. Review progress
   labels reflect the actual number of approvals.
7. **Release evidence:** SDK/host tests, meaningful adversarial tests, Polymarket
   route tests, strict Clippy, WASM build and applicable triad gates pass at
   recorded exact revisions. Login/onboarding acceptance is reported separately
   from reusable BUY acceptance. No production-readiness claim follows from
   serialization tests alone.

## Out of scope

Migrating other default Petals; changing persona limits; making all protocols
fit a token-debit model; promising a wallet-spend limit on funds already at a
venue; proving settlement or contract behaviour; and composing several owner
approvals into one ceremony. These need their own requirements and evidence.
