# Polymarket Petal Parity

## Status

Implementation specification. This document excludes geoblock and jurisdiction
enforcement from scope.

## Objective

Bring the `polymarket` Petal to functional parity with the native
Polymarket surface without adding Polymarket-specific daemon IPC. The Petal
owns protocol semantics and user-facing routes. The daemon supplies only
generic authority, chain-read, and transaction-execution primitives.

## Boundary

The Petal owns:

- Polymarket HTTP and relayer interactions.
- Onboarding, credentials, order construction, policy evaluation, receipts,
  reconciliation, cancellation, builder-key administration, redemption,
  revocation, withdrawal, and funding planning.
- Canonical Petal review artifacts and every Polymarket route schema.

The daemon owns:

- Trusted application/package/route provenance.
- Sealed Approval staging, ceremonies, in-memory grants, and host signing.
- Generic chain reads and generic EVM transaction staging, signing, and
  broadcast through the existing TxEngine and outbox.

The implementation MUST NOT add a `bloom:polymarket/*` WIT interface or any
other venue-specific daemon command.

## Generic IPC

### Structured signing result

Define the initial `bloom:sign/signing@0.1.0` interface with a structured
approval result rather than an error string containing a ceremony URL.

```wit
package bloom:sign@0.1.0;

interface signing {
  record approval-required {
    action-id: string,
    ceremony-url: string,
    expires-ms: u64,
  }

  variant sign-result {
    signature(list<u8>),
    approval-required(approval-required),
  }

  sign-hash: func(wallet: string, hash32: list<u8>, intent: string)
    -> result<sign-result, string>;
}
```

The daemon must derive action identity from trusted Petal route provenance and
the exact hash. It must not accept app-selected Petal identity, route identity,
or action ID.

### Generic EVM outbox

Add `bloom:tx/outbox@0.1.0`, backed by the existing TxEngine and outbox. It is
the only new transaction-write primitive.

```wit
package bloom:tx@0.1.0;

interface outbox {
  record evm-transaction {
    wallet: string,
    chain: string,
    to: string,
    value-wei: string,
    data-hex: string,
    nonce: option<u64>,
    max-fee-per-gas: option<string>,
    max-priority-fee-per-gas: option<string>,
  }

  record approval-required {
    action-id: string,
    ceremony-url: string,
    expires-ms: u64,
  }

  record staged-transaction {
    outbox-id: string,
    plan-md: string,
    approval: option<approval-required>,
  }

  record inspection {
    outbox-id: string,
    state: string,
    tx-hash: option<string>,
    receipt-json: option<string>,
  }

  stage: func(tx: evm-transaction) -> result<staged-transaction, string>;
  confirm: func(wallet: string, chain: string, outbox-id: string, acknowledge-warnings: bool)
    -> result<staged-transaction, string>;
  inspect: func(wallet: string, chain: string, outbox-id: string)
    -> result<inspection, string>;
}
```

The daemon validates, seals, signs, and broadcasts generic EVM transaction
fields through TxEngine. `inspect` is read-only, origin-bound, and exposes only
the persisted outbox state, transaction hash, and receipt. It must not expose
arbitrary key material, raw wallet unlocks, or arbitrary broadcast APIs to the
Petal.

## Stable Approval Retry

Before requesting any signature, the Petal MUST persist a canonical prepared
artifact. A retry after ceremony must reuse that artifact exactly.

| Operation | Prepared fields that must remain stable |
| --- | --- |
| CLOB auth | owner, nonce, timestamp, credential action, signing hash |
| Order | market/token, side, price, size, order type, salt, expiry, funder, neg-risk, chain, signing hash |
| Relayer batch | owner, deposit wallet, exact calls, nonce, deadline, amount/recipient or condition ID, signing hash |
| Funding | quote source, transaction fields, slippage and spend bounds, transaction digest/outbox ID |

The Petal must write structured `approval.json` files for onboarding and trade
drafts. These files expose the action ID, ceremony URL, expiry, prepared-artifact
digest, and retry state, but never credentials, grant material, PRF output, or
raw signatures.

## Petal Route Contract

Retain existing routes and add:

```text
account/<wallet>/status.json
account/<wallet>/buying_power.json
account/<wallet>/funding_options.json

builder-keys/<wallet>/keys.json
builder-keys/<wallet>/revoke

fund/<wallet>/<id>/confirm

trade/<wallet>/orders/<clob-order-id>/cancel
trade/<wallet>/drafts/<id>/approval.json
onboard/<wallet>/approval.json

redeem/<wallet>/<slug>/plan.md
redeem/<wallet>/<slug>/confirm

revoke-approvals/<wallet>/request/plan.md
revoke-approvals/<wallet>/request/confirm

withdraw/<wallet>/pusd/plan.md
withdraw/<wallet>/pusd/confirm

obligations/<wallet>.json

settings/enso-api-key
```

Route behavior:

- Cancellation accepts any CLOB order ID discoverable from account orders; it
  is not limited to Petal-created receipts.
- Builder-key reads expose IDs/status only. Private key material remains in
  the Petal private store.
- Redeem, revocation, and withdrawal construct and persist exact relayer
  batches before generic signing. Withdrawal resolves the live pUSD balance,
  validates `amount` or `all`, and binds amount plus owner recipient.
- Funding retains the existing draft flow, resolves a quote and exact EVM
  calldata in the Petal, stages it through generic `tx/outbox`, and persists
  outbox/receipt state.
- `settings/enso-api-key` is write-only. It provisions Enso credentials into
  the Petal secret store; the value is never readable through VFS or included
  in review, approval, receipt, or error artifacts.
- Add the existing `bloom:chain` capability for pUSD balance and contract
  state reads. Extend CLOB network permissions only for builder-key endpoints.

The Petal must not invoke native `/polymarket/...` VFS write routes as an
integration shortcut. That would couple it to the legacy handler and violate
the ownership boundary above.

## Review Integrity

The Petal writes canonical `review_intent.json` before every signing or
transaction operation. Its BLAKE3 digest is stored with the prepared artifact
and shown in `approval.json`.

The daemon binds the trusted app/package/route provenance and exact signing
hash or EVM transaction bytes. The Petal verifies the returned action ID and
hash against its prepared artifact before proceeding.

No operation may regenerate a timestamp, salt, nonce, deadline, quote, amount,
recipient, batch call, or transaction field after approval has been requested.
Changed values require a fresh prepared artifact and fresh approval.

## Implementation Order

1. Add generic `signing@0.2` and its daemon/VM/SDK adapters.
2. Add generic `tx/outbox@0.1` using TxEngine and the existing outbox.
3. Add prepared-operation persistence and structured approval artifacts to the
   Petal; fix CLOB-auth, order, and relayer retry stability first.
4. Implement account operational reads, arbitrary order cancellation,
   builder-key administration, and obligations.
5. Implement redemption, approval revocation, and pUSD withdrawal with generic
   signing.
6. Implement funding confirmation with generic TxEngine outbox staging.
7. Reconcile forked Polymarket protocol code against the native crate through
   shared fixtures or a deliberately maintained compatibility layer.
8. Replace install-only parity coverage with route-contract and host-lifecycle
   coverage.

## Required Tests

### Generic IPC

- `signing@0.1` remains compatible; `signing@0.2` returns a structured
  approval-required result.
- A first signing request stages one action and returns ceremony metadata.
- An approved retry of identical prepared bytes consumes the grant and signs.
- Any changed stable field creates a different action and cannot consume the
  old grant.
- `tx/outbox` stages canonical EVM transaction bytes, exposes an approval
  result, confirms only the sealed outbox ID, and inspects only entries created
  by the same trusted package origin.

### Petal Workflows

- Onboarding CLOB-auth retry preserves timestamp/hash.
- Order retry preserves salt/hash and posts exactly once after approval.
- Relayer redeem/revoke/withdraw retries preserve calls, nonce, deadline, and
  value-bearing fields.
- Funding stages exact calldata and cannot substitute quote, recipient, spend
  bound, or transaction after review.
- Arbitrary discovered-order cancellation, builder-key revoke, account reads,
  and obligations are covered with mocked CLOB/chain hosts.

### Integration and CI

- A route-contract manifest explicitly maps every required native-equivalent
  route to the Petal route.
- Bloom-host integration tests exercise approval-required then retry for
  onboarding, order posting, funding, and each exit operation.
- Source-install CI validates the route contract and executes mocked workflows;
  it must not rely on self-reported `meta/parity.json` alone.
- Add adversarial tests for replay, mutated prepared state, changed route
  provenance, action-ID confusion, grant reuse, credential exposure, and
  receipt redaction.

## Completion Criteria

The Petal reaches parity only when every route above is present, every
value-moving or signing flow is stable across ceremony retry, no
Polymarket-specific host IPC exists, and the generic IPC plus Petal workflow
tests pass in CI.
