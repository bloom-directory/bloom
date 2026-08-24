# Sealed Approvals

**Status:** architecture overview; triad-aligned
**Audience:** Bloom engineers, Petal authors, and implementation agents

Sealed Approval is Bloom's sole signing-authorization concept. It authorizes
wallet-controlled signatures over Machine- or Petal-originated payloads. It
does not authorize custody changes such as wallet registration, credential
replacement, import, export, deletion, recovery, key derivation, or policy
update; those use the shared custody-ceremony framework.

The normative definitions, state machines, and wire methods are in
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).

## Authority ownership

- **Machine** owns staging, simulation, execution, broadcast, and public VFS
  projections. It has no wallet keys, approval store, decrypted-key cache, PRF
  decryptor, or direct Signer connection.
- **Broker** is the only Machine-facing authority service. It owns canonical
  Sealed Approval terms and lifecycle, review construction, policy evaluation,
  declared-usage budgets, reservations, ceremony HTTP, and authorization
  audit.
- **Signer** owns wallet and delegated keys, credentials, canonical policy,
  independent approval-enforcement state, replay counters, and cryptographic
  signing.
- **Browser** participates in the Broker-hosted ceremony. Sensitive PRF or
  custody input is HPKE-encrypted to Signer; Broker relays ciphertext and
  Machine never receives it.

Petals cannot contact Broker or Signer directly. Machine cannot request a
signature from Signer or reconstruct authority from cached projections.

## Canonical flow

```text
Petal or client stages an action in Machine
Machine calls sealed_approval.prepare on Broker
Broker validates provenance, policy, selector, limits, and review inputs
Broker calls Signer ceremony.prepare
Broker returns approval_id, ceremony_url, expiry, and review digest
Browser completes Broker's ceremony
Broker verifies and calls Signer ceremony.complete
Signer independently verifies and durably activates enforcement state
Machine later calls Broker signing.sign or signing.sign_batch
Broker evaluates policy and reserves limits
Broker presents a short-lived signed request to Signer
Signer enforces key, approval, selector, suite, counters, expiry, and replay
Machine receives only signatures and public receipts
```

Ceremony completion activates an approval only. Execution and broadcast are
separate Machine operations; there is no combined “approve and execute” or
ceremony-and-broadcast mutation.

## Sealed Approval terms

The immutable approval binds at least:

- approval and wallet identity;
- exact `KeyRef` and permitted cryptographic suite;
- an exact-payload selector or installer-pinned Petal selector;
- operation and signature limits, rate limits, declared-value limits, and
  validity window;
- canonical policy version/digest and revocation epoch; and
- the review manifest and provenance record used at preparation.

An exact selector commits to the exact payload or ordered batch. A reusable
Petal selector commits to one package hash and either its legacy singleton
route or a canonical non-empty list of route grants. Each grant binds one
route to its own allowed operation classes and installer-signed provenance
digest, avoiding Cartesian-product authority across routes and classes.
Suites and usage limits remain shared across the approval. It does not silently
become generic wallet authorization.

The canonical approval is durable in Broker. Signer stores the enforcement
projection it independently needs. Machine stores only public status and
launch projections; deleting or altering them cannot authorize a signature.

## Petal claims and trust boundary

Each reusable Petal signing operation carries a normalized `PetalUseClaim`
binding the installed package and actual executing route, operation class, suite, payload
digest, ordered hashes, declared debits and destinations, fee declaration,
nonce, and claim-assurance mode.

Broker verifies the claim's canonical form, provenance, scope, approval
limits, policy, and any configured proof or attestation verifier. In baseline
`machine_asserted` mode Broker does not decode arbitrary Petal payloads to
prove that economic claims are truthful. A compromised Petal or Machine may
therefore consume the remaining approved capacity by lying within that trust
model. Exact selectors prevent payload substitution; reusable selectors rely
on the documented claim assurance.

Petals always submit complete payload bytes through a payload-bearing host
call. Hash-only guest signing is unsupported. Machine may validate guest
capabilities and provenance, but only Broker can authorize and only Signer can
produce the signature.

## Ceremony and public projection

Broker owns the canonical `http://localhost:18734` ceremony application,
review, session token, origin checks, rate limiting, and browser API. Before
returning a launch URL it obtains Signer's signed ceremony contribution and
binds that contribution into the WebAuthn challenge and rendered review.

`sealed_approval.prepare` returns the public preparation fields:

```text
approval_id
state = AWAITING_CEREMONY
ceremony_url
ceremony_expires_at
review_manifest_digest
```

The URL is a single-use owner-readable launch secret. Machine may expose it
only under the originating action or deliberate CLI response; it must not log
it, expose it to a Petal, proxy ceremony HTTP, or rebuild it from local state.
Preparation is idempotent by operation ID and immutable request digest.

Browser returns the raw WebAuthn assertion to Broker. For local encrypted
custody, Browser separately HPKE-encrypts PRF output to Signer. Broker verifies
its part and relays the unchanged assertion and ciphertext through
`ceremony.complete`; Signer independently verifies the assertion, contribution,
scope, RP/origin, user verification, and encrypted-input binding before
activation.

After activation, expiry, cancellation, or failure, Machine clears the URL and
retains only terminal public status. Machine restart reconstructs projections
from Broker rather than local approval artifacts.

## Signing use

For each operation Machine sends Broker the exact payload, operation identity,
approval identity, public key reference, suite, and applicable Petal claim.
Broker loads the active approval and current canonical policy, validates the
operation, durably reserves budgets/counters, and sends Signer a short-lived
Broker-signed request.

Signer independently checks Broker authentication, approval activation,
wallet and `KeyRef`, selector, suite, operation identity, expiry, revocation,
rate backstops, signature counts, and replay. Its signing receipt and Broker's
validation receipt bind the public result to both decisions. Machine never
receives the internal Broker-to-Signer request or any backend credential.

Approval revocation, expiry, counter exhaustion, policy mismatch, Broker
unavailability, or Signer unavailability fails closed. Machine cannot fall
back to a local key, old approval artifact, retired local authorization state,
or hash-only adapter.

## Petal-scoped delegated keys

A Petal that needs a delegated identity uses the generic key-derivation custody
workflow. Signer derives and owns a child `KeyRef` whose immutable scope binds
the wallet, parent key, installer-pinned package hash, route, derivation
purpose, allowed suites, and lifecycle. Petal and Machine receive public key
metadata only. Every use still requires a matching Sealed Approval and is
independently scope-checked by Broker and Signer. Machine may provision one
reusable approval immediately after key derivation, covering only the typed
routes and route-specific classes present in both the immutable derived-key
scope and installer-signed provenance. Machine retains the public approval
binding with the `KeyRef`; the Petal receives neither an approval capability
nor another ceremony for each matching action.

Venue-specific custody and signing protocols do not belong in Machine, Broker,
or Signer. An installed Hyperliquid Petal, for example, uses this generic scope
instead of a native Machine agent-session key.

## Separation from custody and policy updates

Custody ceremonies share Broker's browser origin and common ceremony status,
cancel, expiry, HPKE, and audit mechanisms, but they produce custody receipts
rather than Sealed Approval activation receipts.

Policy update is a `policy_update` custody ceremony. Machine calls
`policy.validate_update`; Broker parses the proposed bytes, verifies the
Signer-authenticated baseline, constructs the exact review, and originates the
Signer ceremony. After completion, `policy.commit_update` calls Signer's
compare-and-swap with the proposed bytes, ceremony receipt, and Broker
validation receipt. There is no direct Machine policy writer or commit path
without a completed receipt.

## Client surfaces

Foreground CLI, foreground VFS facade, and mounted VFS all use these same
Broker and Signer methods. A foreground client may deliberately open the
Broker-provided URL. A mounted write never opens a browser; it projects the URL
for the expecting client to open or forward. See
[`Interaction Modes.md`](./Interaction%20Modes.md).
