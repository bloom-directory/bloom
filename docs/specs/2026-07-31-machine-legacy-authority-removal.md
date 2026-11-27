# Machine Legacy Authority Removal

**Status:** approved goal specification; M3 amended for Petal-scoped sub-keys;
dependency-boundary clarification ratified

**Date:** 2026-07-31; M3 amendment 2026-07-31; dependency clarification 2026-08-01

**Audience:** Bloom engineers, security reviewers, release engineers, and implementation agents

**Scope:** removal of legacy wallet authority, signing, approval, and key-bearing state from Bloom Machine

**Normative parent:** [Bloom Machine, Broker, and Signer Architecture](./2026-07-23-triad-process-architecture.md)

**Inventory baseline:** `triad-architecture` at `2767153bfab6`

## 1. Purpose and precedence

The triad architecture requires production Machine to contain no embedded
signer or authorization fallback. Broker is the only Machine-facing authority
service. Signer is the only owner of wallet and delegated signing keys and the
only producer of wallet-controlled signatures.

The authority plane now exists, but Machine extraction is incomplete. Machine
still opens the pre-triad keystore and approval database, exposes legacy
approval services, uses legacy wallet records as public projections, and owns
legacy delegated signing keys. Deleting the old crates before replacing
those consumers would break production reads, staging, simulation, requests,
outbox handling, and venue integrations. Leaving them in place would fail the
target architecture even where current signing calls happen to route through
Broker.

This document specifies the remaining extraction work. It refines W7, W8, and
AC-04 of the parent architecture. The M3 amendment also defines generic
Petal-scoped derived keys as the replacement for native venue-key custody. It
does not add a Machine-to-Broker or Broker-to-Signer method: derivation uses
the existing `key.derive_prepare`, custody ceremony, public-key projection,
Sealed Approval, and `signing.sign` surfaces. It may extend the request and
Signer registry data carried by those existing methods with the scope fields
defined in section 9. This extension is ratified by this amendment. In every
other conflict the parent controls.

The superseded triad implementability review remains historical inventory
only. It is not normative.

## 2. Goal

After this goal is complete, the production Machine:

1. discovers wallets, keys, credentials, and policy only through authenticated
   Broker public methods or a Machine-owned cache populated from those methods;
2. routes every wallet-controlled signature and every custody mutation through
   Broker, which routes cryptographic effects to Signer;
3. contains no root, child, delegated, venue, payment, recovery, PRF-derived,
   or debug wallet signing key;
4. opens no legacy keystore or daemon approval database;
5. implements no legacy grant, policy-session, ceremony, registration,
   decrypted-signer cache, or hash-only signing path;
6. remains able to read cached public projections and to stage and simulate
   unsigned work when Broker or Signer is unavailable, while signing and
   custody fail closed; and
7. cannot link legacy authority code into any production feature combination
   or release artifact.

The end state is:

```text
Petal / CLI / mounted VFS
          |
          v
       Machine
  public projections,
  staging, simulation,
  execution, broadcast
          |
          v
       Broker
  policy, approval, review,
  authorization, budgets
          |
          v
       Signer
  custody, delegated keys,
  cryptographic signing
```

There is no second authority path hidden behind a feature, degraded startup,
handler-specific adapter, or local developer mode.

## 3. Definitions

### 3.1 Authority code

Authority code is code capable of any of the following:

- generating, importing, decrypting, wrapping, caching, or exporting a wallet
  or delegated private key;
- receiving plaintext PRF output or recovery material;
- deciding that a Machine- or Petal-originated payload is approved;
- minting or consuming an approval, grant, standing session, or signing budget;
- producing a wallet-controlled or delegated-wallet signature; or
- mutating canonical custody or wallet policy state.

Authority code belongs in Broker or Signer according to the parent
responsibility matrix. It must not execute in Machine.

### 3.2 Key material

Key material includes root and child wallet keys, Bloom-managed Petal-scoped
sub-keys, decrypted wallet signers, wrapping keys, PRF output, recovery
secrets, and any secret from which those values can be recovered.

A Petal may independently generate, store, and use its own application keys,
including exchange, payment, API, session, or protocol keys. Those keys are
Petal-owned application data, not Bloom-managed wallet authority, provided
that Machine treats their bytes as opaque guest data and never parses,
receives through a host signing API, invokes, exports, or uses them on the
Petal's behalf. Petals retain access to runtime randomness, private namespaced
storage, WASM cryptography, networking, and payload construction. A Petal may
ask the user to approve a Broker-mediated wallet payload that registers a
Petal-owned public key with an external protocol; subsequent local use and
external revocation of that key belong to the Petal and protocol rather than
Bloom's `KeyRef`, policy, approval, audit, or revocation model.

When a Petal requests a Bloom-managed derived `KeyRef`, section 9 applies:
Signer owns the private bytes and the Petal receives only public metadata.
The two models must remain explicit. A Petal-owned key must not be represented
as, imported into, or granted the protections of a Signer-owned `KeyRef`.

The following are not wallet key material and remain permitted in Machine:

- Machine's own authenticated-transport application identity;
- public keys, addresses, `KeyRef` values, signatures, signed payloads, and
  signed public policy snapshots;
- TLS or package-verification material required for Machine-owned networking;
  and
- opaque Petal-owned application state described above;
- installer/enrollment tooling credentials when that tooling is not reachable
  from the running Machine or Petals and cannot sign wallet payloads.

### 3.3 Public projection

A public projection is a non-authoritative Machine view built from existing
Broker responses such as `WalletPublic`, `KeyPublic`, `CredentialPublic`, and
`SignedPolicySnapshot`. A projection may support display, routing, staging, and
simulation. It never authorizes signing or custody and cannot override a live
Broker decision.

### 3.4 Authority dependency and reachability

A dependency is an authority dependency when production Machine deliberately
uses it to construct, receive, retain, recover, or invoke wallet authority as
defined in sections 3.1 and 3.2. A direct dependency on a Bloom legacy
authority crate is forbidden. A Machine feature that activates a local wallet
or signer adapter, a Machine source reference to such an adapter, or a callable
Machine path to it is also forbidden.

The mere presence of generic signing primitives or an unused local-signer
convenience implementation inside a transitive third-party package is not, by
itself, a Machine authority path. Cargo metadata is evidence for review, not a
substitute for proving construction, key flow, reachability, and invocation.
Release gates must distinguish those cases rather than reject a package solely
because its source tree contains cryptographic implementation code.

Bloom must not vendor, copy, fork, or apply a source patch to an upstream
dependency solely to erase an inert transitive signer implementation or to
make an absence gate pass. Such a change requires an independently reviewed
product need and an explicit specification amendment. If an upstream feature
coupling exposes an actual callable Machine authority path, the conforming
choices are to remove or move the consuming functionality out of Machine, use
an upstream-supported feature boundary, or stop for that amendment. Copying an
upstream package into this repository is not a conforming workaround.

This rule does not authorize a new dependency-ownership inventory, provenance
ledger, approval manifest, or per-package ratification process. Enforce it with
the ordinary dependency graph, Machine source/call-path checks, focused
negative tests, and normal review of any actual source override. Do not add
repository-wide compliance artifacts that are unrelated to a callable Machine
authority path.

## 4. Current verified baseline

At the inventory baseline:

- `Daemon::from_home_inner` unconditionally constructs
  `bloom_keystore::Keystore`.
- `Daemon` publicly exposes both `keystore` and `signer_cache`.
- Machine opens `auth/auth.sqlite`, constructs
  `StoreApprovalVerifier<KeystoreApprovalSignatureVerifier>`, and passes it to
  `TxEngine` and VFS handlers.
- `InMemoryGrantStore`, `SignerCache`, and legacy `AuthServices` are built even
  though the key-bearing Petal host is compile-gated.
- the CLI wallet list, address, portfolio, and related reads use the old
  keystore rather than `MachineBrokerClient::{wallets,wallet,keys,key}`;
- the wallet VFS lists wallets and renders address, public key, kind, policy,
  and outbox preparation from legacy keystore records;
- `RequestsHandler`, `HyperliquidHandler`, `StatusHandler`, `PetalTxOutbox`,
  `/next.md`, and background policy consumers receive the old keystore or old
  approval services;
- `wallets/<wallet>/policy-session/*` remains a compiled daemon-owned approval
  and standing-session surface;
- `EvmOutboxProjection` uses the old approval database as an action-ID index;
- `build_write_daemon` responds to Broker configuration failure by constructing
  the legacy daemon composition;
- `local-integration` and `unsafe-debug-signer` retain Machine-owned signer
  paths; and
- the native `HyperliquidHandler` generates, persists, decrypts, and uses
  `EphemeralAgentKey` inside Machine. This path is superseded by the
  Hyperliquid Petal and is retired rather than promoted into the canonical
  delegated-key architecture; and
- Petals have no generic way to request a Signer-owned child whose use remains
  cryptographically scoped to that Petal's installer-pinned identity.

The normal and `--no-default-features` production dependency graphs still
contain `bloom-keystore`, `bloom-auth`, `bloom-auth-api`, `bloom-vfs`, and
`bloom-tx`. The first three therefore cannot be treated as test-only today.

This inventory is a starting point, not a closed list. Phase M0 must regenerate
it from source and Cargo metadata before edits begin.

## 5. Normative end-state invariants

### MI-01: one authority path

Every production signing or custody request originating from CLI, VFS, Petal,
request execution, transaction execution, venue integration, background job,
or recovery tooling goes Machine to Broker and, where a cryptographic effect
is required, Broker to Signer.

Machine has no Signer client, Signer credential, direct Signer socket path, or
backend handle.

### MI-02: no key-bearing Machine

No production Machine object, field, closure, task, handler, store, or feature
may contain Bloom-managed key material as defined in section 3.2. This includes
scoped and short-lived delegated `KeyRef` keys. Opaque bytes held inside a
Petal's guest memory or package-hash-namespaced private store are the explicit
section 3.2 exception; Machine may provide byte storage but may not interpret
or exercise the key. Machine production source may not import,
construct, configure, receive, retain, or invoke `EphemeralAgentKey`,
`PrivateKeySigner`, a local wallet signer, PRF decryption, or an equivalent
authority implementation. Direct dependencies and explicitly activated
features that provide those Machine capabilities are forbidden. Inert
transitive third-party implementation code is governed by section 3.4 and is
not independently a violation.

### MI-03: Broker and Signer are authoritative

Signer is the sole writer of key registry, custody, credential wraps,
derivation registry, and canonical policy. Broker is the sole owner of Sealed
Approval policy evaluation, lifecycle, limits, reservations, and ceremony
review. Machine stores projections only.

### MI-04: projections cannot authorize

Machine may use a current or cached policy projection to produce advisory
plans and early denials. Final authorization always uses Broker's independently
verified snapshot. A stale, altered, missing, or rolled-back Machine cache can
damage availability or presentation but cannot produce a signature or custody
effect.

### MI-05: unavailable means degraded, not legacy

Broker or Signer unavailability preserves public cached reads, unsigned
staging, and simulation where inputs are available. It denies signing,
broadcast that requires a new signature, approval mutation, policy mutation,
and custody. Machine reports the unavailable authority edge explicitly. It
never constructs an in-process verifier, signer, keystore, or approval store.

### MI-06: no production debug authority

The production Machine has no `local-integration` or `unsafe-debug-signer`
feature capable of restoring authority. Deterministic test credentials and
real-passkey developer workflows run as separate harnesses against the real
Broker and Signer protocols.

### MI-07: clean break from legacy authority state

Production Machine does not open, create, migrate, or write the old keystore,
`auth/auth.sqlite`, approval challenge artifacts, signer cache, or
policy-session state. Old approval, policy-session, and debug-signer state is
not migrated, and legacy v1 wallets are not supported. Old files may be
ignored or diagnosed as obsolete, but their presence must not alter Machine
runtime behavior.

## 6. Machine public projection architecture

### 6.1 Internal interfaces

Machine introduces key-free internal interfaces, with concrete names chosen by
implementation but responsibilities fixed here:

```text
WalletProjectionReader
  list_wallets()
  get_wallet(wallet_id)
  list_keys(wallet_id)
  get_key(wallet_id, key_id)
  list_credentials(wallet_id)
  get_policy(wallet_id)

AuthorityClient
  existing MachineBrokerClient signing, approval, policy,
  ceremony, custody, key, and credential operations

ProjectionStore
  cache authenticated public responses with source version,
  digest, observed time, and freshness state
```

These are Machine-internal seams, not new wire methods. Implementations use the
existing parent section 17.1 Broker methods. Missing convenience methods on
`MachineBrokerClient` are wrappers over existing request variants; this goal
adds no Broker or Signer RPC methods.

### 6.2 Projection contents

The cache may contain only:

- wallet ID, public address, wallet kind, backend ID, and public status;
- public keys, public derivation metadata, and opaque `KeyRef` values;
- public credential descriptors with no PRF, wrap, authenticator secret, or
  recovery secret;
- signed canonical policy bytes, version, digest, signing key ID, and
  verification status;
- public ceremony/status fields already permitted by the parent; and
- source service version, response digest, observation time, and stale marker.

The cache must not contain Broker approval secrets, Signer locators not already
present in a public `KeyRef`, encrypted private-key blobs, credential wraps,
recovery ciphertext, signing nonces, or material useful to reconstruct a key.

### 6.3 Refresh and offline behavior

On an authenticated Broker connection, Machine refreshes projections and
atomically replaces a wallet's cached generation. It never merges a lower
policy version over a higher one. Deleted Broker wallets become tombstoned in
the projection rather than silently resurrected from cache.

When Broker is unavailable:

- cached entries are readable and visibly marked stale;
- an uncached wallet or key returns the existing `SERVICE_UNAVAILABLE` rather
  than falsely reporting that the entity does not exist;
- staging and simulation may continue using public data, but results are
  labelled advisory and unsigned; and
- all authority mutations and signing fail closed.

## 7. Surface migration contract

| Surface or consumer | Required target |
|---|---|
| CLI wallet list/address/portfolio/public key | `WalletProjectionReader`; live Broker refresh when available |
| Wallet VFS discovery and public files | public projection only; no `Keystore` field or fallback |
| Wallet policy read/update | `policy.read`, `policy.validate_update`, completed ceremony receipt, then `policy.commit_update`; no direct policy writer |
| Transaction staging and outbox | explicit public wallet/policy projections for planning; `signing.sign` or `signing.sign_batch` for final bytes |
| Petal payload signing | payload-bearing Broker signing only; v0.1 remains fail-closed |
| Petal transaction outbox | key-free wallet projection and Broker authority client |
| Paid HTTP/x402/MPP requests | Broker approval and signing; no `PetalHost::sign_hash`, old grant, or keystore lookup |
| Generic Petal delegated-key actions | Signer-owned Petal-scoped `KeyRef`; Machine and guest receive public metadata only |
| Native Hyperliquid authority and writes | retired or fail closed with a migration diagnostic; public read-only helpers may remain but no native signing or compatibility path exists |
| `/next.md`, status, bump scanner, watchers | projection reader; stale/unavailable states explicit |
| Central outbox action-ID allocation | Machine-owned operation index with no approval or grant semantics |
| Custody CLI/VFS | existing Broker custody prepares, shared ceremony status/cancel, and custody result |
| Approval lifecycle CLI/VFS | existing Broker Sealed Approval methods only |

Handlers receive the narrow interfaces they need. Passing a broad `Daemon`,
`Keystore`, `AuthServices`, signer cache, or private signer into a production
handler is prohibited.

## 8. Legacy policy-session disposition

The pre-triad `wallets/<wallet>/policy-session/*` model is removed. It is not
retained as an alias and is not migrated into Broker state. Its `use` operation
has no target equivalent: Broker consumes a Sealed Approval as part of the
normal signing operation.

If the mounted VFS continues to expose approval management, its canonical
projection is:

```text
/wallets/<wallet>/sealed-approvals/new.json
/wallets/<wallet>/sealed-approvals/active.json
/wallets/<wallet>/sealed-approvals/<approval_id>/status.json
/wallets/<wallet>/sealed-approvals/<approval_id>/limits.json
/wallets/<wallet>/sealed-approvals/<approval_id>/renew
/wallets/<wallet>/sealed-approvals/<approval_id>/revoke
/wallets/<wallet>/sealed-approvals/revoke_all
```

Each file is a projection or adapter over the existing Broker methods
`sealed_approval.prepare`, `status`, `list`, `limit_state`, `renew`, `revoke`,
and `revoke_all`. Ceremony URLs and expiry follow parent AC-26. Machine stores
no independent approval state.

The CLI follows the same vocabulary. “Grant,” “standing session,” and
“policy-session” disappear from production help, docs, errors, and artifacts.

## 9. Petal-scoped sub-keys

A Petal may need a stable or short-lived Bloom-managed signing identity
distinct from the wallet root: an exchange API wallet, builder identity,
payment key, session agent, or protocol-specific child. When the Petal chooses
Bloom-managed derivation, such a sub-key remains wallet key material. Signer
owns it; neither Petal nor Machine receives its private bytes, an encrypted
export, a wrapping key, or a direct Signer capability. This section does not
restrict the separate Petal-owned application-key model in section 3.2.

### 9.1 Scope identity

The protocol defines a canonical `PetalKeyScope` containing at least:

```text
wallet_id
parent_key_ref
package_hash
route
agent_id?                 # optional stable Petal-local instance identity
purpose                   # short reviewed use, e.g. exchange-agent
allowed_crypto_suites[]
maximum_lifetime_ms
custody_operation_id
```

Its domain-separated digest is the immutable scope identifier. `package_hash`
and `route` are the same installer-pinned provenance identity used by
`ApprovalSubject::Petal`, `ApprovalSelector::Petal`, and `PetalUseClaim`.
Human-readable scope fields, not merely their digest, appear in Broker's exact
custody review.

### 9.2 Derivation and custody

Petal requests enter through a versioned payload-bearing Petal host call, not
through an arbitrary VFS write and not through a guest-supplied provenance
object. The call accepts only:

```text
request_id               # stable Petal-chosen retry identity
wallet_id
purpose
agent_id?
allowed_crypto_suites[]
maximum_lifetime_ms
```

The Petal runner injects the installed package hash and exact route from its
trusted execution context, constructs the parent-bound scope, and rejects a
guest field or serialized payload that attempts to override either value.
Repeated calls with the same `request_id` and identical terms reconcile one
custody operation; changed terms fail closed. The host result is either public
`KeyRef` metadata, a stable pending operation identity, or a terminal error.
It never returns private bytes, Browser HPKE material, or the ceremony session
token to guest code.

Machine projects the pending ceremony URL and expiry only in the originating
owner-readable VFS/CLI status artifact, following parent AC-26. The Petal may
poll the host call by stable request identity and receives public key metadata
only after Broker reports a completed custody result.

Machine then calls the existing `key.derive_prepare` method. The request
carries the canonical
`PetalKeyScope`; this is an extension of the existing request DTO, not a new
method. Broker must:

1. authenticate Machine and validate the package hash and route against the
   installer-signed provenance catalog;
2. evaluate wallet policy for Petal sub-key creation, lifetime, suites,
   purpose, and replacement;
3. construct the exact review and originate the custody ceremony; and
4. forward the scope, review-manifest digest, and existing custody identity to
   Signer.

Signer independently verifies the exact scope digest, user ceremony proof,
parent `KeyRef`, suite support, and that the parent root is enrolled to the
named wallet. It allocates a fresh child in a Signer-owned namespace and
durably records the child's full scope. A conflicting replay fails closed; an
exact retry of the same custody operation is idempotent. Distinct successful
custody operations never reuse a child path, `KeyRef`, or address.

The custody result contains only public `KeyRef`/address metadata. Machine may
cache that projection and return it to the originating Petal. Machine must not
choose a derivation path, configure a derivation authority, or receive a
namespace grant or private material from Browser.

### 9.3 Use isolation

Petal sub-key signing uses the existing payload-bearing
`sealed_approval.prepare` and `signing.sign` surfaces. Every approval names the
derived `KeyRef`; every operation carries the normal operation identity,
payload, digest, `PetalUseClaim`, assurance, and installer-pinned provenance.

Broker rejects a request unless the approval subject, selector, claim,
provenance record, wallet, and requested `KeyRef` all match the recorded Petal
scope. Signer independently loads the sub-key scope and rejects an approval
unless its `ApprovalSubject::Petal` package hash, route, optional `agent_id`,
wallet, key, suites, and validity are within that scope. An exact selector may
be used for a one-shot Petal operation; a reusable Petal selector may be used
only within its displayed limits and maximum scope lifetime.

This is the meaning of “accessible only to the Petal”: no other package hash,
route, first-party Machine/System subject, CLI subject, or unscoped approval
can use the child, even if it learns the public `KeyRef`. Petals still cannot
connect to Signer directly. The parent threat model remains unchanged: a fully
compromised Machine can make false `machine_asserted` claims within the
remaining capacity of an already approved Petal selector, but it cannot change
the selector's pinned Petal identity or use the key outside that capacity.

### 9.4 Lifecycle and revocation

Approval expiry, revoke, `revoke_all`, policy-version change, provenance
withdrawal, or scope expiry makes future signing fail at Broker and Signer.
Revoking an approval need not delete the derived key; reuse requires another
explicit approval for the identical pinned Petal scope. A Petal requesting a
replacement identity receives a fresh derivation and must explicitly migrate
any external authority. Machine cannot resurrect a tombstoned derivation or
retarget an existing child to a different Petal.

Signer audit and public projections expose the scope digest, public `KeyRef`,
status, and non-secret lifecycle metadata. Machine persists no approval
authority and no secret sub-key state.

### 9.5 Native Hyperliquid retirement

Hyperliquid is moving to a Petal and is not the reference implementation for
this mechanism. The replacement Petal may request an exchange-agent sub-key
under sections 9.1–9.4 and implement venue registration, bounded trading, and
cleanup through ordinary Petal approvals and claims.

Production Machine must retire or fail closed the native Hyperliquid authority
and write surface rather than maintain a second venue-specific delegated-key
protocol. Public read-only market/account helpers and a migration notice may
remain, but native owner-key actions, `EphemeralAgentKey`, sealed agent-key
blobs, local agent signing, and native session authorization are not permitted.
No native Hyperliquid behavioral parity is required.

Broker and Signer must contain no Hyperliquid-specific ceremony kind, input
class, namespace, derivation terms, policy rule, signing branch, or stored
metadata. They implement only the generic Petal scope. Hyperliquid registration,
orders, cleanup, and venue policy belong to the replacement Petal. It is
acceptable for the old native write surface to break immediately with a clear
migration diagnostic; compatibility is not a reason to retain authority code.

The same generic scope model applies to x402, MPP, exchange agents, builder
keys, and future protocol-specific delegated credentials. A new consumer does
not add a venue-specific custody or signing method.

## 10. Transaction and request engine extraction

`bloom-tx` may continue to construct unsigned payloads, calculate signing
digests, attach returned signatures, serialize signed transactions, and
broadcast. Its production code must not:

- import or construct `alloy::signers::local::PrivateKeySigner` or an
  equivalent private signer;
- call a local `sign_hash_sync` path;
- accept an `ApprovalVerifier`, `AuthStoreWriter`, legacy `PetalHost`, or
  policy-session store; or
- select an unsafe signing fallback when Broker is unavailable.

Tests may use private signers from dev-dependencies to verify encoding and
vectors. Such test helpers must not be reachable from a production feature or
binary.

Paid-request and transaction state stores remain Machine-owned because they
describe intended and external effects. Approval state does not. The old
`auth.sqlite` action-ID mapping is replaced with a purpose-specific
Machine-owned operation index whose schema contains no approval, challenge,
credential, grant, or signing-secret fields.

## 11. Developer and integration workflows

Removing embedded authority must not remove the ability to test mounted VFS,
Petals, real passkeys, and bounded mainnet flows locally.

The replacement is an out-of-process triad development harness that:

- starts the production Machine, Broker, and Signer protocol implementations
  under temporary developer-owned roots;
- may run all three under one login UID and therefore makes no production
  principal-isolation claim;
- uses the real Broker ceremony origin and real Signer custody/signing path;
- supports a genuine browser passkey for manual tests;
- mounts the VFS and drives Bloom only through that mounted filesystem where a
  mounted test is requested;
- preserves the bounded Polymarket mainnet safety profile and may exercise
  Hyperliquid only through its replacement Petal when that Petal is available;
  and
- never compiles private-key custody or approval verification into Machine.

`bloom-broker-debug-driver` remains the deterministic software-credential
harness required by parent section 24. It does not replace the manual real
passkey harness, and neither harness may be packaged in production.

Only after both deterministic and real-passkey replacement workflows pass may
Machine's `local-integration`, `unsafe-debug-signer`, ceremony server,
registration coordinator, sealed ceremony, signer cache, and hash-signing
modules be deleted.

## 12. Work packages

### M0 — freeze and inventory

- Record the source revision and every production feature combination.
- Generate reverse dependency and source-use inventories for
  `bloom-keystore`, `bloom-auth`, `bloom-auth-api`, private signer types,
  `AuthServices`, legacy `PetalHost`, and `EphemeralAgentKey`.
- Add failing release gates before removing code.

Completion: the inventory is exhaustive enough that adding a new forbidden
direct authority dependency, authority-enabling feature, Machine source use,
or callable fallback fails CI/local release validation. The inventory may flag
transitive third-party signer code for review, but may not fail solely on its
package name or source contents without evidence of a Machine authority path.

### M1 — public projection extraction

- Implement the key-free projection interfaces and cache.
- Add missing `MachineBrokerClient` convenience wrappers over existing RPCs.
- Move CLI wallet reads and Wallet VFS public reads to projections.
- Move status, `/next.md`, portfolio, watchers, bump scanner, and Petal public
  lookup to projections.

Completion: a wallet created in Signer appears in CLI and mounted VFS without
any legacy keystore record; stale-cache behavior passes.

### M2 — execution consumer extraction

- Remove keystore and legacy auth inputs from transaction staging, outbox,
  Petal transaction handling, and paid requests; retire native Hyperliquid
  rather than preserving its master-action implementation.
- Replace the auth-backed action-ID map with the Machine operation index.
- Prove every final signing digest uses Broker.

Completion: request, transaction, Petal, and background execution suites pass
with no legacy authority store present on disk.

### M3 — delegated-key extraction

- Implement canonical Petal-scoped sub-key terms over the existing
  `key.derive_prepare` method.
- Add the versioned Petal host call and owner-readable pending-custody
  projection; runtime provenance is injected and cannot be guest-overridden.
- Make Broker validate installer provenance and wallet policy and render the
  exact Petal scope before the custody ceremony.
- Make Signer own derivation, bind the parent root to the wallet, persist the
  immutable Petal scope, and enforce that scope independently on every sign.
- Route exact and reusable Petal sub-key signing through the existing Broker
  Sealed Approval and `signing.sign` methods.
- Retire the native Hyperliquid implementation; do not migrate its owner or
  agent keys into a venue-specific protocol.
- Remove decryptable delegated-key blobs and private signer APIs from the
  production Machine dependency surface.

Completion: a deterministic fixture Petal derives a fresh sub-key, receives
only public metadata, signs through an approval bound to its package/route, and
cannot use the key from a different Petal, System, CLI, wallet, expired scope,
or revoked approval. Memory, filesystem, dependency, cross-wallet,
cross-Petal, replay, restart, and fault-injection tests prove Machine never
receives the private key and Signer never loses the scope binding. No native
Hyperliquid behavioral parity is a completion condition.

### M4 — approval and policy-session removal

- Add canonical Sealed Approval VFS/CLI projections where product surfaces are
  retained.
- Delete `policy-session/*`, old challenges, grant stores, `AuthServices`,
  `StoreApprovalVerifier`, `KeystoreApprovalSignatureVerifier`, and
  `auth.sqlite` use.
- Remove legacy approval branches from `TxEngine` and request handlers.

Completion: Broker restart/reconciliation tests preserve approval state while
Machine restart loses no authority state because Machine owns none.

### M5 — developer harness migration

- Make deterministic Broker debug-driver coverage replace daemon signer tests.
- Make the out-of-process real-passkey mounted integration pass for the generic
  Petal sub-key derivation and payload-signing fixture, and exercise the pinned
  Polymarket Petal through its mounted production interface. The currently
  pinned Polymarket release imports retired hash-only signing; until a separately
  owned upstream release adopts the existing payload-bearing ABI, the harness
  must prove mounted read compatibility and fail before draft creation. A live
  Polymarket submission becomes a release acceptance test when that immutable
  upstream pin is updated; M5 must not add a shim or modify the Petal. Exercise
  Hyperliquid through its replacement Petal when that Petal is available; do
  not preserve the native agent-session path as a harness dependency.
- Delete Machine embedded ceremony, registration, signer-cache, local PRF, and
  unsafe debug signer code and features.

Completion: both developer workflows pass without a Machine key-bearing
dependency. The manual workflow completes genuine passkey custody and signing
for the generic fixture; the pinned legacy Polymarket route is mounted and its
live incompatibility is proven fail-closed before draft creation as specified
above.

### M6 — dependency and artifact purge

- Remove `bloom-keystore`, `bloom-auth`, and `bloom-auth-api` from every normal
  dependency path into production Machine binaries and libraries.
- Move any still-useful key-free DTOs to neutral crates rather than retaining
  a legacy authority dependency.
- Strengthen AC-04 release validation with Cargo metadata, feature-matrix,
  Machine-source/call-path, symbol-provenance, and runtime negative tests.
- Treat transitive third-party cryptographic code according to section 3.4;
  do not vendor or fork dependencies to satisfy a package-name or marker gate.
- Delete obsolete state writers and documentation.

Completion: all acceptance criteria in section 14 pass on the packaged bundle.

Dependencies:

```text
M0 -> M1 -> M2 -> M3 -> M4 -> M6
                 \         /
                  -> M5 --
```

M1 and M2 may migrate consumers incrementally, but no legacy authority
component is deleted until its final consumer has moved. M6 is the point at
which absence, rather than routing preference, becomes mechanically enforced.

## 13. Explicit removals

Subject to source drift, completion deletes or production-gates away all of
the following from Machine:

- `Daemon.keystore`, `Daemon.signer_cache`, and `Daemon.auth_services`;
- unconditional `Keystore`, `AuthStore`, `StoreApprovalVerifier`,
  `InMemoryGrantStore`, and `SignerCache` construction;
- `registration.rs`, `sealed_ceremony.rs`, `sign_hash.rs`, and the Machine
  ceremony server;
- `local-integration` and `unsafe-debug-signer` authority features;
- legacy `PetalHost::sign_hash` and hash-only production adapters;
- `wallets/<wallet>/policy-session/*` and its documentation;
- `auth/auth.sqlite` and old challenge/grant/session artifacts;
- the native Hyperliquid handler, `EphemeralAgentKey`, sealed delegated-key
  storage, agent sessions, and every native Hyperliquid signing path;
- private signer fields and local signing branches in `bloom-tx`;
- Keystore parameters on Wallets, Requests, Hyperliquid, status, Petal outbox,
  and background consumers; and
- the Broker-unavailable construction branch that restores the legacy
  composition.

This list does not authorize removal of unsigned transaction construction,
chain RPC, simulation, broadcast, public signature handling, Machine audit,
Petal execution, VFS, request state, or public projection caching.

## 14. Acceptance criteria

- **MA-01 — dependency graph:** Every packaged production Machine feature set
  has no normal or build dependency path to `bloom-keystore`, `bloom-auth`, or
  `bloom-auth-api`. Dev-dependencies are absent from production artifacts.
- **MA-02 — no private signer capability:** Production Machine source, objects,
  configuration, and Machine-owned symbols contain no construction, receipt,
  retention, recovery, or invocation path for a local wallet signer,
  `EphemeralAgentKey`, signer cache, PRF decryptor, recovery secret, or key-wrap
  implementation. Symbols attributable solely to an inert transitive
  third-party implementation are not a failure without a Machine source or
  call-path edge to that implementation.
- **MA-03 — projection fidelity:** Wallet registration, import, deletion,
  credential changes, key derivation, and policy updates become visible through
  CLI and mounted VFS solely from Broker projections, including across Machine
  restart.
- **MA-04 — projection rollback safety:** Altered, stale, rolled-back, missing,
  and partially written Machine projections cannot authorize signing or
  custody and are visibly stale or rejected.
- **MA-05 — degraded operation:** With Broker stopped, cached public reads,
  staging, and simulation work where their public inputs exist; every signing,
  approval, policy, and custody mutation fails promptly and reports the
  unavailable authority edge.
- **MA-06 — no fallback construction:** Broker authentication/configuration
  failure never opens a keystore, auth database, verifier, signer, or ceremony
  listener in Machine.
- **MA-07 — signing route matrix:** Automated tests cover transactions, batch
  transactions, ordinary and sub-key Petal payloads, paid HTTP/x402/MPP,
  outbox confirmation, background jobs, and every retained CLI/VFS signing
  entry point. Each observes a Broker operation ID
  and Signer receipt; direct or hash-only alternatives fail. Every retired
  native Hyperliquid write fails closed and performs no signing.
- **MA-08 — Bloom-managed Petal sub-key confinement:** Cross-Petal, cross-route,
  cross-wallet, System-subject, CLI-subject, expired-scope, revoked-approval,
  replay, restart, and fault tests prove a scoped child signs only for its
  pinned Petal identity. Machine receives only public `KeyRef` metadata and
  signatures; its filesystem, memory diagnostics, and crash artifacts contain
  no Bloom-managed sub-key or decryptable key blob. This criterion does not
  scan or prohibit opaque Petal-owned application keys in guest memory or the
  package-hash-namespaced Petal private store.
- **MA-09 — legacy state absent:** A clean production start creates no legacy
  keystore, `auth.sqlite`, approval challenge, grant, policy-session, or signer
  cache state. Pre-existing legacy files are not opened or trusted.
- **MA-10 — canonical approval lifecycle:** Every retained approval management
  surface maps to Broker Sealed Approval methods. `policy-session` paths and
  vocabulary are absent from production help, VFS discovery, and binaries.
- **MA-11 — policy custody:** Policy update uses
  `policy.validate_update` as Broker preparation, a completed ceremony receipt,
  and `policy.commit_update`; no direct commit or Machine policy writer exists.
- **MA-12 — developer parity:** Deterministic Broker debug-driver tests and the
  real-passkey out-of-process mounted integration both pass with Machine built
  from the same key-free production code.
- **MA-13 — production artifact gates:** Release validation rejects the named
  Bloom legacy authority dependencies, authority-enabling Machine feature
  activation, Machine source/call paths, Machine-owned authority symbols,
  forbidden files and methods, Signer sockets, and runtime connector attempts.
  A short marker list alone is not sufficient. A transitive third-party crate
  or symbol is not rejected solely because it contains a generic or unused
  signer implementation; the gate must prove a Machine authority path as
  defined in section 3.4. No vendored or locally forked upstream source may be
  introduced merely to satisfy this criterion.
- **MA-14 — parent conformance:** AC-01 through AC-35 are rerun on the bundle.
  In particular AC-02, AC-04, AC-14, AC-24, AC-26, and AC-35 must pass after
  legacy source and dependencies are removed.

## 15. Release-gate requirements

The release build must evaluate the resolved Cargo graph for every production
binary and allowed production feature set. It must fail if one of the named
Bloom legacy authority crates is reachable, or if a Machine-controlled feature
activates a callable local authority adapter, even when no forbidden string
appears in the final binary. It must report but not automatically reject an
otherwise permitted transitive third-party cryptographic package solely by
crate name or because that package internally contains signer code.

It must also scan for at least these classes:

```text
bloom-keystore
bloom-auth
bloom-auth-api
KeystorePetalHost
StoreApprovalVerifier
KeystoreApprovalSignatureVerifier
SignerCache
EphemeralAgentKey
PrivateKeySigner
unsafe-debug-signer
local-integration
policy-session
bloom.sign-hash
```

String matching is defense in depth, not authority-path proof. False positives
from user-facing migration diagnostics and inert transitive dependency symbols
must be handled through structured provenance tied to the exact artifact,
package, feature, and Machine call path. An allowlist may classify evidence;
it may not excuse a direct dependency, Machine construction site, private-key
flow, or callable signing fallback.

Runtime negative tests launch the packaged Machine with Broker and Signer
stopped or replaced by hostile sockets and prove Machine neither opens legacy
state nor attempts the Signer endpoint.

## 16. Non-goals

- Removing `bloom-vfs`, `bloom-tx`, Alloy transaction encoding, chain RPC,
  simulation, or broadcast from Machine.
- Preventing Machine from receiving public signatures or signed payloads it
  must broadcast.
- Moving Machine-owned action, request, simulation, execution, or external
  effect state into Broker.
- Claiming production process isolation for the same-UID development harness.
- Adding new Machine-to-Broker or Broker-to-Signer methods.
- Preserving legacy approval, policy-session, or debug-signer state
  compatibility, or legacy keystore compatibility.
- Deleting useful test vectors before equivalent Broker/Signer coverage exists.

## 17. Stop conditions and implementation discipline

Implementation stops for review only when a normative section cannot be
implemented as written without weakening a parent invariant, changing a wire
method, or assigning authority to the wrong principal. The delegated-key issue
in section 9 is an example of a legitimate protocol blocker if existing
contracts cannot express it.

An underspecified internal return shape, type name, cache layout, error
wording, unstated inconvenience, or scenario already resolved by the parent
threat model is not a stop condition. The implementer chooses the narrowest
conforming design, records it in the implementation log, and proceeds.

No implementation phase may make a temporary production fallback easier to
activate than the code it replaces. Intermediate commits must fail closed.

An absence gate that can be satisfied only by copying, vendoring, forking, or
patching unrelated upstream source is presumed to be specified at the wrong
boundary. The implementer must not perform that expansion. Apply section 3.4,
remove or relocate an actual Machine authority consumer, or seek a reviewed
specification amendment when the upstream coupling creates a real callable
authority path.

## 18. Proposed `/goal` prompt

```text
/goal Remove all legacy wallet authority, signing, approval, and key-bearing
state from production Bloom Machine according to
docs/specs/2026-07-31-machine-legacy-authority-removal.md and the normative
triad architecture.

Implement M0 through M6 in order. Keep Broker and Signer as the only production
authorization, custody, and signing path. Replace legacy keystore reads with a
key-free Machine public projection over existing Broker methods; remove the old
policy-session/auth database model; implement generic Signer-owned,
Petal-scoped sub-keys whose private material is never exposed to Machine or the
Petal; retire the native Hyperliquid authority implementation without adding any
Hyperliquid-specific Broker or Signer behavior; preserve read/stage/simulate
degraded operation without constructing legacy authority; replace embedded
local integration with out-of-process deterministic and real-passkey triad
harnesses; and enforce absence through dependency, artifact, feature, and
runtime release gates.

Apply dependency gates at the Machine authority boundary defined in section
3.4. Do not reject inert transitive third-party signer implementations solely
by package name or source contents, and do not vendor, copy, fork, or patch an
upstream dependency merely to make an absence gate pass.

Treat M0, M1, M2, M3, M4, M5, and M6 as the major work chunks. After completing
the implementation and local tests for each chunk, stop before beginning the
next chunk and assign a pragmatic reviewer sub-agent to inspect that chunk's
diff, tests, and relevant spec requirements. The reviewer must independently
check spec adherence, security-boundary preservation, regressions, and test
rigor. It must not demand speculative abstractions, unrelated cleanup, or
ceremonial over-engineering. It should report only concrete findings with
severity, evidence, and the violated requirement, or state that no material
findings remain. Address every material finding, rerun the affected tests, and
obtain a clean follow-up review before marking the chunk complete.

Do not add Machine-to-Broker or Broker-to-Signer wire methods without a reviewed
spec amendment. Do not preserve a temporary production signing fallback. Do
not delete a legacy component until its consumer has moved and replacement
coverage passes. Do not change the Polymarket Petal merely to accommodate
Machine extraction; exercise it through its mounted production interface.

Stop only when a normative section cannot be implemented as written without
weakening the parent architecture or changing a frozen protocol. Internal type
names, cache schemas, return shapes, error wording, inconvenient consequences,
and scenarios already decided by the parent spec are implementation decisions:
choose the narrowest conforming option, log it, test it, and continue.

Completion requires MA-01 through MA-14 and a packaged rerun of AC-01 through
AC-35. Report progress by work package and acceptance criterion, not by lines
changed. Do not use GitHub CI as a polling dependency; run platform-independent
tests locally and macOS packaging/isolation tests in the local Tart VM.
```

## 19. Review questions

Ratification should explicitly confirm:

1. the clean break from legacy authority state and `policy-session`;
2. the proposed canonical mounted Sealed Approval paths in section 8;
3. the generic Petal-scoped, Signer-owned derived `KeyRef` model and immediate
   retirement of the native Hyperliquid authority implementation;
4. replacement of embedded `local-integration` with an out-of-process real
   passkey triad harness; and
5. removal of all three legacy crates from the normal production Machine graph,
   moving any still-useful key-free DTOs to neutral crates.

## 20. Deferred TODO — edge-owned protocol repositories

After the authority-removal work settles the remaining DTO and delegated-key
contracts, replace the monolithic `bloom-triad-protocol` ownership model with
two edge-owned API packages:

```text
Machine -> bloom-broker-api  (owned and released by bloom-broker)
Broker  -> bloom-signer-api  (owned and released by bloom-signer)
```

Broker must perform an explicit, exhaustive translation between distinct
nominal Machine-facing and Signer-facing types. The Broker API must not simply
re-export Signer request or response types. Machine must not depend directly or
transitively on the Signer repository.

The split should keep truly edge-specific concepts on their edge: Petal claims,
provenance, public projections, and approval proposals belong to the Broker
API; structural signing enforcement, custody contributions, key registry,
policy CAS, and Signer receipts belong to the Signer API. Any shared wire
utility must remain small and mechanical and must not recreate a universal
domain protocol crate under another name.

Before extraction, freeze both edge schemas, canonicalization and conversion
vectors, closed errors, fake-peer suites, and version negotiation. Publish and
pin immutable releases rather than retaining sibling path dependencies. Amend
the parent repository policy before treating this TODO as normative work; it is
not part of M0--M6 unless separately ratified.

## 21. Implementation decision log

### 2026-08-01 — authority-path dependency gates, not transitive source bans

The first M6 implementation interpreted MI-02 as banning any transitive
third-party package that compiled an unused local-signer convenience
implementation. It copied four upstream package source trees into Bloom and
patched those implementations out. That added 54,782 vendored lines while
changing no Machine key flow or callable authority path. The vendored sources
and workspace patches were removed in `ce4fb74`.

That interpretation is rejected. The security invariant is that Machine
cannot construct, receive, retain, recover, or invoke wallet authority outside
Broker, not that every transitive cryptographic package must be devoid of
signing code. Sections 3.4, MI-02, M0, M6, MA-02, MA-13, and the release-gate
requirements now state the required dependency and reachability analysis.
Future gates must fail direct legacy authority dependencies, enabled Machine
authority adapters, Machine construction/call sites, key flows, and runtime
fallbacks. They must not force repository-scale upstream source copies to
erase inert code.

### 2026-07-31 — AC-18 authenticated journal-head transport (superseded)

The existing authenticated envelope carries an optional
`sender_journal_head`, covered by the envelope application signature. Protocol
minor 1 requires that field in both directions on the Broker-Signer edge and
forbids it on Machine-Broker and every other edge. The head is separately
signed by the sender application identity already pinned in the edge manifest;
its `service_id` and `key_id` must equal the authenticated envelope sender and
application key. Machine therefore cannot inject a peer checkpoint head.

This decision did not conform to parent section 20, which requires every
recipient to retain its peer's signed head after every cross-service security
mutation. It is superseded by the decision below and must not be used as an
acceptance basis.

### 2026-07-31 — AC-18 authenticated heads on both authority edges

Protocol minor 1 requires the existing `sender_journal_head` envelope field in
both directions on Machine-Broker and Broker-Signer. Control, login-session,
and revocation edges continue to forbid it. No RPC method or domain request or
response field is added.

The edge-specific transport builder obtains the head from the sending
service's verified local journal; an RPC caller cannot supply or override it.
The head remains separately signed by the sender application identity already
pinned in the edge manifest, and its `service_id` and `key_id` must equal the
authenticated envelope sender and application key. This preserves the original
anti-injection property without exempting Machine-Broker from parent section
20.

For a security mutation, the recipient checkpoints the authenticated request
head before dispatch and the caller checkpoints the authenticated response
head before publishing success or committing its correlated result. A
checkpoint failure latches local security mutations closed while status and
read-only methods continue from the last fully verified local head. Read-only
traffic also carries heads. Each long-running caller performs an authenticated
readiness exchange at least every 60 seconds while its peer is reachable, so an
idle edge still checkpoints both heads without a new method. Packaging
provisions a principal-private checkpoint root for each service and pins every
allowed current and historical peer application key; restore may not lower an
observed peer sequence. Application-identity rotation records the old public
key in packaging-owned immutable history before replacing the current pin, so
existing checkpoint entries remain verifiable. The service audit-key rotation
itself retains section 20's final-old-head/first-new-head cross-signing rule.

Live transport authentication remains a single-current-key decision. Only the
current application key in the active edge manifest may authenticate a new
envelope or newly observed head. Historical application keys are
verification-only: they may verify checkpoint entries and rotation continuity
created while that key was current, but they must never authenticate a new
connection, envelope, or head after retirement. Removing, substituting, or
rolling back packaging-owned history fails checkpoint verification closed; it
does not make a retired key live again.

Packaging-owned application-key history also records the exact handover tuple
`(service_id, old_key_id, new_key_id, sequence, head_hash)`. This authorizes the
first new-key head to repeat the last old-key `(sequence, head_hash)` exactly
once when the service journal did not advance during transport-key rotation.
No other equal-sequence key change is valid. A different hash, a second use of
the transition, a transition not matching the last retained old-key head, or a
head signed by the retired key after handover is a checkpoint fork and fails
closed. This narrow packaging-authorized handover does not replace the
separate dual-signature continuity required when the service audit key itself
rotates.

Minor 0 remains decodable only on edges whose contract does not require a
journal head. Both Machine-Broker and Broker-Signer reject minor 0 rather than
negotiating away checkpoint coverage. Conformance and golden vectors must cover
missing heads, wrong service/key identity, invalid signatures, rollback,
checkpoint-write failure before mutation dispatch, and response-checkpoint
failure before success publication on both edges. Runtime tests additionally
prove, on each authority edge:

- an idle authenticated readiness timer persists both heads within 60 seconds;
- local-audit or checkpoint degradation leaves reads/status available while
  mutations remain latched;
- restart after application-identity rotation verifies old checkpoint entries
  only through packaging history and rejects missing, substituted, rolled-back,
  or live-reused historical keys; and
- equal-sequence/different-hash or different-key forks are rejected as well as
  lower-sequence rollback.
