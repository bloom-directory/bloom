# Petal derived keys and package succession

Status: design proposal based on the implementation as of 2026-08-12.

This document distinguishes what Bloom implements today from a proposed design
for allowing an explicitly authorized successor Petal package to use an existing
Signer-owned derived key. It covers local development and production, including:

- initially pre-installed Petals;
- new versions of pre-installed Petals;
- arbitrary Petals installed by an end user; and
- new versions of those user-installed Petals.

Current production policy is deliberately narrower than the proposal below:
derived-key authority remains bound to one immutable package hash. Installing a
new package version does not inherit that authority; the Petal must request a new
key/session and the user must authorize it. Succession is deferred until a
durable-key caller requires continuity and the full user-authorized transition
can be implemented end to end.

The central rule is:

> Installing package bytes is not authorization to use a key. Key access is a
> separate, exact, user-authorized relationship between a package hash and a
> durable Petal lineage.

## Terminology

- **Package hash**: the normalized, content-addressed identity of one immutable
  Petal build.
- **Installation slot**: the Machine-owned mutable selection that determines
  which package hash currently owns a Petal name/mount.
- **Lineage ID**: a random, opaque 256-bit identifier for the continuing local
  identity to which derived keys are attached. Knowing the ID grants no access.
- **Key slot**: a Petal-defined public label such as a session or agent ID. A
  durable derived key is identified by wallet, lineage, and key slot.
- **Package admission**: an authorization stating that one exact package hash is
  the active package allowed to exercise a lineage's existing grants.
- **Succession**: the user-authorized transition from one exact active package
  hash to another within a lineage.
- **Pre-installed Petal**: a Petal selected from Bloom's built-in, immutable
  release catalog during initialization. It is not part of the macOS triad
  installer payload.
- **Triad installer**: `install-macos.sh`, which installs and upgrades Bloom's
  Machine, Broker, and Signer services. It does not run during
  `bloom petals install`.

## Security properties

The design must maintain all of the following:

1. Petal private keys remain exclusively inside Signer.
2. A package name, repository URL, source owner, or lineage string is never key
   authority.
3. Machine injects the executing package hash and route; guest code cannot
   assert or override either value or its lineage.
4. Broker and Signer each persist the active package for a lineage and each
   refuse stale, unknown, ambiguous, or frozen lineage state.
5. At most one package is active for a lineage by default.
6. A successor receives only the existing key scopes explicitly carried through
   the succession ceremony. Installing a successor does not widen route,
   operation-class, suite, lifetime, spend, or revocation bounds.
7. A predecessor loses new signing authority before a successor gains it.
8. Interrupted transitions fail closed and can be resumed or rolled back
   without generating a replacement private key.
9. Reinstalling the same hash and retrying the same operation are idempotent.
10. Uninstalling a package does not silently transfer or destroy derived keys.

## How the system works today

### Package installation

`bloom petals install` sends an IPC request to the running Machine daemon.
Machine supports two end-user inputs:

- a local package directory or `.petal.tar`; and
- a GitHub repository, which Bloom resolves and builds before installation.

Both paths validate a `PreparedPetalPackage`, calculate its normalized package
hash, write immutable package content and metadata, and atomically update the
Petal-name owner pointer. GitHub installs retain source URL, repository, commit,
selected tag, and package hash as informational source provenance. Local
installs retain no source provenance.

The current store treats installation of another package with the same Petal
name as replacement. The new owner pointer is committed after the new immutable
package is fully written. The old package remains briefly for in-flight readers
and is reconciled later.

This flow does not call the macOS triad installer, update the triad provenance
catalog, contact Broker about lineage, or contact Signer.

### Pre-installed Petals

Bloom configuration selects names from a built-in catalog. During `bloom init`,
Bloom downloads the catalogued release manifest and archive, checks them against
hard-coded repository, commit, archive checksum, tooling commit, package hash,
and ABI information, then installs the package into the same Petal store.

If Bloom finds an older package installed from the same catalogued repository,
it classifies it as outdated and replaces it with the newly pinned package. It
refuses to overwrite an installation with missing or conflicting source
provenance.

These checks establish which bytes Bloom intends to install. They do not create
or update a derived-key lineage. The release manifest is not currently a signed
lineage authorization artifact.

### Triad provenance catalog

The production macOS triad enrollment process generates an installer identity,
signs records from `provenance-catalog.unsigned.json`, and installs the result as
`provenance-catalog.json`. The current production template contains system
operation records, not arbitrary end-user Petal records.

Machine loads this static catalog to construct trusted execution provenance.
Broker separately loads it and verifies each record using its pinned installer
public key. Signer does not load or resolve this catalog.

The catalog schema now has optional Petal lineage-shaped fields:

- lineage ID;
- release sequence;
- predecessor package hashes;
- controller key ID and signature bytes; and
- active status.

However, the production installation path does not populate these fields. Shape
validation only checks that controller signature bytes are non-empty; there is
no implemented controller-key trust store or cryptographic verification of that
signature. The enclosing installer signature protects the record from mutation,
but it does not explain or implement runtime admission of an end-user package.

### Local triad development harness

A Bloom binary built with the non-default `triad-dev-harness` feature exposes a
hidden `triad-enroll-developer-petal-provenance` command. The local triad launch
script may call it before starting the services. It:

1. reads the developer root's installer private key;
2. builds and hashes a supplied Petal directory;
3. creates catalog entries for routes that declare signing intents;
4. signs those entries with the developer installer key; and
5. rewrites the developer root's static catalog.

Production bundles explicitly reject this feature. This command is test-harness
setup, not the end-user Petal installer. It also does not currently establish an
active lineage membership, so it is not a complete path for the new derived-key
API.

### Current derived-key request

When a Petal calls the typed key-derivation host API:

1. the guest supplies its wallet, key slot, requested routes, operation classes,
   suites, and maximum lifetime;
2. the runtime overwrites any guest context with Machine-trusted executing
   package hash and route;
3. Machine requires an exact `(package hash, route)` entry in its static
   provenance catalog and an active lineage membership on that entry;
4. Machine constructs a `PetalKeyScope` and a deterministic custody operation ID
   from wallet, lineage, and key slot;
5. Broker independently resolves and verifies the exact catalog record, wallet
   policy, active lineage, route, operation classes, suites, and lifetime;
6. Broker conducts the key-derivation ceremony with Signer; and
7. Machine persists only the public `KeyRef`, public-key metadata, scope, and
   ceremony state. The private key remains in Signer.

The stable `PetalKeyScope` digest deliberately excludes the current package hash
and requesting route. This is the correct beginning of a version-stable key
identity. The exact derivation request digest still includes them.

### Why successors do not work today

Several independent checks still prevent an installed successor from reusing
the key:

- normal and pre-installed Petal installation never create or transition an
  active lineage record;
- Machine requires the successor's exact package and route in its static
  catalog;
- Machine's persisted request state binds the original exact scope and
  provenance-record digest;
- wallet policy still requires the current exact package hash for ordinary
  approval preparation;
- Broker has no runtime lineage state-transition protocol;
- Signer persists the original `PetalKeyScope` and requires every Petal approval
  to use `scope.package_hash`; and
- Signer has no independent active-package registry for a lineage.

Consequently, production end-user-installed Petals cannot currently obtain this
lineage-backed key at all, and no successor can inherit it. The local fixture
setup does not change that production fact.

## Proposed authority model

### Separate installation from key admission

Machine continues to own package acquisition, validation, immutable storage,
and the installation-slot owner pointer. Broker and Signer own key authority.

Installing a package produces a **staged installation candidate** containing at
least:

- installation slot ID;
- old package hash, if any;
- new package hash;
- normalized package metadata and route index;
- requested capabilities and signing intents;
- source metadata, if available; and
- a digest over all of the above.

This operation alone grants no key access. If the installation slot has no
lineage with keys, Machine may commit it normally. If it has a lineage with
derived keys, Machine must not switch the owner pointer until succession is
explicitly resolved.

### Runtime lineage registry

Replace Petal key authority's dependence on the static installer catalog with a
runtime registry. Broker is the policy/orchestration authority; Signer retains an
independent enforcement mirror. Machine keeps a public projection for trusted
context injection and recovery, not unilateral authority.

A lineage record should include:

```text
lineage_id                  random pln1_<256-bit value>
generation                  monotonic transition generation
installation_slot_id        Machine installation identity
active_package_hash         exact current package, or none
state                       active | frozen | retired
authorized_package_history  exact transition audit history
active_route_grants         exact route -> allowed operation classes
created_by_operation_id     idempotent user ceremony
last_transition_id          idempotent compare-and-swap token
```

Broker and Signer must store the same lineage ID, generation, state, active
package hash, and route grants. Every transition request names the expected
previous generation and hashes the complete before/after state. Conflicting
retries are rejected.

No long-lived installer private key is involved. The authorization event is the
end user's explicit Bloom ceremony over exact transition terms, carried through
the existing authenticated Machine -> Broker -> Signer channel.

### Durable derived-key scope

The identity of a derived key should remain stable across package versions:

```text
wallet_id
parent_key_ref
lineage_id
key_slot
allowed_operation_classes
allowed_crypto_suites
maximum_lifetime / limits / revocation domain
```

Exact package hashes must not be part of the child-key derivation identity.
Exact route names should either:

- remain in the stable scope when the product promises stable route IDs; or
- move to each package admission's `active_route_grants`, with the durable scope
  retaining only operation-class ceilings or stable logical route roles.

The second model is more flexible and still safe. Every signature must satisfy
both the durable key ceiling and the currently active package's exact route
grant. A successor can narrow access without changing the key. Widening a
durable key ceiling requires a separate key-scope amendment ceremony and must
never be implicit in succession.

### Per-signature enforcement

For every signature, Machine supplies authenticated executing package and route
context to Broker. Broker checks:

- the lineage is active and not frozen;
- the package hash is the exact active package at the current generation;
- the route is admitted for that package;
- the operation class is within both the package grant and durable key scope;
- wallet policy, suite, expiry, limits, approval state, and revocation; and
- the requested public `KeyRef` belongs to the lineage and key slot.

Signer repeats all checks it can enforce independently using its local lineage
and key-scope state. It must at minimum reject when package hash, lineage
generation, active/frozen state, route grant, operation class, suite, expiry,
approval, or revocation does not match its records.

Signer must never accept “Broker says this is a successor” as an unrecorded flag
on an ordinary signing request. It accepts a package only after committing the
corresponding transition in its own durable registry.

## Proposed lifecycle flows

### 1. First installation of a pre-installed Petal

Bloom's built-in catalog may contain a random stable lineage ID assigned once to
that product and the exact expected package hash. This is useful identity and
candidate metadata because the Bloom release already pins the bytes. It is not
by itself permission to derive or use keys.

1. Machine validates and installs the exact pinned package.
2. Machine creates an installation slot associated with the catalogued lineage
   ID and exact hash.
3. No key is created merely because the package was pre-installed.
4. On the first key request, Machine presents the package's exact requested
   scope and installed identity to Broker.
5. The user approves creation of the lineage grant and derived key through the
   normal custody ceremony.
6. Broker and Signer durably commit matching generation-1 records with the exact
   active package and route grants under the fail-closed protocol, then derive
   or reconcile the key.

If a pre-installed Petal never requests a key, it never creates key authority.

### 2. Upgrade of a pre-installed Petal

A newer Bloom built-in catalog entry may identify the same lineage ID and name
the previously pinned package as the expected predecessor. This allows Bloom to
classify the update and produce a clear review, but it must not silently grant
the new hash existing key access.

If the installation has no lineage grants or derived keys, Bloom may retain its
current automatic exact-pin replacement behavior.

If the installation has a lineage with key authority:

1. Machine downloads, validates, and stages the new exact package without
   changing the current owner pointer.
2. Machine asks Broker to prepare a succession from exact old hash to exact new
   hash, including route/operation-class changes and the trusted Bloom catalog
   metadata that suggested the relationship.
3. The user explicitly approves or rejects key succession. Approval identifies
   exact hashes and the key slots/scopes to carry forward.
4. The fail-closed transition protocol below switches the active package.
5. The old package remains content-addressed until recovery and rollback windows
   close, but it is no longer authorized to sign.

Declining succession may either leave the old version active or install the new
version as a fresh lineage with no inherited keys. Bloom must not guess.

### 3. First installation of an arbitrary user Petal

An end user may install any valid local package, archive, or supported GitHub
source. Source identity is useful review information but is not lineage
authority.

1. Machine validates and installs the package into a new installation slot.
2. The slot initially has no lineage key grant.
3. If the Petal requests a derived key, Machine generates a random lineage ID
   (or asks Broker to generate it), binds it to the exact installation slot and
   package hash, and starts a user ceremony.
4. The review shows the exact package hash, source metadata if any, wallet, key
   slot, routes, operation classes, suites, lifetime, and limits.
5. On approval, Broker and Signer create matching generation-1 lineage records
   and the Signer-owned derived key.
6. Machine stores the public lineage projection and `KeyRef` only.

Two unrelated installations of identical bytes may deliberately be placed in
different local lineages. Conversely, the user may explicitly attach an
installation to an existing lineage only through the successor flow; the Petal
cannot request that attachment itself.

### 4. Upgrade of a user-installed Petal

Installing another package with the same name, from the same repository, or
from a newer tag is not sufficient to inherit keys. Those facts only help
Machine suggest that the package may be a successor.

For an installation slot with key authority:

1. Machine stages the replacement instead of immediately overwriting the owner
   pointer.
2. Machine shows the user the exact old and new hashes, source/commit changes,
   code-capability and route/operation changes, and affected public key slots.
3. The user chooses one of:
   - replace and carry selected existing key scopes forward;
   - replace as a fresh lineage with no inherited keys;
   - keep the old package active; or
   - cancel installation.
4. “Replace and carry forward” runs the same succession protocol used for a
   pre-installed Petal.

The user may authorize a successor from a different repository or with a
different name because the explicit exact-hash ceremony is the authority.
Bloom should display a stronger warning, but must not pretend repository
continuity is cryptographic identity.

### Uninstall and reinstall

Uninstalling the active package freezes or retires its lineage admission before
removing the owner pointer. Derived private keys are retained in Signer unless
the user separately and explicitly purges them. Reinstalling the same package
does not automatically reactivate a retired lineage; the user may resume it
through an exact-hash ceremony.

Removing the final package and permanently destroying its derived keys are
separate operations. Key destruction requires its own confirmation and durable
tombstones so an old operation cannot recreate the authority accidentally.

## Fail-closed succession protocol

Package storage and Broker/Signer databases cannot share one filesystem
transaction. The protocol therefore prioritizes never authorizing both package
versions, accepting a temporary signing outage during transition or recovery.

1. **Stage**: Machine fully validates and stores the new immutable package. The
   current owner pointer and active lineage remain unchanged.
2. **Prepare**: Broker and Signer durably record the exact transition digest,
   expected lineage generation, old/new hashes, proposed route grants, carried
   key scopes, and expiry. Exact retries are idempotent.
3. **Approve**: the user approves those exact terms. Any changed bytes require a
   new ceremony.
4. **Freeze**: Signer first, then Broker, marks the lineage frozen at the next
   generation. Neither old nor new package can obtain new signatures.
5. **Drain**: Machine blocks new executions for the installation slot and waits
   for old executions and signing requests to finish or expire.
6. **Switch**: Machine writes a durable transition intent and atomically changes
   the installation-slot owner pointer from the expected old hash to the exact
   new hash using compare-and-swap.
7. **Activate**: Broker and Signer verify the committed Machine switch receipt,
   set the exact new hash and grants active at the new generation, and retain the
   old hash only in audit history.
8. **Unfreeze**: Signer and Broker allow the new exact hash to use the carried
   scopes. Machine resumes the slot.

Recovery examines the durable phase:

- before freeze: abort safely; the old package remains active;
- after freeze but before switch: roll back to the old package or resume;
- after switch but before activation: signing remains frozen; resume activation
  or switch back to the retained old package;
- after activation: complete cleanup idempotently;
- conflicting owner pointer, generation, or transition digest: remain frozen
  and require explicit repair.

Pending approvals created by the predecessor must not become valid for the
successor. Freeze invalidates or tombstones package-bound pending approvals.
Active long-lived approvals must be re-evaluated against the new package's exact
route grants; the safest default is to require new approvals after succession
while retaining the derived key itself.

## Development behavior

Development must exercise the same protocol and state machine as production.
The `triad-dev-harness` may provide only test conveniences:

- local Broker and Signer identities and isolated state roots;
- deterministic fixture packages;
- a test user-approval backend or explicit scripted approval token;
- fault injection at every transition phase; and
- inspection commands for lineage state.

It must not grant inheritance by editing a catalog behind running services. A
developer installing an arbitrary local Petal should use the normal install,
first-key, and successor flows. Automated integration tests may approve exact
fixture terms non-interactively, but that seam must remain excluded from release
bundles.

Required development tests include:

- first key request creates one key and exact retry returns the same `KeyRef`;
- two routes in one admitted package share the same authorized key slot;
- approved successor returns the same `KeyRef` and public key;
- predecessor signing fails after activation;
- unapproved, unrelated, stale, downgraded, or forked packages fail;
- widening routes/classes during succession fails or requires a separate
  explicit amendment;
- pending predecessor approvals cannot cross the transition;
- interruption at each protocol phase recovers without dual authorization;
- rollback restores the predecessor's access without changing the private key;
- Broker or Signer state disagreement freezes signing; and
- uninstall, reinstall, retirement, and permanent key purge are distinct.

## Production integration changes

### Machine and Petal store

- Add stable random installation-slot IDs rather than treating the Petal name as
  identity.
- Split package staging from owner-pointer activation.
- Persist public lineage projection, generation, transition ID, and recovery
  phase beside the installation slot.
- Serialize installs/upgrades per slot and use owner-pointer compare-and-swap.
- Inject exact package, route, lineage, and generation into every authority
  request.
- Add CLI/UI review and recovery commands for pending successors.

### Broker

- Add lineage create, successor prepare, freeze, activate, rollback, retire, and
  inspect APIs.
- Persist a monotonic lineage registry and transition journal.
- Make user-approved exact transition terms the source of runtime lineage
  authority.
- Replace exact-package wallet policy checks with lineage-aware policy plus
  exact active-package checks. Policy may allow a lineage, but only its current
  admitted hash can exercise it.
- Separate key-scope amendment from package succession.
- Tombstone or invalidate incompatible pending approvals during freeze.

### Signer

- Persist its own lineage generation, state, exact active package, route grants,
  transition digest, and key-slot bindings.
- Participate durably in the transition ceremony and reject unilateral Broker
  assertions not backed by committed local transition state.
- Remove the original package hash from durable derived-key identity and from
  the rule that permanently pins all approvals to `scope.package_hash`.
- Continue requiring the exact current package hash on every signature and
  resolve it against local active lineage state.
- Freeze on missing, stale, conflicting, or rolled-back transition state.

### Static provenance catalog

Keep the installer-signed catalog for static triad subjects and other facts that
are genuinely established at triad enrollment. Do not use it as the mutable
runtime database of arbitrary end-user Petal installations.

Pre-installed catalog entries may supply suggested stable lineage IDs and exact
release relationships, but runtime key succession still requires the user
ceremony and Broker/Signer transition. The currently unused controller fields
should either be removed until a real controller-key system exists or specified
and implemented separately; non-empty signature bytes must never be presented
as verification.

## Rollout order

1. Introduce versioned lineage-transition APIs and durable state in Broker and
   Signer, initially unused by signing.
2. Split Machine installation into stage and activation and add crash recovery.
3. Implement first-use lineage creation for arbitrary and pre-installed Petals.
4. Change stable key scopes and Signer enforcement to resolve the active runtime
   lineage registry.
5. Implement user-approved succession and approval invalidation.
6. Move the development Hyperliquid fixture from static catalog enrollment to
   the real runtime flow.
7. Add pre-installed update integration and production conformance tests.
8. Only then claim that a successor can reuse a derived key in production.

During migration, existing package-bound keys remain package-bound. They must
not be silently converted. A one-time user ceremony may adopt an existing key
into a newly created lineage after verifying the original exact package and
scope in Broker and Signer.

## Non-goals and future extensions

This design does not require a marketplace, publisher PKI, repository ownership
proof, or the macOS installer to run during Petal installation. Such systems may
later improve update recommendations or permit a user-configured automatic
approval policy, but they are not prerequisites for safe local succession and
must not replace exact runtime enforcement.

Side-by-side active versions are also out of scope for the first implementation.
They require explicit multi-member admission semantics and substantially expand
the attack surface. The safe default is one active package per lineage.

## Implementation anchors for current behavior

The current-behavior sections above are grounded in these implementation paths:

- End-user install IPC and local package/archive handling:
  `crates/bloom-daemon/src/ipc.rs` (`do_petals_install`).
- GitHub source builds and built-in pre-installed release handling:
  `crates/bloom/src/github_source.rs`.
- Content-addressed package commit and Petal-name owner switch:
  `crates/bloom-petals/src/store.rs`
  (`install_prepared_petal_package_with_source_guarded`).
- Runtime injection of trusted Petal execution context:
  `crates/bloom-petals/src/vm.rs` (`component_petal_key_request`).
- Machine key reconciliation and static provenance lookup:
  `crates/bloom-daemon/src/lib.rs` (`petal_key_request`).
- Stable scope and exact request digest:
  `bloom-broker-api/src/petal_key.rs` and
  `bloom-signer-api/src/petal_key.rs` in their respective repositories.
- Static catalog and lineage-shaped fields:
  `bloom-broker-api/src/provenance.rs`.
- Broker catalog verification, key-scope persistence, and approval enforcement:
  `bloom-broker/src/authority.rs`.
- Signer's original-package enforcement:
  `bloom-signer/src/engine.rs` (`validate_petal_key_approval`).
- Production triad catalog generation and installation:
  `crates/bloom/src/triad_enrollment.rs`,
  `packaging/triad/macos/config/provenance-catalog.unsigned.json`, and
  `packaging/triad/release/install-macos.sh`.
- Local fixture-only catalog rewriting:
  `crates/bloom/src/triad_enrollment.rs`
  (`run_developer_petal_provenance`) and `scripts/triad-dev-launch.sh`.
