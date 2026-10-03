# Petal private-state carry-forward on upgrade

Date: 2026-09-25

Status: implemented continuity contract; updated 2026-09-30
Related: [Minimal HD-account support for Petals](2026-09-25-minimal-hd-account-petals.md)

## 1. Problem

Petal private state (the `bloom:store/kv` store: settings, API keys, secrets,
Petal-side operation records) is partitioned by package hash:
`~/.bloom/petals/data/<package hash>/` (`crates/bloom-petals/src/private_store.rs`).
Any new release has a new hash and so starts with an empty partition. The
[2026-07-10 security review](../reviews/2026-07-10-local-petal-plugins-architecture-security-review.md)
records: "No automatic state migration exists."

Every Petal release therefore makes users re-enter settings and API keys and
loses Petal-side records of in-flight work. Compatible future releases should preserve these stores. The first explicit-route
HD release deliberately starts fresh numbered stores, including account zero;
it does not migrate legacy wallet-wide settings or disposable sessions. Pending
funded operations must be reconciled before that upgrade, and their recovery
records retained, as required by the HD-account spec.

## 2. Decision

Before activating an authenticated successor release of the same Petal lineage,
copy its predecessor's private state into the successor's empty partitions. The predecessor partition is never modified.

Not included:
- Petal-declared migration hooks or schema versions.
- Carrying delegated-key sessions across packages (see §6).
- Garbage collection of old partitions.
- Continuity for packages without lineage provenance (local/dev installs keep
  today's behaviour).

## 3. What authorises a copy

The installer provenance catalog already holds a signed `PetalLineageMembership`
per package (`bloom-broker-api/src/provenance.rs:53`), with `lineage_id`
(publisher + package name), `release_sequence`, `predecessor_package_hashes`,
a controller signature and `active`. The daemon already relies on it for
delegated-key custody (`crates/bloom-daemon/src/lib.rs:1342`).

Copy from package P to package H only when all of these hold:

1. H has a catalog record with an active lineage membership.
2. P appears in H's `predecessor_package_hashes`.
3. P was the installed owner of the same Petal name that H replaced (§4.1).
4. H's private partition does not yet exist.

Missing release information for a lineage-backed upgrade is an activation
failure, not permission to start empty (§4.1). Other ineligible copies start
empty, as today, and the reason is logged. A package from a
different publisher cannot inherit state, because lineage includes publisher
and the predecessor list is signed by the lineage controller. A downgrade does
not copy either: the older package does not list the newer one as a
predecessor.

## 4. Mechanism

### 4.1 Record the outgoing package at install

Before activating a lineage-backed upgrade, load and verify the incoming
package's signed catalog record in the daemon that will execute it. Merely
placing the catalog on disk is insufficient. If loading requires a daemon
restart, complete that before enabling the new package. Until verification
succeeds, do not switch the active owner to H or run H against a fresh store;
leave P active. Report missing or invalid release information as an activation
error. The normal install/release process can retry after supplying it; no
background migration retry mechanism is required. Local/dev packages without
lineage provenance retain their existing empty-store behavior.

A malformed catalog must not disable unrelated stateful Petals. Already
initialized selected store partitions and packages with no replaced owner remain usable.
An existing account-0 partition must not unlock a fresh account-n partition
whose migration is still unresolved. Log a malformed catalog when it is loaded.
Fresh replacement stores whose migration decision needs catalog authorization
must fail closed until valid release information is loaded; do not log and
skip their migration, then allow them to write empty state. With a valid
catalog, replacements without lineage for either package retain development
package behavior. Missing successor metadata for a known lineage predecessor
also blocks first use, even if an installation bypassed the activation check.
Likewise, a successor that lists its replaced package must not start a fresh
store while the predecessor's required lineage record is missing. A verified
different lineage is a known refusal; missing proof is not.

The guarded package activation in `crates/bloom-petals/src/store.rs` knows the outgoing owner hash just
before its commit point (`write_petal_owner`). Record it in the incoming
package's `PetalMeta` as a new optional field:

```rust
#[serde(default)]
pub replaced: Option<String>,   // outgoing owner hash for this Petal name
```

`PetalMeta` does not deny unknown fields, so an older Machine reading this meta
after a rollback ignores it. Re-installing an already-present hash keeps an
existing `replaced` value rather than overwriting it with itself.

### 4.2 Copy before activation

The common local/source/default installation path uses the runner's loaded
catalog to prepare state under the existing package-mutation execution guard,
before `write_petal_owner` makes H visible. No guest code runs during copying.

1. Check §3 against the loaded catalog.
2. If authorised, use the existing `store_op_guard` to copy `data/<P>/` to
   `data/.<H>.carry.tmp/`, then rename it to `data/<H>/`. Do the same for the
   numbered-account root (§5). Existing successor partitions are preserved.
   Preserve file modes; secrets are written `0600`.
3. A copy failure leaves P active. A known ineligible relationship creates
   nothing; first writes still create empty partitions as before. Missing or
   invalid required release information remains an activation error (§4.1).
4. Log `petal_state.carried_forward` or `petal_state.not_carried` with the
   hashes, lineage and reason, then commit the new owner.

This preserves P's state through P → H → J even when H is never invoked and
startup reconciliation removes P's package metadata. No ancestry traversal is
needed. The existing first-use check remains defensive for packages installed
outside the common activation path; it caches completed decisions per hash.

Each directory rename is its commit point. A crash before a rename leaves a
temporary directory that the next attempt deletes and redoes. The two store
roots are not committed atomically: a crash between their renames may leave
partial carry-forward. This risk is explicitly accepted; cross-root recovery
is outside this implementation.

### 4.3 Effects on rollback and re-upgrade

- **Rollback to P:** P's partition is untouched (private data is never removed
  today; `remove_package_data` touches only package files). P resumes from its
  pre-upgrade state. Changes made while H was active are not visible to P.
  This is accepted.
- **Upgrade to H again:** H's partition already exists, so there is no copy and
  H resumes its own state.
- **Skipping releases (P → J):** this works if J lists P as a predecessor. The
  release tooling decides how far back predecessor lists reach.

## 5. Uniform numbered-account partitions

The HD-account spec adds per-account stores keyed by package hash, wallet and
account number. Lay them out so that one package's accounts form one directory:

```text
~/.bloom/petals/data/<package hash>/                            Petal-wide settings and retained unscoped data
~/.bloom/petals/data-accounts/<package hash>/<account digest>/  every numbered account, including 0
```

Carry-forward copies `data-accounts/<P>/` to `data-accounts/<H>/` in the same
step and under the same rules. `<account digest>` (of wallet and account
number) does not depend on the package hash, so each account finds its own
copied store. Legacy package-level records are never translated into these
numbered partitions; a copied public namespace does not become account-zero state.

## 6. Delegated-key sessions

`PetalKeyScope` binds `package_hash` and route, and install already refuses to
replace a package while its sessions are active or pending unless forced
(`crates/bloom-daemon/src/ipc.rs:539-555`). That rule is unchanged: users stop
sessions before upgrading and create new ones afterwards. Session records are
keyed by wallet, lineage and slot and remain visible and stoppable through
`/wallets/<w>/<n>/sessions/`.

## 7. Petal responsibilities

A successor must read state written by its predecessors, or tolerate and
replace it. Bloom copies bytes; it does not interpret or migrate them. Document
this in the Petal author docs. Compatible successor releases must test predecessor store fixtures. The first
explicit-route release instead tests empty uniform account-zero state without
legacy fallback, and documents recovery prerequisites for outstanding funded work.

## 8. Release

The copying and activation changes live in Machine and ship with the HD-account
change. They preserve compatible partitions during subsequent package updates;
they do not migrate the legacy account-zero layout. It requires those Petal releases' catalog records to list
the currently pinned hashes in `predecessor_package_hashes`. Verify that the
existing release tooling fills this in; do not add a new provenance scheme.
Load and verify the successor catalog records before activating the new
default-Petal pins, including on daemon startup after an update.

Implementation audit found that the existing catalog emits lineage records only
for Polymarket and Hyperliquid authority routes. Extend the existing installer
catalog to cover all five compatible Petals and retain their predecessor records.
For Enso, Near and Tolly, these are lineage-only records with no operation classes.
The shared Broker API must accept that shape only for Petal records with valid
lineage metadata. Broker's catalog loader must verify and accept those records;
its approval verifier must continue rejecting records with no operation classes.
This grants no signing authority. An older Broker rejects the expanded catalog,
so the updated Broker and Machine must ship together in the compatible triad
bundle, using the existing dependency and compatibility pin process. Petal
release assets themselves do not supply the catalog.

## 9. Acceptance tests

1. **Authorised upgrade:** P → H with H listing P and an active lineage copies
   KV and secrets. Secret file modes are preserved. P's partition is byte-for-
   byte unchanged.
2. **Refused copies:** H not listing P; inactive lineage;
   different lineage; local package with no lineage; downgrade H → P. Each
   starts empty and logs a reason.
3. **Activation ordering:** stage a lineage-backed H while its catalog record
   is missing, invalid, or present on disk but not loaded. Activation fails,
   P stays active, and H cannot create a fresh store. Load and verify the
   record (restart if required), then activate H. Activation carries P's state
   forward. Exercise the same ordering for the bundled default-Petal update.
   A malformed catalog must leave existing initialized stores and unrelated
   development packages usable while blocking fresh replacements that need
   authorization. Verify that refusal creates neither successor store root.
4. **Single-partition crash safety:** kill before a partition rename. The next
   use cleans its temporary directory and retries. Recovery across the two
   store-root renames is not required (accepted limitation in §4.2).
5. **Concurrency:** active predecessor invocations exclude activation; state is
   copied before the successor becomes visible. Parallel first invocations
   preserve the already prepared state.
   **Unused intermediate:** P → H → J, without invoking H and with a restart
   after installing H, preserves shared and numbered-account state.
6. **Rollback and re-upgrade:** H → P resumes P's pre-upgrade state; P → H
   resumes H's state without copying.
7. **Account-n:** account 1 state for two wallets carries forward to the
   matching account stores.
8. **Bundled Petals:** the first explicit-route release uses empty uniform stores
   when only legacy state exists, leaves old data untouched, and requires funded
   work to be reconciled before upgrade. Compatible later successors preserve
   uniform stores for accounts 0 and 1.
9. **Hot path:** after first use, invocations do no extra filesystem or catalog
   work beyond today's.

### Petal-wide service settings

The explicit-route host also supports exact `[store].shared_keys` declarations.
Those keys remain in the package-level store for every invocation; they are not
account-zero records. Compatible signed succession carries that package-level
store through the existing mechanism, alongside the separate numbered account
stores. No account-store credential is copied into the shared store, and no
legacy account state becomes visible merely because a service key is shared.

### In-flight calls during replacement

Route execution holds a shared store permit from route selection through guest
completion. Package activation and uninstall require an exclusive permit and
return a retryable busy message while any Petal is executing. This keeps normal
invocations concurrent and prevents an outgoing guest from writing after the
successor becomes active and copies its state. The gate is shared by the daemon's
store clones; no per-KV locking, drain queue, or background migration is added.
