# Schema-1 upgrade and schema-2 downgrade boundaries

## Source and scope

The released reference is Machine `9dc4039d96b175b4f7b90d40d6521518a52d5c07`, Broker `dd2add2b9d41540521d08c77d19fb467a2d8029e`, and Signer `ccc9adb3866b17b87d2774018dcfa015184b1918`. The release schema marker is distinct from each SQLite `user_version` or JSON schema string. Bloom 0.4.0 is a product version, not a storage-format identifier.

The original candidate declared `current = 2` and `downgrade_floor = 2` for all components. macOS preflight incorrectly reused `downgrade_floor` as the minimum source state accepted for an upgrade, blocking schema 1 before any service or custody mutation. The original live attempt therefore left the installed release unchanged.

## Machine marker justification

Machine's schema-2 marker is independently justified by persisted public projections, not by possession of custody material:

- The wallet projection cache embeds Broker `CredentialPublic` records. Current records include a `surface`; the exact released Broker API uses `deny_unknown_fields` and rejects this field. Both local and remote credentials can carry it.
- Wallet-registration projections now persist `surface_selection`. The previous Machine registration projection also rejected unknown fields. New recovery projections introduce additional lifecycle state alongside those records.
- An unchanged outer JSON schema string does not make nested records readable by an old implementation. The release marker prevents selecting that old reader after a new reader has persisted these records.
- Current credential decoding defaults an absent surface, so reading an existing schema-1 projection is supported. This is a forward compatibility path, not permission to run an older reader over rewritten data.

The Machine regression serializes a credential using the exact released Broker API, loads it in a populated current projection cache, then persists a surface-bearing projection. It verifies the current cache reader accepts both forms and the released credential reader rejects the new form. No wallet keys or PRF values are involved. The old API is test-only and is not linked into the production Machine.

Keep `current = 2` and `downgrade_floor = 2` for Machine. Describe this as projection-format compatibility, not a change to wallet cryptography. Cache rebuild could support a separately designed downgrade procedure, but the installer must not silently discard pending-operation or migration metadata to force one.

## Authority owners

Signer adds durable surface and credential-authority state, performs additive migration from older database versions, defaults legacy local credential metadata, and preserves the canonical bytes of old signed receipts. Broker adds persisted paired-ceremony/session state and invalidates obsolete pending ceremonies while preserving committed receipts and their delivery state. Their exact populated predecessor compatibility tests belong to their owning repositories; an empty database with its version marker changed is insufficient evidence of a released-data migration.

## Upgrade and rollback rules

`migration_floor` declares the oldest source state the candidate can read/migrate. `downgrade_floor` declares the oldest reader generation permitted after migration. They are different bounds and must satisfy `migration_floor <= downgrade_floor <= current`. The supported schema-1 to schema-2 path uses `migration_floor = 1`, retaining `downgrade_floor = 2`.

A candidate authority service can migrate its database during startup, before the installer health check completes. Therefore crossing the downgrade floor must become durably forward-only before those services start. Retrying a failed or interrupted migration keeps the candidate and journal; it must not select an older forbidden reader or rewind custody/audit databases.

Same-schema upgrades may roll back only before normal user access is published. Machine runs an installer-only health endpoint while enrollment is activating. Before full activation, a durable commit fence must prohibit rollback, because full Machine startup can persist new projections and users may begin operations. Interrupted recovery must honour that fence even if the state marker has not yet been written.

No authority database backup/restore is added as an upgrade rollback mechanism. Rewinding custody after user-visible operations could undo counters, revocation, recovery fencing, or replay protection. Backup and disaster recovery remain separately governed operations.

## Validation evidence

The Machine compatibility regression and all 54 `bloom-machine-client` tests passed, as did strict all-target Clippy for that package. The test-only dependency pins the exact released Broker API; it does not approximate the predecessor by deleting fields from a current type.

Signer commit `34248a3711d8c1c7ddb99d76b3ff5b976e536485` adds a populated SQLite fixture produced by the exact released Signer. Its locked compatibility pipeline verifies migration from SQLite version 0 to 2, unchanged signed receipt and custody bytes, replay rejection, real verification with the restored WebAuthn credential, and matching root identity after both credential and recovery-factor unlock. A separate diagnostic predecessor reopen does not authorize downgrade.

The installer phase tests execute the shell transaction functions with injected health and activation failures. They cover rollback before publication in a same-schema upgrade, no rollback after a schema-1 migration starts, stricter downgrade-floor fencing on retry, and failure after partial multi-login activation. This is transaction-control evidence; it does not substitute for real two-login macOS conformance, which remains deferred.

Broker commit `937729b41c50daf6b8b8cf30b2b7fa1641b1048a` migrates its populated released journal while preserving policy and signed receipts. Independent predecessor-format cases cover genuinely pending cancellation, commit-before-Broker-persistence, stored committed receipts, and pending receipt delivery. All 53 W5 ceremony tests passed with the installed Node 26 runtime, along with strict workspace/all-target/all-feature Clippy and formatting. The adapter reuses Serde and the existing reconciliation state machine; custom field defaults encode only Bloom's fixed legacy localhost identity and generation zero. It never rewrites signed receipt contents.

Final pinned-candidate macOS release suite: 42 passed, with 21 Linux-only cases filtered. The resolved-dependency check inspects normal/build edges for Machine and the integration test APIs, so the intentional predecessor reader remains test-only without weakening the release pin check. The 0.4.0 all-target compile check passed.

At the final pins, all 54 Machine client tests passed outside the sandbox (two local Unix-socket tests are denied by the sandbox). Strict release-test Clippy, formatting, shell syntax and diff checks passed.
