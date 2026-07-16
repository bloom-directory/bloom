# Petal Platform Expansion for Native-Feature Parity

**Status:** Initial detailed specification  
**Date:** 10 July 2026  
**Depends on:** Local Petal Plugins v1, Sealed Approval, Polymarket Petal Parity
**Scope:** Extend the generic Petal platform so venue and protocol integrations can move out of native Bloom without moving Bloom's security kernel into untrusted Wasm.

## 0. Summary

Bloom's current Petals v1 platform is sufficient for request-driven applications that need static-host HTTPS, per-package KV, simple chain calls, one-hash signing, and ordinary EVM transactions.

It is not sufficient for full replacement of native Hyperliquid, paid HTTP, DeFi, watch, simulation, chain explorer, or system-provider functionality.

This specification adds generic platform services in five groups:

1. **Semantic authority:** prepared actions, exact signing sets, multi-signature grants, and host-verifiable effects.
2. **Durable execution:** scheduled jobs, lifecycle hooks, event subscriptions, retry, and checkpoints.
3. **Secret custody:** opaque secrets, HTTP credential injection, and non-exportable delegated signing keys.
4. **Richer system services:** typed wallet/system reads, expanded chain/simulation APIs, and transaction batches.
5. **Upgradeable applications:** stable app data, explicit migrations, provider contracts, and controlled package activation.

The target architecture is:

```text
Petal application
  owns protocol semantics, routes, parsing, plans, calldata, receipts
        |
        v
versioned generic Bloom host interfaces
        |
        v
native Bloom security/runtime kernel
  custody, policy, approvals, audit, chain transport, scheduler,
  transaction execution, secret vault, service selection
```

The objective is not to make the daemon empty. The objective is to make native venue/protocol integrations unnecessary while preserving a small, auditable, venue-neutral kernel.

## 1. Decision

Bloom SHALL retain the following native responsibilities:

- wallet and passkey custody
- Sealed Approval, challenge issuance, grants, and attestation verification
- wallet policy and budget enforcement
- EVM transaction construction validation, signing, and broadcast
- audit-log integrity
- chain endpoint selection and endpoint credential custody
- durable job and subscription supervision
- non-exportable secret and delegated-key custody
- IPC, VFS mounting, daemon lifecycle, and package activation

Petals SHALL own:

- venue and protocol API behavior
- user-facing VFS route trees
- request/response parsing
- quotes and order construction
- protocol-specific hashes and typed-data construction
- calldata construction
- workflow presentation and review artifacts
- protocol-specific receipt parsing and reconciliation
- policy-neutral calculations
- application-local state

### 1.1 Recorded blocking decisions

The following are decisions, not open questions.

#### D1: stable app identity is host-issued

Stable identity is an **app instance ID** allocated by Bloom at first activation. It is not derived from app name, package contents, repository URL, or a package-declared identifier.

- The ID is a random 128-bit value encoded as `app-<lowercase base32>`.
- The activation record binds the ID to the current package hash, app name, source provenance, and consent digest.
- Installing another package with the same app name does not inherit the ID.
- Updating an existing app requires an explicit `bloom petals update <app-instance-id> <artifact>` operation and a new activation decision.
- Matching GitHub provenance is displayed as continuity evidence but is not sufficient authority to update an app instance.
- Stable storage, budgets, secret handles, jobs, and subscriptions key on app instance ID.

This prevents a package from claiming another application's durable identity while allowing local and remotely sourced apps to use the same update mechanism.

#### D2: opaque actions never receive reusable grants

An action whose effects are not host verified requires an explicit ceremony for that exact prepared action.

- The grant may authorize multiple precommitted hashes in the same prepared action.
- It expires with that action and cannot authorize a different subject, hash set, or prepared digest.
- It cannot become a standing policy grant or contribute app-claimed values to an automated host budget.
- Reusable or policy-automatic grants are available only for host-verified effects.

#### D3: remote installs are artifact-first

Production remote installation does not run repository build commands on the user's machine.

- A remote release supplies a prebuilt deterministic `.petal.tar`, a package hash, source commit, and signed release manifest.
- Bloom verifies the publisher key, release manifest, archive hash, normalized package hash, and source provenance before activation.
- GitHub organization membership alone is not a publisher signature.
- Reproducible rebuild verification happens in CI or another explicitly configured builder and is evidence attached to the release; it is not ambient code execution during install.
- `bloom petals build` remains a local developer command. It creates an artifact but does not activate it.
- Any compatibility path that executes a remote source build is development-only, disabled by default, and requires an explicit unsafe flag plus pre-build consent.

This removes the current highest-risk install behavior instead of relying on a cross-platform sandbox that is not yet designed.

Remote release manifest v1 is canonical JSON with lexicographically sorted object keys and no insignificant whitespace:

```json
{
  "schema": "bloom.petal.release.v1",
  "app_name": "example",
  "source_repository": "https://github.com/bloom-directory/example",
  "source_commit": "<40-hex-commit>",
  "source_tag": "v1.2.3",
  "artifact_url": "https://github.com/.../example.petal.tar",
  "artifact_blake3": "<64-lowercase-hex>",
  "package_hash": "<64-lowercase-hex>",
  "publisher_key": "ed25519:<hex>",
  "build_attestation_url": "https://.../provenance.json"
}
```

The detached Ed25519 signature covers `bloom.petal.release.v1\0 || canonical_json`. Trusted publisher keys come from explicit local configuration or a separately authenticated marketplace record, never from the downloaded manifest itself. The artifact URL must be HTTPS and match an allowed release-host policy. Bloom verifies both raw artifact BLAKE3 and normalized package hash.

#### D4: installation has acquisition and activation consent

Consent has two distinct inputs:

1. **Acquisition/build consent:** source identity, requested ref, resolved commit, publisher signature status, build provenance, and manifest-declared maximum capability ceilings. This is required before any optional local build.
2. **Activation consent:** computed only from the fully built, normalized, ABI-validated package and composed route artifacts. It shows actual imports, routes, jobs, metadata, policies, secrets, and capability ceilings.

Activation authority comes from the second consent. Manifest ceilings are upper bounds, not proof of actual imports. A build whose imports exceed its manifest ceiling fails validation; a build narrower than the ceiling displays the narrower effective activation request.

## 2. Goals

1. Enable Polymarket to reach functional and approval-semantic parity without a venue-specific daemon interface.
2. Enable Hyperliquid public reads and bounded agent sessions without guest-visible private keys or native venue code.
3. Enable safe general-purpose paid HTTP and x402/MPP requests to user-selected hosts.
4. Enable DeFi workflows with dependent transaction batches and settlement jobs.
5. Enable Petal-owned durable monitors and event-driven applications.
6. Enable richer chain and simulation applications without exposing raw daemon RPC credentials.
7. Preserve exact package, route, action, and signing provenance in every privileged operation.
8. Preserve compatibility with existing `bloom:route@0.1.0` applications.
9. Make every new authority visible in package consent and runtime audit records.
10. Fail closed when a host service, validator, policy evaluator, secret, or scheduler is unavailable.

## 3. Non-goals

- Moving keystore or passkey implementation into Wasm.
- Giving Petals raw private keys, wallet unlock handles, or unrestricted signing.
- Arbitrary JSON-RPC forwarding under the ordinary chain-read capability.
- Unrestricted sockets, filesystem access, process spawning, or general WASI.
- Allowing an untrusted Petal to self-certify policy facts.
- Allowing jobs to survive package replacement without an explicit activation decision.
- Allowing one Petal to call another Petal through the VFS without declared dependency mediation.
- Replacing IPC, NFS/FUSE mounting, or daemon supervision with Petals.
- Requiring immediate migration of every existing native surface.

## 4. Security model

### 4.1 Principals

The platform recognizes these principals:

- **User/owner:** authorizes package installation and privileged actions.
- **Installed package:** identified by content hash.
- **App identity:** stable declared app name plus publisher/source provenance.
- **Route identity:** package hash, route ID, operation, and resolved path binding.
- **Job identity:** package hash, declared job ID, and job-generation number.
- **Host kernel:** trusted daemon services.
- **Remote service:** HTTP, RPC, venue, merchant, or indexer endpoint.

### 4.2 Trust rules

1. Package and route identity MUST come from the installed route index, never component input.
2. A Petal-provided plan, effect, label, or policy fact is an untrusted claim unless a native verifier confirms it.
3. Automated policy approval MUST apply only to host-verifiable effects.
4. Opaque or unverified actions MAY be explicitly owner-approved, but MUST be labelled as app-provided and MUST NOT consume an automated standing policy grant.
5. Signing MUST be restricted to hashes committed into a prepared action before approval.
6. A job MUST run with no more authority than the package version and job declaration approved at activation.
7. Secret handles MUST be scoped to an app identity, purpose, and allowed operation; handles MUST NOT reveal secret bytes unless explicitly created as exportable.
8. Package updates MUST NOT inherit secrets, jobs, grants, or stable data merely because they reuse the same app name.
9. Cross-package and cross-route transaction access MUST remain denied by default.
10. Every host operation MUST be auditable without logging secret values or raw credentials.

## 5. Platform hardening prerequisite

No additional privileged capability SHOULD ship before Phase 0 is complete.

| Item | Decision/default | Primary code ownership | Acceptance criteria |
| --- | --- | --- | --- |
| Remote source execution | Production remote installs are prebuilt-artifact-only per D3. Legacy source execution is disabled unless an unsafe development flag is present. | `crates/bloom/src/github_source.rs`, `crates/bloom/src/main.rs` | Installing a GitHub URL never invokes `Command` in the default build; tests use a canary executable and verify it is not run. |
| Two-stage consent | Acquisition/build ceiling before optional local build; final activation consent after composition and ABI validation. No package is mounted before activation confirmation. | `crates/bloom/src/main.rs`, `crates/bloom/src/github_source.rs`, `crates/bloom-petals/src/package.rs`, `crates/bloom-petals/src/store.rs` | Declining either stage leaves package store, activation records, mounts, jobs, and secrets unchanged. Final consent reflects actual composed imports. |
| Route consent metadata | Parse and preserve `description` and `consent-summary`, tag both as app-provided, and include them in activation output. | canonical `bloom-directory/petal` route WIT, `crates/bloom-petals/src/vm.rs`, `crates/bloom-petals/src/package.rs` | Component metadata round-trips into route index/consent; control and bidi characters are rejected or escaped. |
| Installed integrity | Verify route-index/package binding and artifact hash before first dispatch; cache successful verification by immutable file identity and invalidate on metadata change. | `crates/bloom-petals/src/store.rs`, `crates/bloom-petals/src/runner.rs` | Modifying source, route index, or artifact after install prevents dispatch under the old package identity. |
| Ingestion limits | Apply the concrete defaults in Section 21 before `read_to_end`, component parsing, or composition. | `crates/bloom-petals/src/package.rs`, `crates/bloom-petals/src/store.rs` | Oversized directory and tar inputs fail before unbounded allocation; boundary tests cover every limit. |
| Component deadline | Wasmtime epoch interruption; default route deadline 10 seconds, metadata deadline 2 seconds, configurable downward per runtime and upward only by daemon config. Expiry returns typed `timeout`, traps the instance, and records fuel/elapsed time. | `crates/bloom-petals/src/vm.rs`, `crates/bloom-petals/src/runner.rs` | A spinning component and a component blocked in a cancellable host call terminate within deadline plus 250 ms scheduling tolerance. |
| Filesystem hardening | Petal data directories mode `0700`; no-follow/beneath-root traversal; randomized create-new temporary files; equivalent owner ACL on supported non-Unix platforms. | `crates/bloom-petals/src/private_store.rs`, `crates/bloom-petals/src/store.rs` | Pre-planted symlinks and temp-name collisions cannot redirect or weaken private/secret writes. |
| Single metadata snapshot | Evaluate dynamic metadata exactly once and pass the immutable result into async/sync dispatch. | `crates/bloom-petals/src/router.rs`, `crates/bloom-petals/src/runner.rs` | A nondeterministic metadata component cannot cause routing and execution to observe different mode/async/capability values. |
| HTTP SSRF hardening | Apply post-resolution IP classification and connection address pinning to static manifest rules and dynamic grants, including every redirect. Private/special ranges require an explicit rule flag and high-risk consent. | `crates/bloom-petals/src/policy.rs`, `crates/bloom-daemon/src/lib.rs` | Static and dynamic allowed hostnames that resolve/rebind to loopback, link-local, private, multicast, or unspecified addresses are denied unless explicitly authorized. |

### 5.1 Activation ordering

The install sequence is:

```text
acquire and authenticate artifact
  -> parse manifest ceiling
  -> optional acquisition/build consent
  -> normalize, compose, and validate package
  -> calculate actual activation request
  -> render final activation consent
  -> user/automation authorization
  -> write package and activation record atomically
  -> enable mount, jobs, secrets, and providers
```

Package bytes MAY be placed in a quarantine/cache before activation, but they MUST NOT appear in `petal_mounts`, receive stable app storage, start jobs, or use secret handles until the activation transaction commits.

## 6. Capability taxonomy

Capabilities are split into risk classes for consent and policy:

### Class R0: pure/local

- environment time/randomness
- app-local non-secret storage
- pure computation

### Class R1: read-only external

- static-host HTTP GET/HEAD
- chain basics and contract calls
- public wallet information
- system information

### Class R2: sensitive read/write

- secret-store use
- credential injection
- scoped VFS reads of wallet, status, outbox, request, or other sensitive mounts
- dynamic-host network grants
- durable jobs
- event subscriptions

### Class R3: authority/value movement

- owner signing
- delegated signing keys
- transaction staging/confirmation
- VFS writes
- unscoped/root VFS access during the compatibility period
- standing automated policy grants
- service-provider registration

Install consent MUST group requested authority by risk class and MUST separately identify persistent/background authority.

### 6.1 Shared host error taxonomy

All new WIT interfaces import `bloom:errors/types@0.1.0` and return a typed host error. Existing interfaces returning strings remain compatible but are not copied as precedent.

```wit
package bloom:errors@0.1.0;

interface types {
  enum error-code {
    invalid-input,
    denied,
    not-found,
    conflict,
    approval-required,
    expired,
    stale,
    unavailable,
    timeout,
    rate-limited,
    resource-limit,
    integrity,
    internal,
  }

  record host-error {
    code: error-code,
    message: string,
    retry-after-ms: option<u64>,
    action-id: option<string>,
  }
}
```

Rules:

1. `message` is diagnostic and MUST NOT be parsed for control flow.
2. Approval-capable methods SHOULD use a structured success variant for approval-required state; `approval-required` error exists for interfaces where such a variant cannot be represented compatibly.
3. `denied` is non-retryable without a policy/authority change.
4. `unavailable`, `timeout`, and `rate-limited` MAY carry `retry-after-ms`.
5. `conflict` identifies idempotency, concurrent transition, or optimistic-lock conflicts.
6. `integrity` fails closed and indicates corrupted or mismatched persisted state.
7. Internal error messages are redacted at trust boundaries and never contain secret values.
8. Host error codes map consistently to logs, audit records, VFS `HandlerError`, and SDK exceptions.

## 7. Semantic prepared actions

### 7.1 Motivation

`bloom:sign@0.1.0` accepts `(wallet, hash32, intent)`. This is sufficient cryptographically but insufficient for:

- one approval covering multiple stable hashes
- binding amount, asset, payee, venue, or order facts
- enforcing host policy against those effects
- distinguishing verified facts from app claims
- stable retry after an approval ceremony

### 7.2 New package

Add `bloom:auth/actions@0.1.0`.

Illustrative WIT:

```wit
package bloom:auth@0.1.0;

interface actions {
  enum effect-confidence {
    app-claimed,
    host-verified,
  }

  record effect {
    kind: string,
    schema: string,
    body-json: string,
  }

  record signing-hash {
    intent: string,
    hash32: list<u8>,
    label: string,
  }

  record prepared-action {
    wallet: string,
    network: string,
    action-kind: string,
    subject-schema: string,
    subject: list<u8>,
    plan-md: string,
    effects: list<effect>,
    signing-hashes: list<signing-hash>,
    requested-ttl-secs: u64,
  }

  record approval-required {
    action-id: string,
    ceremony-url: string,
    expires-ms: u64,
  }

  record prepared-handle {
    action-id: string,
    prepared-digest: string,
    effect-confidence: effect-confidence,
    approval: option<approval-required>,
  }

  variant sign-result {
    signature(list<u8>),
    approval-required(approval-required),
  }

  prepare: func(action: prepared-action) -> result<prepared-handle, string>;
  sign: func(action-id: string, hash-index: u32) -> result<sign-result, string>;
  status: func(action-id: string) -> result<string, string>;
  cancel: func(action-id: string) -> result<_, string>;
}
```

The final WIT MAY differ, but it MUST preserve the following invariants.

### 7.3 Required invariants

1. The host injects app/package/route provenance.
2. `prepared-digest` commits to every subject byte, effect, signing hash, plan, and requested term.
3. `sign` accepts an index only; it cannot accept a new hash after preparation.
4. A changed hash, subject, effect, or plan requires a new action ID and approval.
5. The host caps TTL and signature count independent of the component request.
6. The host records which hashes have been consumed and enforces exactly-once or bounded-use semantics.
7. The component cannot select Petal identity, executor kind, approval assurance, or grant ID.
8. The approval UI identifies app-claimed fields distinctly from host-verified fields.

### 7.4 Persistence and state machine

Prepared actions are durable daemon records stored in the existing auth SQLite database, not files controlled by the Petal.

Minimum tables:

```text
prepared_actions(
  action_id primary key,
  app_instance_id,
  package_hash,
  route_id,
  operation,
  path,
  prepared_digest unique,
  subject_schema,
  subject_bytes,
  plan_md,
  effect_confidence,
  requested_ttl_secs,
  expires_ms,
  state,
  approval_id nullable,
  created_ms,
  updated_ms
)

prepared_hashes(
  action_id,
  hash_index,
  intent,
  hash32,
  label,
  state,
  attempt_id nullable,
  signature nullable,
  updated_ms,
  primary key(action_id, hash_index)
)
```

Action states:

```text
prepared -> awaiting-approval -> active -> consumed
    |              |              |
    +----------> cancelled <------+
    +----------> expired
    +----------> failed
```

Hash states:

```text
available -> signing -> signed
    |           |
    +------> cancelled
```

All state transitions use SQLite transactions and compare-and-set predicates.

### 7.5 Concurrent signing and restart behavior

1. `sign(action-id, hash-index)` first validates active approval and atomically changes the hash from `available` to `signing` with a random attempt ID.
2. A concurrent caller observing `signing` receives typed `conflict` with a short retry hint; it does not invoke the signer.
3. After signing, the daemon stores the public signature and changes the state to `signed` in one transaction.
4. Repeated calls for a `signed` hash return the stored signature without consuming another grant use.
5. A crash after reservation but before signing leaves a stale `signing` row. Startup recovery changes attempts older than 30 seconds back to `available` only after reconciling grant consumption.
6. A crash after the key operation but before signature persistence may repeat signing of the same precommitted hash. This is permitted because it does not widen authority; grant/budget consumption remains idempotent by `(action-id, hash-index)`.
7. Signature bytes are public cryptographic output but remain internal to the auth database and are never exposed through VFS artifacts unless the Petal itself writes them.
8. Action expiry is checked at reservation and completion. An expired action cannot begin a new signature, but an already persisted `signed` result remains readable for stable retry.

### 7.6 Ceremony interaction sequence

```text
Petal route              Bloom daemon/auth DB              User ceremony
    | prepare(action)             |                              |
    |---------------------------->| persist prepared             |
    |<----------------------------| approval-required(URL)       |
    |                             |<---------- open/approve -----|
    | poll status or retry sign   | verify approval, activate    |
    |---------------------------->|                              |
    | sign(action, index)         | CAS available -> signing     |
    |---------------------------->| invoke keystore, persist     |
    |<----------------------------| signature                    |
```

The daemon does not require a component to open a browser. The foreground CLI MAY open the returned ceremony URL as a convenience. Components either poll `status` with bounded backoff or retry `sign`; both survive daemon restart because action state is durable.

### 7.7 Effect verification

Effects are divided into:

- **Host-verifiable standard effects:** ordinary EVM transfer/call, ERC-20 transfer/approval, known transaction batch, and other bytes the host can decode and compare.
- **Registered protocol effects:** a native, versioned verifier maps a subject schema and prepared bytes to facts. Registration is part of the kernel or a separately trusted provider mechanism.
- **Opaque app claims:** no trusted verifier exists.

Automated policy grants MUST NOT authorize opaque app claims. They require an explicit owner ceremony showing:

- package/source identity
- route and path
- raw signing hashes
- subject digest
- app-provided plan and effects
- a warning that protocol semantics are not host verified

This avoids pretending a generic schema string is a security boundary.

### 7.8 Compatibility

`bloom:sign@0.1.0` remains supported. `bloom:auth/actions@0.1.0` is additive. Applications requiring semantic actions use the new interface.

## 8. Secret and delegated-key vault

### 8.1 Motivation

The current secret KV protects files by namespace and Unix mode, but guest code still handles raw values. Long-lived API keys and delegated venue keys require stronger isolation.

### 8.2 New packages

Add:

- `bloom:secrets/vault@0.1.0`
- `bloom:keys/delegated@0.1.0`

### 8.3 Secret vault operations

Required operations:

- provision a secret through a trusted CLI/ceremony path
- enumerate metadata without reading values
- rotate and revoke
- bind a secret to allowed hostnames, header names, query parameters, or signing purposes
- inject a secret into a host HTTP request without returning it to the component
- optionally derive HMAC/signature output under a declared algorithm

Secret metadata includes:

- opaque handle
- app identity
- purpose
- creation and rotation time
- allowed destinations and operations
- exportability flag
- expiry

Raw secret reads MUST be denied for non-exportable secrets.

### 8.4 HTTP integration

Version HTTP with credential references:

```wit
variant header-value {
  literal(string),
  secret-ref(string),
}
```

The host validates that the referenced secret permits the target host and header name. Audit records contain the handle and destination but never the value.

### 8.5 Delegated signing keys

The delegated-key interface supports:

- create secp256k1 key
- return public address and opaque key handle
- sign an exact hash under a declared venue/purpose policy
- usage counter and expiry
- rotate and revoke
- optional host-side rate and bounds enforcement

The private key MUST never enter guest linear memory.

Hyperliquid agent sessions are the first target consumer.

## 9. Stable application storage and upgrades

### 9.1 Problem

Current private KV is partitioned by package hash. An update therefore receives a new partition, which is unsuitable for durable credentials, channel state, user settings, and monitors.

### 9.2 Storage classes

Introduce:

- **version storage:** current package-hash storage; isolated and immutable across versions
- **app storage:** stable app identity storage, available only after activation approval
- **vault storage:** host-managed secret handles; never represented as raw KV

### 9.3 Activation record

The daemon persists an app activation record:

- stable app ID
- current package hash
- source provenance
- previous package hash
- approved capability/policy digest
- app-storage schema version
- active jobs
- granted secret handles
- activation time

App name alone is not sufficient identity. Publisher/source provenance and an explicit update relationship are required.

### 9.4 Migration

A package MAY declare a migration component implementing a dedicated migration world.

Migration rules:

1. Old and new package hashes are both supplied by the host.
2. Migration gets read-only access to old app data and write access to a fresh new schema transaction.
3. Secrets are transferred as handles only if the user approves the new package's requested uses.
4. Jobs remain disabled until migration and activation commit.
5. Migration is atomic: success activates the new schema; failure leaves the old package active.
6. Rollback rules are declared before activation.

### 9.5 Transactional storage design

Stable app storage does not reuse the current file-per-key `PrivateStore`. Add `AppStore`, backed by one owner-only SQLite database per app instance:

```text
~/.bloom/petals/petals/<app-instance-id>/data.sqlite
```

Minimum schema:

```text
kv(namespace, key, value, revision, updated_ms,
   primary key(namespace, key))
meta(schema_version, active_package_hash, generation)
```

All app-store APIs preserve namespace policy and provide transactional implementations of get, put, put-new, list, delete, and compare-and-delete. Vault secrets remain handles and are not stored in this database.

Migration uses a shadow database:

1. Acquire the app activation/migration lock.
2. Snapshot the current database using SQLite backup into `data.migration-<generation>.sqlite`.
3. Run the migration against the shadow database only.
4. Enforce output quota and schema-version monotonicity.
5. `fsync` the shadow database and containing directory.
6. Commit the activation record and database generation through a small journal record.
7. Atomically replace the active database pointer/file.
8. Retain the previous generation until activation health checks pass or rollback TTL expires.

Startup reads the journal and deterministically completes or rolls back an interrupted swap. Routes never observe a partially migrated database. The old package remains active until the activation and storage-generation commit is complete.

Primary ownership:

- new `crates/bloom-petals/src/app_store.rs`
- activation/migration orchestration in `crates/bloom-petals/src/store.rs` or a new `activation.rs`
- VM adapters in `crates/bloom-petals/src/vm.rs`

## 10. Durable jobs and lifecycle

### 10.1 Motivation

Hyperliquid monitors, watches, settlement tracking, and MPP channels require execution outside a VFS request.

### 10.2 Package layout

Add an optional `jobs/` tree and generated job index:

```text
jobs/
  risk-monitor.wasm
  settlement-monitor.wasm
```

Job components implement `bloom:job@0.1.0`, separate from route components.

Illustrative world:

```wit
package bloom:job@0.1.0;

interface types {
  record context {
    app-id: string,
    package-hash: string,
    job-id: string,
    invocation-id: string,
    scheduled-ms: u64,
    attempt: u32,
    checkpoint: option<list<u8>>,
  }

  variant outcome {
    complete(option<list<u8>>),
    retry-after(tuple<u64, option<list<u8>>>),
    disable(string),
  }
}

world handler {
  use types.{context, outcome};
  export run: func(ctx: context) -> result<outcome, string>;
}
```

### 10.3 Scheduler interface

Routes can create, update, inspect, and cancel jobs through `bloom:jobs/control@0.1.0`.

Schedules initially support:

- one-shot timestamp
- fixed interval with a host minimum
- event-triggered invocation

Every time schedule declares a misfire policy:

- `skip`: discard occurrences missed while the daemon was stopped/asleep
- `latest`: run one invocation for the latest missed occurrence
- `catch-up`: run up to a declared bounded count in chronological order

The default is `latest`. `catch-up` is capped at 10 invocations per wake and is not available to sub-minute schedules.

Cron syntax is deferred.

### 10.4 Job invariants

1. Jobs are persisted by the host, not `tokio::spawn` in guest execution.
2. Job authority is fixed at creation and cannot exceed package consent.
3. Jobs identify a specific package hash and job artifact hash.
4. Package replacement disables old jobs until explicit transfer/activation.
5. At most one invocation of a job ID runs concurrently unless declared otherwise and approved.
6. Each invocation has fuel, memory, host-call, output, and wall-clock limits.
7. Retry uses bounded exponential backoff with jitter and a maximum failure count.
8. Checkpoints have a strict size limit and are committed only with successful outcomes.
9. Every invocation and host side effect is audited.
10. The daemon can globally suspend a package's jobs.
11. Job invocations receive a host-generated idempotency scope containing job ID, scheduled occurrence, and event ID where applicable.
12. Side-effecting host interfaces reject job-origin calls that omit an operation key inside that scope.

### 10.5 Laptop scheduling and fairness

The scheduler assumes laptops sleep, clocks jump, networks disappear, and the daemon is not continuously available.

- Time schedules use wall-clock occurrence IDs but monotonic time while the daemon is running.
- On startup/wake, the scheduler applies each job's misfire policy before placing work on the queue.
- Clock regression does not repeat an already completed occurrence ID.
- Default daemon-wide concurrency is 4 job invocations.
- Default per-app concurrency is 1.
- Priority order is: kernel safety cleanup, approved expiry/revocation cleanup, user-triggered jobs, event jobs, interval maintenance.
- User packages cannot request kernel priority.
- Queue aging prevents a continuously busy higher application from starving other applications in the same non-kernel class.
- A package receives a default CPU/fuel duty-cycle budget of 30 seconds of wall time per rolling 10 minutes across background jobs; exhaustion delays non-safety work and is visible in status.
- Network-unavailable failures use backoff and do not consume catch-up slots indefinitely.

### 10.6 Lifecycle hooks

Optional hooks:

- `on-activate`
- `on-deactivate`
- `on-upgrade`

Hooks are bounded jobs. They are not allowed to sign or move value unless separately approved.

## 11. Event subscriptions

Add `bloom:events/subscriptions@0.1.0` for host-managed sources:

- new block
- matching log
- transaction receipt/state transition
- outbox state transition
- fixed interval
- HTTP webhook, deferred until authenticated ingress design exists

The first implementation SHOULD reuse the native watch executor's cursor, reconnect, polling fallback, and history machinery.

Subscriptions deliver events by scheduling a job invocation, not by maintaining a guest WebSocket.

Required properties:

- persistent subscription spec
- cursor/checkpoint
- at-least-once delivery
- stable event ID for deduplication
- bounded backlog
- reorg metadata for chain events
- explicit disabled/degraded state
- package and job provenance

At-least-once delivery means guest code may observe the same event more than once. The host event ID is stable. A side-effecting job MUST use that ID through the workflow/action/HTTP idempotency mechanisms; guest-only state uses `store.put-new` or compare-and-delete. Tests assert idempotent host admission, not an impossible global exactly-once guarantee against arbitrary remote services.

Mempool subscriptions are a separate, higher-risk capability and are deferred until block/log subscriptions are stable.

## 12. Typed wallet and system reads

Add narrow read-only interfaces so applications do not require broad VFS access for basic system facts.

### 12.1 Wallet information

`bloom:wallet/info@0.1.0`:

- list public wallet summaries, subject to consent
- resolve wallet name to address
- get wallet kind
- get public policy digest and selected app-visible policy sections
- resolve default wallet
- report whether signing/transaction authority is available

No private key, unlock state, passphrase, PRF output, or raw policy signature is exposed.

### 12.2 Chain registry

`bloom:chain/registry@0.1.0`:

- list configured chain names and IDs
- resolve name/ID
- report capabilities such as subscriptions, tracing, and private submission
- expose redacted endpoint identity only

### 12.3 Address book

`bloom:addressbook/read@0.1.0`:

- resolve alias to address
- classify an address
- reverse resolve an address to alias

Writes remain a separate capability.

### 12.4 System information

`bloom:system/info@0.1.0` exposes selected non-secret health and version facts. Detailed endpoint health, audit internals, and backend credentials remain native-only unless explicitly consented.

## 13. Expanded chain interfaces

Do not replace the existing narrow interface with arbitrary JSON-RPC. Add typed, separately consented interfaces.

### 13.1 Chain basics

`bloom:chain/basics@0.2.0`:

- chain ID
- latest block number/header
- balance
- account nonce
- code
- storage slot
- transaction
- receipt
- logs with bounded range and result count
- contract call at latest or explicitly bounded recent block

### 13.2 Gas and fees

`bloom:chain/fees@0.1.0`:

- gas estimate
- fee history
- suggested EIP-1559 fees

### 13.3 Simulation

`bloom:chain/simulate@0.1.0`:

- typed transaction request
- optional bounded state overrides
- return data
- gas estimate
- decoded revert when available
- optional trace summary

Full raw `debug_traceCall` output is a separate high-risk capability with strict output and time limits.

### 13.4 Endpoint credentials

Components select a configured chain by logical name. RPC URLs and API keys remain in the host. Applications MUST NOT need raw endpoint URLs for ordinary chain operations.

## 14. Transaction workflow API

### 14.1 Motivation

The current outbox stages one transaction at a time and cannot encode approval → swap, multi-call onboarding, or cross-chain dependencies.

### 14.2 New version

Add `bloom:tx/workflow@0.1.0` while preserving `bloom:tx/outbox@0.1.0`.

Required model:

```text
workflow
  id
  wallet
  app/route origin
  plan
  steps[]
  dependency edges[]
  expected effects[]
```

Each EVM step includes current transaction fields plus optional:

- token/NFT semantic hint
- expected balance delta
- dependency policy: staged, sent, mined, or success
- private-submission preference
- confirmation mode
- caller idempotency key

### 14.3 Operations

- prepare workflow
- stage all eligible steps
- confirm eligible step
- cancel unbroadcast steps
- inspect workflow and steps
- wait/register event for state transition

### 14.4 Invariants

1. Dependency edges are persisted and enforced by `TxEngine`.
2. A step cannot confirm before its dependency condition is met.
3. Transaction bytes are read from persisted host state at confirm time.
4. Workflow identity is origin-bound.
5. Host-verified EVM effects feed wallet policy.
6. Petal semantic hints are labelled claims unless derived from decoded transaction bytes.
7. Confirmation and warning acknowledgement remain host policy decisions.

### 14.5 Persistence, idempotency, and crash recovery

Workflows and steps are persisted in the existing outbox storage plus a workflow index before any external side effect.

The effective idempotency identity is:

```text
(app-instance-id, package-origin, workflow-idempotency-key, step-key)
```

Rules:

1. Preparing the same effective key with byte-identical workflow/step content returns the existing workflow and step IDs.
2. Reusing a key with different content returns typed `conflict` and never mutates the existing workflow.
3. Transaction staging persists the exact request, effect digest, dependency set, and central outbox projection before returning.
4. Confirmation always reads transaction bytes from persisted state.
5. Broadcast state transitions use the existing outbox transaction hash and receipt reconciliation; restart resumes from persisted state rather than restaging.
6. A job invocation that stages a workflow MUST provide an idempotency key derived from its job ID and event ID. The host rejects job-origin transaction staging without one.
7. The same rule applies to prepared actions and dynamically authorized HTTP requests that can create external side effects.
8. Exactly-once external delivery is not promised. Bloom promises idempotent host admission and at-most-one logical workflow per effective key. Remote protocols without idempotency support remain at-least-once risks and must be identified in consent/plan output.

Recovery scan at daemon startup:

- validates workflow index against step/outbox entries
- restores eligible dependency transitions
- resumes receipt reconciliation for broadcast steps
- marks irreconcilable partial records `failed-integrity`
- never automatically rebroadcasts a transaction whose submission outcome is unknown without applying the existing tx-hash/nonce reconciliation rules

## 15. Dynamic network grants

### 15.1 Motivation

Static manifest network policy is appropriate for venue integrations but cannot implement a general `/requests` client that accepts arbitrary user destinations.

### 15.2 Design

Add `bloom:http/authorized@0.1.0`.

A route prepares a request authorization containing:

- scheme, host, and port
- method and path
- redirect policy
- selected headers or header classes
- request-body digest and maximum size
- response-size limit
- request count
- expiry
- payment/credential purpose, if any

The host returns a request handle after policy or explicit user approval. Execution uses the handle and exact prepared request fields.

### 15.3 Rules

1. Dynamic grants are exact-target and short-lived.
2. Redirects require either same-origin conformance or a separately approved target.
3. Secret header injection is permitted only through vault handles authorized for the target.
4. The host enforces DNS/IP policy after resolution and SHOULD block loopback, link-local, and private ranges unless explicitly approved.
5. Request bodies and sensitive headers are never copied into audit logs.
6. A paid HTTP action binds the HTTP request digest and payment requirement into the same semantic action.

WebSocket and SSE are separate future capabilities.

### 15.4 Scoped VFS policy and deprecation

The unscoped `bloom:vfs/readwrite@0.1.0` interface is deprecated. Existing packages continue to run, but new packages MUST use split, scoped interfaces:

- `bloom:vfs/read@0.2.0`
- `bloom:vfs/write@0.2.0`

The manifest declares normalized path-prefix ceilings:

```toml
[vfs]
read = ["chains/polygon/", "wallets/*/address", "status/version"]
write = ["watch/new", "watch/*/delete"]
```

Rules:

1. Paths are parsed and normalized as `VfsPath` before matching.
2. `.`/`..`, alternate separators, NULs, symlink escapes, and ambiguous encodings are rejected before policy evaluation.
3. Read and write are independent imports and independent consent items.
4. Runtime masks intersect manifest prefixes and can only narrow them.
5. `/petals` remains denied; typed cross-app calls require the separate dependency model.
6. Keystore-private files, approval/grant internals, raw audit storage, Petal data roots, and daemon control files are permanently non-addressable through Petal VFS.
7. A root prefix or wildcard spanning multiple mounts is Class R3 and requires explicit high-risk consent. It is not eligible for unattended installation policy.
8. Typed host interfaces take precedence. New first-party Petals MUST NOT request VFS access for facts available through wallet, chain, address-book, outbox, or system interfaces.
9. Compatibility packages importing `readwrite@0.1.0` are displayed as broad R3 authority and cannot gain new jobs, stable storage, or reusable grants until migrated.

Implementation ownership:

- manifest/schema and consent: `crates/bloom-petals/src/package.rs`
- policy parsing/intersection: `crates/bloom-petals/src/policy.rs`
- VM enforcement: `crates/bloom-petals/src/vm.rs`
- final path enforcement and `/petals` denial: `crates/bloom-petals/src/runner.rs`

Acceptance requires tests proving that allowed siblings, dynamic path segments, symlinks, and prefix-confusion strings cannot cross a declared boundary.

## 16. Policy and budget integration

### 16.1 Host-enforced policy

Wallet policy remains native. Petals can read approved public projections but cannot declare their own policy result authoritative.

### 16.2 Standard effect taxonomy

Define generic, versioned effects where the host can validate bytes:

- native transfer
- ERC-20 transfer
- ERC-20 approval
- NFT transfer/approval
- contract call
- EVM transaction workflow
- HTTP payment with exact request/payment binding
- delegated-key creation
- standing job authority

Venue concepts such as “Polymarket BUY order” or “Hyperliquid reduce-only close” may be app claims until a trusted verifier exists. The system must be honest about that distinction.

### 16.3 Budgets

Budget counters are native and keyed by:

- wallet
- verified effect class
- asset/network where applicable
- app identity
- rolling/window period

An app-local KV counter MUST NOT substitute for a host budget when automated authorization depends on it.

## 17. Provider contracts

Some native functionality is consumed as a service rather than only exposed as VFS files. Examples include prices, address resolution, contract metadata, and policy evaluation.

Provider registration is deferred until application capabilities above are stable, but the target contract is:

- manifest declares a typed provider interface/version
- user explicitly activates one provider for a role
- host health-checks it
- deterministic selection and fallback are configured
- provider calls are bounded and fail closed
- a provider cannot silently replace a security-critical native service

Initial eligible provider roles:

- price data source, not final policy oracle
- contract metadata/indexer
- address metadata
- read-only venue data

Keystore, approval verification, audit, and transaction signing are permanently ineligible.

## 18. Inter-app dependencies

The current `/petals` VFS denial prevents recursion and confused-deputy behavior. Preserve that default.

If typed cross-Petal calls are introduced, they require:

- declared package dependency and interface version
- explicit install consent
- caller identity propagation
- callee capability isolation
- cycle detection
- bounded call depth
- no implicit capability delegation
- audit records for both identities

Inter-app calls are not required for the first native-parity migrations; package-local component composition remains preferred.

## 19. Consent and activation UX

Before activation, Bloom displays:

- package/source identity and resolved commit
- route tree
- static and dynamic capability ceilings
- network rules
- dynamic-network capability, if requested
- secret handles requested or created
- delegated-key authority
- signing intents and prepared-action schemas
- transaction/workflow authority
- durable jobs, intervals, and event subscriptions
- stable storage and migration request
- provider roles

Persistent/background authority is shown separately from request-time authority.

Activation requires explicit confirmation. Automation uses an explicit `--yes` plus a machine-readable consent policy; lack of TTY is not implicit consent.

### 19.1 Machine-readable consent policy

Noninteractive activation requires both `--yes` and `--consent-policy <path>`. `--yes` alone is insufficient for packages requesting R2/R3 authority.

Initial format:

```toml
schema = "bloom.petal.consent-policy.v1"

[source]
publisher_keys = ["ed25519:<hex>"]
repositories = ["github:bloom-directory/example"]
require_signed_release = true

[authority]
max_risk_class = "R2"
allow_capabilities = ["bloom:http", "bloom:store", "bloom:chain.basics"]
deny_capabilities = ["bloom:vfs.write", "bloom:keys.delegated"]
allow_opaque_actions = false
allow_background_jobs = false

[network]
hosts = ["api.example.com"]
allow_private_ranges = false

[limits]
max_jobs = 0
max_stable_storage_bytes = 67108864
```

Evaluation is conjunctive and fail closed:

- unknown fields or schema versions are errors
- every requested authority must match an allow rule and no deny rule
- source and publisher rules are checked against verified provenance
- final composed activation facts, not manifest claims, are evaluated
- the policy file digest is stored in the activation record and audit log
- package-specific artifact hashes MAY be pinned for deployments requiring exact builds

### 19.2 Ceremony and consent presentation security

Petal-supplied Markdown, labels, descriptions, effect fields, and Unicode are untrusted presentation input.

The ceremony renderer MUST:

1. Disable raw HTML, embedded images, CSS, scripts, iframes, data URLs, and automatic link navigation.
2. Render links as escaped text plus a host-generated, visibly separated destination. External navigation requires an additional click and never inherits ceremony credentials.
3. Reject or visibly escape bidi overrides, isolates in security-critical tokens, zero-width characters, C0/C1 controls, and noncharacters.
4. Apply Unicode normalization for display while preserving and separately hashing original bytes.
5. Render host-derived wallet names, addresses, hashes, amounts, chain IDs, package IDs, and destinations in fixed-format fields outside app Markdown.
6. Show full canonical addresses/hashes; truncation may be supplementary but never the only representation.
7. Identify every app-provided value as app-provided unless host verified.
8. Cap plan Markdown at 64 KiB, labels at 128 UTF-8 bytes, and individual effect-display fields at 4 KiB.
9. Produce a plain-text fallback containing the same host-derived facts.
10. Include renderer security tests for link spoofing, homoglyphs, bidi controls, zero-width characters, misleading amount formatting, and Markdown parser differentials.

Primary ownership is `crates/bloom-daemon/src/ceremony_server.rs` and the shared rendering/escaping helpers it uses. The sealed action stores original bytes and digests; rendering sanitization never changes what was sealed.

## 20. Audit model

Add normalized audit records for:

- package activation/deactivation/upgrade
- action preparation and signature consumption
- dynamic HTTP grant and execution
- secret use, rotation, and revocation
- delegated-key creation and signing
- workflow/step state transitions
- job creation, invocation, retry, disable, and deletion
- subscription cursor and degraded state
- migration start/commit/rollback
- provider selection and failure

Audit records contain handles, digests, counts, target origins, and result metadata. They never contain secret bytes, raw credentials, passphrases, PRF outputs, or private keys.

## 21. Resource limits

These are required initial defaults, not implementer-selected magic numbers.

| Limit | Default |
| --- | ---: |
| Normalized package files | 4,096 |
| Normalized package aggregate bytes | 128 MiB |
| Individual package file | 32 MiB |
| Routes per package | 1,024 |
| Source or composed route component | 32 MiB |
| Sidecar imports per route | 64 |
| Prepared action subject | 256 KiB |
| Prepared action plan Markdown | 64 KiB |
| Effects per action | 64 |
| Signing hashes per action | 16 |
| Prepared action TTL | 5 minutes default, 30 minutes host maximum |
| Secrets per app instance | 64 |
| Delegated keys per app instance | 16 |
| Jobs per app instance | 32 |
| Subscriptions per app instance | 64 |
| Job wall deadline | 30 seconds |
| Route wall deadline | 10 seconds |
| Metadata wall deadline | 2 seconds |
| Job retries | 10 consecutive failures |
| Minimum interval | 10 seconds; 60 seconds for non-safety jobs by default |
| Job checkpoint | 256 KiB |
| Event backlog per subscription | 1,000 records or 16 MiB, whichever is first |
| Chain log block range | 10,000 blocks |
| Chain log results | 5,000 logs |
| Workflow steps | 32 |
| Workflow dependency edges | 64 |
| Dynamic HTTP request body | 4 MiB |
| Dynamic/static HTTP response body | 8 MiB |
| Requests per dynamic grant | 1 default, 16 host maximum |
| Stable app storage | 256 MiB default quota |
| Version storage | 128 MiB default quota |

The daemon configuration MAY lower any limit. Raising security-sensitive limits requires explicit operator configuration and is surfaced in status. Package manifests may request lower limits but cannot raise host limits.

Limit failures use typed `resource-limit` and include the limit name and configured value without echoing secret input.

## 22. Migration plan by feature

### 22.1 Tools, docs, ENS, and price views

First migrations because they are read-only or pure.

Required platform work:

- chain basics for ENS, if current `eth_call` is insufficient
- static HTTP and app storage already suffice for price views
- no semantic action or durable job required

Success criterion: native VFS routes can be disabled while equivalent app routes pass shared fixtures.

### 22.2 Polymarket

Required:

- prepared multi-hash actions
- stable app storage and secret handles
- wallet info
- expanded chain basics including code
- transaction workflows for funding/onboarding dependencies
- host policy integration for verifiable EVM effects

Native aliasing occurs only after route, approval, retry-stability, receipt, and policy parity tests pass.

### 22.3 DeFi

Required:

- secret injection for Enso
- wallet/address-book reads
- chain basics and simulation
- transaction workflows/dependencies
- settlement job/event support

### 22.4 Paid HTTP/x402/MPP

Required:

- dynamic HTTP grants
- semantic payment action binding
- host budget accounting
- stable storage
- secret injection
- expanded Tempo chain support
- jobs for durable channels

One-shot fixed-host payments may ship earlier under static network policy.

### 22.5 Hyperliquid

Required:

- prepared semantic actions
- delegated-key vault
- stable app storage
- durable risk monitor jobs
- wallet policy projection
- event/interval delivery
- explicit orphan/recovery contract

Public reads may migrate independently before agent sessions.

### 22.6 Watch and chain explorer

Required:

- chain basics
- event subscriptions
- durable jobs and checkpoints
- optional provider registration for metadata/indexing

Mempool subscriptions remain last due to volume and availability risk.

## 23. Implementation phases

### Phase 0: harden current platform

- make remote installation artifact-first and disable ambient source execution
- implement acquisition and final activation consent
- implement machine-readable consent-policy v1
- runtime artifact integrity verification
- package/resource limits
- Wasmtime epoch deadlines with the defaults in Section 21
- private-store filesystem hardening
- single-snapshot dynamic metadata
- static and dynamic HTTP post-resolution SSRF enforcement
- route consent metadata extraction and safe presentation

### Phase 1: stable identity and safe reads

- activation records
- stable app storage and migrations
- wallet info
- chain registry
- address-book reads
- expanded chain basics
- secret vault and HTTP secret injection

### Phase 2: semantic authority and transaction workflows

- prepared actions
- multi-hash signing
- effect confidence and verification
- native budgets
- transaction batches/dependencies
- workflow inspection/events

### Phase 3: durable execution

- job component world
- scheduler control
- lifecycle hooks
- block/log subscriptions
- checkpoint and retry model

### Phase 4: dynamic networking and paid HTTP

- per-request network grants
- DNS/IP enforcement
- paid request/payment binding
- MPP channel jobs

### Phase 5: provider contracts and native removal

- provider selection framework
- shared parity harness
- staged native-route deprecation
- rollback and emergency disable controls

## 24. Testing strategy

### 24.1 Interface conformance

- WIT shape/version fixtures
- malformed resource and nominal-type rejection
- old ABI compatibility
- unknown import fail-closed tests

### 24.2 Security invariants

- component cannot change a prepared signing hash after approval
- component cannot exceed signature count or TTL
- app claims never become host-verified without a validator
- secret handles cannot cross app identities or destinations
- old package cannot use secrets/jobs after upgrade
- job cannot widen capabilities or run old artifact after transfer
- transaction dependency cannot be bypassed
- dynamic HTTP handle cannot change host, path, method, or body digest
- subscriptions resume without cursor rollback; duplicate delivery produces the same host idempotency identity and no duplicate logical workflow/action admission

### 24.3 Failure and recovery

- daemon crash during migration, job, action preparation, and workflow staging
- RPC/WebSocket disconnect and provider regression
- package rollback
- revoked secret during job execution
- expired approval between prepare and sign
- outbox entry tampering
- event reorg and duplicate delivery

### 24.4 Cross-implementation parity

For each migrated native feature, run shared fixtures against native and Petal implementations:

- identical VFS route shape
- equivalent successful outputs
- equivalent denial outcomes
- identical prepared digests where applicable
- equivalent policy facts
- equivalent receipt/reconciliation state
- no secret exposure

The canonical harness lives in:

```text
crates/bloom-it/tests/petal_parity/
crates/bloom-it/fixtures/petal-parity/<feature>/
```

It is a Rust integration harness so it can instantiate the daemon, native handlers, Petal packages, fake auth services, and temporary Bloom homes in one process. HTTP/RPC/venue traffic is served by deterministic local mock servers from checked-in request/response fixtures; parity tests do not call live networks. Binary Wasm artifacts are built once by the fixture build script and verified by hash in test setup.

The Python devnet harness remains suitable for end-to-end smoke and live compatibility tests, but it is not the source of truth for deterministic parity or denial behavior.

## 25. Acceptance criteria

The platform expansion is complete when:

1. A Hyperliquid Petal can create a non-exportable agent key, obtain owner approval, run a durable bounded risk monitor, and clean up after restart without native Hyperliquid code.
2. A general paid HTTP Petal can request a user-selected URL through an exact dynamic egress grant and cannot exceed host payment policy or budget.
3. A DeFi Petal can stage approval → swap workflows whose dependencies are enforced by `TxEngine`.
4. A Polymarket Petal can perform onboarding, trading, cancellation, funding, redemption, and withdrawal with stable multi-hash approvals and no venue-specific daemon command.
5. A watch Petal can register block/log subscriptions with persistent cursors and at-least-once event delivery.
6. No Petal receives raw wallet keys, passkey material, RPC credentials, or non-exportable delegated keys.
7. Package upgrades transfer state, secrets, and jobs only through explicit activation and migration.
8. Every privileged and background action is attributable to app, package, route/job, action, and host policy decision.
9. Native venue handlers can be disabled without reducing security guarantees or losing recovery behavior.

## 26. Open design questions

1. Which effect schemas should the host verify in the first release beyond ordinary EVM transactions?
2. Are delegated keys scoped by venue-specific policy in the kernel, or by generic usage/rate constraints plus explicit approval?
3. How should job authority transfer across a patch update be presented and approved?
4. Should dynamic network grants ever be persisted for a host/path class, or remain single-request by default?
5. What subset of state overrides and trace information is safe for third-party Petals?
6. Which provider roles can safely become Petal-backed without creating circular dependencies or availability hazards?
7. What native/Petal dual-run period is required before removing each native route?

## 27. Immediate next work

The next design slice SHOULD be a focused specification and prototype for:

1. activation records and stable app identity
2. prepared multi-hash actions
3. secret handles with HTTP header injection
4. transaction workflows with dependency edges

Those four primitives unlock meaningful Polymarket and DeFi parity while establishing the security model needed by later Hyperliquid and paid-HTTP work.

Before implementation begins, each primitive receives a mini-spec containing:

- final WIT, importing the shared host error type
- persistence schema and state machine
- concurrency, crash, and restart behavior
- chosen resource limits
- file-level change map
- exact unit, integration, corruption, and recovery tests

Initial file-level ownership map:

| Primitive | Primary files/crates |
| --- | --- |
| Activation records/stable identity | `crates/bloom-petals/src/meta.rs`, `store.rs`, `package.rs`, new `activation.rs`; CLI flows in `crates/bloom/src/main.rs` and `github_source.rs`; daemon mount discovery in `crates/bloom-daemon/src/lib.rs` |
| Prepared actions | WIT under `wit/bloom/`; types/validation in `bloom-auth-api`; SQLite state in `bloom-auth`; host orchestration in `bloom-daemon`; VM adapter in `bloom-petals/src/vm.rs` |
| Secret injection/delegated keys | new vault implementation adjacent to `bloom-keystore`; policy and WIT adapters in `bloom-petals`; HTTP injection in `bloom-daemon`; provisioning CLI in `bloom/src/main.rs` |
| Transaction workflows | `bloom-proto/src/plan.rs`; `bloom-tx/src/outbox.rs` and `tx_engine.rs`; daemon Petal host; `bloom-petals/src/abi.rs` and `vm.rs`; canonical transaction WIT in `bloom-directory/petal` |

Phase 0 is independently implementable from Section 5 and should begin before those mini-specs are complete.
