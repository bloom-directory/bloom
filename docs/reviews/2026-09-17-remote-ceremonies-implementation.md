# Remote ceremony implementation evidence

This records the coordinated implementation of the September 17 remote ceremony
plan. It is not production deployment or a claim of public CA/passkey conformance.
The original planning and architecture documents are preserved.

## Ownership and landing order

1. [Service runtime PR 19](https://github.com/bloom-directory/bloom-service-runtime/pull/19): private Unix listeners and kernel-authenticated administrator peers.
2. [Relay PR 1](https://github.com/bloom-directory/bloom-relay/pull/1): allocation, routing, scoped control, DNS, certificate inventory and CT operations.
3. [Signer PR 58](https://github.com/bloom-directory/bloom-signer/pull/58): immutable surfaces, privileged administration, credential authority and recovery.
4. [Broker PR 73](https://github.com/bloom-directory/bloom-broker/pull/73): browser/session, two-leg orchestration, TLS/ACME and exposure reconciliation.
5. Machine: CLI/VFS projections, installer integration and compatibility pins.

Merge in that order and repin each dependent repository to the merged full commit
before landing it. Review branches use full published Git revisions, not mutable
branches or committed sibling-path overrides.

## Resolved contracts

Machine–Broker is exactly API 1.7; Broker–Signer is exactly API 1.6. The release
state current version and downgrade floor are 2. Legacy localhost credential
wraps, handles and signed receipt bytes remain unchanged. New contributions bind
an immutable surface and credential-authority generation. The surface digest is
SHA-256 over `bloom.surface.identity.v1\0` followed by JCS descriptor bytes.

Localhost remains active. Hosted relay is the desired default. Before assignment,
local operation remains available with explicit incomplete setup; once assigned,
a degraded remote default fails instead of silently selecting another surface.
Only privileged Signer administration changes desired exposure. Effective state
requires Broker reconciliation at that desired revision.

Remote capability exchange is single-use, with five-minute precommit sessions.
Paired enrollment has a ten-minute absolute deadline, requires source authority
bound to the destination key and both origins, then a fresh destination assertion.
Recovery rotates the factor and revokes prior wallet credentials atomically.
Sensitive committed results have a fifteen-minute retrieval window bound to the
original browser key; losing that key does not permit re-encryption.

## Reuse and custom code

Existing typed ceremony APIs, SQLite transactions, signed audit, HPKE, WebAuthn,
JCS and Machine public projections remain the owning implementations. Relay uses
rustls ClientHello parsing, h2 transport, maintained SQL/DNS/Route 53 clients and
standard HTTP. Broker uses instant-acme for ACME. No TLS, HTTP/2, signature or
ACME implementation was written from scratch.

Custom code expresses Bloom-specific surface/revision checks, pairing bindings,
scoped credential lifecycle, durable publication and reconciliation. The narrow
Signer memory bridge allocates separate page-aligned locked mappings because
ordinary heap allocations can share pages; it wipes before unlock/unmap. The
installer wrapper supplies fixed paths and closed operation tokens to the existing
Signer administrator client. It does not add Machine-to-Signer authority.

## Evidence and limitations

| Boundary | Recorded evidence |
| --- | --- |
| Shared transport | 75 runtime tests; strict Clippy and formatting. PR CI passed workspace, Linux UID isolation and macOS listener checks. |
| Signer | All-features workspace: 284 passed, one ignored. Existing isolated-origin harness suite: 180 passed, one ignored. Cargo-deny advisories, bans, licenses and sources passed. |
| Relay borrower revision | 19 integration tests passed at `329b955454db23813e24b0947142c0398bed4b00`, with disposable PostgreSQL and actual opaque TLS tunneling. Server-only delivery follow-up is recorded separately. |
| Machine projections | Final locked workspace: 1,669 passed, one ignored across 64 suites; strict all-target Clippy and the full-commit compatibility gate passed. CLI/VFS selections and status forwarding have focused coverage. |
| Existing integrations | 38 passed across 14 non-release integration binaries; three local Solana-validator tests ignored because that validator was not running. |
| Broker | 303 passed at `6f4d18713ee6b9b1dbb3cf14b1821e74cc448256`; exact-pin workspace check and strict Clippy passed. Three canonical listener tests require an isolated host. Five material tests cover TLS validation, atomic rotation and account-loss refusal. |
| Browser wire | Four Node-executed browser tests passed, including both PRF legs decrypted by native Signer HPKE, pairing substitutions, forced adjacent assertion, scoped reload and recovery landing. This is not a real authenticator matrix. |
| Packaging | Seven Linux packaging tests, twelve macOS release tests and staged macOS installer lifecycle passed. Supplemental Linux container execution passed 48 unchanged release tests, including signed bundle verification and rollback. |
| Real installed triad | Local execution is blocked by the existing installed Broker occupying canonical port 18734. Installed services were left running. An isolated runner is required. |

Frozen-ref release builds and both macOS conformance runs must be recorded
against the final review revisions. The supplemental Linux test
workspace is not a substitute for the full Linux release build.
Cross-repository GitHub validation currently cannot fetch the private relay
repository. A read-only CI credential must be configured for dependent builds;
repository visibility is not changed as a workaround.

## Deployment prerequisites

No deployment, DNS mutation, real wallet ceremony, release publication or merge
is performed by this implementation task. Production needs an owned delegated
zone and ingress placement, PostgreSQL and an independently retained restore
witness, protected installation administrator state, authentic relay receipt and
control CA pins, and Broker-owned scoped credentials and TLS material.

Before production, run controlled DNS/CAA and public CA issuance/renewal drills,
IPv4/IPv6 routing and relocation checks, expiry/rollback and restore exercises,
and CT alert delivery/containment drills against the configured provider. Exercise
real browser/passkey PRF support on host and phone, both enrollment directions,
remote registration and recovery, approval activation followed by separate
execution, mode transitions and relay outage with local credentials.
