# Remote ceremonies implementation plan

**Status:** planning handoff; no implementation claimed. 2026-09-17.

## Objective and authority

Implement the [remote ceremony architecture](../architecture/Open-Internet%20Sealed%20Approval%20Ceremony.md):
self-hosted Triad, default Bloom relay, privileged localhost-only switching,
local and remote credentials for one wallet, two-leg addition, and single-use
recovery. Fully hosted Triads, custom/LAN/VPN domains, alternative relays, and
cross-Signer migration are excluded.

Read repository `AGENTS.md`, [DEVELOPMENT.md](../../DEVELOPMENT.md),
[TESTING.md](../../TESTING.md), the [Triad specification](../specs/2026-07-23-triad-process-architecture.md),
[Wallet architecture](../architecture/Wallet.md),
[Solana native integration](../architecture/Solana%20Native%20Integration.md), and
[release package guide](../../packaging/triad/release/README.md). Current code and
these contracts take precedence over historical plans except for the explicit
remote extensions in the target architecture. Update normative Triad sections
12–13 and packaging contracts as part of implementation, documenting the new
surface, multi-origin, administration, and recovery behavior.

## Delegated planning entrypoint

A fresh agent session using this plan is explicitly authorized to delegate
bounded planning and review tasks to subagents. Start with repository discovery,
status and full commits for Machine, Broker, Signer, and any existing relay
repository. Preserve unrelated work and read each owner's guidance. Do not read
credential-bearing files without exact-path permission. This handoff authorizes
proposing the full implementation; it does not itself authorize cloud deployment,
DNS mutation, real wallet ceremonies, or spending.

Use up to three concurrent subagents while the coordinator handles integration:

1. Signer: schema, WebAuthn, administrative state, two-leg secret lifetime,
   credential/recovery atomicity, compatibility and adversarial tests.
2. Broker/browser: ceremony contracts, HTTPS/session exchange, UX, exposure
   reconciliation, recovery admission and TLS lifecycle.
3. Relay/operations: enrollment identity, DNS/CAA/ACME, tunnel routing, tombstones,
   CT and service packaging. Implement in `../bloom-relay` following its
   [codebase plan](../../../bloom-relay/README.md); never place relay authority in Machine.

Coordinator owns Machine CLI/VFS projections, installer integration, dependency
order, authoritative-doc reconciliation and a coverage matrix. Require each agent
to return exact code seams, types/state transitions, owner, proposed commits,
validation and unresolved implementation choices. Review seam mismatches jointly
before implementation. Do not delegate concurrent edits to shared contract files.

## Reuse-first implementation rule

Every subagent must inspect existing implementations before proposing new code.
Prefer extending the owning repository's existing ceremony state machines, typed
APIs, persistence/transaction helpers, authenticated transport, configuration,
logging, error handling and tests. Reuse shared contracts through their owning
crates; do not copy implementations into another repository or create a parallel
ceremony/session/authority system.

For general infrastructure, prefer maintained, compatible libraries and established
protocols over custom implementations. This applies especially to cryptography,
TLS, HTTP/2, parsing, authentication primitives, serialization, database access,
retries, observability and ACME/DNS integration. Evaluate available libraries for
bounded resource use, security properties, maintenance, license, MSRV and feature
compatibility. Reuse must preserve the architecture's authority boundaries and
must not introduce deprecated fallbacks or unnecessary dependencies.

Each delegated proposal must include a short reuse map: requirement -> existing
module/API or library -> necessary extension. Before proposing a new module or
custom protocol mechanism, identify the alternatives inspected and explain the
specific requirement they cannot satisfy. Keep Bloom-specific policy, bindings
and orchestration small and built on reviewed primitives. In particular, evaluate
maintained ClientHello parsing support before writing a parser; do not implement
TLS, signature algorithms, HTTP/2 framing or ACME from scratch. A library's use
still requires integration and adversarial tests for Bloom's boundary conditions.

## Initial code map (verify against current revisions)

| Owner | Starting points and responsibility |
| --- | --- |
| Signer | `../bloom-signer/crates/bloom-signer/src/ceremony.rs`, `custody.rs`; locate API types, persistence, CLI/config/admin entrypoints and service startup. Own surfaces, binding, credential wraps, recovery and replay. |
| Broker | `../bloom-broker/crates/bloom-broker/src/ceremony.rs`, ceremony assets and API crates; locate transport/service configuration. Own review, sessions, browser HTTP, TLS/tunnel client and orchestration. |
| Machine | `crates/bloom-machine-client`, `bloom-daemon`, `bloom-vfs`, `bloom`, `bloom-it`; locate custody and approval URL projection routes. Preserve authenticated Broker-only calls and exact KeyRef selection. |
| Packaging | `packaging/triad/release/`, platform launchers/installers and `scripts/triad-dev-launch.sh`. Own privilege boundaries, setup, service permissions and acceptance environments. |
| Relay/control plane | `../bloom-relay`, its [README](../../../bloom-relay/README.md), and proposed protocol/client/gateway/control/store/DNS crates. No wallet policy/custody authority. Own hostname allocation, serving DNS, scoped enrollment, tunnel routing, DNS challenge, certificate inventory and CT operations. |

## Work packages and dependency order

### A. Freeze contracts and compatibility

Write versioned surface identity/digest and lifecycle revision types, credential
surface binding, browser WebAuthn DTOs, contribution/challenge/receipt/audit
bindings and typed errors. Keep deployment metadata separate from immutable
surface identity. Specify remote/default surface selection from Signer-approved
state, with no Browser or Machine authority to create surfaces.

Define a migration for legacy localhost credentials, unchanged user handles and
wrap AAD, pending ceremonies, persisted results and public projections. Reject
incompatible old peers before exposing remote support. Document rollout/rollback
behavior after new credential/recovery state is written; never downgrade into
reusable recovery or resurrect credentials.

Before coding dependent seams, the agents must resolve and record these bounded
engineering choices (no further product scope expansion): canonical digest
encoding/domain separation; protocol/storage versions; source/destination handoff
proof and exchange DTOs; numeric absolute leg/session/result deadlines; rate and
transport limits; administrative IPC/config application and recovery-fencing
revision. Review these as a concrete protocol proposal, not implicit defaults.

### B. Signer foundation and administrative control

Implement immutable local/assigned-remote identities and audited lifecycle,
surface-filtered credentials and dynamic WebAuthn verification. Preserve exact
KeyRef and signer identity checks. Administrative commands run as the authorized
local administrator with protected state/identity; use live authenticated admin
IPC or offline exclusive-lock updates, never concurrent file writes beneath a
running Signer. Configuration edits/restart must enforce equivalent checks.

Implement status/desired/effective exposure revisions and protected installation
identity bootstrap. Admin operations permit only the two supported surfaces;
local privilege cannot supply wallet PRF, authorize credential addition, or bypass
lockout checks. Specify installer-to-Signer enrollment, relay admin authentication,
identity rotation/loss, and secure permissions before default provisioning.

### C. Broker surfaces and browser sessions

Generalize existing ceremony serving without parallel authority APIs. Keep local
listener ownership/exclusive binding. Add Broker-owned HTTPS listener and fragment
exchange, verifier storage, scoped sessions, safe concurrent tabs, CSRF protection,
result/ack authentication, redaction, bounded admission, and public readiness.
Use synthetic origins and test certificates before public relay integration.

Implement remote registration/import through existing typed custody operations,
PRF adjacent assertions, credential listings and same-surface add/replace/remove.
Implement remote Sealed Approval using canonical review digest and unchanged
activation/execution separation. Carry valid Broker URLs through Machine CLI,
IPC/VFS, status and mounted documentation; no Machine listener or Signer client.

### D. Two-origin access and recovery

Specify and implement the authority-first two-leg state machine, independent
capabilities and intended handoff proof. Classify the destination handoff as
bearer enrollment authority. Bind wallet, Signer, operation, exact terms, both
surfaces, credentials and deadline; test source-to-destination in both directions,
including a phone completing remote authority and a host browser completing local
enrollment. Establish a non-authoritative destination session and ephemeral
proof-of-possession key before authority; source approval binds that destination
key/session, and enrollment requires it. Specify canonical pairing messages, user
confirmation, challenge replay protection and lost-key restart behavior. Bootstrap
is not credential enrollment and does not relax authority-first proof ordering. No source PRF/WKEK material persists in database, WAL or backups.
Define protected volatile memory and terminal zeroization; restart durably fails
uncommitted legs. Committed retries return the existing receipt.

Recovery bootstrap must hide identifier existence, bound completion attempts and
avoid permanent attacker-induced lockout. Atomic recovery revokes prior wallet
credentials, creates the replacement, rotates the factor and fences stale pending
ceremonies with a credential-authority generation checked by every affected
completion. Fence unfinished passkey-authorized approvals too; already activated
approvals retain their existing rules and are not revoked by this generation.
Preserve root/addresses and existing policy/approval semantics. Define
single-commit result retrieval for bounded encrypted delivery, including timeout,
restart and recipient-key loss: retrieval stays bound to the original recipient;
no unauthenticated re-encryption after key loss. The committed replacement passkey
remains available for normal custody management, but cannot decrypt that result
or reset the recovery factor through an unspecified API. Factor-reset expansion
and richer save-confirmation UX are deferred.

### E. Relay and certificates (parallel infrastructure track)

The owner is the new `../bloom-relay` repository. Its
[README implementation plan](../../../bloom-relay/README.md) specifies Rust 2024,
the current stable toolchain and compatible stable dependencies, crate layout,
structured tracing/logging, typed errors, SQL persistence, tunnel framing,
resource limits, CI and deployment work. Read it alongside this plan; relay
protocol/client changes land there before Broker advances its compatibility pin.

Implement serving DNS as well as DNS-01: a delegated `relay.bloom.directory`
zone, explicit per-installation A/AAAA records and exact CAA, stable ingress
placement, and permanent random-name reservation. The README proposes Route 53
as the first adapter. Record actual provider/delegation/infra ownership before
production. Test authoritative and recursive resolution, unknown-name NXDOMAIN,
IPv4/IPv6 reachability, TTL/placement changes and correct gateway ownership; no
wildcard or random load-balancer routing substitutes for authenticated placement.
Keep initial bootstrap admission, generation-fenced leases, DNS reconciliation
and CT monitoring assigned to this repository, with Broker retaining its TLS and
ACME keys. Deployment/account/retention decisions are required operations work.

Implement allocation and permanent hostname reservations; independently scoped
tunnel/DNS/admin credentials; authenticated exact-host connection ownership;
exclusive routing and reconnect fencing; ordinary SNI routing without ECH;
fragmented/malformed parsing limits and bounded streams/backpressure. Specify the
wire protocol and tunnel client placement inside the Broker boundary.

Implement exact TXT challenge leases/cleanup, ACME account binding and stronger
admin rebinding, restrictive CAA, Broker-owned key storage, ACME renewal and
validated atomic deployment. Document CA/DNS provider selection, staging drills,
expiry behavior, still-valid rollback and CT inventory/15-minute alert target.
Exercise incident response. No tunnel credential can rebind accounts or issue for
siblings. Restore preserves hostname tombstones and authority identity freshness.

### F. Default setup and mode transitions

Installer provisions the local surface, stable relay identity, certificate and
remote surface through privileged Signer administration. Mark remote enabled only
when enrollment, valid TLS and externally observed routing are ready. Provisioning
failure remains explicit/retryable; local operation remains available. Define
idempotent setup/restart and observable partial-failure stages.

Provide the same small administrative interface through osascript/pkexec/sudo.
Broker observes authenticated desired state and reconciles listeners/tunnel;
admin command reports completion only when the effective mode is confirmed.
Broker reports effective state with the desired revision over its existing
Broker-to-Signer edge; local admin IPC returns that status. Disable fences remote
commits immediately and waits for closure acknowledgement; enable activates the
remote surface only after certificate/routing readiness. A staged HTTPS health
endpoint can serve probes before activation but cannot serve wallet ceremonies.
No reverse Signer-to-Broker client connection is introduced.
Localhost remains ACTIVE in both modes. The localhost-only admin command
preflights all active passkey-dependent wallets and refuses with actionable IDs if local credential
coverage is missing; it does not silently initiate or authorize wallet ceremonies.
Map backend kinds explicitly: exclude credentialless wallets only when their
authoritative contract needs no passkey ceremony for continued operation. Unknown
requirements fail preflight; test both passkey-dependent and independent backends.
The user enrolls missing local credentials through Broker, then retries. Clearly
disclose that a credential record does not prove continued authenticator possession.
Atomically revalidate wallet-set/credential generations and fence concurrent
registration/removal/recovery before disabling remote ceremonies/tunnel. A failed
preflight leaves the prior mode in place. Test multiple wallets and relay outage;
recovery is the path when source access is lost. Empty installations can switch
without credential ceremonies. Re-enable reuses hostname/credentials and ensures
TLS readiness before offering remote URLs; missing remote access uses local
passkey authorization. Never revoke credentials merely for exposure switching.

### G. Integration, release and documentation

Land dependencies in owning repositories, then advance full landed pins and
lockfiles in Signer -> Broker -> Machine -> dependent Petal order as applicable.
Relay deployment compatibility gets explicit protocol/version evidence. Do not
repeatedly repin moving upstream branches. Keep at most one unmerged parent and
use separate target directories for concurrent Cargo builds.

Test the exact three binaries with required sibling discovery paths and full
commits/dirty state recorded. Packaging must retain process and UID boundaries,
Broker-only TLS/key access, protected administrative credentials, service socket
ownership, and no release `triad-dev-harness`. Extend Linux and macOS installation
acceptance for new setup/admin/service state. Publish user docs explaining two
passkeys, localhost device restriction, relay trust, disable/re-enable, recovery
replacement, and outage behavior. Update embedded VFS guidance only as necessary.

## Acceptance matrix

| Area | Required evidence |
| --- | --- |
| Surface/protocol | Wrong origin/RP/cross-origin bit/digest/wallet/Signer/KeyRef rejected; disabled state rechecked at commit; legacy localhost migration; incompatible peers fail closed. |
| Credential lifecycle | Same- and cross-origin enrollment in both directions; no early activation/revocation; wrong/reordered/replayed/stolen-unbound handoff rejected; stable addresses; surface-filtered options and scoped handles. |
| Secret lifecycle | Faults at every leg/commit; timeout/cancel/disable/restart destruction; no intermediate plaintext in persistence/logs; meaningful platform memory enforcement evidence. |
| Recovery | Non-enumeration and admission/completion limits; atomic rotation/revocation; concurrent recovery only one winner; stale pending additions cannot restore access; bounded encrypted result retries across restart; no silent factor reuse. |
| Browser | Fragment absent from initial requests/logs; single exchange; scoped cookie and CSRF checks; concurrent ceremonies/tabs; expired/revoked session denial; real browser/passkey PRF matrix with clear unsupported UX. |
| Administration | Privilege rejection; no Machine-Signer path; defaults and partial setup; multiple-wallet lockout guard and races; config parity; restart reconciliation; disable cancels remote sessions and closes tunnel; re-enable retains hostname. |
| Relay | Spoofed identity/SNI, duplicate connections, fragmented/malformed ClientHello, bounded resources, reconnect; no authority/control/filesystem reachability; no Browser TLS termination at relay. |
| TLS/DNS/operations | Exact issuance/renewal/rollback/expiry; scoped TXT and CAA/account tests; CT alert/containment drill; identity-loss/rebinding; tombstone and anti-rollback restore; no weaker fallback. |
| Full stack | Real remote registration, local/remote add, approval activation then separate execution, recovery, disable/re-enable; localhost unaffected by relay outage when a local credential exists. |

Use the smallest owner tests first, then package suites and required gates from
TESTING.md. Cross-service contracts require real out-of-process triad evidence,
not only in-process fixtures. Remote transport needs an actual tunnel integration
fixture plus controlled public/staging certificate tests. Release changes require
Linux build and both macOS conformance workflows at frozen compatibility refs.
Existing custody acceptance, production authority-boundary checks and relevant
EVM/Solana workflows must continue to pass; never blindly retry broadcast.

## Completion and planning deliverables

The next planning session returns a consolidated implementation proposal with:

- owner/file/type/state-machine map and resolved engineering choices from A;
- ordered PRs and dependency versions, including the relay owner;
- acceptance matrix mapped to concrete tests and operational drills;
- resource/timeout defaults and deployment/rollback runbooks;
- explicit remaining blockers, or evidence that every requirement has an owner.

Implementation is complete only after owner and integration gates pass, the
required release evidence is recorded, and documentation describes actual shipped
behavior. Starting services or passing fixture tests alone is not completion.

## Document review evidence

Two review rounds with a GPT-5.6 Sol subagent at medium reasoning evaluated a
fresh-session cross-stack implementation proposal. Round one clarified local
surface availability, administrative preflight/CAS, stale-ceremony fencing,
destination pairing, result recipient loss, and effective-state acknowledgement.
Round two checked the revised proposal and clarified pre-activation health probes,
backend-specific passkey coverage, and the lack of an implicit factor-reset API.
The reviewer found no remaining product decision blocking a complete proposal;
the bounded engineering choices in work package A still require protocol design
and tests before implementation. This is document review, not implementation or
security-conformance evidence.
