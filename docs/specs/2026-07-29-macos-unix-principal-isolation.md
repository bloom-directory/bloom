# macOS Unix-principal isolation profile

> September 2026 amendment: the PF network-containment portions of this original
> profile are retired to preserve iCloud Private Relay. The current release
> retains Unix principal separation but does not satisfy the original MUI-07
> network boundary. See [the current contract and follow-up plan](../operations/macos-private-relay.md).

**Status:** Proposed implementation profile

**Applies to:** Bloom triad architecture, local macOS placement

**Normative base:** `2026-07-23-triad-process-architecture.md`

**Developer Program dependency:** None

## 1. Purpose

This profile defines the macOS construction for the Machine, Broker, and
Signer boundaries required by sections 6, 20, 22, 25, and 27 of the triad
architecture.

The profile deliberately does not use:

- Apple Developer Program membership;
- Developer ID signing, notarization, provisioning profiles, or App Groups;
- App Sandbox as a security boundary;
- same-UID filesystem separation;
- a root-owned audit-checkpoint writer or privileged signing helper.

Containment is instead provided by distinct Unix effective UIDs, supplementary
groups, filesystem ownership, launchd service domains, authenticated local RPC,
and UID-scoped packet-filter rules. Installation requires an administrator
authorization because it creates local service accounts and system
LaunchDaemons. Runtime signing and checkpoint writes are unprivileged.

The existing Ed25519 release signature remains the package-authenticity root.
Keys use OpenSSH Ed25519 format and signatures use domain-separated SSHSIG
namespaces, allowing the elevated installer to verify with the OS-owned
`/usr/bin/ssh-keygen` rather than a login-user-owned package-manager binary.
An unsigned macOS executable is never accepted merely because macOS permits it
to execute.

## 2. Security claim

For each enrolled interactive login UID `U`, packaging creates:

- interactive Machine principal: the existing login UID `U`;
- Broker principal: hidden service account `bloom-broker-U`;
- Signer principal: hidden service account `bloom-signer-U`.

The service-account numeric UIDs are allocated by the installer and recorded
in the root-owned edge manifest. Account names are identifiers, not an
authorization source.

The profile claims containment of a compromised Machine running as `U`:

- it cannot read or modify Broker or Signer private state;
- it cannot authenticate as Broker;
- it cannot open the Broker-to-Signer data endpoint;
- it cannot inspect Broker or Signer process memory through same-UID process
  APIs;
- it cannot replace the installed binaries, manifests, service definitions,
  packet-filter rules, or backend credentials;
- it cannot bind the canonical ceremony listener while the owning Broker is
  serving it.

Root compromise, kernel compromise, and unrelated same-UID malware outside the
compromised Machine model remain outside the claim exactly as in section 6.

## 3. Accounts and groups

For login UID `U`, the privileged installer creates:

| Name | Members | Authority |
|---|---|---|
| `bloom-machine-broker-U` | login user, `bloom-broker-U` | Machine-to-Broker RPC socket only |
| `bloom-broker-signer-U` | `bloom-broker-U`, `bloom-signer-U` | Broker-to-Signer RPC socket only |
| `bloom-revoke-U` | login user, `bloom-broker-U`, `bloom-signer-U` | revocation control sockets only |

The login user is never a member of `bloom-broker-signer-U`. Neither service
account is an administrator, may log in interactively, or has a usable shell.
Service accounts have no shared home directory.

Account provisioning must:

1. allocate unused numeric UIDs without assuming a fixed UID range;
2. reject an existing account or group whose recorded ownership does not match
   the Bloom enrollment record;
3. set `IsHidden=1`, a non-login shell, and authentication disabled;
4. write an owner-only enrollment record containing the login UID, account
   names, allocated UIDs, group IDs, and installed release digest;
5. roll back newly created accounts and groups if provisioning fails before
   state initialization;
6. never delete a pre-existing non-Bloom account during rollback or uninstall.

## 4. Filesystem layout

System-wide immutable inputs:

```text
/usr/local/libexec/bloom/
  bloom
  bloom-broker
  bloom-signer

/Library/LaunchDaemons/
  com.bloom.broker.U.plist
  com.bloom.signer.U.plist

/Library/LaunchAgents/
  com.bloom.session.plist

/Library/Application Support/BloomTriad/
  release/
  enrollments/U.json
  config/U/edge-manifest.json
  config/U/broker/{config.json,identity.json}
  config/U/signer/{config.json,identity.json}
```

Mutable service state:

```text
/var/db/bloom/U/broker/
  journal.db
  authority.db
  ceremonies.db
  audit-checkpoints/

/var/db/bloom/U/signer/
  signer.db
  backend-state/
  audit-checkpoints/
```

Runtime endpoints:

```text
/var/run/bloom/U/machine-broker/broker.sock
/var/run/bloom/U/broker-signer/signer.sock
/var/run/bloom/U/revoke/broker/control.sock
/var/run/bloom/U/revoke/signer/control.sock
/var/run/bloom/U/session/session.sock
/var/run/bloom/U/status/broker-startup.json
```

Required ownership and modes:

| Path class | Owner | Group | Mode |
|---|---|---|---|
| binaries, plists, enrollment, edge manifest | root | wheel | `0755` directories, `0644` files |
| Broker config and identity | `bloom-broker-U` | same | `0700` directory, `0600` files |
| Signer config and identity | `bloom-signer-U` | same | `0700` directory, `0600` files |
| Broker state/checkpoints | `bloom-broker-U` | same | `0700`; checkpoint entries `0600` |
| Signer state/checkpoints | `bloom-signer-U` | same | `0700`; checkpoint entries `0600` |
| Machine-to-Broker socket directory | `bloom-broker-U` | `bloom-machine-broker-U` | `0710`; socket `0660` |
| Broker-to-Signer socket directory | `bloom-signer-U` | `bloom-broker-signer-U` | `0710`; socket `0660` |
| revocation parent directory | root | wheel | `0711`; no sockets |
| Broker revocation socket directory | `bloom-broker-U` | `bloom-revoke-U` | `0710`; socket `0660` |
| Signer revocation socket directory | `bloom-signer-U` | `bloom-revoke-U` | `0710`; socket `0660` |
| startup status directory | `bloom-broker-U` | `bloom-machine-broker-U` | `0750`; status `0640` |

Parent directories must permit traversal only where required and must not
contain readable private data. Symlinks are forbidden for every security path.
The installer and services open security files relative to verified directory
descriptors and fail closed on owner, mode, link-count, or type mismatch.

Broker cannot read Signer state or checkpoints. Machine cannot read either
service's state or checkpoints. This is the section 20 checkpoint boundary:
each checkpoint location is writable only by its service principal and
unreadable by the other product principals. It does not claim protection from
root.

## 5. Local RPC topology

Broker and Signer explicitly bind and publish their Unix RPC sockets inside
the service-owned endpoint directories from section 4. Before binding, each
service verifies the directory owner, group, mode, type, and non-symlink
status. It rejects live or substituted endpoint entries and replaces only a
singly-linked stale socket owned by its effective UID. It publishes each new
socket with its edge group and mode `0660` before accepting traffic.

launchd socket activation is intentionally not used for these Unix endpoints.
Disposable W0 showed that the connecting process observes launchd/root as the
peer owner of a launchd-created socket, rather than the explicit `UserName`
service that accepts it. Service-owned binding preserves mutual kernel
peer-UID verification. This is an explicit platform construction, never a
fallback from failed activation.

Filesystem access is necessary but insufficient. Every RPC connection still
uses:

1. kernel peer effective-UID verification;
2. the application-key challenge and signed envelope;
3. exact service ID, boot epoch, and method authorization from the root-owned
   edge manifest.

The accepted peer UIDs are:

| Endpoint | Accepted peer |
|---|---|
| Broker data | login UID `U` with Machine application identity |
| Signer data | allocated Broker service UID with Broker application identity |
| Broker control | login UID `U` with revoke-client identity |
| Signer control | login UID `U` with revoke-client identity |

Control endpoints expose only the closed revocation/status method set. Access
to a control socket never grants signing, custody, policy mutation, backup, or
credential authority.

## 6. launchd construction

Broker and Signer are per-login system-domain LaunchDaemons with explicit
`UserName` values naming their service accounts. They are not GUI
LaunchAgents. Machine remains an interactive process.

Each daemon:

- receives exact Unix socket paths from its signed LaunchDaemon profile and
  binds only in its verified service-owned endpoint directories;
- sets `InitGroups=true`; enrollment flushes the Directory Service membership
  cache and verifies every effective edge membership before bootstrap;
- has `ProcessType=Background`;
- uses `KeepAlive` only for abnormal exit;
- exits successfully when its enrolled login session ends;
- has a bounded restart throttle;
- sets `SoftResourceLimits` and `HardResourceLimits` for files, processes, and
  core size;
- writes logs only to its principal-owned state directory;
- has no writable current directory containing installed code.

Core dumps are disabled. Environment variables contain paths only, never key
material or backend credentials.

### 6.1 Login-session sentinel

A single system-installed `com.bloom.session` LaunchAgent is offered to each
GUI login domain. It immediately exits for an unenrolled effective UID. For an
enrolled UID it runs the installed Machine executable in a minimal
session-sentinel mode. It contains no signing, custody, policy, release, or
installation authority. It owns a live session sentinel socket and
authenticates with a dedicated session identity.

Broker requires a live authenticated sentinel before serving ceremonies. On
sentinel disconnect caused by logout, Broker:

1. stops accepting new ceremonies;
2. records terminal state for live browser sessions;
3. closes the canonical listener;
4. exits successfully so failure-only KeepAlive does not restart it.

Signer drains accepted operations according to the normal durable-effect rules
and then exits successfully. A missing sentinel causes a clean no-service
state, not a restart loop.

The root containment monitor is the restart bridge for a returning GUI
session. On each one-shot pass it validates the exact login-owned session
directory and `0660` sentinel socket against the enrolled login UID and revoke
group. If that socket exists and either fixed per-enrollment system job is
loaded but stopped, the monitor kickstarts Signer and then Broker. The services
still mutually authenticate the sentinel before serving. An absent sentinel
causes no kickstart, and the login LaunchAgent receives no system-job control
authority.

The sentinel cannot start arbitrary jobs, write service configuration, read
service state, or request signatures.

## 7. Canonical ceremony listener

The macOS Unix-principal profile uses Broker direct ownership rather than
launchd TCP handover. This is the section 22 construction for a platform lane
where reliable conflict handover has not been proven.

Broker binds exactly `127.0.0.1:18734` with:

- no address or port reuse;
- no wildcard, IPv6, alternate-address, or fallback-port bind;
- close-on-exec;
- an exact post-bind local-address check.

Bind conflict is a fatal startup failure. Before exiting, Broker atomically
writes bounded `broker-startup.json` status with incident
`ceremony_listeners_unavailable` and address `localhost:18734`.
Machine reports that status rather than waiting indefinitely. The Broker
service log identifies the failing address or descriptor and its error.
Acquisition failure alone does not establish that another process owns a
listener: IPv6 may be unavailable, or activation may be misconfigured.

Failure-only KeepAlive retries a waiting Broker. When the owning login sentinel
disconnects and its Broker closes the listener, a waiting Broker may acquire
the canonical port without user action. No fairness guarantee is claimed.

The HTTP listener remains reachable by other local UIDs. Its security remains
the single-use 256-bit session token, bounded attempts, bounded bodies, and
short expiry stated in section 6.

## 8. Network containment

No Apple Network Extension entitlement is assumed. The privileged installer
loads a dedicated `pf` anchor whose rules match the allocated service UIDs.
Signer has no permitted IP traffic. Broker receives one preceding `lo0` rule
for ACK-bearing IPv4 TCP packets whose source is the fixed canonical listener
`127.0.0.1:18734`; this admits listener replies but not an initiated SYN.
The following UID-wide rule blocks every other Broker TCP/UDP packet, including
all non-loopback traffic, and the W0 lane proves both the allowed listener and
the denied initiation cases.
The anchor and its inclusion in the system ruleset are root-owned release
assets.

Default rules:

- deny every outbound IP packet owned by each local Signer UID;
- deny Broker outbound connections except loopback traffic required to answer
  the canonical listener;
- do not interfere with Unix-domain sockets;
- log denied first packets at a bounded rate for conformance diagnostics.

The first macOS release supports `LocalSignerBackend` only. AWS KMS is reported
unsupported until a separate profile proves exact reviewed endpoint egress
without DNS, proxy, IPv6, or fail-open bypass. Merely granting unrestricted
network client access is nonconforming.

Installation fails closed if `pf` rules cannot be loaded and verified. Runtime
health reports network containment unavailable if the anchor disappears;
Broker and Signer then refuse signing.

## 9. Secrets and trusted time

No Keychain access group is required.

- application identity seeds are service-owned mode-`0600` files;
- local backend ciphertext, WKEK material, recovery state, and backend state
  are confined to the Signer state root;
- Broker signing and audit keys are confined to the Broker config root;
- Machine receives public projections only;
- secrets never appear in plist files, process arguments, logs, status files,
  or the release bundle.

The edge manifest pins `macos-managed-timed`, and Broker and Signer use the
host wall clock for expiry and rolling-window semantics. Changing that clock
requires administrator authority; administrator/root compromise is outside
the service-isolation threat model because it can already alter Bloom state.
The services therefore do not maintain a second durable effective clock,
reject forward or backward discontinuities, or require clock repair on macOS.

The root platform monitor may continue to report automatic-network-time and
`com.apple.timed` status as telemetry in the version-3 status schema, but those
fields are not packet-filter containment claims and do not gate signing. The
packet-filter availability, exact-build, ownership, and freshness checks
remain mandatory.

## 10. Installation and enrollment

The administrator-facing installer is a small auditable script/tool executed
with explicit authorization. It must re-verify the Ed25519 bundle signature
against the pinned Bloom release public key after privilege elevation.

### 10.1 Install or upgrade

1. Verify archive signature, checksums, closed compatibility matrix, Mach-O
   architecture set, and three exact semantic versions.
2. Reject debug drivers, test credentials, accepting verifiers, retired
   hash-only methods, writable binaries, and unexpected executable files.
3. Stop and drain all Bloom service instances because binaries are shared.
4. Atomically replace the complete versioned release directory.
5. Atomically repoint one root-owned `current` link only after every file is
   durable.
6. Restore previously active compatible instances.
7. Roll back the `current` link if activation health checks fail.

Interruption leaves either the old complete release active or all affected
services unavailable. It never exposes a mixed-version live triad.

### 10.2 Enroll login

1. Resolve the exact login UID and reject network/directory accounts unless a
   future profile explicitly supports them.
2. Create and verify accounts and groups from section 3.
3. Create state, config, runtime, and checkpoint roots.
4. Generate fresh application identities and cross-pin their public keys.
5. Render the edge manifest with actual numeric UIDs.
6. Render the per-login LaunchDaemon plists and verify the global session
   LaunchAgent is installed.
7. Render and load UID-scoped packet-filter rules.
8. Bootstrap the services and run a read-only health handshake over their
   service-owned sockets.
9. Publish Machine configuration only after the handshake succeeds.

No identity seed or backend secret is reused across login enrollments.

### 10.3 Rotation

Identity, config, and packet-filter rotation use prepare/verify/atomic-swap.
Affected services are stopped before swapping cross-pinned identities. Partial
rotation restores the prior complete set. Rotation never changes a service
account UID silently.

### 10.4 Uninstall

Uninstall requires a confirmation containing the exact login UID and offers:

- remove runtime integration but retain encrypted custody state;
- permanently delete the login's Bloom state.

Both modes first stop Broker and Signer, boot out their jobs, unload their
socket definitions, and remove their packet-filter rules. Permanent deletion
then removes state using explicit verified paths, deletes only accounts/groups
named in the enrollment record, and reports whether recovery is possible.

Global binaries and the shared `pf` anchor are removed only when no enrollment
remains.

## 11. Release policy

`BLOOM_PLATFORM_CLAIM=macos-unix-principals` is accepted only on a macOS
builder after the mandatory disposable-host suite passes. `macos`,
`test-unclaimed`, or an App-Group claim is not an alias.

The bundle verifier checks:

- Mach-O format and declared architectures;
- exact service versions and source revisions;
- root-install manifest and expected executable inventory;
- absence of forbidden production symbols and credentials;
- hashes of LaunchDaemon, LaunchAgent, ACL, and `pf` templates;
- the signed disposable-host conformance report schema and canonical release
  subject digest.

The conformance report is evidence for a release candidate, not a reusable
waiver. A report cannot literally contain the digest of an archive that
contains that same report. Packaging therefore defines a canonical release
subject digest over every binary, source revision, compatibility input,
installer, ACL template, plist, and packet-filter template, excluding only the
platform-claim value and the release/conformance signature envelope. The W0
candidate records both that subject digest and its archive digest. Production
may change only the claim/envelope, embeds the signed report, and signs the
final archive. Any change to a security-relevant packaged input changes the
subject digest and invalidates the report.

## 12. Mandatory disposable-host tests

Tests run on a disposable macOS VM with administrator access. They never run
against a developer workstation.

### 12.1 Principal and filesystem tests

- all three processes have the expected distinct effective UIDs;
- Machine cannot traverse or read Broker or Signer roots;
- Broker cannot traverse or read Signer roots;
- Machine and Broker cannot read the Signer checkpoint directory;
- no product principal can replace binaries, plists, edge manifests, or
  packet-filter assets;
- symlink, owner, mode, and hard-link substitutions fail installation/startup;
- Machine cannot attach, sample, or obtain task access to Broker or Signer.

### 12.2 Endpoint tests

- Machine reaches Broker data RPC and cannot reach Signer data RPC;
- Broker reaches Signer data RPC;
- the login user reaches only the closed control method set on control sockets;
- forged application identity, wrong boot epoch, wrong UID, and replay fail;
- another local UID cannot open any Unix RPC or control endpoint.

### 12.3 Listener and lifecycle tests

- a foreign pre-bound `127.0.0.1:18734` causes fatal reported startup failure;
- no fallback address or port is opened;
- two enrolled logins cause the second Broker to fail loudly without hanging
  its Machine;
- logout of the owning login closes the listener;
- failure-only KeepAlive lets a waiting Broker acquire it afterward;
- crash, restart, Fast User Switching, upgrade, rotation, and uninstall do not
  leak listener ownership or leave stale services running.

### 12.4 Network and secret tests

- local Signer cannot open IPv4 or IPv6 TCP/UDP connections, including
  loopback;
- Broker cannot create non-loopback outbound connections;
- removing or weakening the `pf` anchor stops signing;
- Machine cannot read identity seeds, local backend ciphertext, WKEK state, or
  recovery state;
- arguments, environment, logs, status, crash reports, and bundle files contain
  no secrets or test credentials.

### 12.5 Acceptance tests

The exact AC-01--AC-35 source revisions recorded in the bundle are rerun after
installation. Process-boundary tests target the installed executables and
actual service accounts. Fault-injection tests remain separate test
executables and are never installed as production services.

## 13. Acceptance criteria for this profile

- **MUI-01** No Apple Developer Program artifact or entitlement is required.
- **MUI-02** Machine, Broker, and Signer run with the exact distinct UIDs in
  the edge manifest.
- **MUI-03** The three socket groups form only the declared endpoint edges.
- **MUI-04** State and checkpoints meet every negative-read assertion.
- **MUI-05** Broker direct-bind behavior satisfies AC-31 for foreign and
  cross-login conflicts.
- **MUI-06** Logout and KeepAlive transfer availability without a fallback
  port or user action.
- **MUI-07** Packet-filter removal or drift fails signing closed.
- **MUI-08** Local Signer has no IP network authority.
- **MUI-09** Upgrade is complete-version atomic across all enrolled logins.
- **MUI-10** Uninstall stops services before deleting integration or state.
- **MUI-11** The release gate cannot emit a production macOS claim without a
  digest-bound disposable-host conformance report.
- **MUI-12** All triad acceptance tests and macOS negative-access tests pass on
  the installed release.

## 14. Explicit non-claims

- No resistance to root or kernel compromise.
- No notarized or Gatekeeper-frictionless public distribution.
- No App Store distribution.
- No AWS KMS support in the first macOS Unix-principal release.
- No protection for an arbitrary unsigned replacement that an administrator
  deliberately installs after bypassing the Bloom release verifier.
- No same-user malware containment beyond the Machine process and installed
  endpoint construction stated in the triad threat model.

## 15. Implementation sequence

1. Run a disposable-VM W0 spike proving macOS `pf` can enforce outbound rules
   by service UID, service-owned Unix sockets preserve explicit-`UserName`
   daemon peer credentials and required ownership, and logout can terminate
   the session sentinel. Failure blocks this profile before installer
   implementation.
2. Replace macOS App Group templates with account, group, ACL, LaunchDaemon,
   session-sentinel, and `pf` templates.
3. Add Broker's macOS exclusive direct-bind listener path and durable startup
   diagnostic.
4. Add login-sentinel registration and clean logout drain.
5. Rewrite the macOS installer for service accounts and versioned atomic
   releases.
6. Add disposable-VM provisioning and negative-access tests.
7. Enable the `macos-unix-principals` platform claim only after MUI-01--MUI-12
   pass.
