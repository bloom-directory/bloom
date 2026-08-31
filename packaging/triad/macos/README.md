# Bloom triad macOS Unix-principal packaging source

This directory implements the root-requiring Unix-principal profile in
`docs/specs/2026-07-29-macos-unix-principal-isolation.md`. It is source input
for the signed installer and is never installed directly from a checkout.

The rootless code-identity architecture remains documented as a future target
in `docs/specs/2026-07-30-macos-rootless-code-identity-isolation.md`. Nothing
in this directory may emit its `macos-rootless-code-identity` platform claim or
substitute App Groups, same-UID LaunchAgents, or Keychain groups for the Unix
principal boundaries.

## Service topology

For each enrolled login UID, the installer renders two system-domain
LaunchDaemons:

- `com.bloom.broker.LOGIN_UID`, running as `bloom-broker-LOGIN_UID`;
- `com.bloom.signer.LOGIN_UID`, running as `bloom-signer-LOGIN_UID`.

Each daemon explicitly binds its Unix sockets inside endpoint directories
owned by that service UID. The directories use distinct edge groups and mode
`0710`; a service validates this metadata before publishing a `0660` socket.
Broker and Signer have separate revocation subdirectories. This construction
is required because a launchd-created Unix socket reports launchd's UID to the
connecting peer on macOS, which cannot satisfy the protocol's mutual kernel
peer-UID check. It does not fall back from failed launchd activation or create
endpoints outside the signed profile.

Broker owns the canonical ceremony listener by direct exclusive bind to
`127.0.0.1:18734`. The LaunchDaemon does not declare or pre-bind that TCP
socket. A conflict is fatal, reported, retried by failure-only `KeepAlive`, and
never selects a fallback address or port. Before exiting, Broker atomically
writes a Broker-owned, Machine-readable `broker-startup.json`. Machine accepts
only its exact owner, group, mode, schema, address, incident, and message, so a
bind failure is reported promptly as either another Bloom login or a foreign
or unverifiable listener. The root packet-filter monitor performs the public
owner-marker probe and publishes its result in the fresh root-owned platform
status because the confined Broker cannot initiate even a loopback SYN. A
successful retry removes the stale diagnostic.

The global `com.bloom.session` LaunchAgent invokes only Machine's
`serve session-sentinel` mode. It exits successfully for an unenrolled login,
keeps no custody or signing authority, and is destroyed with its GUI login
domain. It owns `session/session.sock` as the login UID and authenticates a
separately pinned `bloom-session` identity. The socket reuses the already
declared revoke group, whose membership contains the login, Broker, and
Signer, while mutual application-key authentication distinguishes the two
service channels. Broker authenticates before binding the canonical ceremony
listener; Signer authenticates before accepting RPC. Both drain and exit
successfully on disconnect. The root containment monitor validates a returning
session socket's enrolled UID, group, mode, and type and kickstarts only that
enrollment's stopped Signer and Broker jobs. It does nothing while the
sentinel is absent; the LaunchAgent itself has no system-job control authority.

The global `com.bloom.machine` LaunchAgent runs `bloom serve --mount-home` for
each enrolled login. Machine resolves the effective login's installed
enrollment, serves its normal `~/.bloom/run/bloom.sock` endpoint, and mounts the
VFS at `~/bloom`. The generic template contains no username or home-directory
literal and exits fail-closed when the effective login is not enrolled.

## Filesystem and network boundaries

The installer renders the root-owned release, edge manifest, account/group
record, LaunchDaemon definitions, session LaunchAgent, and packet-filter
anchor. Broker and Signer state/checkpoint roots remain owned by their
respective service UIDs and mode `0700`.

The installer keeps digest-named releases immutable. A same-digest install
verifies every installed binary and repairs integration files without replacing
custody. A compatible different digest is staged, all enrolled jobs are stopped,
the shared `current` symlink and enrollment build digests are switched
atomically, and launchd is asked to reload the installed jobs. A durable forward
intent makes the next invocation continue toward the newly requested signed
digest after interruption; upgrades never roll back to an older binary because
a runtime job is unhealthy or deferred. Compatibility metadata is mandatory and
a state-schema downgrade is rejected before services are stopped.

`uninstall --retain-custody / LOGIN_UID` removes launchd, packet-filter, and
runtime integration while preserving service principals, identities, and
encrypted state. `restore` accepts only the exact signed retained release and
reinstalls its integration without rotating custody. Permanent deletion remains
a separate `delete-bloom-login-LOGIN_UID` confirmation and is described as a
purge because it destroys custody irrecoverably. Upgrade and restore never run
enrollment-material generation and never rotate transport or custody identity.

Production enrollment invokes the installed Machine binary's root-only
enrollment-material mode against the signed public templates in `config/`.
Five application identities and the Broker/Signer signing authorities are
fresh per login; only their public cross-pins enter the root-owned manifest.
The temporary root-only generation directory is removed on success or error.
The root-owned enrollment record uses `activating` while durable files are being
converged and is published `active` once the requested digest is selected.
Runtime health is reported by Bloom after installation and is not an installer
commit condition. A failed fresh install removes Directory Service records
created by that invocation. An interrupted upgrade retains its forward intent
so the next invocation can finish the same convergence safely.

The packet-filter template denies new Broker IP flows and all Signer TCP/UDP
flows by numeric effective UID. A root/wheel one-shot monitor is launched once
per second with no socket, RPC, custody, or signing surface. It verifies the
loaded per-UID anchors and atomically publishes short-lived root-owned status
records. Broker and Signer require the exact login UID, release digest,
ownership, mode, availability bit, and freshness before readiness or any
signing/custody/policy mutation; revocation and public status remain
available. Production activation is prohibited until the disposable macOS W0
lane proves IPv4/IPv6, TCP/UDP, loopback, accepted Broker responses, anchor
drift, Fast User Switching, forward upgrades, interrupted resumption,
retain/restore, same-digest repair, and purge behavior. Local Signer is the only
initial backend.

Static template and staged-root tests are conformance inputs, not proof of an
operating-system boundary. Tests that create accounts, load LaunchDaemons,
change `pf`, or exercise multiple GUI users run only on disposable macOS VMs.
The guarded harness and its current coverage are documented under `w0/`.

## Service logs

Broker and Signer write complete JSON Lines records to
`/private/var/log/bloom/LOGIN_UID/{broker,signer}.jsonl`. The enrolled user can
read these files without `sudo` but cannot modify them; service state remains
private. Rotation is bounded by `/etc/newsyslog.d/bloom-LOGIN_UID.conf` and
does not require restarting either daemon. Session and containment lifecycle
messages use launchd's native process logging rather than the per-enrollment
diagnostic files.

Each daemon also has a small bounded `SERVICE-bootstrap.log` launchd stderr
fallback. It is only for fixed, sanitized initialization failures that happen
before the canonical app writer is available; routine events never use it.
