# Triad implementation log

This file records fail-closed choices only where the normative
`2026-07-23-triad-process-architecture.md` is silent or internally omits a
wire detail. It does not amend that specification.

## 2026-07-30

- The root-requiring macOS Unix-principal profile is the active implementation
  path. The rootless code-identity profile remains a documented future goal
  and its App Group, same-UID LaunchAgent, Keychain-group, and platform-claim
  inputs are not mixed into Unix-principal packaging.
- Release and conformance signatures remain Ed25519 but use the standard
  SSHSIG envelope with separate archive, payload, and conformance namespaces.
  The elevated installer verifies through the root-owned macOS
  `/usr/bin/ssh-keygen`; it never trusts Homebrew OpenSSL from a login-user
  writable prefix.
- Disposable W0 proved that a launchd-created Unix socket exposes
  launchd/root, not the explicit `UserName` acceptor, through the connecting
  peer's kernel credentials. That construction cannot satisfy mutual UID
  authentication. The macOS profile therefore gives each service a `0710`
  endpoint directory under the appropriate non-transitive edge group; the
  service validates the directory and publishes its own `0660` socket.
  Broker and Signer use separate service-owned revoke subdirectories. This
  preserves the RPC and mutual authentication model without a fallback path.
- Fresh macOS Directory Service group edits are followed by
  `dsmemberutil flushcache` and effective membership checks before any job is
  bootstrapped. Both service LaunchDaemons explicitly set `InitGroups=true`;
  relying on an implicit/default supplementary-group state made immediate
  post-enrollment activation fail closed at the session socket.
- The session sentinel sets group ownership on the bound filesystem socket
  pathname and then verifies its exact type, UID, GID, mode, and link count.
  `fchown` on the listening descriptor did not update the pathname node on
  macOS and caused the sentinel to fail closed with a stale inaccessible
  socket.
- The Unix-principal Broker uses its existing direct exclusive canonical bind;
  its LaunchDaemon supplies only reviewed endpoint paths. Failure-only
  `KeepAlive` retries a fatal `127.0.0.1:18734` conflict. The disposable macOS
  test uses a real direct-bind child, not launchd TCP handover.
- A complete-version upgrade may have several recorded Broker LaunchDaemons
  but only one Broker can pass readiness while owning the host-wide canonical
  listener. Upgrade and rollback therefore restore every session and Signer
  job first, then bootstrap, authenticate, and stop each recorded Broker with
  an active login-session job serially against the candidate release.
  The compact self-contained installer therefore preflights an active GUI
  domain for every enrollment before it creates the transaction or stops a
  job. It validates each Broker serially, then restores the complete job set.
  An operator must perform a shared-release upgrade while all enrolled logins
  are active; otherwise it fails before the commit boundary. This validates
  the runnable enrollment set without weakening AC-31 or introducing a
  fallback port.
- Until a disposable W0 VM proves account creation/rollback, system-domain
  launchd ownership, socket modes, `pf` behavior, and uninstall, the installer
  accepts live test activation only for the non-production
  `macos-unix-principals-w0` claim on a root-marked disposable host. Production
  `macos-unix-principals` release generation remains disabled until the lane
  passes. This is an implementation gate, not a weaker production mode.
- Live account allocation is serialized by an exclusive installer lock and
  selects the next unused Directory Service numeric ID from the actual user or
  group database rather than assuming a platform range. A pre-existing Bloom
  name without the exact root-owned enrollment record is never adopted.
  Failures before a fresh enrollment is committed remove only records created
  by that invocation and its exact per-login paths.
- macOS exposes `/var` through the platform-managed `/private/var` link. Live
  packaging resolves mutable state and runtime roots to canonical
  `/private/var/...` paths so its own no-symlink checks do not make an exception
  for a path component. The documented `/var/...` layout remains the standard
  logical alias.
- The login sentinel uses the existing mutual application-key challenge
  directly on a dedicated Unix stream; it is not an RPC request and adds no
  method to either closed surface. The login UID owns the socket, its
  numeric group is pinned in the root-owned edge manifest, and Broker
  authenticates both peer UID and the separately pinned `bloom-session`
  public key before binding the ceremony listener. Sentinel disconnect first
  drains HTTP acceptance, then makes every remaining browser session terminal
  and lets Broker exit successfully. W0 may temporarily carry the session
  identity as a signed fixture; production claim generation remains blocked
  until enrollment creates all private identities locally.
- The single session socket reuses `bloom-revoke-U`, the only declared group
  already containing the login, Broker, and Signer. This introduces no new
  group membership or RPC access: the sentinel selects the pinned peer by
  kernel UID and completes a separate mutual application-key challenge for
  Broker and Signer. Both services wait for that authenticated channel before
  serving. Logout closes both channels; Broker terminalizes browser sessions,
  while Signer stops accepting and gives already accepted bounded requests up
  to their protocol deadline to finish before exiting successfully.
- Production macOS enrollment uses the already verified installed Machine
  executable in a root-only, noninteractive material-generation mode. Signed
  release inputs contain public JSON templates and an unsigned provenance
  catalog, never concrete identity files or seeds. The generator creates five
  application identities plus the Broker, Signer, installer, audit, review,
  ceremony, and revocation authorities from the OS CSPRNG, cross-pins their
  public keys, signs provenance locally, and writes each output with
  create-new mode `0600` inside an empty root-owned `0700` directory. The
  installer then assigns final principal ownership and removes that temporary
  directory. This mode cannot alter accounts, launchd, or `pf` itself.

## 2026-07-29

- Section 6 already treats a second local login as an availability case, and
  sections 22/27 require a listener conflict to fail closed rather than
  guaranteeing that every concurrent login can acquire the host-wide port.
  Broker therefore adds a non-authoritative
  `X-Bloom-Ceremony-Owner: bloom-broker-v1` response marker. After a bind
  conflict Broker probes that marker and atomically writes the resulting
  operational incident to its Broker-owned, Machine-readable status
  directory. Machine accepts only the exact owner, group, mode, schema,
  address, incident, and message after authenticated readiness fails. A
  foreign process can imitate the marker; it grants no access, is not an
  authentication input, and does not replace the 256-bit session token.
  Unknown ceremony URL tokens return 404. The launchd source requests
  failure-only `KeepAlive`; the platform integration lane must prove
  reacquisition after a conflict clears before packaging may claim it. Neither
  path binds a fallback port.
- Section 22 requires distinct Linux principals but does not assign their
  names. Packaging creates `bloom-broker-UID` and `bloom-signer-UID` system
  principals per enabled login UID. The login and Broker share only a
  Machine--Broker group; Broker and Signer share a different group that
  excludes Machine; a third group reaches only the revocation-control
  sockets. systemd owns all named listeners. Service state and configuration
  roots are mode 0700, local Signer has a private network namespace and
  `AF_UNIX` only, and the AWS-KMS drop-in is rejected unless packaging renders
  a non-wildcard reviewed CIDR allowlist over a deny-all egress baseline.
- Section 20 leaves the audit-checkpoint location to packaging. Consistent
  with the section 6 containment target, packaging selects a separate
  mode-0700 checkpoint root writable only by the owning service principal;
  the Signer root is unreadable by Machine and Broker. This does not claim
  protection from root. Runtime append uses exclusive file creation, rejects
  symlinks and non-owned roots, and refuses sequence rollback or replacement.
- Section 25 leaves the exact adjacent-version window open. v1 ships a closed
  current/current matrix only: Machine 0.1.3 with Broker 0.1.0 and Signer
  0.1.0 over protocol 1.0. No adjacent combination is advertised, so the
  requirement to test every supported adjacent combination is vacuous rather
  than silently downgraded. Bundle assembly rejects any version outside that
  matrix and records all three source revisions.
- Section 26's W9 bundle rerun uses two complementary artifacts. Fault and
  crash injection remains in separately linked test executables, because
  shipping those hooks in a production service would violate AC-20. After
  verifying and extracting the signed bundle, the gate binds the complete
  AC-01--AC-35 workspace rerun to the exact three clean source revisions in
  `SOURCE_REVISIONS`; it separately executes, scans, installs, and uninstalls
  the extracted production artifacts. A source-suite pass from a different
  revision or a version-only bundle smoke is not accepted.
- Section 10.3 permits authenticated NTP, NTS, or a platform-managed time
  daemon. The edge manifest pins one reviewed source ID per platform:
  `linux-chrony-nts` or `macos-managed-timed`. Linux packaging requires two
  NTS sources under chrony's `authselectmode require`; the runtime accepts UTC
  only while the kernel reports a synchronized clock and applies the compiled
  one-hour forward-step bound. macOS `timed` does not publish a comparable
  trust state. Because changing the macOS host clock requires administrator
  authority, which can already alter Bloom state, the macOS profile uses the
  host wall clock directly and does not enter the durable discontinuity or
  repair paths. A missing, cross-platform, or peer-supplied source ID still
  fails closed.
  Linux sampling and durable observation are serialized per service so
  concurrent requests cannot persist monotonic anchors out of order. SQLite
  upgrades add
  the UTC, monotonic, and boot-epoch columns in place; historical reservation
  rows retain an explicit zero/unknown anchor but retries preserve their
  original accounting time rather than comparing it with a fresh sample.
  On Linux, Broker and Signer expose the same offline operator mode through
  `BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS`: it opens only the service's own state,
  lists live approvals that the accepted time expires and requires their
  timestamp-bound digest in
  `BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST` before mutation, appends a signed
  `clock.repaired` audit entry atomically with the new clock state, reports the
  confirmation, and exits before serving sockets.
- Section 13 requires Browser's single-use HPKE output-recipient key to be
  bound before the WebAuthn proof, but section 17.2 lists no RPC capable of
  carrying that key after Browser launch. The implementation adds the
  authenticated, operation-bound Broker-to-Signer method
  `custody.bind_output_recipient`. It can only update an existing compatible
  pending custody ceremony; Signer regenerates the bound challenges and
  rejects replay, expiry, kind mismatch, or recipient substitution.
- Section 13 requires Broker and Signer to verify WebAuthn independently, while
  the original `*.prepare` response DTO exposed only the signed Signer
  contribution. The process-separated response now also carries the exact
  Signer-derived challenge list, WebAuthn options, and the enrolled public
  verification credentials selected for that wallet. Broker persists these
  with its private ceremony session and does not expose the verification
  credential records through the Browser projection.
- Section 17.1 lists `wallet.unlock_prepare`, but the closed `CeremonyKind`
  inventory in section 13.1 has no wallet-unlock kind and assigns no durable
  effect to that method. The Broker dispatcher therefore returns
  `CEREMONY_KIND_MISMATCH`; it does not alias unlock to recovery, approval, or
  another custody mutation.
- Section 17.2 defines `revocation.state` as a signed summary and section 17.3
  requires Broker to fetch the tombstone union, but no separate union-fetch
  method is listed. The response therefore carries a `RevocationSnapshot`
  containing the signed summary plus the exact sorted approval-tombstone
  union. Broker verifies the summary signature, count, digest, individual
  signatures, wallet binding, and append-only history before adopting it.
- The user resolved the policy-update initiation gap across sections 13.1,
  17.1, 17.2, and 19 without adding methods: `policy.validate_update` is the
  Broker-originated custody prepare and uses the existing generic
  `ceremony.prepare`/`ceremony.complete` Signer leg with
  `ceremony_kind=policy_update`. It returns the operation ID, exact signed
  review-manifest digest, ceremony URL, and expiry. Ceremony completion
  durably stages—but does not install—the policy commit signed while the
  policy key is unlocked. `policy.commit_update` requires the exact completed
  custody receipt and is the only path that calls `policy.compare_and_swap`;
  Signer then atomically installs the staged snapshot. The shared ceremony
  status, cancellation, and custody-result methods remain unchanged.
- Section 19 binds an `authority-diff digest` but does not freeze the diff
  schema. Broker deterministically derives a typed diff over every
  authority-bearing `CanonicalWalletPolicy` field: approval lifetime,
  permitted Petal packages, destinations, and required verifiers. Set changes
  are sorted and deduplicated, the diff has its own domain-separated digest,
  and Broker rejects a Machine-supplied digest that differs. The signed review
  carries the typed changes as well as the digest; an opaque Machine assertion
  is never treated as the review.
- Sections 13.3 and 19 require registration to create a policy-signing key and
  let Broker verify the resulting initial policy, but section 17 defines no
  separate policy-key enrollment method. The Signer-signed registration/import
  `CustodyResult` therefore carries the version-1 `SignedPolicySnapshot` and
  its Ed25519 public verification key. Broker enrolls that key only while
  processing a completed `wallet_registration` or `wallet_import` receipt,
  verifies the self-contained snapshot, persists the pin in its own policy
  store, and rejects key self-enrollment through ordinary `policy.read`.
- Section 19 defines the closed `CanonicalWalletPolicy` JSON shape and exact
  canonical bytes but does not assign a VFS filename or a TOML translation.
  Production VFS therefore exposes Broker's authenticated canonical projection
  as `wallets/<wallet>/policy.json` and accepts complete policy replacement
  there. No secondary policy projection or translation is exposed: policy
  review and commit remain bound to the exact canonical bytes.
