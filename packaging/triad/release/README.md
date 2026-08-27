# Bloom triad release package

`compatibility-v1.toml` is the closed v1 service matrix. It declares each edge
independently: the Machine–Broker and Broker–Signer authority APIs require
exactly 1.3, while Signer control and login-session liveness accept 1.0–1.1.
Service packages may advance independently when every edge remains inside its
declared range; incompatible edges fail closed.
It also records the exact Broker, Signer, service-runtime, and Petal-contract
commits plus the current state schema and downgrade floor for Machine, Broker,
and Signer. `check-external-pins.py` rejects mutable or abbreviated Git pins;
its `--remote` mode additionally proves the recorded commits through GitHub.

`build-bundle.sh` accepts the three service binaries, the bounded
`bloom-signer-migrate` staging tool, and a
reviewed Ed25519 release key. It verifies semantic versions, scans every
staged and generated bundle file for release-blocking markers, records all
three Git revisions, embeds both platform installers, signs the internal
payload manifest for post-elevation verification, normalizes metadata, and
emits a deterministic archive with checksum, signature, and public key.
Release and conformance keys use OpenSSH Ed25519 format. Signatures use the
standard SSHSIG envelope with distinct `bloom-release-archive-v1`,
`bloom-release-payload-v1`, and `bloom-macos-conformance-v1` namespaces.
Verification invokes the OS-owned `/usr/bin/ssh-keygen`; the privileged macOS
path never executes a Homebrew- or login-user-owned crypto implementation.

Every signed payload carries an `ARTIFACT_CLASS`. The default and ordinary
release class is `production`; it continues to reject every mainnet-canary
marker. The only other accepted class is `solana-mainnet-canary-v1`, selected
with `BLOOM_ARTIFACT_CLASS`, and it requires all canary markers in the Machine
binary while rejecting them anywhere else. It is a Linux-only,
non-production artifact. Verification and installation each require the
separate `BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE=true` opt in, and the Linux
installer records the class beside the installed instance configuration.

`verify-bundle.sh` verifies the detached signature and both the outer and
internal checksums before accepting the compatibility matrix or installers.
Production verification currently accepts Linux ELF bundles. The
non-production `macos-unix-principals-w0` claim accepts Mach-O binaries only
in its explicitly enabled disposable Darwin lane. The `test-unclaimed` marker requires the explicit
`BLOOM_ALLOW_TEST_UNCLAIMED=true` override at build, verification, and install;
neither test claim can be advertised as production.

Production `macos-unix-principals` bundles are accepted only on Darwin and
only with a signed `bloom.macos-unix-conformance.1` report. The builder
requires an out-of-band SHA-256 pin for the conformance public key; the report
must bind the canonical release-subject digest, all three source revisions,
MUI-01 through MUI-12, installed AC-01 through AC-35, negative-access tests,
and the two-login lifecycle suite. The subject digest covers every packaged
binary, installer, compatibility input, plist, ACL, and packet-filter source
while excluding only the platform-claim value and the release/conformance
signature envelope. This avoids a self-referential archive digest while still
invalidating evidence after any security-relevant packaged input changes.
The final archive and internal release signature then bind the report and its
public key into the distributed artifact.

`macos-conformance-subject.sh` computes the canonical subject.
`sign-macos-conformance-report.sh` refuses to sign until each required
criterion has a regular `CRITERION.pass` evidence file containing that exact
subject digest; it never overwrites an existing report. The release operator
reviews those suite outputs and signs with the separately controlled
conformance key. `verify-macos-conformance.sh` verifies that signature,
criterion completeness, source revisions, subject binding, and—during
production assembly—the out-of-band conformance-key fingerprint.

For one candidate payload `C`, the disposable evidence matrix is:

- run the single-login W0 with `C` as its primary payload to produce MUI-01,
  MUI-02, MUI-03, MUI-04, MUI-07, MUI-08, MUI-10, MUI-11, MUI-12,
  `installed_ac_01_35`, and `negative_access`;
- on a two-GUI-login disposable VM, run the two-login W0 with a valid
  digest-distinct payload as the baseline, `C` as `UPGRADE_PAYLOAD`, and a
  distinct deliberately activation-failing payload as
  `FAILING_UPGRADE_PAYLOAD` to produce MUI-05, MUI-06, MUI-09, and
  `two_login_lifecycle`;
- merge only `.pass` files whose contents equal `C`'s canonical subject
  digest, then review and sign them with
  `sign-macos-conformance-report.sh`.

The signer refuses a mixture of evidence from different candidates.

`check-production-machine-binary.sh` is run by the standalone GitHub release
workflow and normal CI. It fails if an optimized Machine artifact contains a
developer-harness, unsafe debug-approval, or mainnet-canary marker. The release
workflow also builds from an explicit production feature set instead of
`--all-features`.

`triad-release-gate.sh` rejects modified or untracked release inputs, runs
locked fmt, clippy, and tests in all three sibling workspaces, builds release
binaries, assembles the bundle twice, verifies both, requires byte-identical
archives, matches the signed source revisions back to the three clean
workspaces, executes each extracted production binary, then reruns all three
workspace suites with the verified bundle bound as acceptance input.
`--test-signing-key` is CI-only; production invocation must set
`TRIAD_RELEASE_SIGNING_KEY`.

`solana-mainnet-canary-release-gate.sh` is the corresponding bounded canary
gate. It first builds and scans the ordinary incapable production Machine,
then deliberately builds the labeled canary Machine, proves the production
bundle path refuses it, assembles the signed canary bundle twice, verifies
byte identity and fail-closed opt-in behavior, runs the canary protocol and
transfer suites, and installs the exact extracted bytes. Its
`--test-signing-key` mode is CI-only; a candidate for fund testing requires
the reviewed release key and emits the archive and Machine SHA-256 values.

Before compiling, `check-machine-authority-boundary.sh --require-clean`
resolves every entry in `machine-production-feature-sets.tsv` with locked
Cargo metadata and walks the normal/build edge closure from the exact Machine
root. It rejects legacy authority crates, concrete local/custody signer
implementations, and authority-restoring resolved features; dev-dependencies
are not treated as production edges. The same gate checks the reachable
production source roots for forbidden authority markers and files. There are
no file-wide source-marker exceptions: a forbidden marker anywhere in a
production source root fails the build. Bundle assembly independently rejects forbidden
paths, printable markers, and retained Machine symbols, so stripping symbols
or changing one source spelling cannot substitute for the Cargo graph proof.
Debug and accepting-test artifacts remain forbidden across the entire bundle.
Legacy authority markers, files, and symbols are scoped to the Machine
executable and explicit Machine-owned payload roots; conforming custody and
private-signer implementations in `bloom-signer` are not false positives.
The installed macOS acceptance additionally runs the packaged `bloom serve`
Machine against a same-principal hostile Broker socket and an accessible
hostile Signer sentinel, proving prompt fail-closed/degraded behavior, no
direct Signer connection, and no legacy Machine authority state.

Fault-injection acceptance tests remain separately linked test executables:
putting fault hooks into the production services would violate AC-20. Their
post-extraction rerun is bound to the exact clean source revisions recorded in
the signed bundle; process/artifact acceptance additionally executes and
inspects the extracted production binaries.

Linux instance configuration fixtures are site-specific security inputs and
are deliberately not reusable release credentials. Test-only staged
installer fixtures use the following `config/` layout beside the extracted binaries:
`edge-manifest.json`, `broker.json`, `signer.json`,
`machine-identity.json`, `broker-identity.json`, `signer-identity.json`,
`revoke-identity.json`, `session-identity.json`, `installer-identity.json`,
and `provenance-catalog.json`. The macOS W0 bundle deliberately contains none
of these private files: its guarded live installer uses the same fresh
root-owned identity-generation path as the production Unix-principal claim.
On Linux,
`nts-servers.conf`. The last file contains at least two distinct reviewed NTS
host names, one per line. AWS credentials and `aws-kms-ip-allow.conf` are an
optional paired site overlay.

Production macOS enrollment does not accept that private fixture layout. Its
installed Machine binary generates fresh per-login Machine, Broker, Signer,
revoke-client, session, installer, audit, review, ceremony, and revocation
keys from the OS CSPRNG in a root-owned empty staging directory. It renders
only signed public templates from `installer/macos/config`, cross-pins the
public keys, signs the provenance catalog locally, atomically installs the
private outputs under their final principals, and removes the staging
directory. Bundle build and verification reject concrete private seeds and
identity-shaped JSON for a production macOS claim.

The macOS installer stages an immutable release before stopping any installed
triad. It then journals the old and new digests, stops every enrollment before
the shared atomic `current` switch, updates build-digest state, and validates
each installed triad before publishing all enrollments active. Failed activation
and a transaction found after interruption restore the old release, integration
files, and health. Custody and identity directories are never regenerated or
replaced during this sequence. The candidate state schemas must be at least the
installed schemas.

`uninstall --retain-custody` removes runtime integration while preserving the
exact service principals, private configuration, and custody state. `restore`
requires the exact signed retained release and publishes Machine access only
after authenticated health succeeds. Permanent purge uses the distinct
`delete-bloom-login-LOGIN_UID` confirmation and removes custody and principals.
Live configuration and identity rotation are not installer operations.
The Linux AWS KMS profile requires credentials and a non-wildcard reviewed
CIDR allowlist together; reinstall without that pair removes any prior
instance credential and egress drop-in.

The root-requiring macOS Unix-principal templates remain conformance inputs,
not a production platform claim. A release may claim
`macos-unix-principals` only after the disposable W0 lane proves the effective
UID/group, filesystem, launchd, listener, network, lifecycle, and rollback
boundaries and a digest-bound conformance report is included. The rootless
code-identity architecture remains a separate future profile.
