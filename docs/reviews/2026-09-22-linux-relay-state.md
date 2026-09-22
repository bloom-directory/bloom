# Linux relay state layout

The initial remote-ceremony release stores generated Linux relay material under
`/var/lib/bloom/<login-uid>`:

- `installer/admin`: root-owned administration key, allocation retry record,
  credential issuance state and ACME binding records.
- `broker/relay`: Broker-owned scoped credentials and metadata, control CA
  handoff, ACME account credentials/URI and TLS certificate/key bundle.

Both directories are mode 0700. Existing private-file checks and ownership
requirements remain in Signer and Broker. The systemd unit selects Broker's
directory with `BLOOM_BROKER_RELAY_STATE_DIR`, covered by its existing
`ReadWritePaths=/var/lib/bloom/%i/broker`. Broker gains no access to root-only
installer state. Explicit `remote_tls` configuration retains precedence.
Administrator settings and original trust-pin inputs remain under `/etc`.
macOS and the running developer triad retain their existing paths.

There is no migration or fallback for earlier unmerged relay candidates, as
requested by the repository owner. The older identity/configuration split is
tracked separately in [bloom#321](https://github.com/bloom-directory/bloom/issues/321).
This change reuses systemd tmpfiles/sysusers, the existing privileged wrapper,
and Broker's existing material loader. The small custom resolver only selects
the platform-provided default directory; it adds no storage or crypto mechanism.

Broker candidate: `99ea707486dc000c128d1353f5d35081f2c2e47a`; Signer unchanged at
`68f483eefb36d10a4227f01c4059494abc6ef402`.

## Validation

- Broker binary unit tests: 25 passed, one ignored; four new path-selection tests.
- Strict Clippy passed for the Broker binary and both changed Machine test targets.
- Formatting, shell syntax and diff checks passed.
- Locked Machine Linux packaging suite: 8 passed.
- Locked Machine release suite on macOS, excluding Linux-named cases: 41 passed.
- Linux activation/materialization regression: passed on macOS.
- Supplemental Linux execution of the unchanged release-test source: 50 passed,
  11 macOS-named cases filtered. This used a minimal Cargo harness with the
  actual API crates and runtime pin, running as a non-root user in a disposable
  Linux container; it is not the full locked Machine workspace build.
- A separate disposable Linux container ran real `systemd-sysusers` and
  `systemd-tmpfiles` on the package templates. Broker could write its relay
  directory, Signer and the login user could not read it, and Broker could not
  read root-only administration state. Reapplying tmpfiles preserved a fixture
  file. The actual elevated wrapper passed the expected paths and UIDs to a
  stub Signer. This proves filesystem layout/handoff, not live provisioning.
- The release compatibility test caught stale Signer references in the
  integration-test manifest; they now match the candidate's Signer revision.

Fresh release CI and installed-service acceptance remain separate gates. The
known installed macOS NFS conformance limitation and deferred two-login test are
unchanged. No running developer state, relay server or production deployment
was modified by this change.
