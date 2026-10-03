# Direct Signer administration

The installed administrative interface is
`bloom-signer admin <command> --login-uid UID`. Linux and macOS installers call
the installed Signer binary directly during their existing elevated step.
The separate `bloom-ceremonies` script, packaging entries and CLI symlink are
removed. No migration or compatibility wrapper is included for unmerged
candidates.

Installed manual callers explicitly elevate the binary. Root is required for
administrative operations, not for help or for executing the binary itself.
The Signer daemon continues running under its dedicated unprivileged principal.
The existing peer-credential checks and root-only administration storage remain
the authority boundary. The CLI selects fixed installation paths for
`--login-uid`; it does not automatically elevate.

The developer harness keeps `--signer-uid UID`, its sourced path environment,
and its compiled, validated same-UID exception. Installation login UID and
Signer service UID are distinct inputs, not interchangeable account identities.

Signer candidate: `839c083d5ed51febedec3d2afa827f2a9225aea1`. Broker is repinned
at `1cc6cb748ab81c5337c33c41e61b05ba2e887a96`; its all-target check passed.

## Signer evidence

- All-features Signer binary tests: 24 passed; process-hardening tests passed.
- Strict all-features Signer binary Clippy passed.
- Built-binary top-level, admin and provision help exited successfully with an
  empty environment and no elevation. Non-root installed administration failed
  on the effective-UID check before installation metadata access; explicit-path
  production administration also requires root.
- Clap supplies argument parsing and help. The small effective-UID helper uses
  the OS syscall inside the existing audited hardening crate. No shell parser,
  automatic elevation or custom privilege mechanism is introduced.
- Parent review and a separate read-only review found no authority regression.

## Installer evidence

- Direct invocation tests execute each installer's provisioning helper against
  a stub Signer, verify exact arguments, handle paths containing spaces, and
  check the explicit `sudo` retry message after failure.
- Locked Machine release tests on macOS: 40 passed, 21 Linux-named cases filtered.
- Staged macOS CLI lifecycle: passed, including fresh install, upgrade,
  retain/restore, multiple logins and unrelated CLI collision checks.
- Supplemental Linux release-test source in the focused non-root container
  harness: 49 passed, 11 macOS-named cases filtered. This is not a full locked
  Machine workspace or installed service test.
- Strict Clippy for the Machine release test target, formatting and shell
  syntax checks passed.
- Hosted-relay developer launcher fixture tests passed with the existing
  `--signer-uid` invocation.

Actual installed macOS NFS acceptance remains unresolved, and the two-login
workflow remains deferred. The running developer triad and relay infrastructure
are not modified by these source and packaging changes.
