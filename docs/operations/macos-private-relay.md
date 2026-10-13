# macOS Private Relay compatibility and sandbox plan

## Immediate release contract

Bloom no longer installs or enables macOS PF rules. Broker and Signer run as
separate Unix service accounts with their existing filesystem and socket
permissions, authenticated RPC, custody, policy and session controls. Their
optional `network_containment` configuration is null. **This release does not
provide OS-enforced network isolation for Broker or Signer.** Removing the PF
boundary permits a compromised service to initiate network traffic; it does
not grant Machine access to service keys or authorization to sign.

The root monitor remains necessary for restarting services after a login
session returns. Its legacy job, CLI and telemetry names are retained for
upgrade compatibility. It no longer uses PF and reports `available: false`,
`network_enforcement: "none"`, and a zero legacy anchor digest. It never
fabricates a healthy network attestation. Current Broker configuration does
not consume that attestation. Consequently, a conflicting listener remains a
fatal startup error but is classified as foreign or unverifiable, including
when another Bloom login owns it. A future Broker change can separate this
public listener observation from the retired network guard.

## Why PF broke Private Relay

Apple's XNU `pf_check_compatible_rules()` classifies nonempty custom anchors.
`pf_process_compatibilities()` marks `NET_FILTER_EVENT_PF_PRIVATE_PROXY`
incompatible when PF is enabled and custom rules exist. Rule matching by UID,
port or destination does not change that classification. Bloom's old rules
blocked all Signer TCP/UDP egress and all Broker egress except TCP replies from
its loopback ceremony listener. Their presence triggered the host-wide check.

Sources: [Apple's PF classification](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L10593),
[private-proxy compatibility check](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c#L4697),
and [Apple's Private Relay support article](https://support.apple.com/en-us/102022).

## Migration and recovery

The new signed installer handles fresh installation, repair, upgrades and
restore. Existing service JSON is migrated in place, preserving custody and
identity fields. Shared-release upgrades migrate every enrolled login.

After authenticated activation succeeds, cleanup discovers old Bloom UIDs in
managed `/etc/pf.conf` blocks, `/etc/pf.anchors/com.bloom.triad.UID` files, and
the loaded `com.bloom.triad` namespace, including orphaned enrollments. It
flushes only `com.bloom.triad/UID` filter rules, removes the corresponding
managed blocks and files, and preserves unrelated configuration. Uninstall
cleans only the selected login, so another still-old enrollment keeps its
boundary. Malformed managed blocks and failed PF operations fail the installer
and retain evidence for a retry. A same-release repair retries cleanup.

Cleanup does not reload `/etc/pf.conf`, flush global rules or states, or
change PF's enabled state. Empty live anchor references may remain until a
reboot; without custom rules they do not trigger the private-proxy check.
Old installers discarded their `pfctl -E` tokens. Those references cannot be
safely attributed to Bloom and are not released; enabling PF alone is not the
incompatibility condition. Other products' custom rules may still prevent
Private Relay from working.

Cleanup occurs after successful activation so a failed upgrade can restore
its previous configuration and still-loaded rules. After successful cleanup,
installing an old release or running its installer can reintroduce PF; recovery
should use the new installer. Neither old binaries nor historical custody
archives are automatically modified.

## Validation

Automated regression coverage uses the actual cleanup function with a mocked
PF command: multiple enrollments, disk and kernel orphans, repeat cleanup,
per-login uninstall, foreign rule preservation, malformed blocks, symlinks,
PF failures, staged roots, and real macOS JSON migration. Staged installer
lifecycle tests cover install, repair, upgrade, retain, restore and purge.

Before release, run the live installer on a disposable macOS host with iCloud+
and Private Relay enabled. Test both a fresh install and migration from the
previous release, including two enrollments and a failed activation. Confirm:

- Private Relay stays active on fresh installation and recovers after migration.
- Bloom's loaded filter rules and persistent managed blocks are absent.
- Unrelated system/vendor PF rules and enable references remain unchanged.
- Authenticated triad health, signing, logout/login and service restart work.
- A subsequent repair and reboot do not reintroduce rules.

The optional W0 harness verifies PF retirement and emits `pf_retirement.pass`,
not the old MUI-07 network-isolation claim. An unsigned VM without iCloud+
cannot establish actual Private Relay behavior; mocked tests establish command
scope and migration semantics, not Apple's notification timing.

## Future process sandboxing

An executable with no network entitlements is **not** network-restricted unless
App Sandbox is enabled. Entitlements are embedded in the executable's code
signature, not its launchd plist. The intended Signer entitlement set starts
with `com.apple.security.app-sandbox = true` and omits both
`com.apple.security.network.client` and `com.apple.security.network.server`.
Broker additionally needs `com.apple.security.network.server = true` for its
approval listener and omits the client entitlement. TCP server permission
permits replies on accepted connections; it is not restricted to one address
or port. See [Apple's server entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.server).

Implement this in separate, reviewable phases:

1. **Signed sandbox prototype.** Build real Broker and Signer helpers with App
   Sandbox. Start with existing Unix accounts and storage where supported;
   establish whether launchd activation, container initialization, storage,
   Keychain and authenticated Unix sockets work in that packaging. Do not
   assume entitlements are a drop-in change to the current bare binaries.
2. **Boundary proof.** Test the exact signed helpers and subprocesses for IPv4,
   IPv6, TCP, UDP, DNS and loopback restrictions, prohibited alternate launch
   paths, missing/modified entitlements, and code substitution. Signer must have
   no network authority. Broker must serve the canonical approval origin and
   fail outgoing connections. Resolve the broader server entitlement with a
   reviewed listener design; do not claim fixed-port equivalence without proof.
3. **Release integration.** Add stable Developer ID signing identities,
   entitlement verification, Hardened Runtime, notarization and packaged helper
   validation. Replace the optional PF guard with explicit sandbox enforcement
   validation, without an unsandboxed fallback. Test install/upgrade/rollback,
   custody preservation and Private Relay on supported macOS versions.
4. **Rootless deployment separately.** Evaluate the existing
   [rootless code-identity design](../specs/2026-07-30-macos-rootless-code-identity-isolation.md)
   for App Groups, service-private Keychain groups and SMAppService activation.
   Its identity and storage migration is a larger change than replacing PF and
   needs its own threat-model and disposable-host acceptance review.

Until these gates pass, documentation and health reporting must continue to
state that macOS service network containment is absent.
