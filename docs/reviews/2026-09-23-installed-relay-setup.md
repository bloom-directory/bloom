# Installed relay setup correction

The 0.4.0 RC installed and passed authenticated Triad health, but its remote
surface remained unprovisioned. Both installers invoked Signer administration
without supplying the relay control CA and allocation-receipt verification key.

The signed release now includes the reviewed public deployment pins. During
installation, before services activate, an installer-only renderer fills a
missing/null Signer receipt pin and creates private root-owned relay trust
configuration. It preserves all unrelated configuration, matching existing pins,
service principals, wallet state and installation identities. Different existing
pins fail closed; reinstall is not an implicit trust-rotation mechanism.
The renderer performs no network or Signer RPC and uses existing serde_json,
rustix and tempfile dependencies. Signer's privileged client still owns enrollment
and assignment submission; Broker still owns ACME, TLS keys and its tunnel.

Signer `2ea4a8c49636bcfbc482033b8923cd4e364c6b13` checks trust configuration and
local service availability before creating administrative identity state. It
persists the allocation operation before creating a new key and syncs the key's
directory before enrollment. This closes a first-attempt failure window without
weakening the guard against allocating from an ambiguous pre-existing identity.
Broker `62d2bbc655c785d906e78526fe267df9518edfa6` pins that Signer.

Local evidence:

- 26 Signer binary tests and strict package/all-target Clippy pass, including
  missing-config/no-identity and durable-operation interruption regressions.
- 72 Machine binary tests pass before dependency-only repinning; all four trust
  installation regressions also pass with the final pins. They cover unchanged
  unrelated fields, idempotent reinstall, interrupted setup, pin/CA conflict,
  private permissions and symlink rejection.
- 52 Broker W5 ceremony tests pass using Node 26; the fixed-port listener test is
  reserved for CI because the real installed Broker owns 18734.
- 42 macOS/shared release tests pass, including reproducible signed bundles;
  the bundle test verifies the packaged trust bytes against the reviewed inputs.
- The Linux-specific shell tests require GNU tools. Running them directly on
  macOS fails on BSD `mv -T`; Linux CI remains required.

Installed acceptance is pending the owner's manual rerun of the corrected signed
installer. The owner declined direct agent reads/edits of installed Signer
configuration. No installed configuration or service was changed during this
work. Relay's deployment public receipt key was compared over SSH with the pinned
key; enrollment remains closed. A bounded operator enrollment window is required
for live acceptance. No production readiness or completed hostname assignment is
claimed by the local tests.

A key left without an allocation operation by an older unsuccessful candidate
remains deliberately fail-closed. Do not delete its state or create a new
operation on an ambiguous outcome: reconcile it with the original failure and
Relay records before attempting recovery. Fresh setup failures with the corrected
candidate preserve an exact retry operation.
