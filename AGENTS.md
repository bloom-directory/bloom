# Bloom contributor and agent guide

Use [DEVELOPMENT.md](./DEVELOPMENT.md) for setup and cross-repository workflows,
and [TESTING.md](./TESTING.md) for validation gates. The instructions exposed
inside a running VFS are a separate operator contract in
[agent-guidance.md](./crates/bloom-vfs/src/docs/agent-guidance.md).

## Authority and ownership

Read the relevant architecture before changing a cross-process contract:

- [Triad process architecture](./docs/specs/2026-07-23-triad-process-architecture.md)
- [Wallet architecture and account identity](./docs/architecture/Wallet.md)
- [Solana native integration](./docs/architecture/Solana%20Native%20Integration.md)
- [Triad release package](./packaging/triad/release/README.md)

Historical plans and implementation logs are evidence, not authority, when
they conflict with current code or the documents above.

Machine talks to Broker; only Broker talks to Signer. Fix an invariant in its
owning repository:

| Repository | Owns |
|---|---|
| `bloom` (Machine) | CLI, VFS, Petals, public projections, staging, simulation, broadcast, reconciliation |
| `bloom-broker` | Ceremony verification, policy semantics, Sealed Approvals, authorization |
| `bloom-signer` | Encrypted wallet custody, derivation, counters, replay protection, cryptographic signing |

Preserve these boundaries:

- Never add Bloom wallet secrets, a wallet-signing implementation, local
  approval authority, or a direct Signer connection to Machine. This custody
  rule does not prohibit authenticated transport identities or Petal-owned
  application keys described in the wallet architecture.
- Never use a cached projection, list position, address alias, or Petal claim
  as authority. Account-sensitive operations bind the exact public-key
  fingerprint and derivation path in `KeyRef`; ambiguity fails closed.
- Never restore retired Machine keystores, approval stores, or local signer
  fallbacks when an authority service is unavailable.
- Wallet secret input belongs in the Broker-hosted ceremony, not Machine RPC,
  VFS writes, shell arguments, environment variables, or logs. Acceptance
  fixtures use disposable test inputs through the reviewed test harness.
- Development mode may share a UID, but must retain the real process and
  protocol boundaries. `triad-dev-harness` is forbidden in release bundles.
- Solana is native Machine functionality. Preserve its genesis checks, exact
  account selection, and reconciliation after ambiguous sends; never blindly
  retry a broadcast.

## Development and verification

Use the [owner-to-integration workflow](./DEVELOPMENT.md#cross-repository-changes)
and the [change-to-test map](./TESTING.md#change-to-test-map). Run the smallest
check that exercises the change, then the broader gates required by its scope.
Mounted Markdown is embedded in the VFS and has executable documentation tests.

Use separate target directories for concurrent Cargo builds. Select the exact
Machine, Broker, and Signer binaries for integration work, and record their
full commits with the evidence. Follow the launcher's
[repository discovery requirements](./DEVELOPMENT.md#test-the-binaries-you-intended);
binary overrides do not replace those requirements.

## Working agreement

- Preserve unrelated edits and untracked files. Investigate unexpected
  overlapping changes before continuing.
- Do not discard work with destructive Git commands without explicit direction.
  Request explicit approval immediately before recursive forced deletion.
- Use the session's available agent tools only when delegation is authorized.
  Stop only processes you own by their specific handle or recorded PID.
- Use `$VFS_SESSION_DIR` for scratch when provided; preserve shared directories.

Credential-bearing files include `.env` variants, SSH and GPG private keys,
cloud credentials, password stores, token-bearing startup files, private key
files, and Codex authentication data. Before reading one, request narrow
one-off permission for the exact path and explain why. Never bypass a denied
path by copying, encoding, shell expansion, or another tool. Do not enumerate
secret-valued environment variables.
