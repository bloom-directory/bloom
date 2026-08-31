# Bloom contributor and agent guide

This file defines repository-specific rules for coding agents and contributors.
Use [DEVELOPMENT.md](./DEVELOPMENT.md) for the complete local workflow.

## Read authority before code

For cross-process, wallet, signing, policy, or chain work, read the relevant
source of truth before editing:

- [Triad process architecture](./docs/specs/2026-07-23-triad-process-architecture.md)
- [Wallet architecture](./docs/architecture/Wallet.md)
- [Solana native integration](./docs/architecture/Solana%20Native%20Integration.md)
- [Triad release package](./packaging/triad/release/README.md)

Historical plans and implementation logs are evidence, not authority, when
they conflict with current code or the documents above.

## Non-negotiable triad boundaries

```text
Machine <-> Broker <-> Signer
```

| Process | Authority |
|---|---|
| Machine | Public projections, Petals, orchestration, staging, simulation, broadcast, reconciliation, CLI, and VFS |
| Broker | WebAuthn ceremonies, policy semantics, Sealed Approvals, authorization, and public custody projections |
| Signer | Encrypted custody, derivation, counters, replay protection, and signatures |

The following changes are architecture violations:

- Adding a private key, mnemonic, PRF output, decrypted-key cache, or signing
  implementation to Machine.
- Letting Machine connect directly to Signer.
- Letting Machine originate or verify approval authority locally.
- Treating a cached projection, list position, address alias, or Petal claim as
  a substitute for an authenticated authority decision.
- Adding a compatibility path that restores retired Machine wallet, approval,
  challenge, policy-session, or local signer state.
- Logging or accepting private ceremony input through CLI arguments,
  environment variables, fixtures, or Machine RPC.

Development mode may run all processes under one UID, but it must use the real
processes and protocols. The `triad-dev-harness` feature is nonproduction
bootstrap only and must remain rejected by release packaging.

## Put changes in the owning repository

The dependency and integration direction is:

```text
Signer -> Broker -> Machine
```

Use this ownership rule:

| Change | Owning repository |
|---|---|
| Secret format, key derivation, backend signing, cryptographic counters | `bloom-signer` |
| Ceremony, policy interpretation, approval, semantic verifier, authorization | `bloom-broker` |
| CLI/VFS surface, projections, staging, chain RPC, broadcast, reconciliation | `bloom` |

Fix the invariant at its owner. Downstream code should add an exact revision
pin and seam coverage, not a second implementation. Advance cross-repository
candidates left to right and repin each downstream repository once after the
upstream commit is immutable. Commit manifests and lockfiles together.

Do not merge an unrelated `master`-based branch into the middle of an active
custody feature stack. Before building a combined candidate, prove that its
history contains the required Signer, Broker, BIP39, and chain heads.

## Work in the shortest honest loop

Use the smallest scope that exercises the changed boundary:

| Scope | Workflow |
|---|---|
| One crate or pure owner logic | Focused package or named test |
| Machine against unchanged authorities | `scripts/triad-dev-launch.sh --services-only`, then rebuild/restart Machine |
| Ceremony or cross-authority protocol | Full `scripts/triad-dev-launch.sh` |
| Mount behavior | Full launcher with `--mount` |
| Production artifact or principal isolation | Release boundary scripts and disposable installed acceptance |

Do not run concurrent Cargo commands in the same target directory. When using
non-sibling worktrees, set `BLOOM_INTEGRATION_MACHINE_BIN`,
`BLOOM_INTEGRATION_BROKER_BIN`, and `BLOOM_INTEGRATION_SIGNER_BIN` so the
launcher cannot silently select stale binaries. Record all three full commits
with the test evidence.

## BIP39 and account rules

- `bloom wallet import <name>` starts the BIP39 browser ceremony. There is no
  mnemonic CLI argument and no import `--profile` flag.
- Mnemonic and raw-key input exists only inside the Broker-hosted browser flow
  and is delivered to Signer through the protected ceremony path.
- The current BIP39 profile is passphrase-free. Do not add a passphrase field
  to Machine as a shortcut.
- Import creates the canonical EVM child at `m/44'/60'/0'/0/0`.
- V1 explicit allocation exposes Solana SLIP-10 Ed25519 children through
  `bip44-solana-slip10-ed25519-v1`.
- A raw secp256k1 import is an imported scalar wallet, not a BIP39 root, and
  cannot derive Solana children.
- Account selection must bind the exact public-key fingerprint and derivation
  path in `KeyRef`. Ambiguity fails closed and reports the candidates. Never
  select by projection order.
- Account allocation and retirement are authority ceremonies. Machine may
  project their public result but may not mutate root custody or account state.
- Retirement names the full public-key fingerprint. Allocation and retirement
  do not take effect in Machine projections until their Broker-hosted ceremony
  completes.

## Solana rules

Solana is an in-tree native chain integration, not a Petal:

| Responsibility | Code |
|---|---|
| RPC, endpoint health, genesis-bound reads | `crates/bloom-solana` |
| Staging, exact signing request, outbox, broadcast, reconciliation | `crates/bloom-solana-tx` |
| Runtime construction and reconciler | `crates/bloom-daemon` |
| Account-aware reads and outbox routes | `crates/bloom-vfs` |

Preserve these properties:

- Native transfers use Broker authorization and Signer custody. Do not add a
  Solana keystore or direct signer to Machine.
- The selected Ed25519 child is exact and survives staging, approval, signing,
  broadcast, and receipt reconciliation unchanged.
- `allow_broadcast` is necessary but insufficient. A pinned
  `expected_genesis_base58` and live agreement from every configured endpoint
  are required at staging and before broadcast.
- A signed transaction is sent once. Ambiguous transport outcomes reconcile by
  signature and must not trigger blind retry or endpoint failover.
- Account directory and address reads use projections only. Balance and chain
  status reads may call RPC. Do not turn directory listing into an RPC fanout.
- Chain-level balance aliases fail when several compatible children exist.
  Account-specific VFS paths use the full fingerprint; unique prefixes are
  input convenience only.
- Solana status reports `slot` and `block_height`; do not invent EVM-shaped
  block-number or finality semantics.

## Minimum validation by change

| Area | Minimum evidence |
|---|---|
| Machine/Broker projection | `cargo test -p bloom-machine-client` plus affected CLI/VFS tests |
| BIP39 or account lifecycle | Owning Broker/Signer suites, then `scripts/acceptance.sh` |
| Solana RPC/genesis | `cargo test -p bloom-solana` |
| Solana transaction lifecycle | `cargo test -p bloom-solana-tx` and ignored `solana_workflow` |
| Multi-account selection | Ignored `solana_multi_account` against the pinned local validator |
| VFS | `cargo test -p bloom-vfs` |
| Mount adapter | `cargo test -p bloom-mount --features mount` |
| Petal authority seam | `cargo test -p bloom-petals --test triad_authority_fixture` |
| Authority graph or production features | Both Machine authority-boundary scripts |
| Cross-process protocol | Relevant suites in all three repositories and the full launcher |

Run workspace format, locked clippy, and locked tests before presenting a
repository-wide candidate. Run packaging and installed acceptance only on a
frozen, clean three-repository candidate.

## General working agreement

- Work autonomously on routine tasks. Inspect local context, make low-risk
  assumptions, and complete the requested work without asking the user to pick
  implementation details.
- Ask only when required information cannot be discovered and different
  answers would materially change or endanger the result.
- Preserve unrelated user changes and untracked files. Stop if an unexpected
  overlapping change appears while working.
- Prefer `rg` for searches. Batch related terms and independent reads.
- Read the whole relevant file once. Filter large output and save spillover in
  `$VFS_SESSION_DIR/outputs/` when that environment is available.
- Keep edits focused. In VFS agent sessions use the provided `edit` helper for
  existing files and heredocs for new files; otherwise use the environment's
  patch tool.
- Check command exit codes. After mutation, run the smallest relevant check,
  then the broader gate required by the change map.
- Never use destructive Git commands to discard work unless the user explicitly
  requests them.
- Always request explicit user approval immediately before recursive forced
  deletion (`rm -rf`, `rm -fr`, split-flag equivalents, or equivalent APIs).

## Sensitive data

Credential-bearing files include `.env` variants, SSH and GPG private keys,
cloud credentials, password stores, token-bearing shell startup files, private
key files, and Codex authentication data.

Before reading one, request the narrow one-off permission for the exact path
and explain why it is required. Never bypass a denied path by copying,
encoding, shell expansion, or another tool. Do not enumerate secret-valued
environment variables. Ask only for the credential access genuinely required.

## Shared VFS agent sessions

When the session provides `$VFS_SESSION_DIR`, use it for scratch data, outputs,
and the mailbox. Other mounted directories may be shared snapshots; inspect
before mutating. Batch independent exploration commands because each turn
resends context.

Sub-agents, when explicitly requested, are started with `vfs-agent` in a
dedicated work directory and a recorded PID:

```sh
vfs-agent --work-dir workers/research --agent-name research \
  "bounded task description" --max-iterations 5 --token-budget 50000 &
echo $! > workers/research/pid
```

The task is positional, not `--task`. Stop only the exact recorded PID. Never
run `pkill -f vfs-agent` or `killall vfs-agent`; those commands can terminate
the current agent and unrelated workers.
