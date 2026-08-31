# Development guide

Bloom is developed as three cooperating executables:

```text
Machine <-> Broker <-> Signer
```

The processes may share a developer login, but their authority boundaries must
remain the same as production. Development features may simplify enrollment and
process startup. They must never add wallet custody, approval authority, or a
signing implementation to Machine.

Read these documents before changing a cross-process contract:

- [Triad process architecture](./docs/specs/2026-07-23-triad-process-architecture.md)
- [Wallet architecture](./docs/architecture/Wallet.md)
- [Solana native integration](./docs/architecture/Solana%20Native%20Integration.md)
- [Triad release package](./packaging/triad/release/README.md)

For the bounded mounted passkey workflow, read
[Local mainnet integration](./docs/local-mainnet-integration.md).

## Authority and repository ownership

| Process | Owns | Must not own | Repository |
|---|---|---|---|
| Machine | CLI, VFS, Petals, public projections, staging, simulation, broadcast, reconciliation | Wallet secrets, approval decisions, ceremony verification, local signing | `bloom` |
| Broker | Ceremony HTTP, WebAuthn verification, policy semantics, Sealed Approvals, authorization, public custody projections | Raw mnemonic or private-key persistence, signature creation | `bloom-broker` |
| Signer | Encrypted roots and keys, derivation, counters, replay protection, cryptographic signing | Transaction or Petal orchestration, user-facing action semantics | `bloom-signer` |

Machine talks only to Broker. Broker is the only authority peer allowed to talk
to Signer. Public data flowing back to Machine must be authenticated and must
not become a second source of authority.

The cross-repository dependency direction is:

```text
Signer -> Broker -> Machine
```

Put a fix in the repository that owns the invariant. Downstream repositories
normally receive only an exact revision pin and tests for their side of the
seam.

## Prerequisites

| Tool | Use |
|---|---|
| Rust 1.86 or newer | Workspace builds and tests |
| Foundry (`anvil`, `cast`, `forge`) | Local EVM integration tests |
| `jq` | Developer harnesses and shell tests |
| Agave `solana-test-validator` v3.0.0 | Optional validator-backed Solana tests |
| Docker | Optional Linux and Anvil environments |
| macOS NFS client | Mounted-VFS tests on macOS |
| Tart | macOS packaging and principal-isolation acceptance |

Keep the three repositories side by side by default:

```text
work/
├── bloom/
├── bloom-broker/
└── bloom-signer/
```

The launcher copies a canonical Machine config into its isolated developer
home. Create that config once before the first launch:

```sh
cargo run -p bloom -- init
```

To use a candidate-specific config instead, set
`BLOOM_TRIAD_DEV_MACHINE_CONFIG` to a regular, non-symlink file. Never point
`--machine-home` at the canonical `~/.bloom`; the launcher requires Machine
state to live inside the selected developer root.

Keep optional RPC endpoints and API keys in ignored local configuration. Never
put mnemonics, raw private keys, passkey PRF output, wallet passwords, ceremony
capabilities, or backend credentials in command arguments, environment
variables, Machine state, fixtures, or logs.

## Building

Common Machine builds are:

```sh
# Normal developer build, including the mount adapter.
cargo build -p bloom

# Portable production-shaped Machine.
cargo build -p bloom --no-default-features

# Explicit production feature set.
cargo build -p bloom --no-default-features --features mount

# Developer triad bootstrap. This feature is forbidden in release bundles.
cargo build -p bloom --no-default-features \
  --features mount,triad-dev-harness

# Optional heavy revert-decoder fallback.
cargo build -p bloom --no-default-features \
  --features mount,bytecode-decompile
```

Build Broker and Signer from their own repositories. Release artifacts must be
built through `packaging/triad/release/`; a locally compiled set of binaries is
not a release candidate.

## The efficient triad workflow

Use the cheapest loop that still crosses the boundary you changed.

### Loop 1: owning-repository tests

Most work should stay here. Run the affected package or named test while
editing. Before publishing the owning repository, run its format, clippy, and
workspace test gates.

Do not start overlapping Cargo commands in one target directory. Separate
repositories can build concurrently. Separate worktrees of one repository need
distinct `CARGO_TARGET_DIR` values.

### Loop 2: stable services, developer-managed Machine

Use `--services-only` for repeated Machine, CLI, VFS, daemon, or Solana changes.
It keeps real Broker and Signer services running while you rebuild and restart
Machine yourself. No kernel mount or sudo rule is needed.

Terminal 1:

```sh
mkdir -p "$HOME/.bloom/triad-dev/machine-home" /tmp/bloom-triad-logs

scripts/triad-dev-launch.sh \
  --developer-root "$HOME/.bloom/triad-dev" \
  --machine-home "$HOME/.bloom/triad-dev/machine-home" \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready \
  --services-only
```

Terminal 2:

```sh
source /tmp/bloom-triad-logs/triad.env
cargo build -p bloom --no-default-features \
  --features mount,triad-dev-harness
bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"
```

Stop and restart only Machine between edits. Restart the launcher when the
Broker or Signer binary, their configuration, enrollment, or an authority
protocol changes.

### Loop 3: complete out-of-process triad

Use the full launcher for ceremonies, authenticated transport, process
lifecycle, end-to-end signing, and mounted-VFS behavior:

```sh
mkdir -p "$HOME/.bloom/triad-dev/machine-home" \
  /tmp/bloom-triad-mount /tmp/bloom-triad-logs

scripts/triad-dev-launch.sh \
  --developer-root "$HOME/.bloom/triad-dev" \
  --machine-home "$HOME/.bloom/triad-dev/machine-home" \
  --mount /tmp/bloom-triad-mount \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

Omit `--mount` unless the test specifically concerns the kernel adapter. Linux
mounts require a narrowly scoped noninteractive sudo rule for that exact
mountpoint. VFS commands and services-only mode do not.

The launcher uses real protocol implementations and authenticated triad
transport. The developer profile runs them under the same non-root login and
therefore makes no production principal-isolation claim. On Linux it installs
temporary per-user systemd socket units for Broker and Signer; an active
systemd user manager is required. Paths embedded in those units may contain
only ASCII letters, digits, and `_./:@+-`.

Linux also uses the reviewed `linux-chrony-nts` trusted-time profile. The host
clock must already be synchronized through the production two-source NTS
configuration; the developer harness does not replace it with unauthenticated
NTP.

The launcher writes public connection settings to
`/tmp/bloom-triad-logs/triad.env`. Source that file only in the terminal meant
to address this candidate. It places the selected debug Machine binary first
on `PATH`.

### Test the binaries you intended

By default the launcher discovers `../bloom-broker` and `../bloom-signer` and
builds their debug binaries. For other worktrees, build first and pin all three
binary paths explicitly:

```sh
cargo build -p bloom --no-default-features \
  --features mount,triad-dev-harness
cargo build --manifest-path ../BROKER_WORKTREE/Cargo.toml \
  -p bloom-broker --features triad-dev-harness
cargo build --manifest-path ../SIGNER_WORKTREE/Cargo.toml \
  -p bloom-signer --features triad-dev-harness

BLOOM_INTEGRATION_MACHINE_BIN="$PWD/target/debug/bloom" \
BLOOM_INTEGRATION_BROKER_BIN="$PWD/../BROKER_WORKTREE/target/debug/bloom-broker" \
BLOOM_INTEGRATION_SIGNER_BIN="$PWD/../SIGNER_WORKTREE/target/debug/bloom-signer" \
scripts/triad-dev-launch.sh \
  --developer-root "$HOME/.bloom/triad-dev" \
  --machine-home "$HOME/.bloom/triad-dev/machine-home" \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

Never infer the tested revisions from directory names. Record them:

```sh
git -C ../SIGNER_WORKTREE rev-parse HEAD
git -C ../BROKER_WORKTREE rev-parse HEAD
git rev-parse HEAD
```

## Cross-repository changes

Advance a candidate left to right:

1. Implement and test the Signer invariant, then publish its immutable commit.
2. Update Broker's exact Signer/runtime pins once; test Broker and publish it.
3. Update Machine's exact Broker/runtime pins once; test the Machine seams.
4. Run the out-of-process triad at the recorded three commits.
5. Run packaging and installed acceptance only after the candidate is frozen.

Commit each manifest and regenerated lockfile together. Do not repeatedly repin
downstream repositories while upstream code is moving. A new source commit
invalidates evidence for that repository and every repository to its right,
but it does not invalidate already-passing upstream evidence.

Before integration, check the three worktrees and revisions in one pass:

```sh
git -C ../bloom-signer status --short
git -C ../bloom-broker status --short
git status --short
git -C ../bloom-signer rev-parse HEAD
git -C ../bloom-broker rev-parse HEAD
git rev-parse HEAD
```

When concurrent feature branches exist, use a combined integration branch that
is demonstrably descended from the required Signer, Broker, BIP39, and chain
heads. Do not merge an independent `master`-based implementation into the
middle of an active custody stack or reimplement an upstream fix downstream.

## BIP39 and derived-account development

Mnemonic import is a Broker-hosted owner ceremony. The CLI starts the ceremony;
the recovery phrase is entered only in the browser:

```sh
bloom wallet import imported-wallet
```

There is no mnemonic CLI argument and no import `--profile` flag. The current
profile accepts an English BIP39 mnemonic without a passphrase. Import creates
the canonical EVM child at `m/44'/60'/0'/0/0`.

Allocate a Solana child explicitly:

```sh
bloom wallet account-allocate imported-wallet \
  --profile bip44-solana-slip10-ed25519-v1
bloom wallet accounts imported-wallet
bloom wallet address imported-wallet --profile solana
bloom vfs cat /wallets/imported-wallet/accounts.json
```

Solana uses hardened SLIP-10 Ed25519 paths of the form
`m/44'/501'/<account>'/0'`. Machine sees only authenticated public account
projections. Every signing path must select a child by an exact `KeyRef`
containing its public-key fingerprint and derivation path. Projection order,
"first matching child", and an unqualified fallback are not authority.

After more than one Solana child exists, select addresses by fingerprint and
retire accounts through the Broker-hosted authority ceremony:

```sh
bloom wallet address imported-wallet --profile solana \
  --fingerprint <full-or-unique-prefix>
bloom wallet account-retire imported-wallet \
  --fingerprint <full-fingerprint>
```

Complete the ceremony URL printed by allocation or retirement before expecting
the authenticated account projection to change.

Raw secp256k1 migration is a separate explicit ceremony:

```sh
bloom wallet import migrated-wallet --raw-private-key
```

It creates an imported scalar wallet, not a BIP39 root, and cannot derive a
Solana account.

## Solana development

Solana is native Machine functionality, not a Petal. The implementation is
split between:

| Area | Location |
|---|---|
| RPC, endpoint health, genesis verification, reads | `crates/bloom-solana` |
| Durable transfer outbox, signing orchestration, broadcast, reconciliation | `crates/bloom-solana-tx` |
| Chain construction and reconciler lifecycle | `crates/bloom-daemon` |
| Account-aware VFS reads and outbox dispatch | `crates/bloom-vfs` |
| Public account projections and Broker protocol | `crates/bloom-machine-client` |

The mounted route stays consistent with EVM:

```text
/wallets/<wallet>/chains/<chain>/
├── accounts/<full-fingerprint>/{address,balance,balance.raw,balance.json}
└── outbox/{new.tx,pending,sent,failed}
```

Listing accounts and reading addresses use Broker projections and do not call a
Solana node. Balance and chain-status reads use RPC. Chain-level balance aliases
are allowed only when exactly one compatible child is active; ambiguity must
name the account-specific paths and fail closed.

Broadcast requires `allow_broadcast = true` and a pinned
`expected_genesis_base58`. Every configured endpoint must prove that genesis at
staging and again before the single send attempt. A transport ambiguity is
reconciled by signature; it is never handled by blindly rebroadcasting.

Use the short Solana test ladder:

```sh
cargo test -p bloom-solana
cargo test -p bloom-solana-tx
cargo test -p bloom-vfs
cargo test -p bloom-it --test solana_workflow -- --ignored --nocapture
```

For validator-backed coverage, start the pinned Agave v3.0.0 validator used by
`.github/workflows/solana-validator.yml`, then run:

```sh
SOLANA_VALIDATOR_HTTP=http://127.0.0.1:8899 \
  cargo test -p bloom-solana-tx --test local_validator -- \
  --ignored --nocapture

cargo test -p bloom-it --test solana_multi_account -- \
  --ignored --nocapture
```

`local_validator` reads `SOLANA_VALIDATOR_HTTP`; `solana_multi_account`
intentionally targets the validator at `http://127.0.0.1:8899` directly.

Mainnet uses the same transaction path and remains fail closed. Do not add a
second mainnet signer, bypass ceremony approval, weaken genesis checks, or move
chain-specific custody into Machine.

## General local operation

Machine may run without Broker for cached public reads, unsigned staging, and
simulation where the public inputs exist:

```sh
BLOOM_HOME=/tmp/bloom-machine cargo run -p bloom -- status
BLOOM_HOME=/tmp/bloom-machine cargo run -p bloom -- \
  vfs cat /chains/anvil/head/number
```

Signing, custody, approval mutation, and policy mutation must fail promptly
when Broker or Signer is unavailable. They must never restore a local authority
path.

The bounded mounted integration runner is:

```sh
scripts/local-mainnet-integration.sh --wallet test-wallet
```

Its preflight proves generic Petal-scoped derivation and payload signing. It
does not submit a venue order. Installed Petals remain external immutable
packages; do not patch Machine to preserve a retired Petal authority ABI.

## Environment variables

| Variable | Purpose |
|---|---|
| `BLOOM_HOME` | Machine-owned state root |
| `BLOOM_TRIAD_DEV_ROOT` | Persistent developer Broker/Signer enrollment and state |
| `BLOOM_TRIAD_DEVELOPER_ROOT` | Explicit same-UID developer enrollment root |
| `BLOOM_BROKER_SOCKET` | Authenticated Machine-to-Broker endpoint |
| `BLOOM_MACHINE_IDENTITY` | Machine transport identity file |
| `BLOOM_EDGE_MANIFEST` | Signed authority-edge manifest |
| `BLOOM_PROVENANCE_CATALOG` | Signed Petal/operation provenance catalog |
| `BLOOM_INTEGRATION_MACHINE_BIN` | Exact Machine binary for the launcher |
| `BLOOM_INTEGRATION_BROKER_BIN` | Exact Broker binary for the launcher |
| `BLOOM_INTEGRATION_SIGNER_BIN` | Exact Signer binary for the launcher |
| `BLOOM_TRIAD_DEV_MACHINE_CONFIG` | Canonical config copied into a new developer Machine home |
| `BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE` | Install the deterministic authority fixture when set to `1` |
| `BLOOM_TRIAD_DEV_BUILD_PETALS` | Set to `0` only for already-built reviewed Petals |
| `BLOOM_TRIAD_DEV_SOCKET_TIMEOUT_SECONDS` | Positive launcher socket timeout |
| `BLOOM_ANVIL_BIN`, `BLOOM_CAST_BIN` | Foundry test binary overrides |
| `BLOOM_MAINNET_RPC` | Optional read-only EVM endpoint |
| `SOLANA_VALIDATOR_HTTP` | Local validator endpoint for ignored Solana tests |
| `RUST_LOG` | `tracing-subscriber` filter |

Machine environment variables must not contain wallet private keys, mnemonics,
wallet passwords, passkey outputs, backend credentials, or Signer state.

## Test ladder

Platform-independent workspace gates:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Useful focused suites:

```sh
cargo test -p bloom-proto
cargo test -p bloom-machine-client
cargo test -p bloom-vfs
cargo test -p bloom-mount --features mount
cargo test -p bloom-daemon
cargo test -p bloom --test cli
cargo test -p bloom-petals --test triad_authority_fixture
scripts/test-local-mainnet-integration.sh
```

The full projection-fidelity acceptance starts the real triad, builds the
Broker ceremony driver, installs the deterministic authority fixture, and uses
a kernel mount. Run it only after focused suites pass and the mounted-launcher
prerequisites are installed:

```sh
scripts/acceptance.sh
```

Production boundary checks:

```sh
packaging/triad/release/check-machine-authority-boundary.sh
packaging/triad/release/test-machine-authority-boundary.sh
```

macOS packaging, service activation, peer-credential isolation, fixed ceremony
port behavior, and root-installed acceptance belong in a local disposable Tart
VM. Do not use CI as an interactive polling loop for those checks.

## Change-to-test map

| Changed area | Minimum local verification |
|---|---|
| Machine projections or Broker client | `cargo test -p bloom-machine-client` and affected CLI/VFS tests |
| BIP39 import, migration, or account lifecycle | Owning Broker/Signer suites, then `scripts/acceptance.sh` |
| VFS handlers or mount shape | `cargo test -p bloom-vfs`; add `bloom-mount --features mount` for adapter changes |
| EVM staging/signature assembly | `cargo test -p bloom-tx` and affected `bloom-it` tests |
| Solana RPC or genesis rules | `cargo test -p bloom-solana` |
| Solana staging, signing, outbox, or reconciliation | `cargo test -p bloom-solana-tx` and `solana_workflow` |
| Solana account selection | `solana_multi_account` against the local validator |
| Petal host interfaces | `cargo test -p bloom-petals --test triad_authority_fixture` |
| Triad protocol or transport | Relevant suites in all three repositories, then full launcher |
| Machine authority boundary | Both release boundary scripts and production feature checks |
| macOS packaging or isolation | Local Tart VM packaged acceptance |

## Debugging the triad

The launcher writes `machine.log`, `broker.log`, `signer.log`, and `session.log`
under its log directory. Correlate a failure by operation ID and authenticated
receipt across processes. Do not copy ceremony capabilities or private input
into an issue or shared log.

Common failures:

| Symptom | Check |
|---|---|
| A fix appears to have no effect | Confirm the three `BLOOM_INTEGRATION_*_BIN` paths and recorded commits |
| Cargo appears hung | Look for another Cargo process sharing the target directory |
| Linux services never become ready | Confirm an active systemd user manager and inspect Broker/Signer logs |
| Ceremony cannot bind | Check port `18734` and stop the older developer launcher |
| Enrollment is rejected as stale | Start with a new developer root; do not mutate custody files by hand |
| Wallet/account data is missing | Inspect the authenticated Broker projection and its freshness, not a legacy Machine wallet store |
| Solana broadcast is disabled | Check `allow_broadcast`, the pinned genesis, every endpoint, and chain status |
| Solana child selection is ambiguous | Use the full fingerprint/account path; never select by list position |

Useful public diagnostics include:

```sh
bloom vfs cat /status/daemon.json
bloom vfs cat /status/chains/<chain>/status.json
bloom vfs cat /status/outbox/pending_count
bloom vfs cat /status/backends/summary.json
bloom vfs cat /wallets/<wallet>/accounts.json
```

Production Machine state is key-free. Broker and Signer use separate,
packaging-selected roots that Machine cannot access. A missing projection or an
unavailable authority service is never permission to seed, migrate, or reopen
an obsolete Machine wallet, approval, challenge, authorization-session, or
decrypted-key cache.
