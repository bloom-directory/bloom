# Development guide

This document covers building, testing, and debugging the current triad-based
Bloom implementation. Production authority is always split across Machine,
Broker, and Signer. Development convenience must not compile wallet custody,
approval verification, or signing into Machine.

For the manual mounted passkey workflow, read
[`docs/local-mainnet-integration.md`](./docs/local-mainnet-integration.md).
For the production process and security contract, read
[`docs/specs/2026-07-23-triad-process-architecture.md`](./docs/specs/2026-07-23-triad-process-architecture.md).

## Prerequisites

| Tool | Use |
|---|---|
| Rust 1.85 or newer | Workspace builds and tests |
| Foundry (`anvil`, `cast`, `forge`) | Local EVM integration tests |
| `jq` | Developer harnesses and shell tests |
| macOS NFS client | Real mounted-VFS tests on macOS |
| Docker | Optional Linux and Anvil test environments |
| Tart | Optional local macOS packaging/isolation VM |

Keep optional network endpoints and API keys in a gitignored environment file.
Never place wallet secrets, recovery material, or passkey PRF output in shell
variables, command arguments, Machine state, or test logs.

## Building

```sh
# Entire workspace
cargo build --workspace

# Production-key-free Machine CLI
cargo build -p bloom --no-default-features

# Machine with the NFS mount adapter
cargo build -p bloom --no-default-features --features mount

# Optional revert-decoder fallback
cargo build -p bloom --no-default-features --features bytecode-decompile
```

Broker and Signer live in the sibling `bloom-broker` and `bloom-signer`
repositories. Build and test them from those repositories. Machine must never
connect to Signer directly; Broker is its only authority peer.

Release bundles must be built through the triad packaging scripts so resolved
dependency, feature, marker, identity, socket, and runtime boundary checks run
against the packaged artifacts.

## Running locally

### Read, stage, and simulate

Machine may run without an available Broker for public cached reads, unsigned
staging, and simulation where the required public inputs exist:

```sh
BLOOM_HOME=/tmp/bloom-machine cargo run -p bloom -- status
BLOOM_HOME=/tmp/bloom-machine cargo run -p bloom -- vfs cat /chains/anvil/head/number
```

Signing, approval mutation, policy mutation, and custody must fail promptly
when Broker or Signer is unavailable. They never restore a local authority
path.

### Out-of-process triad developer harness

The supported passkey and signing workflow starts real Machine, Broker, and
Signer protocol implementations as separate processes:

```sh
mkdir -p ~/.bloom/triad-dev/machine-home \
  /tmp/bloom-triad-mount /tmp/bloom-triad-logs

scripts/triad-dev-launch.sh \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --mount /tmp/bloom-triad-mount \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

The developer profile runs all processes under the current non-root login UID
on Linux or macOS and makes no production principal-isolation claim. On Linux,
Broker and Signer use temporary per-user systemd socket and service units so
the unchanged production listener code consumes real named socket-activation
descriptors. The login must therefore have an active systemd user manager. For
a dedicated persistent eval account, an administrator can enable it once with
`loginctl enable-linger LOGIN_USER`; ordinary interactive logins usually
already have an active user manager. Linux developer paths used by these units
must contain only ASCII letters, digits, and `_./:@+-`.

Linux kernel mounts additionally require a narrowly scoped noninteractive sudo
rule for the exact mountpoint; VFS-only and services-only modes need no mount
privilege. The temporary user units and sockets are removed when the launcher
exits.
Linux uses the reviewed `linux-chrony-nts` trusted-time profile and therefore
requires a synchronized host clock backed by the production two-source NTS
configuration; the developer harness does not substitute unauthenticated NTP.
It still uses authenticated triad
transport, Broker-owned ceremony HTTP, genuine WebAuthn, and Signer-held keys.
The developer feature is rejected by production release packaging.
Set `BLOOM_TRIAD_DEV_BUILD_PETALS=0` only when the selected integration Petal
has already been built from its reviewed revision. Bloom still prepares,
hashes, provenance-enrolls, and validates the package before installation.

The launcher writes public authenticated connection settings to
`/tmp/bloom-triad-logs/triad.env`. Source it only in a second developer shell.
This prepends the selected debug binary directory to `PATH` in that terminal,
so use `bloom` directly for commands against the running Machine:

```sh
source /tmp/bloom-triad-logs/triad.env
bloom wallet new test-wallet
```

Wallet registration, import, credential changes, policy updates, delegated-key
derivation, and signing all use Broker-originated ceremonies and Signer
receipts. Sensitive import or recovery input belongs only in the Broker-hosted
browser workflow.

### Mounted passkey integration

The bounded manual runner mounts Machine's VFS and drives the requested action
through ordinary mounted filesystem reads and writes:

```sh
scripts/local-mainnet-integration.sh --wallet test-wallet
```

Preflight runs the generic Petal-scoped derivation and payload-signing fixture.
It does not submit a venue order. Live Polymarket mode is separately explicit
and remains blocked while the pinned external Petal imports the retired
hash-only guest ABI; the runner fails before draft creation rather than adding
a compatibility signer.

The former built-in venue routes are retired. Test Hyperliquid only through an
installed external Petal when a compatible package is available.

## Environment variables

Common current variables are:

| Variable | Purpose |
|---|---|
| `BLOOM_HOME` | Machine-owned state root |
| `BLOOM_TRIAD_DEV_ROOT` | Persistent developer Broker/Signer enrollment and state |
| `BLOOM_TRIAD_DEVELOPER_ROOT` | Explicit same-UID developer enrollment root used by launched processes |
| `BLOOM_BROKER_SOCKET` | Authenticated Machine-to-Broker endpoint |
| `BLOOM_MACHINE_IDENTITY` | Machine transport identity file |
| `BLOOM_EDGE_MANIFEST` | Installer/developer-signed edge manifest |
| `BLOOM_PROVENANCE_CATALOG` | Signed Petal provenance catalog |
| `BLOOM_ANVIL_BIN`, `BLOOM_CAST_BIN` | Foundry binary overrides for tests |
| `BLOOM_MAINNET_RPC` | Optional read-only live-network test endpoint |
| `RUST_LOG` | `tracing-subscriber` filter |

Machine environment variables must not contain wallet private keys, wallet
encryption passwords, passkey outputs, backend credentials, or Signer state.

## Tests

Run platform-independent tests locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Useful focused suites:

```sh
cargo test -p bloom-proto
cargo test -p bloom-machine-client
cargo test -p bloom-vfs
cargo test -p bloom-mount --features mount
cargo test -p bloom-daemon
cargo test -p bloom --test cli
cargo test -p bloom-it -- --ignored
```

Run the current developer-harness shell tests without a browser or mainnet:

```sh
scripts/test-local-mainnet-integration.sh
```

Run production boundary checks directly:

```sh
packaging/triad/release/check-machine-authority-boundary.sh
packaging/triad/release/test-machine-authority-boundary.sh
```

macOS packaging, service activation, peer-credential isolation, fixed ceremony
port behavior, and root-installed bundle acceptance belong in the local Tart
VM. Do not use GitHub Actions as a polling dependency for those checks.

## Debugging

### Logs

```sh
RUST_LOG=info bloom serve
RUST_LOG=bloom_daemon=debug,bloom_vfs=debug,info bloom serve
RUST_LOG=bloom_rpc=trace,info bloom status
```

The triad developer launcher writes separate `machine.log`, `broker.log`,
`signer.log`, and `session.log` files beneath its selected log directory. A
signing failure should be correlated by operation ID across those logs and
public receipts. Ceremony URLs and secret input must never appear in logs.

### Status and projections

Machine's VFS status tree is useful for public diagnostics:

```sh
bloom vfs cat /status/daemon.json
bloom vfs cat /status/chains/base/connected
bloom vfs cat /status/outbox/pending_count
bloom vfs cat /status/backends/summary.json
```

Wallet discovery, key references, credential summaries, and policy snapshots
come from authenticated Broker projections or Machine's explicitly stale
public cache. A missing Broker projection is not a cue to inspect or seed an
old wallet store.

### Machine state layout

Machine state is key-free:

```text
$BLOOM_HOME/
├── config.toml
├── addressbook.toml
├── audit.jsonl
├── run/
├── cache/                 # public projections and non-authority caches
├── blobs/
├── operations/            # idempotent Machine operation index
├── central_outbox/
├── outbox/
├── requests/
├── watch/
└── logs/
```

Production Machine must not create, open, migrate, or trust obsolete wallet,
approval, challenge, authorization-session, or decrypted-key-cache state.
Broker and Signer use separate packaging-selected roots inaccessible to the
Machine principal.

## Change-to-test map

| Changed area | Minimum local verification |
|---|---|
| Machine projections or Broker client | `cargo test -p bloom-machine-client` and affected CLI/VFS tests |
| VFS handlers | `cargo test -p bloom-vfs`; add `bloom-mount --features mount` for adapter changes |
| Transaction staging/signature assembly | `cargo test -p bloom-tx` and affected `bloom-it` tests |
| Petal host interfaces | `cargo test -p bloom-petals` plus the deterministic triad fixture |
| Triad transport/protocol | relevant protocol/transport suites in all three repositories |
| Machine authority boundary | both release boundary scripts and production feature checks |
| macOS packaging/isolation | local Tart VM packaged acceptance |

Installed Petals are tested in their own repositories and then installed by
immutable source revision into an isolated developer Machine home. Do not patch
an external Petal inside Machine to preserve a retired authority ABI.
