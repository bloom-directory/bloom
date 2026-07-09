# Development guide

Operator's manual for working on `bloom`: building, running, testing, and
debugging the daemon. The user-facing tour lives in [README.md](./README.md)
and [QUICKSTART.md](./QUICKSTART.md); this file covers the dev loop.

## Contents

1. [Toolchain and prerequisites](#toolchain-and-prerequisites)
2. [Building](#building)
3. [Running locally](#running-locally)
4. [Test suites](#test-suites)
   - [Rust unit tests](#rust-unit-tests)
   - [Rust integration tests](#rust-integration-tests)
   - [Dockerized tests (`tests/docker/`)](#dockerized-tests-testsdocker)
   - [Acceptance script (`scripts/acceptance.sh`)](#acceptance-script-scriptsacceptancesh)
   - [Playground (`scripts/play.sh`)](#playground-scriptsplaysh)
5. [Debugging](#debugging)
6. [Lint and format](#lint-and-format)
7. [Coverage map](#coverage-map): which suite tests which crate

## Toolchain and prerequisites

| Tool | Why |
|------|-----|
| Rust ≥ 1.85 | Pinned via `rust-toolchain.toml`. `rustup` installs it on first `cargo` run. |
| Foundry (`anvil`, `cast`, `forge`) | All anvil-backed integration tests, the acceptance script, and the playground. Override the binary paths with `BLOOM_ANVIL_BIN` / `BLOOM_CAST_BIN`. |
| `jq` | Acceptance script and Docker drivers. |
| Docker (compose v1 or v2) | Dockerized tests and `scripts/play.sh`. |
| Linux kernel NFS client | `--mount`/`--fork`/`--enso(-live)` Docker tests (requires `SYS_ADMIN`, `apparmor=unconfined`, `/dev/fuse`). |
| Optional API keys | `BLOOM_ETHERSCAN_KEY`, `BLOOM_ENSO_KEY`, `BLOOM_MAINNET_RPC` — populate `test.env` (gitignored) and `source` it. |

## Building

The workspace contains 26 crates (`Cargo.toml` `[workspace]`). Default builds
exclude the optional NFS mount adapter; opt in with the `mount` feature when
you need it.

```sh
# Debug build of every crate
cargo build --workspace

# Release binary (used by acceptance.sh and play.sh — lands at target/release/bloom)
cargo build --release -p bloom

# Daemon with the embedded NFS server (pulls embednfs as a git dep)
cargo build --release -p bloom --features bloom-daemon/mount

# Daemon with the heimdall bytecode-decompile fallback for revert decoding
# (heavy build; only needed if you're working on revert decoding)
cargo build --release -p bloom --features bytecode-decompile
```

Release tuning (`Cargo.toml`): `lto = "thin"`, `codegen-units = 1`. Expect
release builds to be slow but cache well.

## Running locally

There are three execution modes. They share the same home directory layout
under `$BLOOM_HOME` (default `~/.bloom`).

```sh
# Mode 1 — one-shot CLI. Each invocation builds the in-process daemon, runs
# the op, and exits. No socket. Good for scripts and CI.
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- init
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs cat /chains/anvil/head/number

# Mode 2 — long-running daemon. Binds a UDS JSON-RPC socket; later `bloom vfs`
# calls auto-detect it and route through (sharing unlock cache, watches, etc.).
bloom serve                                     # foreground; logs to stderr
bloom ipc call lookup --params '{"path":"/status/version"}'

# Mode 3 — NFS mount. Build with the `mount` feature, then run the example
# binary the docker tests use (or `Daemon::mount(path).await` from your own
# binary). The kernel-mounted tree appears at the path you supply.
cargo build --release -p bloom-mount --features mount --example mount_demo
./target/release/examples/mount_demo /tmp/bloom                  # mounts at /tmp/bloom
```

The IPC socket lives at `$BLOOM_HOME/run/bloom.sock` (mode 0600, created on
first `bloom serve`). The same path is the IPC fallback target for `bloom vfs`
calls when a daemon is up.

### Environment variables

Every `BLOOM_*` variable used by the binary, scripts, or test harness:

| Variable | Used by | Notes |
|----------|---------|-------|
| `BLOOM_HOME` | binary, all scripts | Override home dir. Default `~/.bloom`. |
| `BLOOM_PASSPHRASE` | binary, scripts | Argon2id-derived KEK for the keystore. |
| `BLOOM_ETHERSCAN_KEY` | bloom-etherscan, live tests | Etherscan v2 API key. |
| `BLOOM_ENSO_KEY` | bloom-defi, docker `--enso*` | Enso Shortcuts key. |
| `BLOOM_MAINNET_RPC` | bloom-ens live test, acceptance.sh §3/§4 | Optional; scenarios skip cleanly when unset. |
| `BLOOM_LIVE_HOME` | docker `--enso-live` | Path to a real keystore (mounted **read-only** into container). |
| `BLOOM_LIVE_DEST1/2/3` | docker `--enso-live` | Base mainnet sender + sweep targets. |
| `BLOOM_BASE_USDC`, `BLOOM_BASE_AUSDC` | docker `--enso*` | Canonical Base token addresses. |
| `BLOOM_BASE_RPC_URL` | docker `--enso-live` | Defaults to `https://base.publicnode.com`. |
| `BLOOM_SWAP_AMOUNT_ETH` | docker `--enso-live` | Default `0.001` — **real funds**. |
| `BLOOM_ANVIL_BIN`, `BLOOM_CAST_BIN` | bloom-it, bloom-watch | Override Foundry binary paths. |
| `BLOOM_TEST_WALLET_NAME/KEY/PASSPHRASE` | docker drivers | Pre-seeds the daemon wallet. |
| `BLOOM_PLAY_HOME`, `BLOOM_PLAY_PERSIST`, `BLOOM_PLAY_DAEMON_LOG` | scripts/play.sh | Playground knobs. |
| `RUST_LOG` | binary | `tracing-subscriber` env-filter. Default `info`. |

`test.env` (gitignored) is the canonical place to keep these. `source test.env`
before invoking the docker drivers.

## Test suites

CI separates the suites by dependency boundary in `.github/workflows/ci.yml`:

- `build_test_archive` compiles all Rust test targets once with
  `cargo nextest archive` and uploads `target/nextest-archive.tar.zst`.
- `unit_test` downloads that archive and runs only workspace library tests via
  nextest, plus doctests with `cargo test --workspace --doc`. It does not
  install Foundry, Docker, or any external-service credentials.
- `integration_test` downloads the same archive, installs Foundry, and runs
  local-only subprocess/anvil tests on the GitHub runner.
- `e2e_tests` is the live-network lane for ignored external-service tests. It
  is isolated from fork PRs and reports which optional secrets are present
  before tests self-skip or run.
- Docker mount/Enso/live-funds e2e jobs are manual-only (`workflow_dispatch`),
  with the real-funds path guarded by `BLOOM_RUN_LIVE_FUNDS_E2E=1`.

### Rust unit tests

Standard `#[cfg(test)] mod tests` blocks, ~572 across the workspace. None
require external services. Run them all with:

```sh
cargo test --workspace --lib
```

Or scope to a single crate:

```sh
cargo test -p bloom-vfs              # 219 tests — path router, handlers, caches
cargo test -p bloom-proto            # 71  tests — config, intent, policy, units
cargo test -p bloom-evm            # 62  tests — RPC client, blocks, balances
cargo test -p bloom-tx               # 61  tests — staging, simulation, fee logic
cargo test -p bloom-mount --features mount  # 43  tests — NFSv4 server (feature-gated)
cargo test -p bloom-revert           # 27  tests — Error/Panic/custom decoders
cargo test -p bloom-etherscan        # 23  tests — v2 client, ABI parser, cache
cargo test -p bloom-tools            # 22  tests — keccak/sha/abi/rlp helpers
cargo test -p bloom-prices           # 21  tests — DefiLlama oracle
cargo test -p bloom-rpc              # 17  tests — failover, health, sessions
cargo test -p bloom-watch            # 17  tests — watch executor & log rotation
cargo test -p bloom-defi             # 10  tests — Enso route + intent parser
cargo test -p bloom-daemon           # 7   tests — IPC dispatch, lifecycle
cargo test -p bloom-ens              # 6   tests — namehash, encoder
cargo test -p bloom-keystore         # 5   tests — argon2id + chacha20poly1305
```

### Rust integration tests

Integration tests live under crate-local `tests/*.rs` files. The CLI smoke
tests and the primary `bloom-it` anvil flows run by default; heavier anvil,
fallback, watch, and live-network coverage is gated with `#[ignore]` — pass
`-- --ignored` to opt in where appropriate.

```sh
# Always-on: CLI smoke tests (no anvil, no network)
cargo test -p bloom --test cli

# Anvil-backed end-to-end suite (Foundry must be on $PATH)
cargo test -p bloom-it -- --ignored
cargo test -p bloom-watch --test anvil_watch -- --ignored

# Live Ethereum mainnet (skips cleanly if BLOOM_MAINNET_RPC is unset)
BLOOM_MAINNET_RPC=https://eth.example.com cargo test -p bloom-ens -- --ignored

# Heimdall decompile fallback (feature-gated, heavy build)
cargo test -p bloom-it --test revert_decoding_fallbacks \
  --features bytecode-decompile -- --ignored --nocapture
```

What each integration test covers:

| Test file | Covers |
|-----------|--------|
| `crates/bloom/tests/cli.rs` | Subcommand routing, `init`, `status`, `vfs ls/cat/write`, IPC socket fallback, keystore wallet creation. |
| `crates/bloom-it/tests/anvil_e2e.rs` | Full stage → confirm → broadcast for native ETH. Funds a wallet, writes `outbox/new.tx`, confirms, asserts the receipt. |
| `crates/bloom-it/tests/erc20_e2e.rs` | ERC-20 transfer staging incl. fee-bump replacement; surfaces a known failure when token decimals are unreadable. |
| `crates/bloom-it/tests/revert_decoding.rs` | Deploys a `Reverter` contract and asserts the decoder produces correct output for `Error(string)`, `Panic(uint)`, and custom errors. |
| `crates/bloom-it/tests/revert_decoding_fallbacks.rs` | Same contract, no Etherscan ABI — exercises the heimdall bytecode decompile path. **Requires `--features bytecode-decompile`.** |
| `crates/bloom-it/tests/rpc_failover.rs` | Two anvils; kills one mid-loop and asserts subsequent reads succeed within 1s on the survivor. |
| `crates/bloom-it/tests/rpc_health_probe.rs` | Live anvil + dead endpoint; waits ~17s and asserts the health snapshot reflects success rate and cooldown. |
| `crates/bloom-it/tests/rpc_state_drift.rs` | Two anvils at different heights; opens a session and asserts cross-provider hash mismatch is degraded-and-retried, not surfaced. |
| `crates/bloom-it/tests/rpc_ws_subscriptions.rs` | Anvil WS endpoint: `subscribe_blocks`, mines 3 blocks, asserts 3 headers arrive. |
| `crates/bloom-it/tests/rpc_ws_watch_handover.rs` | Watch executor block-watch survives anvil restart by handing over from WS to polling. |
| `crates/bloom-watch/tests/anvil_watch.rs` | Balance watch: anvil_setBalance triggers a transition recorded to the live event log. |
| `crates/bloom-ens/tests/live_mainnet.rs` | `vitalik.eth` round-trip (forward + reverse + text). Skips with a print if `BLOOM_MAINNET_RPC` is unset. |

The `bloom-it` crate (`crates/bloom-it/src/lib.rs`) is the harness shared by
those nine integration tests: `spawn_anvil()`, `cast_send()`, `pick_free_port()`,
and an `AnvilGuard` RAII wrapper that kills the child on drop.

### Dockerized tests (`tests/docker/`)

The Docker harness exists for two reasons: kernel NFS mounts work on Linux
but not on macOS host, and live-network DeFi flows need a controlled wallet.
The host orchestrator is `tests/docker/run.sh`; it builds a Linux `rust:bookworm`
image once (`Dockerfile`), caches the cargo target dir in the
`bloom-cargo-cache` named volume, and dispatches into one of five
in-container drivers.

```sh
# Default — NFS mount surface regression test (no chain, no wallet)
bash tests/docker/run.sh                       # → tests/docker/test.sh

# `cargo test --workspace --lib` inside the Linux container
bash tests/docker/run.sh --workspace           # → tests/docker/test_workspace.sh

# Wallet staging + chain reads against an anvil fork of Base
bash tests/docker/run.sh --fork                # → tests/docker/test_fork_mount.sh

# DeFi intent (Enso → Aave) on an anvil fork — needs BLOOM_ENSO_KEY
bash tests/docker/run.sh --enso                # → tests/docker/test_enso_aave.sh

# Same flow against live Base mainnet — broadcasts and spends real funds
source test.env
bash tests/docker/run.sh --enso-live           # → tests/docker/test_enso_aave.sh

# Force a no-cache rebuild of the test image
bash tests/docker/run.sh --rebuild --mount
```

Coverage per mode:

| Mode | Compose stack | Verifies |
|------|---------------|----------|
| `--workspace` | single container | The unit-test suite passes on Linux as well as macOS. CI-shape regression for OS-specific code. |
| `--mount` (default) | single privileged container | NFS server + kernel mount: `ls`, `cat /status/version`, `cat /tools/keccak/abc`, `write /watch/new`. Regression-tests the WRITE-stability bug that returned EREMOTEIO. |
| `--fork` | compose: anvil-fork sidecar + driver | End-to-end wallet flow over the mount: stage → confirm → broadcast → poll receipt → fee-bump replace; chain reads under `/bloom/chains/base/{head,tx,gas,blocks}`. |
| `--enso` | compose: anvil-fork + driver | Full DeFi intent: post NL intent → confirm session → poll outbox → broadcast → assert aBaseUSDC > 0. Generous 5% slippage and 300s gas-estimation budget to absorb fork drift. |
| `--enso-live` | single privileged container | Same flow against real Base mainnet, plus a balance-neutral unwind (redeem aBaseUSDC → ETH). Mounts `$BLOOM_LIVE_HOME` read-only and copies the keystore to a throwaway home. |

In-container drivers and their helpers all live in `tests/docker/`:

- `Dockerfile` — `rust:bookworm` base; installs `nfs-common` (for `mount.nfs4`),
  `ca-certificates`, `procps`, `curl`, `jq`. Pins rustfmt + clippy to dodge
  transient registry hiccups.
- `docker-compose.yml` — anvil-fork sidecar (Base mainnet at chain_id 8453,
  port 8545, healthcheck via `cast chain-id`); driver profiles (`enso`,
  `fork`, `mempool`) sharing the sidecar.
- `lib.sh` — bash helpers (`prepare_home_dir`, `build_mount_demo`,
  `start_mount_demo`, `wait_for_mount`, `wait_tx_success`,
  `top_up_anvil_balance`, etc.) plus the deterministic Anvil fixtures.
- `test.sh`, `test_workspace.sh`, `test_fork_mount.sh`, `test_enso_aave.sh` —
  the per-mode drivers invoked by `run.sh`.

Common gotchas (more in each script's header comment):

- The `--mount`, `--fork`, and `--enso(-live)` containers run with
  `--cap-add SYS_ADMIN`, `--device /dev/fuse`, and `--security-opt
  apparmor=unconfined`. The `--workspace` mode does not.
- `CARGO_TARGET_DIR=/tmp/cargo-target` is set in-container so Linux artifacts
  don't trample the macOS host's `target/`. The `bloom-cargo-cache` named
  volume persists this between runs; `docker volume rm bloom-cargo-cache`
  to nuke.
- Public Base RPC has 1–2 block lag across replicas. `--enso-live` polls final
  balances for 60s and accepts ≤5 raw aBaseUSDC dust as success.
- `--enso-live` mounts the live home **read-only**; the daemon runs from a
  throwaway copy of the keystore. A bad test cannot corrupt the canonical home.

### Acceptance script (`scripts/acceptance.sh`)

Host-side end-to-end suite that doesn't need Docker. Drives the local native
ETH and ERC-20 acceptance paths using `bloom` CLI calls (which exercise the
same code as VFS writes).

```sh
cargo build --release -p bloom                  # build first
./scripts/acceptance.sh                        # exit 0 = pass, 1 = fail, 2 = missing tools
```

Prereqs: `anvil`, `cast`, `forge`, `jq`, and a built `target/release/bloom`
(override with `BLOOM_BIN`).

| # | Scenario | Skipped when |
|---|----------|--------------|
| 1 | Native ETH send staged on local Anvil; initial confirm must deny and write central `approval_challenge.json` with `ceremony_url` | (always runs) |
| 2 | ERC-20 transfer staged with deployed `MockERC20`; initial confirm must deny and write central `approval_challenge.json` with `ceremony_url` | `forge` missing |

Anvil and the temp home dir are torn down on exit via `trap`.

### Playground (`scripts/play.sh`)

Interactive REPL — not a test, but the fastest way to drive the daemon by
hand against a real anvil.

```sh
./scripts/play.sh                              # builds bloom, boots anvil, drops you into a subshell
BLOOM_PLAY_PERSIST=1 ./scripts/play.sh          # keep the play home between runs
```

What it sets up: anvil at `127.0.0.1:8545` (chain_id 31337) via
`docker/playground/docker-compose.yml`; a fresh `~/.bloom-play` with two
chains (`anvil` broadcasts enabled, `base` mainnet read-only); three wallets
(`alice`, `bob`, `carol`) imported from anvil's deterministic mnemonic with
passphrase `play`; a backgrounded `bloom serve` whose logs go to
`/tmp/bloom-play-daemon.log`. Cleanup on subshell exit kills the daemon and
the anvil container.

## Debugging

### Tracing logs

The binary configures `tracing-subscriber` with `EnvFilter` from `RUST_LOG`
(default `info`, output to stderr). Useful filters:

```sh
RUST_LOG=info bloom serve
RUST_LOG=bloom_daemon=debug,bloom_vfs=debug,info bloom serve
RUST_LOG=bloom_rpc=trace,info bloom serve              # endpoint health & failover
RUST_LOG=error bloom status                           # quiet for scripts
```

For `scripts/play.sh` the daemon log lands at
`${BLOOM_PLAY_DAEMON_LOG:-/tmp/bloom-play-daemon.log}`.

### Audit log

Every side-effecting operation is appended to `$BLOOM_HOME/audit.jsonl` as a
hash-chained record (`{ts_ms, kind, wallet?, chain?, data, prev, digest}`,
all blake3). Tampering is detectable via `AuditLog::verify()`. The live
fingerprint is exposed under the status surface:

```sh
bloom vfs cat /status/audit/head      # current blake3 digest
bloom vfs cat /status/audit/count     # total entries
bloom vfs cat /status/audit/last      # last 10 records as JSON
```

### Status VFS surface

The fastest read-only diagnostic. Backed by
`crates/bloom-vfs/src/handlers/status.rs`; per-path TTLs keep these calls
cheap (chain probes 5s, version 1d, audit live).

```sh
bloom vfs cat /status/daemon.json                        # version, uptime, home, chains
bloom vfs cat /status/chains/base/connected              # true / false (750ms RPC ping)
bloom vfs cat /status/chains/base/block_number           # head height (or backend error)
bloom vfs ls  /status/chains/base/endpoints              # health snapshots, 0-indexed
bloom vfs cat /status/chains/base/endpoints/0/success_rate
bloom vfs cat /status/policies/block_mainnet_broadcast   # safety flag
bloom vfs cat /status/outbox/pending_count               # pending tx count
bloom vfs cat /status/backends/summary.json              # which data source each surface uses
```

### IPC introspection

Once `bloom serve` is up, the JSON-RPC dispatcher
(`crates/bloom-daemon/src/ipc.rs`) exposes `lookup`, `read`, `write`, `list`,
`version`, `chains`, `shutdown`. They are addressable directly:

```sh
bloom ipc call version
bloom ipc call chains
bloom ipc call list   --params '{"path":"/wallets"}'
bloom ipc call read   --params '{"path":"/status/daemon.json"}'
bloom ipc call write  --params '{"path":"/wallets/alice/chains/anvil/outbox/new.tx","text":"send 0.01 eth to 0x..."}'
bloom ipc call shutdown
```

Useful when you suspect the CLI shim is hiding a daemon-side error.

### Home directory layout

```
$BLOOM_HOME/
├── config.toml          # chain config, etherscan/enso keys, broadcast policy
├── addressbook.toml     # local petname directory
├── audit.jsonl          # hash-chained audit log
├── run/bloom.sock        # UDS JSON-RPC socket (mode 0600)
├── keystore/<wallet>/   # encrypted.key, address, pubkey, kind, policy.toml
├── cache/cache.db       # etherscan / ABI cache (TTL-gated)
├── blobs/               # large response storage
├── outbox/<wallet>/<chain>/{pending,sent,failed}/<id>/
├── watch/<id>/          # subscription state + rotated history.jsonl[.n]
└── logs/                # daemon log files (when running detached)
```

## Lint and format

No custom `rustfmt.toml` or `clippy.toml` — defaults apply.

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI expects both clean.

## Coverage map

Quick "if I changed X, what should I run?" matrix.

| If you touched… | Run, in order |
|-----------------|---------------|
| `bloom-proto` (config, intents, units) | `cargo test -p bloom-proto` |
| `bloom-vfs` handlers | `cargo test -p bloom-vfs` then `bash tests/docker/run.sh --mount` |
| `bloom-rpc` failover/health/WS | `cargo test -p bloom-rpc` then `cargo test -p bloom-it -- --ignored` |
| `bloom-evm` | `cargo test -p bloom-evm` then `cargo test -p bloom-it --test anvil_e2e -- --ignored` |
| `bloom-tx` staging / nonce / replace | `cargo test -p bloom-tx` then `cargo test -p bloom-it --test anvil_e2e -- --ignored` then `bash tests/docker/run.sh --fork` |
| `bloom-keystore` | `cargo test -p bloom-keystore` |
| `bloom-revert` | `cargo test -p bloom-revert` then `cargo test -p bloom-it --test revert_decoding -- --ignored` (and `revert_decoding_fallbacks` with `--features bytecode-decompile` if you touched the heimdall path) |
| `bloom-watch` | `cargo test -p bloom-watch -- --ignored` then `cargo test -p bloom-it --test rpc_ws_watch_handover -- --ignored` |
| `bloom-mount` | `cargo test -p bloom-mount --features mount` then `bash tests/docker/run.sh --mount` (and `--fork` if you touched plumbing the wallet flow uses) |
| `bloom-defi` (Enso client + parser) | `cargo test -p bloom-defi` then `bash tests/docker/run.sh --enso` (needs `BLOOM_ENSO_KEY`) |
| `bloom-etherscan` | `cargo test -p bloom-etherscan` (and the live test if you have a key) |
| `bloom-ens` | `cargo test -p bloom-ens` then the live test with `BLOOM_MAINNET_RPC` if applicable |
| `bloom-prices` | `cargo test -p bloom-prices` |
| `bloom-daemon` IPC / lifecycle | `cargo test -p bloom-daemon` then `cargo test -p bloom --test cli` |
| `bloom` CLI | `cargo test -p bloom --test cli` then `./scripts/acceptance.sh` |
| Anything load-bearing for live use | `bash tests/docker/run.sh --enso-live` (sources `test.env`, real funds) |
