# Testing

This document describes the test categories used across the `bloom-eth`
workspace, where each one lives, how to run it, and the relevant environment
variables. The taxonomy is enforced informally via `//! Category: ...`
header comments on integration test files.

## Running everything

```sh
RUST_LOG=warn cargo test --workspace          # all non-ignored tests
RUST_LOG=warn cargo test --workspace -- --ignored   # acceptance suite
```

CI runs the first command on every PR (`.github/workflows/ci.yml`) and both
on `push` to `master` (`.github/workflows/acceptance.yml`).

## Categories

### unit

In-crate `#[cfg(test)] mod tests { ... }` blocks. Co-located with the code
they cover. No external services, no filesystem, no network.

- Run: `cargo test -p <crate>` (or `cargo test --lib`)
- Examples: every protocol crate (`bloom-chain-types`, `bloom-chain-state`,
  `bloom-chain-abi`, `bloom-petals`, `bloom-chain-consensus`, ...)

### integration

`crates/<crate>/tests/*.rs` — each file becomes its own test binary linked
against the crate's public API. May spin up in-process state, but no
subprocesses.

- Run: `cargo test -p <crate> --tests`
- Examples: `bloom-chain-state/tests/snapshot.rs`,
  `bloom-chain-consensus/tests/happy_path.rs`,
  `bloom-petals/tests/chain_imports.rs`.

### property

`proptest`-driven generators that exercise an invariant across many random
inputs. Live alongside other integration tests but use `proptest!` macros.

- Run: `cargo test -p <crate> --tests`
- Examples: `bloom-chain-state/tests/trie_props.rs`,
  `bloom-chain-types/tests/ssz_roundtrip.rs`.

### adversarial

Negative-path tests where forged / tampered / malformed inputs MUST be
rejected (or accounted for) by the protocol. Test names use the
`adversarial_*` prefix where practical.

- Run: `cargo test -p <crate> --tests`
- Examples: `bloom-chain-consensus/tests/locking.rs`,
  `bloom-chain-node/tests/consensus_auth.rs`,
  `bloom-chain-node/tests/block_sync_validation.rs`,
  `bloom-petals/tests/chain_hardening.rs`,
  `bloom-petals/tests/chain_revert_fuel.rs`.

### selector-parity

Tests that pin the on-wire ABI: each method's `[u8; 4]` selector equals
`blake3::hash(canonical_string)[..4]`. Inlined per petal as direct
`blake3::hash(b"<canonical>")[..4]` assertions against the macro-emitted
`<petal>::SEL_*` constants.

- Run: `cargo test -p <petal-crate>`
- Examples: `bloom-dex-erc20`, `bloom-dex-factory`, `bloom-dex-pair`,
  `bloom-dex-router`, `bloom-dex-wloom`.

### macro-DSL

Tests for the `bloom_chain_abi::contract!` macro itself — selector
derivation, encoder/decoder roundtrips, calldata typing, `Bytes` positioning
constraints.

- Run: `cargo test -p bloom-chain-abi`
- Examples: `bloom-chain-abi/tests/contract_macro.rs`.

### smoke

Short-running end-to-end checks that verify the system boots and can do
something trivial. Used as quick gates.

- Run: `cargo test --test chain_smoke -- --ignored`
- Examples: `bloom-it/tests/chain_smoke.rs`.

### acceptance

Long-running end-to-end tests gated behind `#[ignore]`. Spin up a real
multi-validator chain in-process and drive it via the bloom CLI.

- Run: `cargo test --workspace -- --ignored`
- Examples: `examples/dex/tests/bloom-dex-it/tests/chain_dex_demo.rs::dex_v0_acceptance_end_to_end`.

### docker-acceptance

End-to-end tests that bring up a real 4-validator testnet via
`docker compose`, exercise it from outside the JVM-of-the-day, and tear it
down. The CI job runs only if docker is available on the runner.

- Run: `scripts/test-docker-dex.sh`
- Env: `BLOOM_DOCKER_TMPDIR` (workdir for the compose stack — defaults to a
  fresh `mktemp -d`), `BLOOM_RPC_TCP` (`true` to make the CLI use TCP rather
  than UDS — set automatically by the script), `BLOOM_DOCKER_COMPOSE_UP`
  (`false` to skip the `compose up` and reuse an already-running stack),
  `BLOOM_DOCKER_DEX_KEEP` (`true` to leave containers running after a pass —
  useful for debugging), `BLOOM_VALIDATOR_COUNT` (number of validators —
  defaults to 4, parameterised in Phase 5).
- Examples: `examples/dex/tests/bloom-dex-it/tests/docker_dex_multi_user.rs`.

### CLI-subprocess

Tests that shell out to the compiled `bloom` binary (`target/debug/bloom` or
`target/release/bloom`) and assert on its stdout / exit code / produced
files. Includes the chain testnet provisioner.

- Run: `cargo test -p bloom --test cli` /
  `cargo test -p bloom-it --test chain_testnet_provision`
- Env: `BLOOM_BIN` (override the path to the bloom binary; defaults to
  `target/debug/bloom` resolved from `CARGO_MANIFEST_DIR`).
- Examples: `bloom/tests/cli.rs`,
  `bloom-it/tests/chain_testnet_provision.rs`.

### IPC-stub

In-process tests for the IPC handler dispatch layer — `Stub*Handler` shapes
verify that the daemon's request/response framing handles each method
correctly without standing up a real chain.

- Run: `cargo test -p bloom-daemon`
- Examples: `bloom-daemon/src/ipc.rs` (`#[cfg(test)] mod tests` near the
  bottom of the file).

### wasm-guest

Tests that compile inline WAT or load `tests/fixtures/*.wat` files,
instantiate them inside `PetalVm::run_chain_call`, and assert on the
resulting `ChainCallOutput`. Each test acts as both a regression for chain
host import semantics and a worked example of how a real petal would call
those imports.

- Run: `cargo test -p bloom-petals --tests`
- Examples: `bloom-petals/tests/chain_imports.rs`,
  `bloom-petals/tests/chain_hardening.rs`,
  `bloom-petals/tests/chain_revert_fuel.rs`.

## Shared scaffolding

- `crates/bloom-test-util` — single source of truth for validator / block /
  tx builders, multi-`ConsensusState` mailbox, RPC client mocks. Dev-only
  dependency; protocol crates do not depend on it at runtime.
- `examples/dex/tests/bloom-dex-it/src/lib.rs` — shared RPC + math helpers
  for both in-process and docker DEX e2e binaries.
- `crates/bloom-petals/tests/common/mod.rs` — `make_address`, `wat`,
  `block_at(n)`, `block_with(n, b)`, `assert_fuel_close`.
- `crates/bloom-petals/tests/fixtures/*.wat` — externalised WAT modules.
- Per-petal canonical-string selector parity tests inline
  `blake3::hash(b"<canonical>")[..4]` against macro-emitted `SEL_*` constants.

## Naming conventions

- `*_smoke` — minimal "the wires are connected" check.
- `*_acceptance` — end-to-end behaviour against a real stack.
- `*_regression` — pinned reproduction of a specific past bug.
- `*_parity` — wire-format parity (selectors, encoding, replay).
- `adversarial_*` (prefix) — negative-path / forged-input rejection.

## Environment variables (full list)

| Var | Used by | Purpose |
| --- | --- | --- |
| `RUST_LOG` | all | Tracing filter; default to `warn` for tests. |
| `BLOOM_BIN` | CLI-subprocess | Override compiled bloom binary path. |
| `BLOOM_DOCKER_TMPDIR` | docker-acceptance | Compose workdir (defaults to mktemp -d). |
| `BLOOM_RPC_TCP` | docker-acceptance | CLI talks TCP rather than UDS. |
| `BLOOM_DOCKER_COMPOSE_UP` | docker-acceptance | Reuse an existing compose stack. |
| `BLOOM_DOCKER_DEX_KEEP` | docker-acceptance | Leave containers running on pass. |
| `BLOOM_VALIDATOR_COUNT` | docker-acceptance | Validator count for templated compose (Phase 5). |
