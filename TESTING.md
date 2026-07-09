# Testing

This document describes the test categories used across the `bloom` workspace,
where each one lives, how to run it, and the relevant environment variables.
The taxonomy is enforced informally via `//! Category: ...` header comments on
integration test files.

## Running everything

```sh
RUST_LOG=warn cargo test --workspace
RUST_LOG=warn cargo test --workspace -- --ignored
```

CI runs workspace tests through the split jobs in `.github/workflows/ci.yml`.
Ignored live-network and docker suites are run only by the CI lanes that opt in
with `--run-ignored`.

## Categories

### unit

In-crate `#[cfg(test)] mod tests { ... }` blocks. Co-located with the code they
cover. No external services, no filesystem, no network.

- Run: `cargo test -p <crate>` (or `cargo test --lib`)
- Examples: walletFS crates such as `bloom-tx`, `bloom-vfs`, `bloom-petals`,
  `bloom-polymarket`, and `bloom-hyperliquid`.

### integration

`crates/<crate>/tests/*.rs` — each file becomes its own test binary linked
against the crate's public API. May spin up in-process state, but no
subprocesses.

- Run: `cargo test -p <crate> --tests`
- Examples: `bloom-it/tests/anvil_e2e.rs`,
  `bloom-it/tests/revert_decoding.rs`, and `bloom-petals` tests.

### property

`proptest`-driven generators that exercise an invariant across many random
inputs. Live alongside other integration tests but use `proptest!` macros.

- Run: `cargo test -p <crate> --tests`
- Examples: property tests live beside the crate integration tests they cover.

### adversarial

Negative-path tests where forged / tampered / malformed inputs MUST be rejected
(or accounted for). Test names use the `adversarial_*` prefix where practical.

- Run: `cargo test -p <crate> --tests`
- Examples: auth ceremony, tx policy, VFS, and petal VM negative-path tests.

### smoke

Short-running end-to-end checks that verify the system boots and can do
something trivial. Used as quick gates.

- Run: package-specific smoke tests with `cargo test -p <crate> <smoke-name>`.
- Examples: daemon IPC, VFS handler, and wallet command smoke coverage.

### acceptance

Long-running end-to-end tests gated behind `#[ignore]`. They may spin up
external services such as anvil or exercise real wallet integrations.

- Run: `cargo test --workspace -- --ignored`

### CLI-subprocess

Tests that shell out to the compiled `bloom` binary (`target/debug/bloom` or
`target/release/bloom`) and assert on its stdout / exit code / produced files.

- Run: `cargo test -p bloom --test cli` and targeted `bloom-it` tests.
- Env: `BLOOM_BIN` (override the path to the bloom binary; defaults to
  `target/debug/bloom` resolved from `CARGO_MANIFEST_DIR`).
- Examples: `bloom/tests/cli.rs`, `bloom-it/tests/anvil_e2e.rs`.

### IPC-stub

In-process tests for the IPC handler dispatch layer — `Stub*Handler` shapes
verify that the daemon's request/response framing handles each method correctly
without standing up a real service.

- Run: `cargo test -p bloom-daemon`
- Examples: `bloom-daemon/src/ipc.rs` (`#[cfg(test)] mod tests` near the bottom
  of the file).

### wasm-guest

Tests that compile inline WAT or load `tests/fixtures/*.wat` files and run them
inside the petal VM. Each test acts as both a regression for host import
semantics and a worked example of how a wallet extension petal behaves.

- Run: `cargo test -p bloom-petals --tests`
- Examples: `bloom-petals` tests and fixtures.

## Shared scaffolding

- `crates/bloom-petals/tests/common/mod.rs` — `make_address`, `wat`, and
  fixture helpers.
- `crates/bloom-petals/tests/fixtures/*.wat` — externalised WAT modules.
- Per-petal canonical-string selector parity tests inline
  `blake3::hash(b"<canonical>")[..4]` against macro-emitted `SEL_*` constants.

## Naming conventions

- `*_smoke` — minimal "the wires are connected" check.
- `*_acceptance` — end-to-end behaviour against a real stack.
- `*_regression` — pinned reproduction of a specific past bug.
- `*_parity` — wire-format parity (selectors, encoding, replay).
- `adversarial_*` (prefix) — negative-path / forged-input rejection.

## Environment variables

| Var | Used by | Purpose |
| --- | --- | --- |
| `RUST_LOG` | all | Tracing filter; default to `warn` for tests. |
| `BLOOM_BIN` | CLI-subprocess | Override compiled bloom binary path. |
