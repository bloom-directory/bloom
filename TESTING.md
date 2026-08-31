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

## Triad and Solana ladders

Do not begin with the most expensive integration suite. For an authority
change, test the owning repository first, then its downstream protocol seam,
then the real out-of-process triad. The exact cross-repository workflow is in
[`DEVELOPMENT.md`](./DEVELOPMENT.md).

Machine-side triad seams:

```sh
cargo test -p bloom-machine-client
cargo test -p bloom-vfs
cargo test -p bloom-petals --test triad_authority_fixture
scripts/test-local-mainnet-integration.sh
```

Full BIP-39 projection fidelity is deliberately separate:

```sh
scripts/acceptance.sh
```

That script starts the real Machine, Broker, and Signer, builds the Broker
debug ceremony driver, installs the deterministic authority fixture, and uses
a kernel mount. It requires the sibling repositories and the same systemd,
trusted-time, and mount prerequisites as the full developer launcher.

Run native Solana tests from cheap to expensive:

```sh
cargo test -p bloom-solana
cargo test -p bloom-solana-tx
cargo test -p bloom-it --test solana_workflow -- --ignored --nocapture
```

The validator-backed tests require the pinned Agave v3.0.0 validator from
`.github/workflows/solana-validator.yml`:

```sh
SOLANA_VALIDATOR_HTTP=http://127.0.0.1:8899 \
  cargo test -p bloom-solana-tx --test local_validator -- \
  --ignored --nocapture
cargo test -p bloom-it --test solana_multi_account -- \
  --ignored --nocapture
```

`local_validator` reads `SOLANA_VALIDATOR_HTTP`; `solana_multi_account`
intentionally targets `http://127.0.0.1:8899` directly.

## Categories

### unit

In-crate `#[cfg(test)] mod tests { ... }` blocks. Co-located with the code they
cover. No external services, no filesystem, no network.

- Run: `cargo test -p <crate>` (or `cargo test --lib`)
- Examples: walletFS crates such as `bloom-tx`, `bloom-vfs`, and
  `bloom-petals`.

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
- Shell acceptance suites launch the real triad through
  `scripts/triad-dev-launch.sh`:
  - `scripts/acceptance.sh` — the full custody acceptance entrypoint: runs
    the projection-fidelity suite and both transfer suites below.
  - `scripts/test-raw-key-import-transfer.sh` — imports a raw secp256k1 EVM
    key through the real Broker ceremony (base64url key input to the debug
    driver), allowlists a recipient through the policy-update ceremony, and
    proves the imported scalar can stage, approve, sign, broadcast, and
    confirm a transfer on a local anvil chain with the on-chain sender
    matching the imported address. Requires `anvil`/`cast` and the
    `BLOOM_INTEGRATION_*_BIN` binaries.
  - `scripts/test-bip39-import-transfer.sh` — imports a fixed throwaway
    BIP-39 mnemonic through the real Broker ceremony, asserts the canonical
    EVM child projection, completes an `AccountAllocate` ceremony and proves
    the Solana child projects only after the ceremony completes, then spends
    from the canonical EVM child on a local anvil chain with the on-chain
    sender matching cast's independent `m/44'/60'/0'/0/0` derivation.
    Requires `anvil`/`cast` and the `BLOOM_INTEGRATION_*_BIN` binaries.

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
| `BLOOM_INTEGRATION_MACHINE_BIN` | triad | Exact Machine binary under test. |
| `BLOOM_INTEGRATION_BROKER_BIN` | triad | Exact Broker binary under test. |
| `BLOOM_INTEGRATION_SIGNER_BIN` | triad | Exact Signer binary under test. |
| `BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS` | triad | Bounded full-stack startup timeout. |
| `SOLANA_VALIDATOR_HTTP` | Solana acceptance | Local validator JSON-RPC endpoint. |
