# Testing

This document describes the test categories used across the `bloom` workspace,
where each one lives, how to run it, and the relevant environment variables.
The taxonomy is enforced informally via `//! Category: ...` header comments on
integration test files.

## Validation gates

Start with the affected package or named test. For a repository-wide code
candidate, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
RUST_LOG=warn cargo test --workspace --locked
```

For documentation-only changes, check the diff and links. When editing embedded
VFS Markdown, also run the existing documentation tests:

```sh
git diff --check
cargo test -p bloom-vfs --locked root_agent_guidance
cargo test -p bloom-vfs --locked handlers::docs::tests
```

CI runs workspace tests through the split jobs in
[`ci.yml`](./.github/workflows/ci.yml). Ignored suites require their documented
services and tools; run the relevant suite explicitly rather than enabling all
ignored tests on an unprepared host.

Production authority-boundary checks are:

```sh
packaging/triad/release/check-machine-authority-boundary.sh
packaging/triad/release/test-machine-authority-boundary.sh
```

Use a disposable Tart VM for local macOS packaging and principal-isolation
checks. For changes affecting the released service combination, follow the
[release package verification](./packaging/triad/release/README.md) at the
recorded compatibility revisions, including the Linux release build and both
macOS conformance workflows with explicit Broker and Signer refs. Local checks
do not replace required review or CI on the published candidate.

## Triad and Solana ladders

Select the checks for the changed behavior using the map below. Test an
authority change in its owning repository before exercising downstream
boundaries; see the [development workflow](./DEVELOPMENT.md).

The full custody acceptance entrypoint is `scripts/acceptance.sh`. It runs
projection fidelity, raw-key import/transfer, and BIP39 import/transfer through
the real Machine, Broker, and Signer. It requires Foundry, sibling repositories,
the Broker debug ceremony driver, and the systemd, trusted-time, and kernel
mount prerequisites documented in the development guide.

Solana package tests can run without a validator:

```sh
cargo test -p bloom-solana --locked
cargo test -p bloom-solana-tx --locked
```

Before running any of the following ignored tests, start the pinned Agave
v3.0.0 validator using the setup in
[`solana-validator.yml`](./.github/workflows/solana-validator.yml):

```sh
SOLANA_VALIDATOR_HTTP=http://127.0.0.1:8899 \
  cargo test -p bloom-solana-tx --locked --test local_validator -- \
  --ignored --nocapture
cargo test -p bloom-it --locked --test solana_workflow -- --ignored --nocapture
cargo test -p bloom-it --locked --test solana_multi_account -- --ignored --nocapture
```

`local_validator` reads `SOLANA_VALIDATOR_HTTP`. Both `solana_workflow` and
`solana_multi_account` use `http://127.0.0.1:8899` directly. Those two suites
exercise a real daemon and validator with an in-process Broker fixture; they
do not verify separate Broker/Signer processes or a kernel mount.

## Change-to-test map

Choose by the behavior changed, not merely the file or directory touched.
Start with named regression tests, then run the affected package suite.
Documentation follows the documentation gate above. Add the integration
evidence below when the changed path crosses that boundary; required CI and
release gates still apply.

| Changed behavior | Package coverage | Additional boundary evidence |
|---|---|---|
| Public projection or Broker client | `bloom-machine-client`, affected CLI/VFS tests | Real triad workflow when the projection or protocol contract changes |
| Custody import or account lifecycle | Owning Broker/Signer suites | `scripts/acceptance.sh` for custody/lifecycle behavior; CLI presentation alone needs affected CLI tests |
| VFS routing or handlers | `bloom-vfs` | `bloom-mount --features mount` and mounted reproduction when kernel-adapter behavior changes |
| EVM construction or transaction lifecycle | `bloom-tx` | Affected `bloom-it` transaction workflow when staging, signing, or broadcast behavior changes |
| Solana RPC or genesis checks | `bloom-solana` | Validator-backed coverage when correctness depends on live node behavior |
| Solana construction or outbox logic | `bloom-solana-tx` | `solana_workflow` when the stage/confirm/broadcast/reconciliation path changes |
| Solana account selection | Affected account-selection and VFS tests | `solana_multi_account` when selection changes across staging, signing, or chain reads |
| Petal authority interface | `bloom-petals --test triad_authority_fixture` | Real triad workflow when the authority contract changes |
| Cross-process protocol or transport | Affected suites in each changed repository | Exercise the affected operation through the real triad at recorded revisions |
| Machine authority boundary or production features | Both authority-boundary scripts | Release/package checks above |
| macOS packaging or isolation | Disposable Tart VM acceptance | Required release conformance above |

Use `cargo test -p <package> --locked` for package entries. A fixture-backed
test is evidence only for the boundary it exercises; starting the launcher
alone is not evidence that a custody or transaction workflow succeeds.

## Categories and entrypoints

Category comments describe a test's purpose; inspect its setup for actual
dependencies. An in-crate test can use a temporary filesystem or local server,
and an integration test can launch subprocesses.

| Category | Where and how to run |
|---|---|
| Unit | In-crate test modules; `cargo test -p <crate> --lib` |
| Integration | `crates/<crate>/tests/`; `cargo test -p <crate> --test <name>` |
| Property / adversarial | Named generative or rejection tests in the owning crate; select the relevant test binary or filter |
| Smoke | Named startup or basic-workflow tests; select the relevant package/filter |
| Acceptance | Ignored service-backed tests; `cargo test -p <crate> --test <name> -- --ignored` after preparing its dependencies |
| CLI-subprocess | `cargo test -p bloom --test cli` and affected `bloom-it` tests |
| IPC-stub | `cargo test -p bloom-daemon`; dispatch fixtures do not prove real service behavior |
| WASM guest | `cargo test -p bloom-petals --tests`; guest modules exercise host imports |

The custody entrypoint runs these scripts in order:

| Script | Evidence |
|---|---|
| `scripts/test-triad-projection-fidelity.sh` | Authenticated public projections and custody ceremonies through the real triad and mount |
| `scripts/test-raw-key-import-transfer.sh` | Imported scalar spends on local Anvil with the expected sender |
| `scripts/test-bip39-import-transfer.sh` | Canonical EVM derivation, Solana allocation visible after ceremony completion, and imported-root EVM spending |

Use disposable test inputs. Import/transfer suites require `anvil`, `cast`,
and the selected `BLOOM_INTEGRATION_*_BIN` binaries. Successful fixture
signing does not replace these service-boundary checks.

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
