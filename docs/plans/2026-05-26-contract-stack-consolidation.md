# Bloom contract stack consolidation plan

**Status:** draft
**Date:** 2026-05-26
**Spec:** [`docs/specs/2026-05-26-contract-stack-consolidation.md`](../specs/2026-05-26-contract-stack-consolidation.md)

This plan executes the consolidation decision: remove the legacy
`bloom-contract` / account-storage / EVM-style path and keep the
Bloom-native resource/PTB/object path.

## Phase 0: Inventory and Guardrails

Deliverables:

- Build a crate dependency map for every `bloom-contract*`,
  `bloom-chain-abi`, legacy DEX, CLI, VFS, daemon, and test dependency.
- Classify each crate as one of:
  - canonical core
  - canonical example
  - legacy removal
  - temporary bridge
  - unrelated existing Bloom functionality
- Identify all references to:
  - `TxKind::Deploy`
  - `TxKind::Call`
  - `bloom_contract`
  - `bloom_contract_*`
  - `bloom_petal_sdk`
  - selector-style contract ABI APIs
- Record the initial test commands that pass before cleanup.

Rules:

- Do not delete before the dependency map shows what will break.
- Do not preserve a crate only because deletion is noisy.
- Prefer removing old tests over porting tests that only validate removed
  behavior.

## Phase 1: Remove Legacy Workspace Surface

Deliverables:

- Remove legacy contract crates from workspace members and dependencies.
- Delete source crates that are only used by the old contract stack:
  - `crates/bloom-contract`
  - `crates/bloom-contract-macros`
  - `crates/bloom-contract-build`
  - `crates/bloom-contract-metadata`
  - `crates/bloom-client-codegen`, if not needed by canonical PTB clients
- Remove old contract CLI commands and tests.
- Remove legacy docs that present `bloom-contract` as active.

Verification:

- `cargo check --workspace` reaches the next set of real protocol breakages,
  not stale legacy crate breakages.
- No workspace member declares a dependency on `bloom-contract*`.

## Phase 2: Remove Legacy Protocol Transactions

Deliverables:

- Remove `TxKind::Deploy` and `TxKind::Call` from `bloom-chain-types`.
- Update SSZ encode/decode tests and transaction hash tests.
- Update mempool, consensus, RPC, VFS, CLI, daemon, and test utilities to
  submit PTBs instead of legacy deploy/call transactions.
- Remove deployment-address and contract-account code paths that only support
  legacy contracts.
- Preserve plain native transfer only if it remains a protocol primitive
  outside smart-contract execution. Otherwise model value movement through
  canonical coin/object PTB operations.

Verification:

- Transaction encoding tests pass with the reduced tx enum.
- Chain-node tests fail only where they still assume legacy deploy/call, then
  are removed or ported.

## Phase 3: Consolidate VM Host Imports

Deliverables:

- Remove legacy `chain.state.*`, `chain.petal.call`, `msg.value`, and other
  imports that only serve legacy account/storage contracts.
- Keep only imports needed by the resource/PTB model.
- Split `crates/bloom-petals/src/chain_vm.rs` into focused modules.
- Make `ChainEntry` represent canonical PTB/resource exports only.
- Remove special handling for PTB-mode petals with missing `init`; after this
  phase, there is no legacy `init` path.

Verification:

- Chain-mode wasm validation allows the canonical `__petal_*`,
  `__inv_*`, allocation, manifest, and resource host-import surface.
- Legacy `init` / `call` fixtures are deleted or rewritten as resource
  petals.

## Phase 4: Narrow ABI and Codec Ownership

Deliverables:

- Identify the parts of `bloom-chain-abi` still used by canonical crates.
- Remove selector/contract macro surfaces that only support old contracts.
- Decide whether to:
  - keep a narrowed `bloom-chain-abi`, or
  - rename/extract a canonical codec crate.
- Ensure `bloom-resource`, `bloom-objects`, and `bloom-script` share one
  deterministic encoding story for args, returns, type tags, object payloads,
  and PTB wire bytes.

Verification:

- No canonical crate imports a removed selector/contract API.
- Codec roundtrip tests cover PTB args/returns and object payloads.

## Phase 5: Remove Old EVM-Style Examples

Deliverables:

- Remove `examples/dex/*` if it uses the old EVM-shaped paradigm.
- Remove `examples/wloom` if it exists for old wrapped-native semantics.
- Keep or improve canonical examples:
  - `examples/petal-dex/*`
  - `examples/petal-cap`
  - `examples/petal-identity`
  - core petal crates used by tests
- Update Docker scripts, acceptance workflows, and README references.

Verification:

- Acceptance workflows target canonical PTB/resource examples.
- No default workspace member is an old EVM-style app.

## Phase 6: Documentation and CLI Cleanup

Deliverables:

- Update README, quickstart, testing docs, CLI help, VFS docs, and specs.
- Mark superseded specs as historical or remove active references to them.
- Document the canonical developer path:
  - write a `#[bloom::petal]`
  - compile wasm
  - publish/path-bind petal if needed
  - build and submit PTBs
  - inspect object/receipt state

Verification:

- New users reading the docs see one contract model.
- Search results for removed concepts point to historical docs or no active
  code path.

## Phase 7: Final Test Matrix

Run a focused final matrix:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets`
- `cargo test --workspace`
- targeted chain-node/PTB integration tests
- targeted petal DEX tests
- Docker/acceptance tests for the canonical flow, if still present

If the full workspace is still too broad during intermediate phases, record
the temporary exclusions and remove them before completion.

## Done Definition

The plan is complete when the spec acceptance criteria are true and the final
test matrix is green or has documented, unrelated pre-existing failures.
