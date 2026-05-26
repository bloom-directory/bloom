# Bloom contract stack consolidation

**Status:** draft
**Date:** 2026-05-26
**Owners:** Joshua Richardson
**Supersedes:** `docs/specs/2026-05-19-contract-macro-v2.md`,
`docs/specs/2026-05-20-bloom-rust-contracts.md`,
the compatibility portions of
`docs/specs/2026-05-20-bloom-native-contracts-design.md`.

This spec records the decision to consolidate Bloom around a single
smart-contract model: **Bloom-native petals executed through PTBs over the
object/resource substrate**.

The deprecated EVM-style contract stack is removed from the active codebase.
It remains available through git history, not as a maintained compatibility
layer.

## 1. Decision

Bloom has one canonical contract substrate:

- `bloom-resource` and `bloom-resource-macros` define the guest/runtime
  developer surface.
- `bloom-objects` defines object ownership, type tags, packets, abilities,
  and object-store wire types.
- `bloom-script` defines PTB wire types, validation, execution, borrow-table
  checks, linearity, and command output flow.
- `bloom-petals` provides deterministic wasm execution for chain-mode petals.
- `bloom-chain-*` provides state, consensus, transaction, receipt, and node
  plumbing.

Legacy account/storage contracts are not a second supported product surface.
The following are removal targets:

- `crates/bloom-contract`
- `crates/bloom-contract-macros`
- `crates/bloom-contract-build`
- `crates/bloom-contract-metadata`
- `crates/bloom-client-codegen`, if it only serves the old contract ABI
- `examples/dex/*`, if it represents the old EVM-style DEX paradigm
- `examples/wloom`, if it exists to model wrapped-native assets for the old
  EVM-style contract stack
- legacy contract-specific CLI commands, tests, docs, and Docker flows

The protocol transaction surface is also consolidated. `TxKind::Deploy` and
`TxKind::Call` are removed. Smart-contract execution enters the chain through
PTBs. Native balance movement should be modeled through canonical object/coin
operations, not an account-call compatibility path.

## 2. Goals

1. **One contract model.** Bloom developers should not have to choose between
   account/storage contracts and object/resource petals.
2. **Small protocol surface.** Remove legacy tx kinds and host imports that
   only exist to support EVM-shaped contracts.
3. **Maintainable core crates.** Keep the core substrate explicit and layered:
   chain types/state/consensus, object model, PTB executor, wasm VM, resource
   guest runtime.
4. **Succinct workspace.** Remove demo crates and generated compatibility
   layers that make `cargo check` and review scope noisy.
5. **Clear examples.** The canonical application example is a Bloom-native
   petal example, not a legacy EVM-style DEX.

## 3. Non-goals

- Maintaining source compatibility for `bloom-contract`.
- Maintaining wire compatibility for legacy `Deploy` / `Call` transactions.
- Porting every old example before deletion.
- Providing an EVM-like account/storage abstraction on top of PTBs.
- Preserving old CLI command names when they imply the removed model.

## 4. Canonical Architecture

### 4.1 Chain Layer

The chain layer owns:

- block, transaction, receipt, digest, vote, and frame types
- account/state roots and object-store roots
- consensus and mempool validation
- PTB transaction admission
- deterministic execution receipts

`TxKind` should represent protocol actions that are still canonical. Contract
execution should be represented by a PTB submission variant, not by `Deploy`
or `Call`.

### 4.2 Object/Resource Layer

`bloom-objects` is the leaf data-model crate for:

- `ObjectId`
- `Object`
- `Owner`
- `TypeTag`
- `AbilitySet`
- packets and object references
- object trie / ownership index keys and values

`bloom-resource` is the guest-side runtime for petals:

- `Coin<T>` and `Balance<T>`
- `Capability<T>`
- `Signer`
- `UID`
- `Resource<T>`
- host-import wrappers
- args/return buffer encoding for `__petal_*` exports

### 4.3 PTB Layer

`bloom-script` owns:

- PTB wire types
- canonical encode/decode
- PTB hash/signature domain
- validation against chain state and petal manifests
- borrow-table and linearity checks
- built-in commands
- sequential command execution
- invariant execution

The chain-node layer wires `bloom-script::PtbExecutor` into real wasm
execution through a narrow runner interface.

### 4.4 Wasm Layer

`bloom-petals` owns deterministic wasm execution and host imports. After
consolidation, chain-mode imports should be the Bloom-native imports required
by the resource/PTB model. Legacy account/storage imports should be removed
unless a non-contract core path still needs them.

The VM implementation should be split into smaller modules:

- engine configuration
- wasm validation
- memory helpers
- resource/PTB host imports
- dispatch and early-exit handling
- tests

## 5. ABI and Codec Direction

`bloom-chain-abi` currently mixes useful primitive codec pieces with legacy
selector/contract concepts. The consolidation should narrow or replace it.

Acceptable short-term direction:

- keep low-level deterministic encoding helpers when used by canonical crates
- keep `U256` only if still needed outside removed legacy contracts
- remove or quarantine selector/event/contract macro APIs that exist only for
  legacy account/storage contracts
- prefer object/resource/PTB encoding as the canonical public contract wire
  surface

The final shape can either be a narrowed `bloom-chain-abi` crate or a renamed
codec crate. The important rule is that selector-based contract dispatch is
not canonical.

## 6. Removal Policy

Removal means deletion from active source, workspace membership, tests, CI,
docs, and examples. The archive is git history.

When deleting a crate or example:

1. remove it from workspace members and workspace dependencies
2. remove dependents or port them to the resource/PTB model
3. remove tests that only verify the deleted model
4. update docs and CLI help so users see one contract path
5. run the relevant reduced test matrix

Do not leave "deprecated but compiling" crates unless they are required by
canonical crates during an intermediate commit. If an intermediate shim is
required, mark it with a concrete removal task in the execution plan.

## 7. Canonical Examples

`examples/petal-dex/*`, `examples/petal-cap`, `examples/petal-identity`, and
core petal crates are candidates for the canonical example set.

`examples/dex/*` should be removed if it depends on `bloom-contract`, legacy
`Deploy`/`Call`, wrapped-native assets, approval flows, factories, or other
EVM-shaped concepts.

The final workspace should have enough examples to prove the platform, not a
parallel product surface.

## 8. Acceptance Criteria

The consolidation is complete when:

- no workspace crate depends on `bloom-contract*`
- no protocol code exposes `TxKind::Deploy` or `TxKind::Call`
- no chain VM import exists solely for legacy account/storage contracts
- no default workspace member is an old EVM-style DEX/example
- the canonical PTB/resource tests pass
- CLI/docs describe one contract path
- the codebase has a clear crate graph from chain substrate to object/PTB
  execution to guest runtime

