# Bloom contract stack consolidation — /goal prompt

**Date:** 2026-05-26
**Branch:** `feat/bloom-like-petals`
**Spec:** [`docs/specs/2026-05-26-contract-stack-consolidation.md`](../../specs/2026-05-26-contract-stack-consolidation.md)
**Plan:** [`docs/plans/2026-05-26-contract-stack-consolidation.md`](../../plans/2026-05-26-contract-stack-consolidation.md)

This file is a self-contained `/goal` prompt for executing the Bloom smart
contract stack consolidation.

---

## Prompt

```
Consolidate Bloom around the Bloom-native resource/PTB/object contract model.

Use `docs/specs/2026-05-26-contract-stack-consolidation.md` as the canonical
architectural decision and `docs/plans/2026-05-26-contract-stack-consolidation.md`
as the execution plan.

You are on branch `feat/bloom-like-petals`.

Core decision:

- `bloom-resource` / `bloom-resource-macros` / `bloom-objects` /
  `bloom-script` / `bloom-petals` are the canonical smart-contract stack.
- The deprecated EVM-style `bloom-contract*` stack is removed, not maintained
  as a compatibility layer.
- Protocol support for legacy `TxKind::Deploy` and `TxKind::Call` is removed.
- Old EVM-style examples, especially `examples/dex/*` and wrapped-native
  examples, are removed if they depend on the old paradigm.
- Git history is the archive for removed code.

Read first, in order:

1. `docs/specs/2026-05-26-contract-stack-consolidation.md`
2. `docs/plans/2026-05-26-contract-stack-consolidation.md`
3. `docs/specs/2026-05-20-bloom-native-contracts-design.md`
4. `Cargo.toml`
5. `crates/bloom-chain-types/src/tx.rs`
6. `crates/bloom-petals/src/chain_vm.rs`
7. `crates/bloom-chain-node/src/petal_executor.rs`
8. `crates/bloom-script/src/lib.rs`
9. `crates/bloom-resource/src/lib.rs`
10. `crates/bloom-objects/src/lib.rs`

Execution rules:

- Start with inventory. Produce a dependency map and classify crates as
  canonical core, canonical example, legacy removal, temporary bridge, or
  unrelated existing functionality.
- Do not preserve a deprecated crate merely because deletion is noisy.
- Delete old tests when they only validate removed behavior.
- Port only tests that assert canonical PTB/resource behavior.
- Keep edits staged and reviewable by phase.
- Never reintroduce a second contract programming model.
- Do not turn `bloom-contract` into a shim over `bloom-resource`; remove it.
- Do not leave `Deploy` / `Call` as protocol variants after the protocol
  cleanup phase.
- Prefer smaller canonical crates and explicit module boundaries over large
  compatibility files.

Primary deliverables:

1. Remove `bloom-contract*` and old contract/client/build crates from the
   workspace and dependency graph.
2. Remove legacy protocol tx kinds and update encoding, RPC, CLI, VFS, daemon,
   test utilities, and tests accordingly.
3. Remove legacy chain VM imports and split `chain_vm.rs` into focused modules.
4. Narrow or replace `bloom-chain-abi` so the canonical codec story is
   resource/PTB/object oriented, not selector-contract oriented.
5. Remove old EVM-style examples and update acceptance flows to canonical
   petal/PTB examples.
6. Update docs so Bloom presents one smart-contract path.
7. Run the final test matrix or document unrelated pre-existing failures.

Acceptance criteria:

- No workspace crate depends on `bloom-contract*`.
- No active protocol code exposes `TxKind::Deploy` or `TxKind::Call`.
- No chain VM import exists solely for legacy account/storage contracts.
- No default workspace member is an old EVM-style DEX/example.
- Canonical PTB/resource tests pass.
- CLI/docs describe one contract path.
- The crate graph is clear from chain substrate to object/PTB execution to
  guest runtime.
```

