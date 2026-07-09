# View Functions — Read-Only Petal Calls

**Status:** design, approved for planning
**Date:** 2026-05-29
**Branch:** `feat/view-functions`
**Supersedes:** the current hacked `chain_view_call` (staged, uncommitted) in `crates/bloom-chain-node/src/rpc.rs`
**Scope of this spec:** a first-class, read-only "view" call for petal functions — usable both standalone over RPC/CLI and as composed commands inside ordinary mutating PTBs. Bloombook is a downstream consumer, not part of this spec.

---

## 1. Goal

Give Bloom a real notion of a **view function** — a petal function that performs no state mutation — the way Solidity has `view`/`pure`. A view can be:

1. **Called standalone** over RPC/CLI against a chosen state snapshot (chain head, or a past block within the node's retention window), returning typed values and committing nothing.
2. **Composed inside a normal mutating PTB**, where its return values feed later commands, and where the PTB's signatures authenticate any `&Signer` args.

"View" is a **purity property of the function** (no writes), *not* a statement about how it is called. It does not forbid `&Signer` args.

## 2. Why the current implementation is wrong

The staged `chain_view_call` forges a mutating `PtbTx` and runs it through the commit pipeline, then rejects writes after the fact. That approach has structural problems this spec exists to fix:

- **No first-class view concept.** `FunctionDecl` has no purity marker, so clients can't discover which functions are safe to call as views; "view-ness" is asserted post-hoc by running the body and hoping it didn't write.
- **Forked execution pipeline.** The handler hand-rolls a second copy of `execute_tx_impl`'s `validate → execute → drain` sequence. The two *will* drift — and for a view, drift is a **correctness bug**: a view's whole job is to report what the chain would compute. If it diverges, it lies silently.
- **Synthetic-gas / fake-LOOM hacks.** It fabricates a zero-value gas coin and a fake `Coin<LOOM>` type (`petal_hash = [0u8;32]`) purely to satisfy the mutating validator's gas-payer requirement. A read has no business needing a gas coin, and the fake type diverges from the real chain's LOOM type.
- **Spoofable signers via `AlwaysOkVerifier`.** Caller-named addresses are unauthenticated, inviting false-trust mistakes.
- **Untyped return blobs.** Returns are raw hex; every consumer re-implements the layout by hand.
- **Single-command, tip-only, unmetered.** No composition, no historical reads, and free caller-controlled fuel (DoS surface).

## 3. Architecture

A view call is a **read-only PTB** evaluated against a chosen state snapshot, producing typed return values and never committing. Four layers, each with one job:

```
            manifest `view` flag            (the declared contract / discovery)
                    │
 deploy time:  call-graph verifier          (proves the claim, statically)
                    │
 call time:    view orchestrator            (RPC/CLI: snapshot select, arg decode,
                    │                         fuel cap, effect assertion, return decode)
                    │
 shared core:  validate_ptb(ReadOnly)  +  run_ptb(...) helper
                                            (one source of truth, shared with commit path)
```

The consensus core, state, and the PTB *executor* do not change semantically. We add a read-only validation mode, extract a shared execution helper out of the existing commit path, and add a view orchestrator on top.

### 3.1 Components

**PROTOCOL — new/changed in `crates/`:**

| Unit | Responsibility | Builds on |
|---|---|---|
| `view` flag on `FunctionDecl` (`bloom-petal-manifest`) | Per-function purity marker; bumps `SCHEMA_VERSION`, defaults `false`. The discovery/contract mechanism. | `PetalManifest.functions`, `codec` |
| Call-graph view verifier (in `bloom-petals` chain-mode admission, alongside `CHAIN_ALLOWED_IMPORT_MODULES`) | At deploy, reject any `view`-marked function whose static call graph can reach a mutating host import, or that is not statically analyzable (`call_indirect`). | `chain_vm.rs` import/admission pass |
| `ValidationMode { Commit, ReadOnly }` on `validate_ptb` (`bloom-script`) | `ReadOnly`: no gas-payer-Coin requirement; all object args coerced to `ReadOnly`; absent/zero signatures accepted. Makes read-only a first-class, tested property of the validator. | `validate_ptb`, `ValidationContext` |
| `run_ptb(...)` shared helper (`bloom-chain-node`) | The extracted `validate → host_ctx → snapshot → ChainPetalRunner → PtbExecutor::with_ctx_arc → execute → drain` sequence, taking a state reference + validation mode, returning `ExecutionReport`. One execution core for both commit and view. | `PtbExecutor`, `ChainPetalRunner`, `PtbHostCtx` |
| View orchestrator + `chain_view_call` RPC (`bloom-chain-node`) | Snapshot select (head / `at_block`) → typed-arg decode → `run_ptb(ReadOnly)` with node-clamped fuel → assert empty effect set → typed return decode → drop snapshot. | `run_ptb`, `state_index`, `StateBlobStore`, ABI codec |
| `TypeTag`-driven JSON codec (`bloom-script` or sibling) | Bidirectional: typed JSON args → canonical bytes, and return-slot bytes → typed JSON. Single module so encode/decode can't disagree on layout. | canonical no-float object codec, `TypeTag` |

**`bloom` CLI:** replace `bloom chain view` with the typed surface (`--at-block`, typed `--arg` JSON, pretty typed returns; `--commands <json>` for composed multi-command views).

## 4. Enforcement (layered)

### 4.1 Manifest `view` flag
Per-function `view: bool` on `FunctionDecl`. Bumps `SCHEMA_VERSION`; defaults `false` so existing manifests decode as non-views. This is what lets a client discover callable views and what the RPC checks before agreeing to run one.

Implementation constraint: the manifest codec is positional, so this is a version-aware schema change. New encoders write schema version 2 with the `view` byte in each function declaration. Decoders must still accept schema version 1 manifests by reading the old function layout and materializing `view = false`; version 2 reads the new layout. This is what makes the default meaningful for already-deployed or already-built petals.

### 4.2 Deploy-time call-graph verifier
During chain-mode petal admission, for each `view`-marked export walk its **direct static call graph** from `__petal_<name>`. Reject the deploy if the reachable set touches any **mutating host import**:

`object.create`, `object.transfer`, `object.share`, `object.freeze`, `object.delete`, `object.mutate`.

If the function uses indirect or function-reference calls such that the reachable set cannot be bounded statically, reject it too — views must be statically analyzable. This includes `call_indirect`, `return_call_indirect`, `call_ref`, and `return_call_ref`; direct `return_call` is treated as an ordinary static call edge. Chain-mode Wasmtime also disables the tail-call proposal so these opcodes cannot execute even outside view exports.

Because wasm imports are **module-scoped**, a petal may legitimately hold both view and non-view functions sharing the same imports. The per-function call-graph walk (not a module-wide import ban) is precisely what makes per-function purity decidable.

### 4.3 Always-on runtime backstop
Independent of the flag, `ReadOnly` execution:
- forces every object arg to `AccessMode::ReadOnly`, so `borrow_table.diff_check` rejects any in-memory mutation as `IllegalMutation`;
- asserts the post-execution effect set (`object_writes`, `object_deletes`, `ownership_changes`, `publish_events`) is empty.

A lying or buggy flag therefore still cannot produce or hide a state change. If the backstop ever fires it indicates a verifier/node bug and surfaces as a loud, specific error.

## 5. Security invariant: historical snapshot selection is read-path-only

**Block-height / snapshot selection is a property of the standalone read-only view orchestrator only. It is not expressible anywhere in the committed execution path.**

- **`at_block` lives in the RPC request, never in `PtbTx` or any `Command`.** The wire format of a committed PTB has no "read this at height N" field. When a `SubmitPtb` executes for commit there is structurally no way to request anything but the in-flight head state. A view command composed inside a mutating PTB reads the *same single snapshot* (the block being produced) as every other command. The "trust a value the caller pinned to an old block" attack is impossible because the height cannot be encoded in a committed transaction.
- **`validate_ptb` and `run_ptb` take a state reference, not a height.** They have no concept of "which block," so historical selection cannot leak into the shared core. The `ReadOnly` mode + historical snapshot combination only ever exists in the view orchestrator.
- **One snapshot per evaluation, never per-command.** Even in the read path with multi-command composition, a single `at_block` applies to the whole view PTB.

Second, independent reason this must hold: historical reads are served from the node-local state-blob retention window (`StateBlobStore`, last 256 by default, prunable, operator-configurable). Snapshot availability is non-deterministic across the validator set, so historical state could never participate in consensus-executed work regardless.

**Enforced by:** (1) `at_block` is a field of the view RPC params struct only, never present in `bloom-chain-types` PtbTx/Command; (2) the read-only orchestrator rejects any PTB whose effect set is non-empty, so a mutating command cannot ride the historical path; (3) an explicit test that a committed `SubmitPtb` containing a view command always executes at head, and that no deserialization path carries a height into `validate_ptb`/`run_ptb`.

## 6. Caller identity

- **Standalone read (RPC/CLI):** there are no signatures. Any `signers` supplied are **unauthenticated caller-provided context**. This is safe because all object state is public — "read as if I'm address X" leaks nothing X could not already expose. There is no `AlwaysOkVerifier` shim claiming verification happened; the read path simply does not verify because there is nothing to verify.
- **Composed inside a mutating PTB:** normal signature verification applies to the whole PTB envelope, so `&Signer` args inside a composed view are authenticated and the contract may trust them.

The `view` flag never forbids `&Signer` args; authentication is a property of the calling context, not the function declaration.

## 7. Execution: refactor-first seam

**Step 1 — behavior-preserving, lands green before any view code.**
- Add `ValidationMode { Commit, ReadOnly }` to `validate_ptb`. The single existing call site (`execute_tx_impl`) passes `Commit`. `ReadOnly` is defined but unused at this point.
- Extract the inner `validate → build host_ctx → snapshot → ChainPetalRunner → PtbExecutor::with_ctx_arc → execute → drain` block out of `execute_tx_impl` into a shared `run_ptb(state_ref, mode, …) -> ExecutionReport` helper. The commit path calls `run_ptb(Commit)` and keeps its gas reservation (before) and settlement (after) exactly as today.
- **Guard:** the full consensus + petal-integration suite passes unchanged. This is the proof that approach C did not perturb consensus.

**Step 2 — the view path, built on the shared helper.**
- The view orchestrator: resolve snapshot (head or `at_block`) → decode typed args → `run_ptb(ReadOnly)` with node-clamped fuel cap → assert empty effect set → decode typed returns → drop snapshot.

Gas reservation/settlement stays only in the commit orchestrator, because that is the one thing that genuinely differs between commit and view. The validator rules and execution semantics — the two real sources of truth — are shared, so they cannot drift.

## 8. Snapshot selection

- **Tip (default):** the latest retained/indexed committed state. The in-memory `State` lock may be used only for an actually unprogressed bootstrap node (`head = 0`, no indexed snapshots); it must not stand in for an explicit or default historical height once the chain has progressed.
- **`at_block` N:** resolve N through `state_index` (height → `state_root`, `blob_hash`), load the blob via `StateBlobStore`, reconstruct via `State::from_blob(bytes, expected_state_root)`.
- **Out of retention:** clean `HeightUnavailable { requested, oldest_retained, head }` error.
- **Genesis (height 0):** use a fixed/deterministic snapshot context — never wall-clock time (the current code's `unix_time_ms()` fallback is non-deterministic and is removed).

Implementation constraint: the RPC server must be constructed with `StateIndex` and `StateBlobStore` handles. The in-memory `State` lock is sufficient only for the tip path; historical reads must not reconstruct their own storage paths or bypass the checkpoint verifier.

## 9. Typed ABI

- **Args in:** typed JSON, decoded to canonical bytes by the node using each arg's declared `ArgDecl`/`TypeTag`. Hex `const` remains a lower-level escape hatch. Prior-command outputs referenced via `{"use": {"cmd": i, "ret": j}}` (composition).
- **Returns out:** each return slot decoded against the function's declared `returns` TypeTags into typed JSON — u128 → decimal string, address/hash → hex, vectors → arrays. The raw hex slot is included alongside (`returns_raw`) as an escape hatch; an unknown type degrades gracefully rather than failing the call.
- Both directions share one `TypeTag`-driven codec module so arg-encoding and return-decoding cannot disagree about layout.

Implementation constraint for the first landing: arbitrary nested struct JSON is not decoded from `TypeTag::Concrete` alone because the manifest does not yet carry canonical field layouts for non-object structs. The v0 codec supports primitives, addresses/object ids/hashes, bytes/string, type tags, and fixed-width vectors; custom/unknown concretes degrade to `returns_raw`. Manifest-backed struct layouts are deferred until that schema exists.

## 10. RPC / CLI surface

**RPC `chain_view_call`** params:

```jsonc
{
  "commands": [                 // 1..N read-only commands (composition)
    {
      "path": "/bloom/apps/bloombook",
      "function": "thread_view",
      "hash": "…",              // optional pinned petal hash; else resolve path at snapshot
      "type_args": [ <TypeTag> ],
      "args": [ <typed-arg> ]   // typed JSON; may reference prior outputs via {"use":{cmd,ret}}
    }
  ],
  "signers": ["<addr>", …],     // optional, UNAUTHENTICATED context (default none)
  "at_block": 12345,            // optional; omitted = chain head. READ PATH ONLY.
  "fuel_limit": 1000000         // optional; node clamps to configured max
}
```

Response:

```jsonc
{
  "at_block": 12345,
  "chain_head": 12810,          // lets caller see how stale a historical read is
  "fuel_used": 4210,
  "commands": [
    { "returns": [ <typed-json> ], "returns_raw": ["<hex>"], "logs": [ … ] }
  ]
}
```

**CLI `bloom chain view`:** thin wrapper. Single-command stays ergonomic (`--path/--function`, typed `--arg <json>`, `--type-arg`, `--at-block`, `--fuel-limit`); composed multi-command via `--commands <json>`. Pretty-prints typed returns.

## 11. Error handling

Distinct, actionable variants — not one flattened string:

- `FunctionNotAView` — refused before execution (function not flagged `view`).
- `HeightUnavailable { requested, oldest_retained, head }`.
- `PathNotDeployed` / `PetalHashMismatch` — resolution failures at the chosen snapshot.
- `ArgDecodeError { index, type_tag }` / `ReturnDecodeError { index, type_tag }`.
- `FuelExceeded { limit }` — hit the (possibly clamped) fuel cap.
- `Reverted { reason }` — petal called `petal.revert`; structured `PtbError` preserved.
- `ViewProducedEffects { writes, deletes, ownership_changes, publish_events }` — runtime backstop fired (should be unreachable given the verifier; loud signal of a node/verifier bug).

Implementation note: the first landing preserves the existing JSON-RPC envelope and carries these variants in actionable messages. A typed `error.data` envelope is a follow-up compatibility improvement, not part of the consensus/view safety boundary.

## 12. Testing strategy

- **Manifest/codec:** `view` flag round-trips; old manifests decode with `view = false`; schema-version bump respected.
- **Verifier (unit):** view reaching a mutating import (directly and transitively) rejected; `call_indirect` in a view's reachable graph rejected; a genuinely pure view passes; a mixed petal (one pure view + one mutating non-view) deploys fine.
- **Refactor guard (Step 1):** the entire existing consensus + petal-integration suite passes unchanged after extracting `run_ptb` and adding `ValidationMode` — proof that C did not perturb consensus.
- **`ReadOnly` validation (unit):** no gas-payer Coin required; object args coerced to ReadOnly; absent signatures accepted.
- **View execution (integration):** a real read-only petal returns correctly decoded typed values; multi-command composition threads outputs; a view force-fed a bad flag that tries to mutate is caught by `diff_check` (backstop).
- **Security invariant (§5):** committed `SubmitPtb` with a view command always executes at head; no deserialization path carries a height into `validate_ptb`/`run_ptb`; historical `at_block` works via the read path and errors cleanly past retention.
- **ABI codec:** property-style round-trips per supported TypeTag; unknown type degrades to `returns_raw` rather than failing.
- **Determinism:** the same view at the same `at_block` yields identical results across repeated calls; genesis uses a fixed snapshot, not wall-clock.

## 13. Out of scope (deferred)

- Per-command historical heights (one snapshot per evaluation only).
- Merkle/light-client proofs for view results.
- View results beyond the state-blob retention window.
- Persistent caching of view results.
- Manifest-backed arbitrary struct JSON decoding.
- Typed JSON-RPC `error.data` for view-call failures.
