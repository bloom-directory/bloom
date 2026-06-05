# 08 — Implementation Status (v1)

**Status:** IMPLEMENTED · 2026-05-30
**Role:** Records what was *actually built* against
[`07-implementation-plan.md`](07-implementation-plan.md), the deviations the
build surfaced, the two follow-up gaps closed, the standing test gates, and the
verified remaining gaps. This is the doc to read to know **the state of the code**;
`07` remains the spec it was built from. Petal authors who just want to *write*
an invariant should read [`../../guides/authoring-invariants.md`](../../guides/authoring-invariants.md).

> Supersedes the "none of this is in the code yet" note in
> [`04-decision-log.md`](04-decision-log.md) and the "`return 1` stub" claims in
> [`README.md`](README.md) / [`02-architecture.md`](02-architecture.md). The
> first real invariant, `pool_k_non_decreasing`, now evaluates end-to-end on
> real wasm, reverts on violation, and records its verdict into the consensus
> receipt.

All paths are relative to the repo root (`crates/…`, `examples/…`).

---

## 1. What shipped (v1)

`pool_k_non_decreasing` — an `ObjectType("Pool")` invariant asserting
`after.reserve_a * after.reserve_b >= before.k_last` — fires on every Pool
mutation, evaluates in the compiled `__inv_0` wasm export, reverts the PTB on
violation, records a tri-state verdict, and treats out-of-fuel as *indeterminate*
(no revert). Float opcodes are rejected at deploy.

| Plan step / ADR | What landed | Anchor |
|---|---|---|
| Tri-state result (ADR-002, ADR-008) | `InvariantResult { ok, fuel_used, indeterminate }`; `InvariantVerdict` {Satisfied,Violated,Indeterminate}; `ExecutionReport.invariant_outcomes` | `bloom-script/src/executor.rs:75,122,200` |
| Out-of-fuel → indeterminate | real runner maps `PtbError::OutOfFuel` → `{indeterminate:true}` | `bloom-chain-node/src/chain_petal_runner.rs:299,330` |
| `run_invariant` records verdict (even on success), reverts only on clean `0` | `executor.rs:1390` | `bloom-script/src/executor.rs` |
| Field layout (ADR-011, fixed-prefix) | `canonical_byte_width`; `FieldDecl.offset/width` computed by `#[object]`; `ObjectTypeDeclStub.field_layout` | `bloom-petal-manifest/src/types.rs:129`; `bloom-resource-macros/src/object.rs`; `bloom-script/src/chain_iface.rs:140` |
| `target` + predicate threading | `InvariantDeclStub.target` (`InvariantTargetStub`), projection resolves `manifest.invariants[idx]`, `PetalManifestStub::object_invariants(type)` | `bloom-script/src/chain_iface.rs:163,188,199,57`; `bloom-petal-manifest/src/stub.rs` |
| `BoundedArith` node + lowering (ADR-009) | `PredicateAst::ArithCmp` + `ArithExpr` (Field/Literal/Bounded) + `CmpOp`/`BoundedArithOp`/`Widening`/`OverflowPolicy`; macro lowers `a*b >= k` | `bloom-petal-manifest/src/types.rs:270,305,364`; `bloom-resource-macros/src/invariant.rs:131,196,230` |
| Real `__inv_<idx>` body | `emit_invariant_shim` emits a pure `__bloom_inv_N_eval(&[u8])` + a `#[cfg(wasm32)]` export over the calldata/return ABI; `emit_invariant_runtime` emits the shared 256-bit `__bloom_inv_rt` | `bloom-resource-macros/src/codegen.rs:789,813,829,927` |
| Flat field-table scope (ADR-008) + borrow-table firing (ADR-010) | `invariant_scope.rs` (`build/decode/lookup`); `fire_object_invariants` over dirty rows; `build_object_scope` extracts before/after numeric fields | `bloom-script/src/invariant_scope.rs:36`; `bloom-script/src/executor.rs:669,1440` |
| Float rejection (ADR-004) | `is_float_operator` deny-list in `validate_chain_wasm` | `bloom-petals/src/chain_vm.rs:357` |
| Pool integration | `#[invariant(name="pool_k_non_decreasing", target="Pool", pred=…)]` on `swap_exact_in` | `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:1051` |
| Trusted host interpreter (differential oracle) | `interpret_predicate` — independent reference for `__bloom_inv_0_eval` | `bloom-petal-manifest/src/interpret.rs:50` |
| Spec↔intent v1 substrate (ADR-003): `human_text`, AST→English, vacuity gate | `InvariantDecl.human_text` + codec; `render_predicate_english`; `predicate_triviality` in validate_chain_wasm | `bloom-petal-manifest/src/types.rs:249`, `interpret.rs:165`, `chain_vm.rs:367` |
| **Boundary gate (ADR-003 Tier 1a)** — semantic vacuity detection | `boundary_check` generates boundary + randomized corpus, evaluates via `interpret_predicate`, rejects predicates that are always-true, always-false, or always-indeterminate across their field domains | `bloom-petal-manifest/src/boundary.rs`, `chain_vm.rs` gate F |

---

## 2. Deviations the build surfaced (lessons)

1. **The `return 1` stub hid a wrong ABI.** It compiled and was wired, but had
   never run end-to-end. The real chain-VM ABI delivers the scope via the
   `chain.msg.calldata.read` host import (the export is called with `(0, len)`,
   *not* a memory pointer) and reads the verdict from `chain.petal.return` /
   `ret_buf[0]` — *not* the function's `i32` return. The generated body now reads
   calldata and returns the 1/0 byte via `petal_return` (which diverges; the
   `i32` return is vestigial). See `codegen.rs:813-821`, `chain_petal_runner.rs`
   `call_invariant`. → ADR-013.

2. **Host-side differential tests don't catch host/guest ABI seams.** The
   `interpret_predicate`-vs-`__bloom_inv_0_eval` differential passed even while
   the wasm ABI was broken, because both ran on the host over the same slice.
   Only real `PetalVm::run_chain_call` execution exposed it — hence the
   `--ignored` real-wasm gate (§4).

3. **`InvariantTarget` already existed** in `bloom-petal-manifest`; it was being
   *dropped* at projection. The work was threading `target`/predicate into the
   runtime stubs, not creating the type.

4. **Scope-format unification.** The legacy argspec scope encoder
   (`build_argspec_scope`/`encode_arg_for_scope`) was deleted; both
   function-exit and object-type invariants now build the single flat
   field-table format the guest reads (function-exit emits an empty table — see
   gap G2). This removed a latent format mismatch.

5. **Invariant fuel was drawn from leftover command fuel (fixed 2026-05-31).**
   The first build evaluated invariants on the command's *remaining* fuel, not
   the *separate* invariant-fuel budget ADR-002 mandates. Because the PTB
   submitter controls `gas_budget`, a tight limit could starve the check into
   `indeterminate` (out-of-fuel, non-reverting) and commit a violating state —
   red-team RT-006, realized. Fixed: each evaluation now runs on a fixed
   `INV_FUEL_PER_EVAL` budget independent of command fuel
   (`bloom-script/src/executor.rs`), a deploy-time fuel-headroom gate
   (`predicate_max_fuel` / `MAX_INVARIANT_PREDICATE_FUEL` in
   `validate_chain_wasm`) keeps every deployed predicate well under that
   budget, and `MAX_PREDICATE_DEPTH` bounds decode recursion so a nested
   predicate can't stack-overflow the validator. See RT-006 (RESOLVED).

6. **Field references weren't validated at deploy (fixed 2026-05-31).** Deploy
   validation checked predicate *shape* (ADR-014) but not that referenced field
   *names* resolve in the target scope. A missing field lowers to `0` in the
   guest, and a `Not` over it flips to a false `Satisfied` recorded in
   consensus. Fixed: `validate_chain_wasm` now rejects an object-type invariant
   referencing a non-addressable field and a function-exit invariant
   referencing any field (`collect_field_refs`).

---

## 3. Gaps closed after the initial build

### P1 — Fail-closed on unenforceable predicate shapes
The guest can only enforce `ArithCmp`/`FieldGe`/`FieldLe`/`FieldEq`; other shapes
(`Opaque`, `StrategyKNonDecreasing`, `AllPoolsKNonDecreasing`) previously lowered
to a constant — a declared invariant that silently always passed. Now:
- `predicate_is_enforceable` is the single source of truth
  (`bloom-petal-manifest/src/interpret.rs:39`).
- `validate_chain_wasm` **rejects at deploy** any chain petal with an
  unenforceable invariant predicate (`bloom-petals/src/chain_vm.rs:334`).
- the codegen no-op arm fails *closed* (`1`→`0`) as defense-in-depth
  (`bloom-resource-macros/src/codegen.rs:950`).

This realizes ADR-001's consequence ("`validate_chain_wasm` must reject
chain-mode `Opaque` invariants"). → ADR-014.

### P2 — Invariant verdicts in the consensus `Receipt`
Verdicts were trapped in `ExecutionReport`; the social/trust-scoring layer reads
the persisted SSZ `Receipt` (whose `receipts_root` is in the block header). Now:
- new SSZ `InvariantRecord { cmd_idx, verdict, name }` and
  `Receipt.invariant_outcomes` — a deliberate **consensus-format change**
  (`bloom-chain-types/src/receipt.rs:71,134`).
- threaded `ExecutionReport → ExecOutput → Receipt → RPC JSON`: mapper
  `inv_outcome_to_record` (`bloom-chain-node/src/petal_executor.rs:138`),
  populated on the success path and the `InvariantFailed` revert path; the RPC
  `gettransactionreceipt` response includes `invariant_outcomes`
  (`bloom-chain-node/src/rpc.rs`). → ADR-012.

---

## 4. Standing test gates

**CI (host, always run):**
- scope round-trip + idempotence — `bloom-script` `invariant_scope::tests`.
- tri-state (indeterminate no-revert / satisfied recorded / violated reverts) —
  `bloom-script` `executor::tests`.
- `PredicateAst`/`ArithExpr` codec round-trip — `bloom-petal-manifest` `codec::tests`.
- interpreter semantics (satisfied/violated/extremes/missing) — `interpret::tests`.
- **randomized differential** (2000 random `u128` triples; generated evaluator
  vs interpreter) — `petal-dex-it` `pool_k_invariant::generated_evaluator_matches_interpreter_randomized`.
- float-opcode + **unenforceable-predicate** deploy rejection —
  `bloom-petals` `view_function_verifier_contract`.
- real-manifest wiring (AST + field offsets) + verdict mapper —
  `pool_k_invariant`, `petal_executor::tests::inv_outcome_to_record_maps_verdicts`.
- `Receipt`/`InvariantRecord` SSZ round-trip — `bloom-chain-types` `receipt::tests` + proptest.
- **Boundary gate (ADR-003 Tier 1a)** — semantic vacuity (always-true: `after.x >= 0` on u128; always-false: `after.x >= 256` on u8; always-indeterminate: an underflowing `Sub` over a small domain); non-vacuous passes; deterministic seed — `boundary::tests` + `view_function_verifier_contract::semantically_vacuous_*`.

**`--ignored` (compiles the pool to wasm32; runs in `acceptance.yml` on `pull_request` + push-to-master, not in the default `ci.yml` host job):**
- real `__inv_0` returns `1`/`0` for satisfied/violated scopes + 256-bit
  extreme; fuel non-zero, bounded, deterministic —
  `petal-dex-it --test real_inv_wasm`.
- real swap holds k and the receipt carries a `Satisfied`
  `pool_k_non_decreasing` record —
  `petal-dex-it --test real_wasm_pool real_pool_swap_exact_in_executes`.

---

## 5. Verified remaining gaps

1. **Multi-object / router predicates** (`AllPoolsKNonDecreasing`) are *not*
   enforced — rejected at deploy. Boolean composition now exists (see §7), but
   multi-object scope (one invariant reading several rows) does not. Single-object
   `StrategyKNonDecreasing` is likewise still rejected.
2. **Built-in mutations only fire an invariant if the defining petal's manifest
   is loaded.** Object-type invariants now fire after *any* command that dirties a
   target row, built-ins included (B1, §9) — but `fire_object_invariants` resolves
   the type's invariants through `vtx.manifests.get(petal_hash)`, and that map is
   populated only for petals a `Move` command in the PTB references
   (`bloom-script/src/validator.rs`). So a PTB that mutates a foreign-defined type
   purely via a built-in — e.g. a bare `MergeCoins`/`SplitCoins` on a `Coin` whose
   fungible petal is not `Move`-called in the same PTB — finds no manifest and
   silently skips the check (`bloom-script/src/executor.rs` `fire_object_invariants`,
   the `vtx.manifests.get(...)` `continue`). This is **distinct from cross-petal
   *claims*** (an invariant *referencing* a foreign petal's type, `06` §6 #4): here
   the invariant is local to the type, the gap is manifest *loading*. Closing it
   means loading the defining manifest for every dirtied row's type, not just
   `Move`-referenced petals. v1+.
3. **FunctionExit field predicates** are unsupported: the function-exit scope is
   an empty field table, so such a predicate evaluates fail-closed. Arg/return
   field extraction is future work.
4. **Only fixed-prefix object fields are invariant-addressable** (ADR-011): the
   first variable-width field and everything after it have no offset. Fine for
   the pool (reserves/`k_last` are in the fixed prefix).
5. **Trust scoring (`06`) is not built.** Verdicts now reach the consensus
   receipt (P2), which is the prerequisite, but no scoring/market consumes them.
6. **Indeterminate is only reachable via out-of-fuel**, not arithmetic overflow
   (the U256 widening never overflows for `u128` operands; missing-field is
   fail-closed to violated). The one arithmetic node that *could* go
   indeterminate — `Sub` underflow — is **rejected at deploy** (see v1.3 below),
   so it can never reach the runtime.
7. **Out of scope (per `07`):** Rung-3 fuzzing pipeline, Kani/SMT harnesses,
   `VerificationClaim` schema, per-`object.mutate` checking, cross-petal claims.

---

## 6. Consensus / compatibility note

P2 changed the SSZ encoding of `Receipt`, hence `receipts_root` in the block
header. This is a uniform protocol change (pre-mainnet); no stored fixtures
broke (roots are computed at runtime). Any node must adopt it in lockstep.

---

## 7. Update — v1.1 (2026-05-30): boolean vocabulary + second invariant

- **`And`/`Or`/`Not` added** to `PredicateAst` and wired through every layer
  (macro lowers `&&`/`||`/`!`; codec discriminants 7/8/9; codegen short-circuit;
  tri-state interpreter; `predicate_is_enforceable` recurses — a composite is
  enforceable iff all leaves are). ADR-015.
- **`pool_k_non_decreasing` corrected.** As an `ObjectType("Pool")` invariant it
  fires on *every* Pool mutation, including `remove_liquidity`, where reserves
  (and `k`) legitimately drop — so the original predicate reverted all
  withdrawals (a latent soundness bug; the pre-existing `--ignored`
  `real_pool_add_remove_and_exact_out_execute` would have caught it had it been
  run with the invariant active). Fixed to
  `k_nondecreasing || !(after.lp_supply == before.lp_supply)`; regression test
  `real_pool_remove_liquidity_not_blocked_by_invariant`.
- **Second invariant on a new petal** (`/bloom/core/cap`):
  `cap_revoked_is_monotone` = `after.revoked >= before.revoked &&
  after.inner_kind <= 2` — proves the framework off the DEX and exercises
  `And` + a `FieldGe` over `before/after` + a literal-bounded `ArithCmp`. Tested
  in `examples/petal-cap/tests/invariant.rs`.
- **Codegen fix surfaced by the literal:** `ArithExpr::Literal` now emits a
  suffixed `Nu128` (was the invalid `N u128`); never hit before because pool_k
  used no literal.
- **The design rule the bug exposed:** an object-type invariant must hold across
  *every* mutation of its target (documented in
  `docs/guides/authoring-invariants.md`). Per-function targeting is future work.

**Learning:** both bugs were found by *building a second, different invariant* —
neither was visible from `pool_k` alone (the swap path exercised neither a
liquidity event nor a literal). "Prove the design by building it" (README) paid
off twice; a single example invariant is not enough validation.

---

## 8. Update — v1.2 (2026-06-01): ADR-003 Tier 1a boundary gate

- **Boundary test generation gate** (`boundary_check` in `bloom-petal-manifest/src/boundary.rs`)
  added as gate F in `validate_chain_wasm` (after the structural vacuity gate E).
  Generates a deterministic corpus of scope inputs — boundary values (`0`, `1`, `max/2`,
  `max-1`, `max`), extreme points (all-zero, all-max), and a 2000-case SplitMix64
  randomized sweep — and evaluates the predicate against each via `interpret_predicate`.
  Rejects any predicate that returns exclusively `Satisfied`, exclusively `Violated`, or
  exclusively `Indeterminate` across the entire corpus as **semantically vacuous** (the
  all-indeterminate case — `BoundaryError::AlwaysIndeterminate` — was added with the v1.3
  fixes below: an indeterminate verdict never reverts, so it enforces nothing either).
- **Catches cases gate E misses:** `after.x >= 0` on a u128 field (structurally
  non-trivial, semantically always true because every u128 >= 0); `after.x >= 256` on
  a u8 field (max value 255 → always false). The host interpreter only — no wasmtime
  differential (deferred to follow-up).
- **Field-width-aware:** derives numeric domains from `ObjectTypeDecl.field_layout`
  (only addressable fields: `offset` is `Some`, width in `1..=16`).
- **Deterministic across validators.** Fixed seed (0) via `BoundaryConfig::default()`.
- **Unit tests:** `boundary::tests` covers always-true, always-false, always-indeterminate,
  non-vacuous, empty-field no-op, missing-field error, and seed-deterministic checks.
- **Integration deploy-gate tests:** `view_function_verifier_contract`
  `semantically_vacuous_predicate_rejected_at_deploy` +
  `semantically_always_false_predicate_rejected_at_deploy`.

**Remaining in ADR-003 scope:** `text_hash` cryptographic binding; renderer wired
into the deploy gate; mutation completeness score (Tier 1b); LLM consistency signal
(Tier 1c); adversarial counterexample review UI (Tier 2a); spec test-vector corpus
(Tier 2b). The [`nl-to-invariant/`](nl-to-invariant/RESEARCH.md) inquiry (2026-06-02)
establishes *where* these belong: `text_hash` is deterministic and consensus-safe; the
mutation/LLM/adversarial/test-vector signals are off-chain narrowing aids (the
predicate-vs-intent gap is narrowable but not closable on-chain), and a witness-replay
*refutation* path complements — never replaces — the per-transition checked predicate.
See the ADR-003 amendment (2026-06-02) in [`04-decision-log.md`](04-decision-log.md).

---

## 9. Update — v1.3 (2026-06-01): security-review fixes

A security review of the branch surfaced four follow-ups; all are fixed with regression
tests.

- **Object-type invariants now fire after *every* command, not only `Move`.**
  `fire_object_invariants` moved out of `exec_move` into the per-command loop in
  `execute` (after `dispatch_command`, before `diff_check` clears the dirty flags). A
  built-in mutation — `MergeCoins` / `SplitCoins` calling `borrow_table.mark_dirty` —
  is now evaluated against the type's invariants, where before it was silently skipped
  (the firing was coupled to the Move path). Regression:
  `executor::tests::builtin_mutation_fires_object_invariant`.
  *Caveat unchanged:* an invariant only fires when the type-defining petal's manifest is
  loaded into `vtx.manifests`, which today happens via a `Move` reference to that petal —
  the cross-petal/bare-built-in loading gap remains a v1+ item.
- **Subtraction is rejected at deploy.** The two-valued guest fails closed to `Violated`
  on `Sub` underflow while the trusted interpreter (honouring
  `OverflowPolicy::Indeterminate`) returns `Indeterminate` — a divergence the `pool_k`
  differential (which only exercises `Mul`) does not cover. `predicate_uses_subtraction`
  (`interpret.rs`) gates it as gate 1b in `validate_chain_wasm` until the differential
  covers underflowing `Sub` and the two are reconciled. `Add`/`Mul` are unaffected
  (overflow widens to `TooBig`, resolved identically on both sides).
- **The boundary gate also rejects all-indeterminate predicates.**
  `BoundaryError::AlwaysIndeterminate` — a predicate that never decides across the corpus
  can never revert, so it enforces nothing (§8).
- **The `--ignored` real-wasm ABI gate runs on pull requests.** `acceptance.yml` gained a
  `pull_request` trigger, so the host/guest ABI seam (the `return 1`-stub class of bug,
  §2) is exercised before merge, not only on push-to-master.
