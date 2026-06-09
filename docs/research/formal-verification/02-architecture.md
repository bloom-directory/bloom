# A Verification Architecture for Bloom Invariants

**Design research toward implementing the whitepaper**

**Date:** 2026-05-29 *(amended 2026-05-29 with lit findings + verification market design)*
**Status:** Accepted architecture — the eight forks are resolved per the ten amended,
accepted ADRs in [`04-decision-log.md`](04-decision-log.md). Two finer sub-questions (S4, S5)
remain open (S1, S2, S3, S6 resolved). The market-related questions in
[`06-verification-market.md`](06-verification-market.md) §6 are resolved or deferred.
The verification market design (VerificationClaim schema, invariant lifecycle, trust scoring)
is at [`06-verification-market.md`](06-verification-market.md).

> **Status (2026-05-30): the v1 runtime is built.** `pool_k_non_decreasing` now evaluates
> end-to-end on wasm and reverts on violation — see
> [`08-implementation-status.md`](08-implementation-status.md). Consequently the several
> "`emit_invariant_shim` emits a `return 1` stub (`codegen.rs:787`)" references below are
> **historical**: that stub has been replaced by a real generated evaluator over the
> calldata/`petal.return` ABI (ADR-013). The architecture argument is unchanged; only the
> "not yet built" framing is dated.

---

## Contents

- [Executive summary](#executive-summary)
- [Framing: the corrected verification ladder](#framing-the-corrected-verification-ladder)
- [§1 The predicate object — one artifact, three consumers](#1-the-predicate-object--one-artifact-three-consumers)
- [§2 Arbitration and the human↔machine link](#2-arbitration-and-the-humanmachine-link)
- [§3 Determinism and the execution base](#3-determinism-and-the-execution-base)
- [§4 The canonical replay witness](#4-the-canonical-replay-witness)
- [§5 Proofs and trust scoring](#5-proofs-and-trust-scoring)
- [§6 zkVM soundness as a structural risk](#6-zkvm-soundness-as-a-structural-risk)
- [§7 How the pieces compose](#7-how-the-pieces-compose)
- [§8 The verification market](#8-the-verification-market)
- [§9 Where to start (leverage order)](#9-where-to-start-leverage-order)
- [§10 Remaining open sub-questions](#10-remaining-open-sub-questions)
- [Appendix A — codebase anchors](#appendix-a--codebase-anchors)
- [Appendix B — sources](#appendix-b--sources)

> **Section numbering:** the substantive sections are numbered `§1…§10` (the form every
> cross-reference in this workspace uses). The two intro sections are unnumbered. There is no
> second `## N.` ordinal — an earlier draft carried both and they had drifted out of sync.

---

## Executive summary

The eight forks in §7 of the companion note look like eight independent decisions.
They are not. They collapse into **one architecture** with a single load-bearing
idea: **an invariant is one canonical, readable predicate object that the same system
can *run* at execution time, *fuzz* before deployment, and *prove* for high-value
kernels.** Every other decision follows from protecting that object's three
properties — machine-evaluable, hostile-input-testable, and human-renderable.

Concretely, this document recommends:

- **The predicate is a restricted, total AST** (extending the existing
  `PredicateAst`), and that AST — never an opaque closure — is the canonical
  arbitration-citable form. Closures are a frontend that must lower to it. `Opaque`
  is dev-only. Readability is necessary but not sufficient — ADR-003 adds an
  intent-conformance gate (§1, resolves Q1+Q2, ACCEPTED per [`lit/V-001`](lit/05-verdict-log.md)).
- **Arbitration is a two-stage state machine**: an objective replay that is the *only*
  path allowed to slash, and a separate social "is the prose faithful?" path that can
  only deprecate a vague invariant. **At deploy time, an independent intent-conformance
  gate** (spec test-vectors / adversarial counterexample review) must pass — auto-rendered
  English alone is provably insufficient (§2, resolves Q3, ACCEPTED per
  [`lit/V-001`](lit/05-verdict-log.md) Reading B).
- **Chain mode is integer-only and pinned to a conformance profile backed by a verified
  semantics oracle**, because bit-reproducible execution is a *prerequisite* for every
  replay-based guarantee. Integer-only is the simplest sufficient means, not a necessity.
  The conformance profile is necessary but not sufficient — determinism binds on a pinned
  verified executable Wasm semantics (§3, resolves Q4+Q5, ACCEPTED per
  [`lit/V-003/V-004`](lit/05-verdict-log.md)).
- **Proofs are optional, content-addressed, additive to trust score, and provenance-
  gated** with transfer mechanisms **ranked by TCB** (PCC > translation validation >
  trusted verified compiler). No verified Rust→Wasm compiler exists; reproducible builds +
  differential testing are the near-term gate (§5, resolves Q6+Q7, ACCEPTED per
  [`lit/V-005`](lit/05-verdict-log.md)).
- **No single zkVM is the root of trust**; soundness is bought structurally with a
  re-execution/fraud-proof fallback adjudicating against an **independent reference
  semantics**. All evidence is RISC-V — the corpus contains no Wasm-zkVM paper; the
  verified-Wasm-semantics-as-zkVM-oracle is a conjecture, not a settled basis (§6,
  resolves Q8, ACCEPTED per [`lit/V-006`](lit/05-verdict-log.md)).

Two reframings run underneath all of it. First, **runtime invariants detect, they do
not prevent** — they catch a violation after it fires, so the whitepaper's
supply-chain promise rests on the *by-construction* checks, not the human invariant.
Second, that gap is closed cheaply by a **new rung** the original ladder omitted:
adversarially fuzzing the predicate *before* deployment.

Today the substance is missing: `emit_invariant_shim` emits a `return 1` stub
(`codegen.rs:787`), so the whitepaper's central human artifact currently evaluates
nothing. The recommended first build is therefore narrow and concrete: make
**`pool_k_non_decreasing`** a real predicate end to end, and pilot **Kani on
`bloom-dex-math`**, which is already written in a verification-ready style.

---

## Framing: the corrected verification ladder

The companion note's four-rung ladder needs two corrections before the eight forks
resolve cleanly.

**Correction A — detection is not prevention.** A runtime invariant is evaluated on
the inputs that *happen to occur*. It cannot stop a logic bomb that satisfies the
predicate on every normal input and breaks it only on a trigger nobody replays; by the
time arbitration runs, the damage is done. Only checks that hold *by construction* or
*for all inputs* prevent. This is not a reason to abandon runtime invariants — their
breakage is replayable and arbitrable, which is exactly what pruning needs — but it
must be stated, because it relocates the supply-chain guarantee onto Rung 1.

**Correction B — a rung is missing.** Between "checked on observed inputs" (runtime)
and "proved for all inputs" (formal) sits **pre-deployment adversarial testing**:
generate hostile inputs (proptest / fuzz) against the predicate *before* the petal
is admitted. It is the cheapest mitigation for the logic-bomb class, and — per §1 —
it is nearly free, because the same predicate object that runs at runtime is the
thing you fuzz. *(Correction B2, 2026-05-29: Kani is not fuzzing. It is bounded
model checking — Rung 5, not Rung 3. Fuzzing says "we tried hard and didn't break
it." Kani says "no counterexample exists within these stated bounds." Both are
valuable; they answer different questions.)*

The corrected ladder. **This 5-rung scale is the canonical reference for the entire
workspace.** Two other numberings exist and map onto it: `01`'s 4-rung sketch predates the
fuzzing correction below (it has no Rung 3 = fuzzing, so its Rungs 3–4 are this table's
Rungs 4–5), and `06`'s finer L0–L7 trust-scoring scale subdivides these rungs (see `06`
§4.3 for the L→Rung mapping). When in doubt, this table wins.

| Rung | Guarantee | Prevents a logic bomb? | Where it lives |
|------|-----------|------------------------|----------------|
| 1. VM-enforced protocol invariants | holds for *every* petal, by construction | **Yes** | `validate_chain_wasm`, borrow table, view purity |
| 2. Runtime invariants | checked on *observed* inputs | No — **detection only** | `__inv_<idx>` + executor |
| **3. Pre-deploy adversarial testing** *(new)* | checked on *hostile generated* inputs | Partially — before deploy | proptest/fuzz over the AST |
| 4. Canonical replay witness | makes a violation *objectively arbitrable* | n/a (evidence layer) | content-addressed witness |
| 5. External formal proof | holds for all (bounded) inputs | **Yes** | Kani/Verus/Lean on kernels |

Two principles thread through every section below:

- **Determinism is a prerequisite, not a decision.** A replay witness (Rung 4) is
  meaningless unless two honest nodes compute identical bytes. This forces the answers
  in §3.
- **Arbitration neutrality requires readable predicates.** An opaque predicate fuses
  "the predicate failed" and "the assertion was vague" into one un-adjudicable blob.
  This forces the answers in §1 and §2.

---

## §1 The predicate object — one artifact, three consumers

> Resolves Q1 (own spec language vs. Rust closures) and Q2 (Wasm fn vs. manifest
> expression, and how evaluation is constrained). They are one design decision.

### 1.1 The problem

A predicate must simultaneously be (a) deterministically machine-evaluable at runtime,
(b) fuzzable against generated inputs before deploy, (c) provable for high-value
kernels, and (d) human-renderable so arbitration can read it. No single existing
representation gives all four. A Rust closure compiled to Wasm gives (a) and (b) but is
opaque — it fails (d), and (d) is what makes pruning neutral. A pure prose assertion
gives (d) but nothing else.

The codebase has already started down the right path. `PredicateAst`
(`bloom-petal-manifest/src/types.rs:203`) recognises `FieldGe`, `FieldLe`, `FieldEq`,
the pool-shaped `StrategyKNonDecreasing`, the router-shaped `AllPoolsKNonDecreasing`,
and falls back to `Opaque`. `predicate_ast_of` (`invariant.rs:128`) lowers a Rust
closure into that AST best-effort. But `emit_invariant_shim` (`codegen.rs:787`) emits
a `return 1` stub, and `Opaque` is a silent escape hatch — so today the AST is parsed
and then ignored.

### 1.2 Options weighed

*Note (2026-05-29, amended per [`lit/V-001`](lit/05-verdict-log.md)): opaque closures are
machine-verifiable — Prusti encodes closures into first-order logic via SMT (*abstract*),
and Verus does likewise (*abstract*) — but machine-verifiability is distinct from
governance-auditability. The table below evaluates representational options on the
four-consumer criterion (run, fuzz, prove, read-by-governance), not on sheer verifiability.*

| Option | (a) run | (b) fuzz | (c) prove | (d) read | Verdict |
|--------|:---:|:---:|:---:|:---:|--------|
| Opaque Rust closure → Wasm only | ✓ | ✓ | ✓ | ✗ | Fails neutrality |
| Prose assertion only | ✗ | ✗ | ✗ | ✓ | Not a predicate |
| **Restricted AST (canonical) + compiled `__inv` Wasm + closure frontend** | ✓ | ✓ | ✓ | ✓ | **Accepted** |

### 1.3 Recommended design

**The canonical predicate is the AST. The `__inv_<idx>` Wasm export is its compiled
lowering. A Rust closure is a frontend that must lower to the AST or be rejected.**

- **Two representations, one meaning.** The manifest carries the AST (hashable,
  renderable, and — crucially — replayable by a *trusted* AST interpreter without
  executing the petal's own untrusted Wasm). The VM runs the compiled `__inv` export
  inline on the happy path. The two must be **bit-identical in result**; a differential
  test (AST interpreter vs. `__inv` export over the Rung-3 fuzz corpus) should be a
  standing gate, replacing today's `return 1`.
- **Quarantine `Opaque`.** An `Opaque` predicate may run locally and gate the author's
  own CI, but it is **inadmissible in chain mode and never citable in a slashing
  challenge** (see §2). Allowing an unreadable predicate to ground a slash reintroduces
  exactly the "judge the bytecode's vibes" problem the design exists to remove. In
  practice: `validate_chain_wasm` should reject a chain-mode petal whose manifest
  contains an `Opaque` invariant in an arbitration-relevant slot.
- **Grow the grammar deliberately.** Extend `PredicateAst` to cover the shapes that
  actually recur, keeping every node *total* and *quantifier-free*:

  ```
  PredicateAst :=
    | FieldGe/Le/Eq { lhs, rhs }              // existing
    | StrategyKNonDecreasing { … }            // existing (pool k)
    | AllPoolsKNonDecreasing                  // existing (router)
    | Conserves    { sum_in: [Field], sum_out: [Field] }   // Σin == Σout
    | MonotoneAcross { field: Field, dir: Ge|Le }          // before→after on scope
    | BoundedArith { expr: ArithExpr, op, rhs: ArithExpr } // checked +,-,*,/ only
    | And/Or/Not(Box<PredicateAst> …)         // boolean combinators
    | Opaque                                   // dev-only, never chain-citable
  ```

  `MonotoneAcross` and `Conserves` are what most DeFi invariants actually are
  (`k` non-decreasing, supply conservation); `BoundedArith` over checked integer ops
  keeps the language deterministic and SMT-friendly (§3, §5).

### 1.4 The scope-bytes model *(S1 resolved: ADR-008)*

Most interesting invariants are *relational across a mutation* ("`k` does not decrease
across a swap"), so the predicate needs a defined **scope**: the bytes it is allowed to
read. Define the scope buffer passed to `__inv_<idx>(scope_ptr, scope_len)` as a
canonical encoding built from the same `write_*` primitives as `Object::encode_canonical`
(`object.rs:113`) — `write_u8`, `write_u16_be`, `write_u32_be`, `write_u64_be`,
`write_bytes` (u32 BE len prefix). The wire format (ADR-008, concrete byte layout in
[`07-implementation-plan.md`](07-implementation-plan.md)):

```
InvariantScope encoding :=
  scope_kind:              u8    — 0x00 = FunctionExit, 0x01 = ObjectType
  target_name:             u16 BE len + UTF-8
  petal_version:           u32 BE
  before_count:            u16 BE
  for each before-object:  type_tag(canonical) ‖ version(u64 BE) ‖ payload(u32 BE len + bytes)
  after_count:             u16 BE
  for each after-object:   type_tag(canonical) ‖ version(u64 BE) ‖ payload(u32 BE len + bytes)
  args_count:              u16 BE
  for each arg:            u32 BE len + canonical-encoded Arg
  ret_count:               u16 BE
  for each ret:            u32 BE len + bytes
  // ── field table (ADR-011, S7 resolved) ──
  field_count:             u16 BE
  for each field:          name_len(u16 BE) + name_bytes ‖ value_before(u128 LE) ‖ value_after(u128 LE)
```

`InvariantTarget::ObjectType` invariants see `before`/`after` objects; `FunctionExit`
invariants see `args`/`ret`. The borrow table already provides `type_tag`, `version`,
`baseline_payload`, and `payload_bytes` to the scope builder — no new borrow-table
fields are needed. The `InvariantResult` struct (`executor.rs:73`) gains an
`indeterminate: bool` field so out-of-fuel is distinguishable from `ok = false`
(per ADR-002).

**Field resolution (ADR-011, S7 resolved).** A predicate names fields (`reserve_a`,
`k_last`), but payloads are opaque petal-private blobs. Rather than teach the `__inv` export
struct layouts, the **host** extracts named field values into the flat field table above, and
all four consumers (runtime export, AST interpreter, renderer, fuzzer) read it — none decode
the payload. Offsets/widths are added to `FieldDecl`, computed at `#[object]` macro-expansion
time via `canonical_byte_width`, under a **fixed-prefix rule**: a field is addressable only
while every preceding field has a known fixed width (the first variable-width field truncates
static addressing). Because extraction is *not* covered by the AST-vs-`__inv` differential
test (ADR-002), a wrong/malicious offset is caught instead by the auditable, content-addressed
`scope_def` offsets plus the ADR-003 deploy-time intent-conformance gate (red-team thread
RT-011). The scope builder populates the field table from the before/after payloads using the
compile-time `offset`/`width` on `FieldDecl`; full byte layout and the resolved sub-questions
are in [`03-open-questions.md`](03-open-questions.md) §S7 and ADR-011.

### 1.5 Evaluation constraints — an invariant *is* a view function

Predicate evaluation must not be able to lie, mutate, diverge, or hang. Bloom already
has the template: the view-purity verifier in `chain_vm.rs`. **An invariant predicate
is a view function returning `bool`**, and inherits the same four-layer defence:

1. **Declare** — the predicate is marked in the manifest (it already is, via
   `InvariantDecl`).
2. **Static-check** — its reachable call graph touches no object-mutating import
   (`object.create/mutate/transfer/share/freeze/delete`) and uses no statically
   unbounded call (`call_indirect`, `call_ref`, return-call variants), exactly as
   `validate_view_functions_are_pure` already enforces for views.
3. **Constrained-execute** — scope objects forced `ReadOnly`; metered on a **separate
   invariant-fuel budget** so a predicate can neither starve nor be starved by the
   function it guards.
4. **Runtime-assert** — the post-evaluation effect set must be empty.

**Totality and the trap rule.** The predicate returns `true` (satisfied), `false`
(violated), or exhausts fuel. The *only* legal trap is out-of-fuel, and that outcome is
**`indeterminate`, not `failed`**: a predicate too expensive to evaluate has not been
*violated* and must never ground a slash. The receipt records `{satisfied | violated |
indeterminate}` plus the `invariant_id`, **even on success**, so the witness (§4) can
cite it.

### 1.6 Residual sub-questions

- ~~The exact canonical encoding of `InvariantScope`~~ — resolved: ADR-008 (compose from
  existing `Object::encode_canonical` primitives; concrete wire format in
  [`07-implementation-plan.md`](07-implementation-plan.md)).
- ~~Whether `BoundedArith` needs fixed-point~~ — resolved: ADR-009 (integer-only with
  U256/U512 widening; fixed-point deferred until concrete need).
- ~~**S7 — object field-resolution**~~ — resolved: ADR-011 ACCEPTED (option b: host-side
  schema-driven field table; `FieldDecl` gains `offset`/`width` under a fixed-prefix rule;
  S7a–S7e settled; offset-gaming = RT-011, mitigated by ADR-003). See
  [`03-open-questions.md`](03-open-questions.md) §S7.
- The `InvariantResult` tri-state change and the `run_invariant` scope builder are
  specified in [`07-implementation-plan.md`](07-implementation-plan.md) and must land
  before the `return 1` stub at `codegen.rs:787` can be replaced.

---

## §2 Arbitration and the human↔machine link

> Resolves Q3 (linking human-readable assertions to machine predicates; distinguishing
> "the predicate failed" from "the assertion was too vague").

### 2.1 The problem

The whitepaper anticipates an "indeterminate outcome" where the dispute is about the
*specification* being vague, not the execution. For pruning to be credibly neutral
rather than a popularity contest, "broken" must reduce to a replayable fact, and the
two failure modes — *the predicate evaluated false* vs. *the prose was too loose to
adjudicate* — must be mechanically separable.

### 2.2 Recommended design — bind a pair, adjudicate in two stages

At authoring time, an invariant is the **hashed pair** `{human_text, predicate_ast}`,
both committed into the manifest's `InvariantDecl` (extend it with `human_text` and
`text_hash` alongside the existing `name`, `target`, `predicate`, `wasm_export`).
Arbitration is then a state machine with exactly one slashing edge:

```
            challenge (stake LOOM, cite witness W)
                          │
                          ▼
        ┌──────────────────────────────────────────┐
        │  STAGE A — objective replay (no vote)      │
        │  replay W; evaluate predicate_ast on scope │
        └──────────────────────────────────────────┘
             │ satisfied/indeterminate │ violated
             ▼                          ▼
   challenge dismissed          ┌───────────────────────────┐
   (challenger stake slashed)   │  SLASH petal author        │  ◀── only edge that slashes
                                │  (predicate provably broke)│
                                └───────────────────────────┘
                          │
            (defendant disputes that text matches predicate)
                          ▼
        ┌──────────────────────────────────────────┐
        │  STAGE B — social: is human_text faithful  │
        │  to predicate_ast?  (vote)                 │
        └──────────────────────────────────────────┘
             │ faithful           │ vague/misleading
             ▼                    ▼
   slash stands         DEPRECATE/REPLACE invariant
                        (no author slash; optional refund;
                         propose better invariant)
```

Key properties:

- **Only Stage A can slash.** A violation is mechanical and replayable. A challenge
  that fails Stage A is dismissed and the challenger's stake is at risk — exactly the
  whitepaper's incentive.
- **Stage B can never slash the author.** Vagueness is the *specification* author's
  fault, not the code author's, so its only outcomes are deprecate/replace the
  invariant and (optionally) refund. This *is* the whitepaper's "indeterminate
  outcome / propose a better invariant" path, made precise.
- **Auto-render the AST to canonical English.** Because the predicate language is
  restricted (§1), the system generates prose from the AST ("after `swap`,
  `reserve_a × reserve_b` does not decrease"). Stage B then compares the author's prose
  to the *auto-rendered* prose — a far narrower question than interpreting bytecode,
  and one that shrinks as the grammar covers more shapes.
- **Deploy-time intent-conformance gate (added 2026-05-29 per [`lit/V-001`](lit/05-verdict-log.md)).**
  Auto-rendered English alone is provably insufficient — Verus-SpecGym (*full text*) shows
  an LLM judge reading the spec misses 26% of faithfulness failures, and PropertyGPT
  (*full text*, 42 cites) confirms the gap. At deploy time, an independent machine-assisted
  gate must pass: adversarial counterexample review and/or a spec test-vector suite that
  probes whether the predicate encodes the property the human assertion describes. This is
  the load-bearing mechanism that Stage B's social arbitration cannot be.
- **Pin versions.** The witness binds `(petal_version, invariant_version)` so a
  challenger and defendant cannot equivocate across versions ("but invariant v1 said…").

### 2.3 Residual sub-questions

- Quorum/stake parameters for Stage B (economics, out of scope here).
- Whether an `indeterminate` (out-of-fuel) verdict should be separately challengeable
  as a fuel-budget misconfiguration.

---

## §3 Determinism and the execution base

> Resolves Q4 (reject floats in chain mode?) and Q5 (consensus-pin the engine?). Both
> are facets of one requirement: **bit-reproducible execution**, without which the
> witness (§4), the scoring proofs (§5), and zk-provability (§6) are all meaningless.

### 3.1 Floats — reject them in chain mode (simplest sufficient means)

*Amended 2026-05-29 per [`lit/V-003`](lit/05-verdict-log.md): necessity refuted; engineering case
stands. Typed, restricted Wasm subsets with enforced deterministic semantics are demonstrably
practical (CT-wasm, *full text* — though it is constant-time crypto via secret types, **not floats**,
so it supports this only by analogy; deterministic float execution is addressed directly only by
reproducible-FP work, *abstract*), and canonical chain-nondeterminism bugs trace to scheduling and
read-write hazards, not floats (NPChecker, *full text*). Integer-only exclusion is the simplest
sufficient means at the lowest verification cost — not a logical necessity.*

NaN canonicalization (already configured) is necessary but not sufficient. The residual
hazards survive it:

- **`float → int` conversions** have value- and platform-dependent edge behaviour.
- **FMA / contraction and evaluation order** can perturb low bits across Cranelift
  versions and targets.
- **SIMD float lanes** multiply the surface even with relaxed-SIMD disabled (it already
  is — good).

Two independent arguments converge:

1. **Determinism.** Integer-only execution is dramatically easier to make
   bit-reproducible, and bit-reproducibility is a *prerequisite* for Rung 4 and Rung 5,
   not a nicety.
2. **Provability.** SMT float theory is weak and slow; Kani/Verus reason about bounded
   integers far more reliably. Integer-only is what makes the §5 proofs tractable.

The ecosystem already proves floats are unnecessary: `bloom-dex-math` is integer/`U512`,
checked-arithmetic, property-tested today. The cost of the policy is a **fixed-point
helper library** for the few cases authors reach for floats — a bounded, one-time
investment. `validate_chain_wasm` should additionally reject float opcodes in chain
mode, the same way it already rejects tail-call opcodes.

### 3.2 Engine pinning — pin a *conformance profile*, backed by a verified semantics oracle

*Amended 2026-05-29 per [`lit/V-004`](lit/05-verdict-log.md): the profile is necessary but not
sufficient. Wasm SpecTec (*full text*) ships 23,778 vectors with SIMD excluded and only claims to
"reduce the risk" of divergence — a finite suite samples an infinite input space. The industry's
own move deploys WasmRef-Isabelle (*abstract — fetch failed*) as a verified fuzzing oracle in
Wasmtime CI precisely because conformant engines diverge until caught. Sufficiency is carried by
a **pinned verified executable Wasm semantics**, elevated from "long-term" to load-bearing.*

Two honest nodes must never disagree, so the engine's *observable behaviour* must be
fixed. But pinning an exact Wasmtime/Cranelift build is brittle — a security patch
would require a consensus fork. Pin the **semantics**, not the **binary**:

- **Pinned profile contents:** the allowed feature set (already constrained in
  `CHAIN_ALLOWED_IMPORT_MODULES` and the opcode rejections), the **canonical fuel
  schedule**, integer-only arithmetic (§3.1), and the disabling of every
  spec-nondeterministic feature (relaxed SIMD, threads, multi-memory — already off).
- **First concrete fuel-schedule entries (v1, provisional).** The invariant subsystem
  contributes the first real, hand-picked entries the profile will need to own and
  version: the per-evaluation invariant budget `INV_FUEL_PER_EVAL` (10M;
  `crates/bloom-script/src/executor.rs`), the deploy-time worst-case headroom ceiling
  `MAX_INVARIANT_PREDICATE_FUEL` (5M; `crates/bloom-petal-manifest/src/interpret.rs`,
  enforced in `validate_chain_wasm`), and the predicate decode-depth bound
  `MAX_PREDICATE_DEPTH` (256; `crates/bloom-petal-manifest/src/codec.rs`). They are
  consensus-observable limits chosen by hand for v1, not yet ratified into a pinned
  profile — exactly the kind of schedule entry whose revision process **S5** must
  settle.
- **Enforced by:** a versioned **conformance test-vector suite**. An engine build is
  consensus-eligible iff it passes the suite. This decouples "all nodes produce
  identical results" from "all nodes run an identical binary," so patches and
  cross-platform builds remain possible without forking.
- **Load-bearing oracle:** a mechanized reference interpreter (WasmCert-Coq /
  WasmRef-Isabelle) serves as the **verified differential oracle** — the test suite is a
  fast pre-filter, but the oracle is what makes determinism binding. Interim stance:
  pin the build *and* publish the suite, so the profile is enforceable before the
  verified oracle is deployed.

### 3.3 Residual sub-questions

- The fuel-schedule's exact per-opcode costs (must be part of the pinned profile). The
  invariant subsystem has landed the first concrete entries (`INV_FUEL_PER_EVAL`,
  `MAX_INVARIANT_PREDICATE_FUEL`, `MAX_PREDICATE_DEPTH` — §3.2), still hand-picked and
  provisional; the per-opcode costs remain to be fixed and folded into the profile.
- Governance process for revising the conformance suite (see §10).

---

## §4 The canonical replay witness

> The evidence layer (Rung 4). Not raised as a numbered fork in §7, but it is the
> object §2's Stage A consumes, so its schema must be designed alongside the others.

Pruning is only as neutral as the evidence it adjudicates. A challenge or audit cites a
**content-addressed witness** that binds together everything a replay must reproduce:

```
ReplayWitness := {
  petal_hash,                 // exact deployed wasm artifact
  manifest_hash,              // canonical PetalManifestV0
  petal_version, inv_version, // version pinning (see §2)
  assertion_id,               // which InvariantDecl
  assertion_text_hash,        // ties to human_text (see §2)
  dep_lock,                   // resolved dependency hash table
  block_height, state_root,   // the state the replay runs against
  input_bytes / ptb_bytes,    // the triggering call or PTB
  output_bytes,               // returned values
  effect_set_hash,            // canonical hash of the resulting effects
  fuel_used,
  verdict,                    // satisfied | violated | indeterminate
  trace_hash,                 // optional; see caveat
}
```

Stage A re-derives the verdict from `{petal_hash, manifest_hash, dep_lock,
block_height/state_root, input_bytes}` by replaying and evaluating the AST against the
reconstructed `InvariantScope`.

**The costly field, named honestly.** `trace_hash` / `effect_set_hash` presuppose that
execution is bit-reproducible (hence §3) and that a full trace can be canonically
serialized cheaply. Off-chain this means every honest node runs an identical
instrumented evaluation; on-chain the zk-proof *is* the witness (§6), so `trace_hash`
is either redundant with the proof or a second, separately-trusted execution path.
Recommendation: make `effect_set_hash` mandatory (cheap, deterministic given §3) and
`trace_hash` optional, used only where a dispute needs step-level evidence.

---

## §5 Proofs and trust scoring

> Resolves Q6 (smallest proof-carrying interface) and Q7 (source→Wasm equivalence gap).

### 5.1 The proof-carrying interface — optional, additive, never gating

Proofs *boost* trust; their absence never blocks experimentation. A proof artifact is a
content-addressed blob under `/bloom/<path>/proofs/<hash>`:

```
ProofArtifact := {
  prover_id,             // kani | verus | creusot | hax-fstar | lean | …
  prover_version,
  claim,                 // which InvariantDecl id / function contract it discharges
  certificate,           // machine-checkable artifact, where the prover emits one
  toolchain_attestation, // reproducible-build provenance (see §5.2)
}
```

- **What the registry checks:** the **binding** — the proof references *this exact*
  `petal_hash` + `invariant_id`/contract — and, where the prover emits a re-checkable
  certificate (a Lean `.olean`, a Kani harness + CI attestation), the registry
  re-checks it rather than trusting the submitter.
- **How it feeds score:** weight by *rung* — a Rung-5 proof on an invariant outranks a
  Rung-3 fuzz campaign, which outranks Rung-2 runtime-only. Most petals earn Rungs 2–3
  *for free* from the invariant/fuzz pipeline; the expensive Rung-5 proofs target
  high-value kernels and are usually authored **once by the protocol**, not per petal.

A Kani harness for the pilot looks like this — note it uses the **real** signatures in
`bloom-dex-math` (`ConstantProduct::quote`/`apply_swap` take a `&ConstantProductParams` and
`apply_swap` returns a fallible `(new_in, new_out, out)` triple). Unlike a fuzz harness which
samples concrete inputs, Kani symbolically explores **all** inputs within the bounded domain
(exhaustive within bounds, not randomized):

```rust
#[kani::proof]
fn quote_and_apply_swap_safety() {
    // Inputs bounded to u64 — an explicit, documented bound (not a silent unwind
    // artifact). It keeps the internal U512 long-division shallow enough for the
    // SMT backend, which is what makes this harness tractable as a first proof.
    let reserve_in:  u128 = kani::any::<u64>() as u128;
    let reserve_out: u128 = kani::any::<u64>() as u128;
    let amount_in:   u128 = kani::any::<u64>() as u128;
    let fee_bps:     u16  = kani::any();
    kani::assume(reserve_in > 0 && reserve_out > 0 && amount_in > 0);
    kani::assume(fee_bps < MAX_FEE_BPS);                 // mirrors the quote() guard

    let params = ConstantProductParams { fee_bps };
    if let Ok((new_in, new_out, out)) =
        ConstantProduct::apply_swap(reserve_in, reserve_out, amount_in, &params)
    {
        assert!(out < reserve_out);                      // never drains the pool
        assert_eq!(new_in, reserve_in + amount_in);
        assert_eq!(new_out, reserve_out - out);
        // k does not decrease. Compute k in U512 *exactly*, as the production code
        // does (lib.rs:182-184), because u128 × u128 overflows — the obvious
        // `new_in * new_out >= reserve_in * reserve_out` in u128 is itself a bug.
        let k_before = U512::from(reserve_in) * U512::from(reserve_out);
        let k_after  = U512::from(new_in)     * U512::from(new_out);
        assert!(k_after >= k_before);
    }
}
```

**Kani-readiness of `bloom-dex-math` — target choice and bounds are the whole game.** The
crate is integer-only and checked-arithmetic, but it is *not* uniformly turnkey for Kani; the
loops decide feasibility:

- `quote` / `apply_swap` (`lib.rs:159,202`) are **loop-free** at the source level but pull in
  `U512` long-division. Tractable only under bounded inputs (hence the `u64` assume above).
- `integer_sqrt` (`sqrt.rs:21`) has a data-dependent Babylonian `loop`; it needs
  `#[kani::unwind(K)]`. Kani's auto-inserted **unwinding assertion** fails loudly if `K` is
  too small, so coverage stays honest (`K ≈ 8` suffices for `u128`). Native `u128` only — no
  U512.
- `sqrt_product` (`lib.rs:54`) is a `while lo <= hi` binary search over the full `u128` range
  (~128 iterations) — the **worst** first target; defer it.

**Recommended sequencing:** (1) prove `integer_sqrt`'s contract first (smallest, native
`u128`, teaches the unwind discipline and stands up the toolchain); (2) then the bounded
`quote`/`apply_swap` safety + k-non-decreasing harness above; (3) leave `sqrt_product` for
later, or refactor it toward `integer_sqrt`.

These promote the *existing* example-tests in `bloom-dex-math` from "tested" to "proved
for all bounded inputs," and establish the CI/counterexample workflow on a target where
success is near-certain.

### 5.2 The source→Wasm equivalence gap — provenance-gated, TCB-ranked

*Amended 2026-05-29 per [`lit/V-005`](lit/05-verdict-log.md): the three transfer mechanisms
differ systematically in TCB and should be ranked, not flattened. No verified Rust→Wasm compiler
exists in the corpus (verified F\*→Wasm demonstrates the direction is achievable for a different
source language — Protzenko et al. 2019, *abstract*, 25 cites).*

A Kani/Verus proof is about Rust *source*; the deployed artifact is separately-compiled
*Wasm*. A proof transfers only if compilation is trusted or equivalence is established.
Transfer mechanisms are **ranked by TCB size**, cheapest-credible-per-claim:

- **(a) Default — prove against the deployed artifact's provenance.** Require
  **reproducible builds** + `toolchain_attestation` so the *proven* source hash and the
  *deployed* `petal_hash` share one provenance chain. The gap collapses by construction:
  you are pinning that this attested toolchain produced this exact artifact from this
  exact proven source. This is the realistic near-term gate — **no verified Rust→Wasm
  compiler yet exists**, so trusted-toolchain + reproducible-build attestation is the
  default path to full proof credit.
- **(b) Cross-check — differential testing.** Run the source proof-harness and the
  deployed Wasm over the same Rung-3 fuzz corpus; any divergence flags a
  compiler-introduced gap. Cheap, continuous. Translates to **translation validation**
  tier in the TCB ranking.
- **(c) Flagship tier — mechanized semantics / proof-carrying code.** For flagship
  kernels only. Prove against mechanized Wasm semantics (WasmCert) or emit a
  proof-carrying certificate (DeepSEA *full text*: compiler untrusted, TCB = small
  checker), removing the trusted-compiler assumption. This is the **PCC tier** — smallest
  TCB, highest assurance, highest cost.

**Scoring rule:** a proof's trust-score weight is **discounted unless its provenance
chain reaches the deployed Wasm hash.** Never let a proof-about-source masquerade as a
proof-about-the-artifact.

### 5.3 Residual sub-questions

- Which provers' certificates are economically worth re-checking on-chain vs. off-chain.
- Whether `ProofArtifact` lives in the manifest or purely in the VFS proofs path.

---

## §6 zkVM soundness as a structural risk

*Amended 2026-05-29 per [`lit/V-006`](lit/05-verdict-log.md): core findings are well-supported
(SoK-SNARKs *full text*: 124/141 vulns break soundness, 95/99 circuit-layer bugs are
under-constrained; Arguzz *full text*: 3 soundness bugs post-audit via metamorphic testing +
fault injection on RISC-V zkVMs). But all evidence is **RISC-V** — the corpus has no Wasm-zkVM
paper — and Arguzz is a single uncited 2025 preprint. The transfer to Bloom is by analogy. The
cross-cutting conjecture that a verified Wasm semantics could serve as both the determinism
oracle (ADR-005) and the zkVM fallback adjudicator (ADR-007) is an open question, not a
settled result.*

> Resolves Q8 (the soundness bar for the chosen zkVM).

The risk is sharp and *silent*: independent analysis found ~96% of zkVM circuit bugs are
**underconstraint** — the prover accepts a witness of an *invalid* computation as valid.
An unsound prover therefore emits a valid-looking proof of a *wrong* execution,
indistinguishable from a true one to everyone downstream, which defeats the entire
arbitration/witness model from underneath. "Audited" is not a sufficient answer to a
bug class that is, by nature, invisible.

The bar must be **structural, not just diligence**:

1. **Prefer provers with a formal-verification roadmap** and *published underconstraint
   audits* (e.g. the RISC Zero / Veridise / Nethermind verified-zkVM effort, in Lean),
   evaluated on **soundness evidence, not performance.**
2. **Require a re-execution / fraud-proof challenge window** that adjudicates against an
   **independent reference semantics** (not the prover's own trace), so a single unsound
   acceptance is *catchable* rather than final. This is the structural analogue of not
   resting consensus on the prover being bug-free. Arguzz (*full text*) demonstrates the
   principle via metamorphic testing + fault injection on RISC-V zkVMs, not via
   re-execution against a verified semantics — the independent-oracle requirement is
   Bloom's reasoned extrapolation.
3. **Optional multi-prover diversity** for high-value PTBs — two independent provers
   must agree, so one circuit's soundness bug does not silently pass.
4. **Treat the zkVM as in-scope for the same discipline as everything else:** its
   version pinned (§3-style), its soundness assumptions written down as an explicit part
   of the trusted computing base.

**Minimum acceptable bar:** a documented soundness audit **plus** a re-execution /
fraud-proof fallback adjudicating against an independent reference semantics.
Consensus must never rest on the prover being bug-free.

**Cross-cutting conjecture (not a finding — [`lit/RESEARCH.md`](lit/RESEARCH.md) §"The novel insight"):**
the same **verified executable Wasm semantics** anchoring ADR-005's determinism oracle could
also serve as the independent adjudicator for zkVM fraud proofs, shrinking Bloom's trust
surface materially. This bridges RISC-V and Wasm evidence across different machine models;
**no corpus paper studies a Wasm zkVM.** It is the inquiry's best open question, not a
committed design dependency.

---

## §7 How the pieces compose

The architecture is one pipeline viewed from different angles:

```
                         ┌─────────────────────────────┐
        author writes    │  PredicateAst  (§1)          │  the canonical object
   #[invariant(pred=…)]──▶│  {human_text, predicate_ast}│
        (closure frontend)│  hashed into InvariantDecl   │
                         └──────────────┬───────────────┘
              lowers to                 │ feeds, unchanged, three consumers
        ┌────────────────────┬──────────┴───────────┬────────────────────────┐
        ▼                    ▼                       ▼                        ▼
  RUN (Rung 2)        FUZZ (Rung 3)            PROVE (Rung 5)          RENDER (§2)
  __inv_<idx> export  proptest/Kani over       Kani/Verus harness      auto-English
  on InvariantScope   generated scopes         on bloom-dex-math       for Stage B
  (view-fn purity,    BEFORE deploy            (provenance-gated, §5)
   separate fuel)            │
        │                    │ all execute on the integer-only, conformance-pinned
        │                    │ engine (§3) — so results are bit-reproducible
        ▼                    ▼
  receipt: {verdict, inv_id} ──▶ ReplayWitness (§4) ──▶ Stage A replay (§2)
                                                          │ violated
                                                          ▼ slash
                                              (onchain: witness = zk-proof, §6,
                                               backed by re-execution fallback)
```

Read as a defence-in-depth story: **Rung 1** stops whole classes by construction;
**Rung 3** fuzzes the predicate before deploy to catch logic bombs that **Rung 2**
alone would only detect post-hoc; **Rung 2** continuously checks production and emits
**Rung 4** witnesses; **§2** turns a witness into an objective slash; **§5** lets
high-value kernels climb to **Rung 5**; and **§3/§6** ensure the replay and the proof
underneath all of it actually mean what they claim. The single predicate object is what
lets one authoring act feed run, fuzz, prove, and render without divergence.

---

## §8 The verification market

The eight forks resolved the *what* (predicate language, arbitration, determinism). The
teammate review surfaced the *how* this operates as a system over time: invariants, proofs,
and counterexamples are not one-time badges but **first-class, versioned, curated artifacts**
in a market that arrives at eventual formal verification through constant refinement.

The full design is in [`06-verification-market.md`](06-verification-market.md). Three
structures anchor it:

1. **`VerificationClaim` schema** — the atomic market object. Binds `petal_hash →
   predicate_ast_hash → proof_artifact_hash` in a non-repudiable three-anchor chain.
   Carries explicit assumptions with enforceable classification, intent-conformance
   evidence, mutation quality score, vacuity check, and a version chain
   (`supersedes`/`superseded_by`).

2. **Invariant lifecycle state machine** — `Proposed → Active → {Broken, Ambiguous,
   Superseded, Vindicated} → Deprecated`. Exactly one slashing edge (Stage A objective
   replay). Challenges freeze score. Supersession chains claim versions.

3. **Trust scoring model** — `petal_trust_score = Σ claim_score` per active claim.
   Weights by rung (L1=1 … L7=12), multiplied by vacuity, age, mutation quality,
   assumption enforceability, and verifier diversity. Broken claims cost all their score.

The three markets (spec, counterexample, proof-strengthening) directly feed Bloom's
existing emissions/scoring system: authors earn for high-scoring invariants, challengers
earn for valid counterexamples, and provers earn for attached proof artifacts.

---

## §9 Where to start (leverage order)

Leverage order, not deadlines. Finish what makes the whitepaper's core promise real
before reaching for proof assistants.

> **This is the single canonical build sequence** for the workspace (`01` §6.7's earlier
> sketch points here). The open *design questions* each step depends on — and which to claim
> first — are the work-queue in [`03-open-questions.md`](03-open-questions.md).

1. **Manifest-as-contract + Kani pilot — in parallel, both low-risk.** Consolidate the
   per-petal contract (effect class, object modes, capabilities, return TypeTags,
   `{human_text, predicate_ast}` invariants, dep interface hashes, fuel ceilings) and,
   independently, land the Kani harnesses from §5.1 on `bloom-dex-math`. The pilot
   establishes the proof workflow where success is near-certain.
2. **The predicate object — the critical design fork.** Extend `PredicateAst` (§1.3),
   define `InvariantScope` (§1.4), and replace the `return 1` stub in
   `emit_invariant_shim` with a real AST→Wasm lowering, evaluated under the view-purity
   constraints (§1.5).
3. **First real invariant end to end.** Make `pool_k_non_decreasing`
   (`StrategyKNonDecreasing`, already half-recognised) evaluate, revert on violation,
   and emit a receipt — the whole Rung-2 path on one concrete property.
4. **Add the pre-deploy fuzz rung — nearly free.** Point proptest/fuzz at the same
   predicate object before admission (Rung 3). Kani feeds the fuzz corpus with
   counterexamples but lives at Rung 5 — same harness, different guarantee.
5. **Canonical witness (§4) + promote implicit Rung-1 checks** (dependency hash-pinning,
   ABI/interface-hash match, return-bytes-match-TypeTag) to hard admission checks.
6. **Determinism hardening (§3):** integer-only chain mode + conformance profile.
7. **Long-horizon, separable track:** zkVM soundness evaluation (§6) and
   Wasm-semantics grounding (§5.2(c)).

---

## §10 Remaining open sub-questions

Genuinely unresolved finer forks, surfaced for the team rather than decided here.
S1, S2, S6, S7 are resolved (ADR-008, ADR-010, ADR-009, ADR-011) and removed from this list.

1. **Multi-prover economics (S4).** When is two-prover agreement worth the cost, and who
   pays?
2. **Conformance-suite governance (S5).** Who can revise the pinned profile / fuel
   schedule, and through what process, without enabling a stealth consensus change?

---

## Appendix A — codebase anchors

For the implementing agent. All paths relative to `bloom/`.

| Concept | Location |
|---------|----------|
| `PredicateAst` enum (FieldGe/Le/Eq, StrategyKNonDecreasing, AllPoolsKNonDecreasing, Opaque) | `crates/bloom-petal-manifest/src/types.rs:203` |
| `InvariantDecl { name, target, predicate, wasm_export }` | `…/types.rs:173` |
| `InvariantTarget` {ObjectType, FunctionExit} | `…/types.rs:186` |
| `PetalManifestV0.invariants`; `FunctionDecl.attached_invariants` | `…/types.rs:36`, `…:141` |
| Closure → AST best-effort lowering (`predicate_ast_of`, `build_decl`, `expand`) | `crates/bloom-resource-macros/src/invariant.rs:104,128,198` |
| `emit_invariant_shim` — the `__inv_<idx>(scope_ptr,scope_len)->i32` **`return 1` stub** | `crates/bloom-resource-macros/src/codegen.rs:787` |
| `CHAIN_ALLOWED_IMPORT_MODULES` = [chain, object, cap, signer, ptb, log] | `crates/bloom-petals/src/chain_vm.rs:197` |
| `validate_chain_wasm` (import/export/memory/opcode admission) | `…/chain_vm.rs:225` |
| Object-mutating host imports (create/mutate/transfer/share/freeze/delete) | `…/chain_vm.rs:631,686,805,896,935,975` |
| View-purity verifier (the four-layer template to imitate) | `…/chain_vm.rs` (`validate_view_functions_are_pure`) |
| Kani pilot target: `quote`, `apply_swap`, `MAX_FEE_BPS`, `integer_sqrt` | `examples/petal-dex/crates/bloom-dex-math/src/lib.rs`, `…/sqrt.rs:7` |
| Prior research note this builds on | [`01-background-research.md`](01-background-research.md) (the canonical original note) |
| Spec sections referenced (§12 invariants, §12.1–12.3, §14.3) | `docs/specs/2026-05-18-petals-design.md` |

---

## Appendix B — sources

External research carried forward from the companion note.

- **Kani** — attributes, loop/function contracts, releases: <https://model-checking.github.io/kani/>;
  function contracts: <https://model-checking.github.io/kani-verifier-blog/2024/01/29/function-contracts.html>
- **Verifying the Rust std library with Kani (AWS):** <https://aws.amazon.com/blogs/opensource/>
- **Verus** — Verifying Rust Programs using Linear Ghost Types: <https://github.com/verus-lang/verus>
- **Move Specification Language (Aptos):** <https://aptos.dev/build/smart-contracts/prover/spec-lang>
- **Fast and Reliable Formal Verification with the Move Prover:** <https://arxiv.org/pdf/2110.08362>
- **Sui Prover goes open source (Jan 2026):** <https://blockeden.xyz/blog/2026/01/20/sui-prover-formal-verification/>
- **WasmCert / Two Mechanisations of WebAssembly 1.0:** <https://vtss.doc.ic.ac.uk/publications/WasmCert>
- **Progressful Interpreters for Efficient WebAssembly Mechanisation (Wasm 2.0):** <https://dl.acm.org/doi/10.1145/3704858>
- **hax (Cryspen)** — verifying security-critical Rust with multiple provers: <https://eprint.iacr.org/2025/142>; <https://github.com/cryspen/hax>
- **InvBench: Can LLMs Accelerate Program Verification with Invariant Synthesis?** <https://arxiv.org/abs/2509.21629>
- **RISC Zero — path to the first formally verified RISC-V zkVM:** <https://risczero.com/blog/>
- **Veridise on RISC Zero zkVM security (underconstrained bugs):** <https://veridise.com/blog/>
- **Nethermind — towards formal verification of the first RISC-V zkVM (Lean):** <https://www.nethermind.io/blog/>
