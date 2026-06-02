# Rung 3 State-of-the-Art: Invariant-Aware Fuzzing for Bloom

**Date:** 2026-05-29
**Status:** Literature survey — input to the Rung 3 design
**Scope:** How existing tools and papers structure fuzzing that targets invariant violations, and what is practical to integrate with Bloom's predicate AST model.

---

## 1. Tools that structure invariant-aware fuzzing

### 1.1 Echidna (Trail of Bits)

- **Mechanism:** Grammar-based fuzzing from contract ABI. Invariants are `echidna_*` Solidity functions returning `bool`. Each fuzz sequence generates random calls; after each sequence, Echidna evaluates the invariant function. Coverage-guided: corpus of coverage-increasing call sequences feeds mutation. Supports multiple modes: `property` (invariant checking), `assertion` (detect `assert`/`require` failures), `overflow`, `optimization`.
- **How invariants are targeted:** Indirect — the invariant is a passive observer. The fuzzer maximizes *code coverage*, hoping to reach states that violate the invariant. No SMT/symbolic guidance toward the invariant's specific branches. Echidna does *not* extract the predicate structure — it just calls the invariant function and checks the return value.
- **Relevance to Bloom Rung 3:** Medium. The corpus-collection + mutation + coverage-guidance pattern is directly applicable. The invariant-as-observer model maps cleanly: Bloom's `__inv_<idx>` export is exactly an Echidna-style invariant function. **Gap:** Echidna doesn't exploit predicate AST structure to generate inputs that specifically target the invariant's comparison nodes.
- **AST integration:** Low. Echidna treats invariants as black-box functions. No predicate-AST awareness.

### 1.2 Medusa (Trail of Bits, Go reimplementation of Echidna)

- **Mechanism:** Parallelized, coverage-guided, mutational Solidity fuzzing powered by go-ethereum. Same core pattern as Echidna: corpus collects coverage-increasing sequences, mutations from the corpus. Built-in assertion and property testing. Extensible via Go-level test API with hooks and events throughout the fuzzer lifecycle.
- **How invariants are targeted:** Identical to Echidna — black-box invariant function evaluation after call sequences. No predicate-structure awareness.
- **Relevance to Bloom Rung 3:** Medium. Parallel fuzzing is relevant for Bloom's multi-petal pre-deploy gate. The extensible Go API (hooks/events) is the pattern to replicate: Bloom's Rung 3 should expose hooks where `PredicateAst` nodes can drive input generation.
- **AST integration:** Low, but the extensible API model is instructive. Bloom could define an `InvariantFuzzHooks` trait that receives the predicate AST and guides mutation.

### 1.3 Foundry `forge test` / `invariant_*` (Paradigm)

- **Mechanism:** Foundry's invariant testing uses `invariant_*` functions (no args, return void, use `assert*` helpers). Forge runs random call sequences, evaluating invariants after each call. Uses dictionary-based fuzzing (structuring inputs around ABI types) and coverage guidance. Integrates with `forge coverage` for coverage reports.
- **How invariants are targeted:** Same black-box model. Invariants are Solidity functions called after each tx in the sequence. Foundry does not extract or reason about the invariant's internal predicate structure.
- **Relevance to Bloom Rung 3:** Medium. Foundry's dictionary-based input generation (weighted toward values that increase coverage) is a practical baseline. The `invariant_*` naming convention maps to Bloom's `__inv_<idx>` exports.
- **AST integration:** Low. No predicate-AST awareness. But Foundry's cheatcode system (mocking `block.timestamp`, pranking addresses) suggests Bloom's Rung 3 should control the petal's host environment during fuzzing.

### 1.4 Harvey (ConsenSys / Maria Christakis et al.)

- **Mechanism:** Greybox fuzzer for smart contracts. Two key innovations: (1) *Input prediction* — uses lightweight static analysis to predict inputs more likely to cover new paths (e.g., if a branch checks `x > 100`, generate values near 100). (2) *Demand-driven transaction sequences* — only explores state transitions that actually exercise new code, avoiding wasteful random sequence generation.
- **How invariants are targeted:** Harvey doesn't target invariants directly — it detects assertion failures, reentrancy bugs, etc. during execution. The input prediction technique is the relevant piece: it uses branch conditions to *guide* input generation.
- **Relevance to Bloom Rung 3:** **High.** Harvey's input prediction is the closest existing technique to what Bloom's Rung 3 should do: extract the predicate AST's comparison nodes (`FieldGe`, `FieldLe`, `FieldEq`, `BoundedArith`) and generate inputs specifically targeting the boundary values. Harvey does this for arbitrary branch conditions; Bloom can do it *specifically for the invariant predicate*.
- **AST integration:** High pattern match. Harvey's `InputPredictor` component analyzes branch conditions. Bloom's `PredicateAst` already encodes the conditions explicitly — no extraction needed. The technique transfers directly: for `FieldGe { lhs, rhs }`, generate inputs where `lhs = rhs`, `lhs = rhs - 1`, `lhs = rhs - ε`.

### 1.5 SMARTIAN (KAIST, 2022)

- **Mechanism:** Static-analysis-augmented smart contract fuzzer. Uses Slither-based static analysis to extract data-flow and control-flow information, then uses this to generate *semantically meaningful* input sequences. Combines: static analysis → ABI type inference → targeted mutation. Known to outperform Echidna and Harvey on some benchmarks for branch coverage.
- **How invariants are targeted:** Not invariant-specific; aims at general vulnerability detection and coverage.
- **Relevance to Bloom Rung 3:** Low-Medium. The static-analysis-to-fuzzing pipeline is relevant, but Bloom's advantage is that the predicate AST is already a statically-analyzed form — the invariant's internal structure IS the analysis result.
- **AST integration:** Medium. SMARTIAN shows that static analysis of the program can seed fuzzer knowledge. Bloom already has this knowledge in the `PredicateAst`.

### 1.6 Belobog (Aptos/Move)

- **Mechanism:** Fuzzer for the Move language. Generates transaction sequences by mutating existing transactions. Uses *state-aware* fuzzing: tracks the global state of the Move VM across sequences, uses this to avoid redundant exploration. Focuses on detecting abort conditions and invariant violations in Move modules.
- **How invariants are targeted:** Move's `spec` blocks contain invariants; Belobog checks `abort_if` conditions and spec violations during fuzzing. Not deeply AST-aware for spec predicates.
- **Relevance to Bloom Rung 3:** Medium-High. Move's resource model is the closest analog to Bloom's borrow table. Belobog's state-aware fuzzing (tracking object state across sequences) is directly applicable to Bloom's object-based execution model.
- **AST integration:** Medium. Move specs are declarative but Belobog treats them largely as pass/fail oracles.

---

## 2. Coverage-guided property-based testing (CG-PBT)

### 2.1 Coverage Guided, Property Based Testing (Lampropoulos, Hicks, Pierce — OOPSLA 2019)

- **Mechanism:** Marries QuickCheck-style property-based testing with coverage guidance from AFL-style fuzzing. The key insight: random input generation (QuickCheck) finds shallow bugs fast, but stalls on sparse preconditions. Coverage guidance (AFL) steers inputs toward uncovered branches, which often correspond to the property's precondition. **Fuses two generators: one random (QuickCheck), one coverage-guided (AFL), with a feedback loop where coverage data informs the random generator.**
- **How invariants are targeted:** The property is the test oracle. Coverage guidance generates inputs that *reach more code*, which increases the chance of hitting the property's guarded failure case. A **crowbar** mechanism: the coverage-guided generator tries to bypass the property's own precondition guard (the `==>` operator in QuickCheck) by mutating inputs that got further through the predicate.
- **Relevance to Bloom Rung 3:** **Very High.** This is the most directly applicable paper. Bloom's Rung 3 should implement the same fusion:
  1. A QuickCheck/`proptest`-style generator for the scope-bytes + input-args of a petal function.
  2. A coverage-guided mutator that measures Wasm block coverage during invariant evaluation.
  3. A feedback loop where inputs that increase invariant-evaluation coverage are retained in a corpus and mutated.
  4. Specific targeting: inputs that cause the invariant to evaluate *differently* (e.g., from `FieldGe` returning `true` to `false`) are prioritized.
- **AST integration:** Very High. Bloom's `PredicateAst` replaces QuickCheck's `==>` guard. The AST nodes are the *explicit precondition tree*, and Rung 3 can use this tree to:
  - Weight mutations toward boundary values of each `FieldGe`/`FieldLe`/`FieldEq` node.
  - Track which AST leaf was "closest to failing" and focus mutation there.
  - Perform "predicate coverage" — a novel coverage metric: which comparison nodes in the predicate AST were evaluated, and with what result.

### 2.2 Crowbar (QuickCheck + AFL bridge — earlier work by same authors)

- **Mechanism:** Predecessor to CG-PBT. Uses AFL to generate inputs that satisfy a property's precondition (the `==>` guard), then feeds them to QuickCheck's generators. Less integrated than the OOPSLA 2019 paper.
- **Relevance to Bloom:** Medium. Conceptually simpler but less effective than the 2019 fusion.

---

## 3. Kani bounded model checking — complementary to fuzzing, distinct in guarantee

*Note (2026-05-29): Kani is **not fuzzing**. Fuzzing samples concrete inputs and reports "we didn't find a counterexample in the cases we tried." Kani symbolically explores all possible inputs within a bounded domain and reports "no counterexample exists in this bounded model." The harnesses look test-like, but the mechanism is SMT-backed bounded model checking, not randomized testing. Kani sits at Rung 5 (proofs), not Rung 3 (fuzzing). The two are complementary: fuzzing finds bugs cheaply on many inputs; Kani proves absence of bugs exhaustively within stated bounds.*

### 3.1 Kani (AWS model-checker for Rust)

- **Mechanism:** Kani uses CBMC-based bounded model checking. A proof harness is a Rust function with `kani::proof` attribute, calling code under verification with `kani::any()` symbolic inputs. Kani translates Rust → Goto-C → SAT/SMT query. If the query is SAT (property violated), Kani produces a concrete counterexample. If UNSAT (property holds within bound), Kani proves it. If timeout, property is undecided.
- **Kani ↔ fuzz pipeline (complementary, not substitutable):** Kani and fuzzing solve different problems:
  1. Fuzzing (Rung 3): sample many concrete inputs, find counterexamples cheaply. Result: "we found a bug" or "we didn't find one yet."
  2. Kani (Rung 5): exhaustively check all inputs within bounded domain. Result: "no counterexample exists in these bounds" or "here's a concrete counterexample."
  3. The bridge between them: Kani's counterexamples (when SAT) seed the fuzz corpus. The fuzzer's coverage data can flag paths Kani should bound more deeply. A shared harness (same input model) lets both tools operate on the same property without redundant authoring.
- **Relevance to Bloom:** Kani is a Rung 5 artifact that strengthens a Rung 2/3 invariant claim. It provides bounded exhaustive assurance for small pure kernels (DEX math, codecs, fuel arithmetic). The `BoundedArith` PredicateAst node is explicitly designed to make the invariant SMT-encodable so Kani can discharge it. Kani counterexamples become Rung 4 witness seeds.

### 3.2 VeriWasm / Crocus (Wasm verification with fuzz oracle)

- **Mechanism:** VeriWasm: SFI safety for native-compiled Wasm. Crocus: verified Wasm→native instruction selection. Not directly fuzzing-integrated, but both use *differential testing* where the verified component is fuzzed against an unverified oracle.
- **Relevance to Bloom Rung 3:** Medium. The differential testing pattern (AST interpreter vs. `__inv` Wasm export) is structurally identical. Bloom should fuzz both paths with identical inputs and assert bit-identical results.

---

## 4. Differential fuzzing between spec and implementation

### 4.1 Uncovering Smart Contract VM Bugs Via Differential Fuzzing (Neo et al., 2022)

- **Mechanism:** Generates EVM bytecode programs, executes them on multiple EVM implementations (geth, OpenEthereum, Nethermind, Besu), and compares state roots. Differential fuzzing reveals consensus bugs where different VMs produce different results. Found 12 new consensus bugs in production EVM clients.
- **Relevance to Bloom Rung 3:** **High — direct structural analog.** Bloom's invariant evaluation has two paths: (1) the compiled `__inv_<idx>` Wasm export, and (2) the AST interpreter. These are exactly "two implementations of the same spec" and should be differential-fuzzed. The paper's methodology of:
  - Generating random Wasm programs (petal function inputs + scope-bytes)
  - Executing on both implementations
  - Comparing results
  - Minimizing differences

  maps 1:1 to Bloom's "AST interpreter vs. compiled Wasm invariant" gate.
- **AST integration:** Very High. The AST is one of the two implementations being compared.

### 4.2 Verus-SpecGym (Agarwal et al., 2026)

- **Mechanism:** Evaluates LLM-generated formal specifications by *executing* them as Rust code and testing against official test cases + adversarial "hacks" (edge cases from competitive programming). Key finding: frontier models achieve 77.8% spec faithfulness; LLM judges miss 26% of faithfulness failures; generated specs can omit input assumptions, accept incorrect outputs, or reject valid ones.
- **Relevance to Bloom Rung 3:** **High.** This paper attacks the spec↔intent gap — exactly the problem identified in Bloom's ADR-003. The adversarial test case approach (using Codeforces "hacks" as hostile inputs) is a model for Bloom's intent-conformance gate: generate adversarial counterexample inputs that a *faithful* spec would reject but a *buggy* spec might pass.
- **AST integration:** High. Bloom's `PredicateAst` is machine-renderable to English; the Verus-SpecGym methodology can be applied to test whether the AST faithfully captures the human's English prose invariant.

### 4.3 PropertyGPT (NDSS 2025 — 42 cites)

- **Mechanism:** LLM-driven specification generation for smart contracts. Uses retrieval-augmented generation (RAG) to produce verification properties from natural-language descriptions. Key insight: the spec-autogeneration problem is hard; testing the generated spec against known buggy implementations (mutants) is essential.
- **Relevance to Bloom Rung 3:** Medium-High. If Bloom uses LLMs to generate predicate ASTs from prose, PropertyGPT's methodology for testing generated specs against mutants is essential.

---

## 5. Fuzzing with symbolic execution guidance

### 5.1 ILF: Learning to Fuzz from Symbolic Execution (He et al., CCS 2019)

- **Mechanism:** Uses symbolic execution (Mythril) to *train* a neural network to generate inputs that reach deep paths. Symbolic execution solves path constraints, the NN learns the distribution of satisfying inputs, and the fuzzer uses the NN as a generator. Symbex → training data → learned generator → fuzzer.
- **Relevance to Bloom Rung 3:** Medium. The pattern of "symbolic execution informs fuzzer" is relevant, but the NN component is unnecessarily complex for Bloom. A simpler approach: use SMT solving (Z3) directly on the `PredicateAst` nodes to generate boundary-violating inputs.

### 5.2 SMT-based input generation for predicates (general approach)

- **Mechanism:** Given a predicate AST, encode each comparison node as an SMT constraint. To generate an input that *violates* the predicate: negate the root constraint and ask Z3 for a model. To generate an input that *satisfies* a specific branch: add the branch condition as a constraint and solve.
- **Relevance to Bloom Rung 3:** **Very High.** This is the single most powerful technique for "fuzzing the predicate AST":
  1. For each leaf node in `PredicateAst` (e.g., `FieldGe(lhs, rhs)`), negate it: `lhs < rhs`.
  2. If the leaf depends on computed expressions (`BoundedArith`), recursively encode the expression DAG as SMT expressions.
  3. Ask Z3 for concrete values. Feed these as the fuzzer's initial corpus.
  4. This guarantees coverage of *every* predicate-violation boundary in one shot.
  5. For the scope-bytes: treat them as opaque bitvectors; SMT can generate concrete byte sequences that satisfy/violate the predicate.
- **Limitation:** SMT works for the predicate *in isolation*. The predicate's inputs (field values) may come from Wasm computation — the SMT solver doesn't know the Wasm semantics. So the SMT-generated inputs are the *ideal target* for the fuzzer to try to make the Wasm computation produce.
- **AST integration:** Very High. This is the killer integration: the AST nodes ARE SMT-encodable expressions. `BoundedArith` is explicitly designed for this.

### 5.3 Concolic testing / DART / CUTE / SAGE (Microsoft)

- **Mechanism:** Concolic (concrete + symbolic) execution: run the program concretely, collect path constraints symbolically, negate one constraint at a time, solve with SMT, generate new input. SAGE (Microsoft) found 1/3 of all Win7 security bugs.
- **Relevance to Bloom Rung 3:** Medium. Concolic testing on Wasm is possible (e.g., Wasm symbolic execution engines), but Bloom's predicates are small enough that direct SMT encoding of the AST is more practical.

---

## 6. Almost correct invariants: synthesizing inductive invariants by fuzzing proofs

### 6.1 Note on the specific paper

- The exact title "Almost correct invariants: synthesizing inductive invariants by fuzzing proofs" does not appear as a standalone publication in the corpus. The closest matches are:
  1. **"Synthesizing Inductive Invariants by Fuzzing Proofs"** — related to the ICE learning framework (Garg et al., CAV 2014, "ICE: A Robust Framework for Learning Invariants") which uses a learner, a teacher (verified), and a fuzzer to iteratively refine candidate invariants.
  2. **"Almost correct invariants"** — related to work on invariant inference where approximately-correct invariants are tuned via counterexamples from bounded model checking or fuzzing.
  3. **Daikon** (Ernst et al.) — dynamic invariant detection: run the program, observe value traces, infer likely invariants. "Almost correct" in that Daikon's invariants are observed-on-inputs, not proved.

### 6.2 The general approach: fuzz-refine-prove loop

- **Mechanism:** Start with a candidate invariant (possibly too weak or too strong). Fuzz the program: if the invariant passes all fuzz inputs, it might be true (or the fuzzer missed the counterexample). If the invariant fails a fuzz input, weaken it (or conclude the program is buggy). If the invariant passes, try to prove it. If the proof fails, the prover produces a counterexample-to-induction (CTI) — feed this to the fuzzer to confirm it's real. Iterate until a provable invariant is found.
- **Relevance to Bloom Rung 3:** Medium. Bloom's invariants are *human-authored*, not synthesized. But the refinement pattern applies:
  - Rung 3 fuzzing finds counterexamples → the human strengthens the invariant.
  - If Rung 3 finds no counterexample, graduate to bounded proof (Kani).
  - If Kani finds a CTI (not a real bug, just a loop unrolling limit), feed it to the fuzzer to see if it's reachable.

### 6.3 ICE learning framework (Garg et al., CAV 2014)

- **Mechanism:** ICE = Implication CounterExample. Three agents: Learner proposes candidate invariants. Teacher checks if they're inductive (if yes, done). Fuzzer searches for counterexamples to the learner's candidates. The key: the fuzzer provides *implication counterexamples* — states where the candidate invariant holds but the post-state violates it. This drives the learner toward inductive invariants.
- **Relevance to Bloom Rung 3:** Medium. Bloom's invariants are safety properties, not full inductive invariants. The ICE pattern suggests that Rung 3 should not just check "does the invariant hold in the post-state?" but also "could a transition from a state where the invariant holds lead to a state where it doesn't?"

---

## 7. Mutation-based invariant testing

### 7.1 General approach: mutation testing of specifications

- **Mechanism:** Mutate the specification (predicate AST) to produce mutants. Run the original program against each mutant spec. If the original program *passes* the mutant (the mutant doesn't catch a known bug), the original spec might be too weak. If the original program *fails* the mutant, the mutant is stronger — a candidate improvement.
- **Specific techniques:**
  - **Comparison flip:** `>=` becomes `>`, `==` becomes `!=`.
  - **Constant mutation:** Replace constant operands with boundary-adjacent values.
  - **Compound weakening:** `And(a, b)` → `a` alone (drop a conjunct).
  - **Compound strengthening:** `a` → `And(a, b)`.
  - **Scope mutation:** `MonotoneAcross(field, Ge)` → `MonotoneAcross(field, Le)`.
- **Relevance to Bloom Rung 3:** **High.** This is a cheap, AST-native technique:
  1. Given a `PredicateAst`, generate N mutants.
  2. Run known-correct and known-buggy petal executions against each mutant.
  3. A good mutant should: (a) pass all known-correct executions, (b) fail on known-buggy executions.
  4. If a mutant fails known-correct executions, it's too strong.
  5. If a mutant passes known-buggy executions, the original spec is weaker than it should be.
  6. This is an automated spec quality metric — the first line of defense in ADR-003's intent-conformance gate.
- **AST integration:** Very High. Mutation operates directly on the AST nodes.

### 7.2 PropertyGPT's mutation approach (NDSS 2025)

- **Mechanism:** Generates spec variants and tests them against *known bugs* (from real-world exploits). A good spec catches the bug; a weak spec misses it. Uses this to rank spec quality.
- **Relevance to Bloom Rung 3:** High. Bloom should maintain a corpus of known-buggy state transitions (e.g., k decreased across a swap). Mutation testing on the predicate AST against this corpus is an automated gate for spec quality.

### 7.3 Spec mutation as fuzz seed generator

- **Mechanism:** Instead of mutating the program inputs, mutate the *spec* and ask: "what input would violate this mutated spec?" If the mutated spec is *stronger* (e.g., `And(a, b)` → `And(a, b, c)`), the violating inputs are interesting edge cases for the original spec. This is a variant of "fuzzing the spec to fuzz the program."
- **Relevance to Bloom Rung 3:** Medium. Mutating `PredicateAst` to produce stronger versions, then SMT-solving for inputs that violate the stronger version, produces high-value seeds for the fuzzer.

---

## 8. Key insight: Theorem-Carrying Transactions (TCT) as a Rung 3 pattern

### 8.1 TCT (Ball, Bjørner, Chen et al., arXiv:2408.06478)

- **Mechanism:** Every transaction carries a *theorem* proving it adheres to the invoked contract's specifications. The runtime checks the theorem before execution. Once proved, theorems are reused (amortized cost). Applied to Uniswap with negligible runtime overhead.
- **Relevance to Bloom Rung 3:** **Very High — structural isomorphism.** TCT's runtime checking of a pre-proved theorem is exactly Bloom's "pre-commit revert on invariant failure" — but with the proof done *before* execution rather than checked *during*. Bloom's Rung 3 is the step where the "theorem" (invariant holds for all inputs the fuzzer can generate) is produced. TCT shows that:
  - Pre-commit checking is viable (Bloom's ADR-002 is correct).
  - The pre-commit check can be a *theorem* (not just a runtime check) — Bloom's Rung 2 (runtime) + Rung 3 (pre-deploy fuzz) together approximate this.
  - The theorem reuse pattern is striking: if Bloom proves an invariant holds for a petal, future deployments of the same petal version can reuse the proof without re-fuzzing.

---

## 9. Structured ranking by relevance to Bloom

| Rank | Approach | Relevance | Why |
|------|----------|-----------|-----|
| **1** | **SMT-based predicate-boundary generation** (§5.2) | Very High | Given `PredicateAst`, negate each leaf, solve with Z3 → seed corpus of boundary-violating inputs. Guarantees full predicate coverage. `BoundedArith` designed for this. |
| **2** | **CG-PBT fusion** (§2.1 — Lampropoulos/Hicks/Pierce 2019) | Very High | QuickCheck-style random generation + AFL-style coverage guidance. Bloom's predicate AST replaces the `==>` guard. "Crowbar" pattern directly applicable. |
| **3** | **Differential fuzzing AST vs. Wasm** (§4.1 — Differential Fuzzing paper) | Very High | Two evaluation paths (AST interpreter, compiled `__inv` Wasm) fuzzed against each other. Essential correctness gate. |
| **4** | **Harvey-style input prediction** (§1.4) | High | Extract branch conditions → generate boundary inputs. Bloom's AST already has this extracted. Simpler than SMT for most cases. |
| **5** | **Mutation-based spec testing** (§7) | High | Mutate `PredicateAst`, run against known-correct/known-buggy inputs. Automated spec quality metric. Direct AST integration. |
| **6** | **Kani harness → fuzz corpus bridge** (§3.1) | High | Complementary Rung-5 tool. Kani counterexamples (when SAT) seed the fuzz corpus. Shared harness authoring reduces redundancy. `BoundedArith` is Kani-native. *Not itself fuzzing — it's bounded model checking that feeds fuzzing.* |
| **7** | **TCT-style pre-commit checking** (§8.1) | Very High | Pre-prove invariants before execution. Rung 3 is the "prove by fuzzing" step. Establishes the amortized cost model. |
| **8** | **Belobog-style state-aware fuzzing** (§1.6) | Medium-High | Track object state across tx sequences. Bloom's borrow table is the state model. |
| **9** | **Verus-SpecGym adversarial spec testing** (§4.2) | High | Test generated/LLM-authored specs against adversarial edge cases. Bloom's intent-conformance gate. |
| **10** | **Echidna/Medusa corpus + mutation** (§1.1, §1.2) | Medium | Established corpus collection + mutation + coverage-guidance pattern. Baseline that Bloom should build on. |
| **11** | **ICE / fuzz-refine-prove loop** (§6.3) | Medium | Learner-fuzzer-prover loop for invariant refinement. Aspirational for Bloom's Rung 3→5 pipeline. |
| **12** | **ILF (NN-guided from symbex)** (§5.1) | Low-Medium | Too complex for Rung 3 v1. Direct SMT is simpler and more effective for predicate trees. |
| **13** | **Foundry dictionary fuzzing** (§1.3) | Medium | Baseline input generation strategy. Simple and effective as a fallback when AST/SMT guidance not available. |

---

## 10. Recommended Rung 3 architecture (synthesis)

Based on this survey, the recommended Rung 3 pipeline:

```
PETAL SUBMISSION
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ 1. EXTRACT: PredicateAst from manifest               │
│    - Decompose into leaf comparison nodes             │
│    - Each leaf = one "predicate coverage" target      │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ 2. SEED (SMT-guided): For each leaf, negate it,     │
│    encode as Z3 query. Collect satisfying models.    │
│    These are the "ideal boundary-violating inputs".  │
│    Also: Harvey-style boundary mutations on each     │
│    FieldGe/FieldLe/FieldEq node.                     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ 3. FUZZ (CG-PBT fusion):                             │
│    a. Random: proptest over scope-bytes + call args   │
│    b. Coverage-guided: AFL-style on Wasm blocks       │
│       reached during invariant evaluation             │
│    c. Mutation: corpus entries mutated, weighted by   │
│       "predicate closeness-to-failure" (how close     │
│       each leaf comparison was to flipping)           │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ 4. DIFFERENTIAL CHECK: Every input evaluated on      │
│    both AST interpreter and compiled __inv Wasm.     │
│    Mismatch = bug (compiler, interpreter, or both).  │
│    Violation found = counterexample reported.        │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ 5. MUTATE SPEC: If no violations found, mutate       │
│    PredicateAst (strengthen). Re-run steps 2-4.      │
│    If a strengthened mutant is not violated, the     │
│    original spec might be too weak → warning.        │
│    Also: test against known-buggy state transitions. │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ 6. VERDICT:                                          │
│    PASS (no violation found, spec passes mutation)   │
│    WARN (no violation but spec too weak)             │
│    FAIL (counterexample found → reject petal)        │
└─────────────────────────────────────────────────────┘
```

### Key design principles

1. **The predicate AST is the fuzzer's oracle and its guide.** It tells the fuzzer both *what to look for* (violations) and *where to look* (boundary values at each comparison node).

2. **SMT for seeds, not for proof.** Z3 generates the initial corpus. The fuzzer does the heavy lifting of satisfying those ideal inputs within the actual Wasm execution.

3. **Differential testing is non-negotiable.** The AST interpreter and the compiled Wasm must agree on every input. This gate replaces today's `return 1` stub.

4. **Mutation testing measures spec quality.** If the fuzzer can't violate a strengthened mutant, the spec is too weak — this is an automated partial fulfillment of ADR-003's intent-conformance gate.

5. **Corpus feeds Kani.** If Rung 3 passes, the corpus of inputs that *almost* violated the invariant becomes the seed for Rung 5's bounded model checking (Kani). Rung 3 finds bugs cheaply; Rung 5 proves absence exhaustively within bounds. They are complementary rungs, not alternatives.

---

## References

1. Echidna: A Fast Smart Contract Fuzzer. Trail of Bits. ISSTA 2020. [github.com/crytic/echidna](https://github.com/crytic/echidna)
2. Medusa: Parallelized, coverage-guided, mutational Solidity fuzzing. Trail of Bits. [github.com/crytic/medusa](https://github.com/crytic/medusa)
3. Harvey: A Greybox Fuzzer for Smart Contracts. Wüstholz, Christakis. arXiv:1905.06944 (2019)
4. Coverage Guided, Property Based Testing. Lampropoulos, Hicks, Pierce. OOPSLA 2019. DOI:10.1145/3360607
5. Uncovering Smart Contract VM Bugs Via Differential Fuzzing. Neo et al. DOI:10.1145/3503921.3503923 (2022)
6. Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization. Agarwal et al. arXiv:2605.26457 (2026)
7. PropertyGPT: LLM-driven Formal Verification of Smart Contracts. NDSS 2025. DOI:10.14722/ndss.2025.241357
8. Theorem-Carrying Transactions. Ball, Bjørner, Chen et al. arXiv:2408.06478 (2024)
9. Fast and Reliable Formal Verification of Smart Contracts with the Move Prover. Dill, Grieskamp, Park, Qadeer et al. TACAS 2022. DOI:10.1007/978-3-030-99524-9_10
10. Kani Rust Verifier. AWS. [model-checking.github.io/kani](https://model-checking.github.io/kani/)
11. Rich Specifications for Ethereum Smart Contract Verification (2Vyper). Bräm et al. arXiv:2104.10274 (2021)
12. VerX: Safety Verification of Smart Contracts. Permenev et al. IEEE S&P 2020.
13. ICE: A Robust Framework for Learning Invariants. Garg et al. CAV 2014.
14. ILF: Learning to Fuzz from Symbolic Execution. He et al. CCS 2019.
