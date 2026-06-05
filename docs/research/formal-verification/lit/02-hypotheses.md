# 02 — Hypotheses under test

*PI single-writer. 2026-05-29. Culled from 14 candidates (4 stances) to 6, one per ADR, for
1:1 design coverage — the explicit goal is to validate each PROPOSED decision against the
literature. Each kept the sharpest tension its generating stances surfaced.*

State legend: `untested` → `tested` (verdict in `05-verdict-log.md`).

---

## H1 — Readable predicate AST (ADR-001 / Q1) · `untested`

**Claim:** An invariant that must be *run, fuzzed, proved, and adjudicated by humans* has to be
a restricted, total, **semantically transparent** predicate (a declarative AST / spec
language); an opaque closure-compiled-to-Wasm breaks arbitration because its meaning is only
recoverable by execution, dissolving the shared referent both parties reason over.

**Sharpest tensions (must be answered):**
- *Expressiveness counter* (contrarian-2): Prusti/Flux/Verus modularly verify rich
  closures/predicates — is a restricted AST too weak for real DeFi invariants?
- *Binding counter* (frontier-1): even a green-proving readable spec can encode the *wrong*
  property; readability is **necessary but insufficient** without an intent-conformance check.

**supports_if:** Industrial provers that admit arbitration/audit use restricted declarative
specs; rich-closure verification needs whole-program reasoning that defeats neutral adjudication.
**refutes_if:** A corpus tool soundly *and* auditably verifies opaque/first-class-closure
predicates with the transparency arbitration needs — making the AST restriction unnecessary.

**Key papers:** The Move Prover (2020); VerX (2020); Rich Specifications for Ethereum Smart
Contract Verification; Modular specification and verification of closures in Rust (2021); Flux:
Liquid Types for Rust; The Open Veracity Language (2026); Evaluating LLM-driven User-Intent
Formalization for Verification-Aware Languages; Verus-SpecGym; PropertyGPT (2025).

---

## H2 — Runtime view-function invariant: detection ≠ prevention (ADR-002 / Q2) · `untested`

**Claim:** Modeling an invariant as a pure view function returning bool, checked at runtime, is
a *state-observation* mechanism: it can only fire on reached states, so it is structurally
blind to a logic bomb gated on an un-triggered input. Prevention requires quantifying over
unexecuted states before deployment (static proof / exhaustive symbolic reasoning); fuzzing is
sampling with miss-probability bounded by the guarded branch's measure.

**Sharpest tensions:**
- *False-dichotomy counter* (contrarian-1): a transaction-scoped check evaluated **before
  commit** is genuinely preventive (Theorem-Carrying Transactions) — so either Bloom already
  prevents (contradicting its own rationale) or picked a strictly weaker primitive.
- *Fragment counter* (crossdisc-2): a stateless view fn is a sound monitor only for the
  **safety** fragment; liveness / multi-block temporal properties are undetectable by it and
  must be excluded from the guarantee or handled by a stateful monitor.

**supports_if:** RV literature consistently frames runtime checks as post-hoc detection paired
with (not replacing) static methods; fuzzer SoKs show narrow guards evade sampling.
**refutes_if:** Pre-commit transaction-scoped runtime checks are shown to *prevent* the bug
class Bloom worries about, making the static/proof rungs redundant for it.

**Key papers:** Runtime Verification of Ethereum Smart Contracts (2018); A survey of challenges
for runtime verification … (2019); Runtime Assertion Checking and Static Verification:
Collaborative Partners (2018); Theorem-Carrying Transactions; Are We There Yet? … Smart
Contract Fuzzers (2024); Almost correct invariants: synthesizing inductive invariants by
fuzzing proofs.

---

## H3 — Exclude floating point from chain mode (ADR-004 / Q4) · `untested`

**Claim:** Excluding floats is *necessary* for both cross-node determinism and
SMT-provability of chain-mode code.

**Sharpest tension (contrarian-3):** the ban may solve a **non-problem** — typed/fixed-point
Wasm subsets (CT-wasm) and FP-certification work deliver deterministic, verifiable arithmetic
without banning a type, and the canonical Ethereum nondeterminism bugs involved **no floats at
all**. So float exclusion may be *sufficient but not necessary*, and the real determinism risk
lies in non-float nondeterminism and conformance gaps (→ H4).

**supports_if:** Evidence that float opcodes are a live consensus-divergence / unprovability
hazard with no practical deterministic discipline.
**refutes_if:** Deterministic, provable float execution is demonstrably achievable (typed
subset / canonicalization / certified FP), reducing "necessary" to "convenient."

**Key papers:** Detecting nondeterministic payment bugs in Ethereum smart contracts (2019);
CT-wasm (2019); When Does a Bit Matter? … Floating-Point Programs; Floating-point–consistent
cross-verification methodology (2026).

---

## H4 — Conformance profile, not a binary, for deterministic Wasm (ADR-005 / Q5) · `untested`

**Claim:** Pinning a versioned *conformance profile + test-vector suite* (not an exact engine
binary) is **sufficient** to guarantee cross-node deterministic execution.

**Sharpest tension (contrarian-4 / mechanistic-3b):** test-vector conformance is a *sampled
approximation* of engine semantics, not a proof; differential fuzzing finds VMs that pass
conformance yet **diverge on adversarial inputs** — a latent consensus fork. Soundness may
require a pinned **verified executable semantics** as the oracle (which the corpus shows now
exists), not merely a test suite.

**supports_if:** Conformance-suite + canonical fuel discipline empirically prevents divergence;
verified semantics back the profile.
**refutes_if:** Conformant-but-divergent engines are demonstrated on untested inputs, showing
the profile under-determines consensus-critical semantics.

**Key papers:** Mechanising and verifying the WebAssembly specification (WasmCert, 2018);
WasmRef-Isabelle (2023); Wasm SpecTec (2024); Iris-Wasm (2023); Uncovering Smart Contract VM
Bugs Via Differential Fuzzing.

---

## H5 — Source→Wasm proof transfer (ADR-006 / Q6+Q7) · `untested`

**Claim:** A proof about source code does **not** transfer to the deployed Wasm artifact
without verified compilation / translation validation / proof-carrying code; therefore proofs
must be provenance-gated against the deployed `petal_hash`.

**Sharpest tension (crossdisc-1 / frontier-2):** the three transfer mechanisms are **not
interchangeable** — they discharge different trust obligations and TCB sizes (PCC/certificate
checking > translation validation > "trusted verified compiler"). Provenance-gating should
**rank** them, not flatten them into one clause; and per-lowering-rule translation validation
may make a "verified-compilation profile" the practical gate rather than all-or-nothing.

**supports_if:** Foundational PCC / verified-compiler / translation-validation literature
confirms source proofs are unsound on unverified-compiled artifacts; mechanisms differ in TCB.
**refutes_if:** Source-level verification is shown to soundly cover deployed bytecode without
any compilation-correctness argument.

**Key papers:** Proof-carrying code (Necula, 1997); The design and implementation of a
certifying compiler (1998); Formal verification of an optimizing compiler (CompCert lineage);
RustCompCert; Foundational Verification of Smart Contracts through Verified Compilation;
Translation Validation for JIT Compiler in the V8 JavaScript Engine (2024); KEVM (2017).

---

## H6 — zkVM underconstraint & the re-execution fallback (ADR-007 / Q8) · `untested`

**Claim:** zkVM underconstraint is a structural soundness risk no single prover mitigates; a
re-execution / fraud-proof fallback is required (no single zkVM as root of trust).

**Sharpest tension (contrarian-5 vs frontier-3 / crossdisc-3) — the central disagreement:**
contrarian-5 argues re-execution is a **category error**: an honest re-executor can agree with
a forged-but-accepted trace, so replay can't catch a *soundness* bug; the real fix is
circuit-level verification / differential proving. frontier-3 + crossdisc-3 argue re-execution
**is** the empirically-mandated backstop (Arguzz finds production-zkVM soundness bugs) **but
only** when it adjudicates against a mechanized Wasm semantics oracle — tying H6 back to H4/H5.

**supports_if:** Underconstraint is empirically common and uncaught by emitted proofs, and an
independent re-execution-against-semantics check detects it.
**refutes_if:** Re-execution provably cannot distinguish a soundness-violating accepted trace
from a correct one (making the fallback ineffective and forcing circuit-level verification).

**Key papers:** Pinocchio: Nearly Practical Verifiable Computation (2013); Arguzz: Testing zkVMs
for Soundness and Completeness Bugs; SoK: What don't we know? Understanding Security
Vulnerabilities in SNARKs; Formal Verification of Zero-Knowledge Circuits (2023); Towards
Fuzzing Zero-Knowledge Proof Circuits.

---

### Note on ADR-003 (two-stage arbitration)

Not a standalone hypothesis — its core soundness question (can the human-text↔predicate link be
trusted?) is folded into **H1** via the intent-formalization tension (frontier-1). The verdict
on H1 directly informs ADR-003.
