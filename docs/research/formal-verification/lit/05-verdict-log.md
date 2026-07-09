# 05 — Verdict Log (literature)

*PI single-writer. Verdicts on the 6 hypotheses (= the 7 ADRs) after adversarial testing
against the corpus. Each `V-00n` is `PROPOSED` until the synthesis survives red-team (Phase 4),
then `RATIFIED`. Verdict vocabulary: **Supported / Refuted / Inconclusive**, with an
`(amended)` qualifier where the *causal core* holds but the ADR's *wording* overclaims.
These are verdicts about **what the literature says**, distinct from the team's ratification of
the ADRs themselves in [`../04-decision-log.md`](../04-decision-log.md).*

Evidence: `04-evidence/H{n}-proponent.md` + `H{n}-falsifier.md`. Full-text coverage: 13/32 key
papers (see `data/fulltext/manifest.json`).

**Ratification note (post-red-team, 2026-05-29):** all six verdicts moved `PROPOSED → RATIFIED`
after the [`06-red-team.md`](06-red-team.md) pass, **with the amendments the red team forced** —
applied below and carried into [`RESEARCH.md`](RESEARCH.md). The material corrections: (1) Arguzz
is *metamorphic testing + fault injection on product programs with a constructed known output*,
**not** "re-execution against an external honest reference VM" (RT-002); (2) H6 generality is
downgraded to **moderate** — Arguzz is a single uncited 2025 preprint on **RISC-V** zkVMs, and the
corpus contains **no Wasm-zkVM paper** (RT-001, RT-005); (3) *(at inquiry time, WasmCert, Iris-Wasm and
CT-wasm were abstract-only with a failed full-text fetch, tagged `(abstract — fetch failed)`; RT-004,
RT-007, RT-011)* — **update 2026-05-29: all six previously-missing artifacts have since been fetched
in full and persisted (WasmRef-Isabelle, NPChecker, NeoDiff, then CT-wasm, WasmCert-Isabelle,
Iris-Wasm); see `data/fulltext/manifest.json`. CT-wasm in full text proved to be about constant-time
crypto, not floats — its float-subset citation is now reframed as analogical**; (4) the cross-cutting
"verified-semantics-is-the-spine" claim is demoted to an explicit **conjecture**, co-equal with an
**intent-conformance** reading that is in fact *better*-cited (RT-009); (5) every conclusion is
reached for Bloom's Rust→Wasm target **by cross-domain analogy** from EVM/Move/RISC-V evidence
(RT-010). What the red team affirmed as solid (do not soften): V-001 substrate + its two
refutations, V-002 core + the TCT refutation, V-005 gap + provenance-gating, and the SoK-SNARKs
under-constraint numbers.

---

## V-001 — H1 (ADR-001, readable predicate AST) · Supported (amended) · RATIFIED · 2026-05-29
**Proponent:** moderate. **Falsifier:** partial.
**Verdict:** The *pragmatic core* — a restricted, total, declarative predicate is the right
**auditable substrate**, and every real-world verifier in the corpus that targets audit/review
adopts one (The Move Prover *(full text)*; VerX *(full text)*; Rich Specifications / 2Vyper
*(full text)*) — is **Supported**. But two strong-form claims in ADR-001 are **Refuted**:
1. *"Opaque/closure predicates cannot be machine-checked"* is false — Prusti encodes closures
   into FOL and discharges them via SMT ("Modular specification and verification of closures in
   Rust" *(abstract)*); Verus does likewise *(abstract)*. The ADR conflates *opaque-to-a-reader*
   with *opaque-to-the-verifier*.
2. *"Readability solves arbitration"* is **insufficient**: even total, transparent, executable
   spec predicates routinely fail to capture intent — Verus-SpecGym *(full text)*: best model
   writes faithful specs 77.8% of the time and an LLM judge *reading* the spec misses 26% of
   faithfulness failures; "Evaluating LLM-driven User-Intent Formalization" *(full text)* and
   PropertyGPT *(full text, 80% recall)* concur.
**Confidence:** high on the substrate; high on the two refutations.
**Implication for ADR-001/003:** keep the AST; drop "cannot be arbitrated"; readability is
**necessary but not sufficient** — ADR-003 must add an explicit intent-conformance check
(adversarial counterexample review / spec test-vectors), not rely on auto-rendered English.

## V-002 — H2 (ADR-002, runtime view-fn: detection ≠ prevention) · Supported (amended) · RATIFIED · 2026-05-29
**Proponent:** strong. **Falsifier:** partial.
**Verdict:** The **causal core is Supported**: a check that observes a single reached state
cannot catch a logic bomb on an un-triggered path; coverage-guided fuzzing is bounded sampling
on sparse preconditions ("Coverage guided, property based testing" *(abstract)*); prevention
needs quantification over unexecuted states (VerX, Move Prover *(full text)*). But the literal
**"runtime = detection" taxonomy is Refuted** by Theorem-Carrying Transactions *(full text)*: a
transaction-scoped check evaluated **before commit** genuinely *prevents* the bad state — and
TCT prevents exactly the overflow/reentrancy classes. The subtlety vindicates the ADR's
*intuition*: TCT's assurance comes from a **pre-deploy symbolic proof** enforced at commit time
(neither pole of the dichotomy).
**Confidence:** high.
**Implication for ADR-002:** Bloom's *stateless, post-commit, non-reverting* view-function
invariant is confirmed to be the **strictly weaker primitive** — it detects, it does not
prevent. The high-value design move is to (a) evaluate invariants **pre-commit and revert on
failure** (turning detection into prevention for the spec'd class), and (b) state explicitly
that a stateless view fn covers only the **safety fragment** — liveness/multi-block temporal
properties are out of scope or need a stateful monitor (RV survey *(abstract)*).

## V-003 — H3 (ADR-004, exclude floats is *necessary*) · Refuted (necessity); Supported (engineering) · RATIFIED · 2026-05-29
**Proponent:** moderate. **Falsifier:** partial.
**Verdict:** The **necessity claim is Refuted**. (1) Restricting Wasm to a deterministic, well-behaved
subset via the type system is demonstrably practical — CT-wasm *(full text)* builds a secret-typed,
constant-time fragment (analogical support; CT-wasm targets information-flow/timing security, **not
floats**), while reproducible-FP aggregation and FP-consistent cross-verification *(abstract)* speak
to deterministic float execution directly — so exclusion is *sufficient, not necessary*.
(2) **Misattribution:** the canonical chain-nondeterminism bugs ("Detecting nondeterministic
payment bugs in Ethereum smart contracts" / NPChecker *(full text)*) are caused by read-write
hazards from unpredictable transaction scheduling and external callee behavior — **not floats**
(floats appear nowhere in its taxonomy); the float-less EVM has the bug class anyway. (3) Wasm already mandates deterministic IEEE-754 basic ops; the real divergence surface is
a *few* opcodes (NaN payloads, FMA, float→int) that are selectively canonicalizable. The
**engineering claim is Supported**: integer-only is the *simplest sufficient* means and
materially eases provability (Move Prover *(full text)*).
**Confidence:** moderate→firming (RT-007). The nondeterministic-payment-bugs paper (NPChecker) is
now *(full text)* and concretely confirms the misattribution — its taxonomy is transaction
scheduling / read-write hazards / external callees, with no floats. CT-wasm is now *(full text)* too,
read accurately: it evidences *typed restricted Wasm subsets* (constant-time crypto), which support
the float-subset claim only **by analogy** — the FP-consistent cross-verification paper (a 2026 1-cite
preprint) remains the only float-direct citation. The robust part is the *engineering* case (exclusion
is the simplest sufficient means); the *necessity refutation* is backed by NPChecker's taxonomy for
the Ethereum case, and still rests on analogy/thin evidence for the general
deterministic-float-subset claim.
**Implication for ADR-004:** reword from *"necessary"* to *"the simplest sufficient means; a
canonicalized deterministic float subset is feasible at materially higher verification cost."*
Decision can stand on cost/risk grounds — just not on necessity.

## V-004 — H4 (ADR-005, conformance profile *sufficient*) · Supported (amended) · RATIFIED · 2026-05-29
**Proponent:** moderate. **Falsifier:** partial.
**Verdict:** A profile is a **well-defined object** and Wasm's nondeterminism is small and
enumerable (Wasm SpecTec *(full text)*: single source of truth co-generating spec + interpreter
+ 23,778-vector suite, SIMD excluded; WasmCert-Isabelle *(full text)* — a mechanised Isabelle Wasm
semantics with a **verified executable interpreter & type checker** plus a soundness proof, which
itself did **differential fuzzing against industry implementations** and surfaced real spec bugs;
Iris-Wasm *(full text)* — higher-order separation logic over WasmCert-Coq with a robust-safety
logical relation). But the **"test-vectors alone are sufficient" form is Refuted**: a
finite suite is a sample of an infinite input space, and the industry's own move — deploying
WasmRef-Isabelle *(full text)* as a **verified fuzzing oracle** in Wasmtime CI — is
rational only because conformant engines diverge until caught. Sufficiency is carried by the
**verified executable semantics**, which ADR-005 currently demotes to "long-term."
**Confidence:** moderate→firm (RT-004) — both previously-missing papers are now read. (a) "Uncovering
Smart Contract VM Bugs Via Differential Fuzzing" (NeoDiff) *(full text)* supplies the empirical
divergence evidence: feedback-guided differential fuzzing across independent VMs found
cross-implementation divergences (the Neo C# consensus VM vs. neo-python) and memory corruptions in
the C# VM. (b) The keystone verified-oracle datum, WasmRef-Isabelle, is now *(full text — via
co-author Trela's Cambridge dissertation + the published abstract)*, engaging the refinement-proof
construction and the Wasmtime-CI oracle deployment. **Residual:** NeoDiff is EVM/Neo, not a Wasm
engine pair, so the Wasm-specific cross-engine fork transfers by analogy — the amendment is now
corpus-grounded, with that one analogical step remaining.
**Implication for ADR-005:** restate as *"profile + suite is necessary but not sufficient;
cross-node determinism binds on a pinned verified executable semantics (WasmCert/WasmRef) used
as a differential oracle, with the test suite as a fast pre-filter."* Promote the verified
oracle from "long-term" to load-bearing.

## V-005 — H5 (ADR-006/007, source→Wasm proof transfer + ranked mechanisms) · Supported · RATIFIED · 2026-05-29
**Proponent:** strong. **Falsifier:** none (every attack collapsed into evidence *for* H5).
**Verdict:** **Supported, high confidence.** (a) Unverified compilation can silently invalidate
a source proof (CompCert framing; TurboTV *(abstract)* found a real LLVM miscompilation), so a
proof is sound only relative to the deployed artifact → provenance-gating is justified. (b) The
three transfer mechanisms differ systematically in TCB/trust surface — PCC/certifying compiler
(compiler untrusted, TCB = small checker; DeepSEA *(full text)*: "the dsc tool … is not in the
trusted computing base"), translation validation (TCB = validator + solver, per-run, possibly
incomplete), whole-compiler proof (TCB = the whole proof + semantics; RustCompCert *(full
text)*). Attempts to moot the gap *reinforced* it: VeriWasm *(abstract)* and Crocus *(abstract,
9.9-severity Wasm→native CVE)* exist precisely to verify the **deployed binary** — H5's own
mechanism.
**Confidence:** high on the gap and provenance-gating; **moderate** on a strict *total* ordering
— the corpus supports ranking *by TCB* and "complementary, not flat," not a universal order.
Scope caveat: corpus evidence is C/native + Rust→native + source→EVM; **no verified *Rust*→Wasm
pipeline exists** (DeepSEA's eWasm path is explicitly unproven) — though a verified ***F****→Wasm
path does ("Formally Verified Cryptographic Web Applications in WebAssembly", 2019, *abstract*,
25 cites), showing the *direction* is achievable for a different source language (RT-006). The
transfer to Bloom's exact pipeline is by mechanism analogy. Two further hedges the red team
forced: the PCC > TV > whole-compiler **ranking is analytic** (reasoned from each mechanism's
trusted surface), not an empirical comparison — no corpus paper benchmarks the three on a shared
artifact (RT-008); and "Proof-carrying code" is **title-only** (no abstract) in the corpus, so it
is cited as a named concept, with the 1998 certifying-compiler paper (357 cites) and DeepSEA
*(full text)* carrying the actual evidence.
**Implication for ADR-006:** keep optional/provenance-gated proofs; replace "verified
compilation OR TV OR PCC" (flat) with a **ranked-by-TCB** scoring ladder; note that **no
verified Rust→Wasm compiler yet exists** (F*→Wasm aside), so reproducible builds + differential
testing are the realistic near-term gate.

## V-006 — H6 (ADR-007, zkVM underconstraint needs an independent soundness check) · Supported (core); moderate (generality) · RATIFIED · 2026-05-29
**Proponent:** strong. **Falsifier:** none. **Red team:** RT-001/RT-002/RT-003/RT-005 forced the
corrections below.
**Verdict — core (Supported, high):** zkVM underconstraint is real, **post-audit**, and **invisible
to the emitted proof**. Arguzz *(full text)* tested six production RISC-V zkVMs and found 11 bugs
(3 soundness), each an underspecified constraint where "the proof still verifies successfully."
SoK-SNARKs *(full text)* quantifies the class: 124/141 vulns break soundness; 95/99 circuit-layer
bugs are under-constrained. The "no single prover as root of trust; you need a check **independent
of the prover's own constraint system**" conclusion holds.
**Correction (RT-002):** Arguzz's method is **metamorphic testing + fault injection on product
programs with a *constructed* known output**, run inside the *unmodified* zkVM — **not**
"re-execution against an external honest reference VM," and not a verified semantics. The three
soundness bugs were revealed by *fault injection*; the "circuit-equivalence caught zero" figure is
Arguzz's **internal ablation** of its own components, not a refutation of independent
circuit-verification work. So the clean "re-execute against a verified Wasm semantics" framing is
**Bloom's design extrapolation, not what Arguzz demonstrates.**
**Generality (moderate, RT-001/RT-005):** every datum is **RISC-V** zkVMs; the corpus contains
**no paper that runs Wasm through a zkVM**. Arguzz is a single **uncited 2025 preprint**. The
transfer to a Wasm/Bloom setting is analogy. Also: the "verified oracle is a *precondition*" line
is softened — Arguzz's *unverified*-Rust oracle already found 11 bugs (RT-003); a verified oracle
*raises* assurance (removes its toolchain from the TCB), it is not shown to be required.
**Implication for ADR-007:** keep "no single zkVM as root of trust" + the challenge window, and the
recommendation that the fallback adjudicate against an **independent, ideally verified, reference
semantics** rather than the prover's own trace — but flag this as a *reasoned recommendation*
extrapolated from RISC-V evidence, pending any Wasm-zkVM study.

---

## Tally (PROPOSED)

| H | ADR | Verdict | Confidence |
|---|-----|---------|------------|
| H1 | 001 (+003) | Supported (amended) — substrate yes, "cannot arbitrate" no, readability insufficient | high |
| H2 | 002 | Supported (amended) — core yes; pure post-commit view fn is the weaker primitive | high |
| H3 | 004 | Refuted (necessity); Supported (engineering choice) | high |
| H4 | 005 | Supported (amended) — profile needs a *verified-semantics oracle* to be sufficient | moderate |
| H5 | 006/007 | Supported — gap real, provenance-gating + TCB-ranking justified | high (mod. on strict order) |
| H6 | 007 | Supported (core: independent soundness check needed); moderate (generality — RISC-V, 1 uncited preprint, no Wasm-zkVM paper) | high / moderate |

**Cross-cutting — two readings, deliberately co-equal (RT-001/RT-009):**

*Reading A (conjecture, weaker-evidenced):* V-004 and V-006 *could* converge on one missing
artifact — a **pinned, verified, executable Wasm semantics** serving as both the
differential-conformance oracle (determinism, ADR-005) and the adjudicating reference for zkVM
fraud proofs (ADR-007). This is **a conjecture, not a finding**: it bridges Wasm-determinism
evidence (WasmRef-Isabelle, *full text*) and RISC-V-zkVM evidence (Arguzz) across
**different machine models**, and the corpus contains **no Wasm-zkVM paper** to test it. It is the
inquiry's best *open question*, not a result.

*Reading B (better-evidenced):* on raw evidence weight the single most load-bearing gap is
**spec↔intent conformance** — what the predicate is *supposed* to say. This rests on the
best-cited full-text papers in the whole corpus (PropertyGPT, 42 cites; Verus-SpecGym; Evaluating
LLM-driven User-Intent Formalization) and is closed by **no** executable semantics, verified or
not. The H1 and H2 refutations both relocate the real gap to the **human-intent / pre-commit
boundary** — before the verifier and before execution — which is *not* where the ADRs placed it.
Reading B is the firmer conclusion; Reading A is the more generative conjecture.
