# H6 (Proponent): zkVM underconstraint is structural; re-execution against a mechanized Wasm semantics oracle is the required backstop

**SUPPORT STRENGTH: strong** — Two independent full-text studies show that underconstraint is the dominant, recurring soundness bug class in *production*, *audited* zkVMs/SNARKs, that the emitted proofs verify cleanly on the forged traces (the prover cannot catch its own gap), and that the only oracle empirically shown to expose these bugs is an *external* one that knows the *intended semantics* (a metamorphic/reference oracle), not the prover's own trace. The one genuinely hard counter — that naive re-execution cannot detect a soundness bug — is real, but it is precisely answered by adjudicating against a mechanized semantics rather than against the prover's trace, and the corpus supplies the missing piece (a *verified* Wasm reference interpreter built explicitly as a differential oracle).

---

## 1. The claim, decomposed

H6 has three sub-claims. Each is supported by the corpus:

- **(A) Underconstraint is a structural soundness risk** — it recurs even in audited, deployed systems and is the single most common soundness root cause.
- **(B) No single prover mitigates it** — the prover/verifier that contains the underconstrained gap will itself accept the forged proof; self-checking is structurally impossible for this class.
- **(C) The fallback closes the gap only when it adjudicates against a mechanized/reference semantics oracle**, not against the prover's own trace — because an honest re-executor of *the same engine* agrees with the forged-but-accepted trace.

---

## 2. (A) Underconstraint is structural and empirically dominant — quality + scale

### SoK: What don't we know? Understanding Security Vulnerabilities in SNARKs (full text)
arXiv:2402.15293 — https://doi.org/10.48550/arxiv.2402.15293 (Chaliasos, Ernstberger, Theodore, Wong, Jahanara, Livshits; co-authored by Ethereum Foundation, zkSecurity, Scroll Foundation).

This is the strongest single piece of quantitative evidence, and its provenance is high (the same authorship community that the zkVM space defers to).

- **Sample and method.** 141 real vulnerabilities from 107 audit reports + 16 disclosures + bug trackers, spanning ~6 years (2018–2024), across the entire SNARK stack (circuit/frontend/backend/integration). The authors argue the corpus is "representative of the entire SNARK space."
- **Underconstraint is the dominant soundness class.** Of 141 total vulns, **124 break soundness** (Table 3). At the circuit layer (the most prevalent layer, 99 vulns), **95 of 99 are under-constrained** soundness bugs (Table 4: UC=95, OC=1). Root causes are mundane and recurring: *Missing Input Constraints* (25), *Wrong translation of logic into constraints* (32+2), *Assigned but Unconstrained* (14), *Unsafe Reuse* (9), field over/underflow (8). These are not exotic crypto failures — they are the ordinary failure mode of *encoding semantics as constraints*.
- **It is structural, not incidental.** The paper's thesis is explicitly that "ZK systems are **not 'just math'** — they are complex, compositional systems where cross-layer interactions can introduce complex vulnerabilities." The unique programming model "often lead[s] to under-constrained circuits ... from overlooking constraints or misinterpreting logic into circuits." V1 (Under-Constrained) is named "The most frequent vulnerability in ZK circuits."
- **zkVMs are squarely in scope.** The system model names RISC Zero, Jolt, and zk-EVMs as ZK-VMs whose arithmetic circuit "represents the loop of fetching instructions from memory and successively executing them." A missing constraint on an opcode is the zkVM instance of V1.

### Pinocchio: Nearly Practical Verifiable Computation (abstract)
DOI 10.1109/sp.2013.47 — https://doi.org/10.1109/sp.2013.47 (Parno, Howell, Gentry, Raykova, 2013).

Pinocchio establishes the *root* of the soundness property H6 is worried about: the entire value proposition is that "clients should be able to verify the correctness of the results returned" via "a proof of correctness" checked by a verification key, "relying only on cryptographic assumptions." Crucially, soundness here is soundness *with respect to the encoded computation (the QAP/circuit)* — the proof attests that the constraint system is satisfied, **not** that the constraint system faithfully encodes the intended program. That gap between "constraints satisfied" and "intended semantics computed" is exactly where underconstraint lives, and it is baked into the model from the foundational system onward. The cryptographic soundness proof says nothing about whether the circuit is the *right* circuit.

---

## 3. (B) No single prover detects its own underconstraint — and the proofs do not catch it

### Arguzz: Testing zkVMs for Soundness and Completeness Bugs (full text)
arXiv:2509.10819 — http://arxiv.org/abs/2509.10819 (Hochrainer, TU Wien; Wüstholz, Diligence/Consensys; Christakis, TU Wien; 2025).

This is the decisive empirical evidence that the *emitted proofs do not catch* the bug. Arguzz tested **six production RISC-V zkVMs** (RISC Zero, Nexus, Jolt, SP1, OpenVM, Pico — the list was vetted with the Ethereum Foundation as "mature ... state of the art") and found **11 bugs in three of them, including 3 soundness bugs**, all in main branches.

- **The proof verifies on the forged trace.** Arguzz's soundness detector simulates a malicious prover by fault injection, then checks "whether the unmodified verifier accepts the resulting proof." A soundness bug is reported precisely when "the product program return[s] an incorrect output ... but the proof still verifies successfully." Quote: *"The verifier accepting an invalid trace indicates that the constraints are underspecified."* The proof is valid in the cryptographic sense — it is the *constraints* that are too weak. This is direct evidence for (B): the prover/verifier pipeline cannot flag the gap, because from its own constraint system's point of view nothing is wrong.
- **These are real, severe, post-audit bugs.** Bug 1 (RISC Zero): a *missing constraint in three-register instructions* (`remu`, `divu`) let a malicious prover prove `7 % 5 = 0`. It earned a **$50,000 bounty**, "despite prior audits," and required patches across 11 files in Zirgen (the constraint system) and 32 files in the zkVM; all clients were migrated. Bug 3 (Nexus): *unconstrained store operand* in load/store, enabling `2^3 ⊕ 2^3 = 1`. Bug 6 (Jolt): *unconstrained immediate operand in `lui`*, letting the prover control the instruction's output.
- **The pattern generalizes.** "all three soundness bugs ... were detected using the instruction-modification injection type" and each is a *missing/weak constraint on an opcode's operands*. Table 3 confirms that across all six zkVMs, the `OOPS, EC==0` cell (altered output yet verifier succeeds = soundness bug) is the explicit detection signal. That this class survived audits in three of six mature systems is strong evidence it is *structural*, not a one-off: no single prover, however audited, reliably eliminates its own underconstraint.

### Towards Fuzzing Zero-Knowledge Proof Circuits (abstract) & Formal Verification of Zero-Knowledge Circuits (abstract)
DOI 10.1145/3713081.3731718 (Chaliasos, Al-Fath, Donaldson, 2025); DOI 10.4204/eptcs.393.9 (Coglio, McCarthy, Smith, 2023).

These corroborate that the community treats underconstraint as a first-class, unsolved target requiring *external* methods — fuzzing circuits and formally verifying circuits against an independent specification — rather than trusting the prover to self-certify. Their very existence is evidence that "the prover proves itself correct" is not accepted as sufficient. (Abstracts only; both are listed in the corpus with the metadata above. Treated as supporting, not load-bearing.)

---

## 4. (C) Why the fallback must adjudicate against a mechanized semantics — and the strongest counter

### The strongest honest counter
A skeptic correctly observes: **naive re-execution cannot catch a soundness bug.** If the underconstrained zkVM accepted a forged trace for "program P on input x → output y'", and you re-execute by running *the same zkVM/engine* and trusting *its* trace, an honest re-executor reproduces... the same engine behavior. Worse, in the Arguzz threat model the forgery is constructed so the trace is *internally consistent with the faulty state*: the paper notes the trace "remains valid up to the point of injection ... the remainder of the trace becomes consistent again — this time with respect to the faulty state." A re-executor that asks only "is this trace self-consistent?" will agree with the forgery. So re-execution-against-the-prover's-own-trace is **circular** and provides no new information. This counter is valid and must be conceded.

### Why adjudicating against a mechanized/reference semantics defeats it
The resolution is that the backstop must not ask "is the trace consistent?" but "**does output y' match what the *intended semantics* of P on x produces?**" — judged by an *independent* oracle that encodes the semantics, not the prover's encoding of them. Every soundness bug Arguzz found is exactly a *divergence between the constraint system's behavior and the intended instruction semantics* (`7 % 5` should be `2`, not `0`). An oracle that knows the *reference semantics of the instruction set* flags this immediately; an oracle that only re-checks the trace cannot.

This is precisely how the *successful* oracles in the corpus work:

- **Arguzz's working oracle is semantic, not trace-based.** Its detection relies on a *metamorphic oracle* — two semantically equivalent programs whose outputs *must* match by the laws of the instruction semantics (commutativity, associativity, etc.) — encoded as a product program with a *known expected output*. The bug is caught because the forged execution violates a *semantic invariant the prover knew nothing about*. The paper is explicit that bit-flipping a valid trace (a trace-level perturbation) is *inadequate*: "bit flips are not guaranteed to produce invalid traces ... flipping the operand from 42 to 43 would still yield the same valid result of zero." They reject the trace-level approach in favor of one driven by "the program's expected output" — i.e., by semantics. This is direct internal evidence for H6's core claim: the oracle that works is the *semantics* oracle, not the *trace* oracle.

- **SoK independently reaches the same conclusion about defenses.** It states plainly that generic fuzzing "often falls short of finding soundness issues" due to "the oracle problem," and that the credible defenses are those grounded in an independent reference of intended behavior: "**differential testing against a reference implementation** could be a viable method," and formal verification of circuits "even if the circuits have been formally verified or if the proof system is theoretically secure; any defects in [frontend/backend] could render the entire system insecure." The throughline: trust must be anchored in an *independent semantics*, not in the prover pipeline that may itself be the buggy artifact.

### The corpus supplies the concrete semantics oracle H6 requires
H6 specifies a *mechanized/reference Wasm semantics oracle*. The corpus contains exactly the artifact this calls for:

- **WasmRef-Isabelle: A Verified Monadic Interpreter and Industrial Fuzzing Oracle for WebAssembly** (DOI 10.1145/3591224) — a Wasm reference interpreter *proved correct against the mechanized Wasm specification* and *deployed as a differential fuzzing oracle*. (Metadata only — full-text fetch failed in the corpus — but the title and venue establish existence and purpose.) This is the canonical instance of "adjudicate output against a mechanized semantics": the oracle is independent of any prover, its agreement with the spec is *proven*, and it is built to be run differentially against an engine under test.
- **Mechanising and verifying the WebAssembly specification** (DOI 10.1145/3167082) and **Wasm SpecTec: Engineering a Formal Language Standard** (arXiv:2311.07223, full text) establish that Wasm *has* a complete, mechanized, executable formal semantics suitable to serve as the reference. SpecTec exists precisely to make the standard a single mechanized source of truth from which interpreters/oracles are generated — i.e., the semantics oracle is not hypothetical, it is engineered infrastructure.

Putting these together: the re-execution fallback closes the soundness gap **iff** its verdict is "did the engine compute what the mechanized Wasm semantics says it should?" — a question a WasmRef-Isabelle-style verified interpreter answers and a self-consistent-trace re-executor cannot.

---

## 5. Mechanistic argument (why this is structural, not contingent)

1. A zkVM proof attests **C(x,w)=y for the constraint system C**, never "C faithfully encodes the ISA semantics S" (Pinocchio model; SoK system model).
2. Underconstraint is a defect in the map *S → C* (missing/weak constraints). It is *invisible inside C*: every honest and dishonest party reasoning in terms of C agrees the proof is valid (Arguzz: "the proof still verifies successfully ... constraints are underspecified"). Therefore **the prover cannot detect its own underconstraint** — there is no vantage point inside C from which the gap is observable.
3. Audits reduce but do not eliminate this map error: SoK's 95/99 circuit-layer underconstraint bugs and Arguzz's 3 soundness bugs in audited, deployed zkVMs are the empirical proof that a single prover is not a safe root of trust.
4. A *second engine* re-executing and trusting *its own* trace inherits the same C-relative blindness (the counter in §4). Only an oracle that evaluates against **S directly** — an independent, ideally *verified*, reference semantics — sits outside C and can witness the *S → C* divergence.
5. Wasm uniquely makes (4) practical: it has a mechanized, executable, standard semantics (SpecTec, the mechanized spec) and an existing *verified* reference interpreter built as a differential oracle (WasmRef-Isabelle). Hence the specific architecture H6/ADR-007 prescribes — fraud-proof/re-execution adjudicated against a mechanized Wasm semantics — is the minimal construction that actually closes the gap.

---

## 6. Honest limitations of this case (still net-strong)

- **No paper measures a *deployed* fraud-proof-vs-semantics system end-to-end.** The evidence is compositional: (a) underconstraint is real and prover-invisible (Arguzz, SoK, full text); (b) the working oracles are semantic/reference, not trace-based (Arguzz internal design, SoK defenses); (c) a verified Wasm semantics oracle exists (WasmRef-Isabelle, SpecTec). The synthesis is sound but is *argued*, not demonstrated in one experiment.
- **Two key supporting items are metadata-only** (WasmRef-Isabelle, the mechanized-spec paper, and the two ZK-circuit FV/fuzzing abstracts all failed full-text fetch or have empty abstracts). Their titles/venues are load-bearing but their internals are not independently verified here. Tagged accordingly.
- **A residual risk H6 does not escape:** the semantics oracle itself can be wrong. The case is only as strong as the *mechanization* of Wasm — which is why "verified" (WasmRef-Isabelle is proved against the spec) matters and why an *unverified* reference interpreter would weaken the argument to "moderate." H6 as stated (mechanized/reference oracle) is the version the evidence supports; a hand-written re-executor would not be.

**Bottom line:** The corpus strongly supports that underconstraint is a structural, prover-invisible soundness risk surviving audits in production zkVMs (SoK: 95/99 circuit bugs UC; Arguzz: 3 soundness bugs, $50k bounty, post-audit), and that the only oracles empirically shown to expose it are *semantic/reference* oracles — corroborated by SoK's explicit endorsement of "differential testing against a reference implementation" and by the existence of a *verified* Wasm reference interpreter built as a differential oracle (WasmRef-Isabelle). Naive trace-level re-execution is correctly conceded to be circular; adjudicating against a mechanized Wasm semantics is what converts the fallback from circular to sound.
