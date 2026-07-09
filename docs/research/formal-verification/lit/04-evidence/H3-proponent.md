# H3 — Proponent Case

**HYPOTHESIS (H3):** Excluding floating point from chain-mode execution is NECESSARY for both cross-node determinism and SMT-provability. (Bloom ADR-004.)

**SUPPORT STRENGTH: moderate — The corpus strongly and convergently supports the weaker claim (floats are a live nondeterminism + unprovability hazard, and every serious smart-contract verifier in the corpus models computation over integers/reals, never IEEE floats). It supports the strong word "necessary" only by inference, not directly: no corpus paper proves that *exclusion* is the unique sound option, and the very papers on float verification show floats *can* be reasoned about, just at high cost. This is the thinnest evidence cluster in the corpus — most float-specific entries are abstract-only or out-of-scope textbook chapters.**

---

## What "necessary" would require, and what the corpus actually delivers

To honestly defend H3 we must separate three claims of decreasing strength:

1. **(Harm)** Floating point is a genuine source of cross-node consensus divergence and of SMT-unprovability.
2. **(Sufficiency of exclusion)** Removing float opcodes eliminates that specific hazard.
3. **(Necessity of exclusion)** Exclusion is the *only* sound way to get determinism + provability.

The corpus gives **strong** evidence for (1), **strong** evidence for (2) as a logical corollary, and **only inferential / "best-engineering-practice"** evidence for (3). The honest top line is therefore "moderate," and the burden of the word *necessary* is the gap a falsifier will attack. Below I build (1) and (2) as forcefully as the evidence allows, then state plainly where (3) rests on inference.

---

## Cluster A — Nondeterminism is a *root-cause* class of consensus/payment bugs, not a corner case

**Detecting nondeterministic payment bugs in Ethereum smart contracts** (Proc. ACM Programming Languages, 2019; DOI 10.1145/3360615; 83 citations) *(abstract only — full-text fetch returned HTTP 403).* This is the strongest single anchor for H3's determinism limb. Its thesis is precisely that nondeterminism is the *underlying root cause* of an entire family of high-value smart-contract failures, not a peripheral nuisance:

> "due to the lack of awareness of the inherent nondeterminism in the Ethereum blockchain system and how it affects the funds transfer of smart contracts, there can be unknown vulnerabilities ... Our new focus on nondeterminism-related smart contract payment bugs captures the root causes of many common vulnerabilities without relying on any known patterns and also encompasses recently disclosed issues that are not handled by existing research."

Mechanism and quality: this is a peer-reviewed PACMPL paper with high citation count that (a) elevates nondeterminism from "implementation detail" to a *classification primitive* for vulnerabilities, and (b) ties it directly to **funds transfer** — i.e., the exact consensus-critical surface ADR-004 protects. It models the execution context and uses information-flow tracking to show how nondeterministic factors propagate into payment outcomes. For Bloom's argument, the load-bearing inference is: if blockchain execution already harbors nondeterministic factors that silently corrupt money flows, then *adding* opcodes (IEEE float) whose results are platform/order-sensitive enlarges exactly this root-cause class. The paper does not name floating point specifically — that is the honest limit — but it establishes that the *category* H3 worries about is real, financially material, and not reducible to a checklist of known bug patterns.

**VerX: Safety Verification of Smart Contracts** (IEEE S&P 2020; DOI 10.1109/sp40000.2020.00024) *(full text).* VerX corroborates that the *only* nondeterminism a sound verifier can tolerate is **explicitly modeled, bounded** nondeterminism — never silent arithmetic nondeterminism. Its symbolic engine "non-deterministically select[s] a function fi to invoke" and "non-deterministically executes" steps, and to keep this sound it must "model non-determinism more precisely, we use a powerset [construction]" with external/unknown values "modeled with uninterpreted constants" (lines 561, 833, 893, 1117). The lesson supporting H3: verification scales only when every nondeterministic choice is a *deliberate, enumerable* abstraction. IEEE float introduces nondeterminism of a different, hostile kind — value-level divergence from rounding/order/NaN-payload that is *not* a clean enumerable choice — which a powerset/uninterpreted-constant model cannot cheaply absorb.

---

## Cluster B — Floats break the real-arithmetic model that proofs are written against

**When Does a Bit Matter? Techniques for Verifying the Correctness of Assembly Languages and Floating-Point Programs** (PhD dissertation, Univ. of Oregon, 2021; https://openalex.org/W3201237355) *(abstract only — full-text fetch failed, "Stream has ended unexpectedly").* This is H3's anchor for the provability limb. Its framing is exactly the float-vs-abstraction tension ADR-004 invokes:

> "With numerical programs, floating-point arithmetic only approximates real arithmetic. Floating-point issues are compounded by parallel computing, where a large space of solutions are acceptable."

Two mechanisms relevant to H3: (a) float **only approximates** the real/rational arithmetic that specifications and SMT reasoning are naturally written over — so a proof about the intended computation does not transfer to its float realization without extra, hard error analysis; (b) under **parallelism/reordering**, "a large space of solutions are acceptable" — i.e., the same float program legitimately yields *different bit patterns on different nodes/orderings*. That second point is the cross-node-determinism hazard stated in the abstract of an independent verification dissertation. The whole dissertation exists because verifying float requires *bespoke* techniques (refined error analysis, MPI-reduction reasoning) that go well beyond ordinary integer reasoning — which is itself an argument that admitting float into a consensus VM imports a disproportionate verification burden.

**Lipschitz-Based Robustness Certification Under Floating-Point Execution** (arXiv 2603.13334, 2026) *(abstract only).* This gives the cleanest *concrete* statement of the soundness gap H3 relies on. Certifiers are "proved with respect to a semantic model that assumes exact real arithmetic. In reality deployed ... implementations execute using floating-point arithmetic. This mismatch creates a semantic gap," and crucially:

> "we exhibit concrete counterexamples showing that real arithmetic robustness guarantees can fail under floating-point execution, even for previously verified certifiers."

Mechanism for H3: a *property formally proved* over reals can be *violated* once the same code runs in float. This is precisely the "SMT-provability" failure mode — the theorem the SMT solver discharges is about a different (real/integer) semantics than the float machine actually executes, so the proof is unsound for the deployed system. The paper also notes discrepancies "become pronounced at lower-precision formats" and reach "semantically meaningful" magnitudes at float32 — i.e., not an academic epsilon. (Domain is neural-net certification, not blockchains — an honesty caveat — but the *semantic-gap mechanism* is domain-independent.)

**Symbolic execution of floating-point programs: How far are we?** (J. Systems and Software 2025, DOI 10.1016/j.jss.2024.112242; also APSEC 2022 / SSRN versions) and **Efficient generation of error-inducing floating-point inputs via symbolic execution** (ICSE 2020, DOI 10.1145/3377811.3380359; 24 citations) *(abstract-only / metadata).* The existence and framing of this sustained research line ("how far are we?", "error-inducing inputs") is itself evidence that **SMT/symbolic reasoning over floats is an open, hard, partial problem** rather than a solved one. Float symbolic execution is treated as a specialty subfield with its own dedicated tooling and benchmarks — contrast the integer/bitvector reasoning that mainstream smart-contract verifiers use off the shelf.

---

## Cluster C — Determinism is treated as a *prerequisite* across the verification-friendly designs in the corpus, and floats are the canonical thing excluded

The strongest *convergent* signal for H3 is what the corpus's successful verification systems all have in common: they reason over **integers / unbounded mathematical integers / reals**, never IEEE floats.

- **Foundational Verification of Smart Contracts through Verified Compilation** *(full text)* deliberately models contract data with "idealized 'mathematical' data types like unbounded integers and finite maps," is "rigorous about integers versus real numbers," and obliges the programmer to discharge range proofs (`0 ≤ x < 2^256`) per integer assignment (lines 77, 267, 373, 769). The entire methodology presupposes a clean, deterministic arithmetic domain; float is simply absent from the value grammar.
- **Fast and Reliable Formal Verification of Smart Contracts with the Move Prover** *(full text)* likewise builds its spec language on "arbitrary precision signed integers" over an unsigned-integer execution model (lines 164, 176–177). Move's prover-friendliness is rooted in a determinate integer semantics.
- **VerX**, **Rich Specifications for Ethereum Smart Contract Verification**, **PropertyGPT**, and **Theorem-Carrying Transactions** *(all full text)* are uniformly built over word/integer/uninterpreted-value models. None introduces IEEE float into the verified core.

The honest reading: across **every** smart-contract verifier in this corpus, float is excluded *by construction* and determinism over an integer/real model is the implicit precondition that makes SMT discharge tractable. ADR-004's exclusion is therefore squarely **consistent with established best practice** in verification-oriented chain design — Bloom is not inventing a novel constraint, it is conforming to one the literature already obeys.

**SoK: What don't we know? Understanding Security Vulnerabilities in SNARKs** (arXiv 2402.15293) *(full text)* reinforces the determinism-as-prerequisite argument from the proving side. ZK/SNARK pipelines force computation into a **deterministic** circuit over a finite field Fp; the SoK lists "(Deterministic)" computation and correct field-arithmetic encoding as core obligations, and notes "arithmetic circuits do not natively support non-arithmetic operations" (lines 195, 229–243). Floating point has no native, sound representation here — it would have to be emulated bit-for-bit at enormous cost. So in the proving substrate Bloom's class of systems ultimately targets, float is *de facto* excluded and integers/field elements are the only first-class numeric domain. **Arguzz: Testing zkVMs for Soundness and Completeness Bugs** *(full text)* similarly centers on "generating a deterministic program, called circuit" and reasoning "specific to field arithmetic" (lines 123, 299) — again, a deterministic, float-free arithmetic world is the precondition for soundness testing.

**CT-wasm: type-driven secure cryptography for the web ecosystem** (PACMPL 2019, DOI 10.1145/3290390; 55 citations) *(abstract only — fetch 403).* CT-Wasm is the methodological template for H3's move: take WebAssembly and *restrict the type system / instruction surface* to obtain a verifiable guarantee (constant-time, IF-security) that base Wasm cannot give, with the guarantees "verifiable in linear time." It shows that **excluding/constraining hazardous instruction classes to buy a provable property is a recognized, mechanized design pattern** — exactly what excluding float opcodes from chain mode does for determinism+provability.

---

## Mechanism summary (why exclusion buys both properties at once)

1. **Cross-node determinism.** IEEE-754 outcomes depend on rounding mode, operation order (associativity is not preserved), FMA contraction, x87 80-bit intermediates vs SSE, and NaN-payload/sign nondeterminism. The "When Does a Bit Matter?" abstract states the reordering hazard directly ("a large space of solutions are acceptable"); the nondeterministic-payment-bugs paper shows arithmetic-context nondeterminism propagates into funds transfer. Removing the opcodes removes the divergence source — a clean, total fix rather than a per-engine mitigation.
2. **SMT-provability.** Specs and solvers reason naturally over integers/reals; the Lipschitz paper exhibits *concrete counterexamples* where real-arithmetic theorems fail under float execution — the precise unsoundness H3 names. The float-symbolic-execution research line confirms SMT-over-float is hard and only partially solved, whereas every verified smart-contract system in this corpus discharges obligations cheaply over an integer/real model. Excluding float keeps the proof semantics and the execution semantics aligned.

Because the *same* property — a determinate, exact arithmetic semantics — is what delivers both determinism and provability, a single exclusion buys both. That is the genuinely strong part of the H3 case.

---

## Honest limits (where "necessary" is not earned by the corpus)

- **No corpus paper proves uniqueness.** The literature shows float is *harmful* and that exclusion is *sufficient* and *standard*; it does not show exclusion is the *only* sound route. In-principle alternatives the corpus itself hints at: (a) a **fixed, fully-specified deterministic float profile** (single rounding mode, no FMA contraction, canonical NaN) — the Wasm specification effort below shows such pinning is feasible; (b) **bit-exact reproducible arithmetic** (the corpus contains "High-Precision Anchored Accumulators for Reproducible Floating-Point Summation," IEEE TC 2019, and "Reproducible Floating-Point Aggregation in RDBMSs," ICDE 2018 — abstract-only — i.e., reproducible float *is* an active engineering result); (c) **software fixed-point/rational** libraries over the existing integer core. Each is harder to verify and easier to get wrong than exclusion, which is the pragmatic argument for ADR-004 — but "harder" is not "impossible," so the precise word *necessary* overshoots the evidence.

- **Float verification demonstrably exists.** The same dissertation cited as a hazard (and an entire corpus sub-shelf — "Formal Verification of Floating-Point Hardware Design," "Floating-Point Algorithms and Formal Proofs," "Floating-point Semantics of Analyzed Programs") proves floats *can* be formally reasoned about. The honest claim is cost/risk asymmetry, not impossibility.

- **The two best-targeted anchors are not full-text here.** "Detecting nondeterministic payment bugs" (403) and "When Does a Bit Matter?" (stream failed) are cited from abstracts only; CT-Wasm (403) likewise. The full-text corpus that *is* available supports H3 only *indirectly* (by uniformly excluding float and demanding deterministic integer/real models), not by a head-on study of float opcodes in a consensus VM.

- **Determinism vs. float is partly conflated in the sources.** "Nondeterministic payment bugs" concerns blockchain-context nondeterminism (block state, ordering) broadly; it does not isolate IEEE float as a contributor. The bridge from "nondeterminism is a root cause" to "therefore exclude float" is Bloom's inference, well-motivated but not stated in the paper.

**Net:** the corpus robustly supports "exclude floats — they are a real determinism + provability hazard and every verification-friendly design here already does so," which is sufficient to justify ADR-004 as sound, conservative, standard engineering. It supports the literal modal claim *necessary* (exclusion is the unique option) only by inference from cost/risk asymmetry — hence **moderate**, with the strength concentrated in Clusters A and C and the "necessary" wording being the falsifier's natural target.
