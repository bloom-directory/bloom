# H3 Falsifier — "Excluding floats from chain mode is NECESSARY for determinism and provability"

REFUTATION STRENGTH: partial — The corpus decisively refutes the *strong* necessity claim (deterministic, provable float execution demonstrably exists, and the canonical chain-nondeterminism bug paper attributes bugs to non-float sources), but no single paper directly tests Bloom's specific design choice, so the refutation of necessity-in-practice for *this* system is strong-but-not-decisive.

Hypothesis under attack: ADR-004 holds that floats *must* be excluded for chain-mode determinism/provability. "Necessary" is a strong modal claim: it asserts no determinism-and-provability-preserving design admits floats. A single counterexample of deterministic, provable float execution refutes necessity and demotes the claim to "convenient / lower-effort."

---

## 1. Non-problem counter: deterministic, provable float subsets demonstrably exist

If floats *can* be made deterministic and provable, then excluding them is sufficient-but-not-necessary, and "necessary" collapses to engineering convenience.

- **CT-wasm: type-driven secure cryptography for the web ecosystem** (DOI 10.1145/3290390; OpenAlex W2885285030) (abstract only). CT-Wasm is a *strict, type-driven extension to WebAssembly* whose authors "mechanize the full CT-Wasm specification, prove soundness of the extended type system, implement a verified type checker, and give several proofs of the language's security properties." This is direct evidence that a typed Wasm subset can carry mechanized, machine-checked correctness guarantees. The same methodology — a typed subset with a mechanized soundness proof — is exactly what would be needed to admit a *deterministic float subset*. CT-wasm establishes the proof technique is available; it does not establish floats are unverifiable. (Caveat: CT-wasm targets timing/information-flow, not float determinism per se — it is an existence proof of the *method*, not of a verified float fragment.)

- **When Does a Bit Matter? Techniques for Verifying the Correctness of Assembly Languages and Floating-Point Programs** (OpenAlex W3201237355; no DOI) (abstract only). This dissertation explicitly "refine[s] floating-point error analysis of numerical kernels to quantify the tradeoff between accuracy and performance" and verifies correctness of floating-point programs, including handling the fact that "a large space of solutions are acceptable" under MPI. It is a direct counterexample to "floats are unprovable": floats are *verifiable*, and the work shows precisely "when, and precisely how, a computer program's behavior is correct." The cost is heavier reasoning (interval/error bounds), not impossibility.

- **Floating-point–consistent cross-verification methodology for reproducible and interoperable DDA solvers with fair benchmarking** (DOI 10.1016/j.cpc.2026.110172) (metadata/title only; no abstract or full text in corpus). The title itself asserts the achievable goal Bloom claims is impossible without exclusion: *floating-point-consistent, reproducible, interoperable* execution across implementations. Reproducibility/consistency across heterogeneous solvers is the cross-node-agreement property a blockchain needs. (Weight is low: corpus contains only the title, so the methodology's scope and limits cannot be verified from this evidence.)

- **Reproducible Floating-Point Aggregation in RDBMSs** (DOI 10.1109/icde.2018.00098) and **High-Precision Anchored Accumulators for Reproducible Floating-Point Summation** (DOI 10.1109/tc.2018.2855729; conf. version 10.1109/arith.2017.20) (titles only; no abstract/full text in corpus). Independent corroboration that *reproducible* (i.e., bit-deterministic, order-independent) floating-point arithmetic is an actively solved engineering problem in another domain (databases / numerical computing) that, like consensus, requires identical results across machines. Their existence undercuts "floats are inherently nondeterministic." (Low weight: title-only.)

Conclusion of (1): The corpus contains multiple existence proofs that floats can be made deterministic/reproducible (numerical/DB domains) and that typed Wasm subsets can be mechanically verified (CT-wasm). Necessity is therefore not supported: a deterministic, provable float subset is achievable in principle. The honest qualifier is that none of these papers builds *and ships* a verified deterministic-float fragment inside a blockchain VM, so they prove "not impossible," not "easy."

## 2. Misattribution: the canonical nondeterminism bugs are NOT caused by floats

- **Detecting nondeterministic payment bugs in Ethereum smart contracts** (DOI 10.1145/3360615; OpenAlex W2979467439) (abstract only; full text fetch failed, 403). This is the corpus's flagship paper on real, money-losing chain nondeterminism. Its abstract attributes the bugs to: "unpredictable transaction scheduling and external callee behavior," "read-write hazards," and "contract global variables." Verbatim, the root causes are *transaction scheduling, external callee behavior, read-write hazards, and block/contract context*. **The abstract never mentions floating point** (verified: the string "float" does not occur). The EVM has no float opcodes, yet it still has a documented class of nondeterminism bugs — which means float exclusion is neither the cause of, nor a cure for, the canonical chain-nondeterminism hazard.

This is the strongest single blow to necessity-as-stated: ADR-004 frames float exclusion as load-bearing for determinism, but the best-documented nondeterminism failures in the literature come from ordering/scheduling/external-call/state-hazard sources that persist regardless of float policy. Banning floats addresses a hazard the canonical evidence does not implicate.

## 3. The divergence risk is narrow and selectively curable — not type-wide

- **Mechanising and verifying the WebAssembly specification** (DOI 10.1145/3167082; OpenAlex W2778960843) (abstract only) and **Wasm SpecTec: Engineering a Formal Language Standard** (DOI 10.48550/arxiv.2311.07223; OpenAlex W4388685487) (full text). Wasm SpecTec mechanizes the *entire* Wasm standard — including its numeric instructions — into a formal, machine-checkable specification. WebAssembly already mandates IEEE-754 semantics with *deterministic* results for the basic arithmetic operations (the value of `f64.add` etc. is fully specified). The genuinely under-specified / divergence-prone surface is narrow: NaN payload bits, and a small set of operations historically left to host behavior. Wasm closed even these: NaN propagation is canonicalized and `float→int` traps are specified. A mechanized full-spec (SpecTec, and the earlier Isabelle mechanization) is incompatible with the premise that float semantics are inherently un-pin-down-able. If divergence lives in a handful of opcodes (NaN canonicalization, FMA contraction, rounding mode), the *proportionate* control is to canonicalize/ban those opcodes — not to delete the whole `f32`/`f64` type. Banning the type is one valid implementation, but it is over-broad relative to the actual hazard surface, so it is sufficient, not necessary.

- **Bringing the web up to speed with WebAssembly** (DOI 10.1145/3062341.3062363; OpenAlex W2625141509) (abstract only) corroborates that Wasm was designed as a portable compilation target with a precisely-specified execution semantics — i.e., the platform Bloom builds on already specifies float behavior; the open question is only the handful of historically host-dependent corners.

## 4. What the full-text provability evidence actually shows (and its limit)

- **Fast and Reliable Formal Verification of Smart Contracts with the Move Prover** (DOI 10.1007/978-3-030-99524-9_10) (full text). This is the corpus's strongest *pro*-H3-adjacent paper, and it must be read carefully. It states contracts are "easier to verify" partly because "their computations are typically sequential, deterministic." Crucially, it does **not** claim floats are unverifiable; Move simply has no floats and the *spec* language uses "arbitrary precision signed integers... without the complication of arithmetic overflow" — a convenience choice. This shows determinism *helps* provability (which H3 already assumes) but provides **no evidence that float exclusion is necessary** — only that integer-only arithmetic is *easier* to specify. "Easier" ≠ "necessary." This is the central equivocation in ADR-004: the literature supports "deterministic arithmetic eases verification," not "floats preclude verification."

- **Foundational Verification of Smart Contracts through Verified Compilation** (full text) and **Theorem-Carrying Transactions** (full text) similarly establish that provability rests on a deterministic execution semantics — a property a *specified deterministic float subset* would also satisfy. None argues floats are an obstacle in principle.

## Decisive disconfirming result — does one exist?

A truly decisive refutation would be a paper exhibiting a *blockchain/consensus VM* that admits floating point and is both (a) cross-node deterministic and (b) formally verified end-to-end. **No such paper exists in this corpus.** The closest are domain-adjacent: reproducible FP in databases/HPC (titles only) and verified typed-Wasm subsets for a different property (CT-wasm). Therefore the disconfirmation is by *composition* (deterministic-FP techniques + mechanized-typed-Wasm-subset techniques both exist, so a deterministic provable float subset is constructible) and by *misattribution* (the canonical nondeterminism bugs are non-float), not by a single drop-in counterexample.

## Verdict

- The **strong necessity claim is refuted**: deterministic and provable float execution is demonstrably achievable (When Does a Bit Matter?; reproducible-FP line; CT-wasm's verified-typed-subset method), IEEE-754 + mechanized Wasm specs pin down float semantics to a narrow residual hazard (NaN/FMA/rounding) that is selectively canonicalizable, and the canonical chain-nondeterminism bugs (Detecting nondeterministic payment bugs, 10.1145/3360615) are caused by scheduling/external-call/state hazards, not floats.
- The honest residual: ADR-004's *practical* defense survives. The corpus shows floats are *harder* to specify and verify (Move Prover) and that no one has shipped a verified deterministic-float blockchain VM. So float exclusion is a sound, low-effort, defensible engineering choice — it is **sufficient and prudent, but not logically necessary**. ADR-004 should be re-worded from "necessary" to "the simplest sufficient means; admitting a canonicalized deterministic float subset is possible but carries materially higher specification and verification cost."

Refutation strength: **partial** — necessity-as-stated falls; necessity-in-practice-for-Bloom is weakened but not eliminated, because no corpus paper builds the deterministic-provable-float blockchain VM whose mere possibility would make exclusion strictly optional in deployment.

### Citations (corpus only)
- CT-wasm: type-driven secure cryptography for the web ecosystem — DOI 10.1145/3290390 (abstract only)
- When Does a Bit Matter? Techniques for Verifying the Correctness of Assembly Languages and Floating-Point Programs — https://openalex.org/W3201237355 (abstract only)
- Floating-point–consistent cross-verification methodology for reproducible and interoperable DDA solvers with fair benchmarking — DOI 10.1016/j.cpc.2026.110172 (title/metadata only)
- Reproducible Floating-Point Aggregation in RDBMSs — DOI 10.1109/icde.2018.00098 (title only)
- High-Precision Anchored Accumulators for Reproducible Floating-Point Summation — DOI 10.1109/tc.2018.2855729 (also 10.1109/arith.2017.20) (title only)
- Detecting nondeterministic payment bugs in Ethereum smart contracts — DOI 10.1145/3360615 (abstract only)
- Mechanising and verifying the WebAssembly specification — DOI 10.1145/3167082 (abstract only)
- Wasm SpecTec: Engineering a Formal Language Standard — DOI 10.48550/arxiv.2311.07223 (full text)
- Bringing the web up to speed with WebAssembly — DOI 10.1145/3062341.3062363 (abstract only)
- Fast and Reliable Formal Verification of Smart Contracts with the Move Prover — DOI 10.1007/978-3-030-99524-9_10 (full text)
- Foundational Verification of Smart Contracts through Verified Compilation — (full text; no DOI in corpus)
- Theorem-Carrying Transactions: Runtime Verification to Ensure Interface Specifications for Smart Contract Safety — (full text; no DOI in corpus)
