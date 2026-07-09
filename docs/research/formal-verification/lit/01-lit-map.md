# 01 — Literature Map (frozen after Phase 1)

*649 papers gathered across 5 keyless sources; 349 in the on-topic subset (`data/relevant.json`).
2026-05-29.*

This orients the hypothesis and testing agents. It is not the final product. Citations are
title + year; full records (DOI/URL/abstract) are in `data/corpus.json`. The corpus is broad
(some cross-field noise from generic queries was filtered into `data/relevant.json`); the key
clusters below are well-represented.

## The terrain

The literature relevant to "enforce invariants and formally prove petals" splits into seven
clusters that map almost one-to-one onto Bloom's seven ADRs.

**1. Specifying invariants for contracts (→ ADR-001, H1).** The dominant industrial pattern
is a *restricted, declarative specification language* layered over the implementation language:
the Move Prover's MSL ("The Move Prover", 2020; "Fast and Reliable Formal Verification of Smart
Contracts with the Move Prover", 2022), Certora/CVL, Scribble, Solidity's SMTChecker, and
VerX's temporal properties ("VerX: Safety Verification of Smart Contracts", 2020). The
consensus is that specs must be *machine-checkable and human-readable simultaneously*; a recent
frontier line synthesizes or extracts specs (PropertyGPT 2025; "Extracting Formal
Smart-Contract Specifications from Natural Language with LLMs", 2024; "Learning Contract
Invariants Using Reinforcement Learning", 2022; "Almost correct invariants: synthesizing
inductive invariants by fuzzing proofs", 2022). No paper directly argues "opaque closures
cannot be adjudicated" — that human↔machine arbitration angle is a **gap** Bloom is pushing on.

**2. Runtime vs. static enforcement (→ ADR-002, H2).** "Runtime Verification of Ethereum Smart
Contracts" (2018) and the RV survey ("A survey of challenges for runtime verification…", 2019)
establish runtime monitoring as practical but explicitly *post-hoc* — it detects, it does not
prevent. "Runtime Assertion Checking and Static Verification: Collaborative Partners" (2018)
frames the two as complementary, not substitutes. Static analysis tools (ZEUS 2018; SmartCheck
2018; "A Semantic Framework for the Security Analysis of Ethereum Smart Contracts" 2018) catch
classes of bugs pre-deploy. The detection≠prevention principle is **well-supported**; whether a
*view-function-shaped* runtime invariant is the right primitive is more specific to Bloom.

**3. Rust-level proof (→ ADR-006, H5 source side).** A mature toolchain exists for proving Rust
itself: Prusti ("Leveraging Rust types for modular specification and verification", 2019; "The
Prusti Project", 2022), Verus ("Verus: Verifying Rust Programs using Linear Ghost Types", 2023),
RustHorn (2021), Creusot/Aeneas ("Aeneas: Rust verification by functional translation", 2022),
RefinedRust (2024). Crucially these verify *source* Rust, not the compiled Wasm — directly
relevant to the source→Wasm gap.

**4. Wasm formal semantics & deterministic execution (→ ADR-005, H4).** WasmCert ("Mechanising
and verifying the WebAssembly specification", 2018; Iris-Wasm 2023) and the verified monadic
interpreter WasmRef-Isabelle (2023, used as an "industrial fuzzing oracle") are the mechanized
oracles Bloom's ADR-005 names. CT-wasm (2019) and "Formally Verified Cryptographic Web
Applications in WebAssembly" (2019) show typed Wasm subsetting works. This cluster **supports**
the feasibility of a conformance oracle, but no paper validates "pin a *profile* not a binary"
as a consensus mechanism specifically.

**5. Floating-point nondeterminism (→ ADR-004, H3).** "Detecting nondeterministic payment bugs
in Ethereum smart contracts" (2019, 83 cites) is the strongest empirical anchor that
nondeterminism (incl. floats) causes consensus-relevant bugs. "Floating-point-consistent
cross-verification methodology" (2026) and "Lipschitz-Based Robustness Certification Under
Floating-Point Execution" (2026) confirm floats remain a verification headache. The corpus is
**thin** on the specific claim "excluding floats is *necessary*" — most blockchains simply never
had floats, so the counterfactual is rarely studied (a likely Inconclusive-leaning area).

**6. Source→bytecode proof transfer (→ ADR-006/H5).** The foundational results are here:
"Proof-carrying code" (Necula, 1997, 1033 cites), "The design and implementation of a
certifying compiler" (1998, 357 cites), CompCert/verified compilers ("Formal verification of an
optimizing compiler", 2007; "An Iris Instance for Verifying CompCert C Programs", 2024),
translation validation ("Translation Validation for JIT Compiler in the V8…", 2024; "Formally
Verified Native Code Generation in an Effectful JIT", 2023), and KEVM (2017) for bytecode-level
semantics. This cluster **strongly supports** the claim that a source proof does not transfer to
deployed bytecode without verified compilation / translation validation / PCC.

**7. zkVM soundness & underconstraint (→ ADR-007, H6).** Verifiable computation roots
(Pinocchio, 2013, 834 cites) plus the emerging circuit-verification line: "Formal Verification
of Zero-Knowledge Circuits" (2023) and "Role of Zero-Knowledge Proof in Blockchain Security"
(2022). The specific "~96% of zkVM bugs are underconstraint" statistic Bloom cites is **not yet
confirmed in this corpus** — a targeted second-round search may be needed for H6.

**Cross-cutting (PBT/fuzzing as the pre-deploy rung):** SMARTIAN (2021), Echidna-style
coverage-guided PBT ("Coverage guided, property based testing", 2019), the fuzzer SoK ("Are We
There Yet? Unraveling the State-of-the-Art Smart Contract Fuzzers", 2024), and "Belobog: Move
Language Fuzzing Framework" (2025) support Bloom's Rung-3 (pre-deploy adversarial fuzzing) as
standard practice — while the fuzzer SoK is also a source of *limits* (sampling can't catch
narrow logic bombs), which sharpens the H2 falsification.

## Apparent consensus

- Declarative, readable specs + a checker is the established way to make invariants both
  provable and auditable (Move Prover, Certora, VerX).
- Runtime verification detects but does not prevent; it pairs with static methods.
- Source-level proofs do **not** automatically cover compiled artifacts — this is a named,
  studied gap with mature (if heavyweight) solutions (PCC, CompCert, translation validation).
- Deterministic execution is a precondition for any replay/fraud-proof scheme.

## Open disagreements / gaps for this inquiry

- Whether **opaque** predicates can ever be adjudicated (H1) — largely unstudied; Bloom's
  arbitration framing is novel.
- Whether excluding floats is *necessary* vs. merely *convenient* (H3) — corpus thin.
- The empirical magnitude of zkVM underconstraint (H6) — needs targeted search.
- Whether a conformance *profile* (not a binary) is a sound consensus primitive (H4) — feasible
  per Wasm-semantics work, but the consensus-mechanism claim is unvalidated.
