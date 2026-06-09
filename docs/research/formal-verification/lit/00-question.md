# 00 — Research Question (frozen INPUT)

*Status: frozen after Phase 0 · 2026-05-29 · full mode, deep*

## Research question

**Which mechanisms for enforcing invariants and formally proving smart-contract / WebAssembly
programs are sound and practical — and do Bloom's seven proposed verification decisions
(ADR-001…007) hold up against the scientific literature?**

This is a literature-grounding inquiry attached to the existing
[`../`](../README.md) formal-verification design workspace. The design there was argued from
first principles; this inquiry tests each PROPOSED decision against published evidence
(formal methods, programming languages, blockchain security, and ZK research) and folds the
verdicts back into the decision log and red-team.

## Narrowing

- **In scope:** invariant specification & enforcement for contract-like programs; runtime
  verification vs. static proof; deterministic Wasm execution; floating-point determinism;
  source→bytecode proof transfer (verified compilation / translation validation /
  proof-carrying code); zkVM soundness and underconstraint.
- **Out of scope:** Bloom-specific implementation mechanics (handled in `02-architecture.md`);
  consensus/BFT liveness (a separate concern); general DeFi economic-attack taxonomy.
- The unit of evaluation is **the seven ADRs**, restated as falsifiable hypotheses (see
  `02-hypotheses.md`). "Inconclusive" is an acceptable, honest verdict.

## Hypotheses seed (ADRs → claims)

| H | From | Claim under test |
|---|------|------------------|
| H1 | ADR-001 (Q1) | A restricted, total, *readable* predicate AST is necessary for adjudicable invariants; opaque closures cannot serve arbitration. |
| H2 | ADR-002 (Q2) | An invariant is best enforced as a pure view function checked at runtime — but runtime detection ≠ prevention (cannot stop logic bombs). |
| H3 | ADR-004 (Q4) | Excluding floating point is necessary for both cross-node determinism and SMT-provability of chain-mode code. |
| H4 | ADR-005 (Q5) | Pinning a *conformance profile* (not a binary) suffices for cross-node deterministic Wasm execution. |
| H5 | ADR-006/007 (Q6/Q7) | A source-level proof does not transfer to deployed Wasm without verified compilation / translation validation; proofs must be optional + provenance-gated. |
| H6 | ADR-007 (Q8) | zkVM underconstraint is a structural soundness risk no single prover mitigates; a re-execution / fraud-proof fallback is required. |

(Hypothesis agents may sharpen, split, or add; PI culls to the 5 strongest.)

## Query strings (Phase 1)

1. `formal verification smart contracts invariants` — since 2015
2. `Move Prover specification language smart contract verification` — since 2018
3. `Rust program verification Kani Verus Creusot Prusti` — since 2018
4. `WebAssembly formal semantics mechanized verification` — since 2017
5. `runtime verification assertion checking smart contracts` — since 2015
6. `floating point nondeterminism WebAssembly reproducible execution` — since 2017
7. `zero-knowledge virtual machine zkVM soundness underconstrained circuits` — since 2021
8. `proof-carrying code translation validation verified compiler` — all years (foundational)
9. `property-based testing fuzzing smart contract invariants` — since 2017

Sources (keyless, public): OpenAlex, arXiv, Crossref, Europe PMC, Semantic Scholar.
