# 01 — Literature map (frozen after Phase 1)

**Corpus:** 436 unique papers (OpenAlex/arXiv/Crossref/EuropePMC/Semantic Scholar),
`--since 2019`, 0 retracted. Semantic Scholar rate-limited on 3/5 queries; coverage
still broad. Many off-topic items (general LLM/6G/physics) from broad queries — the
on-topic core is ~40–60 papers.

## The terrain
NL → formal specification via LLMs is an **active, fast-moving subfield** with a
clear arc. **Feasibility is established**: *Autoformalization with Large Language
Models* (2022) and *nl2spec* (2023, NL→temporal logic) show LLMs can translate
informal statements into formal artifacts; the smart-contract instance is *PropertyGPT*
(2025, RAG-based property generation for FV), building on *Rich Specifications for
Ethereum Smart Contract Verification* (2021) and a *Survey of Smart Contract Formal
Specification and Verification* (2020/2021).

**The consensus pain point is not generation but *validation that the formal artifact
matches intent*.** *Evaluating LLM-driven User-Intent Formalization for
Verification-Aware Languages* (2024, Dafny/F*) and *Trustworthy Formal Natural
Language Specifications* (2023) both frame the core risk as: a generated spec can be
internally valid yet **not capture what the human meant** (under-specification,
vacuity, silent intent drift). Hallucination is repeatedly named as the dominant
failure mode (PAT-Agent 2025; plus a cluster of LLM-hallucination papers, e.g.
HalluGuard 2026).

**The recurring mitigation is a "propose-and-check" loop: the LLM proposes, a
deterministic oracle disposes.** *Logic-LM* (2023, LLM + symbolic solver),
*SpecLoop* (2026, spec generation with a formal-verification feedback loop),
*KerSpecGen* (2025), *FLAG* (2025, formal+LLM assertion generation), *PAT-Agent*
(2025, autoformalization for model checking with verification feedback), and
*Neuroforger* (2026, **certified violation witnesses** for contracts via LLMs) all
route LLM output through a sound checker (SMT, model checker, proof assistant,
witness validator) rather than trusting the model. This is the literature's answer
to "how do you make it secure."

**Representation choices** span temporal logics (nl2spec, TLA+), SMT, declarative
specs (*Safety Verification of Declarative Smart Contracts* 2022), verification-aware
languages (Dafny/F*), and **controlled natural language** (*Developing controlled
natural language for formal specification patterns* 2025) — the last directly relevant
to a restricted, auditable referent.

## Apparent consensus
- LLM NL→spec is feasible and useful, but **must be checked** by a sound,
  deterministic backend; raw LLM output is not trustworthy on its own.
- The hardest, least-solved part is **intent conformance** (spec ↔ meaning), not
  syntactic formalization.

## Open disagreements / gaps
- **How much can be automated vs. requires a human-in-the-loop** (nl2spec is
  *interactive* by design; others chase full automation).
- **No paper in the corpus addresses the blockchain-consensus determinism
  constraint** — that the enforced artifact must be deterministically re-checked by
  mutually-distrusting validators, which forbids an LLM in the enforcement path. This
  is the gap Bloom sits in.
- **Canonical identity / decidable equivalence of the spec object** as a shared
  referent (for arbitration) is largely implicit; little direct treatment.
- Measured accuracy/failure *rates* are scattered and task-specific; few head-to-head
  numbers.
