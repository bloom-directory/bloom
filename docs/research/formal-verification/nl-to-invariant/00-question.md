# 00 — Research question (frozen INPUT)

## Research question
Can natural-language statements of intent be translated into **formally
enforceable on-chain invariant predicates** through a pipeline that is *secure* —
faithful to the stated intent and robust to LLM/adversarial error — under the hard
constraint that the enforced artifact runs in **deterministic blockchain
consensus**? And what **predicate representation** best serves as the shared
referent between the human claim, the LLM generator, and the on-chain checker?

Decomposed into three testable sub-questions:
- **Q1 (Methods).** How well can current methods translate NL → formal
  spec/predicate (autoformalization, LLM spec generation)? What are the measured
  accuracy rates and the dominant failure modes (under-specification, hallucinated
  constraints, silent intent drift)?
- **Q2 (Security).** What techniques make an NL→predicate pipeline trustworthy
  adversarially — round-trip/back-translation, formal equivalence vs. reference or
  test vectors, counterexample/witness validation, mutation testing, ensembles,
  human-in-the-loop — and what is the defensible division of labor between
  off-chain LLM generation, deterministic on-chain gates, and social/economic
  arbitration (given an LLM judge cannot sit in a consensus path)?
- **Q3 (Representation).** What intermediate representation best supports both
  human-auditability and machine-checkability? Compare restricted decidable /
  sub-Turing predicate ASTs, SMT-LIB, temporal logics, Move MSL, relational
  before/after specs. Which properties (totality, determinism, canonical identity,
  decidable equivalence, bounded resource use) make a representation safe as the
  shared referent?

## Narrowing decisions
- Scope to **safety predicates over program/contract state** (relational
  before/after invariants), not full functional-correctness specs.
- Treat the on-chain/consensus determinism constraint as a hard requirement: the
  enforced object must be deterministic and cheaply re-checkable by every
  validator; LLM/heuristic judgments are admissible only **off-chain**.
- Empirical accuracy is judged from the spec-generation / autoformalization
  literature; we do not run new experiments.

## Search query strings (≥1 adversarial)
1. `natural language to formal specification LLM autoformalization` (methods)
2. `LLM smart contract specification generation formal verification` (domain methods)
3. `specification faithfulness translation validation equivalence checking` (security/validation)
4. **adversarial:** `limitations LLM formal specification hallucination incorrect ambiguity` (failure/negative results)
5. `decidable specification language temporal logic SMT auditability` (representation)

## Mode
**Full** — broad, contested, high-stakes (security of a consensus-enforced
artifact). Full ticket queue, decision log with ratification, dedicated red-team.
