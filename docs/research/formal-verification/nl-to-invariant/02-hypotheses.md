# 02 — Surviving hypotheses (PI-owned)

Culled from 12 candidates across 4 stance-drafts (`03-open-questions/draft-*.json`).
Selected for testability, consequence, and distinctness; heavy convergence collapsed
into H1–H2, and the genuine controversy (round-trip faithfulness) is isolated as H3.

| id | state |
|----|-------|
| H1 | untested |
| H2 | untested |
| H3 | untested |
| H4 | untested |
| H5 | untested |

---

### H1 — Security comes from the gate, not the generator
**Claim.** Faithfulness/security of NL→predicate derives from routing the unreliable
generator's output through a **sound, deterministic gate** (symbolic-equivalence
selection, an external prover, or on-chain replay) — "agents propose, the
deterministic gate disposes" — not from the generator's quality.
**Refuted if:** measured gains track generator scale/prompting rather than the
addition of a sound gate, or a non-sound heuristic selector matches a sound one.
*(from mechanistic-1, crossdisciplinary-2, frontier-1)*

### H2 — A restricted, decidable representation is the right shared referent
**Claim.** A restricted, total/decidable predicate representation (pattern/controlled-NL
over a decidable fragment) is the best shared referent: one mechanism (grammar
restriction) both lowers intent error *and* provides the determinism + decidable
equivalence an on-chain consensus gate requires.
**Refuted if:** expressive (SMT/full-Turing) representations match restricted ones on
intent fidelity at equal determinism/resource bounds (restriction buys determinism but
no faithfulness), or the decidable fragment can't express real economic invariants.
*(from mechanistic-2, crossdisciplinary-3, frontier-3)*

### H3 — Round-trip / back-translation is a reliable faithfulness oracle  *(contested)*
**Claim.** Round-tripping (render predicate→English, compare to the source claim;
or back-translate and check equivalence) is a sufficient, reliable oracle for
NL→predicate faithfulness, enabling a generate-verify-repair loop without a human
inner loop.
**Refuted if:** forward/back errors are correlated (same model → self-consistency, not
faithfulness), round-trip agreement fails to predict human-judged faithfulness, or it
inflates author over-trust. This is the hypothesis most likely to split.
*(from frontier-2 [pro] vs contrarian-2, mechanistic-3 [con])*

### H4 — Intent-conformance is an irreducible gap no in-pipeline check closes
**Claim.** Predicate-vs-meaning conformance is not mechanically decidable; every
automated metric checks predicate-vs-predicate or predicate-vs-execution, never
predicate-vs-intent. Therefore the residual must be carried by human review and/or
social-economic arbitration — it cannot be closed by any in-pipeline (incl. on-chain)
mechanism.
**Refuted if:** some automated signal (round-trip, ensemble consistency, learned judge)
correlates strongly with human-judged intent-conformance across a benchmark.
*(from contrarian-1; bears on Q2 division of labor)*

### H5 — On-chain, the gate is best realized as witness replay (refutes, can't establish)
**Claim.** For the consensus setting, the deterministic gate is best realized as
**witness replay**: an off-chain LLM emits a candidate predicate + a concrete
violation witness, and consensus re-execution validates the witness — making
*refutation* trustless. But this can only **refute** invariants, not **establish**
universally-quantified safety properties, which still require a checked predicate
evaluated every transition.
**Refuted if:** witnesses are non-reproducible across validators (env-dependent), or
witness-replay can in fact establish universal safety properties (so the
refute/establish asymmetry is illusory).
*(from frontier-1; blockchain-specific, directly relevant to Bloom)*
