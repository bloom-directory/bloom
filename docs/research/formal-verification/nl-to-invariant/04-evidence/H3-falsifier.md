# H3 — Falsifier

REFUTATION STRENGTH: decisive — round-trip/back-translation is neither sufficient nor a reliable autonomous faithfulness oracle; all four disconfirming conditions are met.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Decisive — Evaluating LLM-driven User-Intent Formalization** (Lahiri, FMCAD 2024, arXiv 2406.09757, full text): "there is no algorithmic way of ensuring the correctness of the user-intent formalization"; explicitly evaluates and REJECTS semantic-equivalence-against-a-reference ("cannot distinguish weak and vacuous specifications from strong yet incomplete"); still needs human labels + hidden tests.
- **Self-undermining of the strongest pro paper — Autoformalize by Symbolic Equivalence** (arXiv 2410.20936, full text): the back-translation leg (SemCo) "does not grasp the logical nature of formal statements"; best 1@k ~41–42% (wrong the majority of the time); on MATH they "manually check each formalization" — not a no-human loop.
- **Correlated error / self-consistency ≠ faithfulness:** LINC (full text) shows same-LLM NL→FOL has systematic faults; nl2spec's gains came partly from *cross-model* checks + human edits (44.4%→86.1%).
- **Equivalence intractable for the needed fragment:** FOTL is undecidable in full, ExpSpace-complete in decidable fragments (Artale et al., full text) — exactly where quantified+temporal invariants live.
- **Fluent back-translation inflates over-trust:** Gordon & Matskevich (arXiv 2310.03885, full text) — "the only bridge is the humans".
