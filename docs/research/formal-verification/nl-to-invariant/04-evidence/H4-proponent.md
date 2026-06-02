# H4 — Proponent

SUPPORT STRENGTH: strong (for the core predicate-vs-intent gap) — with an explicit caveat that the social-arbitration / on-chain clause is weakly supported by this corpus.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Lahiri, FMCAD 2024** (arXiv 2406.09757, full text): almost verbatim — "there is no algorithmic way of ensuring the correctness of the user-intent formalization"; its metrics are over tests (predicate-vs-execution) and mutants (predicate-vs-predicate); "relies completely on a human to ensure that the specification matches the intent."
- **Gordon & Matskevich, Trustworthy Formal NL Specifications** (arXiv 2310.03885, full text): "the only bridge … is the humans"; even a deterministic, certificate-producing, ML-free pipeline cannot catch a misdefined lexicon (`monotone := λf.True`) — it only leaves evidence for human inspection.
- **nl2spec, PropertyGPT, Autoformalization** triangulate: ambiguity is "inherent" and needs human supervision; ground truth is human-judged.
- Honest weaknesses: Lahiri's automated metric sometimes *outperformed* human labels (in-pipeline checks shrink the residual); "intent" is only ever operationalized via human-authored tests/specs (partly definitional); the social-economic-arbitration clause has **no direct corpus support** — flagged as the weak part.
