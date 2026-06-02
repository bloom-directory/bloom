# H4 — Falsifier

REFUTATION STRENGTH: decisive (for H4 as literally stated — "irreducible gap no automated check can close") — the gap is narrowable by deterministic proxies, though an oracle-relative residual remains.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Decisive — Lahiri, FMCAD 2024** (full text): an automated metric from symbolic spec-testing + output **mutation** (kill-set completeness) + **vacuity** rejection AGREES closely with human {WRONG/WEAK/STRONG} labels on 64 Dafny/MBPP-DFY specs, and even *corrects* the human oracle (caught mislabeled tasks + transcription bugs). Intent-conformance is therefore partially mechanically approximable.
- **Corroborating proxies:** Autoformalize/Li 2024 (symbolic-equivalence + round-trip semantic consistency: +up to 22.6% 1@k, −18–22% human labeling; catches trivial "4=4"); LINC (K=10 ensemble majority vote, +14.2 acc pts); Logic-LM (solver-error self-refinement); PropertyGPT (recall 0.80 vs human props, 26 real violations).
- **Residual (why partial-of-the-strong-claim, not total closure):** every proxy is oracle-relative (Lahiri needs a strong hidden test suite; mutation only covers output-value mutants; quantifier/recursion cases failed); nl2spec keeps a human in the loop for irreducible ambiguity. The gap is **narrowable, not fully closable**.
