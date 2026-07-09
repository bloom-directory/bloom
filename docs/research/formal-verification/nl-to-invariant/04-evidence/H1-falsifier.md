# H1 — Falsifier

REFUTATION STRENGTH: partial — soundness is the mechanism that makes an unreliable generator *usable*, but the strong claim "faithfulness comes from the gate *rather than* generator quality" is contradicted, and the corpus's sound gates do not certify intent.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Gains track generator scale too, and the gate's value vanishes at the top.** Logic-LM (full text): GPT-4 beats GPT-3.5 ~48% on standard prompting before any solver; LINC gives GPT-4 no significant lift on FOLIO (72.5 vs 75.3, p=0.58) — the gate helps the weakest generator most. Symbolic-equivalence: a stronger ATP gate barely helps (selector bounded by generator pass@k).
- **For intent/security, the sound gate degenerates to a consistency/compile check admitting vacuous predicates.** Lahiri (FMCAD 2024, full text): a sound verifier still "allows vacuous specifications such as true". Logic-LM §4.4: "a valid symbolic representation does not necessarily equate to a correct problem formulation". PropertyGPT's per-property gate is largely the compiler (63%→87%).
- **A non-sound heuristic selector is competitive** (fires H1's own refutation trigger): in Autoformalize, the embedding-similarity selector (SemCo) wins several n@k cells and catches the "4=4" case the sound ATP passes; best method is sound+non-sound combined.
- No corpus study holds the generator fixed and varies gate-soundness against a held-out *intent* oracle, so refutation is partial, not decisive.
