# H5 — Falsifier

REFUTATION STRENGTH: partial — witness non-determinism + env-dependence is real and a directly-checked predicate-per-transition is the better on-chain gate for Bloom, but H5's refute-only asymmetry is confirmed (not illusory), so this is a reframing, not a kill.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Neuroforger** (arXiv 2605.31389, full text) is itself a witness-replay system, yet returns only certified `False` or an uncertified `true?` (certified positive answers are explicit future work) — so witness replay provably **cannot establish** universal safety; and its witnesses are non-deterministic ("running again may produce different outputs", temp 1.0) and env-dependent (gas/reentrancy/block context), breaking a consensus-determinism assumption.
- **The "best on-chain gate" sub-claim fails on Bloom's own architecture:** `pool_k_non_decreasing` fires after EVERY command and reverts on violation — a universal all-transitions safety property witnesses cannot express (Neuroforger: ∀/liveness shapes "not expressible in GATE"; 2^256 blow-ups). **DeCon/DCV** (arXiv 2211.14585) establishes exactly such invariants by induction; the on-chain analogue is a consensus-re-executed *checked predicate*, not a replayed witness.
- **Net reframing:** witnesses *refute* (off-chain bug-finding/challenge), checked predicates *gate* (on-chain establish). H5's asymmetry is true but its prescription ("witness replay is the best gate") is backwards for Bloom. FOTL (10.1145/3651161) grounds the safety/all-extensions distinction the per-transition predicate discharges.
