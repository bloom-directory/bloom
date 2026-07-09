# H5 — Proponent

SUPPORT STRENGTH: strong — the corpus contains a near-exact instantiation of the witness-replay mechanism, and the refute-vs-establish asymmetry is stated by the source authors themselves.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Neuroforger** (arXiv 2605.31389, full text): frames verification as concretizing a spec with existentially-quantified abstract variables; an LLM proposes the witness (attacker contracts + tx sequence); type-checking + concrete Forge execution certify it — **precision 100% "ensured by type checking and concrete execution"**, false negatives "do not exist by construction". Exactly "refutation made trustless by replay".
- **The asymmetry in the authors' own words:** liquidity/enabledness ("for all actions, P is reachable") are NOT expressible because showing them "is more similar to a proof than to a counterexample."
- **"Agents propose, solvers verify"** is the validated paradigm — Agentic Model Checking (abstract: BMC "discharges every soundness-relevant decision", counterexamples pass replay/realism validation); echoed by LINC, Logic-LM, SpecLoop.
- **The "establish" side needs a checked predicate:** PropertyGPT runs a dedicated prover; DeCon/DCV proves universal safety only by induction over all reachable states. Witnesses cannot substitute.
- Honest limits: replay needs an unambiguous predicate to replay against; consensus re-execution ≠ Neuroforger's off-chain Forge harness (the host/guest seam must be shown to map).
