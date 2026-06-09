# H2 — Falsifier

REFUTATION STRENGTH: decisive — restriction buys determinism but not intent fidelity; the two properties are separable, and the decidable fragment cannot express real economic invariants.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **Decisive disconfirming study — Developing controlled NL for formal specification patterns** (full text): the restricted CNL grammar *by itself* produced semantically WRONG NL (silently substituting "condition" for the technical attribute `invariant`, "time limit" for `final`/`delay`); fidelity was recovered only by injecting formal LTL semantics — at which point readability "collapsed into cumbersome, unreadable constructions". The fidelity lever was formal-semantics feedback, not grammar restriction, and restriction traded against readability.
- **PropertyGPT** (NDSS 2025, full text): deliberately chose an *expressive* PSL (arbitrary Solidity ops, `old(v)`, Hoare triples, temporal vars) **over** the restricted Certora CVL because expressiveness lowered authoring burden — and hit 80% recall + 12 zero-days on real DeFi, still deterministically verifiable. Expressive beats restricted on intent fidelity in the exact domain.
- **DeCon/DCV** (full text): to stay decidable it had to DROP recursion, the delegate-vote function, mutual cross-contract calls, and Max/Min-with-deletion — real invariants force escape from the fragment.
- **FOTL on finite traces** (full text): decidability bought only via severe restriction (two-variable monodic) and still ExpSpace-complete — the trade is real and steep, not free.
