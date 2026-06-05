# H1 — Proponent

SUPPORT STRENGTH: moderate — the sound deterministic gate is demonstrably load-bearing across math and smart-contract domains, but full-text evidence shows it secures soundness *relative to the formal artifact*, not intent, and generator quality still measurably contributes.

> Persisted by the PI from the sub-agent’s returned verdict + citations (the agent was blocked from writing directly). Verdict and cited papers are the agent’s.

- **LINC** (10.18653/v1/2023.emnlp-main.313, full text): the prover *gate* lets a 15.5B model beat GPT-4+CoT by ~10%; the Scratchpad ablation (same FOL, LLM deduces) gives no gain — direct evidence the **gate, not the generator**, supplies the win.
- **Autoformalize by Symbolic Equivalence and Semantic Consistency** (arXiv 2410.20936, NeurIPS 2024, full text): ATP-checked equivalence selection over k candidates recovers a large pass@1→pass@k gap.
- **Logic-LM** (10.18653/v1/2023.findings-emnlp.248, full text): "faithful as long as the formulation is correct" — a deterministic solver does the inference (+39.2% over base LLM).
- **Neuroforger** (arXiv 2605.31389, full text) and **PropertyGPT** (10.14722/ndss.2025.241357, full text): concrete-execution / prover gates instantiate "agents propose, gate disposes" on contracts.
- Honest limit (keeps it moderate): every full-text paper shows the gate cannot certify *intent* (Autoformalize's vacuous "4=4"; Lahiri arXiv 2406.09757 "no algorithmic way of ensuring correctness of user-intent formalization"), and better generators/RAG still help — so "not the generator's quality" is overstated.
