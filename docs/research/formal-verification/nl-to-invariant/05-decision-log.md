# 05 — Decision log

Verdicts from reading each `04-evidence/H{n}-proponent.md` + `H{n}-falsifier.md`
together; rebuttal reasoning performed by the PI (the matched Proponent/Falsifier
ran as sub-agents; rebuttal folded in here). State: **RATIFIED** — the synthesis survived the red-team pass (`06-red-team.md`,
2026-06-02); RT-001/002/003 required scoping + confidence calibration (applied in
`RESEARCH.md`), none overturned a verdict.

---

### V-001 · H1 (security comes from the gate, not the generator) → **SUPPORTED (refined)** · confidence moderate–high
**Rebuttal of the Falsifier's strongest point.** The Falsifier showed gains also
track generator scale and that the gate's lift vanishes for the strongest generator
(LINC on FOLIO, p=0.58), and that a non-sound selector is competitive — this is
**conceded**: the absolutist "*not* the generator's quality" is too strong.
**What survives (and is decisive):** a *sound, deterministic disposing gate* is what
makes an unreliable generator **usable and trustworthy** (LINC's prover ablation;
symbolic-equivalence selection), and — the load-bearing nuance for this inquiry —
**the gate certifies soundness relative to the formal artifact, not intent** (Lahiri;
Logic-LM §4.4; the vacuous "4=4"). Refined claim supported; the gate is necessary but
certifies form, not meaning. Evidence: `H1-proponent.md`, `H1-falsifier.md`.

### V-002 · H2 (one restriction mechanism lowers intent error *and* gives determinism) → **REFUTED as stated** · confidence high
The Falsifier was **decisive** and the rebuttal cannot answer it: (a) the controlled-NL
study shows fidelity came from *formal-semantics feedback*, not grammar restriction,
and restriction traded directly against readability; (b) PropertyGPT chose an
*expressive* PSL over the restricted Certora CVL and won on real DeFi (80% recall, 12
zero-days); (c) DeCon had to **drop** recursion / cross-contract calls / Max-Min to stay
in the decidable fragment. **Determinism and intent-fidelity are separable**, and
over-restriction harms expressiveness. **Surviving weaker truth:** restriction *does*
buy the determinism + decidable-equivalence half (the on-chain-needed property) — that
leg of the proponent case stands. Evidence: `H2-proponent.md`, `H2-falsifier.md`.

### V-003 · H3 (NL round-trip / back-translation is a reliable faithfulness oracle) → **REFUTED as stated** · confidence high
Falsifier decisive; even the Proponent concedes the reliable oracle is a **formal**
equivalence/execution check, not NL similarity. Lahiri explicitly rejects
equivalence-against-a-reference (can't tell vacuous from incomplete); same-model
forward/back errors are correlated (self-consistency ≠ faithfulness); equivalence is
intractable for the quantified+temporal fragment real invariants need; fluent
back-translation inflates over-trust (Gordon & Matskevich: "the only bridge is the
humans"). **Surviving truth:** a *formal/deterministic* check (equivalence, execution,
witness) closes the loop; **NL round-trip is at best a weak signal and can mislead** —
directly: an AST→English renderer is a readability aid, not a faithfulness gate.
Evidence: `H3-proponent.md`, `H3-falsifier.md`.

### V-004 · H4 (intent-conformance is an irreducible gap no automated check can close) → **SUPPORTED (refined)** · confidence high
The absolutist wording is **refuted** — Lahiri's automated mutation+vacuity metric
agrees closely with human intent labels and even corrects them, and ensembles
(LINC), equivalence+round-trip (Li 2024), and RAG property generation (PropertyGPT)
all *narrow* the gap. **What survives (strongly):** the gap cannot be **fully** closed
by any automated/on-chain mechanism — every proxy is oracle-relative and residual NL
ambiguity needs a human (nl2spec keeps a human in the loop; Gordon: humans are the
bridge). Refined claim: **irreducible *residual* that lands in human review / social
arbitration, but substantially narrowable by deterministic proxies.** The
social/economic-arbitration clause has no direct corpus support (noted). Evidence:
`H4-proponent.md`, `H4-falsifier.md`.

### V-005 · H5 (on-chain gate = witness replay; refutes but can't establish) → **SUPPORTED (refined)** · confidence high
Proponent strong, Falsifier partial — and **both agree the refute-vs-establish
asymmetry is real** (stated by Neuroforger's own authors: universal/liveness shapes
are "more similar to a proof than a counterexample"). The dispute is the
*prescription*, and the Falsifier wins it for Bloom: witnesses are non-deterministic /
env-dependent (can't be a consensus gate), and Bloom's actual need —
`pool_k_non_decreasing` holding across **every** transition — is a universal safety
property witnesses cannot establish; DeCon establishes such invariants by **induction
over all reachable states**, whose on-chain analogue is a deterministically-**checked
predicate per transition** (what Bloom already has). **Refined claim:** witness-replay
is the right mechanism for *off-chain refutation / counterexample challenge*; the
*on-chain establish gate* must be the checked predicate. Evidence: `H5-proponent.md`,
`H5-falsifier.md`.

---

**Cross-cutting result.** V-001…V-005 converge: the *deterministic checker* is the
trust anchor (V-001), it certifies *form not meaning* (V-001, V-004), NL paraphrase
does not bridge the meaning gap (V-003), restriction secures determinism but not
fidelity (V-002), and the on-chain gate must *establish* via a checked predicate while
witnesses *refute* off-chain (V-005). The irreducible residual is intent (V-004).
