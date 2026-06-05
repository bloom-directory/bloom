# 06 — Red team (adversarial review of the synthesis)

> Methodology note: Phase-2 hypothesis and Phase-3 evidence work ran as independent
> sub-agents (Proponent/Falsifier per hypothesis). The synthesis and this red-team
> pass were performed by the PI directly, because the sub-agents were blocked from
> writing to the workspace and returned their analyses instead (their verdicts +
> citations are persisted verbatim-in-substance in `04-evidence/`). This is a
> deviation from full-mode (independent Synthesizer + Red-Team agents); flagged for
> honesty and it lowers the independence of the final write-up.

Challenges to the emerging synthesis, each with disposition.

**RT-001 — "The deterministic checker is the trust anchor" risks equivocating on
*trust of what*.** The corpus supports that the gate makes an unreliable generator
*usable* and certifies *formal soundness*; it does **not** support that the gate makes
the result *intent-faithful*. → **Addressed:** synthesis must state the gate secures
*form, not meaning*, and pair every "gate" claim with the V-004 residual. Done in
RESEARCH "What We Found" #1 and #3.

**RT-002 — Over-refuting round-trip.** V-003 could be read as "round-trip is
worthless." The evidence is narrower: *NL-similarity* round-trip with the *same model*
is unreliable; *cross-model* checks (nl2spec Codex→Bloom) and *formal*-equivalence-closed
loops (Li 2024, SpecLoop[abstract]) do help. → **Addressed:** claim is scoped to
"NL paraphrase is not a sufficient *faithfulness gate*"; a formal check is the reliable
oracle. Do not claim round-trip has zero value.

**RT-003 — Corpus bias: almost no blockchain-consensus-determinism evidence.** The
lit map flagged that no corpus paper addresses the consensus-determinism constraint
directly. So every *on-chain* conclusion (witness non-determinism breaks consensus;
the gate must be a checked predicate per transition) is an **extrapolation** from
off-chain FM + the determinism requirement, not a directly evidenced result. →
**Addressed:** RESEARCH labels these as *engineering inferences for Bloom*, confidence
*tentative*, distinct from the corpus-supported claims.

**RT-004 — Leaning on abstract-only papers.** Agentic Model Checking and SpecLoop are
abstract-only; both are used for the "agents propose, solvers verify" and round-trip-loop
claims. → **Addressed:** those claims are independently carried by full-text LINC,
Logic-LM, Li 2024, Neuroforger; the abstract-only items are cited as corroboration only,
tagged.

**RT-005 — The novel insight (the "type/token" framing below) may outrun the data.**
The corpus does not state it in these words. → **Addressed:** the insight is presented
as a *reframing that organizes* the five verdicts, explicitly an interpretation, not a
cited finding; it is falsifiable (it predicts faithfulness checks that don't reduce to
form-checking would refute the "form not meaning" boundary).

**RT-006 — H4 "irreducible" vs H4-falsifier "narrowable" could look like having it
both ways.** → **Addressed:** stated as a single calibrated claim — the gap is
*narrowable but not fully closable*; "irreducible" applies only to the *residual*, and
the residual's destination (human/social arbitration) is explicitly weakly-supported
by this corpus.

**RT-007 — Generalizing from math/Dafny/RTL autoformalization to DeFi economic
invariants.** Much evidence is from mathematics (miniF2F) and verification-aware
languages, not economic safety invariants. → **Addressed:** PropertyGPT, Neuroforger,
DeCon, and Rich Specifications provide the *smart-contract* anchor; cross-domain claims
are flagged where they rest on math-only evidence.

No challenge overturns a verdict; RT-001/002/003 require *scoping and confidence
calibration* in the write-up, which is applied. Verdicts V-001…V-005 are therefore
RATIFIED.
