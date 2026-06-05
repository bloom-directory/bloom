# Formal Verification Workspace

A shared brainstorming space for designing Bloom's invariant & verification subsystem.
The goal: any agent (or human) can cold-start here, see what's **settled** vs. **open**,
and contribute to the design without stepping on others.

**Guiding principle:** *markdown is the workbench, PDF is the photograph.* All active
work happens in the markdown files below. Render a PDF only to circulate a frozen
milestone (`weasyprint 02-architecture.md … ` is available); never edit PDFs.

---

## Files & reading order

**The spine — read in this order.** Six numbered files carry the argument start to finish:

| # | File | Role | Edit cadence |
|---|------|------|--------------|
| — | [`README.md`](README.md) | This orientation + status board. Read first. | When roles/conventions change |
| 01 | [`01-background-research.md`](01-background-research.md) | **INPUT.** The original research note (converted from PDF). Surveys the problem, the ladder, the external landscape, and poses the 8 forks in its §7. *Historical — its 4-rung ladder is superseded by `02`'s *Framing* section (the corrected 5-rung ladder).* | Frozen — historical input |
| 02 | [`02-architecture.md`](02-architecture.md) | **THE PLAN.** The verification architecture; resolves the 8 forks into one design. Owns the **canonical 5-rung ladder** (the *Framing* section) and the **canonical build sequence** (§9). §8 holds the verification-market summary. | Living — folds in resolved questions |
| 03 | [`03-open-questions.md`](03-open-questions.md) | **WORK QUEUE.** The open *design questions* to claim next: S4, S5. Q1–Q8, S1, S2, S6 research-resolved; the 06 §6 market questions are RESOLVED or DEFERRED (not claimable now). | Every session |
| 04 | [`04-decision-log.md`](04-decision-log.md) | **DECISIONS.** Dated ADR-style record — ADR-001…015 (012–015 added during the v1 build), *research-accepted* (see its preamble for what that does/doesn't mean). | When a question resolves |
| 05 | [`05-red-team.md`](05-red-team.md) | **REVIEW.** Adversarial critique threads — of 11: 8 MITIGATED, 1 RESOLVED (RT-006), 2 OPEN (RT-001, RT-005). | When reviewing |
| 06 | [`06-verification-market.md`](06-verification-market.md) | **MARKET DESIGN.** VerificationClaim schema, invariant lifecycle state machine, trust scoring model (incl. the L0–L7 → Rung mapping, §4.3). Three markets: spec, counterexample, proof-strengthening. | Living — market mechanics evolve |

**Inputs & deep-dives — consult as needed.** These are not on the critical reading path;
each feeds a specific part of the spine:

| File | Feeds | Role |
|------|-------|------|
| [`lit/`](lit/RESEARCH.md) | The ADR amendments in `04` | **LITERATURE.** Full adversarial literature inquiry (649 papers, 6 RATIFIED verdicts). Deliverable: [`lit/RESEARCH.md`](lit/RESEARCH.md); audit trail in `lit/00`–`lit/06`. The raw corpus + paper full-text (`lit/data/`) lives in an external store, not the repo (see `lit/RESEARCH.md`). |
| [`nl-to-invariant/`](nl-to-invariant/RESEARCH.md) | **ADR-003** / `06` / `08` §8 | **NL→INVARIANT INQUIRY (2026-06-02).** Adversarial literature inquiry (436 papers, 5 RATIFIED verdicts) on whether English→enforceable-predicate can be made *secure*, and what representation to use. Key results: security comes from the deterministic checker, not the generator, and the checker certifies *form not meaning*; the intent gap is narrowable but not closable (→ off-chain + human/market); NL round-trip is not a faithfulness gate; on-chain, witnesses *refute* while a checked predicate *establishes*. Deliverable: [`nl-to-invariant/RESEARCH.md`](nl-to-invariant/RESEARCH.md); audit trail in `nl-to-invariant/00`–`06`. Raw `data/` gitignored. |
| [`rung3-fuzzing-state-of-art.md`](rung3-fuzzing-state-of-art.md) | Ladder **Rung 3** (`02` *Framing*) | Survey of 13 fuzzing approaches for invariant-aware pre-deploy testing; 6-step Rung 3 pipeline. |
| [`source-wasm-equivalence-gap-practical-assessment.md`](source-wasm-equivalence-gap-practical-assessment.md) | **ADR-006** / `02` §5.2 | Practical assessment of Rust→Wasm proof transfer; 7-tier roadmap with effort estimates. |
| [`spec-intent-conformance-gap.md`](spec-intent-conformance-gap.md) | **ADR-003** / `02` §2 | Approaches to closing the spec↔intent gap; two-tier deploy-time gate recommendation. |
| [`verification-artifact-schema-patterns.md`](verification-artifact-schema-patterns.md) | `06` schema | Mining of 7 systems (Certora, DeepSEA, CompCert, TCT, Move Prover, bug bounty, HACL\*) for artifact-schema patterns. |
| [`07-implementation-plan.md`](07-implementation-plan.md) | All | **IMPLEMENTATION SPEC.** Concrete first-build spec bridging architecture to code: InvariantScope wire format, InvariantResult tri-state, AST→Wasm lowering, `pool_k_non_decreasing` end-to-end, code change plan by file, test plan. *Now built — see `08`.* |
| [`08-implementation-status.md`](08-implementation-status.md) | `07` | **IMPLEMENTATION STATUS (v1, 2026-05-30).** What was actually built vs `07`: ADR→code map, deviations the build surfaced (the latent ABI), gaps closed (fail-closed predicates, consensus-receipt verdicts), test gates, remaining gaps. Read to know the state of the code. |
| — | — | Milestone PDFs are not kept in-repo (markdown is the source of truth); render one with `weasyprint` only to circulate a frozen milestone. |

---

## How to brainstorm here (the workflow)

Work **one open question at a time**. For each:

1. **Claim it.** In [`03-open-questions.md`](03-open-questions.md), set the item's status
   to `IN PROGRESS` and add your handle/agent id so two agents don't duplicate work.
2. **Draft against the plan.** Develop the design with reference to
   [`02-architecture.md`](02-architecture.md) — weigh options, commit to a recommendation,
   ground it in real code (cite `file:line`, e.g. `chain_vm.rs:225`).
3. **Red-team it.** Open or extend a thread in [`05-red-team.md`](05-red-team.md) and try
   to break the design (logic bombs, arbitration gaming, determinism holes). Convergent
   critique beats divergent addition at this stage.
4. **Log the decision.** When it settles, add a dated entry to
   [`04-decision-log.md`](04-decision-log.md) (`PROPOSED` until team-ratified, then
   `ACCEPTED`).
5. **Fold it into the plan.** Update [`02-architecture.md`](02-architecture.md) to reflect
   the resolution, and flip the item to `RESOLVED` in 03.

Prefer **proving the design by building it** over more prose. That move has now been made:
`pool_k_non_decreasing` evaluates for real (the `return 1` stub is gone), end-to-end on wasm —
see [`08-implementation-status.md`](08-implementation-status.md). Real code surfaced flaws no
brainstorm did (e.g. the latent calldata/`petal.return` ABI; see `08` §2).

---

## Conventions

- **Status tags:** `OPEN` · `IN PROGRESS` · `RESOLVED` · `DEFERRED` · (decisions:
  `PROPOSED` → `ACCEPTED` / `SUPERSEDED`). `DEFERRED` has two flavors, used in 06 §6:
  `DEFERRED (calibration)` = the design is settled, only out-of-band constants or a
  governance process remain; `DEFERRED (v1+)` = scoped out of the current version with a
  sketched design. Neither is claimable design work this session.
- **Code anchors:** cite `file:line` so any reader can jump to source. Canonical anchors
  are in `02-architecture.md` → Appendix A.
- **Dates:** absolute (`2026-05-29`), not relative.
- **Source of truth is markdown.** Render a dated milestone PDF with `weasyprint` only to
  circulate a frozen snapshot externally — PDFs are not committed to the repo.
- **Keep links relative** within this folder so the workspace stays portable.

---

## Status board

The eight forks are **research-resolved** (2026-05-29) and the ADRs are
**research-accepted** (ADR-001…011 with literature amendments; ADR-012…015 added during the v1
build — boolean composition, the consensus-receipt verdict, deploy-reject + field-name gates). S1, S2, S6, S7 are now
resolved (ADR-008, ADR-010, ADR-009, ADR-011); S3 was previously resolved per the verification
market design. **S7 (object field-resolution) — the implementation-gating question — is now
RESOLVED:** ADR-011 (ACCEPTED) settles the host-side field-table design and all five sub-questions
S7a–S7e; the offset-gaming surface is tracked as RT-011 and mitigated by the ADR-003 gate. The
first real invariant (`07` §6) is unblocked. **Only S4 and S5 remain OPEN.** See
[`03-open-questions.md`](03-open-questions.md) §S7 for the full analysis. The six market
questions in 06 §6 are
**resolved or deferred**: content-addressing and vacuity resolved; cross-petal claims
deferred to v1+; stake economics, Stage-B quorum, and scoring calibration deferred to
calibration (parameter space documented, constants pending).

> **Implementation status: v1.1 landed (2026-05-30).** The first real invariant,
> `pool_k_non_decreasing`, evaluates end-to-end on wasm, reverts on violation, and records its
> verdict into the consensus receipt. ADR-001/002/004/008/009/010/011 are realized;
> ADR-012/013/014/015 capture decisions made during the build — including **boolean composition**
> (`And`/`Or`/`Not`, ADR-015) and a second invariant on a non-DEX petal (`/bloom/core/cap`).
> Building that second invariant exposed (and fixed) two latent bugs: `remove_liquidity` reverting
> under the object-type firing model, and a `u128`-literal codegen error — see `08` §7.
> ADR-003/005/006/007 (arbitration, semantics oracle, proof ladder, zkVM) are *not* built —
> "research-accepted" there still means design-only. See
> [`08-implementation-status.md`](08-implementation-status.md) for the full
> map and remaining gaps, and [`04-decision-log.md`](04-decision-log.md)'s preamble for what
> `ACCEPTED` does and does not mean.

### The eight forks

| # | Question | Resolved lean (see ADR) | Status |
|---|----------|-------------------------|--------|
| Q1 | Own spec language vs. Rust closures | Restricted AST is canonical, closures lower to it, `Opaque` dev-only, readability necessary but not sufficient (ADR-001) | RESOLVED |
| Q2 | Wasm fn / manifest expr / both + constraints | Both layered; pre-commit view fn returning bool, separate fuel, safety fragment only (ADR-002) | RESOLVED |
| Q3 | Link human text ↔ machine predicate; failed vs. vague | Hashed pair; two-stage arbitration; deploy-time intent-conformance gate required (ADR-003) | RESOLVED |
| Q4 | Reject floats in chain mode | Yes — simplest sufficient means, not necessity (ADR-004) | RESOLVED |
| Q5 | Consensus-pin the Wasm engine | Conformance profile + test suite necessary but not sufficient; verified semantics oracle load-bearing (ADR-005) | RESOLVED |
| Q6 | Smallest proof-carrying interface | Optional, content-addressed, TCB-ranked (PCC > TV > verified compiler), never gating (ADR-006) | RESOLVED |
| Q7 | Source→Wasm equivalence gap | Ranked-by-TCB ladder; no verified Rust→Wasm exists; reproducible builds + diff testing near-term gate (ADR-006) | RESOLVED |
| Q8 | zkVM soundness bar | No single prover; re-execution against independent semantics; RISC-V evidence by analogy; verified-semantics-oracle conjecture (ADR-007) | RESOLVED |

### Finer sub-questions (02 §10)

| # | Sub-question | Status |
|---|--------------|--------|
| S1 | Canonical encoding of `InvariantScope` (reuse borrow-table payload?) | RESOLVED → ADR-008 |
| S2 | Trigger granularity: per-function-exit vs. per-`object.mutate` | RESOLVED → ADR-010 |
| S3 | Invariant versioning / migration across petal versions | RESOLVED |
| S4 | Multi-prover economics (when is 2-prover agreement worth it?) | OPEN |
| S5 | Conformance-suite / fuel-schedule governance | OPEN |
| S6 | `BoundedArith` numeric domain: integer-only vs. + fixed-point | RESOLVED → ADR-009 |
| S7 | Object field-resolution: predicate field-name → payload bytes | RESOLVED → ADR-011 (option b — host-side field table; S7a–S7e settled; offset-gaming = RT-011, mitigated by ADR-003) |

### Literature verdicts (from [`lit/`](lit/RESEARCH.md), 2026-05-29)

The ADRs have been **amended and accepted** incorporating the literature inquiry's 6 RATIFIED verdicts
(649 papers, 19/32 key papers read in full; 6 fetches completed and persisted 2026-05-29 — WasmRef-Isabelle, NPChecker, NeoDiff, CT-wasm, WasmCert-Isabelle, Iris-Wasm). Each amendment is in [`04-decision-log.md`](04-decision-log.md);
the full audit trail is in [`lit/`](lit/RESEARCH.md).

| Fork | Lit verdict | Amendment applied |
|------|-------------|-------------------|
| Q1 | Supported (amended) — substrate yes; "opaque ⇒ unverifiable" refuted; readability insufficient | Keep AST; drop "unarbitrable"; intent gate via ADR-003 |
| Q2 | Supported (amended) — core yes; pre-commit view fn > post-commit; safety fragment only | Pre-commit + revert; scope to safety fragment |
| Q3 | (via Q1) firmest finding: real gap is **spec↔intent conformance** | Added deploy-time intent-conformance gate |
| Q4 | Refuted (necessity); Supported (engineering) | "necessary" → "simplest sufficient means" |
| Q5 | Supported → now **firm** — verified Wasm semantics oracle exists in production (WasmRef-Isabelle, full text fetched) | Verified semantics confirmed as load-bearing; H4 elevated to high confidence |
| Q6/Q7 | Supported — gap real; rank mechanisms by TCB (no verified Rust→Wasm exists). Practical roadmap in [`source-wasm-equivalence-gap-practical-assessment.md`](source-wasm-equivalence-gap-practical-assessment.md). | Ranked-by-TCB ladder; reproducible builds + differential fuzz near-term |
| Q8 | Supported (core); moderate (RISC-V only, no Wasm-zkVM paper) | Independent semantics fallback; oracle conjecture demoted |

---

## Cross-cutting principles (don't relitigate without cause)

Carried from the analysis behind `02`; these frame every fork:

1. **Detection → prevention via pre-commit revert.** Runtime invariants evaluated
   pre-commit and reverting on failure (ADR-002) prevent the spec'd class from
   persisting. But a logic bomb gated on an un-triggered path still evades them —
   prevention of that class comes from Rung 1 (by construction), Rung 3 (pre-deploy
   fuzzing), and Rung 5 (proof).
2. **Determinism is a prerequisite, not a tunable.** Every replay witness is meaningless
   without bit-reproducible execution (→ Q4, Q5).
3. **Arbitration neutrality requires readable predicates.** An opaque predicate fuses
   "predicate failed" and "assertion vague" into one un-adjudicable blob (→ Q1, Q3).
4. **One predicate object, three consumers** — run, fuzz, prove — plus human rendering.
   Protecting that is the spine of the whole architecture.
