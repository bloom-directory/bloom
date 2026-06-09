# A Verification Market for Bloom

**Date:** 2026-05-29  
**Status:** Design research — the verification artifact schema, invariant lifecycle, and trust scoring model. Grounded in the survey at [`verification-artifact-schema-patterns.md`](verification-artifact-schema-patterns.md).  
**Audience:** Bloom engineers implementing the invariant subsystem and the scoring/emissions system.  
**Context:** The teammate conversation surfaced that invariants, proofs, and witnesses should be
**first-class, versioned, independently scored objects** — not one-time badges on a Petal.
This document defines the data model, lifecycle, and scoring for that market.

---

## Contents

1. [The three markets](#1-the-three-markets)
2. [VerificationClaim schema](#2-verificationclaim-schema)
3. [Invariant lifecycle state machine](#3-invariant-lifecycle-state-machine)
4. [Trust scoring model](#4-trust-scoring-model)
5. [Integration with ADRs](#5-integration-with-adrs)
6. [Open questions](#6-open-questions)

---

## 1. The three markets

The teammate framing surfaces three distinct markets, each with its own participants, incentives, and evidence objects:

### 1.1 Spec market — "What should this Petal guarantee?"

**Participants:** Petal authors, domain experts, agents, curators.  
**Object:** A `VerificationClaim` of kind `Invariant` — a machine-evaluable predicate paired with human prose, declaring a behavioral property of the Petal.  
**Judgment criteria:** Clarity, coverage, usefulness, machine evaluability, false-positive rate, survival of adversarial challenge.  
**What's at stake:** Reputation, trust score contribution, proposal stake.

### 1.2 Counterexample market — "Can you break this claim?"

**Participants:** Challengers, fuzzers, symbolic execution tools, agents, auditors.  
**Object:** A `VerificationClaim` of kind `Counterexample` — a concrete replayable witness of invariant violation, or a challenge to the predicate's faithfulness.  
**Judgment criteria:** Is the witness well-formed? Does it reference the correct Petal version and invariant version? Does the predicate evaluate false on the given scope?  
**What's at stake:** Slashing the Petal author (if violation is confirmed) or the challenger (if frivolous). Reputation and LOOM.

### 1.3 Proof-strengthening market — "Can you upgrade this claim's assurance?"

**Participants:** Verification engineers, Kani/Verus/Lean users, tooling vendors.  
**Object:** A `VerificationClaim` of kind `Proof` — a proof artifact (Kani harness, Verus proof, Lean model, zkVM execution proof) that strengthens an existing invariant claim.  
**Judgment criteria:** Does the proof bind to the correct invariant and Petal version? Are its assumptions declared and enforceable? What's its TCB tier (per ADR-006)?  
**What's at stake:** Trust score boost, proof author reward, score discount if later invalidated.

---

## 2. VerificationClaim schema

Mined from 7 existing systems (Certora/CVL, DeepSEA, CompCert, TCT, Move Prover, bug bounty models, HACL\*). See [`verification-artifact-schema-patterns.md`](verification-artifact-schema-patterns.md) for the full survey and rationale.

### 2.1 Core type

```rust
/// A single verification claim — the atomic market object.
/// Content-addressed by claim_id = hash of all fields below.
#[derive(CanonicalEncode, CanonicalDecode)]
pub struct VerificationClaim {
    // ── Identity & anchoring ──
    pub claim_id:     Hash32,              // content-addressed identity (sha256 of canonical encoding)
    pub claim_kind:   ClaimKind,           // what kind of claim this is
    pub claim_version: u32,                // 1-based; incremented when superseded by a new claim
    pub supersedes:   Option<Hash32>,       // claim_id of the prior version (None for v1)
    pub superseded_by: Option<Hash32>,      // claim_id of the replacement (None until superseded)

    // ── Subject — what this claim is about ──
    pub petal_hash:   Hash32,              // exact deployed Wasm artifact
    pub petal_version: u32,                 // the petal's own version number
    pub target:       InvariantTarget,      // ObjectType { name } or FunctionExit { name }
    pub invariant_id: u32,                  // index into the petal manifest's invariant table

    // ── Predicate body (the machine-readable claim) ──
    pub predicate_ast:      PredicateAst,   // the canonical, total, deterministic predicate
    pub predicate_ast_hash: Hash32,         // hash of predicate_ast for content addressing

    // ── Human-readable text (ADR-003 paired binding) ──
    pub human_text:      String,            // author's prose assertion
    pub human_text_hash: Hash32,            // hash of human_text
    pub rendered_text:   String,            // auto-generated canonical English from predicate_ast
    pub rendered_text_hash: Hash32,         // hash of rendered_text

    // ── Scope definition (what state the predicate reads) ──
    pub scope_def: InvariantScopeSpec,      // struct { before, after, args, ret } per §1.4 of 02-arch
    pub wasm_export: String,                // e.g. "__inv_3"
    pub bloom_vm_profile_hash: Hash32,      // conformance profile pin (ADR-005)

    // ── Assumptions (every assumption declared and categorized) ──
    pub assumptions: Vec<ClaimAssumption>,

    // ── Intent-conformance evidence (ADR-003 gate) ──
    pub intent_conformance: IntentConformance, // results of the deploy-time gate
    pub mutation_score:   Option<f64>,         // fraction of mutants the predicate correctly discriminates (from Certora Gambit / Lahiri)

    // ── Spans (explicit temporal scoping) ──
    pub created_at:  Timestamp,             // when this claim was first proposed
    pub valid_from:  BlockNumber,           // first block this claim applies to (may be > created_at)
    pub valid_until: Option<BlockNumber>,   // last block this claim applies to (None = still active)

    // ── Proof artifacts (content-addressed references — not inline) ──
    pub proof_artifacts: Vec<ProofArtifactRef>,  // ADR-006

    // ── Counterexample (if this claim is a counterexample, or a challenge produced one) ──
    pub counterexample: Option<CounterexampleWitness>,

    // ── Lifecycle state ──
    pub status:           ClaimStatus,
    pub vacuity_checked:  bool,             // has a vacuity check been run?
    pub vacuity_result:   VacuityResult,    // result of vacuity check (Certora-style)

    // ── Provenance ──
    pub proposed_by:   Address,             // who proposed this claim
    pub proposed_at:   Timestamp,
    pub toolchain:     Vec<ToolchainEntry>, // full toolchain provenance for reproducibility
    pub challenge_log: Vec<ChallengeRecord>, // history of challenges against this claim

    // ── Scoring ──
    pub strength:        VerificationRung,  // l1..l7 per §4.3 (L→Rung mapping)
    pub scoring_weight:  u32,               // computed trust-score contribution (see §4)
    pub verification_ts: Option<Timestamp>, // when this claim was last independently verified
}


// ── Enums ──

pub enum ClaimKind {
    Invariant,          // "This petal satisfies predicate P"
    Counterexample,     // "Here is a witness where predicate P evaluates false"
    Proof,              // "I have proved (or bounded-checked) that predicate P holds under assumptions A"
    Supersession,       // "Claim X is superseded by claim Y; here's why"
    AmbiguityReport,    // "The human text and machine predicate may not agree; here's evidence"
}

pub enum ClaimStatus {
    Proposed,           // submitted, not yet active
    Active,             // ratified, in force
    Challenged,         // a counterexample challenge is pending
    Broken,             // a valid counterexample was found — invariant violated
    Vindicated,         // a challenge was resolved in favor of the claim (challenger was wrong)
    Ambiguous,          // ADR-003 Stage B: the prose is not faithful to the predicate
    Superseded,         // a newer version of this claim exists
    Deprecated,         // no longer enforced, but kept in history
}

pub struct ClaimAssumption {
    pub statement:    String,                // e.g. "reserve_in > 0"
    pub enforceability: AssumptionEnforceability,
}

pub enum AssumptionEnforceability {
    RuntimeValidated,   // checked during execution (e.g., "fee_bps < 10_000" — explicit guard in code)
    TCBDeclared,        // part of the trusted computing base (e.g., "Wasm engine executes deterministically")
    ExternallyVerified, // checked by a separate tool or human review
}

pub struct IntentConformance {
    pub gate_passed:     bool,               // did the deploy-time gate pass?
    pub tests_generated: u32,                // number of boundary test cases generated
    pub tests_confirmed: u32,                // number confirmed by human review
    pub llm_signal:      Option<LlmConsistencySignal>, // optional LLM consistency check
}

pub struct LlmConsistencySignal {
    pub agrees: bool,                        // LLM thinks spec matches prose
    pub counterexample: Option<String>,      // LLM-generated counterexample if disagrees
    pub model: String,                       // which LLM was queried
    // Note: this is a signal only, not a gate (Verus-SpecGym: LLM judges miss 26%)
}

pub struct CounterexampleWitness {
    pub witness_hash:   Hash32,              // content-addressed witness blob
    pub petal_hash:     Hash32,              // which petal version was tested
    pub input:          Vec<u8>,             // the specific scope bytes / args that triggered the violation
    pub predicate_result: bool,              // false = violated
    pub block_height:   u64,                 // state root the witness was produced against
    pub captured_by:    CounterexampleSource, // how this counterexample was found
}

pub enum CounterexampleSource {
    Manual,                                  // human-constructed
    FuzzCampaign { seeds: u64, iterations: u64 },  // fuzzer found it
    KaniCounterexample,                      // Kani SAT result
    SymbolicExecution,                       // SMT/symbex derived
    ProductionWitness,                       // caught by runtime invariant evaluation
}

pub struct ProofArtifactRef {
    pub prover_id:    String,                // "kani" | "verus" | "creusot" | "lean" | …
    pub prover_version: String,
    pub artifact_hash: Hash32,               // content-address of the proof blob under /bloom/proofs/
    pub tcb_tier:     TcbTier,               // ADR-006 ranked tier
    pub verified_at:  Timestamp,
}

pub enum TcbTier {
    Pcc,                 // proof-carrying certificate — compiler untrusted, TCB = small checker
    TranslationValidation, // differential testing or per-run validation
    TrustedCompiler,     // reproducible builds + attestation; compiler in TCB
}

pub struct ChallengeRecord {
    pub challenge_id:   Hash32,
    pub challenged_by:  Address,
    pub challenged_at:  Timestamp,
    pub witness:        CounterexampleWitness,
    pub resolution:     ChallengeResolution,
}

pub enum ChallengeResolution {
    Pending,
    ViolationConfirmed,     // Stage A: predicate was objectively violated → petal author slashed
    Dismissed,              // Stage A: replay showed no violation → challenger slashed
    Ambiguous,              // Stage B: prose not faithful to predicate → invariant deprecated, no slash
    Withdrawn,              // challenger withdrew before adjudication
}

pub enum InvariantScopeSpec {
    ObjectType { before: bool, after: bool },
    FunctionExit { args_positions: Vec<u32> },
}

pub enum VerificationRung {
    L0 = 0,  // informal review
    L1 = 1,  // executable runtime invariant
    L2 = 2,  // counterexample witness
    L3 = 3,  // fuzz/property corpus
    L4 = 4,  // Kani bounded proof
    L5 = 5,  // Verus/Creusot/Prusti deductive proof
    L6 = 6,  // Lean/Coq model
    L7 = 7,  // Wasm/zkVM semantic proof
}

pub enum VacuityResult {
    NotChecked,
    Vacuous,             // predicate is trivially true (e.g., always satisfied)
    NonVacuous,          // predicate has discriminative power
    Inconclusive,        // check couldn't determine
}

pub struct ToolchainEntry {
    pub tool_name:      String,
    pub tool_version:   String,
    pub tool_build_hash: Option<Hash32>,
}
```

### 2.2 Key design properties

**The three-anchor pattern** (from CompCert, TCT, and DeepSEA). Every claim independently binds three hashes:

```
petal_hash (subject) → predicate_ast_hash (claim body) → proof_artifact_hash (evidence)
```

No claim can be retrofitted to a different deployment (petal_hash mismatch), misrepresented as a different claim (predicate_ast_hash mismatch), or backed by a different proof (artifact_hash mismatch). This is the chain that makes claims non-repudiable.

**Assumptions are first-class** (from the ambient-assumptions gap across all surveyed systems). Every `ClaimAssumption` has an `AssumptionEnforceability` tag. Assumptions classified as `TCBDeclared` are explicitly named as part of the trusted base — they are not hidden in tool defaults. Assumptions classified as `RuntimeValidated` are checked during execution (e.g., `fee_bps < MAX_FEE_BPS` is already a guard in the DEX math).

**Vacuity is a first-class quality signal** (from Certora). A predicate that is trivially true ("always satisfied") is treated as `Vacuous` and carries no trust-score weight. The `mutation_score` field (from Certora Gambit + Lahiri FMCAD 2024) provides a continuous quality metric: the fraction of predicate mutants that produce different results.

**Supersession is explicit** (Bloom innovation — no surveyed system has it). `supersedes` and `superseded_by` chain claim versions. When `Claim v2` supersedes `Claim v1`, v1 is marked `Superseded` and v2 carries the forward link. This supports the "constant curation" workflow: invariants evolve as gaps are found, and the version chain is auditable.

**Migration from current code is additive.** The current `InvariantDecl` (`types.rs:173`) has fields `{name, target, predicate, wasm_export}`. Every field maps directly into `VerificationClaim`. The new fields (lifecycle, assumptions, scoring, intent-conformance, proof references) default to `None` / `Active` / `[]` / `1` as appropriate.

---

## 3. Invariant lifecycle state machine

```
                    ┌──────────┐
                    │ Proposed │◀──────────────────────────── author submits
                    └────┬─────┘
                         │ ratified (intent-conformance gate passes)
                         ▼
                    ┌──────────┐
          ┌────────▶│  Active  │◀─────── challenge dismissed (challenger slashed)
          │         └────┬─────┘
          │              │
          │    ┌─────────┼─────────┐
          │    │         │         │
          │    ▼         ▼         ▼
          │ ┌───────┐ ┌───────┐ ┌──────────┐
          │ │Broken │ │Ambigu-│ │Superseded│
          │ │       │ │ous    │ │          │
          │ └───┬───┘ └───┬───┘ └────┬─────┘
          │     │         │          │
          │     │         │          │ author proposes v2 (stronger / fixed)
          │     │         │          │
          │     │         ▼          │
          │     │    ┌──────────┐    │
          │     │    │Deprecated│◀───┘
          │     │    └──────────┘
          │     │
          │     └─── (new invariant on fixed petal supersedes broken one) ──┘
          │
          └─────── challenge defeated (predicate held; challenger wrong) ──▶ Vindicated
```

### 3.1 Transition rules

| Transition | Trigger | Who pays | Evidence required | Effect on score |
|------------|---------|----------|-------------------|-----------------|
| Proposed → Active | Intent-conformance gate passes + ratification | Author stakes bond | Gate report + mutation score ≥ threshold | Score begins accruing |
| Active → Challenged | Challenger submits `Counterexample` claim | Challenger stakes bond | Valid `CounterexampleWitness` referencing this claim | Score frozen during dispute |
| Challenged → Broken | Stage A replay confirms violation | Author slashed | Objective replay verdict | Claim score → 0; Petal score reduced |
| Challenged → Vindicated | Stage A replay shows no violation | Challenger slashed | Objective replay verdict showing predicate evaluated true | Score restored + claim age bonus |
| Challenged → Ambiguous | Stage B: prose not faithful to predicate | No slash (deprecation only) | Stage B vote or arbitration finding | Claim deprecated; score removed |
| Active → Superseded | Author proposes v2 of the same invariant | Author stakes upgrade bond | v2 claim with `supersedes = v1.claim_id` | v1 score frozen; v2 enters Proposed |
| Superseded → Deprecated | Governance confirms v2 is settled | None | v2 at least Active | Score removed from active pool |
| Ambiguous → Deprecated | Governance confirms prose/predicate gap | None | Stage B resolution recorded | Score removed |

### 3.2 Key invariants of the lifecycle

1. **At most one version of a claim is `Active` at a time.** When v2 reaches `Active`, v1 must be `Superseded`.
2. **A `Broken` claim can never become `Active` again.** The only path out of `Broken` is via a new version that supersedes it (and that new version anchors to the *fixed* petal, not the broken one).
3. **`Deprecated` is terminal.** No transition out of `Deprecated`.
4. **`Vindicated` is transient.** A vindicated claim returns to `Active` — vindication is a resolution of a specific challenge, not a permanent state.
5. **Challenge bonds are slashed asymmetrically.** A successful challenge slashes the author. A frivolous challenge slashes the challenger. An ambiguous result (Stage B) slashes neither — this is the "no punishment for vagueness" principle from ADR-003.

---

## 4. Trust scoring model

### 4.1 Design principles

1. **Trust is relative, not binary.** No Petal is "safe" or "unsafe." Trust is a continuous score composed from verifiable signals.
2. **Claims age into trust.** A claim that has survived for N blocks without being broken earns more trust than a fresh claim.
3. **Proof strength multiplies trust, but doesn't replace it.** A Lean proof on a vacuous predicate earns zero. A weak runtime invariant that has survived many challenges earns positive score.
4. **Lost challenges deduct hard.** A broken invariant is worse than no invariant — it signals false confidence.
5. **Diverse verifiers count more than one prolific verifier.** A Kani proof from AWS + a Verus proof from an independent auditor earn more than two proofs from the same author.

### 4.2 Scoring formula (initial sketch)

```
petal_trust_score = Σ claim_score(c) for all active claims c on this petal version

claim_score(c) =
    base_weight(c.strength)        // rung-based: L1=1, L2=2, ..., L7=12
  × (1.0 - vacuity_penalty(c))     // 1.0 if non-vacuous, 0.0 if vacuous
  × age_bonus(c)                   // min(2.0, 1.0 + 0.1 × years_survived)
  × mutation_quality(c)            // max(0.1, mutation_score) — a weak predicate earns ≤ full weight
  × assumption_discount(c)         // 1.0 if all assumptions RuntimeValidated; 0.7 if TCBDeclared; 0.5 if any unchecked
  × diversity_bonus(c)             // 1.0 + 0.3 × (num_distinct_verifiers - 1)
  − challenge_penalty(c)           // broken → −base_weight; challenged+pending → −0.5×base_weight
```

### 4.3 Score categories

> **L-levels vs. the canonical ladder.** The `L0…L7` scale here is a *finer-grained
> assurance scale* for trust scoring — it subdivides the **5-rung canonical ladder**
> ([`02-architecture.md`](02-architecture.md) §2), it is not a competing numbering. The
> mapping:
>
> | L-level | base_weight | Canonical rung ([`02`](02-architecture.md) §2) | Meaning |
> |---------|------------:|------------------------------------------------|---------|
> | L0 | baseline | Rung 1 — VM-enforced protocol invariants | Automatic; every petal earns it |
> | L1–L2 | 1–2 | Rung 2 — runtime invariants | Fresh → battle-tested runtime predicate |
> | L3 | 3 | Rung 3 — pre-deploy adversarial testing | Fuzz/mutation-tested predicate |
> | L4–L5 | 6–8 | Rung 5 — external formal proof (bounded) | Kani / bounded model checking, translation-validated |
> | L6–L7 | 12 | Rung 5 — external formal proof (unbounded / transferred) | Verus/Lean; L7 = provenance reaches the deployed Wasm (PCC tier) |
>
> Rung 4 (the canonical replay witness) is the *evidence layer* that makes any claim
> arbitrable — it is not itself a trust tier, so it has no L-level.

| Term | Meaning | Range |
|------|---------|-------|
| `base_weight` | Rung multiplier: L1=1 (runtime invariant), L4=6 (Kani), L6=12 (Lean) | 0–12 |
| `vacuity_penalty` | 1.0 if predicate is `Vacuous` (score → 0); 0.0 if `NonVacuous` | 0–1 |
| `age_bonus` | Claims that survive earn more trust; caps at 2× after 10 years | 1.0–2.0 |
| `mutation_quality` | From `mutation_score` — fraction of predicate mutants that behave differently. Weak predicates (<0.3) earn only 0.1× weight. | 0.0–1.0 |
| `assumption_discount` | Runtime-validated assumptions = 1.0; TCB-declared = 0.7; unchecked = 0.5 | 0.5–1.0 |
| `diversity_bonus` | Each additional independent verifier adds 30% (first author = 1.0, second = 1.3, third = 1.6) | 1.0–2.5 |
| `challenge_penalty` | Broken claim costs all its score; challenged (pending) costs 50% | 0–base_weight |

### 4.4 Scoring interaction with emissions

The petal trust score feeds Bloom's existing scoring/emissions system per the whitepaper. Concretely:

- A petal with **no invariants** earns the baseline score from Rung-1 protocol invariants (import/export/memory admission, borrow table linearity, view purity) — all automatic, all unconditional.
- A petal with **active runtime invariants** earns L1…L2 score per claim.
- A petal with **Kani-proofed kernels** adds L4 score on those specific claims.
- A petal with **broken invariants** loses score — a broken claim is *worse* than no claim.

This creates the economic incentive for the three markets: authors want high scores (emissions), challengers want to find broken claims (slashing reward), and provers want to attach stronger artifacts (score boost).

### 4.5 What this model deliberately avoids

- **No "percentage safe" claims.** The score is additive, not normalizable to [0,1]. An infinite number of claims would produce an infinite score — in practice, gas/state limits bound the number of claims per petal.
- **No absolute ranking of petals.** Scores are comparable within a petal across versions, not between different petals. A DEX pool invariant and a social graph invariant answer different questions.
- **No on-chain SMT solving.** Vacuity and mutation scores are computed off-chain and submitted as `VerificationClaim` fields. The chain verifies the claim is well-formed and content-addressed; it does not re-run the SMT solver.

---

## 5. Integration with ADRs

| ADR | How the verification market relates |
|-----|-------------------------------------|
| ADR-001 (predicate AST) | `VerificationClaim.predicate_ast` carries the canonical AST. `ClaimKind::Invariant` and `ClaimKind::Counterexample` both reference it. |
| ADR-002 (pre-commit view fn) | `VerificationClaim.assumptions[]` with `RuntimeValidated` enforces that runtime-checkable assumptions are actually checked. `ClaimStatus::Broken` is the outcome when a pre-commit check fails. |
| ADR-003 (two-stage arbitration) | `ClaimStatus::Challenged → Broken` is Stage A (objective replay). `Challenged → Ambiguous` is Stage B (prose vs. predicate). `IntentConformance` records the deploy-time gate. |
| ADR-004 (integer-only) | `VerificationClaim.bloom_vm_profile_hash` pins the integer-only profile. A claim is only valid against the profile it was authored for. |
| ADR-005 (verified semantics oracle) | `VerificationClaim.bloom_vm_profile_hash` + `assumptions[]` with `TCBDeclared` for the verified-semantics dependency. |
| ADR-006 (TCB-ranked proofs) | `ProofArtifactRef.tcb_tier` carries the PCC/TV/trusted-compiler ranking. `proof_artifacts[]` is a content-addressed reference list, per ADR-006. |
| ADR-007 (zkVM fallback) | zkVM execution proofs are `ProofArtifactRef` of `TcbTier::Pcc` (if the zkVM has a verified semantics) or `TcbTier::TrustedCompiler` (if not). The verified-semantics-as-zkVM-oracle conjecture is tracked as an assumption, not a claim. |

---

## 6. Open questions

These are the design issues the market model surfaces. The numbers `#1…#6` are **stable
question IDs** (cross-referenced from §6.1, the README status board, and `03`); items appear
under their status bucket, not in numeric order. The split is **two RESOLVED (#3, #5) ·
three DEFERRED (calibration) — design-closed, constants/process pending (#1, #2, #6) ·
one DEFERRED (v1+) — scoped out of v0 (#4)**. Status vocabulary is defined in
[`README.md`](README.md) → Conventions.

**RESOLVED — design complete for v0:**

3. **Content-addressing scheme → RESOLVED.** Option (a): hash the **immutable identity subset** of `VerificationClaim`. The identity fields are: `petal_hash`, `petal_version`, `predicate_ast_hash`, `scope_def`, `bloom_vm_profile_hash`, `wasm_export`. Excluded from the hash: `claim_id` itself (circular), `superseded_by` (forward reference), all timestamps (`created_at`, `valid_from`, `valid_until`, `proposed_at`, `verified_at`), `scoring_weight` (recomputed on re-score), `status` (lifecycle-mutable), `challenge_log` (append-only), `proof_artifacts[]` (proofs have their own content addresses), `vacuity_*` and `mutation_score` (quality signals that may change on re-audit). This follows the existing canonical-encoding discipline (`Object::encode_canonical` at `object.rs:113`): encode the identity subset with fixed field order, length-prefixed framing, sha256 the result. The `claim_id` is stable across re-scoring, supersession, and challenge — exactly what content-addressed identity should mean.

5. **Vacuity check mechanism → RESOLVED.** Option (c): both deploy-time gate AND after-the-fact audit.
   - **Deploy-time gate (Tier 1a):** boundary test-vector generation surfaces predicates with zero reachable `false` outputs as likely vacuous. Cheap, runs as part of ADR-003's intent-conformance gate (`spec-intent-conformance-gap.md` §"Recommendation").
   - **After-the-fact audit:** a challenger can run a vacuity check for a bounty. If the predicate is found vacuous, the claim is marked `status = Deprecated`, the author's bond is not slashed (vacuity is specification weakness, not fraud), and the challenger earns the bounty. This creates an economic incentive to find vacuous claims without punishing authors for specification difficulty.
   - **Who pays:** deploy gate cost is covered by the deploy bond. Audit bounty is paid from protocol treasury or a vacuity challenge pool.

**DEFERRED (calibration) — design-closed; constants or governance process await external input:**

1. **Stake economics → DEFERRED (calibration).** Stake sizing, challenger bond ratio, and Ambiguous-outcome refund policy are economic dials. The parameter space is: author bond as a fraction of the claim's expected scoring contribution; challenger bond as a multiple of author bond (or as a flat minimum); Ambiguous outcomes refund both parties' bonds (since neither is at fault — the spec is vague, not violated). Concrete values are downstream of the Kani pilot and first runtime invariants — the formula shape is specified, the constants are not. **Status: parameter space documented; constants deferred to calibration.**

2. **Quorum for Stage B → DEFERRED (calibration, governance track).** ADR-003's Stage B (prose faithfulness) is social/voted. The option space is council (appointed experts), open vote (token-weighted), or liquid democracy. This is a governance design question, not a verification design question — the verification market schema only needs to know that a `ChallengeResolution::Ambiguous` outcome exists and records the resolution, not how the resolution was reached. **Status: verification-design settled; the quorum mechanism is a separate governance track. The schema carries `ChallengeRecord.resolution` with a `ChallengeResolution` enum that includes `Ambiguous`.**

6. **Scoring weights calibration → DEFERRED (calibration).** The formula in §4.2 is a sketch. The multipliers (1.0 for L1, 6.0 for L4, 12.0 for L6) need calibration against real petals. The Kani pilot on `bloom-dex-math` and the first runtime invariant (`pool_k_non_decreasing`) are the first calibration points. Until then, the formula shape is specified; the constants are TBD. **Status: formula shape fixed; constants require real data from implementation.**

**DEFERRED (v1+) — scoped out of the current version:**

4. **Cross-petal claims → DEFERRED (v1+).** Option (b) for v0: forbid cross-petal claims and require each petal to state its invariants locally. Option (a) — `foreign_petal_ref { petal_hash, invariant_id }` validated against the claimant's `dep_lock` — is the v1+ design but adds version-skew failure modes. Cross-petal claims like `AllPoolsKNonDecreasing` are router-over-pool; the first invariant (`pool_k_non_decreasing` at [`07-implementation-plan.md`](07-implementation-plan.md) §6) is self-contained on the pool petal. No cross-petal support is needed for v0.

---

### 6.1 Option-spaces — the rationale behind §6's statuses (2026-05-29)

§6 is the status table; this section records *why* each question landed where it did. The bucket
labels match §6 exactly.

**RESOLVED — #3 (content-addressing).** Hash the **immutable identity subset** per §6 above:
`canonical_encode(petal_hash ‖ petal_version ‖ predicate_ast_hash ‖ scope_def ‖
bloom_vm_profile_hash ‖ wasm_export) → sha256 → claim_id`. Excluded fields: `claim_id`,
`superseded_by`, all timestamps, `scoring_weight`, `status`, `challenge_log`,
`proof_artifacts[]`, `vacuity_*`, `mutation_score`. This follows the existing
`Object::encode_canonical` discipline and keeps `claim_id` stable across re-scoring,
supersession, and re-audit.

**RESOLVED — #5 (vacuity).** Option (c): deploy gate + audit bounty. Deploy-time gate
(boundary test-vector generation) catches trivially-true predicates. After-the-fact audit with
bounty lets challengers earn by finding vacuous claims. No author slash for vacuity.

**DEFERRED (calibration) — #1/#2/#6 (economics/governance).** Stake sizing, Stage-B quorum,
and weight calibration are governance/economic dials. The verification-design is settled; the
parameter space is documented and the constants are downstream of the first runtime invariants
and the Kani pilot (build steps in [`02`](02-architecture.md) §9 and
[`07-implementation-plan.md`](07-implementation-plan.md)).

**DEFERRED (v1+) — #4 (cross-petal claims).** Option (b) for v0: each petal states invariants
locally. The first invariant (`pool_k_non_decreasing`) is self-contained. Option (a) —
`foreign_petal_ref { petal_hash, invariant_id }` — is designed but gated on `dep_lock` resolution
and version-skew handling.

---

## References

- [`verification-artifact-schema-patterns.md`](verification-artifact-schema-patterns.md) — survey of 7 existing systems
- [`04-decision-log.md`](04-decision-log.md) — ADR-001 through ADR-010
- [`02-architecture.md`](02-architecture.md) — the accepted verification architecture
- [`lit/RESEARCH.md`](lit/RESEARCH.md) — full literature inquiry (649 papers)
