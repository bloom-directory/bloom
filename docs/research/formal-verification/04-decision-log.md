# Decision Log

Dated, ADR-style record of resolved design forks. Each entry is `PROPOSED` until the team
ratifies it, then `ACCEPTED` (or `SUPERSEDED` by a later entry). Newest first.

**What `ACCEPTED` means here — read this first.** These ADRs are marked `ACCEPTED` in the
sense of **research-accepted**: the design argument *converged within this workspace* on
2026-05-29 (after the [`lit/`](lit/RESEARCH.md) inquiry), and the recommendations argued in
[`02-architecture.md`](02-architecture.md) are stable enough to build against. That is **not**
the same as:

- **Team-ratified** — no maintainer sign-off has been recorded; treat these as the research's
  recommendation to the team, not a binding mandate.
- **Implemented** — *partially, as of 2026-05-30.* The v1 runtime now exists:
  `emit_invariant_shim` evaluates a real predicate (no longer a `return 1` stub),
  `pool_k_non_decreasing` fires end-to-end on real wasm, reverts on violation, and its
  tri-state verdict is recorded into the consensus receipt. ADR-001/002/004/008/009/010/011
  are realized in v1; ADR-003/005/006/007 (arbitration, semantics oracle, proof ladder,
  zkVM) are not. See [`08-implementation-status.md`](08-implementation-status.md) for the
  full map of ADR → code, the deviations the build surfaced, and the remaining gaps.

So "ACCEPTED" = "the research settled here," not "the project committed here." A later entry
may `SUPERSEDE` an earlier one; nothing here constrains the eventual implementation beyond
being its best-argued starting point.

Template:
```
## ADR-NNN — <title> · <PROPOSED|ACCEPTED|SUPERSEDED> · <date>
**Question:** <which fork (Q#/S#)>
**Context:** <forces in play>
**Decision:** <what we chose>
**Rationale:** <why; alternatives rejected>
**Consequences:** <what this commits us to>
**Anchors:** <file:line>
```

---

## ADR-001 — The predicate is a readable AST; opaque closures are quarantined · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-001`](lit/05-verdict-log.md) (RATIFIED, high).*
**Question:** Q1 (and feeds Q3).
**Context:** A predicate must be run, fuzzed, proved, *and* read by arbitration. A
closure-compiled-to-Wasm satisfies the first three but is opaque to governance.
**Decision:** A restricted, total `PredicateAst` is the canonical arbitration-citable
form — not because opaque closures cannot be machine-checked (Verus/Prusti disprove
this, [`lit/V-001`](lit/05-verdict-log.md)), but because a transparent, renderable AST is the
right substrate for **cheap, neutral auditability by governance**. Rust closures are a
frontend that must lower to the AST or be rejected. `PredicateAst::Opaque` is permitted
only in local/dev mode and is never admissible in chain mode nor citable in a slashing
challenge.
**Rationale:** Every production verifier in the corpus that targets audit/review adopts a
restricted declarative spec language (Move Prover, VerX, 2Vyper — all *full text*). The
prior claim that "opaque closures cannot be machine-checked" is false — Prusti encodes
closures into first-order logic via SMT (*abstract*), and Verus does likewise
(*abstract*) — but machine-verifiability is distinct from governance-auditability. The
firmer finding is that even a total, transparent, machine-checked predicate routinely
fails to capture author intent: Verus-SpecGym (*full text*) reports the best model writes
faithful specs only 77.8% of the time and an LLM judge reading the spec misses 26% of
faithfulness failures; PropertyGPT (*full text*, 42 cites) and "Evaluating LLM-driven
User-Intent Formalization" (*full text*) concur. Readability is therefore **necessary but
not sufficient** for sound arbitration — the firmest result of the entire literature
inquiry.
**Consequences:** Grow `PredicateAst` (`Conserves`, `MonotoneAcross`, `BoundedArith`,
boolean combinators); `validate_chain_wasm` must reject chain-mode `Opaque` invariants.
ADR-003 must add an independent intent-conformance gate (spec test-vectors / adversarial
counterexample review) — auto-rendered English alone is insufficient.
**Anchors:** `bloom-petal-manifest/src/types.rs:203`, `bloom-resource-macros/src/invariant.rs:128`.

## ADR-002 — An invariant predicate is a pre-commit view function returning bool; safety fragment only · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-002`](lit/05-verdict-log.md) (RATIFIED, high).*
**Question:** Q2.
**Context:** Predicate evaluation must not mutate, diverge, or hang, and must agree across
the AST interpreter and the compiled `__inv` export. Additionally, a post-commit check only
detects violations — it cannot prevent logic bombs gated on un-triggered paths.
**Decision:** Reuse the four-layer view-purity machinery: no object-mutating imports, scope
forced `ReadOnly`, statically-bounded calls, a *separate* invariant-fuel budget, totality.
The only legal trap is out-of-fuel, which yields `indeterminate` (never `failed`). Results
are recorded in the receipt even on success. **Invariants are evaluated pre-commit and
revert the transaction on failure**, per Theorem-Carrying Transactions (arXiv:2408.06478,
*full text*), which demonstrates that a transaction-scoped check evaluated before commit
genuinely *prevents* the bad state. A stateless view function covers only the **safety
fragment** — liveness and multi-block temporal properties are out of scope (RV survey
2019, *abstract*) and require a stateful monitor if needed.
**Rationale:** The view verifier is the strongest existing machine-checkable property; an
invariant is structurally a view returning bool. The prior framing of runtime invariants
as "detection only" is refined: a pre-commit revert turns detection into prevention for
the claimed class. The detection≠prevention principle remains valid for logic bombs on
un-triggered paths — those require Rung 3 (fuzzing) or Rung 5 (proof). VerX and Move
Prover (*full text*) confirm that prevention needs quantification over unexecuted states.
**Consequences:** Replace the `return 1` stub with an AST→Wasm lowering; add an
AST-interpreter-vs-`__inv` differential test as a standing gate. Scope the invariant
guarantee explicitly to the safety fragment. The "canonical fuel schedule" now has its first
concrete (hand-picked, provisional) entries from the invariant subsystem —
`INV_FUEL_PER_EVAL`, `MAX_INVARIANT_PREDICATE_FUEL`, `MAX_PREDICATE_DEPTH` — which belong in
this profile; the process for revising them is open question **S5** (not decided here).
**Anchors:** `bloom-petals/src/chain_vm.rs` (`validate_view_functions_are_pure`),
`bloom-resource-macros/src/codegen.rs:787`.

## ADR-003 — Two-stage arbitration with intent-conformance gate; only objective replay can slash · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-001`](lit/05-verdict-log.md) Reading B (RATIFIED, high — best-evidenced result).*
**Question:** Q3.
**Context:** The whitepaper needs "broken" to be a replayable fact, and to separate a
failed predicate from a vague assertion. The deeper risk — the best-evidenced finding of
the literature inquiry — is that even a total, transparent, machine-checked predicate
routinely fails to capture what the author *meant* (PropertyGPT, 42 cites; Verus-SpecGym;
Evaluating LLM-driven User-Intent Formalization — all *full text*). Auto-rendering the AST
to English shrinks but does not close this gap.
**Decision:** Bind `{human_text, predicate_ast}` as a hashed pair in `InvariantDecl`.
Stage A (objective replay) is the only edge that slashes. Stage B (social: is the prose
faithful to the predicate?) can only deprecate/replace the invariant. Auto-render the AST
to canonical English; pin `(petal_version, invariant_version)` in the witness. **At deploy
time, an independent intent-conformance gate must pass:** adversarial counterexample review
and/or a spec test-vector suite that probes whether the predicate encodes the property the
human assertion describes. This gate is machine-assisted, not purely social — it is the
load-bearing mechanism that Stage B's auto-rendered English alone cannot be.
**Rationale:** Keeps slashing mechanical and neutral; routes vagueness to a non-punitive
path; prevents version equivocation. The deploy-time intent-conformance gate addresses the
firmest negative finding of the literature inquiry: neither executable semantics nor
readable ASTs close the spec↔intent gap, and Stage B's social arbitration over rendered
prose inherits that gap. A machine-assisted conformance check at the boundary (before the
predicate ever fires in production) is the cheapest point to catch it.
**Consequences:** Extend `InvariantDecl` with `human_text` + `text_hash`; build the
auto-renderer; design the intent-conformance gate (spec test-vectors + adversarial
counterexample review); define the witness fields Stage A consumes (see `02` §4).
**v1 substrate landed (2026-05-31):** `InvariantDecl.human_text` (+ the `#[invariant(text =
"…")]` key), the AST→English renderer (`render_predicate_english`), and the
fully-automatable half of the deploy gate — a **vacuity/tautology check**
(`predicate_triviality` in `validate_chain_wasm`) that rejects statically always-true/false
predicates. **Still deferred** (need the trust layer / external review): the intent-*faithfulness*
check (LLM-assisted / adversarial-counterexample / spec test-vectors), `text_hash` + witness
fields, and the Stage-B social deprecate path.

**Amended 2026-06-02 per [`nl-to-invariant/`](nl-to-invariant/RESEARCH.md) (5 RATIFIED
verdicts).** A second adversarial inquiry — on whether English→predicate can be made
*secure* — sharpens the deferred gate's design and confirms the deny-LLM-in-consensus
instinct:
- **The faithfulness gate must be off-chain.** A deterministic checker certifies *form,
  not meaning* (V-001/V-004): every reliable mechanism reduces to checking a fixed
  syntactic object (the *type*), but intent is a *token*-level relation in a human's head
  that no syntactic check reaches. The gap is **narrowable** by deterministic proxies
  (vacuity ✓, mutation score, ensemble/cross-model consistency, spec test-vectors) but
  **not fully closable**; the residual is irreducibly human/market. So the
  intent-faithfulness gate is an *off-chain authoring/market aid*, never a consensus gate —
  an LLM judge cannot be deterministic across validators.
- **The AST→English renderer is a legibility aid, not a faithfulness gate** (V-003): NL
  round-trip / back-translation is self-consistency, not faithfulness; the reliable oracle
  is a *formal* check, not NL paraphrase. Keep `human_text`/`render_predicate_english`
  inert to enforcement (as built).
- **`text_hash` is the one piece that is both deterministic and consensus-safe** — pin the
  human claim to the predicate version; defer the LLM/adversarial parts to the off-chain
  market.
- **Witnesses refute; checked predicates establish** (V-005): the deferred Stage-A
  counterexample path is best realized as an off-chain LLM-proposed violating transaction
  that the chain's deterministic re-execution validates — it can *refute* an invariant but
  cannot *establish* a universal safety property, which remains the job of the per-transition
  checked predicate (the v1 design). See `06` §6 and `08` §8.

## ADR-004 — Integer-only chain mode (simplest sufficient means) · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-003`](lit/05-verdict-log.md) (RATIFIED — necessity refuted; engineering supported, moderate).*
**Question:** Q4.
**Context:** NaN canonicalization is on, but float→int, FMA, and SIMD float lanes remain
divergence-prone; SMT float theory is weak. However, deterministic float subsets exist
(CT-wasm, reproducible-FP work — *abstract*) and canonical chain-nondeterminism bugs trace
to scheduling and read-write hazards, not floats. Exclusion is the simplest sufficient
means, not a logical necessity.
**Decision:** Reject floats in chain mode as the **simplest sufficient means** to ensure
determinism and provability. Provide a fixed-point helper library for the few cases authors
reach for floats. A canonicalized deterministic float subset is achievable at materially
higher verification cost but is not the near-term path.
**Rationale:** Integer-only execution dramatically eases both determinism and provability
(Move Prover, *full text*). `bloom-dex-math` demonstrates the ecosystem needs no floats.
The prior claim that floats *must* be excluded for determinism does not survive the
literature — deterministic/reproducible float execution is demonstrably achievable — but
the engineering case (simplest sufficient means, lowest verification burden) is sound.
Float exclusion should not be presented as closing the determinism hole; the conformance
gap (ADR-005) and scope encoding (S1) are the real determinism risks.
**Consequences:** Add float-opcode rejection to `validate_chain_wasm` (mirror the
tail-call rejection); build fixed-point helpers.
**Anchors:** `bloom-petals/src/chain_vm.rs:225`.

## ADR-005 — Pin a conformance profile, backed by a verified semantics oracle · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-004`](lit/05-verdict-log.md) (RATIFIED, Supported (amended), moderate).*
**Question:** Q5.
**Context:** Two honest nodes must not diverge, but pinning an exact engine build blocks
security patches. A test-vector suite alone is a finite sample of an infinite input space
— Wasm SpecTec (*full text*) ships 23,778 vectors with SIMD excluded and only claims to
"reduce the risk" of divergence. The industry's own move deploys a *verified* interpreter
(WasmRef-Isabelle, *abstract — fetch failed*) as a differential fuzzing oracle in Wasmtime
CI precisely because conformant engines diverge until caught.
**Decision:** Pin a versioned conformance *profile* — feature set, canonical fuel schedule,
disabled nondeterministic features — enforced by a test-vector suite an engine build must
pass to be consensus-eligible. The profile is **necessary but not sufficient**. Cross-node
determinism binds on a pinned **verified executable Wasm semantics** (WasmCert/WasmRef)
used as the differential oracle, with the test suite as a fast pre-filter. The verified
semantics is elevated from "long-term" to load-bearing.
**Rationale:** Decouples "identical results" from "identical binary" for security patches.
The verified-oracle requirement follows directly from the evidence: conformant engines
diverge on untested inputs, and a finite suite cannot cover an infinite space. WasmCert
(*abstract — fetch failed*) and WasmRef-Isabelle (*abstract — fetch failed*) mechanize Wasm
semantics; the corpus confirms the oracle is feasible but does not yet validate its
deployment as a consensus mechanism for Bloom's exact setting — the load-bearing claim is
a reasoned recommendation, not a corpus-proven result. Re-fetching WasmRef-Isabelle full
text is the highest-value gap.
**Consequences:** Author the profile + suite; define a governance process for revising it
(S5); establish the verified-semantics oracle as a first-class dependency of the
determinism guarantee; surface the WasmRef-fetch gap explicitly.

## ADR-006 — Proofs are optional, content-addressed, provenance-gated, TCB-ranked · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-005`](lit/05-verdict-log.md) (RATIFIED, Supported, high).*
**Question:** Q6 + Q7.
**Context:** Proofs should boost trust without taxing ordinary authors, and a proof about
source must not be mistaken for a proof about the deployed Wasm. The three transfer
mechanisms — proof-carrying code (PCC), translation validation (TV), and
whole-compiler proof — differ systematically in trusted computing base size, and the
corpus supports ranking by TCB. No verified Rust→Wasm compiler exists in the corpus
(verified F\*→Wasm demonstrates the direction is achievable for a different source
language).
**Decision:** `ProofArtifact {prover_id, version, claim→invariant_id, certificate,
toolchain_attestation}` under `/bloom/<path>/proofs/<hash>`; registry verifies the binding
and re-checks certificates where possible; never gating. Proof trust-score weight is
discounted unless the proof's provenance chain reaches the deployed `petal_hash` via one
of three transfer mechanisms, ranked by TCB size: **(1) PCC / proof-carrying
certificates** (compiler untrusted, TCB = small checker; DeepSEA *full text*: "the dsc
tool … is not in the trusted computing base"), **(2) translation validation** (TCB =
validator + solver, per-run, possibly incomplete), **(3) trusted verified compiler**
(TCB = whole proof + semantics; RustCompCert *full text*). The ranking is *analytic*
(reasoned from each mechanism's trusted surface), not empirically benchmarked on a
shared target.
**Rationale:** Unverified compilation can silently invalidate a source proof (CompCert
framing; TurboTV *abstract* found a real LLVM miscompilation), so provenance-gating is
justified. **No verified Rust→Wasm compiler exists** in the corpus — only verified
F\*→Wasm (Protzenko et al. 2019, *abstract*, 25 cites) and Rust→native (RustCompCert).
Reproducible builds + differential testing against the Rung-3 fuzz corpus are the
realistic near-term gate for full proof credit.
**Consequences:** Define the schema + scoring weights + TCB-tiered discount rules;
require reproducible-build attestation for full credit; surface the verified-Rust→Wasm
gap as a named open problem.

## ADR-007 — No single zkVM as root of trust; independent semantics fallback required · ACCEPTED · 2026-05-29
*Amended 2026-05-29 per [`lit/V-006`](lit/05-verdict-log.md) (RATIFIED — core Supported, high; generality moderate).*
**Question:** Q8.
**Context:** ~96% of zkVM circuit bugs are underconstraint — silently accepting invalid
witnesses — which would defeat arbitration from underneath. SoK-SNARKs (*full text*):
124/141 vulnerabilities break soundness; 95/99 circuit-layer bugs are under-constrained.
Arguzz (*full text*, single uncited 2025 preprint) found 3 soundness bugs across six
production RISC-V zkVMs post-audit, using **metamorphic testing + fault injection** on
product programs with a constructed known output — not re-execution against an external
honest reference VM. **All evidence is RISC-V; the corpus contains no Wasm-zkVM paper.**
The transfer to Bloom's setting is by analogy.
**Decision:** No single zkVM as root of trust. Require a re-execution / fraud-proof
challenge window that adjudicates against an **independent reference semantics** (not the
prover's own trace). Prefer provers with a formal-verification roadmap and published
underconstraint audits. Optional multi-prover diversity for high-value PTBs. Pin and
document the zkVM as a versioned part of the TCB.
**Rationale:** Underconstraint is empirically real, post-audit, and invisible to the
emitted proof — an unsound prover produces a valid-looking proof of a wrong execution,
indistinguishable to everyone downstream. Soundness must be structural, not just
"audited." The fallback mechanism must be independent of the prover's own constraint
system to avoid circularity. The cross-cutting conjecture — that the same verified
Wasm semantics serving ADR-005's determinism oracle could also serve as the ADR-007
fallback adjudicator — is explicitly a **conjecture, not a finding**: it bridges
RISC-V evidence and Wasm-determinism evidence across different machine models, and no
corpus paper studies a Wasm zkVM. It is the inquiry's best open question, not a
settled basis for design.
**Consequences:** The consensus design must include a fallback path adjudicating against
an independent reference semantics; zkVM choice evaluated on soundness evidence, not
performance; the verified-Wasm-semantics-as-zkVM-oracle conjecture tracked as a
long-horizon open question, not a committed design dependency.
---

## ADR-008 — InvariantScope encoding composed from existing canonical primitives · ACCEPTED · 2026-05-29
**Question:** S1.
**Context:** `__inv_<idx>(scope_ptr, scope_len)` receives a byte buffer describing what the
predicate may read (`before`/`after` object payloads, `args`/`ret`). Two honest nodes — and the
trusted AST interpreter vs. the compiled `__inv` export — must agree on those bytes exactly, so the
encoding must be canonical and deterministic. Two options were analyzed in
[`03-open-questions.md`](03-open-questions.md) §S1: (a) compose existing canonical framing from
`Object::encode_canonical`'s primitives, or (b) a dedicated standalone `InvariantScope` codec. The
borrow table already holds both halves of the scope relation (`baseline_payload` and
`payload_bytes`) at the point `run_invariant` is called. The codebase has rich canonical encoding
primitives — `write_u8`, `write_u16_be`, `write_u32_be`, `write_u64_be`, `write_bytes` (u32 BE len
prefix), `write_string` (u16 BE len prefix) — all deterministic, big-endian, no-floats. The
`Object::encode_canonical` pattern (fixed-width fields first, variable payload last) is the
template.
**Decision:** Compose `InvariantScope` from the existing canonical encoding primitives (Option a).
The borrow table's `BorrowRow` provides `type_tag`, `version`, `baseline_payload`, and
`payload_bytes` to the scope builder — no new borrow-table fields are needed. The encoding reuses
the same `write_*` primitives that `Object::encode_canonical` uses: a 1-byte `scope_kind`
discriminant (FunctionExit=0x00, ObjectType=0x01), a u16-BE-len-prefixed target name, a u32 BE
petal version, then u16-BE-length-prefixed vectors of before-objects, after-objects, args, and
returns — each object carrying `type_tag` (canonical), `version` (u64 BE), and `payload` (u32 BE
len + bytes). This inherits determinism from the state-root encoding that consensus already
depends on, adds almost no new canonical surface, and makes coupling to the object format explicit
and auditable. The `InvariantResult` struct must gain a tri-state: add `indeterminate: bool` to
`executor.rs:73` so out-of-fuel is distinguishable from `ok = false`.
**Rationale:** Option (a) shrinks the attack surface RT-003 identifies: "is the object encoding
canonical?" is a question consensus already answers via the state root. A dedicated codec (Option
b) would introduce a *new* canonical surface that must be independently pinned and differentially
tested — the exact hazard RT-003 is about. The coupling to the object payload format is a
conscious tradeoff: scope encoding changes when object encoding changes, which is acceptable
because the state root already tracks that change, and invariants are version-pinned per ADR-003.
**Consequences:** Replace the argspec-only scope builder in `run_invariant` (`executor.rs:1253`)
with the canonical scope encoding. Add `indeterminate: bool` to `InvariantResult` and a tri-state
dispatch in `call_invariant`. Define the wire format concretely in
[`07-implementation-plan.md`](07-implementation-plan.md). Closes RT-003 (scope encoding
determinism hole — S0) and RT-006 (indeterminate state prerequisite). S5 (conformance-suite
governance) and S6 (`BoundedArith` domain) remain open.
**Anchors:** `crates/bloom-script/src/executor.rs:73,100,1253`;
`crates/bloom-script/src/borrow_table.rs:30,53,69`;
`crates/bloom-resource-macros/src/codegen.rs:787`.

## ADR-009 — BoundedArith is integer-only with defined widening rule · ACCEPTED · 2026-05-29
**Question:** S6.
**Context:** If `PredicateAst` grows a `BoundedArith` node (§1.3), what numeric domain does it
operate on? Two options analyzed in [`03-open-questions.md`](03-open-questions.md) §S6: (a)
integer-only with a defined widening rule (`u128` operands, intermediates in `U256`/`U512`,
overflow ⇒ `indeterminate`), or (b) integer + a fixed-point type. The codebase's one real
arithmetic-heavy kernel, `bloom-dex-math`, is 100% integer-only: `u128` reserves/amounts/k, `u16`
fees (basis points), `U512` wide intermediates via `mul_div_floor`/`mul_div_ceil`, `integer_sqrt`
(Babylonian on `u128`). No floats, no fixed-point, no fractional types exist anywhere in the
petal-dex workspace. The `k` invariant (`k_last`) is `u128 = reserve_a.checked_mul(reserve_b)`.
**Decision:** Integer-only with a defined widening rule (Option a). `BoundedArith` operates on
`u128` operands with `U256`/`U512` widening for intermediate results. Overflow ⇒ `indeterminate`
(never `failed`). No fixed-point type is needed — the ecosystem expresses ratios as basis points
(`u16`/10,000) and fee-aware formulas via wide-integer transforms, never as fractional numeric
types. The grammar node is SMT-encodable because it stays in the same integer domain that Z3 and
Kani's CBMC target.
**Rationale:** (a) matches the existing ecosystem (`bloom-dex-math`), keeps the predicate language
inside the integer domain ADR-004 chose for determinism and SMT-friendliness, and avoids
reintroducing rounding-mode/representation determinism questions. (b) would add expressiveness for
a use case that does not appear in the petal-dex — the closest thing to a fixed-point need (price
ratios) is already solved by the basis-point + wide-integer pattern. If a future invariant
genuinely needs fixed-point, `BoundedArith` can be extended additively without breaking existing
invariants.
**Consequences:** The `BoundedArith` grammar node (specified in `02` §1.3) uses `u128` operands
with widening to `U256`/`U512`. The AST→Wasm lowering emits `checked_mul`/`checked_add`/etc. with
overflow traps mapping to `indeterminate`. The Kani harness on `bloom-dex-math` (§5.1) directly
exercises this domain — `quote`/`apply_swap` already use `U512` wide intermediates.
**Anchors:** `examples/petal-dex/crates/bloom-dex-math/src/lib.rs:38-52,159-200`;
`crates/bloom-petal-manifest/src/types.rs:203`.



## ADR-010 — Trigger granularity is per-function-exit (borrow-release boundary) · ACCEPTED · 2026-05-29
**Question:** S2.
**Context:** `InvariantTarget::ObjectType` is documented as "fires after every mutation" but
"after every mutation" can mean per-`object.mutate` or per-function-exit. The prior analysis in
[`03-open-questions.md`](03-open-questions.md) §S2 cited the Move Prover's "check immediately after
touching the resource" as the Option-(a)-flavoured precedent, and the CPMM swap's multi-field
update as the canonical false-positive risk. Empirical analysis of the actual code revealed the
prior analysis was wrong on both counts: (1) the CPMM swap does a single `object.mutate` — both
reserves are written atomically in one `write_pool()` call (`pool/src/lib.rs:567-579`); Bloom's
whole-payload `object.mutate` primitive naturally produces atomic multi-field updates, unlike
Move's per-field resource model. (2) The ACTUAL false-positive case is pool creation:
`create_pool` does `object_create` (with placeholder ObjectId) → `object_mutate` (stamping real
ObjectId) — per-mutate checking would fire on an incomplete pool object. (3) The multi-hop router
(`swap_2hop`) does sequential pool writes, but each pool's own invariant holds at its write point.
(4) Per-mutate checking would require restructuring the executor to intercept guest-side host calls
from within Wasm execution — it is not wired today.
**Decision:** Evaluate invariants at **function-exit / borrow-release boundary** for both
`FunctionExit` and `ObjectType` targets (Option b). This matches the existing code flow:
`run_invariant` fires inside `exec_move()` (`executor.rs:558-580`) after the petal call returns
but before `diff_check`. For `ObjectType` invariants, after `exec_move` returns, iterate over
object types whose `dirty` flag was set during the call, look up `ObjectType` invariants from the
petal manifest, and evaluate them against the `baseline_payload → payload_bytes` scope (ADR-008).
Per-`object.mutate` checking is reserved as a future opt-in attribute
(`#[invariant(check_on_every_mutate)]`) if a concrete need arises.
**Rationale:** Per-mutate solves a self-healing exploit pattern (violate an invariant, then repair
it before function-exit) that requires the petal author to intentionally split a multi-field update
across multiple `object.mutate` calls — Bloom's replace-entire-payload primitive discourages this.
The threat model for invariants is bugs and supply-chain attacks, not malicious petal authors who
could simply omit invariants entirely. The borrow table's transaction-scoped `diff_check` evaluates
at command boundaries; invariants at function-exit align with the same consistency boundary. Pool
creation would break immediately under per-mutate checking. The Move Prover's per-field-atomic
model does not transfer to Bloom's per-object-atomic model.
**Consequences:** Wire up `ObjectType` invariants alongside the existing `FunctionExit` path in
`exec_move()` — an additional loop over touched object types after the function-attached invariant
loop. No executor restructure needed. The per-mutate opt-in is a v1+ feature. S1 (scope encoding
for before/after payloads) and S2 (this decision) together fully specify the trigger and scope
model for invariants.
**Anchors:** `crates/bloom-script/src/executor.rs:558-580` (run_invariant); 
`crates/bloom-script/src/executor.rs:327` (diff_check call site);
`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:567-579` (single write_pool);
`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:323,336` (create_pool two-step).

---

## ADR-011 — Field resolution via host-side schema-driven flat field table · ACCEPTED · 2026-05-29
**Question:** S7.
**Context:** A predicate references object fields by name — `PredicateAst::FieldGe { lhs: "k_after",
rhs: "k_before" }` — but object payloads are opaque `Vec<u8>` blobs. `FieldDecl`
(`types.rs:104`) carries only `name` + `TypeTag` with no offset or width. The `#[object]` macro
(`object.rs:124-200`) iterates struct fields in declaration order and lowers each `syn::Type` to a
`TypeTag`, but the sequential index is discarded. Object payloads are hand-rolled byte layouts:
the pool's encoder/decoder (`pool_payload`/`decode_pool`, `pool/src/lib.rs:76-134`) is a manual
sequence of `write_u128`/`read_u128` calls with no declarative schema. Three options were analyzed
in [`03-open-questions.md`](03-open-questions.md) §S7: (a) Wasm-side decode, (b) host-side
schema-driven flat field table, (c) host invokes the petal's own decoder.

**Decision:** Option (b) — host-side schema-driven flat field table. Extend `FieldDecl` with
`offset: Option<u32>` and `width: Option<u32>`, computed at macro expansion time by `#[object]`
from its available struct-definition information (field order, lowered `TypeTag`s, and a width
model extended from `primitive_size_hint`). The scope builder on the Rust host extracts field
values from the opaque payload bytes at the recorded offsets and populates a flat
`name → (before_value, after_value)` table appended to the `InvariantScope` buffer (per `07` §5).
All four consumers — runtime `__inv` export, trusted AST interpreter, AST→English renderer,
Rung-3 fuzzer — read the field table directly; none decode the payload. This keeps the Wasm
export trivially simple (no struct-layout knowledge), the AST interpreter trivially correct, and
all four consumers sharing identical field data.

**Fixed-prefix addressing rule.** A field's `offset` is `Some` only while *every preceding field*
has a known fixed width; the first variable-width or unknown-width field (`Vec<u8>`, `String`,
`TypeTag`, or any type for which `canonical_byte_width` returns `None`) sets `offset = None` for
itself and all subsequent fields. Fields with `offset = None` are **not invariant-addressable in
v1** (a predicate referencing one is rejected at deploy). This is what makes `offset: Option<u32>`
load-bearing rather than cosmetic. The DEX pool's `reserve_a`/`reserve_b`/`lp_supply`/`k_last` sit
in the fixed 32/48/64/80-byte prefix (before the variable `params`/tag fields), so
`pool_k_non_decreasing` is fully addressable.

**Rationale:** Option (a) (Wasm-side decode) couples the invariant Wasm to the petal's
serialization format and requires the trusted AST interpreter to replicate the identical decode
— the ADR-002 differential test would adjudicate complex decode logic rather than simple field
comparisons. Option (c) (host invokes petal decoder) introduces re-entrancy, fuel billing,
determinism, and version-skew concerns. Option (b) keeps the risk surface in a single
deterministic Rust function (the scope builder) using the same canonical encoding primitives
(`write_u8`, `write_u16_be`, etc.) that consensus already trusts for state-root encoding
(ADR-008). The manifest schema change (adding `offset`/`width` to `FieldDecl`) explicitly
overrides `07` Appendix B's "no manifest schema changes" — justified as the implementation-gating
prerequisite for the first real invariant.

**Resolved sub-questions (S7a–S7e, settled 2026-05-29 — these close the ADR):**

1. **S7a — Field-offset trust model · RESOLVED.** The macro computes offsets from the struct
   definition, but the actual encode/decode is a hand-written function (`pool_payload`/`decode_pool`)
   with no mechanical correspondence to the struct layout. **Decision:** convention is the v1
   baseline, but safety does **not** rest on "self-punishing author error" — that under-states a
   *malicious* author who points an offset at benign bytes to dodge a slash (see RT-011). Safety
   rests on two existing mechanisms: (i) `offset`/`width` are part of the **content-addressed
   `scope_def`** (`06` §6 #3), so they are auditable at the same layer as the predicate, and (ii) the
   **ADR-003 deploy-time intent-conformance gate** exercises the predicate over *concrete
   field-value test-vectors* — a wrong offset produces wrong predicate results on known vectors and
   is rejected before deploy. A compile-time `encode(decode(x))` round-trip is recommended as
   defense-in-depth. The "is the layout right?" question is thereby folded into the "does the
   predicate encode intent?" question ADR-003 already gates.

2. **S7b — Field-extraction escapes the ADR-002 differential test · RESOLVED.** The host builds the
   field table once and both consumers read it, so the differential test compares only the comparison
   logic, not the extraction. **Decision:** accept the split. The ADR-002 differential test stays
   scoped to the AST→Wasm **lowering** (the riskier transform). Extraction correctness is covered by
   (a) a deterministic scope-builder **round-trip unit test** (known payloads → field table → assert)
   as a separate standing CI gate, and (b) the ADR-003 gate above for the adversarial case. The scope
   builder uses the same canonical primitives the state root already trusts (ADR-008), so its
   correctness is a code-review property, not a dynamic-test property.

3. **S7c — Field-table naming / before-after semantics · RESOLVED.** The field table uses
   `"before.X"` / `"after.X"` keys but `PredicateAst::FieldGe` has bare `String` references with no
   type-level before/after distinction. **Decision:** accept the naming convention for v1 — it works
   for `pool_k_non_decreasing`, which needs a computed LHS via `BoundedArith` regardless, so no node
   alone captures it. Defer the semantically-richer `MonotoneAcross` (`02` §1.3) to the grammar
   expansion that adds `BoundedArith`/`Conserves`. Documented limitation: nothing yet stops a
   nonsensical `FieldGe { lhs: "before.x", rhs: "before.y" }`; the ADR-003 gate catches the ones that
   misencode intent.

4. **S7d — `canonical_byte_width` width model · RESOLVED (with a correction).** *Correction to the
   prior analysis:* `primitive_size_hint` (`primitive.rs:184-192`) **already returns `Some(32)` for
   `ObjectId`/`Address`/`Hash32`** — the earlier claim that it returns `None` for `ObjectId` was
   wrong. The actual gaps are only **`UID`** (absent from the match arm) and **type-arg'd wrappers**
   (`type_args` non-empty ⇒ `None` at `primitive.rs:181`, so `Coin<USDC>`/`Resource<T>` get `None`).
   **Decision:** promote `primitive_size_hint` → `pub canonical_byte_width`; add `UID` (32B) and a
   `type_name`-based special case for `Coin<T>`/`Resource<T>` (32B regardless of `type_args`, since
   both are `ObjectId` wrappers in payload position). The function operates purely on `TypeTag`
   values and is called from the macro's `build_decl`, applying the fixed-prefix rule above.

5. **S7e — Validator-stub field projection · RESOLVED.** `project_object_type` (`stub.rs:78-83`)
   discards `fields`, so the executor's scope builder has no layout. **Decision:** extend
   `ObjectTypeDeclStub` with `field_layout: Vec<FieldLayoutStub { name, offset: Option<u32>, width:
   Option<u32> }>` — a minimal projection that gives the scope builder layout without pulling the
   full `PetalManifestV0` into the execution hot path.

**Consequences:** `FieldDecl` gains `offset: Option<u32>` and `width: Option<u32>`. The manifest
codec (`bloom-petal-manifest/src/codec.rs`) serializes them. The `#[object]` macro's
`build_decl()` computes them from the struct definition using `canonical_byte_width`. The
validator stub projects them to `ObjectTypeDeclStub`. The scope builder in `executor.rs` uses
them to populate a flat field table appended to the `InvariantScope` buffer. The `__inv` Wasm
export and AST interpreter both read the field table. The `07` Appendix B "no manifest schema
changes" clause is overridden for `FieldDecl` only. `primitive_size_hint` is promoted to a
`pub` function `canonical_byte_width`, adding `UID` (32B) and the `Coin<T>`/`Resource<T>` wrapper
special case (`ObjectId`/`Address`/`Hash32` are already 32B). The fixed-prefix rule governs which
fields get a `Some` offset; fields past the first variable-width field are not invariant-addressable
in v1. The adversarial offset-gaming surface this opens is tracked as **RT-011** and mitigated by the
**ADR-003** deploy-time intent-conformance gate (per S7a) — extraction is *not* covered by the
ADR-002 differential test (per S7b).

**Anchors:** `crates/bloom-petal-manifest/src/types.rs:104` (FieldDecl);
`crates/bloom-resource-macros/src/object.rs:168-192` (build_decl field loop);
`crates/bloom-objects/src/primitive.rs:172` (primitive_size_hint);
`crates/bloom-petal-manifest/src/stub.rs:78-83` (project_object_type);
`crates/bloom-script/src/executor.rs:1253` (run_invariant scope builder);
`crates/bloom-resource-macros/src/codegen.rs:787` (emit_invariant_shim);
`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:76-134` (pool_payload/decode_pool).

---

## ADR-012 — Invariant verdicts are recorded in the consensus `Receipt` · ACCEPTED · 2026-05-30
**Question:** Implementation of ADR-002's tri-state result channel: where do verdicts land so
they are trustlessly readable?
**Context:** ADR-002 gives every evaluation a tri-state verdict recorded "even on success," and
`06`'s trust scoring must read verdicts. The executor's `ExecutionReport` is transient; the
social layer reads the persisted, SSZ-encoded `Receipt` whose `receipts_root` is in the block
header. A node-local sidecar would let a node fabricate verdicts.
**Decision:** Add `invariant_outcomes: Vec<InvariantRecord>` (each `{cmd_idx, verdict, name}`)
to the consensus `Receipt`, threaded `ExecutionReport → ExecOutput → Receipt` and surfaced in
the RPC receipt JSON. This is a deliberate `receipts_root` format change (uniform, pre-mainnet).
**Rationale:** Only consensus-committed verdicts are trustlessly verifiable — the prerequisite
for any on-chain trust score (`06`). A sidecar fails that test. No stored fixtures broke (roots
are computed at runtime).
**Consequences:** `receipts_root` encoding changes; all nodes adopt in lockstep. Verdicts are
now readable via RPC; trust scoring (`06`) is unblocked but not built.
**Anchors:** `crates/bloom-chain-types/src/receipt.rs:71,134` (InvariantRecord, Receipt field);
`crates/bloom-chain-node/src/petal_executor.rs:138` (inv_outcome_to_record);
`crates/bloom-chain-node/src/consensus_driver.rs` (Receipt construction);
`crates/bloom-chain-node/src/rpc.rs` (receipt JSON).

---

## ADR-013 — `__inv_<idx>` is generated Rust over the petal calldata/return ABI · ACCEPTED · 2026-05-30
**Question:** How does ADR-008's `InvariantScope` reach the guest, and how does the verdict
return — the lowering mechanism ADR-008/`07` left open.
**Context:** The original stub returned a constant `i32` and was never run end-to-end. The
chain-VM ABI delivers calldata via the `chain.msg.calldata.read` host import (the export is
called with `(0, len)`, not a memory pointer) and reads results from `chain.petal.return`
(`ret_buf[0]`), exactly like `__petal_*` shims.
**Decision:** `emit_invariant_shim` generates **Rust source** — a pure
`__bloom_inv_N_eval(&[u8])` plus a `#[cfg(wasm32)]` export that reads the scope via
`calldata_read` and returns the 1/0 byte via `petal_return` (which diverges; the `i32` return is
vestigial). The scope is the flat field-table (ADR-008/ADR-011); 256-bit widening (ADR-009)
lives in a shared `__bloom_inv_rt`. Predicate AST is lowered to Rust, not hand-emitted wasm
opcodes. A trusted host interpreter (`interpret_predicate`) is the differential oracle.
**Rationale:** Generated Rust is far less error-prone than hand-emitted opcodes and reuses the
proven petal ABI. The `i32`-return / pointer-passing assumptions in early sketches were wrong;
real execution (not the host differential) caught it.
**Consequences:** Host-side differential tests cannot catch the host/guest ABI seam — a
`--ignored` real-wasm gate is required. Indeterminate is reachable only via out-of-fuel, not
arithmetic overflow (U256 never overflows for `u128`).
**Anchors:** `crates/bloom-resource-macros/src/codegen.rs:789,813,829,927` (shim/runtime/lowering);
`crates/bloom-chain-node/src/chain_petal_runner.rs:299,330` (call_invariant trap→indeterminate);
`crates/bloom-script/src/invariant_scope.rs:36` (scope wire format).

---

## ADR-014 — Unenforceable predicate shapes are rejected at deploy · ACCEPTED · 2026-05-30
**Question:** Implementation of ADR-001's consequence ("`validate_chain_wasm` must reject
chain-mode `Opaque` invariants").
**Context:** The v1 guest only enforces `ArithCmp`/`FieldGe`/`FieldLe`/`FieldEq`. Other shapes
(`Opaque`, `StrategyKNonDecreasing`, `AllPoolsKNonDecreasing`) lowered to a constant — a declared
invariant that silently always passes is worse than none.
**Decision:** A single predicate `predicate_is_enforceable` gates deploy: `validate_chain_wasm`
rejects any chain petal carrying a non-enforceable invariant predicate; the codegen no-op arm
additionally fails *closed* (`0`, not `1`) as defense-in-depth.
**Rationale:** Fail-closed at the deploy boundary prevents a false safety promise; the codegen
`0` ensures even a bypass reverts rather than passes.
**Consequences:** Router-style predicates can't yet deploy (tracked as a v1 gap); implementing
real `AllPoolsKNonDecreasing` enforcement lifts the restriction.
**Anchors:** `crates/bloom-petal-manifest/src/interpret.rs:39` (predicate_is_enforceable);
`crates/bloom-petals/src/chain_vm.rs:334` (deploy rejection);
`crates/bloom-resource-macros/src/codegen.rs:950` (fail-closed codegen arm).

---

## ADR-015 — Boolean composition + invariants hold across every mutation · ACCEPTED · 2026-05-30
**Question:** How much predicate vocabulary does v1 need, and what is the firing contract for an
object-type invariant?
**Context:** A single comparison can't express most real invariants. Worse, building a second
invariant exposed a soundness bug: `pool_k_non_decreasing` (an `ObjectType("Pool")` invariant)
fires on *every* Pool mutation, but `k`-non-decreasing only holds for swaps — `remove_liquidity`
shrinks reserves, so it reverted every withdrawal.
**Decision:** (1) Add `And`/`Or`/`Not` to `PredicateAst`, wired through macro lowering
(`&&`/`||`/`!`), codec, codegen (short-circuit), the tri-state interpreter, and the deploy gate
(a composite is enforceable iff all leaves are). (2) Establish the contract: **an object-type
invariant must hold after every mutation of its target.** `pool_k` is corrected to
`k_nondecreasing || !(after.lp_supply == before.lp_supply)` — the disjunct exempts liquidity
events. Per-function targeting is deferred.
**Rationale:** Boolean composition is the smallest vocabulary jump that unblocks real invariants
and the precise fix this bug needs; Kleene three-valued logic in the interpreter keeps
`Indeterminate` well-defined. The "every mutation" rule is inherent to firing on dirty borrow
rows (ADR-010) and is now documented for authors.
**Consequences:** Authors can compose predicates; `Div`/`Sqrt` and multi-object (router) scope
remain future work. A new example invariant on `/bloom/core/cap` (`cap_revoked_is_monotone`)
proves generalization off the DEX.
**Anchors:** `crates/bloom-petal-manifest/src/types.rs:314` (And/Or/Not);
`crates/bloom-resource-macros/src/invariant.rs:157` (lowering);
`crates/bloom-resource-macros/src/codegen.rs:943` (short-circuit);
`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:1051` (corrected pool_k);
`examples/petal-cap/src/lib.rs:210` (cap invariant).

---

ADR-001 through ADR-010 were **amended and accepted** (2026-05-29) incorporating the
findings of the literature inquiry ([`lit/RESEARCH.md`](lit/RESEARCH.md), 6 hypotheses
tested, 649 papers, all verdicts RATIFIED) and resolving three open sub-questions (S1, S2, S6).
**ADR-011** was added later the same day (not a literature amendment) resolving S7. Status index:

| ADR | Verdict | Key change |
|-----|---------|------------|
| ADR-001 | ACCEPTED | Keep AST; drop "opaque ⇒ unarbitrable"; add intent-conformance dependency on ADR-003 |
| ADR-002 | ACCEPTED | Pre-commit + revert (not post-commit); scope to safety fragment only |
| ADR-003 | ACCEPTED | Add deploy-time intent-conformance gate (not auto-rendered English alone) |
| ADR-004 | ACCEPTED | Reword "necessary" → "simplest sufficient means"; float ban is engineering, not necessity |
| ADR-005 | ACCEPTED | Promote verified semantics from long-term to load-bearing oracle |
| ADR-006 | ACCEPTED | Ranked-by-TCB ladder (PCC > TV > verified compiler); note no verified Rust→Wasm exists |
| ADR-007 | ACCEPTED | Add RISC-V-only caveat; clarify Arguzz uses metamorphic testing, not re-execution; mark verified-Wasm-semantics-as-zkVM-oracle as conjecture |
| ADR-008 | ACCEPTED | InvariantScope composed from existing canonical primitives (Option a); `InvariantResult` gains tri-state; closes RT-003/RT-006 |
| ADR-009 | ACCEPTED | BoundedArith is integer-only (u128 + U256/U512 widening); fixed-point deferred until concrete need |
| ADR-010 | ACCEPTED | Trigger granularity is per-function-exit (Option b); per-mutate reserved as opt-in; pool creation false-positive avoided |
| ADR-011 | ACCEPTED | Field resolution via host-side schema-driven flat field table (Option b); `FieldDecl` gains `offset`/`width`; fixed-prefix addressing; S7a–S7e resolved; offset-gaming tracked as RT-011, mitigated by ADR-003 |
| ADR-012 | ACCEPTED · impl 2026-05-30 | Invariant verdicts recorded in the consensus `Receipt` (`receipts_root` format change); unblocks trust scoring (`06`) |
| ADR-013 | ACCEPTED · impl 2026-05-30 | `__inv_<idx>` is generated Rust over the petal calldata/`petal.return` ABI (verdict = `ret_buf[0]`, not `i32` return); flat field-table scope; refines ADR-008/009 |
| ADR-014 | ACCEPTED · impl 2026-05-30 | Unenforceable predicate shapes rejected at deploy + fail-closed codegen; realizes ADR-001's consequence |
| ADR-015 | ACCEPTED · impl 2026-05-30 | Boolean composition (And/Or/Not); object-type invariants must hold across *every* mutation; pool_k corrected for liquidity events; second invariant on `/bloom/core/cap` |

**Implementation note (2026-05-30):** ADR-001/002/004/008/009/010/011 are realized in the v1
runtime; ADR-012/013/014 record decisions made *during* that implementation. See
[`08-implementation-status.md`](08-implementation-status.md) for the full ADR → code map and
remaining gaps.

**Next:** S4 (multi-prover economics) and S5 (conformance-suite governance) remain the only OPEN sub-questions; S7 is now resolved (ADR-011 ACCEPTED), and the first implementation (`07`) has landed (`08`).
