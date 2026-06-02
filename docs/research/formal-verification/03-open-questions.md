# Open Questions — Work Queue

Claimable design items. Each has a **statement**, the **current lean** (the recommendation
in [`02-architecture.md`](02-architecture.md)), a **"done when"** bar, and a **status**.
Work one at a time: claim it (`IN PROGRESS` + your handle), draft, red-team in
[`05-red-team.md`](05-red-team.md), log the outcome in
[`04-decision-log.md`](04-decision-log.md), fold into `02`, mark `RESOLVED`.

Status legend: `OPEN` · `IN PROGRESS (@who)` · `RESOLVED → 04#id`.

> `RESOLVED` / `ACCEPTED` here mean **research-resolved** — the design argument converged in
> this workspace, not team-ratified and not implemented in code (see
> [`04-decision-log.md`](04-decision-log.md)'s preamble). Each "done when" bar is the spec
> work still required before the resolution becomes real.

---

## The eight forks (from `01` §7)

### Q1 — Spec language vs. Rust closures · `RESOLVED → 04#ADR-001`
**Statement.** Define a Bloom predicate language, or overload Rust closures in
`#[invariant(pred = …)]`?
**Resolved lean (ADR-001, ACCEPTED).** A restricted, total, human-renderable `PredicateAst` is
the canonical arbitration-citable form — not because opaque closures cannot be
machine-checked (Verus/Prusti disprove this), but because a transparent, renderable AST is
the right substrate for cheap, neutral auditability by governance. Closures are a frontend
that must lower to it or be rejected. `Opaque` is dev-only and never citable in a slash.
Readability is necessary but not sufficient — ADR-003 adds an independent
intent-conformance gate at deploy.
**Done when.** The `PredicateAst` grammar extension (`Conserves`, `MonotoneAcross`,
`BoundedArith`, `And/Or/Not`) is specified, and `validate_chain_wasm` rejects chain-mode
`Opaque` invariants. Anchor: `invariant.rs:128`, `types.rs:203`.
**Verdict:** [`lit/V-001`](lit/05-verdict-log.md) — Supported (amended), high.

### Q2 — Predicate representation & evaluation constraints · `RESOLVED → 04#ADR-002`
**Statement.** Pure Wasm fn, manifest-level expression, or both? How is evaluation
constrained?
**Resolved lean (ADR-002, ACCEPTED).** Both, layered: AST is canonical, `__inv_<idx>` Wasm
is its compiled lowering, results must match (differential test). An invariant is a
**pre-commit** view fn returning bool — reuse `validate_view_functions_are_pure`;
separate invariant-fuel; total; out-of-fuel ⇒ `indeterminate` (not `failed`). Evaluate
pre-commit and revert on failure (per Theorem-Carrying Transactions evidence). A
stateless view fn covers only the safety fragment — liveness and multi-block temporal
properties are out of scope.
**Done when.** The `__inv` ABI + `InvariantScope` evaluation contract is specified and the
`return 1` stub at `codegen.rs:787` is replaced by a real lowering. (Tightly coupled to
S1.)
**Verdict:** [`lit/V-002`](lit/05-verdict-log.md) — Supported (amended), high.

### Q3 — Human text ↔ machine predicate; failed vs. vague · `RESOLVED → 04#ADR-003`
**Statement.** How are prose assertions linked to predicates so arbitration separates "the
predicate failed" from "the assertion was vague"?
**Resolved lean (ADR-003, ACCEPTED).** Hashed `{human_text, predicate_ast}` pair in
`InvariantDecl`; two-stage arbitration where **only** objective replay (Stage A) slashes;
Stage B (vagueness) only deprecates/replaces. Auto-render AST→English; pin
`(petal_version, invariant_version)`. **At deploy time, an independent intent-conformance
gate must pass** (spec test-vectors / adversarial counterexample review) — auto-rendered
English alone is provably insufficient (PropertyGPT, Verus-SpecGym).
**Done when.** Arbitration state machine + the `InvariantDecl` schema delta (add
`human_text`, `text_hash`) + the intent-conformance gate design are specified.
**Verdict:** [`lit/V-001`](lit/05-verdict-log.md) Reading B — Supported (amended), high.

### Q4 — Reject floats in chain mode · `RESOLVED → 04#ADR-004`
**Statement.** Integer-only chain mode, despite NaN canonicalization?
**Resolved lean (ADR-004, ACCEPTED).** Yes — as the simplest sufficient means. Add
float-opcode rejection to `validate_chain_wasm` (mirroring the tail-call rejection); ship
a fixed-point helper lib. Floats are not strictly *necessary* to exclude for determinism
(deterministic float subsets exist), but integer-only is the lowest-verification-cost path
and `bloom-dex-math` shows the ecosystem needs no floats.
**Done when.** The rejection list + fixed-point lib scope are written.
**Verdict:** [`lit/V-003`](lit/05-verdict-log.md) — Necessity refuted; engineering supported, moderate.

### Q5 — Consensus-pin the Wasm engine · `RESOLVED → 04#ADR-005`
**Statement.** Pin the engine for deterministic replay — and how?
**Resolved lean (ADR-005, ACCEPTED).** Pin a **conformance profile** (feature set + fuel
schedule + test-vector suite), not a build hash, so security patches don't fork consensus.
The profile is necessary but **not sufficient** — cross-node determinism binds on a pinned
**verified executable Wasm semantics** (WasmCert/WasmRef) used as the differential oracle,
with the test suite as a fast pre-filter. WasmCert/WasmRef elevated from long-term to load-bearing.
**Done when.** The profile contents (incl. per-opcode fuel schedule) and the conformance-suite
pass/fail gate are specified. Verified oracle dependency established. (Couples to S5.)
**Verdict:** [`lit/V-004`](lit/05-verdict-log.md) — Supported (amended), moderate.

### Q6 — Smallest proof-carrying interface · `RESOLVED → 04#ADR-006`
**Statement.** Minimal interface that lets proofs boost trust without forcing authors into
provers?
**Resolved lean (ADR-006, ACCEPTED).** Optional, content-addressed `ProofArtifact` under
`/bloom/<path>/proofs/<hash>`; registry verifies the binding + re-checks certificates;
score weighted by rung **and** by TCB-tier of the transfer mechanism (PCC/certificate
checking > translation validation > trusted verified compiler). Absence never gates.
**Done when.** `ProofArtifact` schema + the registry verification rule + TCB-tiered
scoring weights are specified.
**Verdict:** [`lit/V-005`](lit/05-verdict-log.md) — Supported, high.

### Q7 — Source→Wasm equivalence gap · `RESOLVED → 04#ADR-006`
**Statement.** How does a proof about Rust source transfer to the deployed Wasm?
**Resolved lean (ADR-006, ACCEPTED).** Ranked-by-TCB ladder: (1) PCC/certificate
checking (compiler untrusted, TCB = small checker), (2) translation validation (TCB =
validator + solver), (3) trusted verified compiler (TCB = whole proof + semantics).
Reproducible-build provenance is the default gate. Score discounted unless provenance
reaches the deployed `petal_hash`. **No verified Rust→Wasm compiler exists** (verified
F\*→Wasm demonstrates direction is achievable); reproducible builds + differential
testing are the realistic near-term gate. The TCB ranking is analytic, not empirically
benchmarked.
**Done when.** The provenance/attestation requirement, the TCB-tiered score-discount rule,
and the differential-test gate are specified.
**Verdict:** [`lit/V-005`](lit/05-verdict-log.md) — Supported, high.

### Q8 — zkVM soundness bar · `RESOLVED → 04#ADR-007`
**Statement.** What soundness bar must the chosen zkVM meet (given ~96% of zkVM bugs are
underconstraint)?
**Resolved lean (ADR-007, ACCEPTED).** No single prover as root of trust; require
re-execution/fraud-proof fallback adjudicating against an **independent reference
semantics** (not the prover's own trace); prefer FV-roadmap provers; optional multi-prover
for high-value PTBs; pin + document the zkVM as TCB. **All evidence is RISC-V** (no
Wasm-zkVM paper exists in the corpus); transfer is by analogy. The cross-cutting
conjecture — that the same verified Wasm semantics serving ADR-005 could also anchor this
fallback — is an open question, not a settled design dependency.
**Done when.** The minimum bar + fallback mechanism + independent-oracle requirement are
written into the consensus design notes. (Long-horizon; couples to S4.)
**Verdict:** [`lit/V-006`](lit/05-verdict-log.md) — Core supported, high; generality moderate.

---

## Finer sub-questions (from `02` §10)

| # | Sub-question | Current lean | Status |
|---|--------------|--------------|--------|
| S1 | Canonical encoding of `InvariantScope` | RESOLVED → 04#ADR-008 — compose from existing canonical primitives (Option a); `InvariantResult` gains tri-state | `RESOLVED` |
| S2 | Trigger granularity: function-exit vs. per-`object.mutate` | RESOLVED → 04#ADR-010 — per-function-exit (borrow-release boundary); per-mutate reserved as opt-in | `RESOLVED` |
| S3 | Invariant versioning / migration across petal versions | RESOLVED → [`06-verification-market.md`](06-verification-market.md) §3 — lifecycle state machine with explicit `supersedes`/`superseded_by` version chaining | `RESOLVED` |
| S4 | Multi-prover economics | Reserve 2-prover agreement for high-value PTBs | `OPEN` |
| S5 | Conformance-suite / fuel-schedule governance | Avoid stealth consensus changes; needs a process | `OPEN` |
| S6 | `BoundedArith` numeric domain | RESOLVED → 04#ADR-009 — integer-only (u128 + U256/U512 widening); fixed-point deferred | `RESOLVED` |
| S7 | Object field-resolution: predicate field-name → payload bytes | RESOLVED → 04#ADR-011 — option (b) host-side field table; S7a–S7e settled; offset-gaming tracked as RT-011, mitigated by ADR-003 | `RESOLVED` |

The "current lean" column records the *prior research's* inclination (from `02`), not a
decision. S1 and S6 are now resolved (ADR-008, ADR-009); the option-spaces below are kept
as historical design analysis.

### S1 — canonical `InvariantScope` encoding · `RESOLVED → 04#ADR-008`

**Statement.** `__inv_<idx>(scope_ptr, scope_len)` is handed a byte buffer describing what the
predicate may read (`before`/`after` object payloads, plus `args`/`ret` for `FunctionExit`).
Two honest nodes — and the trusted AST interpreter vs. the compiled `__inv` export — must
agree on those bytes exactly, so the encoding must be canonical and deterministic. What is it?

**What the code already gives us.**
- `Object::encode_canonical()` (`crates/bloom-objects/src/object.rs:113`) is a deterministic
  framing — `id ‖ type_tag ‖ owner ‖ version(u64 BE) ‖ len-prefixed payload` — *already trusted
  as part of the state root*.
- A borrow row already holds both halves of the relation: `baseline_payload` (the "before") and
  the live `payload` (the "after") (`crates/bloom-script/src/borrow_table.rs:30,53,69`).
- The call ABI exists: `PetalRunner::call_invariant(petal_hash, export_name, scope_buf,
  fuel_budget) -> InvariantResult` (`crates/bloom-script/src/executor.rs:100`).

**Options.**
- **(a) Compose existing canonical framing.** Build `InvariantScope` out of the primitives
  `Object::encode_canonical` already uses (length-prefixed `payload` for `before`/`after`, the
  length-prefixed return-buffer framing the executor already produces for `args`/`ret`), with a
  fixed field order and a 1-byte presence tag for the `Option` fields.
- **(b) A dedicated `InvariantScope` codec.** A standalone canonical format independent of the
  object layout.

**Tradeoffs.** (a) adds almost no new canonical surface and inherits determinism from the
state-root encoding that consensus already depends on, but couples the scope format to the
object payload format (a change to one is a change to both). (b) decouples them but introduces a
*new* canonical surface that must be independently pinned and differentially tested — which is
exactly the attack surface RT-003 is about.

**Fact the decision must account for (not resolved here).** `InvariantResult { ok: bool,
fuel_used }` (`executor.rs:73`) currently has only a boolean — no third `indeterminate` state —
yet ADR-002 says out-of-fuel must yield `indeterminate`, never `failed`. Whichever encoding is
chosen, the result channel needs a tri-state or the out-of-fuel case is indistinguishable from a
violation (this also feeds RT-006).

### S2 — trigger granularity · `RESOLVED → 04#ADR-010`

**Statement.** When is an `ObjectType` invariant evaluated? The type already documents
`InvariantTarget::ObjectType` as "fires after every mutation" and `FunctionExit` as "on exit"
(`crates/bloom-petal-manifest/src/types.rs:187,193`); object writes flow through `mark_dirty`
on the borrow table (`crates/bloom-petals/src/chain_vm.rs`). "After every mutation" can mean two
materially different things.

**Options.**
- **(a) After each `object.mutate` host call.** Evaluate the predicate every time a row is
  marked dirty.
- **(b) At the borrow-release / function-exit boundary.** Evaluate once per touched object when
  its borrow settles, against `baseline_payload → payload`.

**Tradeoffs.** (a) can observe a violation that exists only mid-call, but **false-positives on
legitimate multi-step updates** — e.g. a CPMM swap writes `reserve_in` then `reserve_out`, and
`k` is only restored after the second write (`apply_swap`, `bloom-dex-math/src/lib.rs:202`), so a
per-write check would fire spuriously between the two — and it costs one predicate evaluation per
write. (b) matches the borrow-table's natural transaction-scoped consistency and avoids the
transient-inconsistency false-positive, but cannot catch a violation that is introduced and then
repaired before the boundary. (The Move Prover's "check immediately after touching the resource"
is the (a)-flavoured precedent the prior note cites; whether Bloom's borrow-commit model wants
the same is the open call.)

### S6 — `BoundedArith` numeric domain · `RESOLVED → 04#ADR-009`

**Statement.** If `PredicateAst` (`crates/bloom-petal-manifest/src/types.rs:203`, no arithmetic
node today) grows a `BoundedArith` node, what numbers does it operate on?

**What the code shows.** The one real arithmetic-heavy kernel, `bloom-dex-math`, is `u128`
operands with `U512` widening and checked `mul_div_floor`/`mul_div_ceil`
(`examples/petal-dex/crates/bloom-dex-math/src/lib.rs:38-52`) — no floats, no fixed-point.

**Options.**
- **(a) Integer-only with a defined widening rule.** `u128` operands, intermediates computed in
  a wider checked domain (u256/u512, mirroring dex-math), overflow ⇒ `indeterminate`.
- **(b) Integer + a fixed-point type.** Add a fixed-point numeric for invariants that are
  naturally fractional (price ratios, percentage bounds).

**Tradeoffs.** (a) matches the existing ecosystem and keeps the predicate language inside the
integer domain that ADR-004 chose for determinism and SMT-friendliness. (b) is more expressive
but reintroduces rounding-mode/representation determinism questions and weaker SMT support —
the exact hazards ADR-004 excluded floats to avoid. The decision interacts with both §3
(determinism) and §5 (provability) of `02`.

### S4 — multi-prover economics · `OPEN`
**Statement.** When is requiring two independent provers to agree worth its cost, and who pays?
**Option-space (not code-coupled).** (a) never — single prover + the ADR-007 re-execution
fallback; (b) two-prover agreement gated by PTB value above a threshold; (c) two-prover only for
a curated set of "flagship" kernels. Tradeoffs turn on slashing-loss magnitude vs. proving cost
and on who bears the second proof's cost (author, protocol treasury, or challenger bounty).

### S5 — conformance-suite / fuel-schedule governance · `OPEN`
**Statement.** Who may revise the pinned conformance profile + per-opcode fuel schedule (the
feature set constrained in `CHAIN_ALLOWED_IMPORT_MODULES`, `chain_vm.rs:197`), through what
process, without enabling a stealth consensus change? **No longer hypothetical:** the v1
invariant subsystem shipped the first concrete, consensus-observable schedule entries —
`INV_FUEL_PER_EVAL` (`bloom-script/src/executor.rs`), `MAX_INVARIANT_PREDICATE_FUEL`
(`bloom-petal-manifest/src/interpret.rs`, enforced at deploy), and `MAX_PREDICATE_DEPTH`
(`bloom-petal-manifest/src/codec.rs`), all hand-picked. Changing any of them silently alters
what deploys/executes across validators, so they are the first real test case for this
question. **Option-space (process, not code).**
(a) hard fork / full governance vote for any profile change; (b) a versioned profile with a
ratification quorum; (c) a split — security patches that provably preserve observable semantics
on a fast path, semantic changes on the slow path. Tradeoff: agility of security patching vs.
the risk that a "patch" silently alters consensus-observable behaviour.

### S7 — object field-resolution model · `RESOLVED → 04#ADR-011` *(added 2026-05-29, refined 2026-05-29, resolved 2026-05-29)*

**Resolution.** Option (b) — host-side schema-driven flat field table. **ADR-011 is now ACCEPTED**
in [`04-decision-log.md`](04-decision-log.md): it records the decision, the rationale, the
fixed-prefix addressing rule, and the resolution of all five sub-questions S7a–S7e (their committed
decisions are mirrored in the per-item *Status* lines below). The offset-gaming surface the design
exposes is tracked as **RT-011** ([`05-red-team.md`](05-red-team.md)) and mitigated by the ADR-003
deploy-time intent-conformance gate. The analysis below is kept as the working record; the
three-option space (a/b/c) is historical.

**Statement.** A predicate references object fields **by name** — `PredicateAst::FieldGe { lhs:
String, rhs: String }` (`crates/bloom-petal-manifest/src/types.rs:205`). ADR-008 settled how the
scope *transports* bytes: it hands the predicate the whole `before`/`after` **object payload** as an
opaque blob. It did **not** settle how a name like `reserve_a` or `k_last` is located *inside* that
blob. How is `field-name → bytes` resolved — canonically, deterministically, and identically across
the predicate's four consumers (the runtime `__inv` export, the trusted AST interpreter that ADR-002's
differential test depends on, the AST→English renderer for arbitration, and the Rung-3 fuzzer)?

**What the code shows (the gap is real).**
- Object payloads are **petal-private, hand-rolled byte layouts**. The DEX pool's is
  `[id 32B][reserve_a 16B BE][reserve_b 16B BE][lp_supply 16B BE][k_last 16B BE][params 4B-len+raw]
  [coin_a_tag][coin_b_tag]`, written/read only by `pool_payload`/`decode_pool`
  (`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:76-134`). The layout mixes fixed-width
  and variable-length fields, so offsets cannot be derived without parsing.
- The manifest's `FieldDecl` carries only `name` + a **best-effort `TypeTag`**
  (`crates/bloom-petal-manifest/src/types.rs:104-109`) — no offset, no width.
- There is **no host-side, schema-driven field decoder** anywhere in `crates/`; `decode_pool` lives
  inside the petal's own crate (compiled into its Wasm), not callable as a generic host primitive.
- The `#[object]` macro (`crates/bloom-resource-macros/src/object.rs:124-200`) already iterates
  struct fields in declaration order and lowers each field's `syn::Type` to a `TypeTag`. The
  sequential index `i` and the field's `TypeTag` are both available at macro expansion time — they
  are just not stored in `FieldDecl`.
- The validator stub (`bloom-petal-manifest/src/stub.rs:78-83`) **discards fields entirely** from
  `ObjectTypeDecl` when projecting to `ObjectTypeDeclStub` — the PTB validator has no field-level
  information at all.
- `primitive_size_hint` (`bloom-objects/src/primitive.rs:172`) returns `Some(16)` for `u128` but
  `None` for `UID`/`ObjectId` even though they are always 32 bytes in canonical encoding. It
  returns `None` for any `TypeTag` with non-empty `type_args`, so `Coin<USDC>` (an `ObjectId` wrapper,
  always 32 bytes) gets `None`. This function is `fn` (not `pub`), private to `bloom-objects`.

**Option-space — analysis complete, option (b) chosen (see ADR-011 ACCEPTED).**
- **(a) Wasm-side decode.** The `__inv` export decodes the payload itself, with struct-layout
  knowledge baked in at lowering time (the `07` §5 "Field layout knowledge" path). Rejected because:
  the trusted AST interpreter must replicate the identical decode, making the differential test
  adjudicate complex decode logic rather than simple field-value comparisons — if both sides share a
  decode bug, the test passes on wrong values.
- **(b) Host-side schema-driven decode (RECOMMENDED).** Extend `FieldDecl` with `offset`/`width`,
  computed at macro expansion time by `#[object]` (which has the struct definition, field order, and
  lowered `TypeTag`s available). The scope builder on the Rust host extracts field values from the
  opaque payload bytes at the recorded offsets and populates a flat `name → (before_value, after_value)`
  table, which is appended to the `InvariantScope` buffer (`07` §5). All four consumers read the field
  table directly — none decode the payload. Requires a **manifest schema change** (adds `offset`/`width`
  to `FieldDecl`; explicitly overrides `07` Appendix B) and a **new canonical surface** (the field
  table encoding in the scope buffer — must be deterministic per RT-003).
- **(c) Host invokes the petal's own decoder.** Call a petal-exported canonical decode function from
  the host. Rejected as highest-complexity: re-entrancy, fuel billing, making the petal's decoder
  consensus-critical, and version-skew between the decoder and the scope's payload snapshot.

**Narrowed sub-questions — must be resolved before ADR-011 can be ACCEPTED.**

**S7a. Field-offset trust model.** The `#[object]` macro would compute offsets from the struct
definition. But the pool's actual encode/decode is **hand-written** (`pool_payload`/`decode_pool`,
`lib.rs:76-134`), not macro-generated. If the macro's offset model and the hand-written encoder
diverge on any detail (field order, width assumptions for custom types like `UID`, endianness),
field extraction silently produces garbage. The correspondence between struct definition and
hand-written encoder is **convention, not enforcement** today.
- **Question:** Is convention sufficient (author error is self-punishing — their own invariants
  break on their own petal), or must there be a mechanical enforcement?
- **Analysis:** The author controls both the struct definition and the hand-written encoder
  (they're in the same petal crate). A mismatch punishes the author (their own invariant fails or
  is spuriously satisfied) but does not endanger other petals. The macro cannot mechanically
  verify the hand-written encoder matches the struct layout without a far more invasive change
  (replacing hand-written encode/decode with macro-generated code). For v1, accept the
  self-punishing convention. Optionally: a compile-time test that round-trips `encode(decode(x))`
  against known offsets to surface mismatches.
- **Status:** RESOLVED → ADR-011. Decision: convention is the v1 baseline, but safety rests on the
  auditable content-addressed `scope_def` offsets + the ADR-003 gate over concrete vectors (not
  "self-punishing convention" — a malicious author is the real case, tracked as RT-011), with an
  optional compile-time round-trip as defense-in-depth.

**S7b. Field-extraction escapes the differential test.** ADR-002 requires an AST-interpreter-vs-`__inv`
differential test. With option (b), the host builds the field table **once** and both consumers read
it — so the differential test only compares the *comparison logic*, not the *field extraction*. If
the scope builder extracts wrong values (wrong offset, wrong endianness), both consumers agree on
wrong values and the test passes.
- **Question:** Does the ADR-002 differential test need to cover the field-extraction step, or
  is it sufficient to test the comparison logic against a known-correct field table?
- **Analysis:** The scope builder is deterministic Rust (same canonical primitives as
  `Object::encode_canonical`, big-endian, no floats per ADR-008). Its correctness is a static
  code-review property, not a dynamic test property. The differential test remains the gate for
  the lowering step (AST→Wasm), which is the riskier transform. The scope builder can be unit-tested
  independently with known payload bytes and known field offsets. Recommend: add a
  scope-builder round-trip test (encode scope from known before/after payloads, decode field table,
  assert values match) as a separate CI gate, but keep the ADR-002 differential test scoped to the
  lowering step only.
- **Status:** RESOLVED → ADR-011. Decision: accept the split — the ADR-002 differential test stays
  scoped to the AST→Wasm lowering; extraction correctness is covered by a standing scope-builder
  round-trip unit test (honest bugs) plus the ADR-003 gate (adversarial case, RT-011).

**S7c. Field-table naming and the before/after semantics gap.** The `07` §5 proposed field table
uses names like `"before.reserve_a"` and `"after.reserve_a"` as keys. But the `PredicateAst` has
bare `FieldGe { lhs: String, rhs: String }` — nothing enforces that `lhs` names an "after" field
and `rhs` a "before" field. The convention is purely string-based, with no type-level distinction.
The `02` architecture (§1.3) proposes `MonotoneAcross { field: Field, dir: Ge|Le }` as a
semantically richer node that explicitly captures before→after comparisons.
- **Question:** For v1, should the naming convention (`before.X`/`after.X` as field-table keys,
  `FieldGe` with bare field-name references) be accepted as the working convention, or should
  `MonotoneAcross` be specified and implemented as part of the S7 resolution?
- **Analysis:** `FieldGe` with the naming convention works — the field table is populated by the
  scope builder, the `PredicateAst` references the field-table key names, and the `__inv` export
  looks them up. But it is fragile: nothing stops an invariant from writing
  `FieldGe { lhs: "before.reserve_a", rhs: "before.reserve_b" }` (both "before", nonsense
  semantically). `MonotoneAcross` would remove this class of error but requires a grammar change
  and a lowering rule. The pool's `k` invariant needs a computed LHS (the BoundedArith product)
  regardless, so neither `FieldGe` nor `MonotoneAcross` alone captures it — the AST needs
  intermediate-value references either way.
- **Status:** RESOLVED → ADR-011. Decision: accept the `before.X`/`after.X` + bare `FieldGe` naming
  convention for v1 (it works for `pool_k_non_decreasing`); defer `MonotoneAcross` to the grammar
  expansion that adds `Conserves` and `BoundedArith` (which `02` §1.3 groups together). The
  nonsense-comparison class is caught by the ADR-003 gate, not the grammar, in v1.

**S7d. canonical_byte_width for wrapper types and type-args.** *Correction (2026-05-29): the prior
draft was wrong about `ObjectId`.* `primitive_size_hint` (`bloom-objects/src/primitive.rs:172-193`)
**already returns `Some(32)` for `ObjectId`/`Address`/`Hash32`** (the match arm at `primitive.rs:190`).
The genuine gaps are: **`UID`** (not in the match arm → `None`) and any `TypeTag` with non-empty
`type_args` (early-return `None` at `primitive.rs:181`, so `Coin<USDC>` — an `ObjectId` wrapper,
always 32 bytes — gets `None`). This function is `fn` (not `pub`), private to `bloom-objects`, and
lives outside the macro crate that would call it. The offset computation needs accurate width
information for every fixed-width field type that appears in object structs.
- **Question:** What is the complete set of types that need known fixed widths, and where does
  the width model live?
- **Analysis:** The types that appear as fields in the DEX pool struct are: `UID` (32B), `u128`
  (16B), `Vec<u8>` (variable), `TypeTag` (variable). For v1 on the pool, extending
  `primitive_size_hint` (or creating a parallel `canonical_byte_width`) to recognize `ObjectId`,
  `UID`, `Hash32`, and `Address` as 32 bytes is sufficient. `Coin<T>` and `Resource<T>` (which
  are `ObjectId` wrappers, always 32 bytes in payload position) could be handled by a special
  case: any `TypeTag` whose `type_name` is `"Coin"` or `"Resource"` is 32 bytes regardless of
  type args. This function should be `pub` and available to the macro crate (via
  `bloom-objects`). The function must be callable from the macro's `build_decl` — which today
  only has access to `TypeTag` values (lowered from `syn::Type`), not to the `bloom-objects`
  runtime crate. This is solvable: the macro generates `TypeTag` literals at compile time, and
  the width function only needs to match on `type_name` and `type_args` — it operates purely on
  `TypeTag` values, which the macro already constructs.
- **Status:** RESOLVED → ADR-011. Decision: promote `primitive_size_hint` → `pub canonical_byte_width`
  returning `Option<u32>`; **add `UID` (32B)** and a `type_name`-based special case for `Coin<T>` /
  `Resource<T>` (32B regardless of `type_args`) — `ObjectId`/`Address`/`Hash32` are already 32B. The
  function operates on `TypeTag` values regardless of call site, and offsets follow the fixed-prefix
  rule (a field's offset is `Some` only while every preceding field has a known fixed width).

**S7e. Validator stub carries no field information.** `project_object_type`
(`bloom-petal-manifest/src/stub.rs:78-83`) discards `fields` when projecting to the validator
stub. The scope builder (which runs inside the executor, which uses the stub) has no access to
field layout information today.
- **Question:** Should the scope builder read field layout from the full manifest (available at
  deploy time and carried alongside the compiled Wasm), or should field layout be projected into
  the validator stub (which the executor holds)?
- **Analysis:** The full `PetalManifestV0` is available at deploy time (stored in the petal
  Wasm's custom section, extracted by `extract_petal_manifest_v0`). The executor currently uses
  `PetalManifestStub`, which is a projected subset. Either: (a) extend the stub with a minimal
  `FieldLayoutStub` carrying `{name, offset, width}`, or (b) have the scope builder access the
  full manifest (not just the stub) for field layout. (a) is cleaner: it keeps the executor's
  dependency on a well-defined projection and avoids pulling the full manifest into the execution
  hot path.
- **Status:** RESOLVED → ADR-011. Decision: extend `ObjectTypeDeclStub` with
  `field_layout: Vec<FieldLayoutStub { name, offset: Option<u32>, width: Option<u32> }>` — a minimal
  projection giving the scope builder layout without pulling the full manifest into the hot path.

**Relation to prior decisions.** ADR-008 (scope transport) assumed payloads are available but left
field access open; S7 is the concrete instance. ADR-002 (differential test) is affected by S7b
(extraction escapes the differential test — covered by a separate correctness gate + ADR-003).
ADR-011 (ACCEPTED) records the option (b) decision and the resolution of all five sub-questions
above. ADR-003 (intent-conformance gate) carries the adversarial mitigation (RT-011). ADR-009
(BoundedArith integer-only) provides the `u128` domain for field values.

**Done — 2026-05-29.** All five sub-questions (S7a–S7e) are resolved and **ADR-011 is ACCEPTED**. The
concrete design — field-table scope encoding, `FieldDecl` `offset`/`width` extension, the fixed-prefix
offset rule, the `canonical_byte_width` width model, and the stub projection — is specified
sufficiently for `07` Steps 6 (lowering) and 7 (scope builder) to proceed. Spec/build work remains
(not research): implementing the schema change, the macro computation, and the scope builder.

**Anchors:** `types.rs:104,205`; `bloom-petal-dex-pool/src/lib.rs:76-134`; `executor.rs:1253`;
`primitive.rs:172`; `object.rs:124-200`; `stub.rs:78-83`.

---

## Suggested first moves (updated 2026-05-29 after ADR acceptance + market design)

This queue covers the **open design questions** to claim next. For the end-to-end *build
sequence* (manifest-as-contract, the predicate object, first invariant, fuzz rung, witness,
determinism, zkVM) see the single canonical leverage order in
[`02-architecture.md`](02-architecture.md) §9.

**Forks Q1-Q8 are research-resolved. S1, S2, S6, and S7 are now resolved (ADR-008, ADR-010, ADR-009, ADR-011).** The remaining work:
0. ~~**S7** — object field-resolution model~~ **RESOLVED (ADR-011 ACCEPTED, 2026-05-29).** The
   implementation-gating field-resolution design is settled (host-side field table; S7a–S7e closed);
   the first real invariant (`07` §6) is now unblocked. What remains for S7 is spec/build, not research.
1. **S4** — multi-prover economics (downstream of zkVM selection) — the only remaining OPEN design question alongside S5
2. **S5** — conformance-suite / fuel-schedule governance (process design)
3. **Kani pilot on `bloom-dex-math`** — establishes the proof workflow
4. **Market questions** in [`06-verification-market.md`](06-verification-market.md) §6 — content-addressing and vacuity resolved; cross-petal claims deferred to v1+; stake economics, Stage-B quorum, and scoring calibration deferred to calibration
5. **First implementation** — see the concrete plan in [`07-implementation-plan.md`](07-implementation-plan.md): InvariantScope wire format, AST→Wasm lowering, `pool_k_non_decreasing` end-to-end
