# Red-Team Log

Adversarial review of the design in [`02-architecture.md`](02-architecture.md). The job
here is to **break the design**, not extend it: find the input, the actor, or the
incentive that makes a guarantee fail. Convergent critique beats divergent addition.

Each thread: a concrete attack/weakness, which design element it targets, severity, and
status (`OPEN` → `MITIGATED → 04#ADR` / `WONTFIX` / `DISPUTED`). Add counter-arguments
inline. Newest threads can go at the bottom; keep the seed threads first.

Severity: `S0` defeats a core guarantee · `S1` major hole · `S2` sharp edge · `S3` nit.

---

## Seed threads (identified during the architecture review)

### RT-001 — Logic bomb survives runtime invariants · targets Rung 2 · S0 · OPEN *(refined 2026-05-29)*
A petal can satisfy its invariant on every normal input and violate it only on a trigger
nobody replays (a specific block height, a magic amount). Runtime invariants (Rung 2) are
**detection, not prevention** — by the time arbitration replays the violation, funds are
gone. So the whitepaper's "supply-chain attacks a problem of the past" rests almost
entirely on Rung 1 (by-construction) checks, not on the human invariant.
**Current mitigation:** the new Rung 3 (pre-deploy adversarial fuzzing of the predicate)
catches *some* of this class before deploy; high-value kernels climb to Rung 5 (proof).
**Mitigation assessed (2026-05-29).** Three candidates weighed against code reality:
**(a) Rung-1 branch restriction** — limit what predicates/functions may branch on.
Impractical: `validate_chain_wasm` (`chain_vm.rs:225`) is a static wasmparser scan that
validates import/export module names and memory caps; it does not inspect function bodies,
enumerate import function names, or inject runtime instrumentation. Specifying a
"forbidden branch condition" without banning legitimate logic is unsolved; false-positive
risk is high; false-negative risk is higher (an attacker can encode a trigger via
arithmetic or indirect call). **Not recommended for v1.**
**(b) Coverage-guided fuzzing seeded with bytecode constants.** Practical: the Rung 3
pipeline ([`rung3-fuzzing-state-of-art.md`](rung3-fuzzing-state-of-art.md) §5, §9)
already designs corpus collection + mutation + coverage guidance. Add a pre-fuzz step:
extract integer constants from the petal's own Wasm bytecode (a simple wasmparser scan
over `i32.const`/`i64.const` instructions) and seed the fuzz corpus with boundary values
around each constant. This raises the odds of hitting a narrow trigger without proving its
absence. **Recommended as the primary mitigation.** Low cost: builds on the already-planned
Rung 3 pipeline. Partial coverage: sampling remains sampling.
**(c) Predicate-language restriction** (ADR-001). Done — but only constrains the
*invariant predicate*, not the guarded *function*. A logic bomb in the guarded function
evades this entirely.
**The honest bound.** None of (a)–(c) converts detection into prevention for an arbitrary
trigger. Only Rung 5 (bounded proof for all inputs) closes the gap for a specific
invariant, and Rung 5 is too expensive to require for all petals. Residual S0 risk is
**accepted as a cost of permissionless deployment** — analogous to how blockchains accept
that a smart contract can hide malicious behavior until triggered. The mitigation path:
Rung 3 fuzzing MUST include bytecode-constant-guided seeding as a standing pre-deploy
gate, and the Rung-1 branch-restriction candidate is deferred as a spec-level open problem
for a future version. **Thread stays OPEN but gains a concrete mitigation path.**

### RT-002 — Stage-B arbitration gaming · targets §2 arbitration · S1 · MITIGATED → 04#ADR-003
**Attack.** An attacker could author a technically-correct but misleadingly-worded
`human_text`, pass Stage A, and rely on Stage B voters to side with the prose. Or grief
honest authors by repeatedly invoking Stage B to force invariant churn.
**Current mitigation (amended 2026-05-29):** the deploy-time intent-conformance gate
(ADR-003) — adversarial counterexample review and/or spec test-vectors — catches
misleading prose *before* it reaches Stage B. Auto-rendered English from the AST provides
a second, independent baseline. Stage B can only deprecate, never slash.
**Unresolved:** griefing economics — who pays for a frivolous Stage-B invocation? Couples
to S4/stake design.

### RT-003 — Determinism hole in scope encoding · targets §3 + S1 · S0 · MITIGATED → 04#ADR-008
The witness's `effect_set_hash` / scope bytes must be **bit-identical** across honest
nodes. If `InvariantScope` encoding has any nondeterminism (map iteration order, padding,
float residue, pointer-derived values), two honest nodes disagree and the whole
replay/arbitration layer collapses.
**Mitigation (resolved 2026-05-29):** ADR-008 composes `InvariantScope` from the same
canonical encoding primitives that `Object::encode_canonical` (`object.rs:113`) uses —
`write_u8`, `write_u16_be`, `write_u32_be`, `write_u64_be`, `write_bytes` (u32 BE len
prefix). These are deterministic, big-endian, no-floats, length-prefixed (no padding), and
already trusted as part of the state-root encoding. The wire format uses fixed field order
with u16-BE-length-prefixed vectors, eliminating map-iteration hazards. The borrow table
(`borrow_table.rs:30,53,69`) provides `type_tag`, `version`, `baseline_payload`, and
`payload_bytes` via deterministic `BTreeMap` ordering. The `run_invariant` function
(`executor.rs:1253`) is the single scope builder — no parallel construction paths.
**Unresolved:** the scope builder must be implemented and differentially tested (AST
interpreter vs. `__inv` Wasm export) before this is *operationally* closed. Conformance
engine divergence (RT-008) is a separate, engine-level hazard that the conformance profile
(ADR-005) + verified semantics oracle address — the scope encoding itself is now
deterministic by construction.

### RT-004 — Opaque-closure escape hatch leaks into arbitration · targets §1 + ADR-001 · S1 · MITIGATED → 04#ADR-001
**Attack.** If any path lets an `Opaque` predicate reach a chain-mode petal (e.g. a closure
the lowering *thinks* it understood but mis-lowered), arbitration is back to judging
bytecode.
**Mitigation (amended 2026-05-29):** `validate_chain_wasm` hard-rejects chain-mode
`Opaque` invariants (ADR-001, ACCEPTED). The AST-interpreter-vs-`__inv` differential test
(ADR-002) catches mis-lowering.
**Unresolved:** confirm the macro can *always* tell "lowered faithfully" from "fell back to
Opaque" — a silent mis-lowering that still produces an AST is the dangerous case.

### RT-005 — Single zkVM unsoundness defeats everything · targets §6 · S0 · OPEN
If the onchain zkVM is underconstrained (the ~96% bug class), it emits a valid-looking
proof of a *wrong* execution. Every downstream guarantee — witness, arbitration, score —
inherits the lie, undetectably.
**Current mitigation:** ADR-007 (re-execution / fraud-proof fallback; no single prover as
root of trust).
**Unresolved:** the fallback's economics and latency; whether re-execution is feasible at
throughput. Long-horizon.
**Candidate mitigations to weigh (no verdict).** The independent-oracle options RT-009
surfaces are the menu here: (a) re-execution on L1 against the chain's own VM — feasible only
if throughput allows replaying challenged PTBs; (b) a second, independent prover (the S4
two-prover question) — cost vs. one circuit's bug not silently passing; (c) a verified Wasm
interpreter as adjudicator — strongest, but the verified-Wasm-semantics-as-zkVM-oracle is a
*conjecture* (ADR-007), and whichever oracle is chosen risks *becoming* the new single point
of trust. The cross-cutting decision (does S4's second prover double as this fallback?) is the
team's; this thread cannot close while the independent oracle is unselected and the corpus has
no Wasm-zkVM evidence.

### RT-006 — Invariant-fuel as a violation-evasion channel · targets §1 evaluation · S2 · RESOLVED *(2026-05-31)*
A predicate that is *almost* too expensive could be pushed out-of-fuel by an adversary
tuning inputs, yielding `indeterminate` instead of `failed` — evading a slash on the very
input that violates it. **Worse than the original framing:** ADR-002 makes the invariant a
*pre-commit revert*, so under the as-built design (which evaluated on *leftover command
fuel* — a deviation from ADR-002's mandated separate budget) a PTB submitter could simply
set a tight gas limit to starve the check and commit the violating state outright.
**Mitigation (partial, 2026-05-29):** ADR-008 adds `indeterminate: bool` to `InvariantResult`
(`executor.rs:73`), making out-of-fuel mechanically distinguishable from `ok = false`.
**Resolution (2026-05-31):**
(1) **Separate fixed budget** — each evaluation runs on `INV_FUEL_PER_EVAL`
(`bloom-script/src/executor.rs`), independent of command fuel, so the submitter cannot
shrink the allowance (realizes ADR-002 as written; closes the deviation).
(2) **Deploy-time fuel-headroom gate (option b)** — `predicate_max_fuel`
(`bloom-petal-manifest/src/interpret.rs`) computes a conservative worst-case cost and
`validate_chain_wasm` rejects any predicate above `MAX_INVARIANT_PREDICATE_FUEL`
(< the runtime budget), so a deployed predicate provably completes within budget and can't
be pushed out-of-fuel by inputs.
(3) **Decode depth bound** — `read_predicate`/`read_arith_expr` cap nesting at
`MAX_PREDICATE_DEPTH`, so a deeply-nested predicate can't stack-overflow the validating node.
**Residual (out of scope for v1):** a *true* fuzz-corpus headroom check, and option (a)
(witness-recorded `indeterminate` verdicts feeding the Stage-B deprecate path) — both await
the trust layer (`06-verification-market.md`). The static worst-case bound is conservative in
the safe direction (rejects too early, never too late).

---

## Literature-grounded threads (from the [`lit/`](lit/RESEARCH.md) inquiry · 2026-05-29)

These threads attach published evidence to the seed threads above (and open new ones). Every
citation traces to `lit/data/corpus.json` (the raw corpus lives in the external research store,
not the repo — see [`lit/RESEARCH.md`](lit/RESEARCH.md)); verdicts in
[`lit/05-verdict-log.md`](lit/05-verdict-log.md).

### RT-007 — A green-proving invariant can encode the wrong property · targets §1/§2 + ADR-001/003 · S0 · MITIGATED → 04#ADR-003
The **best-evidenced** finding of the literature inquiry ([`lit/V-001`](lit/05-verdict-log.md)
Reading B): even a total, transparent, machine-checked predicate routinely fails to capture author
intent. Verus-SpecGym *(full text)* — best model writes faithful specs 77.8% of the time and an LLM
judge *reading the spec* misses 26% of faithfulness failures; "Evaluating LLM-driven User-Intent
Formalization" *(full text)*; PropertyGPT *(full text, 80% recall)*. So an invariant can pass Rung 5
(proof) and Stage A (objective replay) and still protect the *wrong* property — arbitration over a
faithful-*looking* spec adjudicates the wrong question. This is **upstream of** RT-001/RT-002: the
gap is at the human→spec join, not the closure-vs-AST representation ADR-001 fixates on.
**Mitigation (amended 2026-05-29):** ADR-003 now includes a deploy-time intent-conformance gate —
adversarial counterexample review and/or a spec test-vector suite — that must pass before the
predicate goes live. The gate is machine-assisted: it probes whether the predicate encodes the
property the human assertion describes. Auto-rendered English from the AST provides a baseline
for Stage B but is not the sole guard.
**Unresolved:** who runs the gate, and how to keep it from becoming Stage-B-style social theater.

### RT-008 — Conformant Wasm engines still diverge on adversarial inputs · strengthens RT-003 · targets §3/ADR-005 · S0 · MITIGATED → 04#ADR-005
A pinned conformance *profile + test-vector suite* is a finite sample of an infinite input space
([`lit/V-004`](lit/05-verdict-log.md)). The industry's own tell: a *verified* interpreter
(WasmRef-Isabelle *(full text)*) is deployed as a differential fuzzing oracle in
Wasmtime CI precisely because conformant engines diverge until caught; Wasm SpecTec *(full text)*
ships 23,778 vectors with SIMD excluded and only claims to "reduce the risk" of divergence. Two
honest nodes on different conformant engines can therefore fork — the same S0 hole as RT-003, one
level up (the engine, not just the scope encoding).
**Mitigation (amended 2026-05-29):** ADR-005 (ACCEPTED) now binds determinism on a pinned
**verified executable Wasm semantics** (WasmCert/WasmRef) as the differential oracle, with the
test suite as a fast pre-filter — i.e. the verified semantics is promoted from "long-term" to
load-bearing. The profile is stated as necessary but not sufficient.
**Evidence gap closed (2026-05-29 — both papers fetched).** "Uncovering Smart Contract VM Bugs Via
Differential Fuzzing" (NeoDiff) *(full text)* supplies the empirical S0: feedback-guided
differential fuzzing across *independent* smart-contract VMs found cross-implementation divergences
between the Neo VM in C# (run by the main consensus nodes) and the neo-python VM, plus memory
corruptions in the C# VM — independent conformant implementations *do* fork on adversarial input.
WasmRef-Isabelle *(full text — via co-author Trela's Cambridge dissertation + the published
abstract)* confirms the mitigation is real in production: a Wasm interpreter proven correct against
the WasmCert-Isabelle mechanisation, adopted as the fuzzing oracle in Wasmtime's CI precisely
because the unverified OCaml reference interpreter was too slow to keep. **Residual caveat:**
NeoDiff's divergences are EVM/Neo, not a Wasm engine *pair* directly — the cross-engine Wasm-fork
hazard still transfers by analogy, and ADR-005's verified-oracle dependency remains the standing
mitigation, not an empirically-closed result for Wasm specifically.

### RT-009 — Re-execution does not catch a soundness bug unless it adjudicates against an independent semantics · refines RT-005 · targets §6/ADR-007 · S0 · MITIGATED → 04#ADR-007
RT-005's "~96%" is roughly right (SoK-SNARKs *(full text)*: 95/99 circuit-layer bugs are
under-constrained; 124/141 vulns break soundness), and Arguzz *(full text)* confirms it empirically —
3 soundness bugs in production RISC-V zkVMs **post-audit**, where "the proof still verifies." **But the
falsifier's category-error attack has teeth:** naive re-execution that trusts the prover's own trace
is circular. What works in Arguzz is *metamorphic testing + fault injection on product programs with a
constructed known output* — **an independent oracle**, not replay-of-the-prover.
**Mitigation (amended 2026-05-29):** ADR-007 (ACCEPTED) now requires the fallback to adjudicate
against an **independent reference semantics** (not the prover's own trace), and explicitly notes that
the verified-Wasm-semantics-as-zkVM-oracle is a cross-cutting conjecture, not a demonstrated result.
**Caveats the inquiry forces:** all evidence is **RISC-V** — the corpus has **no Wasm-zkVM paper**, so
transfer is by analogy; Arguzz is a single uncited 2025 preprint; and Arguzz's *unverified*-Rust oracle
already worked, so a verified oracle *raises* assurance rather than being a strict precondition.
**Unresolved:** is the independent oracle re-execution-on-L1, a second prover, or a verified
interpreter — and does that oracle become the new single point of trust?

### RT-010 — The float ban targets the wrong hazard · refines/lowers RT-003 · targets ADR-004 · S3 · MITIGATED → 04#ADR-004
ADR-004's prior rationale ("floats are *necessary* to exclude for determinism") is not what the
evidence shows ([`lit/V-003`](lit/05-verdict-log.md)): the canonical Ethereum nondeterminism bugs came
from scheduling and read-write hazards, **not floats**. "Detecting nondeterministic payment bugs in
Ethereum smart contracts" (NPChecker) *(full text)* names the nondeterministic factors precisely as
**read-write hazards arising from unpredictable transaction scheduling and external callee behavior**
(plus Ethereum system properties) — floats appear nowhere in its taxonomy; it flagged nondeterministic
payments in **1,111 of 3,075** distinct mainnet contracts. And typed, restricted Wasm subsets with
enforced deterministic semantics are demonstrably practical: CT-wasm *(full text)* extends Wasm with a
secret-typed, constant-time fragment that its type system keeps information-flow-secure and
timing-side-channel-free — evidence *by analogy* (CT-wasm is about constant-time crypto, **not floats
directly**) that a constrained-but-usable deterministic Wasm subset is achievable at type-system cost.
**Resolved (amended 2026-05-29):** ADR-004 (ACCEPTED) has been reworded from "necessary" to
"simplest sufficient means." The ban stands on engineering grounds (lowest verification cost,
simplest determinism story), but the rationale no longer claims necessity and explicitly
notes that deterministic float subsets are achievable at higher cost. This removes the false
confidence about the float ban closing the determinism hole — RT-003/RT-008 (scope encoding,
engine divergence) are the real S0s.

### RT-011 — Field extraction escapes the differential test; a wrong offset reads the wrong bytes · targets §1 + ADR-011 · S1 · MITIGATED → 04#ADR-011 *(added 2026-05-29)*
**Attack.** ADR-011 resolves field-name → bytes by extracting values from the opaque payload at
`offset`/`width` recorded on `FieldDecl` (computed by the `#[object]` macro from the struct
definition). But the petal's *actual* encoder is hand-written (`pool_payload`/`decode_pool`,
`pool/src/lib.rs:76-134`) with no mechanical correspondence to the struct layout. Per S7b, the host
builds the flat field table **once** and both the runtime `__inv` export and the trusted AST
interpreter read it — so the **ADR-002 differential test compares only the comparison logic, never
the extraction**. A wrong offset (honest bug, or a *malicious* author who lays out the struct so the
macro-computed offset for `k_last` lands on benign constant bytes while the real value is written
elsewhere) makes the predicate evaluate over attacker-chosen bytes. Both consumers agree on the
wrong value, the differential test passes, and at arbitration the replay reads the same wrong bytes —
the violation never surfaces. This is the field-resolution analogue of RT-004/RT-007 (a predicate
that silently checks the wrong property), one layer down at the *extraction* step.
**Mitigation (ADR-011 + ADR-003).** The extraction surface is *not* covered by the differential
test, so it is closed by two other mechanisms: **(1)** `offset`/`width` are part of the
content-addressed `scope_def` (`06` §6 #3), so the layout is pinned and auditable at the **same layer
as the predicate** — an auditor sees "`k_last` @ offset 80, width 16" and can check it against the
petal's encoding. **(2)** The **ADR-003 deploy-time intent-conformance gate** exercises the predicate
over *concrete field-value test-vectors*; a wrong offset yields wrong predicate results on known
inputs and is rejected before deploy. A deterministic scope-builder **round-trip unit test** is a
standing CI gate for the honest-bug case (S7b). Defense-in-depth: an optional compile-time
`encode(decode(x))` round-trip in the petal. The fixed-prefix rule (ADR-011) also shrinks the
surface — only fixed-prefix fields are addressable, so variable-offset fields can't be mis-targeted.
**Unresolved.** Like RT-007, this leans on the ADR-003 gate actually being run by an independent
party with adversarial vectors — if the gate degrades into self-attested theater, the extraction
surface reopens. Tracked with RT-007 as the shared dependency on a real intent-conformance gate.

---

## Mitigation tally (2026-05-29, amended with ADR-008/009/011)

After the ADR amendments incorporating the literature inquiry (649 papers, all verdicts RATIFIED)
and resolving S1 (ADR-008) and S6 (ADR-009):

| Thread | Severity | Status | Resolved by |
|--------|----------|--------|-------------|
| RT-001 | S0 | OPEN *(refined)* | Inherent to runtime invariants; Rung 3 + bytecode-constant seeding + Rung 5 mitigate partially |
| RT-002 | S1 | MITIGATED | ADR-003 — deploy-time intent-conformance gate + auto-rendered English |
| RT-003 | S0 | MITIGATED | ADR-008 — InvariantScope composed from canonical primitives inherited from state-root encoding |
| RT-004 | S1 | MITIGATED | ADR-001 — `validate_chain_wasm` hard-reject + diff test |
| RT-005 | S0 | OPEN | ADR-007 fallback mitigates partially; long-horizon, economics undesigned |
| RT-006 | S2 | RESOLVED *(2026-05-31)* | Separate fixed `INV_FUEL_PER_EVAL` budget + deploy-time fuel-headroom gate (`predicate_max_fuel`) + decode depth bound; residual fuzz-corpus check / witness verdicts await trust layer |
| RT-007 | S0 | MITIGATED | ADR-003 — deploy-time intent-conformance gate |
| RT-008 | S0 | MITIGATED | ADR-005 — verified semantics oracle promoted to load-bearing |
| RT-009 | S0 | MITIGATED | ADR-007 — independent reference semantics requirement |
| RT-010 | S3 | MITIGATED | ADR-004 — rewording to "simplest sufficient means" |
| RT-011 | S1 | MITIGATED | ADR-011 — auditable `scope_def` offsets + ADR-003 gate over concrete vectors; extraction excluded from the ADR-002 differential test by design |

**S2 resolution note (ADR-010, 2026-05-29).** The prior concern that per-mutate invariant
checking would false-positive on CPMM swaps (two-step reserve_in / reserve_out writes) was
empirically refuted: the actual CPMM swap does a single `object.mutate` writing both reserves
atomically via `write_pool()`. The ACTUAL false-positive case is pool creation (`object_create` →
`object_mutate` to stamp ObjectId). ADR-010 resolves S2 to per-function-exit checking, which
avoids this and aligns with the borrow table's `diff_check` boundary. No red-team thread depends
on S2's resolution — the trigger model doesn't create or close attack surface.

**8 of 11 threads fully mitigated** by the ADRs (RT-011 added and closed by ADR-011). RT-003 closed
by ADR-008; RT-011 by ADR-011 (+ADR-003). RT-006 RESOLVED 2026-05-31 (separate fixed invariant-fuel
budget + deploy-time fuel-headroom gate + decode depth bound; residual fuzz-corpus check and
witness-recorded verdicts await the trust layer). The **2 remaining OPEN threads**: RT-001 (logic
bombs — refined with concrete mitigation path), RT-005 (zkVM soundness — long-horizon).
Two MITIGATED threads (RT-007, RT-011) share a standing dependency on the ADR-003
intent-conformance gate being run adversarially by an independent party; RT-002/RT-007 also carry
sub-question tails tracked under S4 — none are counted as open threads.
