# Formal Verification and Invariants in Bloom

**Background research toward implementing the whitepaper**

**Date:** 2026-05-29
**Status:** Background research — not a spec, not an implementation plan
**Audience:** Bloom engineers
**Scope:** How Bloom can use formal verification, invariants, and related techniques to
deliver the trust guarantees the whitepaper promises; how amenable the current petal
design is to writing proofs about it; and where we should start designing.

> **Provenance.** This file *is* the original research note (the canonical record; it began
> as a 2026-05-29 PDF, now kept only as markdown). It is the **input** to the workspace; the
> proposed resolutions to its §7 questions live in [`02-architecture.md`](02-architecture.md).
> See [`README.md`](README.md) for how the files relate.

---

## Contents

1. [Executive summary](#1-executive-summary)
2. [What the whitepaper actually asks verification to do](#2-what-the-whitepaper-actually-asks-verification-to-do)
3. [Where the implementation stands today](#3-where-the-implementation-stands-today)
4. [The verification ladder](#4-the-verification-ladder)
5. [External landscape](#5-external-landscape)
6. [What needs to change, and where to start designing](#6-what-needs-to-change-and-where-to-start-designing)
7. [Open questions for the team](#7-open-questions-for-the-team)
8. [Tentative conclusion](#8-tentative-conclusion)
- [Appendix: sources](#appendix-sources)

---

## 1. Executive summary

The whitepaper makes a strong claim: that humans and agents can trust and verify
AI-generated software, with the invariant as "the most important contribution to a
Petal by a human" and arbitration ("pruning") as the mechanism that adjudicates whether
an invariant was broken. Today the protocol has the plumbing for this — invariant
slots, a borrow table, view-purity checks, deterministic chain-mode execution — but not
the substance: the generated `__inv_<n>` invariant bodies are literally `return 1`. The
single highest-leverage gap between the codebase and the whitepaper is that invariants
do not yet evaluate anything.

The central finding of this research is that **Bloom should not pick a verification
language. It should build a verification ladder** and decide, per claim, which rung is
appropriate. The rungs, in increasing cost and rigour:

1. **VM-enforced protocol invariants** — properties of the Bloom VM and PTB semantics
   that hold for every petal regardless of source language (import allow-lists, effect
   typing, linearity, dependency pinning). Mostly already implemented; these are the
   cheapest and most valuable.
2. **Executable runtime invariants** — the human-authored `#[invariant]` predicates the
   whitepaper centres on. Not proofs, but replayable, machine-checkable assertions. This
   is the biggest build and the right near-term focus.
3. **Canonical replay witnesses** — a content-addressed artifact that lets arbitration
   judge a concrete input/state/output/effect trace rather than "source-code vibes".
   This is what makes pruning credibly neutral.
4. **External formal proofs** — Kani/Verus/Move-Prover-style/Lean proofs attached to
   small, high-value pure kernels (DEX math, codecs, scoring). Optional, score-boosting,
   not gating.

The current design is **more amenable to verification than a generic "arbitrary Wasm
plugin" platform**, because it has converged on a Move-like resource model with
deterministic execution, content-addressing, and an explicit manifest. The closest
external analog — Move and the Move/Sui Prover — exists precisely because that shape is
verification-friendly. The main things that fight verification are: Rust-macro
heuristics standing in for a real language boundary, the unverified Wasmtime/Cranelift
toolchain underneath a consensus-critical replay, an undefined invariant predicate
language, and the soundness of the zkVM the whitepaper leans on for execution proofs.

**Where to start designing:** define the Bloom invariant/specification language and the
before/after scope model, finish the runtime-invariant path end to end (one real
invariant on the DEX pool), harden the manifest into the canonical petal contract, and
pilot Kani on `bloom-dex-math` (which is already written in a verification-ready style).
Treat zkVM and Wasm-semantics soundness as a separate, long-horizon track.

---

## 2. What the whitepaper actually asks verification to do

Reading the whitepaper as a verification requirements document, five distinct demands
emerge. They do not all want the same kind of guarantee, which is why a single tool
cannot satisfy them.

**Invariants as the human artifact.** "As the code in a Petal is an artifact from
agents, there should also be an artifact from humans that enforces the correctness of a
Petal." Invariants must be evaluable "across both onchain and offchain executions, and
used in arbitration." This is the load-bearing concept. It implies invariants must be
(a) human-authored and human-readable, (b) machine-evaluable deterministically, and
(c) the same across execution modes. Crucially, the whitepaper does not claim invariants
are proofs — it claims they are an enforceable specification.

**Arbitration / pruning needs replayable, objective breakage.** A challenger stakes LOOM
"along with proof that an invariant is broken"; voters decide; stakers are slashed or
the challenger is penalised. For this to be credibly neutral rather than a popularity
contest, "broken" has to be reducible to a replayable fact: on this input and this
state, this predicate evaluated false. The whitepaper also anticipates an "indeterminate
outcome" where a better-defined invariant is proposed — i.e. the dispute may be about
the specification being vague, not the execution. The verification design must
distinguish "the predicate failed" from "the assertion was too vague to adjudicate."

**Scoring and emissions assume determinism.** Scores are "computed from deterministic,
epoch-bounded inputs and public formulae" and are "amenable to succinct zero-knowledge
proof generation" — a validator attaches a zk-proof that the ranking was derived
correctly. zk-provability requires deterministic, well-defined computation. Any
nondeterminism in petal execution or scoring undermines both consensus and the proof
story.

**Supply-chain trust is the headline use case.** Bloom aims to make "supply chain attacks
a problem of the past" via content-addressing, versioned petals, pinned dependencies,
and continuous review. Verification here is largely about what cannot happen by
construction: an unpinned dependency, an undeclared host import, a type-confused object.

**"Everything is Wasm" is a hard constraint, and a double-edged one.** Wasm is the
deployed and consensus-relevant artifact, and the whitepaper even imagines agents writing
WAT directly. That makes source-language-independent, Wasm-level checks robust (they
survive any frontend) — but it also means the trusted computing base is the Wasm engine
and, onchain, the zkVM. Proving things about a nice Rust source program is worth less if
the deployed artifact is a separately-compiled Wasm blob running on an unverified engine.

The **ROOT consensus** design adds one more: onchain execution must run inside a zkVM
prover (the whitepaper names Ligero/Ligetron as a candidate). The soundness of that
prover is therefore part of Bloom's trusted base — a false execution proof is
indistinguishable from a true one to everyone downstream.

---

## 3. Where the implementation stands today

This section is the verified state of the code as of this date (`bloom/crates/...`), not
the aspiration. It matters because amenability to proof is a property of what exists, not
of the design docs.

### 3.1 Chain-mode admission — strong and verification-friendly

`bloom-petals/src/chain_vm.rs` already enforces a deterministic, constrained execution
surface, and does so at the Wasm level (source-language-independent):

- A separate Wasmtime engine with `consume_fuel`, `cranelift_nan_canonicalization`,
  `wasm_relaxed_simd(false)`, `wasm_multi_memory(false)`, `wasm_tail_call(false)`,
  `wasm_threads(false)`, `async_support(false)`. Standard SIMD and bulk-memory are
  allowed.
- An import allow-list: only `chain`, `object`, `cap`, `signer`, `ptb`, `log` modules
  may be imported; anything else is rejected at admission.
- An export allow-list: function exports must match `__petal_*`, `__inv_*`, `__alloc`,
  `__dealloc`, or `__bloom_manifest_*`.
- A 16 MiB memory cap (256 pages), start sections rejected, and tail-call opcodes
  (`return_call`, `return_call_indirect`, `return_call_ref`) rejected at the opcode level
  so admission matches the engine config.

This is exactly the kind of property that belongs in the VM and not in a proof assistant:
it is decidable, cheap, and holds for every petal.

### 3.2 View functions — the clearest machine-checkable property

The view-purity verifier (`validate_view_functions_are_pure` in `chain_vm.rs`, designed
in `2026-05-29-view-functions-design.md`) is the best existing example of a real,
enforced semantic property. For every manifest function marked `view`, it walks the
static call graph from `__petal_<name>` and rejects the deploy if the reachable set
touches a mutating object import (`object.create/transfer/share/freeze/delete/mutate`) or
uses a call it cannot bound statically (`call_indirect`, `call_ref`, and the return-call
variants). At execution time the view path additionally forces every object arg to
`ReadOnly` and asserts the post-execution effect set is empty. This is a genuine
four-layer defence (declare → static-check → constrained-execute → runtime-assert) and is
the template the rest of the verification work should imitate.

### 3.3 Borrow table — Move-like resource semantics, already enforced

`bloom-script/src/borrow_table.rs` is more complete than the earlier research note
implied, and it is the strongest existing foundation for invariants. It distinguishes
persistent rows (loaded from the object trie) from transient rows (produced mid-PTB), and
enforces:

- ReadOnly rows that change are rejected as `IllegalMutation` (`diff_check`).
- Mutable/Consume rows that change get exactly one version bump per diff cycle, including
  an auto-promotion guard against guests that mutate payload bytes without calling
  `object.mutate`.
- Linearity: transient objects not consumed/transferred/shared/frozen/deleted by tx-end
  are returned as orphans (`linearity_check`), with deterministic `BTreeMap` ordering for
  reproducible reporting.

The host imports in `chain_vm.rs` back this with a type-defining-petal rule (only the
petal that defines a type may create/mutate/delete it, with an explicit linear-move
exception for Consume-mode args) and an authorized-minter list for Coin. These are
resource-conservation properties in the Move sense, and they are exactly the kind of
state-machine that Verus or a Move-Prover-style spec proves well.

### 3.4 Invariants — the scaffolding exists, the substance does not

This is the gap. `bloom-resource-macros/src/invariant.rs` parses
`#[invariant(name, target, pred)]`, derives a best-effort `PredicateAst` (it recognises
`FieldGe`/`FieldLe`/`FieldEq` and a pool-style `S::k(p) >= p.k_last` shape, otherwise
`Opaque`), and records a manifest `InvariantDecl` with a `__inv_<idx>` export name. But:

- `expand()` currently re-emits the function unchanged plus a name constant; the
  predicate is parsed but not yet compiled into anything that runs.
- `codegen.rs::emit_invariant_shim` emits the `__inv_<idx>` body as a `return 1` stub
  (both the Wasm export and its host-side mirror). The executor calls it after petal
  functions and reverts on failure — but it can never fail.

So Bloom has invariant slots, names, best-effort ASTs, export plumbing, and
revert-on-failure wiring, but **no invariant actually evaluates a predicate.** The
whitepaper's central human artifact is, in code, a no-op. Everything in §6 below about
"where to start" treats closing this as the priority.

### 3.5 DEX math — already written like a verification target

`examples/petal-dex/crates/bloom-dex-math/src/lib.rs` is a pure, dependency-light library
(not a petal — it is linked into the pool/router at compile time) with `Result`-typed
errors, wide `U512` intermediates, checked arithmetic, a `MAX_FEE_BPS` guard, and an
`integer_sqrt` whose tests already assert the property `s*s <= n < (s+1)^2`. It is the
ideal first formal-verification pilot: the properties are already stated as comments and
tests; they just need to be promoted from "tested on examples" to "proved for all bounded
inputs."

### 3.6 Typed cross-petal calls — conservative by design

The cross-petal-call design (`2026-05-26-typed-cross-petal-calls.md`) is deliberately
restrictive in v1: static, hash-pinned dependencies only; synchronous fail-fast;
manifest-carried ABI/interface hashes; explicit object grants to child frames; child
failure aborts the parent PTB. This conservatism is a verification asset — it keeps the
dependency graph statically analyzable and gives a clean basis for dependency and
interface invariants later.

### 3.7 Capability snapshot

| Surface | State today | Verification character |
|---------|-------------|------------------------|
| Chain-mode import/export/memory/opcode admission | Implemented | VM-enforced, language-independent — **strong** |
| View purity (static call-graph + runtime effect assertion) | Implemented | Decidable, machine-checkable — **strong** |
| Borrow table (read-only protection, version bumps, linearity) | Implemented + tested | Move-like resource state machine — **strong** |
| Type-defining-petal / minter authorization | Implemented | Object-ownership invariant — **strong** |
| `#[invariant]` parse + manifest decl + `__inv_` plumbing | Implemented | Scaffolding only |
| `#[invariant]` predicate evaluation | `return 1` stub | **Missing — top priority** |
| Invariant before/after scope model | Not designed | Missing |
| Canonical replay/witness artifact for arbitration | Not implemented | Missing |
| External proofs (Kani/Verus/…) on kernels | None | Greenfield, low-risk to start |
| Determinism hardening (floats, engine pinning) | Partial (NaN canon; floats allowed) | Open decision |

---

## 4. The verification ladder

> **Historical input — superseded numbering.** This is the *original* 4-rung ladder. The
> canonical ladder is now the **5-rung** table in [`02-architecture.md`](02-architecture.md)'s
> *Framing* (the corrected ladder), which inserts a new **Rung 3 = pre-deploy adversarial
> testing (fuzzing)** between runtime invariants and the replay witness. As a result the
> rungs below are renumbered in `02`: this doc's *Rung 3 (replay witnesses)* → `02` Rung 4,
> and *Rung 4 (external proofs)* → `02` Rung 5. The text below is preserved as the historical
> input that `02` builds on; cite `02`'s *Framing* section for the current scale.

The recommended mental model. Each claim type in Bloom maps to a rung; the cost rises as
you climb, and most claims should be satisfied as low on the ladder as possible.

### Rung 1 — VM-enforced protocol invariants (mostly done)

Properties that define the system and hold for every petal regardless of how it was
authored. They live in admission, validation, and execution, and are checked against
manifests, Wasm bytes, PTBs, and state diffs. Examples already enforced: only-approved
imports, only-approved exports, bounded memory, no start section, no rejected opcodes, no
read-only mutation, linearity of transient objects, type-defining-petal rule, view
purity. Examples to add: dependency hash-pinning enforcement, dependency
ABI/interface-hash match, return-bytes-match-declared-TypeTag, "historical snapshot
selection cannot appear in a committed PTB" (already a design invariant of the view path),
fuel charged per consensus rules.

These are the cheapest guarantees and the most valuable, because they are unconditional
and survive any future language frontend (Rust DSL, WAT, or otherwise). **Recommendation:
keep pushing properties down to this rung wherever possible.**

### Rung 2 — Executable runtime invariants (the big build)

This is the whitepaper's human artifact. A `#[invariant]` becomes a real predicate that
runs after relevant function exits and (eventually) after relevant object mutations, with
its result included in receipts/traces and a failure reverting the PTB. It is not a proof
— it does not establish the property for all inputs — but its breakage is replayable and
machine-checkable, which is exactly what pruning needs. The honest framing for the team
and for users: **a runtime invariant is a continuously-checked, arbitrable specification,
not a mathematical theorem.**

The design work this requires is in §6. The key point here is that Rung 2 is where most of
Bloom's distinctive value lives, and it is currently empty.

### Rung 3 — Canonical replay witnesses (what makes pruning neutral)

For arbitration to avoid asking humans to judge source code, a challenge or audit should
cite a content-addressed witness binding together: `petal_hash`, `manifest_hash`,
`assertion_id`, `assertion_text_hash`, dependency lock table, block height / state root,
input (or PTB) bytes, output bytes, effect-set hash, fuel used, trace hash, and the
machine verdict. Then governance judges two separable things: **did the predicate fail on
this replay?** (objective) and **does the human-readable assertion fairly describe the
predicate?** (the "indeterminate / propose a better invariant" path the whitepaper
anticipates). This is the bridge between the deterministic machine and the social
consensus layer, and it is unbuilt.

### Rung 4 — External formal proofs (selective, score-boosting)

Full mathematical guarantees for small, high-value, pure targets. These attach to a petal
version as optional proof artifacts that improve trust score but never gate ordinary
experimentation. The right targets are pure kernels and small state machines — DEX math,
codecs, scoring/emission formulae, the borrow-table state machine — not whole arbitrary
petals. Tool fit is surveyed in §5.4.

**The strategic claim:** Rungs 1–3 are Bloom-specific and must be built in-house; Rung 4
is where the external formal-methods ecosystem plugs in, and only after Bloom has stable
kernels and stable manifest semantics to prove against.

---

## 5. External landscape

### 5.1 The closest analog: Move and the Move/Sui Prover

Bloom's object/capability/linearity/PTB model is, by convergent evolution, close to
Move's resource semantics — and Move is the one mainstream smart-contract language
designed for formal verification from the start. The Move Prover specifies three things
that map almost one-to-one onto Bloom's needs: **struct invariants** (state a structure
must always satisfy ≈ Bloom object invariants), **function pre/post-conditions** (≈ petal
function contracts), and **global/state-machine invariants** checked immediately after
any instruction that touches the relevant resource. The Sui Prover went open-source in
January 2026 and has been used to verify AMMs and leveraged-yield protocols — the exact
DeFi shapes in Bloom's petal-dex example.

The lesson is **borrow the specification model, not the language.** Translating petals to
Move would fight the "everything is Wasm" premise, and running the Move Prover on Bloom's
Rust/Wasm is not a straight path. But the way Move structures resource invariants — and
the empirical evidence that this style proves real DeFi properties — is the strongest
available template for the Bloom invariant/spec language.

### 5.2 The Rust verification tools (for Rung 4 on kernels)

Bloom is written in Rust, so the Rust verification ecosystem is the natural fit for
proving kernels, and it has matured:

- **Kani** (bounded model checker, AWS). Now supports function contracts
  (`#[kani::requires]`/`ensures`/`modifies`) and loop contracts (`#[kani::loop_invariant]`,
  added across the 0.62–0.66 releases), so it is no longer limited to pure unwinding —
  loop contracts let it reason about some unbounded loops. Harnesses look like tests, it
  gives counterexamples, and it was used to verify parts of the Rust standard library.
  Best first tool for `bloom-dex-math`, codec round-trips, and fuel arithmetic. Limit:
  still fundamentally bounded; large state spaces need care.
- **Verus** (SMT-backed, CMU). Supports a large Rust subset including finite- and
  infinite-range integers, ghost code, and linear/affine ghost state — a strong conceptual
  match for the borrow table and resource accounting. Limit: it verifies a subset (not
  arbitrary production Rust), proof effort is real, and SMT query instability is a known
  operational cost (Verus benchmarks were contributed to SMT-LIB in 2025 specifically
  because of this).
- **Creusot / Prusti / Flux.** Deductive verification (Why3/SMT), Viper-based contracts,
  and refinement types respectively. Useful for source-level contracts, panic/overflow
  freedom, and numeric refinements; maturity and Rust coverage vary.
- **hax** (Cryspen). Translates a Rust subset to F\*/Rocq/ProVerif/EasyCrypt. Notably used
  to verify libcrux's ML-KEM — directly relevant because Bloom's security model is
  post-quantum (xDSA = ML-DSA + Ed25519). hax is the most promising route for
  high-assurance crypto and codec kernels while keeping Rust as the authoring language.

A standing caveat for all of these: they prove things about **Rust source**, while Bloom
deploys separately-compiled **Wasm**. A proof about the source only transfers to the
deployed artifact if the compilation is trusted or an equivalence is established. This is
the "equivalence gap" the team must decide how to handle (see §6.6).

### 5.3 Wasm and zkVM soundness — the trusted base

Because the deployed and consensus-relevant artifact is Wasm running (onchain) inside a
zkVM, the trusted computing base is larger than the petal:

- **Wasm semantics are mechanized** (WasmCert-Coq/Rocq, WasmRef-Isabelle's verified
  interpreter and fuzzing oracle, and 2024–2025 "progressful interpreter" work that
  extended mechanization to Wasm 2.0 and found bugs in the spec's type system). This makes
  Wasm a plausible long-term proof target. But Bloom executes on Wasmtime/Cranelift, which
  is **not formally verified** — so today the engine is trusted, not proven. Consensus
  replay also depends on the engine version being pinned, or two honest nodes could
  disagree.
- **zkVM soundness is the sharpest risk.** Independent analysis of RISC Zero found that
  **~96% of zkVM circuit bugs were underconstrained** — i.e. the prover accepts witnesses
  of invalid computations as valid, which silently breaks soundness. RISC Zero is working
  toward the first formally verified RISC-V zkVM (with Veridise and Nethermind, using
  Lean). The implication for Bloom: an unsound zkVM means a petal can produce a
  valid-looking proof of a wrong execution, which would defeat the entire
  arbitration/witness model from underneath. Whatever zkVM Bloom adopts (Ligero/Ligetron
  or otherwise) should be evaluated on soundness evidence, not just performance, and
  treated as a long-horizon verification target in its own right.

### 5.4 Reality check on LLM-synthesized invariants

The whitepaper cites Wei et al. 2025 and bets that "LLMs continue to improve" at invariant
synthesis. The honest current state (InvBench, the same line of work): **LLM-based
invariant synthesis does not yet beat state-of-the-art symbolic tools** such as
UAutomizer, though fine-tuning and best-of-N sampling give measurable gains. This does not
undermine Bloom's thesis — agents proposing invariants for humans to ratify is valuable
even if imperfect — but it argues strongly that **Bloom must machine-check invariants
rather than trust their provenance.** An agent-proposed invariant is a hypothesis; the VM,
the replay witness, and (optionally) a prover are what make it trustworthy. Design the
invariant pipeline so that who or what wrote the invariant is irrelevant to whether its
breakage can be objectively demonstrated.

### 5.5 Tool-fit summary

| Tool | Best Bloom use | Rung | Maturity / caveat |
|------|----------------|:----:|-------------------|
| Bloom VM admission/executor | Protocol invariants, effect/linearity/import rules | 1 | In-house; already strongest asset |
| Bloom runtime `#[invariant]` | Human-authored arbitrable specs | 2 | To build; predicate language undefined |
| Canonical witness object | Arbitration evidence | 3 | To build |
| Kani | DEX math, codecs, fuel arithmetic, parsers | 4 | Mature; bounded; great first pilot |
| Verus | Borrow-table state machine, resource accounting | 4 | Rust subset; SMT instability |
| Creusot/Prusti/Flux | Function contracts, overflow/panic freedom | 4 | Coverage varies |
| hax → F\*/Rocq | PQ crypto, hashing, canonical codecs | 4 | Strong for crypto; subset only |
| Move/Sui Prover (model) | Spec-language design template | 2/4 | Borrow ideas, not the language |
| Lean/Coq/Isabelle | Flagship theorems (AMM, sqrt, PTB model) | 4 | Highest rigour, lowest ergonomics |
| WasmCert / WasmRef | Long-term Wasm semantics grounding | 4 | Engine (Wasmtime) still unverified |

---

## 6. What needs to change, and where to start designing

This is background reasoning to inform several months of work by several people, not a
task list. The ordering reflects leverage: finish what makes the whitepaper's core promise
real before reaching for proof assistants.

### 6.1 Make the manifest the canonical petal contract (foundation for everything)

Every rung reads from the manifest, so it should be the first object machines and humans
inspect. Extend it toward a complete contract per petal version: per-function effect class
(Pure/View/Mutating), object access modes, required capabilities and signers, return
TypeTags, attached invariants (name + machine predicate + human text), declared
dependencies and their interface hashes, fuel ceilings, allowed host imports, and optional
proof-artifact references. Much of this exists piecemeal (the view flag, invariant decls,
TypeTags); the design work is consolidating it into one versioned, hashable contract that
the witness object (§6.4) can reference. This is low-risk and unblocks the rest.

### 6.2 Finish runtime invariants end to end — the priority

Turn the `return 1` stub into a real predicate path, and prove the whole pipeline on one
concrete invariant (the obvious candidate: `pool_k_non_decreasing` — `reserve_a *
reserve_b` non-decreasing across a swap — since the AST shape is already half-recognised
and the math kernel already exists). The design questions that must be answered to do this
at all:

- **Scope model.** Most interesting invariants are about before vs. after a mutation (k
  non-decreasing, supply conservation). The current projection has no rich argspec. Bloom
  needs to define what "scope bytes" an invariant sees: the prior and posterior object
  payloads, function args, return values, and which of these are available at which
  trigger point.
- **Trigger points.** After function exit only, or also after each object mutation?
  Per-object invariants likely want the latter; the Move Prover's "check immediately after
  touching the resource" is the reference behaviour.
- **Predicate representation.** This is a genuine fork in the road (see §7): a
  Bloom-defined tiny spec language (machine-readable, restricted, easy to reason about and
  to render for arbitration) vs. compiling user Rust closures to `__inv_` Wasm (ergonomic
  but opaque to governance). The pragmatic answer is probably both: a restricted predicate
  AST that covers the common comparisons/conservation shapes and renders to human text,
  with an opaque Wasm-closure escape hatch that is still replayable but harder to
  adjudicate.
- **Fuel and receipts.** Invariant evaluation must be metered like everything else, and
  its result (pass/fail + which invariant) should appear in the receipt/trace even on
  success, so the witness object can cite it.

### 6.3 Promote the protocol invariants that are still implicit

A handful of Rung-1 properties are designed but not yet enforced as hard, non-optional
admission/execution checks: dependency hash-pinning, dependency ABI/interface-hash match
on cross-petal calls, return-bytes-match-declared-TypeTag, and the "no historical snapshot
in committed execution" rule (currently a property of the view path's structure rather
than an explicit committed-path check). Making these explicit and tested is cheap relative
to their value and strengthens the supply-chain story directly.

### 6.4 Design the canonical witness object

Pruning is only as neutral as the evidence it adjudicates. Designing the content-addressed
witness (§4 Rung 3) early — even before invariants are rich — pays off because it forces
clarity about what a replay must reproduce (state root, inputs, fuel, effect set, trace)
and therefore about what determinism guarantees the chain must make. It also gives the
eventual arbitration UI/governance a stable schema to build on, and cleanly separates
"predicate failed" from "assertion was vague."

### 6.5 Pilot Kani on `bloom-dex-math`

This is the cheapest possible win and a template for proof-carrying petals. The kernel is
already pure and property-tested; promoting `quote` (never returns `>= reserve_out`),
`apply_swap` (preserves nonzero reserves; k non-decreasing modulo fee), `fee_bps >=
10_000` rejection, and `integer_sqrt` correctness from tests to Kani harnesses establishes
the workflow (CI integration, counterexamples, proof artifacts) on a target where success
is near-certain. Verus or Creusot become worthwhile only if a property genuinely needs
unbounded proof. Lean/Coq only if the AMM math becomes a flagship.

### 6.6 Decide the determinism and equivalence questions deliberately

Two longer-horizon design decisions block the strongest guarantees and should be put on the
roadmap explicitly rather than drifting:

- **Determinism hardening.** Chain mode canonicalizes NaNs but still allows floats and
  standard SIMD. For consensus replay and zk-provability, consider whether chain-mode
  petals should reject floats entirely (integer-only is dramatically easier to make
  deterministic and to prove about), and whether the Wasm engine version should be
  consensus-pinned so two honest nodes cannot diverge.
- **The source-to-Wasm equivalence gap.** A Kani/Verus proof about Rust source only
  transfers to the deployed Wasm if compilation is trusted or equivalence is established.
  Decide the smallest acceptable story: trusted-toolchain assumption with reproducible
  builds, differential testing between source and Wasm, or (long term) proof against
  mechanized Wasm semantics. Related: how much of the Rust macro heuristic layer (e.g.
  "CamelCase means object-like") must be replaced by explicit annotations before any
  source-level proof is credible.

### 6.7 Sequencing sketch (leverage order, not deadlines)

> **Superseded — see the single canonical forward-plan.** This early sketch has been folded
> into and replaced by the leverage order in [`02-architecture.md`](02-architecture.md) §9
> ("Where to start"), which is the **one** place the build sequence now lives. The open
> *design questions* to resolve along the way are tracked in
> [`03-open-questions.md`](03-open-questions.md). Don't maintain a third copy here.

---

## 7. Open questions for the team

These are genuine forks where the research does not dictate an answer; they should be
decided before committing to the invariant build.

> **Proposed resolutions to all eight are in [`02-architecture.md`](02-architecture.md);
> their live status is tracked in [`03-open-questions.md`](03-open-questions.md).**

1. Should Bloom **define its own tiny specification language**, or overload Rust closures
   in `#[invariant(pred = ...)]`? (The recommendation leans toward a restricted,
   human-renderable AST plus an opaque-closure escape hatch — but this is the most
   consequential decision and deserves its own design.)
2. Should invariant predicates be **pure Wasm functions, manifest-level expressions, or
   both** — and how is a predicate's evaluation itself constrained (no mutation, bounded
   fuel, deterministic)?
3. How are **human-readable assertions linked to machine predicates** so governance can
   cleanly distinguish "the predicate failed" from "the assertion was too vague"? This is
   the mechanism behind the whitepaper's "indeterminate outcome / propose a better
   invariant."
4. Should chain mode **reject floats entirely**, despite NaN canonicalization, to simplify
   determinism and formal reasoning?
5. Should the **Wasm engine version be consensus-pinned** for chain-mode replay?
6. What is the **smallest proof-carrying interface** that boosts score/trust without
   forcing ordinary petal authors into proof assistants? Should proof artifacts be
   content-addressed under `/bloom/<path>/proofs/<hash>` and feed the trust score?
7. How is the **source-to-Wasm equivalence gap** handled for any Rung-4 proof — trusted
   toolchain, differential testing, or mechanized-semantics proof?
8. What **soundness bar must the chosen zkVM meet**, given that ~96% of zkVM bugs
   historically break soundness via underconstraint, and an unsound prover defeats
   arbitration from underneath?

---

## 8. Tentative conclusion

The current petal design is well-positioned for the kind of verification the whitepaper
wants — more so than a generic Wasm-plugin system — because it has already converged on a
Move-like resource model with deterministic chain-mode execution, content-addressing, an
explicit manifest, and statically-checkable view purity. The borrow table and admission
checks are real, enforced, source-language-independent guarantees today.

The decisive gap is that **invariants — the whitepaper's most important human artifact —
do not yet evaluate anything.** The highest-leverage work is therefore not choosing an
external proof language; it is (1) finishing the runtime-invariant path end to end on one
concrete property, (2) consolidating the manifest into the canonical petal contract, and
(3) designing the canonical replay witness that makes pruning credibly neutral. External
formal tools — Kani first, on the already-verification-ready DEX math — should be adopted
selectively for small, high-value, pure kernels, and only become broadly valuable once
Bloom has stable kernels and stable manifest semantics to prove against. The harder,
longer-horizon truths the team should plan around are the unverified Wasm engine and the
zkVM soundness assumption that sit underneath the whole stack.

**In one line:** build the ladder, start the climb at the invariant rung, and don't trust
a proof about source code more than the Wasm and zkVM it actually runs on.

---

## Appendix: sources

**Implementation (local repo, `bloom/`):**

- `crates/bloom-petals/src/chain_vm.rs` — chain engine config,
  import/export/memory/opcode admission, view-purity verifier, object host imports
- `crates/bloom-script/src/borrow_table.rs` — resource borrow table, diff/linearity checks
- `crates/bloom-resource-macros/src/invariant.rs` — `#[invariant]` parsing and predicate
  AST
- `crates/bloom-resource-macros/src/codegen.rs` — `__inv_<idx>` shim (`return 1` stub)
- `examples/petal-dex/crates/bloom-dex-math/src/lib.rs` — pure CPMM math kernel
- `docs/specs/2026-05-18-petals-design.md`, `docs/specs/2026-05-26-typed-cross-petal-calls.md`,
  `docs/superpowers/specs/2026-05-29-view-functions-design.md`
- `thread/bloom-whitepaper.pdf` — *Bloom: A self-governing growth system for humans and
  agents*

**External research:**

- Kani Rust Verifier — attributes, loop unwinding, function contracts:
  <https://model-checking.github.io/kani/>;
  <https://model-checking.github.io/kani-verifier-blog/2024/01/29/function-contracts.html>;
  <https://github.com/model-checking/kani/releases>
- Verifying the Rust standard library with Kani (AWS):
  <https://aws.amazon.com/blogs/opensource/verifying-the-safety-of-the-rust-standard-library/>
- Verus — Verifying Rust Programs using Linear Ghost Types:
  <https://dl.acm.org/doi/10.1145/3586037>; <https://github.com/verus-lang/verus>
- Move Specification Language (Aptos):
  <https://aptos.dev/build/smart-contracts/prover/spec-lang>
- Securing the Aptos Framework through formal verification:
  <https://medium.com/aptoslabs/securing-the-aptos-framework-through-formal-verification-14124d1ed660>
- Fast and Reliable Formal Verification of Smart Contracts with the Move Prover:
  <https://arxiv.org/pdf/2110.08362>
- Sui Prover goes open source:
  <https://blockeden.xyz/blog/2026/01/20/sui-prover-formal-verification-smart-contract-security-move/>
- WasmCert / Two Mechanisations of WebAssembly 1.0:
  <https://vtss.doc.ic.ac.uk/publications/WasmCert>
- Progressful Interpreters for Efficient WebAssembly Mechanisation (Wasm 2.0):
  <https://dl.acm.org/doi/10.1145/3704858>
- InvBench: Can LLMs Accelerate Program Verification with Invariant Synthesis?
  <https://arxiv.org/abs/2509.21629>
- hax (Cryspen) — verifying security-critical Rust with multiple provers:
  <https://eprint.iacr.org/2025/142>; <https://github.com/cryspen/hax>
- RISC Zero — path to the first formally verified RISC-V zkVM:
  <https://risczero.com/blog/RISC-Zero-formally-verified-zkvm>
- Veridise on RISC Zero zkVM security (underconstrained bugs):
  <https://veridise.com/blog/audit-insights/risc-zeros-zk-vm-security/>
- Towards formal verification of the first RISC-V zkVM (Nethermind, Lean):
  <https://www.nethermind.io/blog/towards-formal-verification-of-the-first-risc-v-zkvm>
