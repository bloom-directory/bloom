# Verification Artifact Schema Patterns

**Date:** 2026-05-29
**Status:** Research survey — informs Bloom's `VerificationClaim` schema
**Audience:** Bloom engineers designing the invariant/persistence layer
**Prerequisites:** [`01-background-research.md`](01-background-research.md) §4 (the ladder), [`02-architecture.md`](02-architecture.md) §4 (canonical witness), ADR-006 (proof artifacts)

---

## Contents

1. [Motivation and methodology](#1-motivation-and-methodology)
2. [System 1 — Certora / CVL rules](#2-system-1--certora--cvl-rules)
3. [System 2 — DeepSEA certificate format](#3-system-2--deepsea-certificate-format)
4. [System 3 — CompCert assembly_semantic_preservation](#4-system-3--compcert-assembly_semantic_preservation)
5. [System 4 — Theorem-Carrying Transactions (TCT)](#5-system-4--theorem-carrying-transactions-tct)
6. [System 5 — Move Prover spec versioning](#6-system-5--move-prover-spec-versioning)
7. [System 6 — Bug bounty finding classification models](#7-system-6--bug-bounty-finding-classification-models)
8. [System 7 — F* / HACL* verification pipeline](#8-system-7--f--hacl-verification-pipeline)
9. [Cross-cutting pattern extraction](#9-cross-cutting-pattern-extraction)
10. [Bloom schema recommendation](#10-bloom-schema-recommendation)

---

## 1. Motivation and methodology

Bloom treats invariants, proofs, counterexamples, and witnesses as first-class, versioned,
curatable objects — not as ephemeral CI outputs. To design a schema that can persist,
version, supersede, and challenge these objects, we survey how seven existing verification
systems structure their artifacts.

For each system we answer four questions:

- **(a) Data structure:** What fields anchor the artifact to source, deployment, and witness?
- **(b) Assumptions:** How are assumptions made explicit rather than ambient?
- **(c) Versioning and supersession:** How are artifacts versioned? What happens when
  one artifact replaces another?
- **(d) Challenge and invalidation:** How is a claim disputed, refuted, or invalidated?

From these we extract cross-cutting patterns and derive a concrete `VerificationClaim`
schema for Bloom, with each field's rationale traceable to one or more studied systems.

---

## 2. System 1 — Certora / CVL rules

Certora's CVL (Certora Verification Language) is the closest production analog to Bloom's
`#[invariant]` predicates: named, declarative rules checked by an SMT-backed prover at
development time. While Certora rules are not on-chain objects, their structure illuminates
what a named verification claim must carry.

### (a) Data structure and anchoring

A CVL rule is a named entity in a `.spec` file. Its fields:

- **`rule` name** — a unique identifier within the specification file (e.g., `rule checkKNonDecreasing(uint256 amount)`)
- **`using` / contract interface declaration** — binds the rule to specific contract methods,
  storage variables, and their types. This is the *subject binding*: it declares which
  contract's state the rule operates over, analogously to `InvariantTarget` in Bloom
  (`types.rs:186`).
- **`env` block** — captures the transaction environment (msg.sender, block.timestamp,
  etc.). These are ambient assumptions the rule relies on.
- **Method references** — CVL rules invoke contract methods as symbolic steps
  (e.g., `swap(amount)` at `env`). The rule is parameterized by method arguments, which become
  the rule's input scope.
- **Assertions** — `assert`, `require`, and `satisfy` statements that form the claim body.
  `require` statements are preconditions (the rule only applies when they hold); `assert` and
  `satisfy` are the property being proved.
- **`invariant` keyword** — CVL distinguishes `rule` (checked for one transaction) from
  `invariant` (checked across all methods that touch the relevant storage). This maps to
  Bloom's `InvariantTarget::ObjectType` vs. `FunctionExit` distinction.
- **Counterexample** — when a rule fails, the Prover emits a counterexample: a concrete
  call trace (sequence of method invocations with argument values) that drives the
  assertion false. This counterexample is the *witness of failure*.
- **Vacuity check** — Certora also reports when a rule is vacuously true (the precondition
  is never satisfiable), which is a distinct quality signal.

**Minimal anchor fields extracted:** `{rule_name, subject_contract_hash, method_references,
preconditions[], assertions[], counterexample_trace}`.

### (b) Assumptions

CVL makes assumptions explicit through:

- **`require` statements** — explicit preconditions that scope the rule. If the require
  fails, the rule is vacuously satisfied (trivially true), and Certora flags this.
- **`env` block** — immutable transaction context assumptions (sender, timestamp,
  block number). These are *ambient* but declared — the rule reader knows the rule only
  holds under the stated env constraints.
- **`invariant` filter methods** — an invariant can declare a `filter` function whose
  return value gates whether the invariant is checked. This is an explicit correctness
  assumption: "I assume this filter correctly identifies states of interest."
- **Ghost variables and summaries** — CVL supports `ghost` variables (spec-level state not
  present in the contract) and method summaries (approximations of external calls). Both
  are assumptions about the verification model: the rule holds assuming the summary
  correctly characterizes the external contract, and assuming the ghost state is maintained
  atomically.

**Key lesson for Bloom:** Every assumption a predicate depends on must be a declared,
checkable field — not an ambient TCB property. CVL's vacuity detection (a rule that is
vacuously true due to an unsatisfiable require) is a quality signal Bloom should adopt.

### (c) Versioning and supersession

Certora does not version rules as first-class objects — rules live in spec files in git
alongside contracts. Versioning is therefore implicit in three layers:

1. **Git commit hash** — the spec file at a given commit binds rules to the contract
   source at that commit. A rule's identity is `(spec_file_hash, rule_name)`.
2. **CI run ID** — each Certora Prover run produces a job with a unique ID, binding
   `(rule, contract_version, prover_version, result)`. Past runs are queryable but not
   typically linked to future runs.
3. **Spec evolution** — rules are refactored, split, or deleted in subsequent commits.
   There is no formal "this rule supersedes that rule" link; it must be inferred from
   git history.

**The "spec correctness problem" and Gambit:** The core question "is the spec correct,
or just passing?" is addressed by **Gambit**, Certora's mutation testing tool. Gambit
introduces mutations (small bugs) into the contract and re-runs the spec. If a mutated
contract still passes, the spec is too weak to catch that class of bug. Gambit produces a
**mutation score** — the fraction of mutations the spec killed — which is a quantitative
measure of spec quality.

Gambit treats the spec as an object under test: the spec's "correctness" is measured by
its sensitivity to injected faults in the contract. This is structurally similar to
Bloom's proposed Rung 3 (adversarial fuzzing) — both test the predicate against hostile
inputs rather than trusting the prover's verdict.

**Key lesson for Bloom:** A mutation score or adversarial-coverage metric should accompany
every verification claim. A claim that kills 0/100 mutations is low-quality regardless of
prover verdict.

### (d) Challenge and invalidation

CVL rules are invalidated by:

- **Counterexample from the Prover** — a concrete trace that violates an assertion. This
  is the objective path: the prover found inputs that break the rule. The counterexample
  is a re-executable witness.
- **Vacuity** — the rule is true only because its precondition is never satisfied. The
  prover reports this; the remediation is to strengthen the precondition or admit the rule
  is meaningless.
- **Spec bug** — the rule passes but does not encode the author's intent. Gambit catches
  some of these; code review catches others. This is the *spec↔intent conformance gap*
  that ADR-003's intent-conformance gate addresses.
- **Contract upgrade** — if the contract changes, old rules must be re-run against the new
  code. No automatic invalidation; this must be done in CI.

---

## 3. System 2 — DeepSEA certificate format

DeepSEA (Park et al., 2021) is a certified DeFi framework: a Coq-verified compiler from a
high-level specification language (DeepSEA) to EVM bytecode. The key architectural
innovation relevant to Bloom is that **the compiler is not in the trusted computing base
(TCB)** — the proof certificate it emits can be independently checked, so a buggy compiler
cannot produce a false guarantee.

### (a) Data structure and anchoring

The DeepSEA certificate binds five artifacts:

1. **DeepSEA source program** — the human-written specification + implementation in
   DeepSEA's language. Anchored by content hash.
2. **Specification statement** — a Coq theorem statement of the form "for all initial
   states satisfying P, the compiled bytecode produces a final state satisfying Q."
   This is the *claim*.
3. **EVM bytecode** — the compiled output. Anchored by keccak256 hash (the natural
   content address on Ethereum).
4. **Proof term** — a Coq proof object (a λ-term) that witnesses the theorem. This is
   the *proof artifact*.
5. **Coq kernel version** — the exact version of the Coq proof checker that validates the
   proof term. Since Coq's kernel is the TCB, its version must be recorded.

**How the anchoring works structurally:** The Coq theorem `∀ source. compiled(source) = bytecode → behavior(source) <≈> behavior(bytecode)` takes the concrete source and bytecode as
arguments. The certificate is the instantiation of this theorem with the specific source
and bytecode hashes + the proof that `compiled(source) = bytecode`. Anyone with access to
those hashes and a compatible Coq kernel can re-verify the certificate.

**The "dsc tool is not in the TCB" property:** This is possible because dsc emits a proof
that is checked by Coq's small (~400-line) kernel. If dsc has a bug and generates
incorrect bytecode, it will either (a) emit a proof of `compiled(source) = bytecode` that
Coq rejects (the compilation-and-proof step failed), or (b) emit bytecode that doesn't
match the `compiled(source)` relation at all (the certificate references the wrong bytes).
The TCB is Coq's kernel, not dsc.

This is the PCC (proof-carrying code) model that ADR-006 ranks as the highest tier.

**Minimal anchor fields extracted:** `{source_hash, spec_statement, bytecode_hash,
proof_term_hash, checker_name, checker_version}`.

### (b) Assumptions

DeepSEA certificates make assumptions explicit at two levels:

- **The Coq specification itself** declares assumptions as hypotheses of the theorem. For
  example: "assuming the initial gas is sufficient" or "assuming storage slot X is
  initially zero." These are part of the theorem statement and are visible in the
  certificate.
- **The trusted base is explicitly enumerated.** The DeepSEA paper lists exactly what is
  in the TCB: Coq's kernel, the EVM operational semantics (formalized in Coq), the
  arithmetic libraries, and the linking process. This explicit TCB declaration is itself a
  schema field: every certificate declares what it trusts.

**Key lesson for Bloom:** The certificate must carry its own TCB declaration as a field.
A proof artifact that doesn't declare its trusted base has ambiguous value.

### (c) Versioning and supersession

DeepSEA certificates are not versioned within the certificate format — each certificate is
a one-shot object binding a specific `(source, bytecode, spec)` triple. Versioning arises
from the development process:

- A new source version produces a new certificate.
- The old certificate is not invalidated — it remains a valid statement about the old
  bytecode.
- The relationship between old and new certificates is external (git history), not encoded
  in the certificate.
- Critically, the **bytecode hash** is a natural *revocation anchor*: if the deployed
  bytecode changes, no certificate referencing the old hash applies to the new deployment.

### (d) Challenge and invalidation

A DeepSEA certificate can be challenged or invalidated by:

- **Specification bug** — the theorem statement is true but doesn't encode the property
  anyone cares about. A human reviewer must identify this; there is no automated challenge
  path.
- **Checker bug** — a bug in Coq's kernel (extremely rare, but theoretically possible)
  could accept a false proof. This would require a Coq kernel CVE.
- **Bytecode mismatch** — if the deployed bytecode's hash does not match the certificate's
  `bytecode_hash`, the certificate does not apply. This is an automatic, mechanical check
  — Bloom's equivalent would be comparing `certificate.bytecode_hash` to the on-chain
  `petal_hash`.
- **EVM semantics mismatch** — if the real EVM's behavior diverges from the formalized EVM
  semantics in Coq, the proof holds only for the formal model, not the real chain. This is
  the *semantics gap* problem that Bloom faces with Wasm semantics and zkVM soundness.

---

## 4. System 3 — CompCert assembly_semantic_preservation

CompCert (Leroy, 2008–present) is a verified C compiler with a machine-checked Coq proof
that the compiled assembly preserves the semantics of the C source. Unlike DeepSEA, which
emits per-compilation certificates, CompCert's proof is a single theorem over the compiler
pipeline — but the certificate structure is still instructive.

### (a) Data structure and anchoring

The CompCert correctness theorem `transf_c_program_preservation` has these components:

1. **C source program** — the input AST (abstract syntax tree) in CompCert Clight
   (a deterministic, side-effect-free subset of C). Anchored by the source file content.
2. **Assembly program** — the output AST in CompCert Asm (the target assembly language).
   Anchored by the assembly file content.
3. **Compiler passes** — the ordered list of compiler passes applied (e.g., Cshmgen →
   Cminorgen → Selection → RTLgen → …). This is part of the proof's induction structure:
   each pass's correctness lemma composes transitively.
4. **Configuration flags** — compilation options (optimization level, target architecture,
   etc.) that affect which passes run and how.
5. **Observable behaviors** — CompCert defines "behavior" as the trace of externally
   observable events (system calls, volatile reads/writes, program termination status).
   The proof says: if the C source has behavior X (or undefined behavior), the assembly
   has behavior Y such that Y is *at least as good as* X (it may improve on undefined
   behavior, but it never introduces new defined behaviors that contradict the source).
6. **The proof term** — a Coq proof object that is type-checked by Coq's kernel.

**How the proof anchors to specific artifacts:** The theorem is generic — it holds for
any C program `p` compiled with any pass configuration `cfg`. To get a concrete
certificate for a specific compilation, you instantiate `p := <concrete AST>` and
`cfg := <-O1, ARMv7, …>` and apply the generic theorem. The certificate is
parameterized by content hashes of the source and assembly, making it a concrete,
checkable artifact rather than a generic claim.

**Minimal anchor fields extracted:** `{source_hash, assembly_hash, compiler_version,
pass_chain, config_flags, proof_term_hash, checker_version}`.

### (b) Assumptions

CompCert's assumptions are part of the theorem statement itself:

- **Defined behavior assumption** — the theorem only guarantees semantic preservation for
  programs with *defined* behavior. If the C program has undefined behavior (e.g., signed
  overflow, out-of-bounds access, use-after-free), CompCert may produce assembly with
  *any* behavior. This is not a CompCert bug — it is a stated assumption documented in the
  theorem's hypotheses. The practical consequence: **to trust a CompCert certificate, you
  must independently verify that the source program has no undefined behavior.**
- **Memory model** — CompCert assumes a specific flat memory model (no separate address
  spaces, aligned accesses, etc.).
- **External calls** — external (system) calls are assumed to respect certain axioms
  (they must not modify CompCert-visible state arbitrarily).
- **Linking** — the theorem assumes the assembly is linked with a correct runtime
  (CompCert provides a verified runtime for some targets).

**Key lesson for Bloom:** The certificate must carry an explicit `assumptions` block.
CompCert's "defined behavior assumption" is a clean example: a proof is only as strong as
its weakest assumption, and assumptions that are easy to violate accidentally (like "no
undefined behavior") must be surfaced prominently. Bloom's equivalent is the
source→Wasm equivalence gap: a Kani proof about Rust source assumes the Rust compiler
correctly compiles to Wasm. That assumption must be a declared field in the claim, not an
unstated premise.

### (c) Versioning and supersession

CompCert uses explicit semantic versioning:

- Each CompCert release (3.0, 3.1, …, 3.14) is a distinct artifact with a published
  changelog. A certificate produced by CompCert 3.12 carries that version number.
- A new CompCert release may add passes, fix bugs in existing passes (invalidating old
  proofs), or extend the supported C subset.
- Old certificates remain checkable if you retain the old CompCert version + its
  Coq proofs. But a new CompCert version does not retroactively invalidate old
  certificates — it just means new compilations use the newer (hopefully better) proof.

**Key lesson for Bloom:** The toolchain that produced a claim is a versioned part of
the claim. A `ProofArtifact` must record `{tool_name, tool_version, tool_attestation_hash}`
so that a challenger knows which toolchain to evaluate.

### (d) Challenge and invalidation

CompCert claims are invalidated by:

- **Source undefined behavior** — if the C program has UB, the theorem's hypothesis is
  violated and the certificate is void. Tools like Frama-C or Kani can independently
  verify UB-freedom; the certificate should reference such an audit.
- **Coq kernel bug** — as with DeepSEA, a kernel bug could accept a false proof.
- **CompCert bug** — historically, bugs have been found in CompCert's value analysis and
  register allocation passes (e.g., via Csmith fuzzing). A bug in a compiler pass means
  that pass's correctness lemma does not hold, and the entire compositional proof is
  unsound. The fix is a new CompCert release. Old certificates compiled by the buggy
  version are potentially invalid — but only if the bug manifests in that specific
  compilation. This is a *conditional invalidation*: a certificate is invalid iff the
  bug's trigger condition exists in the source.
- **Mismatched semantics** — if the real hardware's behavior diverges from CompCert's Asm
  semantics (e.g., due to a CPU errata), the certificate does not hold on that hardware.

---

## 5. System 4 — Theorem-Carrying Transactions (TCT)

TCT (arXiv:2408.06478) moves verification from design-time to runtime: each blockchain
transaction carries a "theorem" proving that the transaction's state transition preserves
a set of invariants. This is the model closest to Bloom's Rung 2 runtime invariants with a
proof upgrade path.

### (a) Data structure and anchoring

A TCT theorem object carries:

1. **Theorem statement** — a logical formula (in the runtime's assertion language)
   asserting a post-condition given a pre-condition. Example: "if balance[x] ≥ amount
   before the transaction, then balance[x] ≥ 0 after."
2. **Code hash binding** — the theorem is bound to a specific contract code hash. This
   is the critical anchoring field: the theorem only applies when `hash(deployed_code) ==
   theorem.code_hash`. If the contract is upgraded, the theorem no longer applies.
3. **Proof** — a machine-checkable proof object (compact, suitable for inclusion in a
   transaction). The paper uses an SMT-friendly encoding so the runtime can re-validate
   with a lightweight checker.
4. **Pre-state constraint** — the theorem declares what conditions must hold in the
   pre-state for the theorem to apply. These are not "assumptions we hope are true" —
   the runtime *validates* them against the current state before accepting the
   transaction.
5. **Transaction payload** — the actual state mutation (function call + arguments). The
   theorem covers this specific payload.

**Runtime validation flow:**
1. Read `theorem.code_hash`. Assert it equals `hash(deployed_code)`. Reject if mismatch.
2. Read `theorem.pre_state_constraints`. Evaluate each constraint against the current
   chain state. Reject if any constraint is false.
3. Verify `theorem.proof` against `theorem.statement` using the runtime's SMT checker.
4. Execute the transaction payload.
5. Evaluate `theorem.post_state_claim` against the resulting state. Reject if false.

If any step fails, the transaction is rejected before commit — preventing the bad state.

**Minimal anchor fields extracted:** `{theorem_statement, code_hash, proof_object,
pre_state_constraints[], post_state_claim, transaction_payload_hash, runtime_check_result}`.

### (b) Assumptions

TCT is notable because **assumptions are not optional or ambient — they are enforced at
runtime.** The `pre_state_constraints` are assumptions that the runtime validates. If a
constraint fails, the transaction is rejected. This is the ideal model for Bloom: every
assumption a predicate makes about its input state must be a checkable field the executor
validates before evaluating the predicate.

Additional ambient assumptions:

- **Checker correctness** — the runtime's SMT checker must correctly verify proofs.
- **Gas metering** — proof verification consumes gas and must be bounded.
- **SMT soundness** — the SMT solver's results are trusted. TCT mitigates this by using a
  small, auditable checker rather than a full SMT solver where possible.

### (c) Versioning and supersession

TCT's versioning is entirely code-hash-driven:

- A theorem is bound to `code_hash`. When the contract is upgraded, `code_hash` changes,
  and all existing theorems become inapplicable. New theorems must be produced for the
  new code.
- There is no concept of "theorem versioning" — theorems are stateless, single-use
  objects attached to transactions. They are not persisted as curatable artifacts.
- **Bloom extension:** Bloom would benefit from persisting theorems as versioned objects
  that can be superseded. A theorem proven for Petals v1 might be *updated* for a later schema rather
  than discarded — the update itself is a curation action.

### (d) Challenge and invalidation

A TCT theorem is invalidated at runtime:

- **Code hash mismatch** — mechanical, immediate.
- **Pre-condition violation** — the pre-state constraints don't hold. The transaction is
  rejected before execution.
- **Failed proof check** — the runtime SMT checker rejects the proof. The transaction
  is invalid.
- **Post-condition violation** — even if the proof checks, runtime re-evaluation of
  the post-condition against actual state may reveal a mismatch (e.g., due to an
  unmodeled effect like reentrancy). This is the *proof gap* — the proof covers a model
  that may not be faithful to the real execution.

---

## 6. System 5 — Move Prover spec versioning

The Move Prover (Aptos/Sui) is the production system structurally closest to Bloom's
invariant model: it has named specification blocks attached to on-chain modules, with
machine-checked properties that are versioned alongside the code.

### (a) Data structure and anchoring

Move `spec` blocks are embedded in the Move source file and carry:

1. **Spec kind** — `spec fun` (function pre/post), `spec struct` (struct invariant),
   `spec module` (global/module invariant), `spec schema` (reusable spec block).
2. **Target binding** — for function specs: the function name, its parameter types, and
   return type. For struct invariants: the struct name and field types. For global
   invariants: the module and resource type. This is the subject anchor.
3. **Pre-conditions (`requires`)** — conditions that must hold when the function is
   called or the invariant is checked. Corresponds to TCT's pre-state constraints.
4. **Post-conditions (`ensures`)** — conditions that must hold after execution.
5. **Abort conditions (`aborts_if`, `aborts_with`)** — conditions under which the
   function is expected to abort. These are *negative* claims: "the function must abort
   if X, and must not abort if Y."
6. **Modifies clauses (`modifies`)** — declares which global state the function may
   change. An invariant can reference a specific resource and the prover verifies that
   only functions declaring `modifies <resource>` can change it.
7. **Data invariants** — `invariant` on a struct: the property holds after construction
   and after every mutation of that struct (any function that writes to a field of the
   struct must prove the invariant is preserved).
8. **Update conditions** — global invariants can have `update` conditions specifying
   when the invariant must be re-checked (e.g., `update [global] after <event>`). This
   controls the *trigger granularity* — the Move Prover does not re-check every invariant
   on every instruction; it checks only when a relevant resource is touched.

**How specs anchor to bytecode:**
Move specs are part of the Move source, and the source compiles to bytecode. The spec is
not embedded in the bytecode directly, but the prover can verify that the bytecode
satisfies the spec. The critical structural point: **the spec is a separate artifact from
the bytecode, anchored by the module address and name.** This is the model Bloom should
adopt: the claim (spec/invariant) is a content-addressed object that *points to* the
subject (petal/bytecode) rather than being embedded in it.

**Minimal anchor fields extracted:** `{spec_kind, target_module, target_function_or_struct,
pre_conditions[], post_conditions[], abort_conditions[], update_trigger, modifies_set}`.

### (b) Assumptions

The Move Prover makes several assumptions explicit:

- **Module-level requires** — function preconditions are checked at every call site. The
  prover assumes callers satisfy them; the runtime enforces them.
- **Invariant suspension** — some invariants can be *suspended* during internal
  operations (e.g., a pool invariant may be temporarily violated mid-swap before being
  restored). The spec must explicitly declare when an invariant is suspended and when
  it is re-enabled.
- **Pragma declarations** — specs can declare pragmas that affect verification (e.g.,
  timeout, verification-depth, disable-invariants-in-fun). These are ambient assumptions
  that narrow the verification scope — they must be documented.
- **Ghost state** — the spec may reference `global` ghost variables that do not exist in
  the compiled bytecode. These are spec-level abstractions; the prover verifies they are
  used consistently, but they are not present in the runtime artifact.

### (c) Versioning and supersession

Move handles spec versioning through module upgrades:

- **Specs are part of the module source, versioned with it.** When a module is upgraded
  (from address `A::M` v1 to `A::M` v2), the spec blocks are upgraded along with the
  code. The old module and its specs remain accessible at their historical address.
- **Old specs remain checkable** — the Move Prover can be run against v1 of the module
  source. Old spec versions are not deleted; they are historical artifacts.
- **No explicit "supersedes" link** — v2's spec blocks replace v1's, but there is no
  formal declaration that "v2's pool invariant supersedes v1's." This is a gap Bloom
  should fill: an invariant should carry an optional `supersedes` field pointing to the
  previous version's content hash.
- **Compatibility rules** — Move module upgrades must follow compatibility rules (no
  breaking changes to public function signatures, no storage layout changes that would
  invalidate old data). Spec blocks are not part of the compatibility check — a new
  spec can be completely different from the old one, and there is no machine check that
  the new spec is "at least as strong as" the old spec. This is a governance concern.

**Key lesson for Bloom:** Specs should be versioned as first-class objects, not just
as lines in a source file. A `spec_version` field and an explicit `supersedes →
prev_spec_hash` pointer enable curation decisions (e.g., merging two invariants into one,
splitting one into two, strengthening).

### (d) Challenge and invalidation

Move Prover specs are challenged through:

- **Prover counterexample** — if the prover finds inputs that violate a post-condition or
  invariant, it reports a counterexample (concrete values for function arguments and
  initial state). This is analogous to Certora's counterexample trace.
- **Timeout** — the prover may fail to prove or disprove a property within the time
  budget. This is an *indeterminate* outcome — the property is neither proved nor
  refuted.
- **Specification upgrade** — a newer module version may carry a completely different
  or incompatible spec set. The community must notice this and evaluate whether the new
  specs are acceptable.
- **Vacuous spec** — a spec with unsatisfiable preconditions is trivially satisfied. The
  Move Prover does not report vacuity as clearly as Certora does; this is a quality
  signal Bloom should adopt.

---

## 7. System 6 — Bug bounty finding classification models

Immunefi, Code4rena, and Sherlock classify and lifecycle-manage security findings. While
their findings are prose reports (not machine-checked claims), their classification
schemas and lifecycle state machines are directly relevant to Bloom's challenge and
curation model.

### (a) Data structure and anchoring

A finding report across the three platforms carries these fields:

**Core identity fields:**
- `finding_id` — unique identifier within the contest/program
- `contest_id` / `program_id` — the specific security review this finding belongs to
- `submitter` — the researcher who submitted the finding (pseudonymous address)
- `submitted_at` — timestamp or block number

**Subject binding:**
- `target_contract` — the address and/or code hash of the affected contract
- `affected_lines` — specific file:line references (Code4rena convention)
- `affected_function` — the function(s) containing the vulnerability

**Classification fields:**
- `severity` — Critical, High, Medium, Low, Informational (Immunefi); High Risk,
  Medium Risk, QA, Gas (Code4rena)
- `impact` — description of what the vulnerability enables (loss of funds, denial of
  service, governance manipulation)
- `likelihood` — how likely exploitation is (sometimes a separate field, sometimes
  folded into severity)

**Evidence fields:**
- `description` — prose description of the vulnerability
- `proof_of_concept` — code or transaction trace demonstrating the vulnerability
  (this is the *counterexample/witness*)
- `recommended_fix` — the submitter's suggested remediation

**Outcome fields:**
- `status` — the lifecycle state (see below)
- `bounty_amount` — the reward if accepted
- `resolution_reason` — why the finding was accepted/rejected/escalated

### (b) Assumptions

Bug bounty findings do not carry formal assumptions, but implicit ones exist:

- **Scope assumption** — the finding is only valid if the affected contract is
  in-scope for the contest/program. In-scope assets are listed in the program brief.
- **Environment assumption** — the vulnerability assumes a specific deployment
  configuration (e.g., a specific version of a dependency, a specific chain ID).
- **Reproducibility assumption** — the PoC assumes the vulnerability can be triggered
  at a specific block or with specific state.

**Key lesson for Bloom:** Every claim should carry an explicit `scope` field enumerating
the versions, addresses, and chains to which it applies. Out-of-scope claims are
automatically irrelevant.

### (c) Versioning and supersession

Finding reports are **versioned by edit history, not by explicit versions**:

- Submitters can edit findings during the contest window, and edits are tracked.
- After submission closes, findings are immutable for the review period.
- A finding cannot formally "supersede" another finding, though wardens sometimes
  reference related findings.

**The important lifecycle state machine** (relevant to Bloom's challenge model):

```
Submitted → Under Review → { Accepted (paid), Rejected (invalid), Duplicate, Escalated }
                                                ↓
Escalated → { Upheld (paid), Overturned (rejected) }
```

The escalation path is the *challenge resolution mechanism*: when the project team and
the submitter disagree on validity, an impartial third party (Immunefi's team, Sherlock's
senior watchers) adjudicates. This is structurally similar to Bloom's two-stage
arbitration (ADR-003): objective replay (Stage A) + social adjudication (Stage B).

### (d) Challenge and invalidation

Findings are challenged through:

- **Project team rejection** — the project claims the finding is invalid, out of scope,
  a duplicate, or of lower severity. Must provide a reason.
- **Warden escalation** — if the warden disputes the rejection, they escalate to the
  platform's arbitration.
- **Community review** — in Code4rena, other wardens can comment on findings, providing
  supporting or refuting evidence.
- **Final adjudication** — the platform's arbitrators issue a final decision with a
  written justification.

**Findings can be invalidated by:**
- **Out of scope** — the affected contract is not in the program
- **Already known** — duplicate of a previously reported issue
- **Invalid PoC** — the proof of concept does not actually demonstrate the claimed
  vulnerability
- **Won't fix** — the project acknowledges the issue but declines to fix it (e.g.,
  acceptable risk, will be addressed in a future upgrade)
- **Spam** — the report is maliciously fabricated

---

## 8. System 7 — F* / HACL* verification pipeline

HACL* (High-Assurance Crypto Library) is a verified cryptographic library written in F*
and extracted to C via Kremlin, then compiled to native code or Wasm. Its pipeline is the
closest existing system to Bloom's future verification architecture: a proof at the source
level must survive multiple compilation steps to reach a deployed binary artifact.

### (a) Data structure and anchoring

The HACL* pipeline produces these artifacts at each stage:

**Source level (F*):**
- `fstar_source` — the F* implementation with embedded specifications (pre/post conditions,
  type refinements, and lemmas).
- `fstar_proof` — the F* type-checking derivation that proves the implementation meets
  its specification. The proof is the type-checking itself (F* is dependently typed).

**Extraction level (Low* → Kremlin → C):**
- `lowstar_source` — a subset of F* (Low*) targeting C extraction.
- `kremlin_config` — the Kremlin extraction configuration specifying C types, memory
  layout, and linking.
- `c_source` — the extracted C code.
- `extraction_proof` — a proof that the extraction preserves semantics. This is a
  *translation validation* pass: Kremlin ensures the generated C is trace-equivalent to
  the Low* source.

**Compilation level (C → Wasm):**
- `compiler_config` — compiler (clang/Emscripten/wasm_of_ocaml) with version and flags.
- `wasm_binary` — the final deployed artifact.
- `reproducible_build_manifest` — build system lockfile (opam/nix) pinning exact versions
  of every toolchain component.

**The metadata that survives to Wasm:**
In current HACL*, almost no formal metadata survives from the F* proof to the Wasm
binary. The Wasm binary is a compiled artifact — it does not carry a proof certificate.
The HACL* team has explored proof-carrying binaries and reproducible builds, but at
present the chain of trust is:

1. The F* proof is checked at build time.
2. Kremlin's extraction proof is checked at build time.
3. The C → Wasm compilation is *trusted* — there is no machine-checked proof of
   CompCert for the C→Wasm path (CompCert targets native assembly, not Wasm).
4. Reproducible builds (byte-identical Wasm output given the same inputs) allow
   independent verifiers to reproduce the Wasm binary and confirm it matches the
   claimed source → Wasm path.

**What a Bloom-compatible HACL* certificate would carry:**
```
{
  source_spec_hash: <F* source + spec>,
  proof_artifact_hash: <F* type-check proof>,
  extraction_proof_hash: <Kremlin TV proof>,
  wasm_binary_hash: <final Wasm>,
  toolchain_versions: [
    {tool: "fstar", version: "2025.01.15", hash: <...>},
    {tool: "kremlin", version: "0.9.8", hash: <...>},
    {tool: "clang", version: "18.1.8", hash: <...>},
    {tool: "wasm-ld", version: "...", hash: <...>},
  ],
  build_manifest_hash: <reproducible-build lockfile>,
  tcb_declaration: ["fstar_checker", "kremlin_tv", "clang_compiler"]
}
```

**Minimal anchor fields extracted:** `{source_spec_hash, implementation_hash,
wasm_binary_hash, toolchain_versions[], build_manifest_hash, tcb_declaration[]}`.

### (b) Assumptions

HACL* makes assumptions explicit at multiple levels:

- **F* level** — the F* specification states preconditions (e.g., "input buffer length
  must be 32 bytes"). These are checked at the type level.
- **Memory model** — Low* assumes a specific heap model. Kremlin translates this to C's
  malloc/free. The proof assumes Kremlin's translation is correct (translation validation
  checks this assumption).
- **C compiler correctness** — the CompCert assumption: the C → native compilation
  preserves semantics. As noted in ADR-006, CompCert targets native assembly, not Wasm,
  so for Wasm targets this assumption is currently *unverified*.
- **Side-channel resistance** — HACL* targets constant-time execution. The proof
  covers logical correctness; side-channel resistance is established by a separate audit
  (manual review of the C output for secret-dependent branches/memory accesses). The
  certificate should carry a `side_channel_audit` field if it claims constant-time
  properties.

### (c) Versioning and supersession

HACL* uses semantic versioning for its library releases, with the additional constraint:

- **EverCrypt agile crypto** — HACL*'s EverCrypt layer provides algorithm agility
  (e.g., choose between C implementation and hardware-accelerated AES-NI at runtime).
  The verification must cover all algorithm variants and their interactions.
- **Rebuild-on-upgrade** — when any toolchain component upgrades, the entire pipeline
  must be re-run. Old proofs are not automatically invalidated, but they are no longer
  reproducible unless the exact old toolchain versions are archived.
- **Toolchain archive** — to make old proofs re-verifiable, HACL* projects typically
  archive the entire toolchain (via opam lockfiles or Docker images). This is a
  practical prerequisite for long-lived proof artifacts: the checker must be
  available to re-verify.

### (d) Challenge and invalidation

A HACL* proof is invalidated by:

- **Source→Wasm semantics gap** — a bug in the C compiler or Wasm backend means the
  compiled Wasm does not preserve the proved F* properties. This is the primary
  risk for any proof that compiles through an unverified compiler.
- **Toolchain version mismatch** — if the verifier cannot reproduce the exact build
  environment, the proof is unverifiable (practically invalid).
- **Memory-safety violation at the C level** — if Kremlin generates C with a buffer
  overflow (a Kremlin bug), the proof is invalid.
- **Side-channel success** — even if the crypto is logically correct, a timing leak
  can make it insecure. The proof does not cover this; a separate side-channel audit
  is the (partial) mitigation.

**Key lesson for Bloom:** Every proof artifact must carry a full toolchain version vector
and a reproducibility manifest. Without these, a proof is a build artifact that cannot
be independently verified — it's a claim of correctness, not a proof.

---

## 9. Cross-cutting pattern extraction

### 9.1 Recurring field categories

Every system surveyed carries fields in these categories. The categories are orthogonal —
a `VerificationClaim` must have at least one field from each.

| Category | Certora | DeepSEA | CompCert | TCT | Move Prover | Bounties | HACL* |
|----------|:-------:|:-------:|:--------:|:---:|:-----------:|:--------:|:-----:|
| **Subject anchor** (what is this about?) | contract + method | source + bytecode hash | source + assembly | code_hash | module + function | target_contract | source + wasm hash |
| **Claim body** (what is asserted?) | assertions / satisfy | theorem statement | behavior preservation | theorem_statement | requires/ensures/invariant | description + severity | F* spec |
| **Assumptions** (what must hold for the claim to apply?) | require + env | TCB declaration | defined-behavior hypothesis | pre_state_constraints | requires + pragmas | scope | toolchain + mem model |
| **Proof / evidence** (why should I believe this?) | prover verdict | Coq proof term | Coq proof term | proof_object | prover result | PoC | F* typing proof |
| **Version identity** | spec file commit | (implicit via hash) | CompCert version | code_hash (anchor) | module version | contest + finding id | toolchain versions |
| **Witness of failure** | counterexample trace | — | — | pre-cond violation | prover counterexample | PoC (adversarial) | — |
| **Status / lifecycle** | pass/fail/vacuous | verified/rejected | verified | accepted/rejected | proved/timeout/refuted | submitted→resolved | verified |

### 9.2 The "three-anchor" pattern

Every claim that binds a formal statement to a deployed artifact uses exactly three hashes
that together provide non-repudiable anchoring:

1. **Subject hash** — identifies *what* the claim is about (contract code, bytecode,
   function). In Bloom terms: `petal_hash`.
2. **Claim hash** — identifies *the claim itself* (spec text, theorem statement,
   assertion). In Bloom terms: `predicate_hash`.
3. **Proof hash** (optional but desirable) — identifies *the evidence for the claim*
   (proof term, prover result, certificate). In Bloom terms: `proof_artifact_hash`.

These three hashes together form a content-addressed triple: given them, any observer
can independently verify that the claim applies to the subject and that the evidence
supports the claim.

### 9.3 Assumption patterns

Systems declare assumptions in four styles, ordered by runtime-enforceability:

| Style | Example | Runtime-enforceable? | Bloom relevance |
|-------|---------|:--------------------:|-----------------|
| **Validated pre-conditions** | TCT pre_state_constraints, Move `requires` | Yes — the runtime checks them before evaluating the claim | ADR-002 pre-commit check |
| **Explicit TCB declaration** | DeepSEA "Coq kernel v8.18", HACL* toolchain vector | Partially — the verifier can check toolchain versions | ADR-006 toolchain attestation |
| **Ambient hypothesis** | CompCert "no undefined behavior", Move `pragmas` | No — must be independently verified | Source→Wasm equivalence gap (ADR-006) |
| **Undocumented assumption** | (none in surveyed systems) | No — invisible risk | Must be *absent* in Bloom's schema |

The design rule: **every assumption must be either (a) runtime-validatable, or (b) an
explicitly declared TCB entry.** Nothing else.

### 9.4 Versioning and supersession patterns

Three models for how claims evolve:

| Model | Systems | Mechanism | Supersession link? |
|-------|---------|-----------|:------------------:|
| **Hash-driven (code-centric)** | TCT, DeepSEA | Claim binds to code hash; code upgrade invalidates old claim | No — implicit |
| **Source-file versioning** | CVL, Move Prover, HACL* | Claims live in source files versioned by git | No — implicit from git history |
| **Explicit versioned object** | (none surveyed) | Claim is a first-class object with version field + `supersedes` pointer | Yes — explicit |

**None of the surveyed systems implement explicit versioned-object supersession.**
This is a gap Bloom can fill: a `VerificationClaim` should carry a `version` field
(incrementing) and an optional `supersedes → claim_hash` pointer. This makes
curation — merging, splitting, strengthening, deprecating — a machine-trackable action.

### 9.5 Challenge and invalidation patterns

Five paths by which a claim can be challenged:

1. **Counterexample / witness of failure** — Certora counterexample, Move Prover
   counterexample, bug bounty PoC. A concrete input-state-trace that makes the claim
   false. This is the *strongest* challenge: objective, replayable, non-arbitrable.
2. **Vacuity / unsatisfiable precondition** — Certora vacuity check. The claim is true
   but only because its precondition is impossible. Not a false claim, but a worthless
   one. Requires a distinct status (`vacuous`) vs. `failed`.
3. **Code mismatch** — TCT code_hash mismatch. The claim applies to a different artifact
   than the one deployed. Mechanical, non-controversial.
4. **Toolchain invalidation** — CompCert bug, Coq kernel CVE, HACL* Kremlin bug. The
   trusted base that produced the claim is known to be unsound. Old claims are
   potentially invalid; new ones must use a patched toolchain.
5. **Intent mismatch** — the "spec correctness problem." The claim is true but
   irrelevant — it doesn't encode the property people care about. The hardest to
   adjudicate mechanically. Bloom's ADR-003 intent-conformance gate is the structural
   mitigation.

---

## 10. Bloom schema recommendation

### 10.1 Design constraints from the existing codebase

Bloom already has:
- `InvariantDecl { name, target, predicate: PredicateAst, wasm_export }` (`types.rs:173`)
- `InvariantDeclStub { name, wasm_export, argspec }` (`chain_iface.rs:127`)
- ADR-003 requires `human_text` + `text_hash` paired with `predicate_ast`
- ADR-006 requires `ProofArtifact { prover_id, version, claim→invariant_id, certificate, toolchain_attestation }` under content-addressed storage
- ADR-002 requires pre-commit evaluation with a revert-on-failure path

### 10.2 The `VerificationClaim` schema

A `VerificationClaim` is the top-level versioned, curatable object that binds a predicate
to a petal, carries its evidence and assumptions, and tracks its challenge lifecycle.

```
VerificationClaim {
    // ── Identity & anchoring (from all 7 systems) ──
    claim_id: Hash32,                    // content hash of the claim body
    claim_kind: ClaimKind,               // Invariant | Proof | Counterexample | Witness
    petal_hash: Hash32,                  // the petal/Wasm artifact this claim is about
    petal_version: u32,                  // the petal's own version number (from manifest)

    // ── Subject binding (from Certora, TCT, Move Prover) ──
    target: InvariantTarget,             // ObjectType | FunctionExit — what triggers eval
    function_name: Option<String>,       // if FunctionExit, which function
    object_type: Option<String>,         // if ObjectType, which object type

    // ── The predicate (from ADR-001, ADR-002, ADR-003) ──
    predicate_ast: PredicateAst,         // canonical machine-readable predicate
    predicate_ast_hash: Hash32,          // content hash of predicate_ast
    wasm_export: String,                 // __inv_<idx> export name
    scope_def: ScopeDef,                 // which state the predicate reads (pre-state, post-state, args, returns)

    // ── Human-readable text (from ADR-003, Certora CVL, bug bounty models) ──
    human_text: String,                  // the author's prose description
    human_text_hash: Hash32,             // content hash of human_text
    rendered_text: Option<String>,       // auto-rendered canonical English (from AST renderer)
    rendered_text_hash: Option<Hash32>,  // pinned so rendering is auditable

    // ── Assumptions (from Certora, DeepSEA, CompCert, TCT, HACL*) ──
    assumptions: Vec<Assumption>,        // declared assumptions the predicate depends on

    // ── Versioning & curation (from Move Prover model + gap filled by Bloom) ──
    claim_version: u32,                  // monotonic version of this claim (1, 2, 3, ...)
    supersedes: Option<Hash32>,          // claim_id of the previous version, if any
    superseded_by: Option<Hash32>,       // claim_id of the next version, filled when superseded
    created_at: BlockHeight,             // block height when this version was published
    valid_from: BlockHeight,             // block height from which this claim applies
    valid_until: Option<BlockHeight>,    // block height at which this claim expired (if superseded)

    // ── Intent-conformance gate (from ADR-003, Gambit/Certora) ──
    intent_conformance: Option<IntentConformance>, // result of the deploy-time spec-test-vector / adversarial review gate
    mutation_score: Option<f32>,         // fraction of contract mutations killed by this predicate (Gambit-inspired)

    // ── Evidence (from DeepSEA, CompCert, TCT, HACL*) ──
    proof_artifacts: Vec<ProofArtifactRef>, // links to content-addressed proof objects (ADR-006)

    // ── Witness of failure (from Certora, Move Prover, bug bounty models) ──
    counterexample: Option<Hash32>,      // content hash of a concrete counterexample witness, if one exists for this version

    // ── Status & lifecycle (from bug bounty classification models) ──
    status: ClaimStatus,                 // Active | Challenged | Vindicated | Superseded | Deprecated
    vacuity_checked: bool,               // has vacuity analysis been run on this predicate?
    vacuity_result: Option<Vacuity>,     // result of vacuity analysis (VacuouslyTrue | NonVacuous)

    // ── Toolchain provenance (from CompCert, HACL*) ──
    bloom_vm_profile_hash: Option<Hash32>, // conformance profile used to evaluate (ADR-005)
    toolchain: Vec<ToolchainVersion>,    // versions of tools used to produce verification (macro version, compiler, prover)
}

enum ClaimKind { Invariant, Proof, Counterexample, Witness }

enum ClaimStatus {
    Active,            // claim is current and untriggered
    Challenged {        // a challenge has been submitted
        challenge_id: Hash32,
        challenged_at: BlockHeight,
    },
    Vindicated,         // challenge was resolved in favor of the claim
    Superseded,         // a newer version exists
    Deprecated,         // author withdrew the claim (non-punitive)
}

struct Assumption {
    assumption_text: String,             // human-readable description
    assumption_text_hash: Hash32,        // content hash
    enforceability: AssumptionEnforceability,
}

enum AssumptionEnforceability {
    RuntimeValidated,                     // the VM checks this before evaluating the claim
    TCBDeclared,                          // part of the trusted computing base (e.g., "Wasm engine vX is correct")
    ExternallyVerified,                   // must be independently verified (e.g., "source program has no UB")
}

struct IntentConformance {
    test_vector_count: u32,              // how many spec test vectors were checked
    adversarial_review_passed: bool,     // did it pass the adversarial counterexample review?
    reviewer_attestation: Option<String>, // optional: who reviewed (for audit trail)
    conformance_hash: Hash32,            // content hash of the conformance data
}

enum Vacuity { VacuouslyTrue, NonVacuous }

struct ProofArtifactRef {
    proof_hash: Hash32,                  // content address of the proof under /bloom/proofs/<hash>
    prover_name: String,                 // "Kani", "Verus", "Coq", ...
    prover_version: String,
    tcb_rank: TcbRank,                   // from ADR-006: PCC > TV > TrustedCompiler
    toolchain_attestation_hash: Hash32,  // reproducible-build manifest (from HACL* pattern)
}

enum TcbRank { ProofCarryingCode, TranslationValidation, TrustedCompiler }

struct ToolchainVersion {
    tool_name: String,
    tool_version: String,
    tool_build_hash: Option<Hash32>,     // reproducible-build pin
}
```

### 10.3 Field rationale table

| Field | Rationale | Source system(s) |
|-------|-----------|------------------|
| `claim_id` | Content-addressed identity; prevents version equivocation | ADR-003; all systems use hash-based identity |
| `claim_kind` | Distinguishes invariant from proof from counterexample from witness — separates "I claim X" from "X was violated" | Bug bounty models (finding type); Certora (rule vs. invariant) |
| `petal_hash` + `petal_version` | Subject anchor — binds claim to specific deployment | TCT `code_hash`; DeepSEA `bytecode_hash`; CompCert source/target hashes |
| `target` + `function_name` + `object_type` | Trigger granularity — when is the claim evaluated? | Certora `invariant` (per-method); Move Prover `spec struct` (per-type) |
| `predicate_ast` + `predicate_ast_hash` | Canonical machine-readable claim body; hash enables content addressing | ADR-001 (AST is canonical); Move Prover `spec` blocks |
| `scope_def` | What state the predicate reads — enables relational before/after claims | Move Prover `modifies` + `requires`/`ensures`; Bloom §3.4 (scope model not yet designed) |
| `human_text` + `human_text_hash` | The prose description paired with the machine predicate (ADR-003 binding) | ADR-003; CVL rule descriptions; bug bounty `description` |
| `rendered_text` + `rendered_text_hash` | Auto-generated canonical English from the AST — pinned so rendering is auditable | ADR-003 auto-renderer requirement |
| `assumptions[]` with `AssumptionEnforceability` | Every assumption must be declared and classified by whether the runtime can check it | Certora `require` + `env`; CompCert "no UB" hypothesis; TCT pre-state constraints; DeepSEA TCB declaration |
| `claim_version` + `supersedes` + `superseded_by` | Explicit version chain — fills a gap present in all surveyed systems | Gap: none of the 7 systems have explicit supersession links. This is a Bloom innovation grounded in Move Prover's module versioning + the curation workflow from ADR-003 |
| `created_at` + `valid_from` + `valid_until` | Temporal scoping — a claim may not apply retroactively, and a superseded claim has a defined end | Bug bounty finding `submitted_at`; Move module upgrade lifecycle |
| `intent_conformance` + `mutation_score` | The deploy-time gate that checks spec↔intent alignment | ADR-003 intent-conformance gate; Certora Gambit mutation score |
| `proof_artifacts[]` (content-addressed refs) | Optional proofs that boost trust score; separated from the claim so proofs can be verified independently | ADR-006: `ProofArtifact` under `/bloom/proofs/<hash>`; DeepSEA certificate; CompCert proof term |
| `counterexample` | Concrete witness of failure — the strongest possible challenge | Certora counterexample trace; Move Prover counterexample; bug bounty PoC |
| `status` (state machine) | Explicit lifecycle from Active → Challenged → Resolved | Bug bounty classification state machine (submitted→resolved) |
| `vacuity_checked` + `vacuity_result` | Prevents vacuously-true predicates from passing as "verified" | Certora vacuity detection |
| `bloom_vm_profile_hash` | Pins the conformance profile so determinism is auditable | ADR-005 (conformance profile) |
| `toolchain[]` | Full toolchain provenance so claims can be independently reproduced | HACL* toolchain version vector; CompCert version; DeepSEA Coq kernel version |

### 10.4 What the schema deliberately omits

- **No embedded proof bytes.** Proofs are large (Coq terms can be megabytes; SMT proofs are tens of KB). They live at content-addressed paths under `/bloom/proofs/` and are referenced by hash — the claim carries references, not the proofs themselves. From ADR-006.
- **No on-chain predicate evaluation result.** The `status` field records the claim's lifecycle state; the *evaluation result* at runtime is recorded in the replay witness (Rung 4), not in the claim itself. The claim declares what *should* hold; the witness records what *did* hold.
- **No governance-vote aggregation.** The challenge state machine records that a challenge exists and its resolution; how the resolution was reached (vote count, arbitrator identity) is a separate governance concern. The claim carries the outcome, not the process.
- **No zk-proof embedding.** ADR-007 explicitly recommends against trusting a single zkVM. zk-proofs of execution are a separate artifact class (`ExecutionProof`), not part of `VerificationClaim`.

### 10.5 How the schema enables the three consumers

Per ADR-001, a predicate must serve three consumers (run, fuzz, prove) plus human readability:

| Consumer | Fields consumed | How |
|----------|----------------|-----|
| **Run** (pre-commit executor) | `target`, `wasm_export`, `scope_def`, `assumptions[]` (runtime-validated), `predicate_ast` (via AST interpreter fallback), `bloom_vm_profile_hash` | Executor runs `__inv_<idx>` or interprets `predicate_ast`; validates runtime-enforceable assumptions; reverts on failure per ADR-002 |
| **Fuzz** (pre-deploy adversarial testing) | `predicate_ast`, `scope_def`, `target`, `petal_hash` | Fuzzer generates hostile inputs against the AST + compiled `__inv`; differential test (AST vs. Wasm) is a standing gate |
| **Prove** (external proof tools) | `proof_artifacts[]`, `toolchain[]`, `predicate_ast`, `assumptions[]` | Kani/Verus/etc. consume the predicate statement and produce a `ProofArtifact`; TCB-rank (ADR-006) determines trust-score weight |
| **Read** (arbitration / governance) | `human_text`, `rendered_text`, `predicate_ast`, `intent_conformance`, `mutation_score`, `counterexample`, `vacuity_result`, `status` | Two-stage arbitration (ADR-003): Stage A reads the machine verdict from the replay witness; Stage B reads the human text + intent-conformance data to judge "is this predicate faithful to the human assertion?" |

### 10.6 Migration path from current code

The current `InvariantDecl` (`types.rs:173`) maps to `VerificationClaim` as follows:

| Current field | Maps to | Notes |
|---------------|---------|-------|
| `name` | `human_text` (title portion) + claim identity | Name becomes part of `human_text`; `predicate_ast_hash` replaces it as the machine identifier |
| `target` | `target` | Direct migration |
| `predicate: PredicateAst` | `predicate_ast` + `predicate_ast_hash` | Add hashing step |
| `wasm_export` | `wasm_export` | Direct migration |
| *(none)* | `human_text`, `human_text_hash`, `rendered_text` | **New** — required by ADR-003 |
| *(none)* | `assumptions[]` | **New** — required to close the "ambient assumptions" gap identified across all 7 systems |
| *(none)* | `claim_version`, `supersedes`, `created_at`, `valid_from` | **New** — versioning from Move Prover model + Bloom innovation |
| *(none)* | `intent_conformance`, `mutation_score` | **New** — ADR-003 gate + Gambit-inspired quality metric |
| *(none)* | `proof_artifacts[]` | **New** — ADR-006 |
| *(none)* | `status`, `vacuity_*` | **New** — lifecycle + quality signal |
| *(none)* | `toolchain[]` | **New** — HACL* reproducibility pattern |

The migration v0 → v1 is additive: all existing fields are preserved, and the new fields
default to `None` / `Active` / `[]` / `1` as appropriate. No existing invariant data is
invalidated.

---

## Sources referenced

- Certora CVL documentation: <https://docs.certora.com/en/latest/docs/cvl/>
- Certora Gambit mutation testing: <https://docs.certora.com/en/latest/docs/gambit/>
- D. Park et al., "DeepSEA: A Language for Certified DeFi Smart Contracts," 2021
- X. Leroy, "Formal Verification of a Realistic Compiler," CACM 2009
- CompCert releases: <https://compcert.org/releases.html>
- Theorem-Carrying Transactions: arXiv:2408.06478
- Move Specification Language (Aptos): <https://aptos.dev/build/smart-contracts/prover/spec-lang>
- Sui Move Prover: <https://docs.sui.io/concepts/sui-move-concepts/prover>
- Move Prover paper: "Fast and Reliable Formal Verification of Smart Contracts with the Move Prover," arXiv:2110.08362
- Immunefi bug bounty program: <https://immunefi.com/>
- Code4rena: <https://code4rena.com/>
- Sherlock: <https://www.sherlock.xyz/>
- HACL*: <https://github.com/hacl-star/hacl-star>
- J.-K. Zinzindohoué et al., "HACL*: A Verified Modern Cryptographic Library," CCS 2017
- Kremlin: <https://github.com/FStarLang/kremlin>
- ADR-001 through ADR-010: [`04-decision-log.md`](04-decision-log.md)
- Invariant schema design (ADR-003): [`02-architecture.md`](02-architecture.md) §4
