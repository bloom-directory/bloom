# H1 — Proponent Case

SUPPORT STRENGTH: moderate — The mechanism (a shared, statically-readable syntactic referent is what makes invariants specifiable, modularly checkable, and human-auditable) is directly and repeatedly instantiated by the strongest production-grade verifiers in the corpus (Move Prover, VerX, 2Vyper/Rich Specifications), all of which deliberately adopt restricted *declarative* spec languages over reasoning about opaque executable code. But the corpus contains no study that *directly tests* the contrastive claim — that an opaque closure-compiled-to-Wasm "breaks arbitration" — so the inference from "declarative specs are what worked" to "closures dissolve the shared referent" is supported by mechanism and design rationale rather than by a controlled comparison. The honest counter-evidence (rich-closure verification is achievable; declarative specs do *not* escape the intent gap) constrains the claim but does not overturn its arbitration core.

---

## The hypothesis, restated precisely

H1 makes two coupled claims:

1. **Necessity of restriction.** An invariant that must be simultaneously *run*, *fuzzed*, *proved*, and *adjudicated by humans* must be a restricted, total, semantically transparent predicate — a declarative AST / spec language.
2. **Closures break arbitration.** An opaque closure compiled to Wasm fails because its meaning is recoverable *only by execution*, so the parties to an arbitration lose a shared referent.

The proponent case is strongest on a *refined* version: declarative, statically-inspectable specification languages are what every mature, routinely-run, human-auditable verifier in this corpus actually uses, and the design papers state *why* — transparency, modularity, and reviewability. The leap to "execution-only opaqueness dissolves arbitration" is the part the corpus supports by mechanism, not by direct experiment.

---

## Direct supporting evidence

### 1. Move Prover — the flagship instance of "declarative spec, run routinely, in CI" (full text)

*Fast and Reliable Formal Verification of Smart Contracts with the Move Prover* (DOI 10.1007/978-3-030-99524-9_10) is the single strongest support in the corpus, because it satisfies *all four* of H1's demands at once on a production system.

- **Declarative, restricted spec language separate from code.** Move code carries specifications in a dedicated language supporting `aborts_if`, `ensures`, helper `spec fun`s, and global `invariant ... forall`. The toolchain explicitly produces "an **abstract syntax tree (AST) of the specifications**" as a first-class artifact, merged with bytecode in the "Move Model" (full text, §3 / lines 217–223). This is precisely H1's "declarative AST / spec language."
- **Semantic transparency over execution semantics.** The spec language uses *arbitrary-precision signed integers* so a reviewer can write `x + y <= limit` "without the complication of arithmetic overflow" (lines 176–178). The meaning of the predicate is read off its syntax, not recovered by running u64 wrap-around semantics — a concrete realization of "semantic transparency / shared referent."
- **The same artifact is simultaneously run/proved AND human-read.** MVP "is fully automatic, like a type checker or linter" and "runs continuously with unit and integration tests"; "Changes in the Diem framework must be successfully verified before being integrated" (lines 59–60, 182–184). The authors emphasize the goal of specs that are easy to *read and write* — "reduce the effort of reading and writing specs" (lines 720–722) — i.e., the predicate must remain a human referent, not just an executable.
- **Restriction is a deliberate, load-bearing engineering choice.** The three techniques that made MVP fast and reliable enough to run in CI — alias-free memory model, fine-grained invariant injection, and **monomorphization** — all work by *restricting* what the verifier must reason about (eliminating aliasing; eliminating type-indexed generic value domains). Monomorphization "almost" eliminated timeouts (lines 580–581). This is direct evidence that tractable, reliable verification of an invariant depends on a *restricted* representation, not an arbitrarily expressive executable one.

Quality: **high.** Peer-reviewed (TACAS 2022), production deployment (entire Diem framework, ~8,800 LOC code + 6,500 LOC specs, verified in minutes, in CI). It is a real-world existence proof that the H1-shaped design is what makes the run/prove/audit loop practical. Caveat for honesty: the paper argues restriction yields *tractability and readability*; it does not frame an opaque-closure alternative and show it fails, so it supports claim (1) far more than claim (2).

### 2. VerX — declarative temporal specs as the auditor's interface (full text)

*VerX: Safety Verification of Smart Contracts* (DOI 10.1109/sp40000.2020.00024) supports H1's *adjudication/audit* angle most directly.

- Requirements are written as **temporal safety properties in a declarative spec language** layered on Solidity syntax with `always`/`once` operators — e.g., `always(claimRefund() ==> !once(sum(deposits) >= 10000))` formalizing the English requirement "investors can claim refunds only if the sum of deposits never exceeded 10,000 ether" (full text, lines 57–62, 127–140).
- The paper frames this against **current audit practice**, where deep functional requirements are checked by "manual, best-effort code inspection" that is error-prone (lines 38–53). VerX's contribution is to give auditors a *formal, readable predicate* standing between informal intent and code — exactly H1's "shared referent" between human and machine.
- The restriction to **EECF (effectively external callback free) contracts** is, again, a deliberate semantic restriction that "simplif[ies] the formalization of requirements, as auditors can write the specification without explicitly considering all possible external callbacks" (lines 120–126). Restriction is justified by *auditor cognition*, not only solver tractability — a clean instance of H1's mechanism.

Quality: **high.** Peer-reviewed (IEEE S&P 2020), evaluated on 83 properties across 12 real-world projects.

### 3. Rich Specifications / 2Vyper — declarative resource specs as the way to exclude errors "by default" (full text)

*Rich Specifications for Ethereum Smart Contract Verification* (arXiv:2104.10274, http://arxiv.org/abs/2104.10274v2) supports H1's claim that the *right declarative vocabulary* is what makes invariants both provable and intuitively reviewable.

- The methodology introduces **declarative, domain-specific specification constructs** for resources, ownership, and transfers, written as "readable, source-level code annotations" (full text, lines 95–102). Ownership, access control, and non-duplicability are "baked into" the spec language so violations "are found by default," "avoiding potentially repetitive and error-prone boilerplate" (lines 90–94).
- This is a strong statement of the *semantic-transparency* mechanism: by making the invariant a declarative predicate over resources, the spec *concisely captures programmer intentions* and "exclude[s] typical errors by default" — the shared referent does cognitive work an opaque executable cannot.
- Notably, the soundness contribution — reasoning "in the presence of unverified, potentially adversarial outside code" and "arbitrary re-entrancy" (lines 16–22, 83–86) — is achieved precisely by *not* trusting opaque external code's executable behavior, and instead reasoning declaratively at the specification/interface level. This is the adversarial-environment analogue of H1: when the counterparty's code is opaque, the only sound shared object is a declarative specification.

Quality: **moderate-to-high.** Detailed methodology with an implemented tool (2Vyper) and real-world contract evaluation; venue is a strong PL track (the artifact corresponds to OOPSLA-line work). The match to H1's *resource-invariant* framing is unusually tight.

### 4. The Open Veracity Language — a direct statement of H1's thesis (abstract only)

*The Open Veracity Language: A Sub-Turing Specification for Declarative Computation in Adversarial Verification Environments* (DOI 10.2139/ssrn.6388459) is the corpus paper that *asserts* H1 most explicitly. It argues that in adversarial domains, computational claims are "routinely acted upon without mechanical verification," that "no existing language simultaneously satisfies the expressiveness, determinism, auditability, and canonical identity requirements," and proposes a **deliberately sub-Turing-complete** declarative language — finite acyclic dataflow graphs of total functions — trading Turing-completeness for "termination, determinism, bounded resource consumption, and **auditability by construction, without runtime enforcement**" (abstract).

This is almost a paraphrase of H1: *total*, *restricted*, *declarative*, auditable *without execution*. Quality caveat (honest): **weak as independent evidence.** It is abstract-only (no methods/results read), an SSRN working paper without peer review, and it argues the thesis rather than empirically testing the closure alternative. It should be cited as *articulation of the mechanism and a position consonant with H1*, not as confirmation.

### 5. Theorem-Carrying Transactions — when code is too opaque to verify statically, attach a checkable proof object (full text)

*Theorem-Carrying Transactions* (arXiv:2408.06478, http://arxiv.org/abs/2408.06478v2) supports H1 obliquely but informatively. Its premise is that "Static code verification cannot be faithful to this gigantic program due to its scale and high polymorphism" — i.e., the *opaque, composed, executable* artifact is exactly what defeats shared static reasoning. Its remedy is to carry an explicit **theorem** (a declarative, checkable object) with each transaction, proving adherence to *interface specifications* (abstract; full text). The structural move — replace "trust the execution" with "carry a transparent, independently checkable predicate/proof" — is the same move H1 prescribes against opaque closures. Quality: **moderate**; peer-status unclear, but full text available and the architecture is the relevant analogue. This is the same lineage as classical *Proof-carrying code* (DOI 10.1145/263699.263712, abstract only), which establishes the general principle that a consumer should be able to check a transparent certificate rather than re-execute opaque code.

---

## The mechanism, stated

Across the high-quality full-text papers the *same* causal story recurs:

1. An invariant must serve **two audiences at once** — a solver/fuzzer (machine) and an auditor/arbitrator (human). Move Prover, VerX, and 2Vyper all expose the invariant as a *declarative predicate* (an AST, a temporal formula, a resource annotation) precisely so both audiences read the *same object*.
2. **Restriction buys tractability and reliability.** Move's monomorphization/alias-elimination and VerX's EECF restriction are not incidental; they are what makes the prove/fuzz/run loop terminate predictably enough to sit in CI.
3. **Restriction also buys human legibility.** 2Vyper's "errors excluded by default," Move's overflow-free signed-integer spec arithmetic, and VerX's auditor-facing temporal syntax all reduce the cognitive cost of holding the invariant as a shared referent.

An opaque closure-to-Wasm artifact satisfies the *machine-execution* role but, by construction, exposes no syntactic referent for the human-arbitration role: its meaning "is only recoverable by execution." The corpus's mature systems *never* chose that design when humans had to adjudicate — which is the affirmative, design-revealed-preference form of H1's argument.

---

## Honest treatment of the counters (addressed, not conceded)

### Counter A — Rich closures *can* be modularly verified (so opacity is not intrinsic)

*Modular specification and verification of closures in Rust* (DOI 10.1145/3485522, abstract only) shows closures — including ones that mutate captured state — admit "modular specification and verification" of "rich functional properties," encoded into first-order logic for SMT automation (Prusti extension). *Flux: Liquid Types for Rust* (arXiv:2207.04034, http://arxiv.org/abs/2207.04034v2, full text) shows refinement types verify rich invariants ergonomically, even "slashing specification lines by a factor of two."

Why this does **not** overturn H1: read carefully, both *confirm the mechanism* rather than refute it. In each case verification succeeds **because a declarative specification artifact is attached to the closure** — Prusti's specification features (DOI 10.1145/3485522, abstract), Flux's refinement-type *indices and predicates* layered onto types (full text, lines 49–60). The verified object is *not* "the opaque closure body"; it is "the closure plus a transparent declarative predicate." Flux even notes Prusti's *program logic* is more expressive in general while *refinements* (a more restricted, more transparent fragment) are what make lightweight verification ergonomic (full text, lines 23–30) — i.e., restriction again earns transparency/tractability. So these papers refute a *strawman* ("you can never verify closures") but support H1's actual claim ("the shared, adjudicable referent is the declarative spec, not the executable"). What they *do* legitimately pressure is H1's strongest wording: a closure is not *inherently* opaque to *verification*. H1 must therefore be read as a claim about *arbitration's shared referent*, not about provability per se.

### Counter B — The intent-formalization gap afflicts declarative specs too

This is the more serious counter, and the corpus evidence for it is **strong and full-text**:

- *Verus-SpecGym* (arXiv:2605.26457, http://arxiv.org/abs/2605.26457v1, full text) finds that even for a *declarative, verification-aware* spec language (Verus over Rust), spec autoformalization is "brittle": generated specs "omit important input assumptions, accept incorrect outputs, and reject valid ones," the best frontier model reaches only 77.8%, and — critically — an **LLM-as-a-judge misses 26%** of the failures their evaluator catches (full text, lines 40–51, 148–160).
- *Evaluating LLM-driven User-Intent Formalization for Verification-Aware Languages* (arXiv:2406.09757, http://arxiv.org/abs/2406.09757v2, full text) states the structural problem plainly: "there is no algorithmic way of ensuring the correctness of the user-intent formalization" because intent is informal and the spec is formal (full text, lines 13–20, 49–63). Rich declarative specs (quantifiers, ghost variables) "cannot be evaluated through dynamic execution," forcing a *symbolic-testing* metric.
- *PropertyGPT* (DOI 10.14722/ndss.2025.241357, full text) reports only ~80% recall vs. ground-truth properties and needs a *dedicated prover* plus compilation oracle to keep generated properties "compilable, appropriate, and verifiable" (abstract; full text).

Why this **constrains but does not refute** H1:

1. The gap these papers document is between *informal human intent* and *any* formal artifact. It is **orthogonal** to H1's machine-vs-machine claim: H1 says the formal object that gets run/proved/adjudicated must be transparent-by-syntax. None of these papers shows an *opaque* artifact closing the intent gap *better*; if anything an opaque closure makes the gap *worse*, since a reviewer cannot even read the candidate predicate to judge faithfulness.
2. Most pointedly, **Verus-SpecGym's own evaluation method vindicates H1's transparency requirement.** To adjudicate faithfulness deterministically, the authors could not trust opaque judgment — they *extended Verus's `exec_spec` to compile each declarative spec into an executable, total Rust check* and ran it against official tests and adversarial "hacks" (full text, lines 40–43, 96, 132, 164–166), and found the *opaque* surrogate (LLM-as-judge) missed 26% of failures. The lesson aligns with H1: reliable adjudication came from a *restricted, executable-yet-transparent declarative predicate* tested adversarially, not from opaque holistic judgment. The intent gap is real, but the corpus's *fix* for evaluating it is exactly H1's kind of artifact.

So Counter B downgrades any claim that declarative specs *solve* correctness — they do not; the human-intent step remains unverifiable in principle (Lahiri, full text). It does **not** support the rival design (opaque closures), and one of its central studies operationally endorses transparent, restricted predicates for adjudication.

---

## Where the proponent case is genuinely thin (honest limits)

- **No head-to-head test of the contrastive claim.** The corpus contains no paper that takes a real invariant, expresses it once as a declarative AST and once as an opaque Wasm closure, and measures arbitration/audit outcomes. The case for claim (2) is *abductive* (best explanation of why mature systems all chose declarative specs) plus *mechanistic*, not experimental.
- **The most on-point paper (OVL) is the weakest evidence** — abstract-only, unrefereed, and argumentative rather than empirical.
- **"Run, fuzz, prove, AND adjudicate" as a single conjoined requirement** is asserted by H1; the corpus shows each leg individually (CI-run + proved: Move Prover; auditor-adjudicated: VerX; fuzzed against adversarial inputs: Verus-SpecGym/`exec_spec`) but no single study demonstrates the full quadruple on one artifact and ties failure specifically to closure opacity.
- **Counter A legitimately narrows the claim** from "closures are unverifiable" (false) to "the adjudicable shared referent must be a declarative spec, not the executable closure body" (supported).

## Bottom line

The mechanism at H1's core — *a restricted, declarative, statically-readable predicate is what lets one artifact serve solver, fuzzer, and human arbitrator at once* — is corroborated convergently by three high-quality, real-world verification systems (Move Prover, VerX, 2Vyper) and by the proof-carrying lineage (TCT, Proof-carrying code). The counters either confirm the mechanism while refuting a strawman (Flux, Rust-closures) or document a real *intent-gap* that is orthogonal to the closure question and whose best mitigation (Verus-SpecGym's executable, adversarially-tested declarative checks) itself instantiates H1. What keeps this at **moderate** rather than **strong** is the absence of any direct experimental contrast against the opaque-closure alternative: the corpus shows overwhelmingly *that* practitioners chose H1's design and *why* they say they did, but not a controlled demonstration that the closure alternative dissolves arbitration.
