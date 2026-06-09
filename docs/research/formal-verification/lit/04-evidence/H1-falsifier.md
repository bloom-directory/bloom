# H1 Falsifier — Restricted Predicate-AST Invariants

REFUTATION STRENGTH: partial — The corpus decisively refutes the *necessity* half of H1
(rich / closure-bearing predicates ARE soundly and modularly machine-checkable, so the
"opaque ⇒ unverifiable" inference is a conflation), and it independently undermines the
*sufficiency* premise the ADR rests on (readable, total, transparent predicate ASTs
routinely fail to capture intent, so transparency does not by itself buy sound
human↔machine arbitration). It does **not** refute the weaker, design-pragmatic reading
of H1 — that a restricted total AST is a *useful* arbitration substrate — because no
corpus paper studies the specific human-arbitration use case, and one corpus paper
(OVL) actively endorses the sub-Turing/total-predicate design. Hence partial, not
decisive.

---

## What H1 actually asserts (two separable claims)

- **H1a (necessity/amputation):** an invariant *must* be a restricted, total, semantically
  transparent predicate AST.
- **H1b (impossibility):** opaque/closure predicates *cannot* serve human↔machine
  arbitration.

A decisive refutation needs to break **either** the soundness inference behind H1b
(showing closures are soundly machine-checkable and usable as specs) **or** the implicit
premise that motivates H1a (that transparency is what makes a predicate
arbitration-grade). The corpus breaks both inferences; it does not break the bare design
preference, which is why the verdict is partial.

---

## Front 1 — Expressiveness: closures and rich predicates ARE soundly, modularly machine-checkable

The cleanest disconfirmer of H1b is the closures paper itself.

- **"Modular specification and verification of closures in Rust"**
  (Wolff, Bílý, Matheja, Müller, Summers — Prusti), DOI 10.1145/3485522 *(abstract only)*.
  It "presents a novel technique for the modular specification and verification of
  closure-manipulating code in Rust… combines Rust's type system guarantees and novel
  specification features to enable formal verification of rich functional properties.
  It **encodes higher-order concerns into a first-order logic, which enables automation
  via SMT solvers** … implemented as an extension of the deductive verifier Prusti, with
  which we have successfully verified many common idioms of closure usage."

  This is the head-on counterexample to H1b. A *closure* — the paradigm "opaque/closure
  predicate" — is given a modular spec and discharged soundly by an SMT solver. The
  property "opaque predicate cannot be machine-checked" is therefore false as stated: the
  higher-order/closure content is reflected into decidable first-order obligations. The
  thing H1 calls un-arbitrable between human and machine is exactly what this tool
  machine-checks. The ADR conflates *opaque to a naive textual reader* with *opaque to the
  verifier*; this paper severs that link.

- **Flux: Liquid Types for Rust**, arXiv:2207.04034 *(full text)*. Flux is, ironically,
  the closest thing in the corpus to the ADR's preferred design — invariants ARE
  restricted, total, quantifier-free predicate expressions in a decidable logic
  (`i32[@n]`, `RVec<T>[n]`, `{v: v > 0}`), composed via type constructors. So Flux is
  *consistent* with H1a's aesthetic. But the paper's own framing is the refutation of
  H1a's *necessity*: the authors explicitly position Flux against **Prusti**, whose "more
  expressive program logic can, in general, verify deep functional correctness
  specifications **beyond the scope of Flux**" (abstract; §1, §5). Flux's restricted
  refinements are sold as an *ergonomics* trade-off for "lightweight but ubiquitous"
  cases — not as a soundness or arbitration prerequisite. The restricted AST is one
  *point on a Pareto frontier*, not a requirement. The richer program logic is sound and
  modular; it simply costs more annotation. H1a's word "must" is unsupported.

- **Rich Specifications for Ethereum Smart Contract Verification** (Bräm, Eilers, Müller,
  Sierra, Summers — 2Vyper), arXiv:2104.10274 *(full text)*. This is the strongest
  evidence that a restricted predicate AST is **too weak for real DeFi invariants**. The
  paper's entire premise is that classical predicate specifications are *insufficiently
  expressive* for smart contracts: they cannot soundly express behaviour "in the presence
  of unverified code and arbitrary re-entrancy," modular reasoning about *collaborating*
  contracts, or *resource transfers* (§1, contributions 1–3). Their solution is to add
  domain-specific specification constructs — resources, offers, transfer/loan primitives,
  interface-level abstractions — that are emphatically *not* a flat total predicate over
  current state, yet are discharged by an SMT backend and remain "readable, source-level
  code annotations" (§1, contribution 4). DeFi-grade invariants (a contract's resources
  are conserved across an adversarial re-entrant callback) require richer-than-AST
  machinery, and that machinery is still both readable *and* machine-checkable. This
  directly contradicts the ADR's implied dichotomy "restricted-transparent vs.
  opaque-unverifiable."

- **Verus: Verifying Rust Programs using Linear Ghost Types**, DOI 10.1145/3586037
  *(abstract only)*. Verus admits specifications using *ghost variables* and *linear ghost
  types* (permissions for pointers, interior mutability, concurrent resources), all
  checked soundly by Z3. Ghost/permission state is not a "semantically transparent
  predicate over visible state"; it is auxiliary machinery a naive reader does not see.
  Yet it is sound and modular. Again: opacity-to-reader ≠ unverifiability.

**Front 1 verdict:** H1b is refuted as a universal ("cannot"). Closures, ghost state,
resource logics, and richer program logics are all soundly machine-checkable and modular.
H1a's "must" is refuted: the restricted AST is an ergonomics choice, and the corpus's own
DeFi paper says it is too weak for the headline DeFi invariants.

---

## Front 2 — The deeper gap: readable, transparent, machine-checkable specs still fail to capture intent

This is where the corpus is decisive *against the ADR's underlying premise* — that a
*readable* AST solves the adjudication problem. Three corpus papers show readability and
machine-checkability are **not sufficient** for capturing intent.

- **Verus-SpecGym / Verus-SpecBench**, arXiv:2605.26457 *(full text)*. This is the
  sharpest disconfirmer. The specs in this benchmark are *exactly* the ADR's ideal object:
  Verus `spec fn` predicates (`pre_spec`, `post_spec`) — total, side-effect-free logical
  predicates that the authors additionally make **executable** by extending Verus's
  `exec_spec` mechanism to compile each predicate into a Rust function (§1, §2.2). So they
  are restricted, total, transparent, *and* runnable. Despite this, the strongest frontier
  model writes a faithful spec for only **77.8%** of tasks; others 51.1–57.8%; OSS models
  21.5–25.5% (abstract; §1). Failures cluster into three modes (§4, App. F.3/G):
  specifications that **omit input assumptions**, **accept incorrect outputs**, and
  **reject valid outputs** — e.g. gemini-3.1pro writes "an overly complex interval-union
  postcondition that rejects valid answers" (l.980). Crucially: "even on problems where
  current agents can generate correct code, they often fail to write a faithful
  specification" (l.148). Transparency of the predicate did *not* prevent the
  arbitration error. Worse for the ADR's "human reads it" story: an **LLM-as-a-judge baseline
  reading the spec misses 26% of the faithfulness failures** that the executable evaluator
  catches (abstract; l.158). A transparent, readable predicate that *a reader endorses*
  was still semantically wrong 26% of the time. Readability is demonstrably not sufficient
  for sound arbitration.

- **Evaluating LLM-driven User-Intent Formalization for Verification-Aware Languages**
  (Lahiri, Microsoft Research), arXiv:2406.09757 *(full text)*. The paper's thesis is that
  "there is **no algorithmic way of ensuring the correctness of the user-intent
  formalization**" — a spec being machine-checkable against code says nothing about whether
  it matches intent (Abstract; §I). Concretely (§I-B/§I-C): a Dafny postcondition that
  *human experts labeled STRONG SPEC* — a perfectly readable, transparent predicate using
  the auxiliary `InArray` predicate — was discovered by the automated metric to be
  *incomplete* (score 0.6), because `==>` only checks that result elements are in both
  arrays, not that *all* common elements appear (l.323–334). The human reader endorsed a
  transparent AST that did not capture intent. Lahiri further finds the human labels
  themselves were wrong on multiple tasks (task ids 2, 145, 161 over-labeled; 234, 240,
  445 had copy bugs) — i.e. transparent human-checkable specs were mis-adjudicated *by the
  humans who wrote them*. This is the empirical core: **transparency ≠ correctness of
  arbitration.**

- **PropertyGPT** (Liu et al., NDSS 2025), DOI 10.14722/ndss.2025.241357 *(full text)*.
  PropertyGPT's Property Specification Language (PSL, Fig. 2) is precisely a restricted,
  readable predicate grammar — `inv ∈ Invariant = bool expr ⇂(v*,C*)`, pre/postconditions
  as boolean expressions over state — deliberately "easier… because they share similar
  structures with the Solidity language" (l.300). It is the ADR's transparent AST applied
  to DeFi. Result: even with retrieval-augmentation from Certora's human-written
  properties, it reproduces only **80% recall** of ground-truth properties (l.139, l.931–
  952). **One in five intended invariants is simply absent**, despite the spec language
  being maximally readable and verifiable. Transparency did not close the intent gap. The
  paper also notes (l.291–299) that the industrial DeFi spec language, Certora **CVL**,
  needs *hooks* for low-level read/write semantics — escape hatches beyond a flat
  predicate — to express real properties; the restricted grammar is acknowledged as
  expressively limited (App. B), echoing the 2Vyper finding.

**Front 2 verdict:** The ADR's premise — that a readable/transparent AST is what makes a
predicate suitable for human↔machine arbitration — is empirically false. Three corpus
papers show that the *most* transparent, total, machine-checkable predicates (Verus
`spec fn`, Dafny postconditions, PSL invariants) still mis-encode intent 20–48% of the
time, and human readers (and LLM judges) endorse wrong-but-readable specs. Readability is
necessary-ish but provably insufficient. If the ADR's justification for the amputation is
"a readable AST lets human and machine agree," that justification does not hold.

---

## Front 3 — The conflation

H1 conflates two distinct properties:

1. **Opaque-to-a-naive-reader** (closure body, ghost state, a higher-order predicate, a
   resource-transfer clause are not legible at a glance), and
2. **Unverifiable / unsuitable for arbitration** (the machine cannot soundly check it, or
   the two parties cannot agree on its meaning).

The corpus dissociates these in *both directions*:

- **Opaque-to-reader yet soundly verifiable:** closures (10.1145/3485522), Verus ghost/
  linear types (10.1145/3586037), 2Vyper resource logic (arXiv:2104.10274). Higher-order
  and ghost content is opaque to a casual reader but is reflected into first-order SMT
  obligations and discharged soundly and modularly. (Front 1.)
- **Transparent-to-reader yet semantically wrong / mis-arbitrated:** the STRONG-SPEC-
  labeled Dafny postcondition that was actually incomplete (Lahiri, l.323), the readable
  Verus `spec fn` that LLM judges endorse but the executor refutes 26% of the time
  (SpecGym, l.158), PSL's 80% recall (PropertyGPT). (Front 2.)

So transparency and verifiability/arbitrability are *orthogonal*. The ADR treats them as
the same axis ("transparent ⇒ arbitrable; opaque ⇒ not"). That is the conflation, and it
is the load-bearing error in H1.

---

## Front 4 — What a decisive disconfirming result would look like, and what the corpus has

A *decisive* refutation of H1 (as a hard "must/cannot") would be a single artifact that:
(i) uses a closure/opaque predicate as the invariant, (ii) discharges it soundly and
modularly by machine, and (iii) demonstrably supports human↔machine *arbitration* of a
dispute in an adversarial setting.

- (i)+(ii) are **fully present**: the closures paper (10.1145/3485522) is exactly an
  opaque predicate + sound modular SMT check.
- (iii) is **absent**: no corpus paper studies the *arbitration / dispute-adjudication*
  use case the ADR is built around (a human and a machine, or two adversaries, agreeing on
  whether an invariant was violated). The closest is 2Vyper's adversarial/unverified-code
  reasoning and the SpecGym adversarial "hacks," but neither frames a human↔machine
  arbitration protocol. So the corpus cannot close the loop on the *specific* claim that
  closures are unfit *for arbitration* — it can only show they are fit *for verification*.

There is also a **confirming** voice the falsifier must report honestly:

- **The Open Veracity Language (OVL): A Sub-Turing Specification…**, DOI
  10.2139/ssrn.6388459 *(abstract only)*. OVL argues *for* the ADR's design: a closed
  vocabulary of ~25 typed primitives, "finite acyclic dataflow graphs of total functions,"
  "deliberately sub-Turing-complete," trading expressiveness for "termination,
  determinism, bounded resource consumption, and **auditability by construction**" in
  "adversarial verification environments." This is essentially H1a restated as a language
  design, motivated by *auditability/arbitration*, not by verifiability. It supports the
  ADR's pragmatic reading. (Caveat: abstract-only, 2026 preprint, no empirical evaluation
  in the corpus; it is a design argument, not evidence that closures *fail* at
  arbitration.)

**Front 4 verdict:** The corpus contains the disconfirmer for the soundness/expressiveness
inferences (decisively) but lacks a study of the arbitration use case itself, and contains
one design-level paper (OVL) that endorses the ADR's restriction on auditability grounds.
That asymmetry is why the overall refutation is partial rather than decisive.

---

## Bottom line

- **H1b ("opaque/closure predicates *cannot* serve … machine [checking]") is refuted** by
  the closures paper, Verus, and 2Vyper: such predicates are soundly and modularly
  machine-checked. The "cannot" is false.
- **H1a's "*must*" is refuted**: Flux frames restriction as an ergonomics trade-off, not a
  necessity, and 2Vyper + PropertyGPT/CVL show a flat restricted AST is *too weak* for the
  headline DeFi invariants (re-entrancy-robust resource conservation, collaborating-
  contract invariants).
- **The ADR's premise that *readability solves arbitration* is empirically false** (Front
  2): the most transparent, total, machine-checkable predicates mis-capture intent
  20–48% of the time, and readers/LLM-judges endorse wrong-but-readable specs (26% miss
  rate). Transparency is not sufficient for sound arbitration; the conflation in Front 3 is
  the core defect.
- **What survives:** the narrow, pragmatic claim that a restricted total AST is a *useful
  and auditable* arbitration substrate is *not* refuted — no corpus paper tests the
  human↔machine arbitration scenario directly, and OVL (abstract only) independently argues
  for exactly this restriction on auditability grounds. The ADR is defensible as an
  engineering preference; it is **not** defensible in its strong "must/cannot" form, and
  its stated justification (transparency ⇒ arbitrability) does not hold.

### Citations
- Modular specification and verification of closures in Rust — DOI 10.1145/3485522 *(abstract only)*
- Flux: Liquid Types for Rust — arXiv:2207.04034 *(full text)*
- Rich Specifications for Ethereum Smart Contract Verification (2Vyper) — arXiv:2104.10274 *(full text)*
- Verus: Verifying Rust Programs using Linear Ghost Types — DOI 10.1145/3586037 *(abstract only)*
- Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization — arXiv:2605.26457 *(full text)*
- Evaluating LLM-driven User-Intent Formalization for Verification-Aware Languages — arXiv:2406.09757 *(full text)*
- PropertyGPT: LLM-driven Formal Verification of Smart Contracts through Retrieval-Augmented Property Generation — DOI 10.14722/ndss.2025.241357 *(full text)*
- The Open Veracity Language: A Sub-Turing Specification for Declarative Computation in Adversarial Verification Environments — DOI 10.2139/ssrn.6388459 *(abstract only)*
