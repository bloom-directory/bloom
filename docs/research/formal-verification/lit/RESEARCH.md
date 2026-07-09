# Enforcing invariants & formally proving petals: do Bloom's ADR-001…007 hold up against the literature?

> **Corpus location.** The raw literature corpus (`data/corpus*.json`) and the full text of the
> surveyed papers (`data/fulltext/`) are **not tracked in this repo** — they are large
> machine-generated artifacts and the full text carries third-party copyright. They live in the
> external research store and are git-ignored here (`.gitignore`: `lit/data/`). The synthesized
> analysis below (and the `0x-*.md` files in this directory) is self-contained; references to
> `data/fulltext/manifest.json` etc. point at that external store.

> **TL;DR:** The *substrate* choices in Bloom's verification design survive the literature well —
> a restricted readable predicate, the detection-vs-prevention distinction, provenance-gating of
> proofs, and "no single zkVM as root of trust" are all backed by published work. But four
> *strong-form* claims overreach and need rewording: invariants do **not** have to be a restricted
> AST to be machine-checkable (only to be cheaply *auditable*), float exclusion is **sufficient not
> necessary**, a conformance test-suite alone is **not sufficient** for determinism, and the
> headline idea that "one verified Wasm semantics anchors both determinism and zkVM soundness" is a
> **conjecture, not a result** (the corpus has no Wasm-zkVM paper). The firmest, best-cited finding
> is the one the design under-weights: the real soundness gap is **spec↔human-intent conformance**,
> which no executable semantics closes. *Update 2026-05-29: all six previously-missing papers fetched in
> full and persisted to `data/fulltext/manifest.json` — WasmRef-Isabelle (via co-author Trela's
> Cambridge dissertation + published abstract; ACM PDF Cloudflare-gated), NPChecker, NeoDiff, then
> CT-wasm, WasmCert-Isabelle, and Iris-Wasm. The verified Wasm semantics oracle (V-004) is now firm
> (WasmCert-Isabelle's verified interpreter + its own differential fuzzing against industry engines
> reinforce it); the float-misattribution finding (V-003) has NPChecker's taxonomy behind it, and
> CT-wasm in full text turned out to be constant-time crypto, not floats — its citation is reframed as
> analogical.*

*649 papers across 5 keyless sources (349 on-topic) · 19 of 32 key papers read in full (6 fetches
completed and persisted 2026-05-29) · 6 hypotheses (= the 7 ADRs) tested adversarially · red-teamed · 2026-05-29.*

Citations are tagged `(full text)` / `(abstract)` / `(abstract — fetch failed)` / `(title only)`
by what was actually readable (`data/fulltext/manifest.json`). The corpus's heaviest-lifting
full-text papers for the contested claims are **2024–2026 preprints with ~zero citations** (Arguzz,
RustCompCert, DeepSEA, Theorem-Carrying Transactions, Verus-SpecGym); the well-cited anchors back
the *least* contested claims. Confidence is calibrated accordingly.

---

## What we found

**1. A restricted, declarative, readable predicate is the right *auditable substrate* — but not
because opaque predicates are unverifiable. (Strong on substrate; the "cannot" is refuted.)**
Every production verifier in the corpus aimed at human review adopts a declarative spec language:
the Move Prover ("Fast and Reliable Formal Verification of Smart Contracts with the Move Prover",
DOI 10.1007/978-3-030-99524-9_10, *full text*), VerX ("VerX: Safety Verification of Smart
Contracts", 10.1109/sp40000.2020.00024, *full text*), and 2Vyper ("Rich Specifications for Ethereum
Smart Contract Verification", arXiv:2104.10274, *full text*). However, the claim that *opaque /
closure predicates cannot be machine-checked* is false: Prusti encodes closures into first-order
logic and discharges them via SMT ("Modular specification and verification of closures in Rust",
10.1145/3485522, *abstract*), as does Verus with ghost/linear types (*abstract*). ADR-001 conflates
*opaque-to-a-reader* with *opaque-to-the-verifier*. The defensible claim is narrower: a restricted
total AST is the right substrate for **cheap, neutral auditability**, not the only *verifiable*
form.

**2. Runtime detection ≠ prevention — and Bloom's stateless post-commit view function is the
strictly weaker primitive. (Strong.)** A check that observes one reached state is blind to a logic
bomb on an un-triggered path; coverage-guided fuzzing is bounded sampling on sparse preconditions
("Coverage guided, property based testing", 10.1145/3360607, *abstract*); prevention needs
quantification over unexecuted states (VerX; Move Prover, *full text*). The literal "runtime =
detection" taxonomy is itself refuted in *form* by Theorem-Carrying Transactions (arXiv:2408.06478,
*full text*): a transaction-scoped check evaluated **before commit** genuinely *prevents* the bad
state — its assurance coming from a pre-deploy symbolic proof enforced at commit time. The actionable
consequence: evaluate invariants **pre-commit and revert on failure**, and state explicitly that a
stateless view function covers only the **safety fragment** — liveness / multi-block temporal
properties are out of scope for it ("A survey of challenges for runtime verification…", *abstract*).

**3. Source proofs do not transfer to the deployed artifact without verified compilation /
translation validation / proof-carrying code; provenance-gating is justified; the mechanisms differ
by trusted-computing-base. (Strong on the gap; moderate on a strict ranking.)** Unverified
compilation can silently invalidate a source proof, and translation validation has caught real
production miscompilations ("Translation Validation for JIT Compiler in the V8 JavaScript Engine",
10.1145/3597503.3639189, *abstract*). The three transfer mechanisms differ systematically in TCB:
PCC / certifying compilers keep the compiler untrusted behind a small checker ("Foundational
Verification of Smart Contracts through Verified Compilation" / DeepSEA, arXiv:2405.08348, *full
text* — "the dsc tool … is not in the trusted computing base"); whole-compiler proof puts the entire
proof + semantics in the TCB ("RustCompCert", arXiv:2602.07455, *full text*). Tools that "moot" the
gap actually *reinforce* it by verifying the **deployed binary** — VeriWasm ("…SFI safety for
native-compiled Wasm", *abstract*) and Crocus ("Lightweight, Modular Verification for
WebAssembly-to-Native Instruction Selection", *abstract*, a 9.9-severity Wasm→native CVE). The
ranking PCC > TV > whole-compiler is **analytic** (reasoned from trusted surface), not an empirical
benchmark on a shared target.

**4. zkVM proofs are blind to their own underconstraint; an independent check (not the prover's own
constraint system) is needed. (Core: strong. Generality to Wasm: moderate.)** Arguzz ("Arguzz:
Testing zkVMs for Soundness and Completeness Bugs", arXiv:2509.10819, *full text*) found 11 bugs (3
soundness) across six production **RISC-V** zkVMs, **post-audit**, each a case where "the proof still
verifies successfully." SoK-SNARKs (arXiv:2402.15293, *full text*) quantifies the class: 124/141
vulnerabilities break soundness; 95/99 circuit-layer bugs are under-constrained. Two corrections the
red team forced: (a) Arguzz's method is **metamorphic testing + fault injection on product programs
with a constructed known output**, *not* "re-execution against an external honest reference VM" — so
the tidy "re-execute against a verified Wasm semantics" framing is **Bloom's extrapolation, not what
Arguzz shows**; (b) all evidence is **RISC-V**, the corpus has **no Wasm-zkVM paper**, and Arguzz is
a single uncited 2025 preprint — so "no single prover as root of trust" is well-supported in
principle, but its transfer to a Wasm zkVM is by analogy.

**5. Excluding floats is sound *engineering*, but not *necessary*. (Engineering case: moderate;
necessity: refuted, with thin evidence.)** Integer-only execution materially eases provability (Move
Prover, *full text*). Typed, restricted Wasm subsets with enforced deterministic semantics are
demonstrably practical (CT-wasm, 10.1145/3290390, *full text* — but it is constant-time crypto via
secret types, **not floats**, so it supports the float-subset case only by analogy), and deterministic
float execution is addressed directly only by reproducible-FP work (*abstract*); the canonical
chain-nondeterminism bugs trace to scheduling and read-write
hazards, **not floats** ("Detecting nondeterministic payment bugs in Ethereum smart contracts",
10.1145/3360615, *full text* — NPChecker's taxonomy is transaction scheduling / read-write hazards /
external callees, no floats; 1,111 of 3,075 distinct mainnet contracts flagged). Caveat the red team
is right to press: the *necessity refutation* now has NPChecker's taxonomy behind it for the
Ethereum case, but the general "deterministic float subset exists" claim is *weaker* than the prior
draft implied — CT-wasm (*full text*) turned out to be constant-time crypto, **not floats**, so it is
only analogical support; reproducible-FP work (*abstract*) is the sole float-direct citation. So the
necessity refutation stays directional there; the *engineering* case ("simplest sufficient means")
is firm.

## The novel insight

The inquiry surfaces **two patterns, deliberately ranked by evidence weight — opposite to how
Bloom's design ranks them.**

**The firmer one (under-weighted by the ADRs): the real soundness gap is spec↔intent conformance,
which no executable semantics closes.** Bloom's design energy goes into the *representation* of the
predicate (AST vs. closure) and the *proof* of the code. But the best-cited, full-text, non-preprint
evidence in the entire corpus clusters elsewhere: even when a spec is total, transparent, and
machine-checked, it routinely fails to capture *what the author meant*. Verus-SpecGym
(arXiv:2605.26457, *full text*) reports the best model writes faithful specs only 77.8% of the time
and an LLM judge *reading the spec* misses 26% of faithfulness failures; "Evaluating LLM-driven
User-Intent Formalization" (arXiv:2406.09757, *full text*) and PropertyGPT (10.14722/ndss.2025.241357,
*full text*, 42 cites — the highest-cited full-text paper backing any contested claim) concur. Both
the H1 and H2 refutations independently land on the **same boundary**: the leverage point is *before*
the verifier and *before* execution — the human→spec join and the pre-commit gate — **not** the
representational choice (AST vs. closure) or the timing label (runtime vs. static) the ADRs fixate
on. A green-proving invariant on a faithful-looking spec can still encode the wrong property; a
readable AST is *necessary but provably insufficient* for sound arbitration. This is the strongest,
most actionable result of the inquiry, and ADR-003 currently leans on auto-rendered English where the
evidence demands an independent intent-conformance check (adversarial counterexample review / spec
test-vectors).

**The more generative one (a conjecture, not a finding): the verification ladder may have fewer
independent trust roots than it looks.** V-004 (determinism) and V-006 (zkVM soundness) *could*
converge on one artifact — a pinned, verified, executable Wasm semantics serving as both the
differential-conformance oracle and the fraud-proof adjudicator — collapsing two "long-term" forks
(Q5, Q8) into one near-term spine. This is appealing and worth pursuing, but it is **explicitly a
conjecture**: it bridges Wasm-determinism evidence (WasmRef-Isabelle, *full text*) and
RISC-V-zkVM evidence (Arguzz) across *different machine models*, and **no corpus paper studies a Wasm
zkVM**. It belongs in the open-questions column, not the findings column.

## Hypotheses tested

| H | ADR | Verdict | Key evidence | Confidence |
|---|-----|---------|--------------|------------|
| H1 | 001 (+003) | **Supported (amended)** — restricted AST is the right *auditable* substrate; "opaque ⇒ unarbitrable" **refuted**; readability **insufficient** for intent | Move Prover, VerX, 2Vyper *(full text)*; Prusti/Verus *(abstract)*; Verus-SpecGym, PropertyGPT *(full text)* | high |
| H2 | 002 | **Supported (amended)** — core holds; stateless post-commit view fn is the weaker primitive; "runtime = detection" taxonomy refuted | Theorem-Carrying Transactions *(full text)*; VerX, Move Prover *(full text)*; RV survey *(abstract)* | high |
| H3 | 004 | **Refuted (necessity); Supported (engineering)** — float exclusion is simplest-sufficient, not necessary; canonical nondeterminism bugs aren't float-caused | Detecting nondeterministic payment bugs (NPChecker) *(full text)*; CT-wasm *(full text — constant-time crypto subset; analogical, not float-direct)*; Move Prover *(full text)* | moderate |
| H4 | 005 | **Supported (amended) → now firm.** The verified Wasm semantics oracle exists in production: WasmRef-Isabelle *(full text fetched 2026-05-29)* is a verified monadic interpreter deployed as a fuzzing oracle in Wasmtime CI, with performance comparable to Wasmi debug and fully mechanised integer semantics. Profile is necessary but not sufficient — sufficiency IS carried by this verified semantics oracle. | Wasm SpecTec *(full text)*; WasmRef-Isabelle *(full text — fetched)*; WasmCert-Isabelle *(full text — verified interpreter + diff-fuzzing vs industry engines)*; Iris-Wasm *(full text)*; differential-fuzzing paper (NeoDiff) *(full text — EVM/Neo, not Wasm)* | high |
| H5 | 006/007 | **Supported** — gap real; provenance-gating + TCB-ranking justified | DeepSEA, RustCompCert *(full text)*; certifying-compiler 1998 (357 cites); F*→Wasm 2019 *(abstract)* | high (mod. on strict order) |
| H6 | 007 | **Supported (core); moderate (generality)** — underconstraint real & proof-invisible; independent check needed; but RISC-V-only, 1 uncited preprint | Arguzz, SoK-SNARKs *(full text)* | high core / moderate transfer |

## Open questions

**The single most valuable question:** *Can one pinned, verified, executable Wasm semantics serve
simultaneously as the differential-conformance oracle for cross-node determinism (ADR-005) and the
adjudicating reference for zkVM fraud proofs (ADR-007), in one deployed artifact?* It matters because
it is the inquiry's central conjecture made testable — if one verified semantics anchors both,
Bloom's trust surface shrinks materially and two "long-term" forks become one near-term spine. No
corpus paper studies a Wasm zkVM, so this is genuinely open.

**Cheapest unblocking step:** ~~re-fetch the two failed-but-load-bearing artifacts~~ **COMPLETED
(2026-05-29) and persisted to the corpus** (`data/fulltext/manifest.json`). WasmRef-Isabelle full
text obtained via co-author Maja Trela's open Cambridge dissertation ("Extending a WebAssembly
formalisation") plus the published abstract — the ACM paper PDF itself is Cloudflare-gated —
confirming the verified monadic interpreter, the refinement proof against WasmCert-Isabelle, and the
Wasmtime-CI fuzzing-oracle deployment. "Uncovering Smart Contract VM Bugs Via Differential Fuzzing"
(NeoDiff) obtained in **full text** — coverage- + state-guided differential fuzzing across
independent smart-contract VMs, finding cross-implementation divergences (the Neo C# consensus VM
vs. neo-python) and C#-VM memory corruptions; EVM/Neo-specific, not Wasm, so the methodology
transfers by analogy and strengthens the Rung 3 differential-test case. NPChecker (H3) was fetched
in the same pass.

**Second-order:** does a verified **Rust→Wasm** compilation path (none exists in the corpus; only
F*→Wasm and Rust→native) change the ADR-006 ranking, and at what cost?

## References

Tagged by read depth. DOIs/URLs are in `data/corpus.json`.

1. Dill, Grieskamp, Park, Qadeer, Roberts, Zhong et al. (2022). *Fast and Reliable Formal
   Verification of Smart Contracts with the Move Prover.* CAV. DOI 10.1007/978-3-030-99524-9_10 —
   [full text]
2. Permenev, Dimitrov, Tsankov, Drachsler-Cohen, Vechev (2020). *VerX: Safety Verification of Smart
   Contracts.* IEEE S&P. DOI 10.1109/sp40000.2020.00024 — [full text]
3. Bräm, Eilers, Müller, Sierra, Summers (2021). *Rich Specifications for Ethereum Smart Contract
   Verification* (2Vyper). arXiv:2104.10274 — [full text]
4. Wolff, Bílý, Matheja, Müller, Summers (2021). *Modular specification and verification of closures
   in Rust.* OOPSLA. DOI 10.1145/3485522 — [abstract]
5. Lattuada, Hance, Cho, Brun, Subasinghe, Zhou, Howell, Parno, Hawblitzel (2023). *Verus: Verifying
   Rust Programs using Linear Ghost Types.* OOPSLA. DOI 10.1145/3586037 — [abstract]
6. Lampropoulos, Hicks, Pierce (2019). *Coverage guided, property based testing.* OOPSLA. DOI
   10.1145/3360607 — [abstract]
7. *Theorem-Carrying Transactions: Runtime Verification to Ensure Interface Specifications for Smart
   Contract Safety.* arXiv:2408.06478 — [full text]
8. *A survey of challenges for runtime verification from advanced application domains (beyond
   software).* Formal Methods in System Design (2019). DOI 10.1007/s10703-019-00337-w — [abstract]
9. *Translation Validation for JIT Compiler in the V8 JavaScript Engine* (TurboTV). ICSE 2024. DOI
   10.1145/3597503.3639189 — [abstract]
10. Li, Choi, Kim, Shao et al. (2024). *Foundational Verification of Smart Contracts through Verified
    Compilation* (DeepSEA). arXiv:2405.08348 — [full text]
11. *RustCompCert: A Verified and Verifying Compiler for a Sequential Subset of Rust.*
    arXiv:2602.07455 — [full text]
12. Necula, Lee (1998). *The design and implementation of a certifying compiler.* PLDI. — [abstract]
13. Necula (1997). *Proof-carrying code.* POPL. — [title only]
14. Johnson, Thien, Tsai, Zaldivar, Vanover, Shaon et al. (2021). *…SFI safety for native-compiled
    Wasm* (VeriWasm). NDSS. — [abstract]
15. *Lightweight, Modular Verification for WebAssembly-to-Native Instruction Selection* (Crocus,
    2024). — [abstract]
16. *Arguzz: Testing zkVMs for Soundness and Completeness Bugs.* arXiv:2509.10819 — [full text]
17. *SoK: What don't we know? Understanding Security Vulnerabilities in SNARKs.* arXiv:2402.15293 —
    [full text]
18. Watt (2018). *Mechanising and verifying the WebAssembly specification* (WasmCert). CPP. DOI
    10.1145/3167082 — [**full text persisted 2026-05-29** — author PDF (cl.cam.ac.uk); mechanised
    Isabelle Wasm semantics + **verified executable interpreter & type checker** + type-soundness proof;
    surfaced real bugs in the official spec via **differential fuzzing against industry implementations**]
19. *WasmRef-Isabelle: A Verified Monadic Interpreter and Industrial Fuzzing Oracle for WebAssembly.*
    DOI 10.1145/3591224 — [**full text persisted 2026-05-29** via co-author Maja Trela's open Cambridge
    dissertation "Extending a WebAssembly formalisation" + the published abstract (the ACM paper PDF is
    Cloudflare-gated); verified monadic interpreter in Isabelle/HOL; deployed in Wasmtime CI; fully
    mechanised integer semantics; refinement proof against WasmCert-Isabelle]
20. *Wasm SpecTec: Engineering a Formal Language Standard.* arXiv:2311.07223 — [full text]
21. *Iris-Wasm: Robust and Modular Verification of WebAssembly Programs.* PLDI 2023. DOI 10.1145/3591265
    — [**full text persisted 2026-05-29** — iris-project.org PDF; higher-order separation logic over
    WasmCert-Coq + a **robust-safety logical relation** (adversarial modules affect others only via
    explicitly exported functions); module-encapsulation case study — adjacent to RT-001 isolation]
22. Watt, Renner, Popescu, Cauligi, Stefan (2019). *CT-wasm: type-driven secure cryptography for the
    web ecosystem.* POPL. DOI 10.1145/3290390 — [**full text persisted 2026-05-29** — arXiv:1808.01348;
    **constant-time crypto via secret types** (information-flow + timing-side-channel security), **not
    floats** — cited only by analogy for "typed restricted Wasm subsets are feasible"]
23. *Detecting nondeterministic payment bugs in Ethereum smart contracts.* OOPSLA 2019. DOI
    10.1145/3360615 — [**full text persisted 2026-05-29** — author PDF (HKUST), CC-BY; NPChecker:
    nondeterminism taxonomy = transaction scheduling / read-write hazards / external callee behavior,
    no floats; 1,111 of 3,075 distinct mainnet contracts flagged]
24. Lahiri (2024). *Evaluating LLM-driven User-Intent Formalization for Verification-Aware
    Languages.* arXiv:2406.09757 — [full text]
25. *Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization.*
    arXiv:2605.26457 — [full text]
26. *PropertyGPT: LLM-driven Formal Verification of Smart Contracts through Retrieval-Augmented
    Property Generation.* NDSS 2025. DOI 10.14722/ndss.2025.241357 — [full text]
27. Protzenko, Beurdouche, Merigoux, Bhargavan (2019). *Formally Verified Cryptographic Web
    Applications in WebAssembly.* IEEE S&P. DOI 10.1109/sp.2019.00064 — [abstract]
28. *Uncovering Smart Contract VM Bugs Via Differential Fuzzing.* DOI 10.1145/3503921.3503923 —
    [**full text persisted 2026-05-29** — author PDF (NeoDiff GitHub repo); coverage- + state-guided
    differential fuzzing of EVM and Neo VMs; found cross-implementation divergences (Neo C# consensus VM
    vs. neo-python) and memory corruptions in the C# Neo VM; methodology transfers to Bloom's
    AST-vs-Wasm differential test even though the paper is EVM/Neo-specific]
