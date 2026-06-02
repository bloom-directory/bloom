# Spec↔Intent Conformance Gap: Research Survey

**Date:** 2026-05-29  
**Context:** Bloom deploy-time intent-conformance gate for PredicateAST predicates.  
**Core problem:** A machine-checked predicate can be total, transparent, and faithfully executed, yet encode the wrong property. How do we know the spec says what the author meant?

---

## 1. PropertyGPT (NDSS 2025)

**Paper:** "PropertyGPT: LLM-driven Formal Verification of Smart Contracts through Retrieval-Augmented Property Generation"  
**Authors:** Ye Liu, Yue Xue, Daoyuan Wu, Yuqiang Sun, Yi Li, Miaolei Shi, Yang Liu  
**arXiv:** 2405.02580 | **DOI:** 10.14722/ndss.2025.241357

### Workflow
1. **Retrieval-Augmented Generation (RAG):** Embeds ~2,000 human-written Certora/CVL properties into a vector database. For a new contract, retrieves semantically similar reference properties and provides them as few-shot examples to GPT-4.
2. **Iterative Compilation Feedback Loop:** Generated properties are compiled by the Certora prover. Compilation errors and static analysis feedback serve as an "external oracle" that guides the LLM to revise (up to 5 iterations).
3. **Weighted Property Ranking:** Properties are ranked by multiple similarity dimensions (syntactic, semantic) and the top-K are selected.
4. **Dedicated Prover:** Generated properties are formally verified against the target contract using the Certora Prover. Only verifiable properties survive.

### How It Validates Generated Properties
- **Compilability gate:** Property must compile against the contract (syntactic correctness).
- **Verifiability gate:** Property must pass formal verification (the contract must satisfy the property).
- **NOT a faithfulness gate:** PropertyGPT ensures properties are _compilable_ and _verifiable_, but does NOT check whether the property encodes the correct intent. A vacuous property like `assert(true)` would pass both gates. The paper's "80% recall vs ground truth" measures how many of the human-written reference properties were _recovered_, not whether the generated properties are faithful to the informal specification.

### Relevance to Bloom
PropertyGPT's approach of iterative feedback from the prover is directly adaptable: Bloom could use Z3/SMT feedback on candidate predicates. But PropertyGPT's core limitation — no intent-conformance check — is exactly the gap Bloom needs to close. The retrieval component could be adapted to find _existing_ Bloom predicates similar to the one being authored, as a form of consistency check.

---

## 2. Verus-SpecGym (2026)

**Paper:** "Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization"  
**Authors:** Anmol Agarwal, Natalie Neamtu, Pranjal Aggarwal, Seungone Kim, Jannis Limperg, Cedric Flamant, Kanna Shimizu, Bryan Parno, Sean Welleck  
**arXiv:** 2605.26457 (May 2026, preprint)  
**Code:** https://github.com/formal-verif-is-cool/verus-spec-gym

### Core Findings (per your notes)
- Best model (Gemini 3.1 Pro) writes faithful specs on **77.8%** of tasks
- Frontier models: 51.1–57.8%; Open-source: 21.5–25.5%
- **LLM-as-judge misses 26% of faithfulness failures** caught by execution-based evaluation

### Evaluation Methodology
The paper defines specification faithfulness through four buckets of test cases:

| Bucket | Description | Expected spec behavior |
|--------|-------------|----------------------|
| τ_pre-comp | Valid inputs | pre_spec should ACCEPT |
| τ_pre-sound | Invalid inputs | pre_spec should REJECT |
| τ_post-comp | Correct (input, output) pairs | post_spec should ACCEPT |
| τ_post-sound | Valid input + incorrect output | post_spec should REJECT |

**Key innovation:** They extend Verus's `exec_spec` to compile logical specifications into executable Rust code, enabling concrete testing. A spec is "faithful" iff it passes ALL tests in ALL four buckets.

### How They Determine "Faithfulness"
- **Ground truth test cases** come from Codeforces problems (official tests + adversarial "hacks" submitted by competitors to break incorrect solutions).
- **Hack tests are particularly valuable:** They expose specification failures that official tests miss — human-written adversarial inputs catch subtle spec errors that both LLM judges and standard test cases overlook.
- **Evaluation is deterministic and execution-based**, not LLM-judged.

### Failure Modes
Specs fail in three recurring ways:
1. **Omitted input assumptions** (incomplete precondition — accepts invalid inputs)
2. **Accepted incorrect outputs** (unsound postcondition — too permissive)
3. **Rejected valid outputs** (incomplete postcondition — too strict)

### Adaptability to Bloom
**Highly adaptable.** The four-bucket framework maps directly to Bloom's PredicateAST:
- τ_pre-comp: Generate valid input records → predicate should return `true`
- τ_pre-sound: Generate invalid input records → predicate should return `false`
- τ_post-comp: N/A for Bloom (predicates are unary, not pre/post)
- τ_post-sound: N/A

For Bloom's single-predicate model, we collapse to two buckets:
- **Completeness tests:** Valid inputs → predicate must accept
- **Soundness tests:** Invalid inputs → predicate must reject

The adversarial hack collection strategy is directly applicable: Bloom could maintain a corpus of "boundary test cases" that probe predicate edge cases, sourced from user review and automated generation.

---

## 3. Lahiri FMCAD 2024 — Symbolic Testing of Specifications

**Paper:** "Evaluating LLM-driven User-Intent Formalization for Verification-Aware Languages"  
**Author:** Shuvendu K. Lahiri (Microsoft Research)  
**arXiv:** 2406.09757 | **Venue:** FMCAD 2024  
**Code:** https://github.com/microsoft/nl-2-postcond

### Approach to Measuring Spec↔Intent Gap

Lahiri proposes two automated metrics for specification quality, evaluated purely against test cases (no reference implementation needed):

1. **Correctness (Soundness):** For each test (i, o), insert the spec φ as a postcondition and symbolically verify the Hoare triple `{true} x:=i; y:=o; {φ(x,y)}`. If verification succeeds for all tests, the spec is _correct_ (it accepts all valid input-output pairs).

2. **Completeness (Discriminative Power):** For each test (i, o), generate up to 5 _output mutants_ (o' ≠ o). The completeness score is the fraction of mutants that the spec _rejects_. A high score means the spec is precise enough to distinguish correct from incorrect outputs. This is inspired by mutation testing's kill-set concept.

### Key Findings
- **Automated metrics agree with human labeling** on 64 Dafny specifications from the MBPP benchmark.
- **Found human labeling errors:** The automated metric caught cases where humans labeled a spec `strong_spec` but it was actually incomplete (e.g., SharedElements spec using `==>` instead of `<==>`, only requiring output elements to be in both arrays but not requiring ALL common elements to be in the output).
- **Vacuous specs exposed:** A spec `ensures true` would pass correctness checks but score 0 on completeness (rejects no mutants).
- **Limitations:** Recursive predicates need manual fuel annotation; quantifier instantiation over large domains is problematic for SMT solvers.

### Adaptability to Bloom
The completeness metric using output mutation is elegant but Bloom predicates are unary (input → bool). For Bloom, we can adapt this as **input mutation**: given a set of valid inputs, generate boundary/edge-case mutants and measure how many the predicate correctly rejects. However, Bloom doesn't have a separate postcondition — the predicate is the whole spec.

The symbolic testing approach (inserting predicates as assertions and running the verifier) could work if Bloom predicates compile to SMT-LIB, but the current model uses concrete Rust evaluation. The key insight is: _automated metrics can align with human judgment and even catch human labeling mistakes_.

---

## 4. nl2postcond (Endres et al., FSE 2024)

**Paper:** "Can Large Language Models Transform Natural Language Intent into Formal Method Postconditions?"  
**Authors:** Madeline Endres, Sarah Fakhoury, Saikat Chakraborty, Shuvendu K. Lahiri  
**arXiv:** 2310.01831 | **Venue:** FSE 2024

### Approach
- Repurposes HumanEval and MBPP code-generation benchmarks for specification generation.
- Defines two metrics:
  - **Correctness:** Does the spec accept the reference implementation's outputs on all test inputs?
  - **Discriminative power (Completeness):** Does the spec reject buggy code mutants? Mutants are generated by LLMs and grouped by which tests they fail.
- Generated postconditions caught 64 real-world bugs from Defects4J.

### Limitations for Verification-Aware Languages
Lahiri's FMCAD paper explicitly critiques this approach for verification-aware languages:
1. Rich specifications (quantifiers, ghost variables) cannot be evaluated through dynamic execution.
2. The approach requires generating program mutants via LLMs as a benchmark, which is expensive.
3. Running tests on implementations without specifications doesn't rule out vacuous specs.

### Relevance to Bloom
The correctness+completeness metric pair is fundamental. However, Bloom's PredicateAST is simpler (no quantifiers, no ghost state) and auto-renders to English, which means dynamic execution IS possible — a key advantage over Dafny/Verus-style specs. Bloom predicates can be concretely evaluated on generated test vectors.

---

## 5. 3DGen — Oracle-Based Specification Validation (Fakhoury et al., 2024)

**Paper:** "3DGen: AI-Assisted Generation of Provably Correct Binary Format Parsers"  
**Authors:** Sarah Fakhoury, Markus Kuppe, Shuvendu K. Lahiri, Tahina Ramananandro, Nikhil Swamy  
**arXiv:** 2404.10362

### Key Insight for Intent Conformance
3DGen uses **symbolic methods to synthesize test inputs that can be validated against an external oracle.** The workflow:

1. AI agent generates a formal specification (in the 3D language) from RFC documents + example inputs.
2. Symbolic methods generate test inputs that distinguish between multiple plausible specifications.
3. These test inputs are validated against an external oracle (a reference parser, a human, or domain knowledge).
4. Through repeated refinement, the spec converges to one that conforms to the test suite.

### Oracle Types
- **Reference implementation:** An existing parser (e.g., Wireshark) acts as a ground-truth oracle.
- **Human judgment:** Generated test inputs are presented to a human to judge whether the output is correct.
- **The oracle doesn't need to be automated** — the key is that symbolic generation produces _informative_ test inputs that efficiently probe the spec's boundaries.

### Adaptability to Bloom
This is the most directly applicable approach for Bloom's deploy-time gate:
1. Given a Bloom predicate and its English rendering, use SMT/Z3 to generate boundary test cases.
2. Present these to the human author at deploy time: _"Here are edge cases your predicate would accept/reject. Is this what you intended?"_
3. The human is the oracle. The system's job is to generate _interesting_ counterexamples that maximize the chance of surfacing a gap between the English description and the formal predicate.

---

## 6. Faria et al. — Test Oracles for Spec Validation (2026)

**Paper:** "Automatic Generation of Formal Specification and Verification Annotations Using LLMs and Test Oracles"  
**Authors:** João Pascoal Faria, Emanuel Trigo, Vinicius Honorato, Rui Abreu  
**arXiv:** 2601.12845

### Key Insight
- Uses **assertions in test cases as static oracles** to automatically validate generated pre/postconditions.
- If a generated postcondition is consistent with all test assertions, it passes the oracle check.
- Achieved 98.2% on 110 Dafny programs using a multimodel approach (Claude + GPT-5.2).
- The test oracle is _static_: assertions in the test suite serve as ground truth for both input validation and output validation.

### Adaptability to Bloom
Bloom predicates could be validated against a corpus of labeled examples (input → expected boolean). The test corpus serves as a lightweight oracle. This is simpler than full symbolic testing but requires maintaining a labeled dataset.

---

## 7. Bartoletti et al. — LLMs as Verification Oracles (2025)

**Paper:** "LLMs as verification oracles for Solidity"  
**Authors:** Massimo Bartoletti, Enrico Lipparini, Livio Pompianu  
**arXiv:** 2509.19153

### Key Insight
- Evaluates GPT-5 as an oracle for judging the validity of Solidity verification properties (Certora-style).
- LLMs are "surprisingly effective" at predicting property (in)validity, despite lacking soundness guarantees.
- Suggests a new frontier: **LLMs as lightweight, approximate oracles for spec validation**, complementary to formal tools.

### Relevance to Bloom
An LLM could serve as a secondary judge at deploy time: given the predicate's English rendering + the formal predicate + generated test cases, the LLM compares whether the predicate and the description agree. This is cheaper than human review but unreliable (Verus-SpecGym shows 26% miss rate). It could serve as a _pre-filter_ before human review.

---

## 8. Lahiri 2026 — Intent Formalization as Grand Challenge

**Paper:** "Intent Formalization: A Grand Challenge for Reliable Coding in the Age of AI Agents"  
**Author:** Shuvendu K. Lahiri  
**arXiv:** 2603.17150

### Key Arguments
- Intent formalization is **the** bottleneck for reliable AI-generated code.
- The tradeoff spectrum: lightweight tests → full functional specifications → DSLs with code synthesis.
- Central bottleneck is **validating specifications**: "there is no oracle for specification correctness other than the user."
- Proposes semi-automated metrics using proxy artifacts such as tests.
- Open challenges: scaling beyond benchmarks, compositionality over changes, metrics for validating specifications, designing human-AI specification interactions.

### Relevance to Bloom
This position paper validates that Bloom's problem is not niche — it's the central challenge in the field. Lahiri explicitly calls for the kind of deploy-time gate Bloom needs. The paper also argues for a spectrum of formality, which aligns with Bloom's approach of keeping predicates simple and auto-renderable.

---

## 9. Certora/CVL — The Spec Correctness Problem in Practice

Certora is the most widely used formal verification tool for smart contracts. They use a specification language called CVL (Certora Verification Language). The spec correctness problem is well-known in the Certora community:

### How Certora Addresses It
- **Mutation Verification (Gambit):** Certora's mutation testing tool generates mutants of the specification and checks whether the verifier still passes. If a weakened spec still passes, it suggests the spec is incomplete. This is the practical deployment of Lahiri's completeness metric.
- **Rule coverage:** Certora measures which parts of the contract are exercised by the spec rules.
- **Human review is still the final gate:** Certora audit reports are manually written and reviewed. PropertyGPT was built by _mining existing Certora audit reports_ — the training data for good specs comes from humans.
- **The community has not solved automated spec validation.** The Bartoletti et al. paper (LLMs as verification oracles) was motivated by exactly this gap in the Certora ecosystem.

### Relevance to Bloom
The mutation verification approach (Gambit) is directly applicable: generate mutated versions of a Bloom predicate, check whether they produce different results on a test suite, and flag predicates with low "kill rate" as potentially incomplete. This aligns with Lahiri's completeness metric.

---

## 10. "Extracting Formal Smart-Contract Specifications" Paper

I could not locate a paper with this exact title on arXiv. The closest matches are:
- **PropertyGPT** (above): Extracts properties from Certora audit reports and generates new ones via RAG.
- **FLAMES** (arXiv:2510.21401): Fine-tunes LLMs on 514,506 verified contract invariants to synthesize runtime guards. Achieves 96.7% compilability but only 44.5% exact/semantic match to ground truth — a significant faithfulness gap.
- Neither paper directly addresses the faithfulness validation problem; both focus on generation.

---

## Structured Comparison

| Approach | Validation Method | Oracle | Automation Level | Faithfulness Coverage | Key Limitation |
|----------|------------------|--------|-----------------|----------------------|----------------|
| **PropertyGPT** | Compilation + formal verification | Certora Prover | Fully automated | Low (no intent check) | Vacuous specs pass |
| **Verus-SpecGym** | Execution-based 4-bucket testing | Codeforces tests + hacks | Fully automated (given test suite) | High (catches 4 failure modes) | Requires pre-existing test suite |
| **Lahiri FMCAD'24** | Symbolic testing + output mutation | SMT solver + human-labeled tests | Automated metrics, human labels | Medium (catches weak/vacuous specs) | SMT solver limitations on quantifiers |
| **nl2postcond (Endres)** | Correctness + LLM mutant discrimination | Reference code + LLM mutants | Fully automated | Medium | Not suitable for verification-aware languages |
| **3DGen** | Symbolic test generation + external oracle | Reference parser or human | Semi-automated | High (oracle validated) | Requires oracle per domain |
| **Faria et al.** | Test assertions as static oracles | Test suite assertions | Fully automated | Medium (depends on test quality) | Test suite coverage limits |
| **Bartoletti (LLM oracle)** | LLM predicts property validity | GPT-5 as judge | Fully automated | Medium (26%+ miss rate) | No soundness guarantee |
| **Certora/Gambit** | Mutation verification | Formal verifier | Fully automated | Medium (discriminative power) | Only catches incomplete specs |
| **Human review** | Manual inspection | Human expert | Manual | High | Expensive, doesn't scale |

---

## Recommendation: A Two-Tier Deploy-Time Gate for Bloom

Bloom's advantage: PredicateAST is **declarative, total, and auto-renderable to English.** This means predicates CAN be executed concretely (unlike Dafny/Verus specs with quantifiers and ghost state). No SMT solver is needed for basic evaluation — just generate inputs, run the predicate, and check the output.

### Tier 1: Automated (fast, always runs)

**1a. Boundary Test Generation (adapted from Verus-SpecGym + 3DGen)**
- Given the predicate AST, use a simple fuzzer + constraint solver to generate test inputs that:
  - **Positive tests:** Should satisfy the predicate (sourced from user-provided examples or type-driven generation)
  - **Negative tests:** Should violate the predicate (sourced from type boundary mutation)
- Run the predicate on each test input and record results.
- **Gate check:** Does the predicate behave consistently? If a predicate accepts no inputs or all inputs, flag as likely vacuous.

**1b. Mutation Completeness Score (adapted from Lahiri FMCAD'24 + Certora Gambit)**
- Generate N mutants of the predicate (swap operators, negate subexpressions, widen/widen ranges).
- Evaluate all mutants on the test suite.
- **Completeness score = fraction of mutants that produce different results from the original.**
- A low score (<0.3) means the predicate is likely too weak or vacuous.
- Flag for human review if score is below threshold.

**1c. English Consistency Check (LLM-as-judge, adapted from Bartoletti)**
- Render the predicate to English.
- Ask an LLM: "Here is a human's description of a property: [assertion text]. Here is a formal predicate: [English rendering]. Do they say the same thing? If not, give a counterexample where they disagree."
- Use LLM response as a **signal** (not a gate), due to the 26% miss rate.
- LLM-generated counterexamples become candidate test cases for Tier 2 review.

### Tier 2: Human-in-the-Loop (runs when Tier 1 flags issues, or on first deploy)

**2a. Adversarial Counterexample Review (adapted from 3DGen oracle pattern)**
- Generate K (e.g., 5–10) boundary test cases using constraint-solving + fuzzing.
- For each test case, show:
  - The concrete input values
  - What the predicate evaluates to (true/false, rendered in English)
  - What the English assertion description says should happen
- The human confirms or rejects each test case.
- **Gate:** Deploy is blocked until all generated test cases are confirmed.

**2b. Spec Test-Vector Corpus (adapted from Verus-SpecGym hack collection)**
- Maintain a growing corpus of Bloom-specific test vectors.
- When a human approves a predicate, the generated test cases are added to the corpus.
- Future predicates can reuse the corpus as a regression suite.
- This builds a "hack database" for Bloom — similar to Codeforces hacks but for Bloom predicates.

### Why This Works for Bloom Specifically

1. **Predicates are executable** — No need for SMT solver gymnastics. Concrete evaluation is cheap and deterministic.
2. **English rendering is built-in** — Makes the human review step actually usable. The human doesn't need to read predicate AST.
3. **Restricted AST means restricted failure modes** — No quantifiers, no recursion, no ghost state. The mutation space is bounded.
4. **Deploy-time gate is a natural choke point** — Unlike continuous integration, deploy is a low-frequency event where human attention is acceptable.

### Priority Implementation Order
1. **Tier 1a (Boundary test generation)** — highest ROI, leverages existing executable predicate infrastructure
2. **Tier 2a (Adversarial counterexample review UI)** — the actual intent-conformance check
3. **Tier 1b (Mutation completeness)** — quantitative quality signal
4. **Tier 2b (Test-vector corpus)** — compounding benefit over time
5. **Tier 1c (LLM consistency check)** — cheap additional signal

### Risks / Open Questions
- The "no oracle other than the user" problem (Lahiri 2026) is fundamental. Tier 2 still relies on human judgment.
- How many counterexamples are enough? Sparse testing can overestimate faithfulness (Verus-SpecGym shows diminishing returns with more tests, but the first few are critical).
- Predicate authors might get "review fatigue" if the gate generates too many spurious counterexamples.
- The English rendering must be accurate enough that humans can meaningfully compare it with their original assertion intent.

---

## References

1. Liu et al., "PropertyGPT: LLM-driven Formal Verification of Smart Contracts through Retrieval-Augmented Property Generation," NDSS 2025. arXiv:2405.02580
2. Agarwal et al., "Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization," 2026. arXiv:2605.26457
3. Lahiri, "Evaluating LLM-driven User-Intent Formalization for Verification-Aware Languages," FMCAD 2024. arXiv:2406.09757
4. Endres et al., "Can Large Language Models Transform Natural Language Intent into Formal Method Postconditions?" FSE 2024. arXiv:2310.01831
5. Lahiri, "Intent Formalization: A Grand Challenge for Reliable Coding in the Age of AI Agents," 2026. arXiv:2603.17150
6. Fakhoury et al., "3DGen: AI-Assisted Generation of Provably Correct Binary Format Parsers," 2024. arXiv:2404.10362
7. Faria et al., "Automatic Generation of Formal Specification and Verification Annotations Using LLMs and Test Oracles," 2026. arXiv:2601.12845
8. Bartoletti et al., "LLMs as verification oracles for Solidity," 2025. arXiv:2509.19153
9. Eshghie et al., "FLAMES: Fine-tuning LLMs to Synthesize Invariants for Smart Contract Security," 2025. arXiv:2510.21401
