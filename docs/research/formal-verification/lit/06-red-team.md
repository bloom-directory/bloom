# 06 — Red Team (literature synthesis)

*Adversarial review of the ADR-001…007 stress-test synthesis and its `05-verdict-log.md`.
Each `RT-00n` names a specific claim, why it is vulnerable, and the minimal change that
would make it defensible (soften / cite / drop). Citations are to corpus papers only.
"Cites" figures are the corpus `citations` field; "fetch status" is from
`data/fulltext/manifest.json`. Verdict at the end: which parts survive.*

---

## RT-001 — The "novel insight" (§3, V-006 cross-cutting) outruns the corpus: there is NO Wasm-zkVM evidence in the corpus at all

**Claim:** "Can one verified executable Wasm semantics serve simultaneously as the
differential-conformance oracle (determinism) AND the adjudicating reference for zkVM fraud
proofs?" — framed as the synthesis's central, earned reframing ("the verified semantics… is the
real spine").

**Why vulnerable:** The entire zkVM half of this unification rests on **Arguzz**, which tests
**six RISC-V zkVMs** (SP1, RISC Zero, JOLT, …). A full-text grep of the corpus for
`zkvm|zkwasm|zk-wasm|(zero-knowledge … vm)` returns **no paper that puts a Wasm program through a
zkVM**. The bridge "RISC-V zkVM underconstraint ⇒ therefore a *Wasm* semantics must adjudicate
Wasm fraud proofs" is an analogy the corpus does not contain a single instance of. The determinism
oracle (WasmRef-Isabelle, Wasm) and the soundness oracle (Arguzz, RISC-V) operate on **different
machine models**; the claim that one artifact serves both is asserted, not evidenced. The
verdict log itself concedes "no single corpus paper demonstrates it deployed" (V-006) and "argued
compositionally" — yet §3 promotes it to "the real spine" and §4 to "best open question" without
carrying that caveat.

**What would have to change:** Demote §3 from a finding to an explicitly-labeled *conjecture /
research direction*. State plainly that the unification is a **cross-model analogy** (RISC-V
soundness evidence + Wasm determinism evidence), and that **no corpus paper studies a Wasm zkVM**,
so the "one oracle for both" architecture is untested in the corpus. Keep it as the open question
(§4) but strip the load-bearing language ("the real spine," "fewer independent trust roots than it
appears") that presents it as a result.

---

## RT-002 — Arguzz's mechanism is mischaracterized: it is "fault injection into product programs with a *constructed* known output," NOT "re-execution against honest reference semantics"

**Claim (§1, V-006):** "re-execution against honest reference semantics is the structural
backstop"; "Arguzz's oracle re-executes inputs under honest reference semantics (a product
program with known output) — the honest VM *is* the authoritative semantics."

**Why vulnerable:** This is the keystone of the "strong" H6 verdict and the §3 insight, and it
misstates what Arguzz does. Arguzz's own description (full text, lines 31–34, 155, 326–351,
460–464, 863–864): it is **"a novel variant of metamorphic testing with fault injection."** The
oracle is a **product program whose output is known *by construction*** (the program is built to
compute a known value), executed inside the *unmodified* zkVM; fault injection then perturbs it.
The three soundness bugs "were revealed through **fault injection**" (line 863–864) — not through
re-execution against an external authoritative VM semantics. There is no "honest reference VM" in
Arguzz; the "known output" comes from the synthetic product-program construction, the same Rust
toolchain that compiles the candidate. The synthesis relabels "metamorphic + fault injection on
self-checking product programs" as "re-execution against honest reference semantics" because that
phrasing is what the verified-Wasm-semantics insight (RT-001) needs. The further claim that
"circuit-equivalence metamorphic testing alone caught zero [soundness bugs]" is *Arguzz's own
metamorphic component vs. its own fault-injection component* (line 863–866) — an internal ablation,
not a refutation of an independent circuit-equivalence line of work.

**What would have to change:** Restate the mechanism in Arguzz's own terms: metamorphic testing +
fault injection on product programs with a constructed known output. Drop "re-execution against
honest reference semantics" as a description of Arguzz. The H6 *conclusion* (a check independent of
the prover's own trace is needed) can survive, but the specific "re-execution-against-semantics"
framing — and therefore the clean tie to the Wasm-semantics oracle — is not what Arguzz shows.

---

## RT-003 — "Sound only with a *verified* oracle" is an inference the corpus contradicts in its own example

**Claim (V-006):** the fallback "is sound only with a **verified** oracle (Arguzz even hit a Rust
miscompilation)."

**Why vulnerable:** The Arguzz Rust miscompilation (full text, lines 964–972) was found *as a
by-product* in RISC Zero's Rust 1.80 toolchain — while Arguzz's **own** product-program oracle is
built with the **same unverified Rust compiler** and was nonetheless effective at finding 11 bugs.
So the corpus's one data point shows an *unverified* oracle working, with toolchain bugs surfacing
as additional findings — not that a *verified* oracle was necessary. "Therefore you need a verified
semantics" is the synthesis's desired conclusion (it props up RT-001), not Arguzz's. The corpus's
only "verified oracle deployed in industry" datum is **WasmRef-Isabelle** — see RT-004.

**What would have to change:** Soften to: "a verified oracle would *raise assurance* by removing the
oracle's own toolchain from the TCB; the corpus shows an unverified oracle is already effective and
that toolchain bugs are themselves detectable." Do not assert verification is a soundness
*precondition* for the fallback.

---

## RT-004 — WasmRef-Isabelle is load-bearing for the central insight yet is abstract-only AND its fetch FAILED

**Claim (§2, V-004):** the verified fuzzing oracle (WasmRef-Isabelle) carries "sufficiency"; §3
makes "a pinned, verified, executable Wasm semantics" the spine of the whole ladder.

**Why vulnerable:** WasmRef-Isabelle is cited "(abstract)." The manifest is worse than that: its
fetch `status` is **`"failed"`** (403), `chars: 0` — it was never retrieved as a research artifact;
the synthesis is leaning on the corpus abstract alone. The single most architecturally consequential
artifact in the synthesis (the "spine") is supported by one paragraph. The abstract does support
"verified interpreter deployed as a Wasmtime fuzzing oracle" (11 cites, the best-supported of the
load-bearing claims), but it says nothing about (a) serving as a zkVM fraud-proof adjudicator,
(b) a Rust→Wasm setting, or (c) being a single shared artifact across both roles. The synthesis's
"(full text)/(abstract)" tagging is also slightly generous here — there is no full text.

**What would have to change:** Tag WasmRef-Isabelle as **abstract-only, full-text fetch failed**.
Explicitly state that no full-text engagement with the verified-semantics-as-oracle claim was
possible, and that the §3 "spine" rests on one abstract plus the cross-model analogy of RT-001.
Flag a WasmRef-Isabelle / WasmCert-Isabelle re-fetch as a *higher* priority gap than the
"Uncovering… Differential Fuzzing" paper currently named in V-004.

> **DISCHARGED (2026-05-29).** WasmRef-Isabelle full text persisted via co-author Maja Trela's open
> Cambridge dissertation ("Extending a WebAssembly formalisation") + the published abstract — the ACM
> paper PDF is Cloudflare-gated — and "Uncovering… Differential Fuzzing" (NeoDiff) fetched in full
> (recorded in `data/fulltext/manifest.json`, in the external research store — see [`RESEARCH.md`](RESEARCH.md)). The full text engages the
> refinement-proof construction and the Wasmtime-CI oracle deployment, firming V-004. The thread's
> *substantive* caveats stand and are not retracted: the dissertation/abstract still say nothing about
> a zkVM fraud-proof role, a Rust→Wasm setting, or a single shared artifact across both roles — so the
> §3 "spine" remains a **conjecture** carried by analogy (V-006), not a corpus-proven result. Only the
> *fetch-gap* sub-claim is closed. *(Update: WasmCert-Isabelle has since also been fetched in full —
> the mechanised Isabelle semantics + verified interpreter underneath WasmRef — so the fetch gap is now
> fully closed; the substantive conjecture caveat still stands.)*

---

## RT-005 — Nearly every full-text pillar of the "strong" verdicts is an uncited 2024–2026 preprint; publication-bias risk is not disclosed

**Claim:** H5 and H6 are "STRONG / high confidence"; the §1 evidence list presents the full-text
papers as settled.

**Why vulnerable:** Corpus `citations`: **Arguzz = None**, **RustCompCert = None**, **Foundational
Verification (DeepSEA) = None**, **Theorem-Carrying Transactions = None**, **Verus-SpecGym = None**,
**Wasm SpecTec = 1**. The papers doing the heaviest lifting for the "strong" labels are unreviewed-
or-just-published preprints (2024–2026) with essentially zero independent corroboration. Move
Prover, VerX, PCC, and the 1998 certifying-compiler paper are the only well-cited anchors, and they
back the *least* contested claims (predicate substrate; gap exists). The novel/aggressive claims
(re-execution backstop, TCB ranking, verified-semantics spine) ride on the uncited cohort. A "strong"
label on an uncited 2025 preprint (Arguzz) is a confidence claim the citation record cannot yet
support.

**What would have to change:** Add a publication-bias disclosure. Downgrade H6 generality from
"STRONG" to "MODERATE — single uncited 2025 preprint, RISC-V only." Keep "high" only on the
claims anchored by well-cited papers (substrate, the compilation gap). Distinguish "the mechanism
is real and demonstrated once" from "the field has confirmed this."

---

## RT-006 — Cherry-picking: a verified verification-to-Wasm result (F*→Wasm, 25 cites) is uncited against "no verified Rust→Wasm pipeline"

**Claim (V-005, §2 "Open"):** "no verified Rust→Wasm pipeline exists."

**Why vulnerable:** The literal claim (Rust *source* → Wasm, end-to-end machine-checked) may hold,
but the synthesis presents the gap starkly without engaging the corpus's nearest counter-evidence:
**"Formally Verified Cryptographic Web Applications in WebAssembly"** (2019, **25 cites** — better
cited than any H5/H6 pillar). That work compiles verified F* down to Wasm with assurance carried to
the Wasm artifact, i.e. a *verified-to-Wasm* path. The corpus also has **"Lightweight, Modular
Verification for WebAssembly-to-Native Instruction Selection"** (2024, 7 cites — this is Crocus) and
**SFI safety for native-compiled Wasm** (2021, 13 cites — VeriWasm), which the synthesis cites only
on the *binary-verification* side while omitting that the verified-*producer*-to-Wasm direction
already has a cited exemplar. Omitting the 25-cite F* result while leaning on uncited preprints is
exactly the asymmetry a reviewer should flag.

**What would have to change:** Narrow the claim to "no verified **Rust**→Wasm compiler exists,
though verified **F***→Wasm (Protzenko et al., 2019, 25 cites) demonstrates the *direction* is
achievable for a different source language." This actually *strengthens* the ADR-006 "feasible at
cost" framing — it just has to be cited rather than omitted.

---

## RT-007 — Cherry-picking on floats: the corpus has float-verification successes beyond the three cited, and the necessity-refutation leans on a failed-fetch paper

**Claim (V-003):** float exclusion is "NOT necessary"; deterministic/reproducible FP is achievable
(CT-wasm, FP-consistent cross-verification, nondeterministic-payment-bugs).

**Why vulnerable on two sides.** (1) **The refutation's own evidence is thin:** of the three cited
FP papers, **CT-wasm** and **"Detecting nondeterministic payment bugs"** both have manifest
`status: "failed"` (403, chars 0) — abstract-only at best — and the FP-consistent cross-verification
paper is a **2026, 1-cite** preprint. The verdict log already flags this ("thinnest corpus cluster;
several FP papers abstract-only"), but §1/§2 of the synthesis present the necessity-refutation
crisply without that hedge. (2) **Under-cited supporting work exists** ("Lipschitz-Based Robustness
Certification Under Floating-Point Execution," 2026; "When Does a Bit Matter?", 2021) but is itself
uncited and fetch-failed — so it cannot rescue the cluster. The net: the *direction* (exclusion is
sufficient-not-necessary) is plausible, but the confidence should not read "STRONG (engineering)"
beside a refutation built on failed fetches and 1-cite preprints.

**What would have to change:** Move the float-necessity refutation's confidence from the assertive
§1 phrasing to "MODERATE — supporting FP papers are abstract-only/fetch-failed; the engineering
case for exclusion (simplest sufficient means) is the robust part." This is mostly already in V-003;
the *synthesis §1/§2 bullets* need to inherit the hedge.

---

## RT-008 — "Strict total order vs. complementary" already softened in the log but overstated in §1

**Claim (§1):** "mechanisms rank by TCB (STRONG on gap; MODERATE on strict total order)."

**Why (mostly) solid, with one nit:** The verdict log (V-005) handles this well: gap + provenance-
gating "high," strict total order "moderate," and notes the corpus supports "ranking by TCB" and
"complementary, not flat." This is one of the more disciplined parts of the synthesis. The only
residual overreach: DeepSEA's "the dsc tool is not in the TCB" quote supports *PCC has a small
checker TCB*, but the **ordering across PCC vs. TV vs. whole-compiler-proof** is argued
mechanistically, not measured — no corpus paper benchmarks the three on a common artifact. The
"ladder" is a reasoned construct, not an empirical ranking.

**What would have to change:** Minor. Add one clause: "the TCB ranking is *analytic* (reasoned from
each mechanism's trusted surface), not an empirical comparison; no corpus paper evaluates the three
on a shared target." Otherwise this verdict holds.

---

## RT-009 — Alternative reading: the same corpus supports "intent-conformance, not verified semantics, is the real spine"

**Claim (§3):** the verified executable semantics is "the real spine"; H1/H2 refutations are a
*secondary* "second pattern" relocating the gap to the human-intent boundary.

**Why vulnerable:** A reviewer can read the *same* corpus the opposite way and arrive at a defensible
rival thesis. The best-cited, full-text, **non-preprint** evidence in the whole corpus clusters on
the **specification-faithfulness / intent-formalization** problem: Verus-SpecGym (judge misses 26%),
"Evaluating LLM-driven User-Intent Formalization" (full text), PropertyGPT (**42 cites** — the
highest-cited full-text paper backing any contested claim). The verified-semantics spine, by
contrast, rests on one failed-fetch abstract (WasmRef) + one RISC-V preprint (Arguzz) + a cross-model
analogy (RT-001). On *evidence weight*, the stronger "single load-bearing gap" is **intent
conformance** (what the predicate is *supposed* to say), which no executable semantics — verified or
not — closes. The synthesis subordinates its best-evidenced pattern to its least-evidenced one
because the latter is tidier.

**What would have to change:** Either (a) elevate the intent-conformance gap to co-equal "spine"
status, noting it is the better-cited finding, or (b) explicitly argue why the verified-semantics
gap dominates despite resting on weaker evidence — which the current text does not do. As written,
the ranking of the two "patterns" is inverted relative to the evidence.

---

## RT-010 — Scope/transfer: EVM- and RISC-V-derived conclusions are exported to Bloom's Rust→Wasm / Move-like setting with thin bridging

**Claim (throughout):** conclusions are presented as applying to Bloom's ADRs.

**Why vulnerable:** The corpus's strongest anchors are domain-shifted from Bloom: Move Prover (Move,
not Wasm-deployed), VerX / 2Vyper / PropertyGPT / TCT (EVM/Solidity), Arguzz/SoK (RISC-V + EVM-style
SNARK circuits), DeepSEA (eWasm path "explicitly unproven" per V-005). The verdict log flags the
H5 transfer ("by mechanism analogy") but the *synthesis* §1/§3 generalize to "Bloom's verification
ladder" without restating that almost every pillar is EVM/Move/RISC-V and the Rust→Wasm target is
extrapolated. The §3 claim about "Bloom's" trust roots inherits every transfer gap at once.

**What would have to change:** Add a standing scope caveat to §1/§3: the corpus's evidence base is
EVM/Solidity (predicate + intent), Move (prover/floats), RISC-V (zkVM), and C/Rust→native
(compilation gap); **the Rust→Wasm, Wasm-deployed, Move-like target is reached by analogy in every
strand**, and the convergence claim in §3 multiplies those analogies rather than testing them.

---

## RT-011 — An empty-abstract paper is named as a load-bearing gap, which is fine; but a *failed-fetch* paper is treated as read elsewhere

**Claim (§2 / V-004):** "Uncovering Smart Contract VM Bugs Via Differential Fuzzing" is
title/empty-abstract only (unread) — correctly disclosed.

**Why (mostly) solid:** This disclosure is good practice and should stay. The inconsistency is that
the *same hygiene is not applied* to fetch-failed papers cited affirmatively (WasmRef = failed but
cited "(abstract)", RT-004; CT-wasm and nondeterministic-payment-bugs = failed but cited "(abstract)"
to refute float necessity, RT-007). The synthesis discloses the *one* empty-abstract paper while
silently upgrading several *failed-fetch* papers to "(abstract)."

**What would have to change:** Apply the V-004 honesty uniformly. Mark every cited paper with its
true manifest status; where a "(abstract)" citation is actually a failed fetch backed only by the
corpus abstract field, say so.

---

## What is genuinely solid (do not soften)

- **V-001 substrate + the two refutations.** Move Prover/VerX/2Vyper (well-cited, full text) clearly
  back "restricted declarative predicate = right auditable substrate," and Prusti/Verus clearly
  refute "opaque ⇒ unarbitrable." The "readability ≠ arbitration" refutation is the **best-evidenced
  claim in the synthesis** (PropertyGPT 42 cites + two full-text papers). Keep "STRONG."
- **V-005 gap + provenance-gating.** The "source proof ≠ deployed-artifact guarantee without
  verified compilation/TV/PCC" core is anchored by CompCert-lineage and the 1998 certifying-compiler
  paper (357 cites) plus DeepSEA full text. The gap itself is not in doubt; only the *total ordering*
  and the *Rust→Wasm transfer* need the existing hedges (RT-008, RT-010).
- **V-002 causal core + TCT refutation.** Solid and full-text-backed; the "stateless post-commit view
  fn is the strictly weaker primitive" survives, and the TCT pre-commit refutation is correctly
  scoped.
- The SoK-SNARKs quantification (124/141 soundness; 95/99 circuit bugs under-constrained) **checks out
  against the full text** and legitimately establishes that under-constraint is the dominant class.
  The weakness is not SoK; it is the leap from SoK+Arguzz (RISC-V) to a Wasm semantics oracle
  (RT-001/RT-002).

---

## Net assessment

The synthesis is strongest exactly where it is least exciting (substrate, compilation gap, intent-
conformance refutation) and weakest exactly at its headline (§3 "verified semantics is the spine,"
§4 unified oracle). The two should trade places in prominence. Required changes, in priority order:
**RT-002** (fix the Arguzz mechanism description — it is a factual misread), **RT-001/RT-004**
(demote the unified-oracle insight to conjecture; disclose WasmRef is a failed fetch),
**RT-005** (publication-bias disclosure; downgrade H6 generality to MODERATE), then the cherry-pick
and scope fixes (RT-006, RT-007, RT-010, RT-011). RT-008/RT-009 are reframes, not errors. The
verdict log's own confidence hedges are good; the failure mode is that the **synthesis prose
(§1–§4) does not inherit them** and rounds "moderate, analogical, uncited-preprint" up to "STRONG."
