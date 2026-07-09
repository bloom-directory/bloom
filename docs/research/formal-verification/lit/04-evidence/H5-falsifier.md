# H5 Falsifier — Source→Wasm proof transfer requires provenance-gating + ranked trust obligations

REFUTATION STRENGTH: none — every line of attack collapsed against the corpus. The two papers offered as gap-closers (RustCompCert, DeepSEA) are explicitly partial/unfinished and, crucially, DeepSEA's *Wasm* path "does not yet have a correctness proof"; bytecode-level verification (KEVM, VeriWasm, Crocus) does not moot source proofs but instead *confirms* the source→deployed gap is real and has already broken security in production; and the corpus shows PCC/TV/verified-compiler are complementary with no flips that would damage a trust-obligation ranking. The hypothesis survives intact and is in fact *strengthened* by the evidence.

---

## What H5 claims (restated for attack)

1. A source-level proof does NOT transfer to deployed Wasm absent a verified-compilation / translation-validation / PCC bridge.
2. Proofs must be provenance-gated (the proven artifact must be the deployed artifact).
3. The transfer mechanisms must be RANKED by trust obligation, not flattened into "all equally fine."

A refutation needs to break *any* of these. I attacked all three plus searched for a decisive disconfirming result. None held.

---

## Attack 1 — "The gap is real but practically negligible; verified compilation closes it for the relevant subset"

This is the strongest available line, and it fails on its own cited evidence.

### RustCompCert (full text) — explicitly ongoing, sequential subset only, partial safety
"RustCompCert: A Verified and Verifying Compiler for a Sequential Subset of Rust" (arXiv 2602.07455, https://arxiv.org/abs/2602.07455) (full text).

- Self-described as "**our ongoing work** on verifying a Rust compiler frontend." It is not a finished artifact.
- Scope: "Verifying all features of Rust is not realistic. We therefore focus on a core subset… **The main unsupported features include concurrency, polymorphism, traits, and higher-order functions (e.g., closures).**" Any realistic on-chain Rust contract (generics, traits, often closures) is outside the verified envelope.
- Target is **Asm via CompCert, not Wasm.** There is no verified Rust→Wasm pipeline here at all; the deployed-artifact language for Bloom is not even reached.
- Even within scope, the safety guarantee is **partial**: "the safety ensured by the borrow checker is partial safety: some UBs may still occur in the semantics… For example, division-by-zero is a typical UB that borrow checking cannot prevent… it remains the prover's responsibility to rule out these UBs" (footnote 2).

So the one verified-Rust-compiler paper in the corpus (a) is unfinished, (b) excludes the language features real contracts use, (c) does not target Wasm, and (d) preserves only partial safety. It cannot support "gap negligible."

### DeepSEA (full text) — the decisive blow against this attack
"Foundational Verification of Smart Contracts through Verified Compilation" (arXiv 2405.08348, https://arxiv.org/abs/2405.08348) (full text). This is a *real, working* end-to-end verified compiler from a source language to deployed bytecode — exactly the artifact a refuter wants. And it documents precisely why H5 is right:

- **The Wasm path is unverified.** "The backend for the MiniC language has two compilation paths, compiling to either EVM or 'Ethereum-flavored Web Assembly' (eWasm), but **the eWasm path does not yet have a correctness proof**." A state-of-the-art verified-compilation effort, when it targets the *exact artifact class H5 names (Wasm)*, has no proof. This is direct corroboration that source→Wasm transfer is the unsolved leg.
- **The trusted base contains a knowingly-false axiom.** "In the final compiler phase we need an **axiom (which is actually false, but 'true enough') stating that the concrete Keccak hash function is injective**." A "verified" compiler still rests on a false-but-tolerated assumption — i.e., verified-compilation is itself a *graded* trust obligation, not a binary "gap closed." This directly supports H5's ranking/provenance framing.
- **The target semantics is only tested, not verified.** The EVM model "has been tested against the VM test suites provided by the Ethereum Foundation" — testing, not proof. The bottom of even a foundational stack is a trust assumption.
- DeepSEA itself motivates H5: "the VC generation is not itself verified, so the verification tool itself could have correctness-critical bugs. This leads to the demand of foundational systems." That is the provenance-gating argument in the authors' own words.

Conclusion: the verified-compilation literature does not show the gap is negligible for the relevant subset. For the relevant *target* (Wasm) it shows the proof is **absent**, and even for EVM the bridge carries explicit, ranked residual trust (false axiom, tested-not-proven semantics). Attack 1 fails — and converts into supporting evidence.

---

## Attack 2 — "Verify the deployed Wasm/bytecode directly; source proofs and their transfer become moot"

This attack mis-models the relationship. Bytecode-level verification does not eliminate the transfer problem; the corpus shows it is *how you discharge* the transfer obligation when you can't trust the compiler — which is exactly translation-validation / PCC, i.e. H5's own mechanisms. And the bytecode-verification papers report the gap biting in production.

### KEVM (abstract) — semantics-first bytecode verification is real, but it is itself a transfer mechanism, not an escape
"KEVM: A Complete Semantics of the Ethereum Virtual Machine" (https://openalex.org/W2741675276) (abstract only). KEVM is the canonical "verify the deployed artifact directly" case: a complete executable EVM bytecode semantics, "an ideal formal reference implementation," used to "verify… properties over the arithmetic operation of an example smart contract." Two points defeat the attack:
- KEVM verifies *the bytecode against a model of the VM* — it does not relieve you of relating that bytecode to a source-level specification; it relocates the spec to bytecode level (more laborious, per DeepSEA: "working directly on bytecode without the benefit of data abstraction is very laborious… hard to use for large contracts"). The transfer obligation (does the deployed artifact meet the intended property?) remains; only its *placement* moves.
- Even KEVM's own foundation is validated by **testing**: it "passes the official 40,683-test stress test suite" and "reveals ambiguities and potential sources of error in the existing on-paper formalization." The bottom layer is again a trust assumption, reinforcing that mechanisms are *ranked*, not flat.

### VeriWasm (abstract) — the gap is not theoretical; it has broken Wasm isolation in production
"Доверяй, но проверяй: SFI safety for native-compiled Wasm" (NDSS 2021, https://openalex.org/W3138722985) (abstract only). The title ("trust, but verify") is itself H5's thesis. Verbatim: "subtle bugs in the Wasm compiler can break — **and have broken** — isolation guarantees." Their remedy is to "**verify memory isolation of Wasm binaries post-compilation**" — i.e. a verifier over the *deployed* artifact, deployed at Fastly. This is precisely provenance-gated, post-compilation checking. It does not make the source→deployed question moot; it *is* the answer to it, and it exists because trusting the compiler failed in the field.

### Crocus / Cranelift (abstract) — Wasm→native lowering carries CVE-severity miscompilation
"Lightweight, Modular Verification for WebAssembly-to-Native Instruction Selection" (DOI 10.1145/3617232.3624862, https://openalex.org/W4394871756) (abstract only). "Language-level guarantees — like module runtime isolation for WebAssembly — are only as strong as the compiler that produces a final, native-machine-specific executable." Crocus "reproduce[s] 3 known bugs (including a **9.9/10 severity CVE**), identif[ies] 2 previously-unknown bugs." So even *below* deployed Wasm, the Wasm→native leg miscompiles in ways that void the very isolation property. Verifying "the deployed Wasm directly" still leaves the Wasm→native execution leg as a separate, demonstrably-buggy transfer obligation. The number of trust legs increases, not decreases — directly opposing the attack's premise that bytecode verification ends the question.

### Wasm itself is a moving target
"Wasm SpecTec: Engineering a Formal Language Standard" (arXiv 2311.07223, https://openalex.org/W4388685487) (full text): Wasm is "a young technology [that] continues to evolve — it reached version 2.0 last year and another major update is expected soon." Any "verify the deployed Wasm directly" strategy is pinned to a semantics that is still changing — another reason direct-bytecode verification does not collapse the transfer/provenance question into nothing.

Conclusion: Attack 2 fails. Bytecode/Wasm-level verification is not an alternative that moots source proofs; in the corpus it *is* a transfer/PCC mechanism (KEVM relocates the spec; VeriWasm post-compiles a checker; Crocus checks lowering). And the empirical record (VeriWasm "have broken," Crocus 9.9 CVE) is the strongest possible confirmation that the source→deployed-Wasm gap is real and consequential — exactly H5's point.

---

## Attack 3 — "The PCC > TV > verified-compiler ranking is unsupported; mechanisms are context-dependent / the order flips"

I looked specifically for corpus evidence that the ordering inverts or that the three are interchangeable. I found the opposite: the mechanisms differ systematically in *what they put in the trusted computing base (TCB)*, which is exactly a trust-obligation ranking, and the literature treats them as complementary rather than rank-equal.

- **PCC pushes trust to a small proof checker.** "Proof-carrying code" (Necula, DOI 10.1145/263699.263712) and "The design and implementation of a certifying compiler" (DOI 10.1145/277650.277752, abstract): the certifier "automatically checks the type safety and memory safety of any assembly language program produced by the compiler," yielding "either a formal proof of type safety or a counterexample," and "this approach is a practical way to produce the safety proofs for a Proof-Carrying Code system." The compiler is *outside* the TCB; only the checker is trusted. "Foundational proof-carrying code" (DOI 10.1109/lics.2001.932501) shrinks the TCB further to the logic's foundations. This is a *strictly smaller* trust obligation than trusting a whole verified compiler's spec — a real ordering, not a flat field.
- **Verified compilation puts the whole compiler proof + target/source semantics in the TCB.** "A formally verified compiler back-end" (CompCert, arXiv 0902.2137): "the verification of the compiler guarantees that the safety properties proved on the source code hold for the executable." DeepSEA shows the residual TCB concretely: a false-but-"true enough" Keccak axiom and a *tested* (not proven) EVM semantics. Larger, graded trust surface.
- **Translation validation trusts a per-run validator, not the compiler.** "Translation Validation for JIT Compiler in the V8 JavaScript Engine" (DOI 10.1145/3597503.3639189): TurboTV "checks whether a *specific compilation* is semantically correct" and even "discovered a new miscompilation in LLVM." TV's obligation is per-instance and can be unsound if the validator's IR encoding is wrong — a different trust profile from a once-and-for-all compiler proof.
- **They are complementary, not competing/rank-equal.** The certifying-compiler paper explicitly frames itself as a *producer* for a PCC *consumer* (compiler emits proofs; checker verifies them) — the two compose. VeriWasm (post-compilation validation) composes with an untrusted compiler. JIT work ("Formally Verified Native Code Generation in an Effectful JIT," DOI 10.1145/3571202) "**reuses CompCert and its correctness proofs**" inside a TV-style dynamic setting — verified-compilation as a *component* of another mechanism. Composition is evidence *for* a structured ordering of obligations, against "flatten them."

I found **no** corpus paper claiming the ordering flips (e.g., that a verified compiler ever has a *smaller* TCB than a foundational-PCC checker, or that TV and verified compilation impose identical trust). The mechanisms differ precisely in trust surface — which is what "rank by trust obligation, not flatten" means. Attack 3 fails; if anything it supplies the ranking H5 asserts. (Caveat: the corpus supports ranking *by TCB/trust surface*; it does not uniquely pin a single total order valid in all deployment contexts — but H5 only claims they must be ranked, not flattened, which the evidence supports.)

---

## Attack 4 — Is there a decisive disconfirming result?

A decisive refutation would be a corpus paper showing a *verified, deployed* Rust→Wasm (or source→Wasm) pipeline whose source proofs transfer to the deployed artifact with no residual provenance/trust step — making gating "overkill." No such paper exists in the corpus:

- The closest verified-compiler-to-bytecode result (DeepSEA, full text) **explicitly lacks a Wasm correctness proof** and carries a known-false axiom.
- The closest verified-Rust-compiler result (RustCompCert, full text) is **ongoing**, excludes traits/generics/closures/concurrency, and targets Asm, not Wasm.
- The bytecode/Wasm verification results (KEVM, VeriWasm, Crocus) are *transfer/validation mechanisms themselves* and report the gap causing **real production failures** (VeriWasm "have broken" isolation; Crocus a 9.9 CVE).

The decisive result, if it existed, would refute H5. It does not exist; the nearest candidates each confirm the gap and the need for gating.

---

## Verdict

REFUTATION STRENGTH: **none.** I could not refute any of H5's three claims, and the corpus actively corroborates all three:

1. *Gap is real:* DeepSEA's Wasm path is unverified; VeriWasm reports compiler bugs that "have broken" Wasm isolation; Crocus finds a 9.9-severity Wasm→native CVE. (DeepSEA full text; VeriWasm, Crocus abstracts.)
2. *Provenance-gating needed:* VeriWasm verifies the *deployed binary* post-compilation; KEVM/DeepSEA bottom out in *tested* (not proven) semantics and false-but-tolerated axioms — the deployed artifact must be the gated one. (Full text + abstracts.)
3. *Rank, don't flatten:* PCC (small checker TCB) / TV (per-run validator TCB) / verified compiler (whole-proof + semantics TCB) differ systematically in trust surface and compose as complementary layers; no corpus paper shows the order collapsing or flipping. (PCC, certifying-compiler, CompCert, TurboTV, effectful-JIT.)

Honest residual: the corpus supports ranking *by trusted-computing-base / trust surface* and supports "complementary, not flat," but it does not, by itself, prove a single universal total order (PCC > TV > verified-compiler) that holds in *every* context — the relative trust can depend on checker quality, validator soundness, and semantics fidelity. That nuance refines H5's ranking, it does not refute it: the claim "must be ranked, not flattened" stands, and the specific PCC-minimizes-TCB direction is well supported.

### Papers cited
- Foundational Verification of Smart Contracts through Verified Compilation — https://arxiv.org/abs/2405.08348 (full text)
- RustCompCert: A Verified and Verifying Compiler for a Sequential Subset of Rust — https://arxiv.org/abs/2602.07455 (full text)
- Wasm SpecTec: Engineering a Formal Language Standard — arXiv 2311.07223, https://openalex.org/W4388685487 (full text)
- KEVM: A Complete Semantics of the Ethereum Virtual Machine — https://openalex.org/W2741675276 (abstract only)
- Доверяй, но проверяй: SFI safety for native-compiled Wasm (VeriWasm) — DOI 10.14722/ndss.2021.24078, https://openalex.org/W3138722985 (abstract only)
- Lightweight, Modular Verification for WebAssembly-to-Native Instruction Selection (Crocus) — DOI 10.1145/3617232.3624862, https://openalex.org/W4394871756 (abstract only)
- Proof-carrying code (Necula) — DOI 10.1145/263699.263712 (abstract only)
- The design and implementation of a certifying compiler — DOI 10.1145/277650.277752 (abstract only)
- Foundational proof-carrying code — DOI 10.1109/lics.2001.932501 (abstract only)
- A formally verified compiler back-end (CompCert) — arXiv 0902.2137 (abstract only)
- Translation Validation for JIT Compiler in the V8 JavaScript Engine (TurboTV) — DOI 10.1145/3597503.3639189, https://openalex.org/W4394745579 (abstract only)
- Formally Verified Native Code Generation in an Effectful JIT — DOI 10.1145/3571202, https://openalex.org/W4310884974 (abstract only)
