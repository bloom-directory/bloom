# H5 — Proponent Case: The source→artifact gap, provenance-gating, and ranked transfer mechanisms

SUPPORT STRENGTH: strong — The foundational literature establishes both legs of the hypothesis: (a) unverified compilation can silently invalidate a source-level proof (Leroy/CompCert, V8/TurboTV miscompilation found in LLVM), and (b) the three transfer mechanisms — proof-carrying code/certificate checking, translation validation, and whole-compiler proof — discharge *different* trust obligations with *different* TCB sizes, which is exactly what justifies ranking them rather than treating them as interchangeable. The corpus is honest about its limits: the directly-verified-compiler evidence is mostly C/native (CompCert) and Rust→native or DeepSEA→EVM, not Rust→Wasm specifically; but the *mechanism-level* argument is language-agnostic and transfers cleanly to the Bloom petal (Rust→Wasm) setting.

---

## Claim 1 — A proof about source code does NOT automatically hold of the deployed artifact (the gap is real)

The canonical statement of the gap comes from the CompCert program itself. Leroy frames compiler verification precisely as closing a hole that formal source-level methods would otherwise leave open:

- **"Formal verification of an optimizing compiler"** (Leroy), DOI: 10.1109/memcod.2007.371254 (abstract only) —
  > "Bugs in compilers do happen and can lead to silently producing incorrect executable code from a correct source program. This is a significant concern in the context of high-assurance software that has been verified (at the source level) using formal methods … any bug in the compiler can potentially invalidate the guarantees so painfully established by the use of formal methods."

  This is the hypothesis's claim (a) stated by the field's foundational author: a source proof does not transfer through an unverified compiler, because miscompilation is *silent* — the artifact misbehaves while the source proof remains "true" of the source. The same paper enumerates exactly the three remediation families H5 wants to rank: *"There are several ways to generate confidence in the compilation process, including translation validation and proof-carrying code,"* before turning to *"applying program proof technology to the compiler itself."*

- **"A formally verified compiler back-end"** (Leroy), DOI: none in corpus / corpus key present, year 2009 (abstract only) — confirms the converse (what verified compilation *buys* you):
  > "the verification of the compiler guarantees that the safety properties proved on the source code hold for the executable compiled code as well."

  Read together, these two establish the logical core of H5: **without** a verified/validated translation, the implication "source proof ⇒ artifact safe" is *unsound*; **with** it, the implication holds. So a deployment that ships an artifact must tie any accepted proof to that artifact's provenance — otherwise the proof is about a different object than the one running.

The gap is not theoretical. Translation validation work finds *actual* miscompilations in production compilers:

- **"Translation Validation for JIT Compiler in the V8 JavaScript Engine"** (TurboTV), DOI: 10.1145/3597503.3639189 (abstract only) — an SMT-based validator that *"checks whether a specific compilation is semantically correct"* and, in evaluation, *"discovered a new miscompilation in LLVM."*

  This is direct empirical support that even mature, heavily-tested optimizing compilers emit semantically-wrong code — i.e., the source→artifact gap manifests in shipping toolchains, not just in principle. (Honest scope note: V8/TurboFan is JS JIT and LLVM IR, not Rust→Wasm; but the failure mode — optimizing-compiler miscompilation surviving conventional testing — is the same one a Rust→Wasm petal pipeline faces.)

**Provenance-gating follow-through.** Because the proof is sound only relative to a *specific* compiled artifact (the validated "specific compilation," the certified target program, or the output of the proven compiler), the correct deployment discipline is to bind the accepted proof to the bytes that were actually deployed — in Bloom's terms, gate proofs against the deployed `petal_hash`. A proof over source `S` says nothing about a Wasm blob `W` unless something certifies `W = compile(S)` (translation validation), or `W` carries its own checkable evidence (PCC), or the compiler producing `W` is itself proven (whole-compiler proof). Absent that link, an attacker (or an honest toolchain bug) can deploy a `W` that does not match the proven `S`, and the proof provides no protection. This is the architectural reason ADR-006/007 attach proofs to artifact hashes rather than to source.

---

## Claim 2 — The three transfer mechanisms differ in trust obligation and TCB, justifying a RANK

The three mechanisms all close the gap, but they are *not* interchangeable: each moves a different amount of code into or out of the trusted computing base, and each demands a different per-deployment obligation. The corpus lets us characterize all three.

### Mechanism A — Proof-carrying code / certificate checking (artifact carries checkable evidence)
- **"Proof-carrying code"** (Necula), DOI: 10.1145/263699.263712 (abstract only; 1033 citations — the foundational, highest-cited node here). PCC ships the (untrusted) code together with a machine-checkable *proof* that it satisfies a safety policy; the consumer runs a small **proof checker**. The trust obligation is per-artifact (every artifact carries its own certificate) and the TCB is the proof checker + the safety/verification-condition framework.
- **"The design and implementation of a certifying compiler"** (Necula & Lee), DOI: 10.1145/277650.277752 (abstract only) — shows how to *produce* PCC evidence automatically. Crucially it names the trust trade-off that underlies the whole ranking:
  > "The notion of a certifying compiler is significantly easier to employ than a formal compiler verification, in part because it is generally easier to verify the correctness of the *result* of a computation than to prove the correctness of the computation itself."

  This is the key asymmetry: **you do not have to trust the compiler at all** under PCC/certificate-checking — you trust only the checker that validates each output. The compiler can be buggy, optimizing, even adversarial; a bad output simply fails the check. The certifier *"is either a formal proof of type safety or a counterexample,"* and it makes the result independently checkable. TCB ≈ checker; per-deployment cost = run the checker on each artifact.

### Mechanism B — Translation validation (per-compilation equivalence check)
- **"Translation Validation for JIT Compiler in the V8 JavaScript Engine"** (TurboTV), DOI: 10.1145/3597503.3639189 (abstract only). TV does not prove the compiler; it proves, *for each run*, that this output is semantically equivalent to this input (*"checks whether a specific compilation is semantically correct"*). The compiler stays out of the TCB; what enters the TCB is **the validator plus the formal semantics it encodes** — for TurboTV, the SMT encoding of TurboFan IR semantics and the SMT solver. The obligation is per-compilation (must re-validate after every build), and TV can be *incomplete* (false positives / unvalidated cases) where the certifier/PCC checker is a total decision procedure for its policy.

  TV and PCC differ in *what* is checked: PCC checks an artifact against a *safety policy / spec* and ships a proof object; TV checks an artifact against the *source it was compiled from* and need not ship anything (the validator re-derives equivalence). They therefore discharge different obligations: PCC transfers a *property* proof; TV transfers a *semantic-equivalence* guarantee that lets a separate source proof carry over.

### Mechanism C — Whole-compiler proof (compile once, trust the compiler forever)
- **"Formal verification of an optimizing compiler"** / CompCert (Leroy), DOI: 10.1109/memcod.2007.371254, and the **back-end** correctness result (Leroy 2009): a once-and-for-all *semantic preservation theorem* proved for every pass in Coq. After this, no per-artifact check is needed for correctness of translation — the theorem covers all inputs. But the **compiler itself is now in the TCB** (specifically its Coq proof and the trusted extraction/spec), which is a much larger artifact than a proof checker.
- **"RustCompCert: A Verified and Verifying Compiler for a Sequential Subset of Rust"** (Wu, Wang, Yu, Meng), arXiv:2602.07455 (full text) — the most on-point corpus item for Bloom's Rust setting. It targets exactly H5's structure for a Rust source language and gives the end-to-end transfer theorem:
  > "∀ (Ms : Rustlight) (Mt : Asm), RustCompCert(Ms)=Mt ⇒ ⟦Mt⟧ ⩽ ⟦Ms⟧ … the behaviors of source program is included in the behaviors of target program."
  and the explicit property-transfer corollary:
  > "By combining the soundness of borrow checking and the compiler correctness, the properties verified in RustIRspec can be preserved to the assembly."

  Two things matter for H5 here. First, this *is* whole-compiler proof for Rust: the compiler (green/verified passes) is in the TCB but discharges all per-artifact obligation. Second, RustCompCert is also *"verifying"* — it includes a verified borrow-check pass whose soundness is itself a proved refinement — illustrating that a single toolchain can combine a verified core with verifying/certificate-producing passes. The paper is also commendably honest that even a verified compiler only transfers the properties it proves: borrow checking gives only *partial* safety, and *"it remains the prover's responsibility to rule out"* remaining UB (e.g. division-by-zero). That sharpens H5: the *kind* of property transferred, not just the fact of transfer, depends on the mechanism. (Scope note: RustCompCert targets a sequential Rust subset → Asm via CompCert, **not Wasm**, and excludes traits/closures/concurrency — directly relevant but not yet the Rust→Wasm petal target.)
- **"Foundational Verification of Smart Contracts through Verified Compilation"** (DeepSEA; Sjöberg, Dave, Britten, Schett, Sun, Wang, Anderson, Reeves, Shao), arXiv:2405.08348 (full text) — the closest corpus analogue to the *blockchain-artifact* setting. It is the strongest single statement that the **mechanism choice determines what is trusted**:
  > "dsc generates a proof that the specification is refined by the bytecode, so although the dsc tool is not itself verified it is **not in the trusted computing base**."

  This is precisely the PCC/certificate-checking idea operationalized in a smart-contract pipeline: because each compilation *emits a checkable refinement proof tying the user's spec to the deployed bytecode*, the (large, unverified) compiler is kept out of the TCB. The paper also motivates *foundationality* in exactly H5's terms — correctness must be anchored to the operational semantics of the *deployed* artifact's execution environment (the EVM), not to ad-hoc source-level VCs:
  > "the VC generation is not itself verified, so the verification tool itself could have correctness-critical bugs. This leads to the demand of foundational systems, which are based on a formal semantics for the [machine] itself."

  DeepSEA further shows the gap has *machine-specific* teeth: the correctness theorem must track **gas** through every pass and distinguish programmer-avoidable UB from attacker-triggerable errors (out-of-gas) — obligations that exist only because the proof must hold of the *deployed* artifact in its real VM, not of an idealized source. That is the H5 thesis (gate to the deployed artifact, in its real execution semantics) demonstrated end-to-end for bytecode.

### The machine the artifact runs on must itself be formalized (why "deployed-artifact" proofs need a target semantics)
- **"KEVM: A Complete Semantics of the Ethereum Virtual Machine"** (Hildenbrandt et al.), OpenAlex W2741675276 (abstract only) — argues the *"semantics-first formal verification approach"*: verify the bytecode against a complete, executable formal semantics of the VM (the EVM). KEVM is the reference the DeepSEA effort builds on. For H5 this supplies the missing piece of the transfer chain: to gate a proof against a *deployed* artifact you need a formal semantics of the artifact's language (EVM bytecode there; Wasm in Bloom's case). KEVM shows this is achievable and that the on-paper semantics it replaced contained *"ambiguities and potential sources of error"* — i.e., even the target-semantics layer is a real trust obligation, reinforcing that different mechanisms shift trust between checker, validator, compiler, and *machine semantics* differently.

---

## Why this ranks (synthesis the corpus supports)

The papers collectively support a *ranking by TCB / trust obligation*, not a flat "any mechanism will do":

1. **PCC / certificate-checking** (Necula 1997; certifying compiler 1998; DeepSEA's "dsc not in TCB") — smallest TCB (a proof checker), compiler fully untrusted, per-artifact checkable evidence. Strongest provenance story: the certificate is *about the deployed bytes*. Cost: every artifact must ship and pass a certificate; expressiveness limited by the policy/spec the checker understands.
2. **Translation validation** (TurboTV) — compiler untrusted, but TCB grows to include the validator + encoded target semantics + solver, and it is per-compilation and potentially incomplete. Empirically finds real miscompilations, so it genuinely closes the gap, but its guarantee is equivalence-to-source, not a self-contained property proof.
3. **Whole-compiler proof** (CompCert/Leroy; RustCompCert) — no per-artifact check, but the *entire verified compiler* (and its Coq proof / extraction) is in the TCB; covers only the proven subset and proven property classes. Highest one-time assurance, largest trusted artifact, least flexible to a heterogeneous/optimizing real-world toolchain.

These are *not* interchangeable precisely because they trade the same risk along different axes — *who is trusted* (checker vs. validator+semantics vs. whole compiler), *when the obligation is paid* (per-artifact vs. per-compilation vs. once), and *what is transferred* (a property proof vs. semantic equivalence vs. a preservation theorem). That asymmetry is the substantive content of H5's "should be RANKED."

---

## Honest limitations of the supporting corpus

- **No Rust→Wasm verified/validated compiler in the corpus.** The verified-compilation evidence is C/native (CompCert), Rust→native (RustCompCert), or DeepSEA→EVM bytecode. The Rust→Wasm path that Bloom petals actually use is *not* directly covered; the support is by mechanism-level analogy, not by a paper that verifies the exact pipeline.
- **TV/miscompilation evidence is JS/LLVM (TurboTV), not Wasm-emitting Rust.** It proves the *failure mode* exists in production optimizing compilers generally; it does not measure it for `rustc`/LLVM-Wasm specifically.
- **Several foundational items are abstract-only** (Necula PCC; certifying compiler; Leroy compiler papers; KEVM; TurboTV; Foundational PCC has no abstract in-corpus), so the per-mechanism TCB claims rest on abstracts plus the two full-text anchors (RustCompCert, DeepSEA) rather than on full-text TCB accounting for every cited work.
- **RustCompCert is explicitly partial** (sequential subset; partial safety; remaining UB is the prover's burden) and is described as *ongoing work* — it demonstrates the transfer theorem exists for Rust, not that a production Rust→Wasm petal toolchain is verified today.

Even with these caveats, the central two propositions of H5 are well-supported: unverified compilation can silently invalidate a source proof (Leroy; TurboTV's real LLVM miscompilation), and the three transfer mechanisms discharge distinct trust obligations with distinct TCBs (Necula PCC; certifying compiler; CompCert/RustCompCert; DeepSEA's "compiler not in the TCB") — which is what licenses both provenance-gating against the deployed artifact and a *ranking* of the mechanisms.
