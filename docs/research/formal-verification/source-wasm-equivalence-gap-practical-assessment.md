# Source→Wasm Equivalence Gap — Practical Assessment

**Date:** 2026-05-29  
**Status:** Research input for ADR-006 refinement  
**Scope:** What is *practically* achievable today for proving Rust source → trusting deployed Wasm, with concrete toolchain recommendations and TCB analysis.

---

## TL;DR

**No verified Rust→Wasm compiler exists.** None of the three verification-aware Wasm paths — VeriWasm (SFI safety only, not source mapping), Crocus (Wasm→native instruction selection only), DeepSEA (eWasm "explicitly unproven") — bridges this gap. The F\*→Wasm pipeline is the closest precedent (a verified compiler from a different source language to Wasm) but has no Rust frontend. The most impactful thing Bloom can do *today* is differential testing between a Kani-proved source kernel and its compiled Wasm, using wasm-mutate/wasm-smith as adversarial generators.

**TCB ranking remains correct (PCC > translation validation > trusted compiler), but the entire "PCC for Rust→Wasm" entry is vacant.** For Bloom's near term, the pragmatic path is: (1) reproducible builds + toolchain attestation, (2) differential fuzz-gate between proven Rust source and deployed Wasm, (3) hedge with the DeepSEA-approach pattern (embed Wasm semantics in the proof, making the compiler untrusted).

---

## 1. VeriWasm (Johnson et al., NDSS 2021)

### What it does
VeriWasm verifies **SFI (Software Fault Isolation) safety** for native-compiled Wasm binaries. Specifically, it proves that the native code generated from a Wasm module (via Cranelift's AOT path, or Lucet's native compiler) respects Wasm's memory isolation guarantees — the native code cannot escape its linear memory sandbox, cannot access unaligned addresses, and cannot jump to arbitrary code locations.

### Workflow
1. Take a `.wasm` binary + the native-compiler's output (x86-64 machine code).
2. Translate the x86-64 into a formal model of the native code.
3. Prove, via symbolic execution + SMT, that *every* memory access and control-flow transfer in the native code is bounded within the Wasm sandbox.
4. The TCB is: the Wasm-to-native compiler (Cranelift/Lucet) + the SMT solver + VeriWasm's own model of x86 semantics.

### Can it adapt to verify Wasm faithfully implements Rust source?
**No — it operates at the wrong layer.** VeriWasm verifies Wasm→native compilation preserves SFI safety, not that the Wasm correctly implements a particular source program. It does not have a Rust semantics, nor a Wasm semantics, nor a notion of functional correctness. Its property is *sandbox integrity*, not program equivalence. Adapting it to prove Rust→Wasm equivalence would require building a Rust formal semantics, a Wasm formal semantics, and a simulation proof between them — essentially writing a verified Rust compiler from scratch. VeriWasm's approach (symbolic execution of native code) is orthogonal.

**Relevance to Bloom:** Low. VeriWasm validates that native-compiled Bloom Wasm doesn't escape its sandbox. Useful for defense-in-depth on validator nodes, irrelevant to the source→Wasm equivalence problem.

---

## 2. Crocus (2024) — "Lightweight, Modular Verification for WebAssembly-to-Native Instruction Selection"

### What it verifies
Crocus verifies that Wasm→native **instruction selection** (the mapping from Wasm opcodes to individual native instructions) is correct. This is a phase inside a Wasm runtime's JIT/AOT compiler — the step that replaces `i32.add` with `add eax, ebx`. Crocus uses a modular proof structure: each Wasm instruction's translation is verified independently, and proofs compose.

The paper was motivated by a 9.9-severity CVE in Cranelift's instruction selection (2022) that allowed crafted Wasm to escape sandboxing — a *real* security bug in production infrastructure.

### Could it be extended to Rust→Wasm?
**No directly — Crocus verifies Wasm→native, not Rust→Wasm.** Crocus is downstream of the gap Bloom faces. However, its *methodology* (modular verification of each compilation pass) is the standard technique used by verified compilers (CompCert, DeepSEA backend, RustCompCert). Extending it "upward" would mean building a verified Rust→Wasm compiler phase-by-phase using the same modular proof structure — which is the entire unbuilt compiler problem.

**Relevance to Bloom:** Low. If Bloom ever runs Wasm→native AOT compilation (e.g., for validator performance), Crocus is directly applicable as a defense for that pass. But it doesn't help close the Rust→Wasm gap.

---

## 3. DeepSEA (2024) — "Foundational Verification of Smart Contracts through Verified Compilation"

### What it does
DeepSEA is a fully verified compiler from the **DeepSEA language** (a custom, small, Coq-friendly language) to EVM bytecode. The compiler is written and verified in Coq. The correctness theorem is: for any DeepSEA program that passes side-condition checks (no overflow, etc.), the generated EVM bytecode faithfully implements the Coq specification derived from the source. The DeepSEA frontend (`dsc`, 11,000 lines of OCaml) is **unverified** but generates a proof that the specification is refined by the bytecode — so it is *not* in the TCB.

### The eWasm path — "explicitly unproven"
The DeepSEA paper's architecture diagram (Figure 1) shows a Wasm compilation path alongside the EVM path, but the paper explicitly states this path is **unverified**. The Wasm path exists as an alternative code generation target in `dsc`, but no Coq verification has been done for it.

### What's the gap?
1. **Semantics gap:** DeepSEA's verified backend targets EVM operational semantics, formalized in Coq. A Wasm backend would require formalized Wasm 1.0/2.0 semantics (which exist — WasmCert, WasmRef-Isabelle — but are not currently integrated into DeepSEA's proof chain).
2. **Compilation pass proof:** The backend passes (MiniC → EVM) are proven correct for EVM. Each pass would need to be re-proven for a Wasm code generation target. The intermediate language MiniC (a C-like IR) is designed to be target-agnostic, so the frontend-to-MiniC proofs would transfer, but the MiniC-to-Wasm passes would be new proof work.
3. **No Rust frontend:** DeepSEA's source language is not Rust. It has no borrow checker, no ownership, no traits, no generics. To use it for Bloom, you'd need to either write petals in the DeepSEA language (losing the entire Rust ecosystem) or build a verified Rust→DeepSEA lowering.

### What would it take to close the eWasm gap?
- Integrate a mechanized Wasm semantics (WasmCert-Coq or WasmRef-Isabelle ported to Coq) into DeepSEA.
- Rewrite the MiniC→target backend to emit Wasm, with a Coq simulation proof against the Wasm semantics.
- Estimated effort: substantial (a full verified-compiler backend), but the architecture makes it feasible — the 12-pass structure and the MiniC intermediate language are designed for retargeting.

**Relevance to Bloom:** Moderate-high. DeepSEA demonstrates the *pattern* Bloom should aim for: an unverified frontend (not in TCB) generates a formal specification and a proof that bytecode refines it. If Bloom's `PredicateAst` were compiled through a similar pipeline, the TCB would shrink to the AST→Wasm lowering proof − a tractable target. For now, DeepSEA's unproven eWasm path is a cautionary data point: even with a verified compiler infrastructure, adding a new target is major work.

---

## 4. wasm-mutate / wasm-smith — Mutation-Based Wasm Testing

### What they are
- **wasm-smith** (bytecodealliance/wasm-tools, 1.7k stars): Generates *valid*, *arbitrary* Wasm modules from a seed. Deterministic, supports all Wasm features, integrates with `cargo fuzz`. Every generated module passes validation.
- **wasm-mutate** (same repo): Takes an *existing* valid Wasm module and applies **semantics-preserving** mutations — transformations that produce a different module computing the same result. Used for fuzzing Wasm consumers (compilers, runtimes).

### Can they be used for differential testing between source proofs and deployed Wasm?
**Yes — and this is the highest-leverage near-term action for Bloom.**

The workflow:
1. **Source side:** Run a Kani harness proving `∀ inputs: invariant(input)` on the Rust source.
2. **Wasm side:** Take the deployed Wasm binary (the `petal_hash` artifact).
3. **Fuzz bridge:** Use wasm-smith to generate random inputs to the invariant-scope buffer. Execute both the Kani-proven source (compiled natively) and the deployed Wasm (in Wasmtime) on the same inputs.
4. **Divergence detection:** If outputs differ, you've found a compiler-introduced bug — the source proof is *not* valid for the deployed Wasm.

wasm-mutate adds an orthogonal capability: **semantics-preserving mutation fuzzing**. After proving that Rust source S satisfies invariant I, use wasm-mutate to generate semantically-equivalent Wasm variants W1, W2, ... of the compiled artifact. Check that all variants also satisfy I. If any variant violates I while being semantically equivalent to the original, you've found either (a) a bug in wasm-mutate's equivalence claim, or (b) evidence that the invariant is sensitive to internal representation — which is itself a useful finding.

**Practical integration for Bloom:**
```
cargo-kani verify harness → produce proof certificate
rustc --target wasm32-unknown-unknown → produce petal.wasm
# Standing CI gate:
wasm-smith generate N random InvariantScope inputs
for each input:
    assert_eq!(native_kani_harness(input), wasmtime_exec(petal.wasm, input))
```

This gives you translation-validation-tier assurance (ADR-006's tier 2) — cheap, continuous, and catches real bugs. It does *not* replace a proof, but it makes the trusted-toolchain assumption (tier 3) falsifiable in CI.

**Relevance to Bloom:** High. Implement today.

---

## 5. Reproducible Builds for `wasm32-unknown-unknown`

### Current state
The `wasm32-unknown-unknown` target is *partially* reproducible. Cargo's reproducible-build infrastructure (`--remap-path-prefix`, `SOURCE_DATE_EPOCH`, etc.) works for Wasm targets.

Key points:
- **rustc supports** `-C linker-plugin-lto` on nightly for Wasm, which can affect reproducibility.
- **wasm-opt** (Binaryen) passes can introduce nondeterminism — must be pinned.
- **LTO** across crates can produce different function ordering across compiler versions.
- Unlike native targets, Wasm has no platform-dependent relocation or code-model issues, **making it easier to get bit-identical output than native targets.**

### Toolchain attestation story
There is **no standard Wasm toolchain attestation** comparable to Sigstore or SLSA provenance for native binaries. The closest patterns:
- `cargo vendor` to lock dependencies.
- `Cargo.lock` + `--locked` for dependency hashing.
- Publish the exact rustc commit hash + wasm-bindgen version.
- `wasm-strip` + hash the `.wasm` binary; distribute the hash.

For Bloom's `ProofArtifact.toolchain_attestation`, the minimum viable format would be:
```
ToolchainAttestation := {
    rustc_version_hash,        // exact nightly commit
    Cargo_lock_hash,           // content hash of Cargo.lock
    build_command,             // exact invocation
    wasm_opt_version,          // if used
    SOURCE_DATE_EPOCH,         // pinned for reproducibility
    target_hash,               // sha256 of .wasm output
}
```

**Relevance to Bloom:** High. Makes ADR-006's tier-3 (trusted compiler) falsifiable and auditable. Must be implemented as a prerequisite for any proof transfer claim.

---

## 6. Other Projects Handling the Rust→Wasm Verification Gap

### Known blockchain/verification efforts
- **ConCert / Scilla:** Coq-based verification of smart contracts, but the backend is unverified — they verify Coq models, not bytecode. ConCert explicitly lacks a verified compilation backend.
- **CertiK's DeepSEA:** As discussed above — verified compiler but from a non-Rust language to EVM (not Wasm).
- **Aeneas (Son Ho & Protzenko, 2022):** Translates Rust to pure functional specifications (in F\* or Coq) via a symbolic borrow-checker. Importantly, Aeneas *preserves* the borrow-checking guarantees through translation — it's a functional correctness bridge from Rust to F\*. Combined with the F\*→Wasm pipeline (see §7), this is the *closest thing to a practical Rust→Wasm proof transfer chain that exists*. Aeneas → F\* → Low\* → Wasm would be a 3-step verified pipeline, but Aeneas currently targets F\*'s Low\* subset and the integration with the Wasm backend has not been demonstrated end-to-end.
- **Move Prover / Sui Prover:** Proves Move source bytecode properties, but Move is compiled to Move VM bytecode via a *trusted* compiler — the same trust gap Bloom faces, just with a different VM. No evidence of translation validation or PCC between Move source and deployed bytecode.

### Summary
**No production blockchain project verifies Rust source and carries assurance to deployed Wasm.** The closest analogues (DeepSEA, Move Prover) use verified compilers for non-Rust languages, and even those don't target Wasm. Aeneas + F\*→Wasm is the most promising research combination but has no end-to-end demonstration.

**Relevance to Bloom:** Confirms the gap is real and universal. Bloom's "reproducible builds + differential testing" near-term gate is the appropriate pragmatic response.

---

## 7. The F\*→Wasm Pipeline (Protzenko et al., 2019)

### What it achieved
Protzenko, Beurdouche, Merigoux, and Bhargavan (IEEE S&P 2019, 25 cites) built a verified pipeline from F\* (a dependently-typed functional language) to Wasm. The toolchain:
1. **F\*** → **Low\*** (a low-level, C-like subset of F\*) — verified via F\*'s type system.
2. **Low\*** → **C** → **CompCert** → **assembly** — verified via the CompCert chain.
3. **Low\*** → **Wasm** — via a custom code generator (Kremlin), which was *not* verified at the time.

The F\*→Wasm path was used to produce verified cryptographic implementations (Curve25519, Poly1305, ChaCha20) that run in browsers. The *functional correctness* proofs were done in F\*, and the Wasm backend was *trusted but tested* — they used differential testing between the native and Wasm outputs to catch bugs.

### What was the TCB?
At the time of the paper (2019), the Wasm code generator (Kremlin's Wasm backend) was **in the TCB** — it was not verified. The core cryptographic proofs (in F\*) transferred to Wasm only under the assumption that Kremelin correctly translated Low\* to Wasm. This is *exactly* the same tier-3 assumption Bloom would make with `rustc` today.

### What happened since?
Subsequent work (the HACL\* project, which maintains this pipeline) has improved the situation:
- Kremlin now has a *validated* (not formally verified) Wasm backend used in production (Firefox, WireGuard, Linux kernel).
- The F\* ecosystem now includes Vale, a verified assembly-level language, and the chain is F\* → Low\* → Vale → (verified) → assembly.
- The Wasm backend remains the "weak link" — it has extensive differential testing but no formal verification.

### What would it take to have a verified F\*→Wasm path?
- Formalize Wasm semantics in F\* (WasmCert is in Coq, but a Wasm semantics in F\*/Lean would be needed for a native proof).
- Prove that the Kremlin Wasm code generator is a refinement of the Low\* semantics against the Wasm semantics.
- This is feasible (the F\* ecosystem has the infrastructure) but **not done** as of 2026.

**Relevance to Bloom:** High. Demonstrates that (a) the tier-3 approach (trusted compiler + differential testing) is production-tested in a security-critical context, (b) the gap to tier-1 (PCC) for a functional language is feasible but multi-year research. For Rust specifically, the path would be: Aeneas (Rust→F\*) → F\*→Low\*→Wasm. But Aeneas is research-stage and the full chain has never been assembled.

---

## 8. TurboTV (2024) — Translation Validation for JIT Compilers

### What it does
TurboTV (ICSE 2024) validates the **JIT compilation** in V8's JavaScript engine (TurboFan). It uses a translation validator: after each JIT compilation, it checks that the generated native code is a refinement of the source bytecode semantics. The validator uses SMT solvers to prove equivalence.

Key finding: TurboTV found a **real miscompilation bug** in production V8 that had survived existing testing — a case where the JIT produced wrong output for a specific input pattern.

### Is there work adapting translation validation to Rust→Wasm (AOT)?
**No published work exists specifically for Rust→Wasm AOT compilation.** Translation validation for Wasm has been explored in:
- **WasmRef-Isabelle** (2023): A verified Wasm interpreter used as a differential fuzzing oracle in Wasmtime CI. It's translation validation in the limit — running the same Wasm in two different interpreters and checking equality — but not a per-compilation validator.
- **CT-Wasm** (2019): Typed Wasm subsets that guarantee cryptographic constant-time properties are preserved through compilation. This is property-preservation, not full equivalence.
- **CompCert's approach**: CompCert uses a mix of verified passes (proven once) and validated passes (checked per-run) — the latter is translation validation applied to AOT compilation. But CompCert is C→assembly, not Rust→Wasm.

### What would a Rust→Wasm translation validator look like?
1. Extract the Rust MIR of the proven source kernel.
2. Compile to Wasm.
3. Lift the Wasm back to an IR that can be compared against MIR.
4. Use SMT to check refinement (or equivalence on bounded inputs).

This is **research-grade work**. The main challenge is the semantic gap: Rust MIR has complex features (borrow-checking, drop elaboration, trait resolution) that are eliminated before Wasm codegen. The MIR-to-Wasm lowering passes in `rustc` are numerous and complex, making per-compilation validation very hard.

**Relevance to Bloom:** Moderate. TurboTV shows translation validation works for JIT compilers, but the Rust→Wasm AOT path is a different, harder problem. Bloom's differential-testing approach (comparing native Kani harness output to Wasmtime output on fuzzed inputs) is a **practical approximation** of translation validation — it's runtime validation rather than static validation, but catches the same class of compiler bugs.

---

## 9. Kani and `wasm32` Target Support

### Does Kani support wasm32 targets?
**No — Kani targets native code only.** Kani works by compiling Rust to LLVM bitcode (via `rustc`'s LLVM backend with a Kani-specific codegen backend), then translating that to GOTO programs, then model-checking with CBMC. This pipeline fundamentally depends on:
1. LLVM codegen (Kani replaces the normal LLVM backend with its own GOTO backend).
2. Native target semantics (integer widths, memory models match the host).

For `wasm32-unknown-unknown`, the compilation target emits Wasm, not LLVM bitcode. Kani cannot ingest Wasm; it needs the Rust→GOTO translation, which requires an LLVM intermediate representation.

### What about `cargo-kani`?
`cargo-kani` is a Cargo subcommand that automates Kani harness execution. It wraps `kani-compiler` (rustc plugin) + CBMC. It respects `--target` flags for cross-compilation of *dependencies*, but the verification itself runs on the host architecture.

### Kani vs. Verus for wasm32
**Verus** (verifies Rust programs, also native only) and **Creusot** (translates Rust to Why3, native only) share the same limitation — they verify Rust at the LLVM level or translate to SMT/Why3 for native semantics. None targets Wasm.

### Practical workaround
The most practical approach for Bloom today:
1. **Verify the Rust source with Kani/Verus on native target.** The proof is about Rust source semantics.
2. **Build a CI gate** that compiles the proven source to `wasm32-unknown-unknown` and runs the fuzz bridge (§4) to check equivalence.
3. **Accept that the proof is tier-3** (trusted compiler) unless the fuzz bridge is made comprehensive enough to approximate translation validation.

**What would make Kani work for Wasm?**
A Wasm-compatible Kani backend would need:
- A Wasm operational semantics in the GOTO framework.
- A translator from GOTO programs to Wasm (or a Wasm interpreter).
- This is feasible but not on any published roadmap. The CBMC team (Kani's upstream) has explored WebAssembly verification but from the Wasm→GOTO direction (verifying Wasm directly), not Rust→Wasm.

**Relevance to Bloom:** High. Confirms that any Rust source proof (Kani/Verus/Creusot) is today locked to native semantics. The Wasm deployment path is either trust-the-compiler (tier-3) or build a custom verification bridge.

---

## Practical Assessment & Recommendations

### What's achievable today (ordered by effort)

| Tier | Approach | TCB | Effort | Catches |
|------|----------|-----|--------|---------|
| **1. Reproducible builds + attestation** | Pin rustc, Cargo.lock, SOURCE_DATE_EPOCH; publish Wasm hash | rustc (trusted) | ~1 week | Nothing (trust) |
| **2. Differential fuzz bridge** | wasm-smith generates InvariantScope inputs; compare native Kani harness vs. Wasmtime execution | rustc + Wasmtime + harness (trusted but tested) | ~2 weeks | Compiler-introduced functional divergence |
| **3. wasm-mutate equivalence fuzzing** | Mutate deployed Wasm preserving semantics; check invariants hold | rustc + wasm-mutate (trusted but tested) | ~3 weeks | Invariant sensitivity to Wasm representation; compiler bugs |
| **4. AST interpreter cross-check** | Build a trusted `PredicateAst` interpreter in Wasmtime; compare against `__inv` export | AST interpreter + Wasmtime (trusted) | ~4 weeks | Incorrect `__inv` lowering (the `return 1` stub gap) |
| **5. Kani + native Wasm semantics** | Prove Rust source; separately verify Wasm binary against Wasm formal semantics; prove bisimulation | Wasm semantics model + proof tool (large TCB without mechanization) | Research project | Full source→Wasm equivalence (for bounded inputs) |
| **6. Aeneas + F\*→Wasm pipeline** | Translate Rust to F\* via Aeneas; verify in F\*; compile to Wasm via Kremlin | F\* toolchain + Kremlin (trusted Wasm backend) | Research project (~6 months) | Full functional correctness for Wasm, but Kremlin Wasm backend is unverified |
| **7. DeepSEA-style verified compiler** | Build a verified Rust→Wasm compiler, or verified `PredicateAst`→Wasm lowering with mechanized Wasm semantics | Small checker (PCC tier) | Multi-year research | Full PCC-tier equivalence |

### Bloom-specific path

1. **Today (0-4 weeks):** Implement tiers 1+2+4.
   - Tier 1: Reproducible builds for all chain-mode petals, with published `ToolchainAttestation`.
   - Tier 2: Standing CI gate that runs the Kani harness (native) and the Wasm deployment on identical fuzzed inputs; flags divergence.
   - Tier 4: Replace the `return 1` stub at `codegen.rs:787` with a real AST→Wasm lowering, and cross-check via a trusted `PredicateAst` interpreter.

2. **This quarter:** Tier 3 (wasm-mutate fuzzing) to gain confidence that invariants are robust to Wasm-level representation choices.

3. **Next 6-12 months:** Explore Aeneas + F\* pipeline as a path to PCC-tier assurance. Even without a verified Kremlin Wasm backend, the differential-testing bridge gives tier-2 confidence on top of tier-1 F\* proofs.

4. **Long-horizon hedge:** Track RustCompCert. If/when it gains a Wasm backend (not currently planned — it targets CompCert's assembly backends), it would be the first verified Rust→Wasm path. The RustCompCert team's approach (verified borrow-checker + CompCert backend) is the right architecture; the Wasm codegen target is the missing piece.

### TCB analysis for Bloom's immediate plan

For the near-term "reproducible builds + differential fuzz bridge" approach:

| Component | TCB role | Mitigation |
|-----------|----------|------------|
| `rustc` wasm32 codegen | Trusted to preserve semantics | Differential fuzzing catches divergence |
| Wasmtime | Trusted to correctly execute Wasm | Two independent Wasm runtimes (Wasmtime + wasmi) |
| Kani harness | Trusted to correctly encode invariant | Kani proves harness against source; counterexample if wrong |
| `PredicateAst` interpreter | Trusted for arbitration replay | Deterministic, simple; easy to audit |

This yields a TCB roughly equivalent to ADR-006's "translation validation" tier (tier 2), on the strength of continuous differential testing rather than a formal validator.

---

## References

1. Johnson, Thien, Tsai, et al. (2021). *VeriWasm: SFI Safety for Native-Compiled Wasm.* NDSS. [abstract]
2. Crocus (2024). *Lightweight, Modular Verification for WebAssembly-to-Native Instruction Selection.* [abstract]
3. Sjöberg, Dave, Britten, et al. (2024). *Foundational Verification of Smart Contracts through Verified Compilation (DeepSEA).* arXiv:2405.08348. [full text]
4. Protzenko, Beurdouche, Merigoux, Bhargavan (2019). *Formally Verified Cryptographic Web Applications in WebAssembly.* IEEE S&P. DOI 10.1109/sp.2019.00064. [abstract, 25 cites]
5. Wu, Wang, Yu, Meng (2026). *RustCompCert: A Verified and Verifying Compiler for a Sequential Subset of Rust.* arXiv:2602.07455. [full text]
6. Leroy (2009). *Formal Verification of a Realistic Compiler (CompCert).* CACM.
7. Ho & Protzenko (2022). *Aeneas: Rust verification by functional translation.* ICFP. DOI 10.1145/3547647.
8. Wasm-mutate / wasm-smith: <https://github.com/bytecodealliance/wasm-tools>
9. Kani Rust Verifier: <https://model-checking.github.io/kani/>
10. TurboTV (2024). *Translation Validation for JIT Compiler in the V8 JavaScript Engine.* ICSE. DOI 10.1145/3597503.3639189. [abstract]
11. Watt (2018). *Mechanising and verifying the WebAssembly specification (WasmCert).* CPP. [abstract]
12. WasmRef-Isabelle (2023). *A Verified Monadic Interpreter and Industrial Fuzzing Oracle for WebAssembly.* DOI 10.1145/3591224. [abstract — fetch failed]
