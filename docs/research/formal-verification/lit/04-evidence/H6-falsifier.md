# H6 Falsifier — zkVM underconstraint requires re-execution / fraud-proof fallback (ADR-007)

REFUTATION STRENGTH: none (partial on two sub-claims) — the central category-error argument is
empirically false: the corpus contains a working demonstration (Arguzz) that honest re-execution
against a reference VM *does* catch underconstraint soundness bugs. The hypothesis survives. Two
narrower attacks (trust-relocation, redundancy) land as genuine caveats but do not refute H6 as
ADR-007 actually states it.

---

## What H6 / ADR-007 actually claims (read the text before attacking it)

The attack brief imports a strawman ("every tx is re-executed", "single zkVM... re-execution is
the fix"). The actual ADR-007 text (`02-architecture.md` §8, lines 505–521) is weaker and more
defensible:

- It is a **defence-in-depth bar, not a single mechanism.** Minimum bar = "a documented soundness
  audit **plus** a re-execution / fraud-proof fallback" (line 520).
- Re-execution is explicitly a **partial-coverage challenge window**: "A subset of validators
  re-executes and can challenge a proof **off the happy path**" (line 510–511). Not every tx.
- It is paired with **circuit-level effort** (prefer provers with "a formal-verification roadmap
  and published underconstraint audits", line 507) and **optional multi-prover diversity** (line
  514). ADR-007 does not claim re-execution is "the real fix" instead of circuit verification — it
  asks for both.

The brief's points 1 and 3 attack a claim ADR-007 does not make. That alone caps the achievable
refutation at "partial."

---

## Attack 1 — the category error ("re-execution can't adjudicate underconstraint"). REFUTED.

The brief's sharpest move: a soundness bug means the verifier accepted a trace that does *not*
correspond to correct execution; against *what* does re-execution adjudicate, and if the attacker
forges the result the honest node would also compute, replay sees no divergence.

The corpus contains a direct, empirical counterexample.

**Arguzz: Testing zkVMs for Soundness and Completeness Bugs** (Hochrainer, Wüstholz, Christakis;
arXiv:2509.10819; https://arxiv.org/abs/2509.10819) (full text). Arguzz's soundness oracle *is*
honest re-execution against a reference semantics, and it works:

- The zkVM threat model is exactly ADR-007's: "the verifier is the only trusted component, while
  the prover is potentially adversarial... an attacker may use a malicious execution environment to
  generate an invalid trace and a corresponding proof, and it is the verifier's responsibility to
  detect and reject such proofs" (p. 7). This is the re-execution/fraud-proof picture stated as the
  field-standard model — not a Bloom invention.
- The adjudication target is concrete and answers the brief's "against WHAT?" question: Arguzz runs
  a **product program with a known expected output** (`SUCCESS`), defined by the *honest* RISC-V
  semantics of the same inputs (Fig. 4, §3.2). The honest execution *is* the oracle. A malicious
  prover injects a fault (e.g. `remu rd, rs1, rs2` → `remu rd, rs1, rs1`), the honest semantics say
  the output should be `7 % 5 = 2`, the faulty trace yields `0`, and "if the fault injection causes
  the product program to return an incorrect output... but the proof still verifies successfully,
  Arguzz reports a soundness bug" (p. 5, §2 step 7).
- This caught real underconstraint: **RISC Zero** missing constraint on three-register
  instructions ($50,000 bounty, "despite prior audits"), **Nexus** unconstrained store operand,
  **Jolt** unconstrained `lui` immediate — "all three soundness bugs... detected using the
  instruction-modification injection" (Tab. 1; §4.2 RQ1).

This is decisive against the category-error claim. Underconstraint means the circuit accepts *both*
the correct trace and a forged one. Re-execution under honest semantics computes the *unique
correct* result; whenever the malicious prover's accepted trace diverges from it, the divergence is
observable and the proof is flagged. The brief's escape hatch — "if the attack forges the result
the honest node would also compute" — is not an underconstraint exploit at all: if the forged
output equals the honest output, there is no soundness violation in the value (the attacker gained
nothing), and the "missing semantics" worry is empty because the honest VM *is* the authoritative
semantics by construction. Arguzz's own false-positive guard makes this precise: it "does not
report a bug solely because the verifier accepts a proof after fault injection. We additionally
require that the product-program output changes from `SUCCESS` to `OOPS`" (§3.3) — i.e. it only
counts cases where honest re-execution *disagrees*. Exactly the cases re-execution catches.

The SoK corroborates that the trusted anchor is the honest reference, not the circuit:
**SoK: What Don't We Know? Understanding Security Vulnerabilities in SNARKs** (Chaliasos et al.;
arXiv:2402.15293; https://arxiv.org/abs/2402.15293) (full text) recommends "differential testing
against a reference implementation" as a viable method for circuit issues (§8, Circuit Layer
Defenses). Differential against a reference *is* re-execution-as-oracle.

## Attack 2 — re-execution relocates rather than removes the trust root. PARTIAL HIT (caveat, not refutation).

This is correct and worth recording, but it does not refute H6. Re-execution shifts the trusted
component from "the prover's circuit is sound" to "the honest re-executor's semantics are correct."
That oracle can itself be under-tested. Arguzz makes this explicit and even *exploits* it the other
direction: it found a **Rust compiler miscompilation** (Rust 1.80) as a by-product, a fault in the
very toolchain a re-executor would rely on (§4.2 RQ2). And the SoK warns frontend/backend bugs
"could render the entire system insecure for end-users... even if the circuits have been formally
verified" (§7) — the same warning applies to a re-execution oracle's own stack.

But this is an argument that *no* mechanism removes the trust root (circuit verification relocates
it to the spec + the prover-FV gap; multi-prover relocates it to "two provers don't share a bug").
ADR-007 anticipates exactly this by demanding the zkVM be "in-scope for the same discipline as
everything else: its version pinned, its soundness assumptions written down as an explicit part of
the trusted computing base" (line 516–518). H6 never claims to *eliminate* a root of trust; it
claims no *single zkVM* should *be* the root. Relocating to a diverse, audited, pinned re-executor
is the claim, not a bug in it. Caveat sustained; refutation not achieved.

## Attack 3 — internal incoherence: if re-execution is always done, the zk proof is pointless. FAILS against the actual ADR.

This depends entirely on the strawman that *every* tx is re-executed. ADR-007 says the opposite:
re-execution is a **subset-of-validators challenge window "off the happy path"** (line 510–511) — a
fraud-proof / optimistic posture, not universal replay. Under that design the division of labour is
coherent and standard:

- The zk proof provides **succinct, cheap, on-chain verification** for the common case — Arguzz
  describes verification "carried out... directly on-chain through smart contracts" (§1) and SoK
  notes succinct verification is the whole point (§2, §3, ZK-rollup motivation). Most validators
  verify the proof, not the trace.
- Re-execution is the **rare, off-path adjudicator** that makes a single unsound acceptance
  *catchable rather than final* — precisely the optimistic-rollup pattern.

So the proof buys succinct verification + a window in which fraud is detectable; re-execution buys
soundness-recovery against circuit bugs the proof cannot self-detect. No incoherence. The "pointless
proof" objection only bites a design ADR-007 explicitly rejects. Note the residual tension: a
fraud-proof window weakens *finality*, and an underconstraint bug must be hit *within* the window
by a re-executing validator who happens to run the malicious inputs — re-execution is probabilistic
coverage, not a guarantee. That is a real limitation of the fallback's *strength*, but it is an
argument for ADR-007's belt-and-braces stance (audit + FV-roadmap + multi-prover too), not against
H6.

## Attack 4 — is there a decisive disconfirming result? NO.

The brief hoped to use the two circuit-level papers to show "the real fix is circuit-level
verification / differential proving, not replay":

- **Formal Verification of Zero-Knowledge Circuits** (Coglio, McCarthy, Smith; EPTCS 393;
  doi:10.4204/eptcs.393.9) (abstract only — abstract empty in corpus).
- **Towards Fuzzing Zero-Knowledge Proof Circuits** (Chaliasos, Al-Fath, Donaldson; ISSTA 2025;
  doi:10.1145/3713081.3731718) (abstract only — abstract empty in corpus).

Two problems. First, on the available evidence (titles/DOIs only; the corpus carries no abstract or
full text for either) I cannot quote any finding from these that disconfirms re-execution. Second,
and decisively, these are **complements, not substitutes**. They presuppose a *circuit DSL* with
explicit constraints to verify/fuzz. Arguzz's central architectural finding is that **zkVMs do not
have that**: "developers do not explicitly write constraints... constraints are enforced
automatically by the zkVM based on the semantics of the compiled Rust program... this abstraction
improves usability, but also makes it harder to reason about the enforced constraints and identify
bugs" (§1). And critically: "metamorphic testing cannot detect soundness bugs caused by overly weak
constraints when both the original and transformed programs exhibit the same behavior" (§1) — i.e.
pure circuit-equivalence checking misses exactly the underconstraint class. Arguzz needed the
**fault-injection (re-execution-of-malicious-prover) channel** to catch all three soundness bugs;
circuit-level metamorphic testing alone caught zero of them (Tab. 1: all soundness = "FI", all
completeness = "MT"). This is the corpus *confirming*, not disconfirming, that for a zkVM you need
the re-execution/malicious-prover oracle on top of circuit-level methods — which is precisely H6.

There is no decisive disconfirming result in the corpus. The strongest candidate evidence runs the
other way.

---

## Verdict

The hypothesis is **not refuted.** The central category-error argument is empirically wrong:
Arguzz demonstrates a working re-execution-against-honest-semantics oracle that catches real zkVM
underconstraint soundness bugs (including a $50k RISC Zero bug that survived audits), and shows
that circuit-level equivalence testing alone misses exactly this class. Two narrower attacks land
as legitimate caveats:

1. **Trust relocation (Attack 2):** re-execution moves the trusted root to the reference-semantics
   oracle, which is itself fallible (Arguzz found a Rust-compiler miscompilation). This is true of
   every mitigation and is acknowledged by ADR-007's "zkVM in the TCB" clause; it sharpens H6
   rather than breaking it.
2. **Probabilistic coverage / finality cost (Attack 3 residual):** a fraud-proof window only
   catches a bug if a re-executor runs the malicious inputs within the window, and it weakens
   finality. This argues for ADR-007's *additional* layers (audit + FV-roadmap + multi-prover), not
   against the fallback.

The "redundancy / pointless proof" and "circuit verification is the real fix instead of replay"
attacks fail because they target a strawman (universal re-execution; replay-only) that ADR-007
explicitly does not adopt — its design is optimistic subset re-execution *plus* circuit-level
discipline *plus* optional multi-prover. On the actual text, H6 is well-supported by the corpus.

### Sources cited
- SoK: What Don't We Know? Understanding Security Vulnerabilities in SNARKs — arXiv:2402.15293,
  https://arxiv.org/abs/2402.15293 (full text)
- Arguzz: Testing zkVMs for Soundness and Completeness Bugs — arXiv:2509.10819,
  https://arxiv.org/abs/2509.10819 (full text)
- Formal Verification of Zero-Knowledge Circuits — doi:10.4204/eptcs.393.9 (abstract only; abstract
  field empty in corpus — cited as an existing circuit-level technique, no finding quoted)
- Towards Fuzzing Zero-Knowledge Proof Circuits (Short Paper) — doi:10.1145/3713081.3731718
  (abstract only; abstract field empty in corpus — cited as an existing circuit-level technique, no
  finding quoted)
