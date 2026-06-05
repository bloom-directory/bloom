# H2 Falsifier — Runtime invariant = detection-not-prevention; only pre-deploy quantification prevents logic bombs

REFUTATION STRENGTH: partial — The corpus decisively refutes H2 *as literally worded* ("runtime ... is detection, not prevention; only pre-deploy quantification over all states prevents"). A transaction-scoped check evaluated before the state-commit point genuinely *prevents* the bad state (revert-before-commit), and the strongest disconfirming artifact — Theorem-Carrying Transactions — is itself a *runtime* mechanism that prevents the exact "logic bomb" classes (integer-overflow, reentrancy) H2 says runtime cannot touch. What survives is a much weaker and differently-framed claim: a *stateless pure-view* invariant evaluated only *after* commit, or evaluated *post-hoc* without the ability to revert, is detection; and pre-deploy quantification covers a strictly *larger temporal fragment* than any single-transaction runtime check. H2 conflates "runtime" with "post-commit / non-reverting / stateless-view," and conflates "prevention" with "static." Both conflations are false in the corpus.

---

## 1. The false-dichotomy counter (strongest) — DECISIVE against the literal H2

**Theorem-Carrying Transactions: Runtime Verification to Ensure Interface Specifications for Smart Contract Safety** (Ball, Bjørner, A. Chen, S. Chen, Y. Chen, Guo, Hsu, Liu, Luo), arXiv:2408.06478v2 — *(full text)*.

TCT is, by its own title and design, a **runtime** verification system, yet it **prevents** bad states. The mechanism settles the question:

- The protocol's `Execute(tx, h)` runs the transaction on the executor `net`, and **only** calls `E.net.commitStorageUpdates()` **if `ok`** — i.e., the check gates the commit. "Reversion means that the program state remains unchanged" (Background §2.1). So the safety decision is taken *before* state commits. This is exactly the "revert before commit" semantics the falsification brief asks about: TCT genuinely prevents the bad state, it does not merely observe it after the fact.
- TCT explicitly claims to subsume static verification's power *at runtime*: "TCT is designed to have the same symbolic-reasoning capability as static verification" and "the same faithfulness as runtime assertions." It enforces ERC-20 invariant `0 ≤ balances[x] ≤ totalSupply ∧ Σ balances = totalSupply` and shows this "straightforward property defeats the two attacks" — the 2016 DAO-style integer-overflow and the reentrancy logic bombs — *without foreseeing the code-level pattern.* These are precisely the "logic bombs" H2 claims a runtime check is "structurally blind to."

Therefore H2's headline equation "runtime ⇒ detection, not prevention" is **false as stated.** A runtime, transaction-scoped check evaluated before commit prevents.

**The decisive nuance that rescues a weakened H2.** TCT is *not* a "pure-view-function invariant" in the naive sense, and it is *not* purely runtime. Read carefully, TCT is a hybrid that *vindicates the spirit* of ADR-002 while refuting its letter:

- The **symbolic proof** that the guard `φ(s, f.p)` implies the invariant for the *entire* straight-line trace is done in `AddTheorem`, via `E.net.prove(φ ⇒ VC(ct))` (Boogie/SMT). The paper expects this to happen at *testing time, before the contract processes real user transactions* — i.e., **pre-deploy quantification over states** (all states satisfying `φ`, all aliasings of `msg.sender/_from/_to`). "Because all variables are symbolic, a proven theorem has the generality to cover all future transactions that follow the same code trace."
- What runs *per transaction* is only the cheap **guard check + path-hash match** (`Apply`), 0.20–0.57% overhead. The per-tx step does *not* re-derive safety; it certifies that this concrete tx falls inside a pre-quantified, already-proven envelope.

So TCT's prevention power comes *precisely from the pre-deploy symbolic quantification* that ADR-002 advocates — the runtime component is a fast inclusion check, not the source of assurance. This is a genuine vindication of ADR-002's underlying intuition ("only pre-deploy quantification prevents"), but it simultaneously refutes the dichotomy framing, because the quantified proof is **enforced at runtime via revert**, not by refusing to deploy. Prevention here is *runtime-enforced pre-deploy quantification* — neither pole of H2's dichotomy.

**Implication for Bloom (the brief's "either/or").** TCT shows the strongest option is *not* a stateless post-commit view function (which would be detection), and *not* pure static-only verification (rejected by TCT as "not faithful to the GP," producing false alarms on every cross-contract call). If Bloom's runtime invariant is a *pure view function read after the state transition with no power to revert*, then TCT confirms Bloom "chose a strictly weaker primitive than necessary" — the necessary primitive is a *pre-commit gate carrying a pre-proven theorem.* H2's claim that the runtime primitive is *structurally* incapable of prevention is the false part; the achievable correct architecture is runtime-but-pre-commit-and-pre-quantified.

---

## 2. The fragment limitation cutting the OTHER way — H2 over-promises on "prevents [logic bombs]"

**A survey of challenges for runtime verification from advanced application domains (beyond software)** (Sánchez et al.), DOI 10.1007/s10703-019-00337-w — *(abstract only)*. Runtime verification "studies the dynamic analysis of *execution traces* against formal specifications." The unit of monitoring is a trace; the discipline's core competency is *safety* (bad-prefix) properties observable on the trace, with liveness/temporal multi-window properties being the hard, open challenges the survey is *about*. A single stateless view function evaluates one state, not a trace, so it covers an even narrower slice than trace-based RV.

This cuts *against* H2's second clause. H2 asserts that pre-deploy quantification "prevents" logic bombs — implying coverage of the property classes that matter. But:

**VerX: Safety Verification of Smart Contracts**, DOI 10.1109/sp40000.2020.00024 — *(full text)*. VerX is a *static/pre-deploy* verifier of *temporal* properties over the "unbounded number of transactions processed by the contract." Crucially, it achieves this **only over a restricted fragment**: it is "precise and efficient for a *practical fragment* of Ethereum contracts," requires **effectively-external-callback-free (EECF)** contracts, and requires **bounded loops** ("SE requires loops to be bounded"). Multi-block / multi-transaction liveness ("Investors cannot claim refunds after more than 10,000 blocks," "investors cannot claim refunds after the crowdsale succeeded") is reachable *only* inside that fragment.

So the honest picture is: **neither** pole reaches the full property lattice for free. A pure-view runtime invariant covers only single-state safety (narrowest). Pre-deploy quantification *can* reach temporal/liveness — but in the corpus this is demonstrated only on an EECF, bounded-loop fragment, with the false-alarm/soundness tradeoffs static analysis is known for (TCT's central criticism of static verification). H2 silently over-promises by presenting "pre-deploy quantification" as an unqualified preventer of logic bombs, when the corpus shows it is itself fragment-limited and (in TCT's framing) *unfaithful to the deployed gigantic program* because it must hypothesize the environment, the reference topology, and the attacker.

---

## 3. Does static proof actually reach real-world logic bombs at scale, or is "prevention" aspirational too?

The corpus shows static/pre-deploy "prevention" is *not* a free, fully-realized capability — it is bought with strong fragment restrictions and is, at the deployed-program level, *not faithful*:

- **TCT** (full text) is built on the explicit premise that "**static code verification cannot be faithful** to this gigantic program due to its scale and high polymorphism." Its dilemma argument: a static verifier must treat every cross-contract call via an address as "potentially unsafe" → false alarms on *every* `businessPartner.foo()`; for soundness it "needs to err by assuming all possibilities of these hypothetical elements." So pure pre-deploy quantification over a *contract* (not the GP) either floods false positives or makes environment assumptions that the logic-bomb author controls. A logic bomb hidden in an externally-controlled address target is *exactly* the case static-over-one-contract cannot quantify, because "the semantics of a contract code containing such a call is **undefined** until the address value is concretized at runtime."
- **VerX** (full text) reaches scale only by the EECF + bounded-loop restriction (§ above). Outside the fragment, completeness is not claimed.

This makes the real comparison not "detector vs. preventer" but, as the brief anticipates, **two imperfect mechanisms with complementary blind spots** — which is precisely the thesis of the supporting (abstract-only) corpus entry **Runtime Assertion Checking and Static Verification: Collaborative Partners**, DOI 10.1007/978-3-030-03421-4_6, whose title alone disconfirms the either/or framing: the literature treats runtime checking and static verification as *collaborators*, not as a detection/prevention dichotomy. Classic **Proof-carrying code** (Necula), DOI 10.1145/263699.263712 — *(abstract only)* — already established the very pattern TCT instantiates: a *proof* (pre-computed, quantified) is *checked at the consumption/runtime boundary before the untrusted code is admitted*. PCC is prevention-by-runtime-admission-check, again collapsing H2's dichotomy.

The narrower, abstract-only **Runtime Verification of Ethereum Smart Contracts**, DOI 10.1109/edcc.2018.00036 — *(abstract only)*, sits on the runtime side and is consistent with the survey's safety-fragment scoping; it does not supply a counter to TCT.

---

## 4. Is there a decisive disconfirming result?

Yes for the **literal** H2, no for a **charitably-restated** H2.

- **Disconfirms the literal claim (decisive):** TCT (full text) — a runtime mechanism that prevents integer-overflow and reentrancy logic bombs by reverting before commit, deriving its assurance from pre-deploy symbolic quantification but enforcing it at runtime. This single artifact breaks both the "runtime ⇒ detection" implication and the "only [static] pre-deploy prevents" exclusivity. PCC (abstract) and "Collaborative Partners" (abstract) corroborate at the level of principle.
- **Does NOT disconfirm (so H2 partially survives):** If ADR-002's "runtime pure-view-function invariant" specifically means a *stateless, single-state, post-commit, non-reverting* view check, then nothing in the corpus shows such a primitive preventing anything — it is detection, consistent with the RV survey's trace/safety scoping. And the corpus *does* support the proposition that *quantification over states* (whether literally pre-deploy, as VerX, or pre-deploy-proven-then-runtime-enforced, as TCT) is what supplies the prevention guarantee. The part of H2 that is *true* is "quantification, not single-state evaluation, is what prevents." The part that is *false* is "this must be static/pre-deploy rather than runtime, and runtime is structurally blind."

---

## Verdict and what Bloom/ADR-002 should change

- **Cannot fully refute, cannot fully sustain → partial.** The *causal* intuition behind ADR-002 (single-state view evaluation ≠ prevention; you need to quantify) is correct and corpus-supported (TCT's guard is a quantified envelope; VerX quantifies over transaction sequences). The *taxonomy* in H2 (runtime=detection, static=prevention) is wrong and is decisively contradicted by TCT and PCC.
- **Actionable:** The strongest primitive is neither of H2's poles. It is a **pre-commit, revert-capable check that carries a pre-deployment-quantified proof** (TCT). If Bloom's invariant is a non-reverting post-state view, TCT shows it is strictly weaker than necessary and H2's "detection" charge lands *on Bloom's specific choice*, not on "runtime" as a category. If Bloom can move the invariant to a pre-commit gate, it prevents — and H2's dichotomy should be retired in favor of the "collaborative partners" framing.
- **Honesty check on the other side:** Whatever Bloom calls "prevention," the corpus says it is fragment-bounded (VerX EECF + bounded loops) and, for whole-program/cross-contract logic bombs, *unfaithful* unless the proof is anchored to the concrete runtime trace (TCT's core critique of static-only verification). H2 should not present pre-deploy quantification as an unqualified preventer of all logic bombs.

### Papers cited
- Theorem-Carrying Transactions: Runtime Verification to Ensure Interface Specifications for Smart Contract Safety — arXiv:2408.06478v2 (http://arxiv.org/abs/2408.06478v2) — full text.
- VerX: Safety Verification of Smart Contracts — DOI 10.1109/sp40000.2020.00024 — full text.
- A survey of challenges for runtime verification from advanced application domains (beyond software) — DOI 10.1007/s10703-019-00337-w — abstract only.
- Runtime Assertion Checking and Static Verification: Collaborative Partners — DOI 10.1007/978-3-030-03421-4_6 — abstract only.
- Runtime Verification of Ethereum Smart Contracts — DOI 10.1109/edcc.2018.00036 — abstract only.
- Proof-carrying code (Necula) — DOI 10.1145/263699.263712 — abstract only.
