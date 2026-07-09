# Bloom Machine + Petals

**Status:** architecture decision
**Audience:** Bloom engineers, Petal authors, and implementation agents

Bloom is comprised of:
 - **Bloom Machine**: a long-running daemon that mounts `/bloom` (a VFS), orchestrates Sealed Approval ceremonies, holds keystores, and runs Petal execution via a WASM VM.
 - **Petals**: dynamic code in the form of WASM, projecting into the VFS and interfacing with Bloom Machine APIs (for signing, storage, HTTP calls, etc.)

The Bloom Machine is the trusted core. In the codebase and older material it may
also appear as "the daemon", "the Bloom runtime", or "the host"; those name the
same trusted process. Petals are domain plugins that run on top of it.

## Division of Responsibility

Authorization in Bloom is split across three roles. Keeping them distinct is
what lets the platform stay general — the Bloom Machine never needs to
understand any Petal's domain — while still giving the user something meaningful
to approve.

| Role | Who | Responsibility | Nature |
|---|---|---|---|
| Structure | Bloom Machine | key custody; the grant envelope; binding attestations into the audit trail; ceremony and grant minting | structural — a Petal cannot bypass it |
| Enforcement | the acting Petal | interpreting what is being signed and enforcing its own domain limits; producing an attestation | trusted — not structurally enforced |
| Verification | verifier Petals (future) | independently checking or simulating another Petal's payload before it is signed | pluggable — unimplemented today |

## The Grant Envelope

A Sealed Approval grant authorizes a single Petal to use bounded signing
authority for a single sealed action. The Bloom Machine structurally enforces
the *envelope* of that grant:

 - the **wallet** whose key may be used;
 - the **Petal identity** allowed to consume the grant;
 - the **sealed action** the grant is bound to;
 - the allowed **signing intents** a request may declare;
 - the maximum **signature count**, `N`;
 - the **expiry**, `T`.

Within a live grant the acting Petal may request up to `N` signatures until `T`.
These bounds are the guarantees the Bloom Machine makes, and that no Petal
can exceed.

## Trust Boundary

Petals are trusted for now in that they can propose arbitrary bytes to be
signed, provided they hold a granted [Sealed Approval](./Sealed%20Approvals.md).

Concretely: within a live grant, the Bloom Machine signs whatever hash the
acting Petal presents, up to the grant's signature count and expiry. **The Bloom
Machine does not interpret or bind the bytes being signed.** It does not check
that the hash corresponds to the action the user approved; that correspondence
is the Petal's responsibility.

This is a deliberate boundary, not an oversight. Petals are early, and the space
of things a Petal might legitimately sign — new key types, transactions whose
parameters are only known moments before execution, off-chain credentials,
message formats not yet imagined — cannot be enumerated or type-checked in the
Bloom Machine without constraining what a Petal is allowed to be. Rather than
model every payload, Bloom trusts a Petal, once it holds a grant, to request
only signatures consistent with what that grant was approved for.

What this means in practice:

 - **Structurally guaranteed** (a Petal cannot exceed these): the wallet, the
   Petal identity, the signature count, the expiry, that PRF output and key
   material never leave the Bloom Machine, and that every signature is recorded.
 - **Trusted to the Petal** (correctness depends on the Petal behaving): that
   the bytes signed correspond to the approved action, and that any domain
   limits — amounts, destinations, allowlists — are honored.

A consequence worth stating plainly: a compromised or buggy Petal, within a live
grant, can obtain signatures the user did not intend, up to `N` times before
`T`. The grant bounds the blast radius; it does not eliminate it. This is
acceptable only because Petals sit inside the trust boundary today, and it is
the reason verifier Petals exist as a planned escape valve.

## Attestations

Even though the Bloom Machine does not verify what a Petal signs, the Petal must
still declare it. Each signing request carries a structured **attestation** —
the Petal's own statement of what the signature does and which approval
authorizes it. The Bloom Machine binds that attestation to the signature and
records it in the append-only audit trail.

The attestation is therefore not a check the Bloom Machine performs; it is a
claim it witnesses. Its value is legibility and attributability: every signature
is tied to a Petal-authored description of intent, so misbehavior is provable
after the fact, and a verifier Petal has something concrete to check against.

## Consent

Because a grant may authorize more than one signature, what the user approves in
a ceremony must be rendered honestly. A grant that authorizes a standing budget
must be presented as a delegation — *"authorize this Petal to sign up to `N`
times until `T`"* — and never disguised as approval of a single concrete action.
The user must always be able to tell whether they are approving one payload or
granting a Petal a signing budget.

## Verifier Petals [unimplemented]

Multiple Petals can be party to the same Sealed Approval ceremony, allowing
"verifier Petals" to hook into other Petals in order to verify, simulate, or
otherwise check the payload of another (potentially adversarial) Petal before it
is signed.

This is the path by which the trust boundary above is tightened without giving
up generality. Verification stays domain-specific and optional: an EVM verifier
might simulate a transaction and confirm its effects fall within an approved
capability; a different verifier might check an off-chain credential against its
own rules. Because verifiers are themselves Petals, the Bloom Machine still needs
no domain knowledge — it only routes a signing request through the verifiers
attached to a grant and refuses to sign if any of them reject.

Until verifier Petals exist, every grant is attested-only: the acting Petal's
claim is recorded, but not independently checked.
