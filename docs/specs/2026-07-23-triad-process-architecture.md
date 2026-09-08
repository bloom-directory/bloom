# Bloom Machine, Broker, and Signer Architecture

**Status:** implementation-ready target architecture; all decisions ratified  
**Date:** 2026-07-23; consolidated revision 2026-07-29; corrected revision 2026-07-29  
**Audience:** Bloom engineers, Petal authors, security reviewers, backend authors, and implementation agents  
**Scope:** decomposition of the current Bloom process into Machine, Broker, and Signer executables  
**Related:** [Sealed Approval](./2026-07-02-sealed-approval.md), [Wallet Architecture](../architecture/Wallet.md), [Bloom Machine + Petals](../architecture/Bloom%20Machine%20+%20Petals.md), [Interaction Modes](../architecture/Interaction%20Modes.md)

## 1. Purpose and precedence

Bloom currently implements orchestration, approval, policy enforcement, key
custody, and cryptographic signing inside one process and trusted core. The
target is three independently released and independently sandboxable
executables:

```text
bloom-machine  <->  bloom-broker  <->  bloom-signer
```

The roles may initially run on one host over authenticated local IPC. Future
versions may place the Broker or Signer remotely without changing the logical
boundaries.

This consolidated document is the normative target. It supersedes the earlier
daemon/signing/keystore terminology and the earlier distinction between
one-shot grants and standing authorizations. Historical documents and code may
still use those names; they do not define the target contract.

Bloom has no deployed users or persisted production state. Compatibility and
migration rules in this document are forward-looking release policy. The
implementation may make a clean break from current formats, APIs, origins, and
crate boundaries.

One compatibility exception is normative: an explicitly staged Bloom v1
single-passkey wallet may be converted once by Signer into the current WKEK
format. Machine never reads the legacy wallet, Broker never receives its
ciphertext or plaintext key, and Signer never signs from the legacy format.
The existing passkey assertion and HPKE-protected PRF output authorize the
conversion. This exception does not preserve any legacy approval, policy
session, daemon signer, or runtime fallback.

### 1.1 What v1 authorization does and does not contain

This architecture contains a compromised Machine for **custody**: it cannot
read keys, PRF output, backend credentials, or Broker/Signer state, and it
cannot obtain a signature without an authenticated Broker request bound to a
user-approved Sealed Approval.

It does **not** contain a compromised Machine **economically** for reusable
approvals in v1. The baseline ClaimAssurance mode is `machine_asserted`
(section 10.2): Broker enforces declared-value limits against a
`PetalUseClaim` that the Machine and Petal produce, and Broker does not parse
the payload to prove the claim. A compromised Machine or Petal may therefore
declare false debits, destinations, or fees and consume the full remaining
capacity of a reusable approval. Signer's independent operation, signature,
rate, and expiry backstops bound **volume and duration only**; a single
signature may drain a wallet.

Exact selectors (section 10.2) are different: they bind the approval to
user-reviewed bytes and hashes, so no substitution is possible after approval.
They do not prevent a user from being deceived about what those bytes mean.

`proof_verified` and `invariant_attested` are the mechanisms that raise
reusable approval above `machine_asserted`. Their registry and review contract
are specified in section 11.1. No verifier is required to ship in v1, so a v1
deployment that uses reusable approvals is operating at `machine_asserted`
unless wallet policy says otherwise.

Every user-facing surface that displays a reusable approval — the ceremony
review (section 12.1), approval listings, and status projections — must
display the effective ClaimAssurance and, for `machine_asserted`, must state
that the limits are asserted by the named Petal and are an accounting bound
rather than an enforced spend cap. This requirement is normative and is
covered by acceptance test AC-09.

## 2. Executive model

The three roles are:

```text
Machine
  runs Petals and coordinates actions and external effects

Broker
  decides whether an operation is authorized under a Sealed Approval

Signer
  performs cryptographic operations through a selected SignerBackend
```

The Machine is the high-churn, lower-trust orchestration process. The Broker is
the approval and policy boundary. The Signer is the custody and cryptographic
boundary.

The Browser participates in a live ceremony. It receives the Broker's signed
review application and WebAuthn data. For a local passkey-backed key it also
transiently receives PRF output, encrypts it to a Signer-provided ephemeral
key, and sends the ciphertext through the Broker to the Signer. Browser and
extension compromise during a ceremony remains an accepted risk.

The Signer never exports a raw private key. A backend may itself be remote and
non-extractable, as with AWS KMS.

## 3. Terminology

| Term | Meaning |
|---|---|
| Machine | The `bloom-machine` executable: VFS, Petal runtime, package handling, chain access, simulation, action orchestration, broadcast, and user projections. |
| Broker | The `bloom-broker` executable: Sealed Approval, ceremony HTTP application, canonical review, policy evaluation, declared-usage budgets, reservations, and authorization audit. |
| Signer | The `bloom-signer` executable: backend registry, backend credentials, key operations, structural approval checks, replay protection, revocation, and custody audit. |
| Sealed Approval | The sole Bloom **signing**-authorization concept. It binds a subject, key, selector, limits, validity, policy, and lifecycle. It never authorizes a custody workflow. |
| Custody ceremony | A user-present ceremony that changes wallet root authority or moves a custody secret: registration, credential add/replace/remove, recovery, import, export, deletion, and backend enrollment. It uses `CeremonySession` (section 13.1), not a Sealed Approval, because it produces no wallet-key signature over a Petal- or Machine-originated payload. |
| Operation class | A short token from a Petal's installer-signed catalog record naming a category of signing operation it may perform, such as `swap` or `order.place`. The catalog fixes the closed set a package may ever claim; the per-call value is asserted by the Machine and is only as trustworthy as the ClaimAssurance mode. |
| SealedApprovalTerms | The immutable, canonically serialized portion of a Sealed Approval that the user and Signer approve. Mutable state, counters, receipts, and projections are excluded. |
| Selector | The portion of a Sealed Approval that identifies permitted payloads, either exactly or by trusted Petal identity and operation class. |
| PetalUseClaim | A normalized accounting claim emitted by a Petal for one signing operation. Broker enforces limits against the claim but does not parse the payload to prove the claim. |
| ClaimAssurance | Evidence, if any, that binds a PetalUseClaim to the signed payload, such as a proof or independently verified invariant attestation. |
| SignerBackend | A compile-time Rust implementation used inside Signer to describe keys and perform cryptographic operations. |
| KeyRef | A structured backend-qualified opaque key reference. Machine and Broker compare it but never parse its backend locator. |
| CryptoSuite | A closed identifier binding key specification, signature algorithm, input kind, domain rules, and normalized output encoding. |
| Operation ID | A caller-generated 256-bit identifier used for deduplication and result recovery. |
| Boot epoch | A random service-instance identifier changed on every process start. |
| Sign request | A short-lived Broker-signed request presented to Signer, binding one operation to one Sealed Approval, key, algorithm, and ordered digest set. |

“Grant,” “standing authorization,” “one-shot grant,” and “standing
capability” are not target product or protocol concepts.

## 4. Goals

### 4.1 Security

- Machine cannot read Signer state, backend credentials, encrypted local key
  files, PRF output, decrypted keys, or raw signer objects.
- Petals cannot contact Broker or Signer directly.
- Machine cannot bypass Broker and request a signature from Signer.
- Broker does not receive plaintext local-backend PRF output or private keys.
- Signer does not parse Petal packages, chain policy, asset budgets, arbitrary
  calldata, or simulation results.
- Every signature over a Machine- or Petal-originated payload is bound to an
  authenticated Broker request, Sealed Approval, KeyRef, operation ID,
  algorithm, ordered digest set, and validity interval. The only signatures
  Signer produces outside that path are made with Signer-internal service keys
  that no wallet controls and that `signer.sign` can never reach: the audit
  journal key, receipt/contribution signing keys, and the per-wallet
  policy-signing key of section 19. Wallet keys are never self-authorizing.
- Each durable datum has one authoritative writer.
- Ambiguous timeouts fail closed and are reconciled with the same operation ID.
- Every service records the effects and decisions it alone can observe.

### 4.2 Product and engineering

- Present one user-facing authorization concept: Sealed Approval.
- Keep approval policy and declared-usage limit enforcement in Broker without
  requiring Broker to understand Petal calldata.
- Make Signer extensible through reviewed Rust backend crates and Cargo
  features.
- Support `LocalSignerBackend` and `AwsKmsSignerBackend` first.
- Preserve the Petal guest abstraction while adding the payload-bearing
  signing version required for exact review.
- Preserve read, stage, and simulation when Broker or Signer is unavailable.
- Support local production first and authenticated remote placement later.
- Split repositories only after protocols and conformance suites stabilize.

## 5. Non-goals

- Runtime loading of arbitrary signer plugins or dynamic libraries.
- Threshold cryptography or MPC in the first implementation.
- Treating AWS IAM, a Unix socket, or filesystem mode as Sealed Approval.
- Teaching Signer or SignerBackend implementations chain semantics.
- Guaranteeing the eventual effect of arbitrary calldata, proxies,
  simulations, external systems, or contract execution.
- Same-user malware resistance unless platform packaging proves it.
- Transparent production fallback to a monolithic embedded signer.
- Reusing the Petal WIT as an inter-service custody protocol.

## 6. Trust and compromise model

The first release targets custody and process containment of a fully
compromised Machine: packaging must make it impossible for the Machine
principal to read Broker or Signer state, authenticate as Broker, or connect to
privileged Signer methods.

Authorization containment depends on selector and ClaimAssurance. Exact
selectors remain bound to user-reviewed bytes. Baseline Petal selectors
deliberately trust the bound Petal and Machine assertion; they do not claim
economic containment of a compromised Machine. Stronger proof or invariant
evidence can add the guarantees of its verifier without making Broker a
protocol parser.

| Compromised component | Property retained | Accepted limitation |
|---|---|---|
| Machine or Petal | Cannot reach Signer directly or read key material or PRF. Exact selectors prevent post-approval substitution. Cannot select the policy it is judged under, exceed local quotas, or spam ceremonies without bound. | For Petal-scoped reusable approval, Broker trusts the bound Petal/Machine claim unless stronger ClaimAssurance is present. A compromised Machine or Petal may lie about value, destination, or payload meaning and consume all remaining approval capacity. See section 1.1: this is the v1 posture, not an edge case. |
| Broker | Cannot extract a local private key or AWS KMS private key. Signer still enforces key binding, exact selectors where present, operation counts, rate backstops, expiry, revocation, and replay. | For Petal-scoped reusable selectors, a compromised Broker may obtain arbitrary signatures up to Signer-enforced parser-free limits. One signature may drain a wallet. During a ceremony, compromised Broker-served JavaScript may deceive the user or exfiltrate browser-visible PRF. |
| Signer | Machine and Broker state remain unavailable. | It can use every local key and remote backend credential it can reach. A local key may be extractable; AWS KMS generally improves extraction resistance, not authorization containment. |
| Browser or extension | No protection is claimed during ceremony. | It can alter review presentation or steal browser-visible PRF. |
| Local process racing the ceremony origin | Broker refuses to run when it cannot own the canonical listener, and the failure is user-visible rather than silent. | A local process that binds `127.0.0.1:18734` before Broker can serve a phishing ceremony on the exact canonical origin under RP ID `localhost`. Section 22 requires activation-manager socket handover and a fail-closed startup bind check; neither can stop a same-RP-ID listener on a *different* port. |
| Other local user on a multi-user host | Cannot reach Machine, Broker, or Signer RPC endpoints, which use OS peer credentials. | The ceremony HTTP listener is loopback TCP and cannot use peer credentials, so it is reachable by any local UID. Its only defense is the single-use 256-bit session token, plus concurrency, body-size, and attempt-rate limits. |
| Filesystem thief | Depends on backend and activation mode. | Local durable activation may weaken at-rest security. AWS credentials or platform secrets have provider-specific exposure. |
| Network attacker | Cannot authenticate, replay, downgrade, or read protected traffic. | Remote topology requires mTLS and enrollment not required for the first local release. |

If Broker is later changed to be the sole verifier of ceremony completion,
Signer compromise bounds must be restated: a compromised Broker would then be
an unrestricted signing principal. This document does not select that weaker
model.

## 7. Responsibility matrix

| Concern | Machine | Broker | Signer |
|---|---|---|---|
| Petal VM and package execution | Owns | No | No |
| Package install and catalog | Owns | Verifies signed catalog evidence | No |
| Chain RPC, simulation, broadcast | Owns | No network by default | Backend-dependent network only |
| Full sealed action and execution state | Owns | Stores digest and receipts | No |
| Canonical review plan | Supplies facts and advisory material | Owns verified rendering | Verifies terms digest only |
| Ceremony HTTP server and assets | No | Owns | No |
| Ceremony challenge and WebAuthn verification | No | Orchestrates and verifies | Independently verifies activation proof |
| Plaintext PRF | Never | Never in the honest implementation | Local backend only |
| Sealed Approval record | Projection only | Sole authoritative owner | Stores enforcement projection |
| Approval policy and declared-usage budgets | No | Sole owner | No |
| Exact digest/count/rate backstops | No | Issues | Enforces independently |
| Backend-qualified keys | Public projection | Opaque references | Sole registry owner |
| Hierarchical key derivation | Projects public children | Requests policy-approved child roles | Backend capability and path registry |
| Local encrypted and decrypted keys | Never | Never | Local backend only |
| AWS credentials and KMS access | Never | Never | AWS backend only |
| Cryptographic signing | No | Authorizes | Performs |
| Canonical wallet policy | Reads projection | Parses and evaluates its own verified snapshot | Sole persistent writer; signs with the dedicated policy-signing key of section 19 |
| Ceremony listener ownership | Never binds or proxies | Sole owner, by activation handover where available | No |
| Revocation epoch reconciliation | No | Active party; polls `revocation.state` | Passive; never calls Broker |
| Registration/import/export/recovery | Public UX orchestration | May host browser shell | Owns secret input and durable effect |
| Audit | External effects | Authorization decisions | Key and backend effects |

## 8. Signer backend architecture

### 8.1 Crates

The initial crate layout is:

```text
bloom-signer-backend-api
bloom-signer-backend-local
bloom-signer-backend-aws-kms
bloom-signer
```

`bloom-signer` compiles a registry of reviewed backends through Cargo
features. `local` is the default production backend; `aws-kms` is opt-in.
Adding a backend requires a new crate, review, rebuild, and signed release.
Runtime plugin loading is prohibited.

The backend trait is internal to Signer. It is not the Broker-to-Signer wire
protocol and contains no Sealed Approval, policy, Petal, asset, or budget
logic.

### 8.2 Core trait

The logical object-safe asynchronous interface is shown below. The concrete
Rust API uses boxed `Send` futures (or an audited `async_trait` expansion);
native trait `async fn` must not be described as object-safe:

```rust
trait SignerBackend: Send + Sync {
    fn backend_id(&self) -> BackendId;
    fn capabilities(&self) -> BackendCapabilities;

    fn describe_key<'a>(
        &'a self,
        key: &'a BackendKeyRef,
    ) -> Pin<Box<dyn Future<
        Output = Result<KeyDescription, BackendError>
    > + Send + 'a>>;

    fn sign<'a>(
        &'a self,
        request: BackendSignRequest,
    ) -> Pin<Box<dyn Future<
        Output = Result<BackendSignature, BackendError>
    > + Send + 'a>>;
}
```

Separate optional traits cover provisioning and local activation:

```text
SignerBackendProvisioning
  generate, import, delete, export_encrypted

SignerBackendActivation
  prepare, activate, deactivate, activation_status
```

A backend must not fake support for an operation. Signer advertises backend
capabilities and rejects unsupported wallet/backend combinations at enrollment.

### 8.3 Capabilities

At minimum:

```text
backend_id
configured backend_instance_id
supported key specifications
supported signature algorithms
supported derivation schemes and namespace constraints
raw-message versus digest input
normalized output forms
maximum input and batch size
generate/import/export/delete support
activation or user-presence requirements
local versus networked operation
provider idempotency characteristics
```

`backend_id` names an implementation kind such as `local` or `aws-kms`.
`backend_instance_id` names a Signer-owned, pinned configuration instance such
as one AWS account/role/region/egress profile. Key routing always uses the
instance ID; a key ARN alone does not select credentials.

The normalized backend request is:

```text
BackendSignRequest {
  provider_attempt_id
  key_ref
  crypto_suite
  input = Digest32(bytes) | Message(bytes)
  deadline
}
```

The normalized result is:

```text
BackendSignature {
  crypto_suite
  encoding
  bytes
  provider_correlation_id?
}
```

Backend outcomes use a closed taxonomy:

```text
Success(BackendSignature)
DefinitiveRejected
RetryableBeforeAcceptance
Unsupported
InvalidRequest
IndeterminateAcceptance
```

Backend-specific errors map into this taxonomy before leaving the backend
crate. Deadline or cancellation is `RetryableBeforeAcceptance` only when the
backend can prove no provider acceptance; otherwise it is
`IndeterminateAcceptance` and becomes `AMBIGUOUS_PROVIDER_EFFECT`. Unknown
errors default to indeterminate. The backend conformance suite fault-injects
each outcome.

Signer verifies every backend result against the KeyRef's pinned public key
and requested CryptoSuite before it journals or publishes the result. W1
freezes CryptoSuite identifiers, input rules, normalized encodings, and golden
vectors. Backends never choose whether an input is raw or prehashed.

### 8.4 LocalSignerBackend

The local backend owns:

- encrypted private-key material and credential records;
- local wallet generation and encrypted import/export;
- PRF-based unwrap;
- optional durable activation wrapping;
- decrypted-key memory and zeroization;
- local cryptographic signing.

Plaintext PRF and decrypted keys exist only in Browser during ceremony and
LocalSignerBackend/Signer memory as applicable. They are never persisted or
returned to Broker.

### 8.5 AwsKmsSignerBackend

The AWS backend owns:

- AWS credential acquisition under an explicitly configured provider;
- tightly scoped network egress;
- key enrollment and metadata pinning;
- KMS `GetPublicKey`, `DescribeKey`, and `Sign` calls;
- provider signature normalization;
- provider-specific audit correlation and error mapping.

Enrollment pins immutable key ARN, account, region, key usage, key spec,
supported algorithm, canonical public key, and public-key fingerprint/address.
Aliases are not durable key identity because they can be retargeted.

For recoverable secp256k1 signatures, the backend accepts a 32-byte digest,
requests the provider's compatible ECDSA operation without rehashing,
DER-decodes `(r,s)`, normalizes low `s`, derives recovery parity against the
pinned public key, and returns Bloom's normalized recoverable signature.

Signer stores the normalized terminal result before publishing it. A provider
timeout can make it impossible to know whether the remote provider computed a
signature. When no signature result is available and provider acceptance
cannot be disproved, the attempt terminates as
`AMBIGUOUS_PROVIDER_EFFECT`: no signature is published, all applicable
operation/signature limits remain charged, and automated retry is forbidden.
A new signature requires a new operation and whatever new approval capacity is
then required. Signer therefore guarantees one published/accounted result per
operation ID, not that a nondeduplicating backend was invoked exactly once.

Ambient cloud credentials and unrestricted instance-metadata discovery are
disabled by default. Packaging must declare credential source, account,
region, allowed ARNs, egress, CloudTrail expectations, quotas, and failure
behavior.

### 8.6 Hierarchical key derivation

**Proposed resolution (D-052).**

Hierarchical derivation is an optional backend capability, not an assumption
of every SignerBackend. A separate trait exposes it:

```text
SignerBackendDerivation {
  supported_derivation_schemes()
  derive_public(root, canonical_path)
  register_derived_key(root, canonical_path)
}
```

The first implementation is `bip32-secp256k1` in LocalSignerBackend. The local
backend stores one encrypted root seed/key, derives a requested child only
inside Signer memory, signs with it, and zeroizes child private material.
Persisted state contains the encrypted root and public derivation registry, not
plaintext extended private keys or child private keys.

Callers do not submit arbitrary paths. A wallet policy defines derivation
namespaces such as:

```text
m / purpose' / coin_type' / account' / change / index
```

Signer allocates the next index transactionally from a named namespace,
enforces canonical BIP32 syntax, hardened/non-hardened rules, maximum depth and
index, and prevents path reuse. The resulting child public key and fingerprint
are verified before the child KeyRef is committed. Public xpub export is a
separate policy-controlled custody operation and is not implied by derivation.

Each derived child receives its own KeyRef. Sealed Approval binds the exact
child KeyRef; authority does not automatically flow from a root or sibling
key. Rotation or recovery of the encrypted root restores access to all
registered children, while deletion of a child tombstones its path so it is
never silently reallocated.

Recovering the root recovers the *ability* to derive, not the *knowledge of
what was derived*. The derivation registry — allocated paths, tombstones, the
next index per namespace, and pinned child public keys — is Signer durable
state and is not reconstructible from the seed. It is therefore part of the
Signer backup set defined in section 19.1 and is included in the encrypted
export of section 13. Restoring a root without its registry leaves funds at
already-issued child addresses unreachable in practice, so:

- `key.derive` fails closed when the registry store is unavailable or its
  integrity check fails; Signer never re-derives an index it cannot prove is
  unallocated;
- every registry mutation is journalled before the child KeyRef is published;
- encrypted export of a wallet with derivation enabled always includes the
  registry, and importing a root without a registry marks the wallet
  `DERIVATION_REGISTRY_MISSING` and refuses new derivation until an operator
  supplies the registry or explicitly accepts a rescan bound.

Creating a child is authority-extending: it produces a new receivable address
under the wallet root. `key.derive` therefore requires either an exact custody
ceremony or an explicit wallet-policy rule naming the namespace and a maximum
number of children Broker may allocate without a ceremony. Broker cannot
allocate children unilaterally by default.

AwsKmsSignerBackend advertises hierarchical derivation as unsupported. AWS
wallets may enroll multiple independent KMS keys instead. A future HSM or
backend may implement its native derivation only if it produces the same
stable derived-KeyRef, public-key verification, path-allocation, audit, and
recovery semantics.

## 9. Backend-qualified key references

Protocol key identity is structured:

```text
KeyRef {
  backend: Token,
  backend_instance: Token,
  locator: String,
  key_spec: Token,
  public_key_fingerprint: Hex32,
  derivation?
}
```

Examples:

```json
{
  "backend": "local",
  "backend_instance": "local-default",
  "locator": "018f6a40-7b63-7f4d-a64a-0cf3d5f0d8b1",
  "key_spec": "secp256k1",
  "public_key_fingerprint": "<64 lowercase hex>",
  "derivation": {
    "scheme": "bip32-secp256k1",
    "root_key_id": "root-018f6a40",
    "path": "m/44'/60'/0'/0/0"
  }
}
```

```json
{
  "backend": "aws-kms",
  "backend_instance": "aws-prod-eu-west-2",
  "locator": "arn:aws:kms:eu-west-2:123456789012:key/1234abcd-...",
  "key_spec": "secp256k1",
  "public_key_fingerprint": "<64 lowercase hex>",
  "derivation": null
}
```

`locator` is opaque outside Signer and bounded to 2 KiB. A local locator is a
stable random ID, never a wallet name or filesystem path. An AWS locator is the
immutable key ARN; region is not duplicated outside the ARN.

The fingerprint is lowercase SHA-256 over the canonical DER SubjectPublicKeyInfo
bytes returned or constructed at enrollment. KeyRef equality compares every
field exactly, including derivation metadata. Changing backend kind, backend
instance, locator, key spec, derivation root/path, or pinned public key creates
a new KeyRef and requires a fresh Sealed Approval.
The Signer enrollment record additionally freezes the effective CryptoSuites
supported by that exact key and configuration.

## 10. Unified Sealed Approval

### 10.1 Canonical structure

There is one authorization record. Its immutable terms and mutable state are
separate fields:

```text
SealedApproval {
  schema
  approval_id
  terms: SealedApprovalTerms
  review_manifest_digest
  state
  activation_receipt?
  created_at
  updated_at
}

SealedApprovalTerms {
  subject
  wallet_id
  key_ref
  allowed_crypto_suites[]
  selector
  limits
  activation_mode
  wallet_revocation_epoch
  policy_version
  policy_digest
  provenance_digest
  request_nonce
  issued_at
  not_before
  expires_at
  renewal_of?
}
```

`subject` is a tagged union:

```text
PetalSubject {package_hash, route, agent_id?}
CliSubject {client_id, command_class}
SystemSubject {component_id, operation_class}
```

There is no custody subject. Registration, credential changes, recovery,
import, export, deletion, and backend enrollment are custody ceremonies
(section 13), not Sealed Approvals: they produce no wallet-key signature over a
Machine- or Petal-originated payload, and `ApprovalLimits` — whose counts must
all be greater than zero — cannot describe them.

Unknown variants or fields are rejected. Every limit is explicit. Missing
limits never mean unlimited authority.

`agent_id` is an optional Machine-supplied label used only for attribution in
the ceremony display, listings, and audit. It is not authenticated, confers no
authority, is never compared during authorization, and must be rendered as
Machine-asserted wherever it is shown.

`provenance_digest` is the SHA-256 of the JCS encoding of the provenance record
Broker verified for this subject before preparing the approval: for
`PetalSubject`, the installer-signed catalog record binding package hash,
route, declared operation classes, and publisher identity; for `CliSubject` and
`SystemSubject`, the installer-signed edge-manifest entry for that client or
component. Binding it into the immutable terms means an approval cannot outlive
the catalog record that justified it: Broker recomputes the digest on every
use and denies the operation on mismatch, so replacing an installed package
without a fresh ceremony invalidates its approvals.

`request_nonce` is a caller-supplied 128-bit random value. It exists so that
approving identical terms twice — explicitly permitted by section 10.4's
overlapping-approval rule — always produces distinct `approval_id`s. Broker
rejects a prepare whose computed `approval_id` already exists in any state.

`allowed_crypto_suites` is an ordered, deduplicated list of one to four
CryptoSuite identifiers from the closed W1 registry. Every one of them is
displayed in the ceremony and bound into the approval digest. A multi-step
Petal flow that legitimately spans suites — an authentication signature plus a
typed-order signature, say — uses one approval naming both, rather than
interrupting the flow with a second ceremony. Each `PetalUseClaim` and each
SignRequest names exactly one member; Broker and Signer independently reject
any suite outside the list. An `ExactSelector` approval normally names exactly
one suite, because its ordered hashes are already suite-specific.

`approval_digest` is:

```text
SHA-256("bloom-sealed-approval-terms/v1" || JCS(SealedApprovalTerms))
```

`approval_id` is the lowercase hexadecimal `approval_digest`. Lifecycle state,
review-manifest digest, counters, timestamps of state transitions, receipts,
and service projections are excluded. Every ceremony contribution, review
manifest, SignRequest, activation receipt, ledger entry, and audit event binds
both `approval_id` and `approval_digest`. The review manifest contains the
approval digest; its own digest is stored outside the immutable terms, avoiding
a circular digest.

`activation_mode` is one of:

```text
boot_bound
durable_local {provider_tier, maximum_rearm_until}
backend_managed
```

It is displayed to the user and bound into every ceremony and activation
receipt. `durable_local` is valid only for LocalSignerBackend and
`backend_managed` only for a backend whose enrolled capabilities support it.

### 10.2 Selectors

Selectors are tagged fields inside the same structure, not separate
authorization products:

```text
ExactSelector {
  ordered_payload_digests[]
  ordered_hashes[]
}
```

```text
PetalSelector {
  package_hash
  route
  allowed_operation_classes[]
  required_claim_assurance
}
```

An exact approval is normally:

```text
selector = ExactSelector
max_operations = 1
max_signatures = length(ordered_hashes)
```

Exact single-use approval is represented by `max_operations = 1`, not by
`amount = 1`. Asset amount, operation count, and signature count are
independent. An approved batch is one operation with multiple ordered
signatures.

A reusable approval uses a `PetalSelector` plus explicit operation, signature,
declared-value, rate, and lifetime limits. It does not require Broker to know
the payload format, calldata encoding, chain, venue, or protocol. A new Petal
can use reusable approval without first adding Broker code.

`allowed_crypto_suites` in `SealedApprovalTerms` applies to both selector
variants. Neither selector permits Broker or Machine to substitute a backend
algorithm, input mode, signing domain, or normalized output form outside that
approved list.

`allowed_operation_classes` must be a subset of the operation classes declared
in the installer-signed catalog record committed by `provenance_digest`.
Broker rejects a prepare that names a class the package is not permitted to
claim, and rejects a `PetalUseClaim` naming a class outside the approval. This
bounds the *vocabulary* a package can ever use; under `machine_asserted` it
does not establish that the class named on a given call is the operation
actually performed.

Every Petal-scoped use carries:

```text
PetalUseClaim {
  package_hash
  route
  operation_class
  crypto_suite
  payload_digest
  ordered_hashes[]
  declared_debits[]
  declared_destinations[]
  declared_fee
  nonce
  claim_assurance
}
```

Broker validates the claim's canonical shape, Petal/route/operation binding,
CryptoSuite membership in `allowed_crypto_suites`, nonce, approval limits, and
any ClaimAssurance. It does not establish that declared debits, destinations,
fees, or operation class truthfully describe the payload merely by inspecting
the payload.

`declared_fee` is mandatory. For an operation class whose CryptoSuite and
chain can incur a network fee, it is a `(chain, asset, amount)` line naming the
maximum fee the operation may consume, and Broker debits it against a value
limit for that native asset exactly as it debits any other line. An approval
that omits a value line for the fee asset denies every fee-bearing operation;
this is deliberate, because otherwise an approval scoped to a token budget
would permit unbounded native-token burn. For an operation class that cannot
incur a fee — an off-chain authentication signature, for instance — the Petal
declares the explicit `none` variant, and Broker denies the operation if the
catalog record marks that class fee-bearing.

`claim_assurance` is a tagged value:

```text
machine_asserted
proof_verified {verifier_id, verifier_digest, proof_digest}
invariant_attested {attestor_id, attestation_digest}
```

`machine_asserted` is the baseline mode and explicitly trusts the Petal and
Machine runtime. Proof and attestation verifiers establish only the claims
defined by their reviewed contract; they are general assurance mechanisms,
not protocol-specific calldata adapters. Wallet policy may require a minimum
assurance for selected limits or Petals.

### 10.3 Limits

```text
ApprovalLimits {
  max_operations
  max_signatures
  operation_rate_limits[]
  signature_rate_limits[]
  value_limits[]
}
```

Counts are unsigned 64-bit canonical decimal strings and must be greater than
zero. They are lifetime totals for the approval. Amounts are unsigned 256-bit
canonical decimal strings; arithmetic overflow denies the operation. Rate
limits use exact continuous sliding windows over Broker reservation time with
durations expressed as positive integer milliseconds. Windows include
reserved, committed, and quarantined entries and exclude only durably released
known non-effects.

The edge manifest pins the platform time profile. Linux reads the host wall
clock and persists a nondecreasing floor. During one boot, a suspend-aware
monotonic anchor detects an unexpected large forward step; across boots Bloom
accepts nondecreasing elapsed wall time so ordinary powered-off intervals do
not require repair. Clock rollback or a same-boot discontinuity degrades the
service and denies new rate-limited signing. Peer-supplied time is never
authoritative, and no particular host time daemon is required.

The macOS profile uses the host wall clock directly. Changing that clock
requires administrator authority, and administrator/root compromise is
outside the service-isolation threat model: that actor can already alter Bloom
state. Bloom therefore does not persist a second effective clock, reject wall
clock discontinuities, or require an operator clock-repair ceremony on macOS.
Expiry and rolling-window semantics follow the host wall clock.

Linux durable entries store UTC plus boot/monotonic audit anchors. Across a
Linux service restart, `effective_now` is the maximum of current trusted UTC
and the last durably accepted effective time, so rollback never restores
budget or extends authority. Existing macOS clock-state rows are legacy data
and are not consulted or updated.

For the Linux authenticated-time profile, both directions of clock fault are
bounded and both have a repair path:

- **Rollback.** Effective time freezes and new rate-limited signing is denied
  until the clock catches up or an audited operator repair advances it.
- **Forward jump.** A reading more than `max_forward_step` (compiled default:
  one hour) ahead of the last durably accepted effective time is not adopted.
  The service records a `CLOCK_FORWARD_JUMP` audit event, continues on the
  previous effective time plus elapsed monotonic time, and reports the
  condition through `readiness`. This prevents a single bad reading from
  permanently burning every rolling window and mass-expiring live approvals.
  An operator may accept the new time through the same audited repair path; a
  repair that would expire live approvals lists them in its confirmation.

Linux suspend/resume, rollback, forward-jump, and untrusted-source tests are
mandatory. macOS restart tests must prove that stale durable clock state and
wall-clock discontinuities do not latch Broker or Signer readiness.

Broker and Signer each evaluate rate limits over their own clock and their own
reservation timestamps, so their windows can disagree at the boundary. Broker's
window is authoritative for user-facing budget display and for the decision to
reserve; Signer's is an independent backstop. When Signer definitively rejects
an operation Broker had already reserved, the rejection is a known non-effect:
Broker releases the reservation in full, records
`SIGNER_RATE_BACKSTOP_DENIED`, and surfaces a distinct status so the condition
is never reported to the user as a spend. Broker must not retry the operation
under a new ID. Because both windows derive from the same immutable approved
limits, this divergence is bounded by clock skew, and packaging must keep the
two services on the same time source.

`not_before` and `expires_at` are the sole validity bounds and `expires_at`
must be later than `not_before`. Broker defaults requested approvals to 30
days; the interactive exact-operation UX defaults to 10 minutes. Broker
enforces any lower wallet-policy maximum. Signer independently rejects every
approval longer than the compiled v1 ceiling of 90 days. Renewal requires a
fresh ceremony and cannot extend the immutable old terms.

Value lines identify a canonical `(chain, asset, amount)` and may contain
rolling-window and lifetime limits. Broker debits them from
`PetalUseClaim.declared_debits` and `PetalUseClaim.declared_fee`. Assets absent
from the approval are denied, including fee assets. V1 uses no price feed or
fiat-denominated budget inside Broker, so a value line bounds a token quantity
and not a monetary amount; the ceremony displays it as such.

A Petal must claim the full delegated amount for value-delegating operations
such as token approvals. Unlimited declared approvals exceed finite limits and
are denied. Under `machine_asserted` assurance, this is a trusted-Petal
contract rather than a Broker-derived fact.

SignerApprovalState independently reserves and commits ceremony-bound
`max_operations`, `max_signatures`, operation/signature rate limits, total
counts, and expiry in one transaction. Signer does not interpret asset values,
Petal claims, or payload meaning. These are parser-free custody backstops, not
economic-loss bounds.

### 10.4 Lifecycle

The unified lifecycle is:

```text
PREPARED
  -> AWAITING_CEREMONY
  -> ACTIVE
  -> EXHAUSTED | EXPIRED | REVOKED

PREPARED | AWAITING_CEREMONY -> CANCELLED | FAILED | EXPIRED

reconciliation-only, never terminal:
AWAITING_CEREMONY -> ORPHANED -> ACTIVE | REVOKED | FAILED
```

`ORPHANED` is a transient reconciliation state, not an outcome. It is entered
only when Signer holds a durable activation receipt Broker cannot match, and
it always resolves as described in section 10.5. An approval may not remain
`ORPHANED` across a completed reconciliation pass, and an `ORPHANED` approval
never authorizes signing.

Renewal creates a new `approval_id` through a fresh ceremony and references the
previous approval with `renewal_of`. By default renewal is a no-overlap
replacement: Signer atomically activates the new approval and revokes the old
approval before returning its receipt, and Broker marks the new approval
active only after that receipt. The ceremony displays prior committed and
quarantined spend. Rolling-window history carries into the replacement.
Lifetime budgets reset to the newly displayed limits because renewal is fresh
user authorization; wallet policy may forbid early renewal or cap cumulative
renewals. A deliberately overlapping approval is a separate new approval, not
`renewal_of`, and must be displayed and budgeted independently.

Operation reservation and signing progress are not approval lifecycle states.
They live in the operation journal described in section 16.

### 10.5 Persistence and activation

The canonical Sealed Approval is durable regardless of selector or limits.
Persistence of authorization and availability of a backend key are separate:

- AWS KMS may remain usable across local restart.
- A local activation may be boot-bound and require a new unlock ceremony.
- A local durable activation may re-arm from a platform-protected wrap when
  the approved terms and wallet policy permit it.

Signer stores a `SignerApprovalState` keyed by `approval_id` containing only
the exact or parser-free constraints it can enforce, the frozen
`allowed_crypto_suites` list, activation mode, backstop counters, revocation
state, and backend binding. Broker stores
declared-usage limits and the spend ledger. These are projections of one Sealed
Approval, not separate authority concepts.

Signer activation state is independent:

```text
PENDING_PROOF -> ACTIVE -> INACTIVE | REVOKED | EXPIRED
PENDING_PROOF -> CANCELLED | FAILED
```

`INACTIVE` means the approval remains canonically active but the backend must
be re-armed using a fresh ceremony proof for the same immutable terms.
`ORPHANED` is used only when Signer has a durable activation receipt that
Broker cannot reconcile. Broker denies new operations, queries Signer with the
same activation operation ID, and resolves to `ACTIVE` or atomically revokes
Signer state before marking the approval `FAILED`/`REVOKED`. An orphaned
approval never authorizes signing.

## 11. Broker policy and Petal-claim enforcement

Broker is the sole approval-policy and declared-usage limit authority. It owns:

- canonical payload/envelope validation;
- policy parsing and evaluation;
- provenance verification;
- canonical PetalUseClaim validation;
- optional proof/invariant assurance verifiers;
- declared debit and value-delegation accounting;
- declared fee reservation;
- rolling/lifetime budget evaluation;
- reserve, commit, release, and quarantine ledger state.

Broker does not decode Petal calldata or require a registered schema before a
Petal can receive reusable approval. It verifies that Petal identity, route,
operation class, claim assurance, and declared usage fit the immutable Sealed
Approval. It derives or checks the cryptographic signing hash only at the
generic CryptoSuite/envelope layer required to prevent byte substitution; it
does not infer application meaning from those bytes.

The security meaning of a declared-value budget is conditional:

- with `machine_asserted`, it bounds honest bound-Petal behavior and
  accounting, but does not contain a compromised Machine or Petal;
- with `proof_verified` or `invariant_attested`, it additionally has exactly
  the integrity guarantees supplied by the selected verifier contract;
- Signer operation/signature/rate/expiry backstops remain independent of all
  Petal claims.

The ledger is append-only and keyed by
`(approval_id, operation_id, asset_id)`. Concurrent limit checking and
reservation insertion occur in one transaction. Ambiguous effects remain
charged. Known non-effects may be released.

### 11.1 Assurance verifier registry

`proof_verified` and `invariant_attested` are the only mechanisms that raise a
reusable approval above `machine_asserted`, so their supply chain is governed
exactly as strictly as `SignerBackend`:

- a verifier is a reviewed Rust crate compiled into Broker behind a Cargo
  feature; runtime loading of verifiers is prohibited;
- `verifier_id` is a stable token naming the implementation kind;
  `verifier_digest` is the SHA-256 of the reviewed verifier artifact recorded
  at build time, and Broker rejects any claim whose `verifier_digest` does not
  match a compiled-in verifier;
- each verifier ships a written **verifier contract** stating precisely which
  fields of a `PetalUseClaim` it establishes and under what assumptions. Broker
  treats every field outside that contract as `machine_asserted` even when the
  claim carries a verified proof, and the ceremony renders the two categories
  separately;
- `attestor_id`/`attestation_digest` follow the same rules for
  `invariant_attested`, with the attestor's public key pinned in the edge
  manifest;
- `broker.capabilities` advertises the compiled verifier set with digests so
  wallet policy can require a minimum assurance that the running Broker can
  actually satisfy. A policy naming an unavailable verifier fails closed rather
  than silently degrading to `machine_asserted`.

No verifier is required to ship in v1. A build with no compiled verifiers
advertises an empty set, and every reusable approval on that build operates at
`machine_asserted` with the disclosure required by section 1.1.

## 12. Ceremony ownership and protocol

### 12.1 Broker-owned web application

Broker owns:

- the loopback HTTP listener and stable browser origin;
- embedded static HTML, JavaScript, CSS, and images;
- ceremony URL/session tokens;
- canonical plan rendering;
- WebAuthn request orchestration;
- Origin, Host, CSRF, Fetch Metadata, CSP, cache, size, and concurrency
  enforcement;
- user-visible status and retry UX.

Production assets are embedded in the signed Broker binary and pinned by
content digest. There are no remote assets, redirects, CORS, JSONP, service
workers, or Machine reverse proxies.

Broker constructs:

```text
ReviewManifest {
  schema
  approval_id
  approval_digest
  canonical_plan
  canonical_plan_digest
  exact_payload_digests[]
  exact_hashes[]
  petal_use_claim?
  claim_assurance?
  attributed_advisory_items[]
  issued_at
  expires_at
  broker_key_id
  broker_signature
}
```

For opaque exact payloads the plan displays the complete digest/hash,
CryptoSuite, outer target/value facts that Broker can verify, package/route
identity, and an explicit statement that Bloom has not established execution
effects. Petal/Machine plans, PetalUseClaims, and simulations are separately
attributed advisory material. Verified proof or invariant evidence may state
only the claims established by its verifier contract.

For a reusable (`PetalSelector`) approval the plan additionally displays every
member of `allowed_crypto_suites`, the permitted operation classes, all
declared-value and fee lines, the operation/signature/rate/lifetime limits,
the activation mode, and the effective ClaimAssurance. When the assurance is
`machine_asserted`, the plan must state in the primary approval surface — not
in a footnote or a disclosure the user can approve without seeing — that the
displayed limits are asserted by the named Petal, that Bloom does not verify
them against the payload, and that a compromised Petal or Machine can consume
the full remaining capacity. Where a verifier is present, fields inside and
outside its contract are rendered as visibly distinct categories.

The initial origin is:

```text
listener = 127.0.0.1:18734
origin   = http://localhost:18734
RP ID    = localhost
```

Broker must own the canonical listener or refuse to serve ceremonies. It
acquires the socket by handover from the OS activation manager wherever the
platform supports it (section 22); where it binds directly it uses exclusive
binding without address reuse, and a bind conflict is a fatal, user-visible
startup error reported through `broker.readiness` and the CLI. Broker never
falls back to another port, and Machine never proxies or re-hosts the ceremony
surface. This prevents a local process from pre-empting the canonical origin;
it does not prevent a same-RP-ID listener on a *different* port, which remains
the accepted residual recorded in section 6.

Every request requires exact Host. Mutations require exact Origin, JSON
content type, Fetch Metadata `same-origin`, and a single-use 256-bit session
token. Responses are `no-store` and set strict CSP, frame, referrer, and MIME
headers. The listener enforces bounded concurrent sessions, a bounded request
body, and a per-source attempt rate; repeated invalid-token requests are
rate-limited and audited, because loopback TCP is reachable by any local UID.

### 12.2 Signer proof contribution

Before Browser launch, Broker calls `ceremony.prepare` with the complete
immutable `SealedApprovalTerms`, review-manifest digest, exact ordered payload
digests/hashes where applicable, requested replacement approval if any, and a
stable activation operation ID. Signer verifies the KeyRef enrollment, that
every member of `allowed_crypto_suites` is supported by that exact key and
configuration, the wallet revocation epoch, activation mode, selector/count
consistency, and replacement rules, persists `PENDING_PROOF`, and returns:

```text
SignerCeremonyContribution {
  ceremony_id
  signer_nonce
  approval_digest
  review_manifest_digest
  key_ref
  allowed_crypto_suites[]
  activation_mode
  wallet_revocation_epoch
  required_user_verification
  ephemeral_encryption_public_key?
  expires_at
  signer_signature
}
```

Broker includes that immutable signed contribution in the WebAuthn challenge
and rendered review. Broker cannot change approval terms without invalidating
the Signer contribution.

Browser returns the raw WebAuthn assertion to Broker. Broker verifies it and
calls `ceremony.complete` with the unchanged assertion, signed contribution,
and optional encrypted local PRF envelope, reusing the activation operation
ID. Signer independently verifies:

- credential and wallet binding;
- challenge and Signer nonce;
- exact Sealed Approval digest and KeyRef;
- exact review-manifest digest;
- exact `allowed_crypto_suites` list, activation mode, and wallet revocation
  epoch;
- RP ID, origin, user-presence/user-verification flags;
- expiry, single-use status, and replay;
- requested activation mode and parser-free limits.

Signer atomically records `SignerApprovalState`, activation/replacement
effects, counters, ceremony consumption, and custody audit only after
successful verification. `ceremony.complete` is the sole activation mutation;
there is no separate `sealed_approval.activate` RPC. It returns:

```text
SignerActivationReceipt {
  activation_operation_id
  ceremony_id
  approval_id
  approval_digest
  review_manifest_digest
  key_ref
  allowed_crypto_suites[]
  activation_mode
  wallet_revocation_epoch
  replaced_approval_id?
  activated_at
  expires_at
  signer_signature
}
```

Same-ID replay returns the identical receipt. Broker marks the Sealed Approval
`ACTIVE` only after persisting and verifying it.

### 12.3 Local PRF transport

For LocalSignerBackend, Browser receives PRF output and seals it with RFC 9180
HPKE base mode using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
ChaCha20-Poly1305. The recipient public key is the single-use Signer ephemeral
key in the signed contribution. `info` is the ASCII string
`bloom-local-prf/v1`. Associated data is JCS:

```text
{
  ceremony_id,
  signer_nonce,
  approval_id,
  approval_digest,
  review_manifest_digest,
  key_ref,
  allowed_crypto_suites,
  credential_id,
  activation_mode,
  wallet_revocation_epoch
}
```

The HPKE envelope contains `{kem_output, ciphertext}` as unpadded base64url,
is limited to 4 KiB, and is accepted once. Browser POSTs it to Broker, which
forwards it unchanged in `ceremony.complete`. Broker has no decryption key.

Signer rejects wrong AAD, key reuse, replay, expiry, or a noncanonical
envelope. It decrypts only after assertion verification, passes the secret
directly to LocalSignerBackend activation, and zeroizes plaintext and
ephemeral private key. Plaintext PRF is never logged, cached, persisted, or
represented in a Broker DTO. W1/W5 publish HPKE and JCS golden vectors.

Because Broker serves JavaScript, a compromised Broker can serve code that
exfiltrates PRF before encryption. This is part of the accepted
Browser/Broker-during-ceremony risk and must not be hidden by claims about
honest-path encryption.

AwsKmsSignerBackend does not use PRF to unlock the remote private key. It still
requires the independently verified ceremony proof when a new Sealed Approval
is activated.

### 12.4 Separation from execution

Ceremony activates a Sealed Approval only. Machine execution is always a
subsequent operation with its own operation ID. There is no combined
“approve and broadcast” mutation.

### 12.5 Prepare response and Machine projection

**Proposed resolution (D-053).**

After Broker has durably prepared the Sealed Approval, obtained the Signer
contribution, and created the browser session, `sealed_approval.prepare`
returns:

```text
SealedApprovalPrepareResponse {
  approval_id
  state = "AWAITING_CEREMONY"
  ceremony_url
  ceremony_expires_at
  review_manifest_digest
}
```

`ceremony_url` is the Broker-owned
`http://localhost:18734/ceremony/<single-use-token>` launch URL.
`ceremony_expires_at` is the Broker session expiry and is no later than the
Signer contribution or immutable approval expiry. The URL is an owner-readable
launch secret: it may appear in the originating VFS status projection and CLI
output, but never in logs, audit messages, Petal-visible data, telemetry, or
unrelated projections.

Prepare is idempotent by operation ID and immutable request digest. Repeating
it while the session is live returns the same URL and expiry. It never creates
parallel ceremony tokens. After completion, expiry, or cancellation, the old
URL cannot be revived; a new ceremony attempt uses a new operation/session
identity according to the lifecycle rules.

Because approval fatigue is the one attack a compromised Machine can mount
against an honest user for free, Broker bounds ceremony creation
independently of Machine cooperation: at most one live ceremony session per
wallet, a bounded number of distinct prepare requests per wallet per rolling
window, and an exponential backoff after consecutive user cancellations or
expiries. Exceeding a bound returns `CEREMONY_RATE_LIMITED` with a retry-after
value and is audited. This is a Broker-side control; it is not derived from
any Machine-supplied hint.

Machine stores only this public launch projection under the originating action
or VFS workflow:

```text
ceremony_state
ceremony_url?
ceremony_expires_at?
approval_id
last_error?
```

Machine polls or subscribes to Broker status and surfaces `ceremony_url` and
`ceremony_expires_at` only while Broker reports `AWAITING_CEREMONY`. On
`ACTIVE`, `EXPIRED`, `CANCELLED`, or `FAILED`, Machine atomically clears both
fields while retaining the terminal status and approval ID. After Machine
restart it rebuilds the projection from Broker; it never reconstructs a URL
from local data or proxies ceremony HTTP.

## 13. Custody workflows

Registration, raw-key import, encrypted export, recovery, credential changes,
key deletion, backend enrollment, and local durable activation contain custody
secrets or change root authority.

These are **custody ceremonies, not Sealed Approvals.** A Sealed Approval
authorizes wallet-key signatures over Machine- or Petal-originated payloads and
is measured in operations, signatures, and declared value; a custody workflow
produces no such signature and has no meaningful `ApprovalLimits`. Custody
workflows therefore use `CeremonySession` (section 13.1) and the state machines
of section 13.6. They share the Broker ceremony application, the HPKE secret
channel, Signer's independent verification boundary, operation identity,
idempotency, and audit correlation with Sealed Approval ceremonies, and they
differ only in what they authorize. `ceremony_kind` is the discriminator, and a
mismatch between the requested kind and the durable effect is a security error.

Broker hosts their common browser shell and is the only browser HTTP endpoint.
There is no direct Browser-to-Signer endpoint. Each `custody.prepare` call
causes Signer to return a signed single-use session contribution containing
workflow kind, custody operation ID, expiry, expected input class, and an HPKE
recipient key. Browser encrypts sensitive input using the same HPKE suite as
section 12.3 with `info = "bloom-custody-input/v1"` and JCS AAD binding the
session contribution, workflow, wallet/KeyRef if known, and Browser credential.
Broker relays only ciphertext through `custody.complete`.

For a sensitive output such as an encrypted backup or recovery material,
Browser supplies a single-use HPKE recipient key bound into the authenticated
request. Signer encrypts the output directly to that key and Broker relays the
ciphertext. Broker status contains only public progress and receipt digests.
All custody preparation, completion, and result retrieval use stable operation
IDs, single-use sessions, bounded ciphertexts, replay rejection, and signed
terminal receipts. W5 freezes DTOs and golden vectors.

Signer and the selected backend own key generation, import, export encryption,
credential records, recovery verification, key deletion, and backend
enrollment. Machine never transports sensitive input through VFS, generic RPC,
logs, environment variables, or command-line arguments.

### 13.1 Shared ceremony framework

**Proposed resolution (D-054 for registration and credential workflows).**

Sealed Approval, wallet registration, passkey addition/replacement, and wallet
recovery use one Broker-hosted ceremony application and common protocol
components:

```text
CeremonySession {
  ceremony_id
  ceremony_kind
  operation_id
  review_manifest_digest
  signer_nonce
  WebAuthn options/challenge
  required user verification
  HPKE recipient key
  expires_at
  single-use state
}
```

`ceremony_kind` is a closed tag:

```text
sealed_approval
wallet_registration
wallet_import
wallet_export
wallet_delete
wallet_recovery
credential_add
credential_replace
credential_remove
backend_enrollment
key_derive
policy_update
```

`sealed_approval` is the only kind that activates a Sealed Approval; every
other kind is a custody ceremony and produces a custody receipt instead of a
`SignerActivationReceipt`.

All kinds reuse Broker origin/assets, exact Host/Origin/CSRF/Fetch Metadata
checks, session URLs, expiry, WebAuthn parsing, HPKE envelope, idempotent
completion, status projection, and audit correlation. Signer independently
verifies the raw attestation/assertion, challenge, nonce, RP/origin, ceremony
kind, wallet binding, UV requirement, and encrypted secret AAD before a durable
effect. A ceremony-kind mismatch is a security error.

Custody prepare responses use the same `ceremony_url` and
`ceremony_expires_at` fields as section 12.5 and Machine applies the same
projection/clearing rules.

### 13.2 Multi-passkey wallet wrapping

A local wallet has one random 256-bit Wallet Key Encryption Key (`WKEK`). WKEK
encrypts the wallet's root seed/private key with ChaCha20-Poly1305. If
hierarchical derivation is enabled, this is the one root from which registered
child keys are derived.

Each passkey independently wraps the same WKEK:

```text
WalletCredentialRecord {
  credential_id
  public_key
  rp_id
  user_handle
  prf_salt
  wrapped_wkek
  wrapped_wkek_nonce
  created_at
  state
}
```

For credential `C`, Browser evaluates WebAuthn PRF using `C.prf_salt` and HPKE
encrypts the output to Signer. Signer derives:

```text
credential_wrap_key =
  HKDF-SHA256(
    prf_output,
    salt = SHA-256(JCS({wallet_id, credential_id})),
    info = "bloom-passkey-wallet-wrap/v1"
  )
```

It wraps WKEK with ChaCha20-Poly1305 using a random nonce and JCS AAD
containing exactly:

```text
{wallet_id, credential_id, root_ciphertext_fingerprint, wrap_format_version}
```

Every field in that AAD is immutable for the life of the wrap.
`wrap_format_version` is the version of this wrapping construction, not the
wallet policy version. **Canonical wallet policy is deliberately excluded.**
Policy is monotonic (section 19) and every update would otherwise invalidate
the AAD of every existing wrap, requiring a simultaneous re-wrap under fresh
PRF output from every registered credential — impossible for any passkey not
physically present and impossible for the recovery factor without consuming
it. Policy is authenticated by Signer's policy signature and enforced at use
time; it is not, and must not become, an unwrapping precondition.

Changing `wrap_format_version` or re-encrypting the root is a deliberate rekey
that re-wraps every credential and the recovery record in one transaction, and
it fails closed unless every active credential and enabled recovery factor can
be re-wrapped in that transaction.

Every credential has a distinct PRF salt/output/wrap; passkeys do not share PRF
material. Successfully using any active bound credential unwraps the same WKEK
and therefore recovers access to the same wallet root and all registered
derived keys.

Credential public keys, PRF salts, and wrapped WKEKs are Signer-owned durable
state. PRF outputs, credential wrap keys, plaintext WKEK, root seed, and child
private keys are never persisted or returned to Broker/Machine.

#### 13.2.1 One-time v1 passkey conversion

An administrator may stage the bounded v1 passkey envelope into a
Signer-owned pending-import location. Staging validates ownership, regular-file
type, size, the exact `PasskeyEncrypted v1` shape, the `localhost` ES256
credential, and a canonical bundle digest. It emits a public receipt containing
only operation identity, wallet name, address, public fingerprints, format,
bundle digest, policy mode, and their exact terms digest.

Machine may read that public receipt and call the existing
`wallet.import_prepare` method with `ceremony_kind=wallet_import` and
`expected_input_class=legacy_passkey_v1_prf`. No new RPC method is introduced.
Broker renders the exact public migration review. The ceremony uses
`navigator.credentials.get` for the staged credential and HPKE-encrypts its PRF
output to Signer.

Signer verifies the assertion and user verification before consuming the PRF,
decrypts the v1 envelope using its historical BLAKE3/ChaCha20-Poly1305
construction, and checks that the recovered secp256k1 key reproduces both
staged public projections. It then immediately commits ordinary WKEK custody,
the credential wrap, backend enrollment, restrictive current policy, public
projection, operation result, and audit effect through the normal crash-safe
custody commit. Temporary secrets are zeroized. The staged private record is
consumed only after the durable result exists.

The converted wallet has no legacy runtime mode. Exact retries return the
durable result; changed receipts, bundles, operations, assertions, PRFs, or
public identities fail closed. The original user-owned directory is not
silently deleted and is ignored by production Machine.

### 13.3 Initial wallet registration

Initial registration is a custody ceremony, not a Sealed Approval because no
wallet root authority exists yet:

1. Machine calls Broker's `wallet.registration_prepare`, which forwards the
   typed custody prepare to Signer. Machine has no route to Signer.
2. Signer allocates wallet/registration IDs, generates WKEK, the root key/seed,
   and the per-wallet policy-signing key in pending secret memory, and returns
   signed WebAuthn creation options plus its ceremony contribution.
3. Broker returns the ceremony URL/expiry and serves the common UI.
4. Browser performs `navigator.credentials.create` with required UV and PRF.
   If the platform does not return usable PRF output during creation, the same
   session immediately performs `navigator.credentials.get` against the new
   credential. No wallet commits until the new credential has both a verified
   creation attestation and a verified PRF result. Browser HPKE-encrypts the
   PRF output to Signer.
5. Broker verifies and relays; Signer independently verifies credential
   creation, PRF adjacency, origin/RP ID, challenge, and contribution.
6. Signer encrypts the root and the policy-signing key with WKEK, creates the
   first credential-specific WKEK wrap, the canonical wallet policy and its
   signature, public KeyRef(s), and the audit event in one transaction.
7. Signer returns a signed public registration receipt. Machine projects only
   wallet ID, public keys/addresses, credential summary, and terminal status.

Restart before the atomic wallet commit destroys pending WKEK/root material
and fails the attempt. Restart after commit replays the public receipt. A
registration retry never creates two wallets under one operation ID.

### 13.4 Adding, replacing, and removing passkeys

Adding a passkey is authority-changing and uses one Broker ceremony with two
bound WebAuthn phases:

1. an existing active credential completes a **root-authority phase**: a
   user-verified WebAuthn assertion over a challenge that binds the exact
   canonical credential-add terms digest, the wallet ID, the ceremony ID, and
   `ceremony_kind = credential_add`. This is the custody analogue of an exact
   selector — it binds the assertion to the precise authority change being
   made — but it is not a Sealed Approval and carries no `ApprovalLimits`;
2. Browser creates the new credential and obtains its distinct PRF output;
3. Signer verifies both phases, unwraps WKEK through the existing credential,
   creates the new credential-specific WKEK wrap, and commits it atomically.

The new credential is active only after the signed commit receipt. Replacement
adds and verifies the new credential before revoking the old one. Removal
requires the same root-authority phase over exact removal terms and is denied
if it would leave neither an active credential nor an enabled recovery factor. Credential IDs, public keys,
wallet IDs, ceremony IDs, and approval digests are bound through both phases;
one wallet's credential or PRF result cannot be replayed into another wallet.

### 13.5 Unlock and recovery

Normal unlock presents all eligible credential IDs and their PRF salts in
WebAuthn options. Browser returns the selected assertion and encrypted PRF
output. Signer selects exactly that credential record, verifies it, unwraps
WKEK, and unlocks the same wallet root.

Optionally, registration creates a random recovery secret. A recovery-derived
key wraps the same WKEK in a separate recovery record; the secret is delivered
once to Browser encrypted to the single-use HPKE recipient key the Browser
supplied in that custody session, and is never visible to Broker/Machine. The
recovery wrap key is
`HKDF-SHA256(recovery_secret, salt=wallet_id,
info="bloom-recovery-wallet-wrap/v1")`; its AEAD AAD is
`{wallet_id, recovery_record_id, root_ciphertext_fingerprint,
wrap_format_version}`, matching the credential-wrap rule of section 13.2 and
excluding policy version for the same reason. When all
passkeys are unavailable, `wallet_recovery` uses the
recovery factor as its root authentication instead of pretending an existing
WebAuthn assertion is available. The common Broker UI then creates and verifies
a new passkey, and Signer activates it before optionally revoking lost
credentials. Recovery never changes wallet root or derived addresses.

If every passkey is lost and no valid recovery factor exists, the wallet is
unrecoverable by design. Broker, Signer metadata, PRF salts, and WebAuthn public
keys are insufficient to reconstruct WKEK or the root.

### 13.6 Custody ceremony states

```text
PREPARED -> AWAITING_USER -> VERIFYING -> WALLET_COMMITTED
         -> AWAITING_RECOVERY_ACK -> COMPLETED

terminal before commit:
CANCELLED | EXPIRED | FAILED
```

Credential addition/replacement/removal and recovery use:

```text
PREPARED -> APPROVING_ROOT_CHANGE -> CREATING_CREDENTIAL
         -> COMMITTING -> SUCCEEDED

terminal before commit:
CANCELLED | EXPIRED | FAILED
```

The remaining custody kinds — `wallet_import`, `wallet_export`,
`wallet_delete`, `backend_enrollment`, `key_derive`, and `policy_update` — use
the generic machine:

```text
PREPARED -> AWAITING_USER -> VERIFYING -> COMMITTING -> SUCCEEDED

terminal before commit:
CANCELLED | EXPIRED | FAILED
```

Cancellation is accepted only before the atomic commit marker. Status and
result recovery reuse the same operation ID across every kind.

An AWS key enrollment verifies provider metadata and public key and then binds
the resulting KeyRef through a `backend_enrollment` custody ceremony, because
it admits a new key into the wallet rather than authorizing signatures under an
existing one. An existing alias is resolved to an immutable key ARN before the
ceremony. Signing with the newly enrolled key still requires a separate Sealed
Approval.

## 14. Signing flow

```text
Petal -> Machine
  payload-bearing sign request

Machine
  validates guest capability
  attaches trusted package/route provenance
  freezes action and advisory material

Machine -> Broker
  sign(operation_id, operation_digest, approval_id, key_ref,
       crypto_suite, payload, petal_use_claim)

Broker
  authenticates Machine
  loads active Sealed Approval
  validates exact selector or Petal identity/use claim
  checks policy and limits
  atomically reserves operations, signatures, and declared debits
  creates signed short-lived SignRequest attempt

Broker -> Signer
  sign(SignRequest)

Signer
  authenticates Broker
  verifies approval/key/backend/algorithm/digests/counts/expiry/revocation
  deduplicates operation ID and request digest
  reserves parser-free counters
  invokes selected SignerBackend
  normalizes and durably stores result

Signer -> Broker
  normalized signature result + signed receipt

Broker
  commits reservation and terminal result

Broker -> Machine
  signature result + Broker receipt
```

Machine never receives the internal SignRequest. Signer never receives the
approval policy, declared-usage ledger, Petal plan, or arbitrary policy files.

Machine does not select the policy under which its request is judged. There is
no policy reference in the Machine-to-Broker call: Broker evaluates against its
own frozen snapshot of the Signer-signed canonical wallet policy and stamps the
resulting `policy_version`/`policy_digest` into the SignRequest itself. Any
Machine-supplied policy hint would be an attacker-controlled input to the
authorization decision and is rejected as an unknown field.

## 15. Sign request

The canonical Broker-signed request contains:

```text
schema = "bloom.sign-request/1"
attempt_id
operation_id
operation_digest
attempt_digest
audience = "bloom-signer"
issuer_service_id
issuer_boot_epoch
broker_signing_key_id

approval_id
wallet_id
key_ref
crypto_suite

selector_kind
ordered_payload_digests[]
ordered_hashes[]
signature_count
petal_use_claim_digest?
claim_assurance_digest?

policy_version
policy_digest
validation_receipt_digest

issued_at
not_before
expires_at
```

Expiry is at most 30 seconds after issue and no later than the Sealed Approval.
`operation_digest` is stable:

```text
SHA-256(
  "bloom-sign-operation/v1" ||
  JCS({
    operation_id,
    approval_id,
    key_ref,
    crypto_suite,
    ordered_payload_digests,
    ordered_hashes,
    petal_use_claim_digest,
    claim_assurance_digest,
    policy_version,
    policy_digest
  })
)
```

`attempt_digest` covers the complete SignRequest with both `attempt_digest`
and its signature omitted. The Broker signature covers that attempt digest. A
new Broker attempt may change only attempt ID, Broker boot epoch, and attempt
validity.
Signer accepts a replacement attempt for the same
`(operation_id, operation_digest)` only when no backend attempt was durably
accepted. After acceptance it returns status/result for the original operation
and never invokes a backend again. A changed operation digest is always an
operation-ID conflict. This permits expiry recovery and Broker restart without
weakening immutable operation identity.

The optional claim digests let operation identity and receipts commit to what
Broker accounted without sending claim contents or teaching Signer their
meaning.

`crypto_suite` names exactly one suite for this operation. Signer rejects any
request whose suite is not a member of the `allowed_crypto_suites` list frozen
in `SignerApprovalState` at activation.

`validation_receipt_digest` is the SHA-256 of the JCS encoding of the signed
`BrokerValidationReceipt` Broker produced when it authorized this operation:
the approval ID and digest, the operation digest, the evaluated policy version
and digest, the claim and assurance digests, the reservation IDs it took, and
the effective ClaimAssurance. Signer stores the digest with the operation
result so a merged audit view can bind Signer's key use to the exact Broker
decision that authorized it, without Signer ever parsing the receipt. Broker
retains the receipt itself.

For an `ExactSelector`, Signer requires exact equality of ordered payload
digests, ordered hashes, array lengths, and signature count against
`SignerApprovalState`, plus suite membership. For a `PetalSelector`, Signer
cannot evaluate Petal identity, claims, or payload meaning; it verifies
approval ID, KeyRef, suite membership, operation/signature count and rate
backstops, expiry, and replay.

## 16. Operation and batch semantics

Every mutation carries an opaque 256-bit operation ID and immutable stable
operation digest. Transport-attempt digests may change only as specified in
section 15. Reusing an ID with a different stable digest is a security
error. Services persist state before acknowledging:

```text
RECEIVED -> VALIDATED -> RESERVED -> DISPATCHED
         -> DOWNSTREAM_ACCEPTED -> COMMITTED -> SUCCEEDED

terminal alternatives:
DENIED, CANCELLED, FAILED, QUARANTINED
```

Client timeout stops waiting, not execution. After ambiguous dispatch the
caller queries downstream using the same ID. It never creates a new ID to
force a retry.

Revocation and expiry linearize at durable acceptance. Work accepted before
the boundary may finish and is reported as completed after the boundary. Work
not accepted is denied or cancelled. Ambiguous work remains quarantined and
charged.

Batches contain one KeyRef, Sealed Approval, CryptoSuite, and ordered set of
1–32 payloads, subject to the hierarchical size limits of section 18: each
batch child payload decodes to at most 64 KiB, the decoded aggregate across a
batch is at most 512 KiB, and the complete encoded frame still obeys the 1 MiB
maximum. A non-batch payload may decode to 256 KiB. These bounds are
deliberately not independent — 32 children at the single-payload maximum would
exceed the frame limit — and the codec enforces all four.
Broker reserves all applicable claim-based limits in one transaction. Signer
reserves all parser-free counters, computes all signatures, and commits the
complete ordered result before publishing any signature. Parent and
deterministically derived child operation IDs are queryable. Children cannot
be retried or cancelled independently.

For a remote backend without provider deduplication, “at most once” applies to
published/accounted results. If an ambiguous provider call returns no
signature, the operation terminates `AMBIGUOUS_PROVIDER_EFFECT`, publishes no
signature, and remains charged. It is never automatically retried.

SignerBackend's core `sign` method is scalar. Signer derives each
`provider_attempt_id` from the operation digest, Signer boot epoch, and child
index; Broker never supplies it. Signer may invoke the backend for each batch
child, or use an optional `SignerBackendBatch` trait advertised by the
backend. If any scalar/provider call is
ambiguous or fails after another may have succeeded, the complete batch is
quarantined, no child signature is published, and all reserved counts remain
charged. Signer stores computed signatures only inside the unpublished parent
record until the complete batch commits.

## 17. Service APIs

Method names are normative at the responsibility level; exact DTO schemas are
frozen in the protocol package.

### 17.1 Machine to Broker

```text
system.hello
broker.readiness
broker.capabilities

action.validate

sealed_approval.prepare
sealed_approval.status
sealed_approval.list
sealed_approval.limit_state
sealed_approval.revoke
sealed_approval.revoke_all
sealed_approval.renew

signing.sign
signing.sign_batch
operation.status
operation.cancel

policy.read
policy.validate_update
policy.commit_update

wallet.list_public
wallet.get_public
wallet.registration_prepare
wallet.unlock_prepare
wallet.import_prepare
wallet.export_prepare
wallet.delete_prepare

key.list_public
key.get_public
key.derivation_capabilities
key.derive_prepare
key.list_derived
key.enroll_prepare

credential.list_public
credential.add_prepare
credential.replace_prepare
credential.remove_prepare
recovery.prepare

ceremony.status
ceremony.cancel
custody.result
```

All authorization lifecycle methods use the `sealed_approval` protocol family.

Machine has no direct route to Signer, so every custody and public-key surface
it needs is a Broker method. Broker's role on these is narrow and mechanical:
it forwards the typed `custody.prepare` to Signer, returns the resulting
`ceremony_url`/`ceremony_expires_at` and public session state, serves the
ceremony application, relays opaque HPKE ciphertext in both directions, and
projects public status and receipt digests. It never sees custody plaintext,
never originates a custody effect, and never synthesizes a receipt. The
`*_prepare` methods mirror the Signer methods of section 17.2 one-for-one;
`ceremony.status`, `ceremony.cancel`, and `custody.result` are shared across
every `ceremony_kind`, including `sealed_approval`.

`key.derive_prepare` is a prepare, not a direct derivation, because deriving a
child is authority-extending under section 8.6. It completes without a ceremony
only when wallet policy explicitly permits it for that namespace and the
policy's ceremony-free child budget is not exhausted.

### 17.2 Broker to Signer

```text
system.hello
signer.readiness
signer.capabilities

key.get_public
key.list_public
key.derivation_capabilities
key.derive_prepare
key.list_derived
key.enroll_prepare
key.enroll_status

ceremony.prepare
ceremony.complete
ceremony.status
ceremony.cancel

sealed_approval.status
sealed_approval.revoke
sealed_approval.revoke_all
revocation.state

signer.sign
signer.sign_batch
operation.status

policy.read
policy.compare_and_swap

wallet.registration_prepare
wallet.registration_status
wallet.unlock_prepare
wallet.import_prepare
wallet.export_prepare
wallet.delete_prepare
credential.list_public
credential.add_prepare
credential.remove_prepare
credential.replace_prepare
recovery.prepare
custody.complete
custody.result
custody.status
```

Signer methods never accept declared-usage budgets, Petal claims, or Petal
policy objects.
Every `*_prepare` custody method is shorthand for a typed `custody.prepare`
request and returns the signed session contribution defined in section 13.
`custody.complete` accepts only the opaque HPKE envelope and public binding
metadata; `custody.result` returns public status plus optional ciphertext
encrypted to Browser.

### 17.3 Revocation control

Broker and Signer expose independent same-login, revocation-only control
endpoints:

```text
control.revoke
control.revoke_all
control.status
```

`bloom wallet panic-revoke` fans out to both concurrently. Either durable
tombstone prevents new signing at that layer. Tombstones reconcile
monotonically when the other service recovers. Control endpoints cannot create
approvals, sign, unlock, export, or mutate credentials.

Each per-approval tombstone is:

```text
ApprovalTombstone {
  approval_id
  wallet_id
  wallet_revocation_epoch
  reason
  operation_id
  revoked_at
  issuer_service_id
  signature
}
```

Each service also stores a monotonically increasing `wallet_revocation_epoch`.
`revoke_all` atomically increments its local epoch and writes a signed wallet
tombstone. Reconciliation takes the maximum valid epoch plus the union of
per-approval tombstones. Prepared or active approvals carrying an older epoch
are denied. Creating an approval at the new epoch requires both services to
have reconciled and a fresh ceremony; backup restore can never decrease the
epoch. Concurrent renewal below a newly accepted epoch fails.

Reconciliation needs a defined mechanism, because the control endpoints are
deliberately independent and Signer has no channel to call Broker. Broker is
therefore the active party and Signer's state is readable through
`revocation.state`, which returns the signed tuple:

```text
RevocationState {
  wallet_id
  wallet_revocation_epoch
  wallet_tombstone?
  approval_tombstone_digest
  approval_tombstone_count
  observed_at
  issuer_service_id
  signature
}
```

Broker calls it at startup, before every `sealed_approval.prepare`, before
marking any approval `ACTIVE`, and whenever a Signer response reports an epoch
mismatch. If Signer's epoch exceeds its own, Broker adopts the higher epoch,
fetches and stores the tombstone union, denies every approval below it, and
audits the adoption; the adoption is monotonic and never reversible. If
Broker's epoch is higher, it pushes `sealed_approval.revoke_all` to Signer
until Signer reports the matching epoch. Until both agree, Broker denies new
prepares with `REVOCATION_EPOCH_UNRECONCILED` rather than proceeding under the
lower epoch. Panic-revoke reaching only one service is therefore always
converged by the next Broker reconciliation pass, in either direction.

Signer revocation rejects new SignRequests, cancels work not durably accepted
by a backend, destroys approval-scoped durable local wrapping, zeroizes
approval-scoped decrypted material, and retains only tombstone, counters,
receipts, and audit evidence.

## 18. Local protocol and authentication

Local service traffic uses bounded length-prefixed canonical JSON:

- four-byte unsigned big-endian length followed by UTF-8 JSON;
- nesting depth 32, string 256 KiB unless a field has a narrower bound, and
  list length 256;
- binary values are unpadded base64url;
- digests are lowercase hexadecimal SHA-256;
- large integers are canonical decimal strings;
- signatures cover RFC 8785 JCS bytes with the signature member omitted.

Size limits are hierarchical and independently enforced, because the outermost
bound alone does not constrain a batch:

| Bound | Maximum |
|---|---|
| encoded frame | 1 MiB |
| single non-batch payload, decoded | 256 KiB |
| one batch child payload, decoded | 64 KiB |
| all batch children, decoded aggregate | 512 KiB |
| batch children | 32 |
| HPKE envelope (PRF or custody) | 4 KiB |
| KeyRef locator | 2 KiB |

A request violating any one of these fails closed before parsing continues, and
the codec conformance suite asserts each bound separately. Thirty-two children
at the per-child maximum exceed the aggregate bound and are rejected on that
bound, not incidentally on the frame bound.

Every envelope binds:

```text
protocol and schema version
kind and method
operation_id and request_digest
caller service ID and boot epoch
audience
sent_at and deadline
body
application key ID and signature
```

Connections begin with a mutual challenge/response `system.hello`. OS peer
credentials and installer-pinned application keys must both match a
root/admin-owned edge manifest. Unknown required fields, methods, schemas, or
weaker security semantics fail closed.

Endpoint ACL:

| Endpoint | May connect | Must not connect |
|---|---|---|
| Machine | CLI and approved local clients | Petals directly |
| Broker | Machine | Petals and arbitrary local clients |
| Signer | Broker | Machine, Petals, CLI, arbitrary clients |
| Broker control | Same-login revoke client | Signing or approval creation |
| Signer control | Same-login revoke client | Signing, activation, or custody mutation |

Quotas are not deferred to the remote case. Every server applies per-caller
bounds locally: maximum concurrent in-flight operations, a request rate
ceiling, a bounded operation-journal admission rate, and the ceremony bounds of
section 12.5. A compromised Machine is an authenticated peer, so peer
authentication is not a defense against resource exhaustion or approval
fatigue; exceeding a bound returns a distinct retryable error and is audited,
and read/status methods stay available while a mutation quota is exhausted.

Remote transport is deferred. It requires TLS 1.3 mutual authentication,
pinned service identities, enrollment/rotation/revocation, audience binding,
replay protection, quotas, and no insecure fallback.

### 18.1 Error taxonomy

Errors are a closed, versioned set frozen in W1 alongside the DTOs. Every error
carries a stable code, a retryability class, and whether any durable effect may
have occurred. Callers branch on the code, never on message text. Unknown codes
from a peer are treated as non-retryable and fail closed.

| Code | Class | Durable effect |
|---|---|---|
| `UNAUTHENTICATED_PEER` | fatal | none |
| `UNSUPPORTED_VERSION` | fatal | none |
| `MALFORMED_FRAME` | fatal | none |
| `LIMIT_EXCEEDED_FRAME` | fatal | none |
| `UNKNOWN_FIELD` / `UNKNOWN_METHOD` | fatal | none |
| `OPERATION_ID_CONFLICT` | fatal | prior operation stands |
| `APPROVAL_NOT_FOUND` / `APPROVAL_EXPIRED` / `APPROVAL_REVOKED` | denied | none |
| `APPROVAL_REARM_REQUIRED` | denied, user-actionable | none |
| `REVOCATION_EPOCH_UNRECONCILED` | retryable after reconciliation | none |
| `SELECTOR_MISMATCH` / `SUITE_NOT_ALLOWED` / `KEYREF_MISMATCH` | denied | none |
| `LIMIT_EXCEEDED_OPERATIONS` / `_SIGNATURES` / `_VALUE` / `_RATE` | denied | reservation released |
| `SIGNER_RATE_BACKSTOP_DENIED` | denied | reservation released |
| `CLAIM_INVALID` / `ASSURANCE_UNAVAILABLE` | denied | none |
| `PROVENANCE_MISMATCH` | denied | none |
| `POLICY_BASELINE_STALE` | retryable after reread | none |
| `CEREMONY_RATE_LIMITED` | retryable after backoff | none |
| `CEREMONY_REPLAY` / `CEREMONY_KIND_MISMATCH` | fatal, security-audited | none |
| `QUOTA_EXCEEDED` | retryable after backoff | none |
| `CLOCK_UNTRUSTED` / `CLOCK_ROLLBACK` | denied until repaired | none |
| `BACKEND_UNSUPPORTED` / `BACKEND_INVALID_REQUEST` | fatal | none |
| `AMBIGUOUS_PROVIDER_EFFECT` | terminal, never auto-retried | possible provider effect; limits stay charged; operation is `QUARANTINED` |
| `SERVICE_UNAVAILABLE` | retryable with same operation ID | unknown; resolve by status query |

`AMBIGUOUS_PROVIDER_EFFECT` is the only error that maps to the `QUARANTINED`
terminal state of section 16; every other denial resolves to `DENIED`,
`CANCELLED`, or `FAILED`.

## 19. Persistence and ownership

| Owner | Durable contents |
|---|---|
| Machine | VFS/outbox, full sealed actions, Petal catalog/cache, execution journal, projections, Machine audit |
| Broker | canonical Sealed Approvals, operation journal, Petal claim/assurance receipts, policy snapshots, spend ledger, ceremony public state, Broker audit |
| Signer | backend registry, public key metadata, local sealed keys and credentials, canonical wallet policy, SignerApprovalState, parser-free counters, operation results, revocation tombstones, custody audit |

Backend-specific durable state remains under Signer ownership. AWS private keys
remain in AWS KMS; Signer stores the pinned reference and public metadata.

No service opens a sibling state root. Each root has one process lock and one
transactional store. Cross-service consistency uses signed receipts and
operation IDs, not shared filesystem locks.

Canonical wallet policy bytes, signature, and monotonic version are written by
Signer. Broker independently verifies and evaluates those bytes. Machine owns
only workflow projections. Policy replacement is compare-and-swap on wallet,
baseline version, and baseline digest.

A policy update is a `policy_update` custody ceremony, not a Sealed Approval.
It changes what future approvals may authorize rather than authorizing a
signature, so it has no `ApprovalLimits` and consumes no operation or signature
capacity. Its ceremony terms bind exactly:

```text
wallet_id
baseline version and digest
complete proposed canonical policy digest
authority-diff digest
assurance level
```

The policy signature itself is produced by a dedicated, per-wallet
**policy-signing key** held by Signer. That key is not a wallet key, controls
no funds, is never enrolled as a `KeyRef`, and is unreachable through
`signer.sign` or `signer.sign_batch` — it exists only so Broker can verify that
the policy bytes it evaluates were installed by Signer under a completed
ceremony. This is the section 4.1 carve-out: it keeps `policy.compare_and_swap`
a single atomic sign-and-install, and it keeps wallet keys strictly
non-self-authorizing, since a wallet key would otherwise have to sign under
Signer's own authority with no Broker SignRequest. The policy-signing key is
created during wallet registration, wrapped under WKEK alongside the root, and
rotated only by a `policy_update` ceremony that re-signs the current policy.

Broker parses the complete proposed bytes, verifies the current
Signer-authenticated baseline, constructs the exact review, and completes the
ceremony. `policy.compare_and_swap` carries the proposed bytes, the ceremony
receipt, and Broker's validation receipt. Signer verifies the ceremony receipt
and the exact proposed/baseline digests, signs with the policy-signing key, and
atomically installs version `baseline + 1`, returning a commit receipt. Broker
rereads the committed bytes from Signer, verifies the Signer signature, freezes
its new policy snapshot, and only then reports success to Machine. Stale
baseline, crash, or receipt mismatch fails closed and reconciles by the same
operation ID. A compromised Broker cannot persist a policy mutation without an
exact ceremony-bound Signer verification.

### 19.1 Signer backup set

Signer durable state is not uniformly reconstructible, so the backup set is
normative rather than an operational detail. It contains the encrypted root,
every `WalletCredentialRecord`, the recovery record, the derivation registry
of section 8.6, the backend enrollment records and pinned public keys, the
canonical wallet policy with its signature and version, the wrapped
policy-signing key, revocation tombstones, and the `wallet_revocation_epoch`.
Counters, operation results, and the audit journal are backed up for
continuity but are never restored in a way that decreases a counter or an
epoch. Restore is monotonic: any restore that would lower an epoch or a
parser-free counter is refused, and the condition is reported rather than
silently reconciled.

## 20. Audit

Each service owns a hash-chained, service-signed audit journal:

- Machine: staging, Petal execution, network calls, broadcast, result
  projection;
- Broker: ceremony decisions, policy decisions, Sealed Approval lifecycle,
  reservations, limit evaluation, authorization results;
- Signer: activation proof, key/backend use, normalized result, provider
  correlation, policy commit, recovery, import/export, deletion.

Security mutations append the local effect and audit record atomically or fail
closed. Status and read-only methods remain available during audit
degradation. Events share operation and correlation IDs and upstream/downstream
receipt digests. A merged view verifies service chains instead of asserting one
process's narrative as universal truth.

After every cross-service security mutation, each recipient stores the peer's
signed journal head `(service_id, sequence, head_hash, key_id, signature)` with
the receipt. Services also periodically exchange heads and write them to an
OS-protected append-only checkpoint location selected by packaging. Key
rotation cross-signs the final old-key head and first new-key head. Restore
must not roll a checkpoint sequence backward.

Hash chains detect internal mutation and non-tail deletion. Peer/OS checkpoints
detect truncation only through the latest independently stored head. A fully
compromised service can rewrite an uncheckpointed tail; the spec makes no
stronger claim.

## 21. Failure, restart, and revocation

### Machine restart

- Durable staged actions and execution results remain.
- Broker does not accept replay under a new operation ID.
- Same-ID result recovery remains available.

### Broker restart

- Durable Sealed Approvals and ledgers reload.
- Nonterminal operations reconcile against Signer receipts before new budget
  is released.
- Ceremony sessions that lack a completed Signer activation proof expire.
- Canonically active approvals whose boot-bound Signer state is `INACTIVE`
  remain visible but unusable and return `APPROVAL_REARM_REQUIRED`; a fresh
  ceremony for the identical immutable terms re-arms them without creating a
  second approval ID.

### Signer restart

- Backend-independent terminal results, counters, and tombstones reload.
- Boot-bound LocalSignerBackend activations become unavailable.
- Durable local activation re-arms only when approved and the platform
  provider permits it.
- AWS KMS key availability depends on pinned credentials, key state, network,
  and policy, not local decrypted-key memory.
- Nonterminal backend calls reconcile or remain quarantined.

### Partitions

- Machine may continue reads, staging, and simulation.
- Broker and Signer fail signing closed.
- No embedded fallback is permitted.
- Status distinguishes unavailable, incompatible, rearm-required,
  approval-required, exhausted, revoked, rate-limited, and ambiguous. There is
  no "locked" status: no public lock operation exists, and interactive
  re-arming is reported as `APPROVAL_REARM_REQUIRED`.

Revocation requires no ceremony. Revoking through either Broker or Signer
prevents new signing at that layer. Renewal always creates a new approval and
cannot remove a tombstone for an old approval ID.

Cancellation is accepted only before durable downstream/backend acceptance.
Before Broker dispatch it cancels and releases reservations. After dispatch,
Broker records cancellation intent and queries Signer; it may not report
`CANCELLED` unless Signer proves no backend acceptance. After acceptance the
operation completes, fails, or becomes quarantined. Signer therefore needs no
unsafe best-effort backend cancellation RPC.

## 22. Service activation and packaging

Normal production uses OS-managed per-login product services with demand or
socket activation. The CLI never forks security services in production.

Where the platform supports it, the activation manager owns and pre-binds the
ceremony listener on `127.0.0.1:18734` and hands the bound socket to Broker.
This is a security requirement, not an optimization: demand activation means
the security services start late, which is exactly the window in which another
local process could claim the canonical origin. Where handover is unavailable,
Broker binds exclusively without address reuse and treats a conflict as a fatal
startup error. Packaging must demonstrate, per platform, that no unprivileged
process can pre-empt or take over the listener; failure of that negative test
is an E-05 go/no-go failure for that platform, exactly like the state-isolation
tests.

Authenticated Unix endpoints are different: on Linux the service principal
must create its own listener after activation so `SO_PEERCRED` identifies that
principal in both directions. A root-created systemd Unix listener reports the
launch manager as the peer to a connecting client and therefore cannot satisfy
the UID-plus-application-key authentication rule. Packaging may use a separate
path or demand trigger, but it must not pass a root-created authenticated Unix
listener to Broker or Signer.

Distinct effective principals or mandatory sandbox identities must prevent a
compromised Machine from:

- reading Broker or Signer roots;
- opening the privileged Signer endpoint;
- reading AWS credentials or local platform-secret storage;
- ptracing or inspecting Broker/Signer memory;
- replacing signed binaries, assets, edge manifests, or backend crates;
- binding, pre-empting, or proxying the canonical ceremony listener.

Signer has no network by default. Enabling a networked backend grants only the
documented egress needed for that backend. An unrestricted networked Signer is
nonconforming.

An unsandboxed same-UID installation cannot claim Machine-compromise
containment. macOS and Linux packaging experiments remain a release gate.

Production builds contain no embedded Machine/Broker/Signer fallback and no
debug approval verifier.

## 23. Petal trust and compatibility

Petal guests call Machine only. Machine supplies trusted package and route
provenance to Broker. Broker verifies it against an installer-signed,
content-addressed catalog record.

Signing uses a versioned payload-bearing guest API:

```text
wallet
final preimage bytes
claimed hash
signature algorithm
operation class
PetalUseClaim
optional ClaimAssurance evidence
```

For an `ExactSelector`, the preimage is required so live review can bind exact
bytes. For a `PetalSelector`, the Petal supplies the payload commitment, hash,
operation class, and usage claim without requiring Broker to decode the
preimage. Machine translates the guest call into the richer Broker protocol;
guests never receive Broker or Signer credentials.

The pre-triad `sign` v0.1 guest interface is hash-only: it carries a wallet, a
32-byte hash, and an intent, with no preimage and no usage claim. It therefore
cannot satisfy exact review or produce a `PetalUseClaim`, and it is not
forward-compatible. **Every v0.1 signing call fails closed** with
`UNSUPPORTED_VERSION` on a triad build; there is no shim that fabricates a
preimage, synthesizes a claim, or downgrades an approval to accept a bare hash.
Non-signing v0.1 routes remain compatible. Installed first-party Petals that
sign — Polymarket in particular — must move to the payload-bearing interface as
part of W7, and the release gate treats a hash-only signing path present in a
production artifact the same way it treats an embedded signer.

Reusable approval is available to any installed Petal whose package/route,
operation class, and CryptoSuite match the approval and whose catalog record
matches the approval's `provenance_digest`. New Petals do not require Broker
adapter work or an amendment to this architecture.

The baseline trust root is the installer-pinned package hash plus the
authenticated Machine assertion that the request came from that Petal route.
This provides provenance in the honest runtime, not isolation from a fully
compromised Machine. Future proof systems, invariant attestations, reproducible
build evidence, and scoring may strengthen policy decisions without changing
the selector or signing protocol.

Authority-changing operations such as policy changes, credential changes,
backend enrollment, broad approval, or onboarding use exact live review unless
wallet policy explicitly permits a Petal-scoped form with a displayed
assurance level.

## 24. Broker debug driver

The Broker workspace contains a sibling test crate:

```text
bloom-broker-debug-driver
```

Its purpose is to drive the production ceremony HTTP and protocol surfaces in
integration and end-to-end tests using a software credential or virtual
authenticator.

Required properties:

- `publish = false`;
- dependency direction is driver to public Broker interfaces;
- Broker never depends on the driver;
- it is a dev-dependency or separate test executable, not a production
  feature;
- it creates genuine WebAuthn assertions and deterministic test PRF output;
- it never calls an internal “mint approval” or accepting-verifier hook;
- it drives the same Broker-to-Signer activation and signing paths as
  production;
- release CI proves it and its test keys/verifiers are absent from production
  dependency graphs, symbols, method inventories, and artifacts.

Unit tests may still use direct mocks. End-to-end conformance tests must use the
driver. A browser/virtual-authenticator lane additionally exercises embedded
JavaScript and browser WebAuthn behavior.

The driver covers:

- correct ceremony and signing;
- altered plan, payload, hash, KeyRef, or approval terms;
- wrong Host, Origin, CSRF token, Fetch Metadata, challenge, credential, or
  verification flags;
- replay, expiry, restart, cancellation, and revocation;
- encrypted PRF binding and wrong Signer ephemeral key;
- exact and Petal selectors at each ClaimAssurance level;
- budget races and ambiguous Signer/backend responses;
- multi-suite approvals, including a suite outside `allowed_crypto_suites`;
- fee-line exhaustion and a claim omitting `declared_fee`;
- every `ceremony_kind`, including a kind/effect mismatch;
- revocation-epoch divergence and convergence in both directions;
- ceremony-creation rate limits under a hostile prepare loop.

## 25. Release and repository policy

Each executable and backend crate has its own semantic version. Adjacent
services require an exact protocol major and advertise supported minor
versions, methods, schemas, backends, algorithms, and limits. Security
semantics never downgrade silently.

Installer bundles are tested as current/current and every supported adjacent
version combination. Status output includes service versions, build digests,
protocols, backend capabilities, and KeyRef metadata without secrets.

Repository extraction occurs only after:

1. protocol schemas and canonicalization vectors are frozen;
2. backend API and normalized signature vectors are frozen;
3. fake-peer, replay, restart, and fault-injection suites pass;
4. local and AWS KMS integration suites pass;
5. adjacent-version bundle tests pass;
6. the installer reproducibly provisions principals, ACLs, sockets, assets,
   backend credentials, sandbox profiles, upgrade, rotation, and uninstall.

## 26. Implementation sequence

| Package | Scope | Completion evidence |
|---|---|---|
| W0 packaging | Principals, sockets, ACLs, sandboxing, demand activation, ceremony-listener handover, trusted time source, audit checkpoint location, backend egress and platform-secret tiers | macOS/Linux negative-access, listener pre-emption, and activation suite |
| W1 contracts | Role traits, DTOs, KeyRef, `allowed_crypto_suites`, SignerBackend API, canonical codec, hierarchical size bounds, closed error taxonomy, golden vectors | protocol/backend conformance tests |
| W2 journals | Unified Sealed Approval lifecycle, operation journal, ledgers, audit chains, fault hooks | crash/replay matrix |
| W3 Signer seam | backend registry, local backend, WKEK/policy-signing key, BIP32 derivation registry and backup set, structural SignRequest validation, policy CAS, `revocation.state`, custody APIs | Machine/Broker dependency graphs contain no key-bearing types; derivation and wrap-AAD vectors pass |
| W4 Broker seam | Sealed Approval, policy snapshot evaluation, PetalUseClaims, fee accounting, assurance verifier registry, budgets, quotas, epoch reconciliation, ceremony application | selector, claim, fee, and budget vectors |
| W5 ceremony | Broker HTTP/assets, prepare projection, Signer contribution and independent verification, encrypted PRF forwarding, multi-passkey registration/recovery UI | origin, projection, proof, replay, PRF, credential, recovery, and restart suite |
| W6 AWS backend | KMS enrollment, KeyRef pinning, normalized signatures, egress/IAM, ambiguous-call handling | provider integration and fault tests |
| W7 Machine integration | projections, Broker custody/key/credential client surface, payload-bearing Petal ABI with v0.1 fail-closed, provenance, execution separation | all VFS/CLI signing and custody routes through Broker; no hash-only signing path remains |
| W8 process extraction | three binaries and service clients | process/ACL/negative-connector suite |
| W9 release | compatibility matrix, installer, debug-driver exclusion, repository gate | reproducible signed bundle |

Dependencies:

```text
W0 packaging ─────────────────────────────────────────────────┐
                                                              v
W1 contracts ──> W2 journals ──> W3 Signer seam ──> W4 Broker seam
     |               |                |                  |
     |               |                +──> W5 ceremony <─+
     |               |                          |
     |               |                          v
     +───────────────+──────────────────> W7 Machine integration
                                                 |
                     W6 AWS backend ─────────────+
                                                 v
                                        W8 process extraction
                                                 |
                                                 v
                                             W9 release
```

W0 is a go/no-go conformance spike and runs in parallel with W1–W2; its failure
on a platform blocks the release claim for that platform rather than the work.
W6 depends only on W1 and W3 and can proceed alongside W4/W5. W8 is the only
intentionally non-independent package: extraction cannot demonstrate a real
boundary without two completed endpoints, and its risk is contained by keeping
all domain logic mergeable and tested behind the W1 traits first.

Acceptance-test ownership:

| Package | Acceptance tests |
|---|---|
| W0 | AC-01, AC-02, AC-04, AC-31 |
| W1 | AC-05, AC-19, AC-21, AC-33, AC-34 |
| W2 | AC-06, AC-07, AC-10, AC-12 |
| W3 | AC-03, AC-11, AC-15, AC-25, AC-27, AC-28, AC-32 |
| W4 | AC-08, AC-09, AC-10, AC-22, AC-29, AC-30 |
| W5 | AC-13, AC-14, AC-23, AC-26, AC-27, AC-31 |
| W6 | AC-16 |
| W7 | AC-24, AC-26, AC-35 |
| W8 | AC-01, AC-02, AC-04, AC-17 |
| W9 | AC-18, AC-19, AC-20, and a full rerun of AC-01–AC-35 on the bundle |

## 27. Acceptance tests

The first production release is accepted only when automated tests prove the
following. Identifiers are stable and are referenced by the work-package
ownership table in section 26.

- **AC-01** Three distinct production binaries and effective principals run.
- **AC-02** Machine cannot read Broker/Signer state or connect to Signer.
- **AC-03** Broker cannot read Signer state, local keys, AWS credentials, or
  plaintext PRF in the honest ceremony flow.
- **AC-04** Production artifacts contain no embedded signer, accepting
  verifier, debug driver, or direct Machine-to-Signer route.
- **AC-05** Wrong principal, app key, boot epoch, audience, signature, frame
  size, schema, backend, KeyRef, or algorithm fails closed.
- **AC-06** Same-operation retry permits only the attempt-envelope changes in
  section 15, returns one stable published result after acceptance, and rejects
  a conflicting stable operation digest.
- **AC-07** Crashes at every durable transition recover without unaccounted
  published signing.
- **AC-08** Exact selectors reject every changed payload, digest, order, count,
  or algorithm.
- **AC-09** Petal selectors reject the wrong package, route, operation class,
  CryptoSuite, assurance level, claim nonce, `provenance_digest`, or approval
  limits. Tests explicitly demonstrate that `machine_asserted` claims are
  trusted rather than Broker-derived, while proof/attestation modes reject
  altered claims outside their verifier contract. The rendered ceremony for a
  `machine_asserted` reusable approval is asserted to carry the section 1.1
  disclosure in its primary approval surface, and a build with no compiled
  verifiers is asserted to advertise an empty verifier set and to fail closed
  rather than degrade when policy requires one.
- **AC-10** Concurrent reservations cannot overspend operation, signature,
  rolling, lifetime, asset, or fee limits. In the Linux authenticated-time
  profile, clock rollback freezes effective time; a forward jump beyond
  `max_forward_step` is not adopted and does not expire live approvals or burn
  rolling windows; an untrusted time source denies new rate-limited signing.
  The macOS profile follows the administratively controlled host wall clock.
  A Signer rate-backstop denial after a
  Broker reservation releases that reservation in full and is never reported
  as spend.
- **AC-11** Signer rejects forged, expired, replayed, excessive, wrong-key,
  revoked, or unsupported SignRequests without trusting Broker policy parsing.
- **AC-12** Batch results are atomically published and parent/children are
  queryable.
- **AC-13** Broker ceremony tests cover assets, headers, origin, challenge,
  plan, WebAuthn, replay, encrypted PRF, restart, and accepted browser
  residuals. Ceremony creation bounds, per-wallet single-live-session, and
  cancellation backoff hold against a hostile Machine that spams prepares, and
  read/status methods stay available while a mutation quota is exhausted.
- **AC-14** Registration, import, encrypted export, recovery, credential
  add/replace/remove, backend enrollment, deletion, and policy update never
  expose secrets to Machine or Broker. Every one of them is asserted to run as
  a custody ceremony that creates no Sealed Approval and consumes no operation
  or signature capacity, and a `ceremony_kind` mismatch between request and
  durable effect is rejected as a security error.
- **AC-15** Local backend zeroization and restart behavior match approved
  activation.
- **AC-16** AWS backend pins immutable ARN/public key, normalizes signatures,
  restricts IAM/egress, and quarantines ambiguous provider calls.
- **AC-17** Either Broker or Signer revocation tombstone stops new signing and
  later reconciliation is monotonic.
- **AC-18** Audit mutation, non-tail deletion, reordering, or signing-key
  mismatch is detected; truncation through the latest independent peer/OS
  checkpoint is detected; mutations fail closed on forced audit-write failure.
- **AC-19** Unsupported version combinations refuse without downgrade.
- **AC-20** Debug-driver and test-credential scans pass on every production
  artifact.
- **AC-21** Golden vectors prove non-circular approval digest construction and
  reject changes to subject, KeyRef, `allowed_crypto_suites`, selector, limits,
  activation mode, revocation epoch, policy, provenance, `request_nonce`, or
  validity. Approving identical terms twice produces distinct `approval_id`s.
- **AC-22** `revoke_all`, concurrent renewal, stale backup restore, and partial
  reconciliation never decrease a wallet revocation epoch or reactivate an old
  approval. With Broker stopped, panic-revoke through Signer's control socket
  alone is asserted to converge on the next Broker `revocation.state` pass, and
  the reverse case converges by push; until both agree, new prepares are denied
  with `REVOCATION_EPOCH_UNRECONCILED`.
- **AC-23** Custody HPKE vectors and end-to-end tests prove Broker cannot
  decrypt inputs or sensitive results and that replay/wrong-AAD/wrong-session
  fails.
- **AC-24** Policy compare-and-swap fails for any changed baseline, proposed
  bytes, authority diff, ceremony receipt, or version, and the policy-signing
  key is asserted unreachable through `signer.sign` and `signer.sign_batch`.
- **AC-25** Local BIP32 derivation produces golden child public keys, allocates
  paths atomically without reuse, keeps root/child private material confined,
  binds approval to the exact derived KeyRef, and recovers every registered
  child through the same wallet root. Deriving without an explicit policy
  allowance requires a ceremony. AWS KMS reports derivation unsupported.
- **AC-26** `sealed_approval.prepare` and every custody prepare return the
  stable Broker ceremony URL and expiry; the originating VFS projection exposes
  them only while awaiting ceremony and clears them on completion, expiry,
  cancellation, or failure.
- **AC-27** Initial registration atomically creates one root, one policy-signing
  key, and the first passkey wrap; each additional passkey independently wraps
  the same WKEK; every active passkey unlocks the same root/derived keys;
  replacement is add-before-revoke; and loss of all passkeys without recovery is
  unrecoverable.
- **AC-28** A wallet policy update, repeated across several monotonic versions,
  leaves every existing credential wrap and the recovery wrap unwrappable —
  proving policy version is absent from wrap AAD. A deliberate
  `wrap_format_version` rekey re-wraps every active credential and enabled
  recovery factor in one transaction and fails closed if any cannot be
  re-wrapped.
- **AC-29** An approval with a token value line but no native-asset line denies
  every fee-bearing operation; fees debit the native line exactly as other
  debits; a claim omitting `declared_fee` for a fee-bearing operation class is
  rejected; and fee exhaustion is reported distinctly from value exhaustion.
- **AC-30** An approval naming several CryptoSuites permits each member in the
  same flow without a further ceremony, rejects any suite outside the list at
  both Broker and Signer, displays all members in the ceremony, and binds the
  full ordered list into the approval digest and activation receipt.
- **AC-31** Broker refuses to serve ceremonies when it does not own
  `127.0.0.1:18734`: a pre-bound foreign listener produces a fatal, reported
  startup failure and never a fallback port; where the platform supports
  handover, the activation manager owns the socket; and no unprivileged process
  can pre-empt or take over the listener.
- **AC-32** The derivation registry round-trips through the Signer backup set;
  restoring a root without its registry marks the wallet
  `DERIVATION_REGISTRY_MISSING` and refuses new derivation; and no restore can
  lower an epoch or a parser-free counter.
- **AC-33** Each hierarchical size bound in section 18 is enforced
  independently: a 32-child batch at the per-child maximum is rejected on the
  aggregate bound, not merely on the frame bound.
- **AC-34** The error set is closed: every failure path returns a code from
  section 18.1 with the specified retryability and durable-effect class, and an
  unknown peer code is treated as non-retryable and fails closed.
- **AC-35** A v0.1 hash-only guest signing call fails closed with
  `UNSUPPORTED_VERSION` on every route, no shim synthesizes a preimage or a
  claim, and release scans prove no hash-only signing path exists in a
  production artifact.
- **AC-36** The one-time v1 passkey-wallet conversion accepts only a staged,
  digest-bound legacy bundle; requires a valid assertion from that bundle's
  existing passkey and a matching PRF result encrypted end-to-end to Signer;
  rejects a changed bundle, credential, PRF result, public key, or address;
  commits the root only through current WKEK custody; and leaves no callable
  legacy decrypt or signing backend in Machine, Broker, or Signer's normal
  runtime surface.

## 28. Fixed decisions

| Decision | Status | Choice |
|---|---|---|
| D-040 | Ratified | Rename the roles and executables to Machine, Broker, and Signer. |
| D-041 | Ratified | Broker owns ceremony HTTP, assets, rendering, and orchestration. Signer independently verifies its nonce, WebAuthn proof, exact approval digest, KeyRef, `allowed_crypto_suites`, activation mode, revocation epoch, and limits. Local PRF is HPKE-encrypted end-to-end to Signer and only forwarded by Broker. |
| D-042 | Ratified | Signer is extended through reviewed compile-time `SignerBackend` crates/features, initially Local and AWS KMS. Runtime backend plugins are prohibited. |
| D-043 | Ratified | Key identity is the structured backend-qualified `KeyRef`; AWS uses immutable key ARN without a duplicated region field. |
| D-044 | Ratified; amended by D-051 | Broker enforces approval policy and limits against canonical PetalUseClaims but does not decode protocol calldata or independently extract application meaning. Signer retains structural approval, exact-hash, key, CryptoSuite, operation/signature count and rate, expiry, replay, and revocation enforcement. |
| D-045 | Ratified | `bloom-broker-debug-driver` drives genuine production ceremony interfaces in tests and is absent from production dependency graphs and artifacts. |
| D-046 | Ratified; amended by D-055 | Sealed Approval is the only **signing**-authorization concept. Exact single-use and reusable bounded behavior are selectors and limits within one canonical structure and lifecycle. |
| D-047 | Ratified | Canonical Sealed Approvals are durable. Backend key availability and activation persistence are independent, backend-specific state. |
| D-048 | Ratified | `approval_id` is the domain-separated digest of immutable `SealedApprovalTerms`; lifecycle state and receipts cannot change what was approved. |
| D-049 | Ratified | Stable operation identity is separate from expiring signed attempt envelopes; accepted provider ambiguity never triggers automatic re-signing. |
| D-050 | Ratified | Per-approval tombstones and monotonic wallet revocation epochs define revoke-all, restore, renewal, and reconciliation ordering. |
| D-051 | Ratified | Reusable approval binds Petal package, route, operation classes, claims, limits, and required ClaimAssurance. No registered payload schema or Broker protocol adapter is required. Baseline `machine_asserted` claims trust the Petal/Machine; proof and invariant verifiers are optional strengthening mechanisms. |
| D-052 | Ratified | LocalSignerBackend supports policy-scoped BIP32 secp256k1 derivation from one encrypted root, issuing a distinct KeyRef per registered child. Derivation is an optional backend capability; AWS KMS initially reports it unsupported. Deriving a child is authority-extending and requires a ceremony unless wallet policy explicitly budgets it. |
| D-053 | Ratified | `sealed_approval.prepare` and every custody prepare return `ceremony_url` and `ceremony_expires_at`; Machine exposes them only in the originating owner-readable VFS status projection while the ceremony awaits completion. |
| D-054 | Ratified | Local wallets encrypt one root with WKEK and let each passkey independently wrap that same WKEK using credential-specific PRF output. Registration, credential changes, and recovery reuse the Broker ceremony framework and Signer HPKE/verification boundary. |
| D-055 | Ratified | Custody workflows are ceremonies, not Sealed Approvals. `CustodySubject` is removed from the subject union. Registration, credential add/replace/remove, recovery, import, export, deletion, backend enrollment, key derivation, and policy update use `CeremonySession` with a closed `ceremony_kind`, share the ceremony framework and HPKE boundary, and carry no `ApprovalLimits`. Authority-changing custody phases bind the exact canonical terms digest, which is the custody analogue of an exact selector. |
| D-056 | Ratified | Signer signs canonical wallet policy with a dedicated per-wallet policy-signing key that controls no funds, is never enrolled as a `KeyRef`, and is unreachable through `signer.sign`. Section 4.1's "every signature is bound to a Broker request" is scoped to signatures over Machine- or Petal-originated payloads; wallet keys are never self-authorizing. |
| D-057 | Ratified | `SealedApprovalTerms` carries `allowed_crypto_suites[]` (one to four members) rather than a single suite, so a multi-step Petal flow spanning suites needs one ceremony rather than several. Each claim and SignRequest names exactly one member; Broker and Signer independently enforce membership. |
| D-058 | Ratified | The credential and recovery WKEK wrap AAD binds only wallet ID, credential/record ID, root ciphertext fingerprint, and `wrap_format_version`. Canonical wallet policy version is excluded, because a monotonic policy would otherwise invalidate every wrap on every update. Rekey is a deliberate all-credentials transaction. |
| D-059 | Ratified | `declared_fee` is mandatory and debits a native-asset value line. An approval without a value line for the fee asset denies every fee-bearing operation, so a token budget can never permit unbounded native-token burn. |
| D-060 | Ratified | Broker must own the canonical ceremony listener or refuse to serve ceremonies, acquiring it by activation-manager handover where available. Listener pre-emption is an E-05 negative test and a per-platform go/no-go. Same-RP-ID other-port phishing and compromised browsers/extensions remain accepted, documented residuals. |
| D-061 | Ratified | `revocation.state` is the defined reconciliation channel. Signer never calls Broker; Broker polls at startup, before every prepare, and on epoch mismatch, adopting a higher Signer epoch monotonically and pushing a higher local epoch downward, denying prepares with `REVOCATION_EPOCH_UNRECONCILED` until they agree. |
| D-062 | Ratified | Assurance verifiers are compile-time, feature-gated, digest-pinned crates with written verifier contracts, advertised through `broker.capabilities`. Fields outside a verifier's contract remain `machine_asserted` even under a verified proof. v1 may ship with none, in which case reusable approvals operate at `machine_asserted` with the section 1.1 disclosure. |
| D-063 | Ratified | Payload size bounds are hierarchical and independently enforced (frame, single payload, batch child, batch aggregate, child count, HPKE envelope, locator); the frame bound alone does not constrain a batch. Errors are a closed, versioned set with declared retryability and durable-effect class. |
| D-064 | Ratified | The v0.1 hash-only guest signing interface fails closed on triad builds with no compatibility shim, and its absence from production artifacts is a release scan. Machine supplies no policy reference on the signing call; Broker evaluates its own verified snapshot. Quotas and ceremony-creation bounds apply locally, because an authenticated Machine may still be compromised. |

Earlier decisions remain applicable only where consistent with D-040 through
D-064 and this consolidated normative text. In particular, any earlier decision
requiring a registered semantic adapter before a Petal may hold a reusable or
standing approval is superseded by D-051 as qualified by section 1.1 and D-062:
adapters are an optional strengthening mechanism, not a precondition, and the
resulting v1 posture is `machine_asserted` unless a verifier is compiled in and
required by policy.

## 29. Remaining questions

These do not block the logical architecture but must be resolved before the
corresponding implementation ships:

- Exact macOS and Linux principal, socket-activation, sandbox, and secret-store
  constructions, including ceremony-listener handover.
- The OS-protected append-only audit checkpoint location on each platform, and
  what integrity it actually provides against a compromised service. Section 20
  makes no claim stronger than "truncation is detected through the latest
  independently stored head," and that claim is only as good as this location.
- The pinned time profile per platform and the production Linux value of
  `max_forward_step`; macOS uses its administrator-controlled host wall clock.
- Whether any assurance verifier ships in v1. If none does, every reusable
  approval operates at `machine_asserted` and the section 1.1 disclosure is the
  only mitigation.
- Whether local durable activation is enabled in the first release and which
  platform tiers qualify.
- AWS credential sources, cross-account enrollment, multi-region key policy,
  quotas, CloudTrail retention, and supported failure modes.
- Additional signature algorithms and whether composite xDSA wallets are
  local-backend-only.
- Additional derivation schemes, exact namespace templates per chain, and
  whether public xpub export ships in v1.
- Whether creation of a recovery factor is mandatory at registration and
  which non-passkey recovery factors are supported.
- Remote Broker/Signer placement and enrollment.
- Import/export UI details and supported wallet kinds.
- Exact adjacent-version compatibility window.

None of these questions permits weakening the boundaries silently. Unsupported
combinations fail closed and are reported as unsupported.
