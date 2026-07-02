# Sealed Approval Ceremony

**Status:** definitive target spec  
**Date:** 2026-07-02  
**Audience:** Bloom engineers and future implementation agents  
**Supersedes:** informal "Layer B" auth language  

## 1. Summary

Bloom authorizes value-moving and authority-changing work through the **Sealed
Approval Ceremony**.

The flow is:

```text
stage central action
seal canonical intent
issue challenge
one passkey ceremony returns WebAuthn assertion + PRF output
verify signed approval
mint short-lived Sealed Approval Grant
run the bound Petal from sealed intent bytes
Petal requests signatures with structured attestations
host enforces grant and sealed Petal policy snapshot
record central audit outcome
```

The user-facing term is **Sealed Approval**. Avoid "Layer B" in code,
documentation, and UI.

The central abstraction is an action in `/outbox/pending/<id>`. Venue folders
such as `/requests`, `/wallets`, `/polymarket`, `/hyperliquid`, and `/defi`
are projections and staging ergonomics. They do not own separate approval
systems.

The authorization boundary is not NFS uid/mode bits, filesystem path origin,
or marker-file provenance. The authorization boundary is:

1. a sealed canonical intent;
2. a WebAuthn-signed approval over that intent's challenge;
3. an in-memory, short-lived grant bound to the sealed intent and a specific
   Petal identity.

## 2. Definitions

**Sealed action**  
A canonical intent stored in daemon-controlled state and addressed by
`intent_hash`. It is immutable. Rewriting a venue path creates a new action; it
never mutates an existing sealed action.

**Action Outbox**  
The single central authorization queue exposed at `/outbox/pending/<id>`.
Every user-verified value movement or authority change has a corresponding
action here.

**Petal**  
The component that executes a sealed action. In the future this is a dynamically
loaded WASM module. In the MVP, first-party components such as EVM wallet,
paid HTTP, DeFi, Polymarket, and Hyperliquid are treated as first-party Petals
and must use the same identity/grant model.

**Petal identity**  
The tuple that identifies what code is allowed to consume a grant:

```text
petal_id
petal_digest
petal_version
```

For first-party Rust components, `petal_digest` may initially be a stable build
or source digest recorded by the daemon. It must still be present in sealed
intent and grant records so the model is compatible with dynamically loaded
WASM Petals.

MVP first-party digests may be hardcoded placeholders only while first-party
Petals are still built into the daemon. Placeholder constants must be named and
documented as temporary non-attestation values in code, for example:

```text
first-party-placeholder:evm-wallet:v0
first-party-placeholder:paid-http:v0
```

Every placeholder must carry a TODO stating that it is not a real tamper
evidence boundary and must be replaced by reproducible build/source digests
before untrusted or dynamically loaded Petals can receive signing grants.
Audit/status output must label placeholder digests as placeholders so operators
do not mistake them for code attestation.

**Assurance**  
Approval assurance is one of:

- `standard`: passkey user presence and normal WebAuthn verification.
- `hardened`: passkey user verification is mandatory. The ceremony must require
  UV/PIN/biometric, and verification must reject assertions without UV.

Authority-changing actions, wallet re-key/passkey management, policy edits that
expand authority, and any configured high-value threshold require `hardened`.

Assurance describes the strength of a fresh user approval ceremony. It does not
mean every agent action requires a passkey prompt. Agents may perform actions
without a new passkey ceremony when the daemon can authorize them entirely under
signed policy plus active bounded authority that was previously minted by
Sealed Approval. If an action needs new wallet-key signing authority, lacks an
active session/capability, or exceeds policy/session limits, it must stage a
sealed action and obtain the required approval assurance.

**Autonomy**
Autonomy is not a wallet kind. It is derived authority for a passkey wallet:
signed `policy.toml` defines what may run without a fresh ceremony, and live
session/capability state provides the actual signing or venue authority. A
passkey wallet remains the root authority for policy changes, re-keying, and
minting or expanding autonomous capability.

For example, an x402 request that spends `$0.01` may execute without a fresh
passkey ceremony when all of these are true:

1. signed wallet policy enables autonomy for that surface/action;
2. the action fits global wallet limits and the Petal-specific policy snapshot;
3. the cross-Bloom budget ledger has remaining reserved+spent capacity;
4. the daemon has an active bounded signing/session capability for the wallet;
5. the action does not change authority or expand policy.

Policy alone does not decrypt a passkey wallet after cold start. If no active
owner-signing session, delegated credential, service credential, or other
bounded capability can authorize the action, Bloom must request fresh Sealed
Approval even for a low-value action.

**Signed approval**  
The `approval.json` record written for an action. It contains no secret key
material. It proves that a passkey/WebAuthn ceremony approved the exact sealed
action challenge.

`approval.json` is an audit/projection artifact, not a secret courier. A
mounted client may write it, but grant minting requires a live trusted ceremony
channel carrying the corresponding PRF output to daemon memory. An approval file
that appears without a live PRF-bearing ceremony cannot mint a grant and must
fail closed for actions requiring wallet signatures.

**Sealed Approval Grant**  
An in-memory grant minted by the daemon after verifying `approval.json` and
deriving the wallet key from the WebAuthn PRF output. It is bound to a sealed
action and Petal identity. It is not persisted across restart.

**Petal policy snapshot**  
A daemon-cut, sealed projection of wallet policy and daemon-owned configuration
for one Petal. It is committed into the sealed action and injected into the
Petal at execution time. Petals do not read live `policy.toml` for an already
sealed action.

**Signing attestation**  
A structured Petal claim describing what a generic `sign-hash` request means:
amount, asset, destination, network, action kind, risk class, session use, or
other Petal-specific facts. The daemon validates this attestation against the
sealed Petal policy snapshot before signing. For MVP, Bloom trusts approved
Petals not to lie about the relationship between the attestation and `hash32`.

## 3. Non-Negotiable Decisions

1. **Passkey-only signing.** Local/passphrase wallets are removed. Existing
   local wallets fail closed with a manual developer migration path.
2. **No `write_unlocked`.** Delete privileged unlocked-write IPC behavior.
   There is no alternate signer lane.
3. **No legacy or unwired behavior.** Delete marker formats such as
   `.confirm_approved.json`, `review_approved.json`, policy-session approval
   markers, and all fallback branches that consume them.
4. **One approval record.** Every approval uses `approval.json` with the
   Sealed Approval schema.
5. **One central action outbox.** Anything needing user verification has a
   central `/outbox/pending/<id>` action. Venue directories project to the
   central action.
6. **Petal-scoped grants.** Grants are bound to `intent_hash` and Petal
   identity, not to exact signing digests for the MVP.
7. **No PRF output in files.** PRF output, decrypted keys, and signing grants
   are process-local only and must be zeroized or expired.
8. **Remove out-of-scope signers.** `bloom-chain` and `pipe` signing paths are
   removed or hard-disabled because they sign outside this model.
9. **Challenge binds the sealed intent.** The WebAuthn challenge is the domain
   separated hash of the daemon-issued approval payload, including
   `intent_hash`, `action_id`, `petal_id`, `petal_digest`, `server_nonce`,
   `daemon_terms_digest`, `petal_policy_digest`, `policy_version`, and
   `expiry_ms`.

## 4. Why Passkey Wallets Still Use a Keystore

Removing local wallets does not remove keystore-backed wallets.

Current passkey wallets still store encrypted chain private-key material on
disk:

```text
kind = "passkey"
encrypted.key
prf.salt
passkey.json
policy.toml
policy.toml.sig
```

The difference from a local wallet is how `encrypted.key` is decrypted:

| Wallet kind | At-rest key wrapping | User proof |
|---|---|---|
| local | Argon2id(passphrase) | caller knows passphrase |
| passkey | BLAKE3(WebAuthn PRF output) | authenticator signs challenge and returns PRF output |

The WebAuthn PRF output is derived live by the authenticator for the responding
credential's `prf.salt`. Without an authorized authenticator, disk contents are
insufficient to decrypt the wallet key.

The Sealed Approval Ceremony uses a single WebAuthn operation to request both:

1. the authentication assertion over the Sealed Approval challenge;
2. PRF extension output for the wallet's `prf.salt`.

The assertion is serialized into `approval.json`. The PRF output is never
serialized. The daemon uses it only to derive the wrap key, decrypt the wallet
key in memory, mint a scoped grant, and zeroize temporary secret material.

There are two different signatures in the ceremony:

1. **WebAuthn assertion**: authenticator signature over the Sealed Approval
   challenge. This proves user approval and is represented by `approval.json`.
2. **Wallet/chain signature**: signature over a transaction, typed-data payload,
   policy digest, venue credential approval, or similar payload. This is made by
   the wallet key after a grant permits a Petal host signing request.

The grant authorizes the second operation. The WebAuthn assertion never signs
chain transactions directly.

## 5. Security Invariants

### 5.1 Transport Is Untrusted

NFS AUTH_SYS, local uid, Docker mount boundaries, IPC clients, and VFS write
origin are not authorization boundaries. Any local process may be treated as
capable of staging actions or writing bytes to exposed paths.

### 5.2 Intent Sealing

At stage time the daemon must:

1. parse and validate the requested action;
2. construct a canonical intent;
3. persist it in daemon-controlled storage;
4. compute `intent_hash = BLAKE3("bloom.intent.v1" || canonical_bytes)`, encoded
   as lowercase, full-length, untruncated hex. The `bloom.intent.v1` domain tag
   MUST be bumped whenever the canonical schema changes;
5. expose only projections of that sealed action through VFS paths.

Once sealed, canonical bytes are immutable. A venue path cannot mutate the
sealed action. Re-stage instead.

### 5.3 Sign From Sealed Bytes

Petals execute from sealed canonical intent bytes, not from mutable venue files.
Immediately before a grant is consumed, the daemon must verify that:

```text
grant.intent_hash == sealed_action.intent_hash
grant.petal_id == sealed_action.petal_id
grant.petal_digest == sealed_action.petal_digest
approval.intent_hash == sealed_action.intent_hash
```

Under generic `sign-hash`, the daemon cannot decode `hash32` and therefore
cannot prove by itself that the digest submitted by a Petal is byte-for-byte
derived from the sealed bytes. For the MVP, that equality is a trusted-Petal
assumption. The Petal must submit a signing attestation, and the daemon enforces
identity, sealed-action binding, daemon grant terms, signature count, TTL,
allowed `intent` strings, and attested facts against the sealed Petal policy
snapshot. Exact-digest grants or preimage verification can later make this
byte-for-byte invariant daemon-enforced.

### 5.4 Single Ceremony, No Secret Files

One passkey ceremony must be sufficient for a normal action. It returns a
WebAuthn assertion and PRF output. Only the assertion may be persisted.

The PRF output must travel from the ceremony page to the daemon over a trusted
local channel controlled by the daemon, such as the daemon's authenticated UDS
or a short-lived loopback ceremony server bound to a nonce-bearing session
created by the daemon. It must not traverse the VFS/NFS surface, `approval.json`,
logs, CLI stdout/stderr, or any other untrusted courier.

For the MVP, the trusted ceremony channel is the existing browser-based local
ceremony server, tightened as follows:

1. the daemon creates a random `ceremony_id` and `ceremony_secret`;
2. the daemon starts a short-lived `127.0.0.1` HTTP server for that ceremony;
3. the browser is opened to a URL carrying the ceremony id and one-time secret;
4. the page calls `navigator.credentials.get()` with the daemon-issued approval
   challenge and PRF extension request;
5. the page POSTs `{assertion, prf_output}` directly back to that ceremony
   server;
6. the daemon rejects missing/wrong ceremony secrets, wrong action ids, expired
   ceremonies, repeated submissions, and unexpected origins;
7. the daemon closes the ceremony server after success, timeout, or failure.

The ceremony server may use the existing browser helper implementation, but it
must be treated as a secret-bearing channel. It must not proxy PRF output
through the mounted Bloom VFS. A future toolbar app may replace this local HTTP
server with an authenticated daemon IPC channel without changing the sealed
action or grant model.

Forbidden:

- writing PRF output to `approval.json`;
- writing PRF output to any VFS path;
- writing decrypted wallet keys to disk;
- persisting grants;
- using a passphrase fallback;
- caching a raw unlocked signer outside a grant or an approved owner-signing
  session.

### 5.5 Grant Scope

A Sealed Approval Grant authorizes only one Petal identity to request wallet
signatures for one sealed action, within the sealed daemon terms and Petal
policy snapshot, and before expiry.

The grant does not authorize arbitrary callers, arbitrary Petals, or signing
outside the sealed action's declared `allowed_sign_intents`.

### 5.6 Hard vs Step-Up Policy

Policy must distinguish:

- **hard rules**: never escalatable, even with a passkey;
- **step-up rules**: require Sealed Approval and may be bounded by explicit
  ceilings;
- **informational rules**: plan/audit only.

Examples of hard rules include geoblock failures, denylist hits, unavailable
compliance checks that fail closed, and any destination/asset/rule marked
absolute.

### 5.7 Assertion Binding and Verification

The WebAuthn `challenge` MUST equal:

```text
BLAKE3("bloom.approval.v1", canonical(ApprovalChallenge))
```

The canonical `ApprovalChallenge` preimage must include at least:

```text
schema
action_id
wallet
surface
petal_id
petal_digest
intent_hash
server_nonce
assurance
daemon_terms_digest
petal_policy_digest
policy_version
expiry_ms
```

Verification must happen in the daemon and must:

1. load the sealed action from daemon-controlled storage;
2. load the issued challenge/nonce from daemon-controlled storage;
3. recompute the expected challenge from the sealed action and issued nonce;
4. parse `clientDataJSON` and require its `challenge` to match the recomputed
   expected challenge;
5. verify the WebAuthn assertion signature against the stored credential public
   key identified by `credential_id`, and confirm that credential is registered
   and not revoked for the wallet;
6. check RP ID hash and origin for the configured Bloom local relying party;
7. enforce user verification when `assurance = "hardened"`;
8. reject authenticator counter regression or clone indicators;
9. require `approval.expiry_ms` to equal the daemon-issued challenge expiry;
10. require the approval `daemon_terms_digest`, `petal_policy_digest`, and
   `policy_version` to equal the daemon-issued challenge values;
11. burn `server_nonce` transactionally before or with grant minting.

`surface` and `action_id` are informational for projection routing but are also
part of the signed preimage. Approvals must bind concrete `action_id` values;
they must never bind `latest`.

### 5.8 Atomic Verify-at-Use

For any signature-producing action, the following must happen under a per-action
lock with no re-read from mutable VFS projections:

```text
verify approval against sealed action
burn nonce
mint or consume grant
render Petal signing request from sealed bytes
check daemon terms, signing attestation, and sealed Petal policy snapshot
produce wallet signature
record audit event
```

For typed or exact-digest signing, there must be no window where approval is
verified against one intent and a signature is produced from different bytes.
For generic `sign-hash`, where the daemon cannot decode `hash32`, this
byte-for-byte property is enforced by trusting the approved Petal's attestation.
Only trusted first-party or reviewed Petals may receive `sign-hash` grants
until exact digest grants or preimage verification lands.

### 5.9 WYSIWYG Plan Rendering

The human-facing plan shown during approval must be rendered by trusted daemon
code from the same sealed canonical intent that produces `intent_hash`. The
toolbar or ceremony UI must not render plan details by re-reading mutable mount
paths. The signed challenge commits to the same `intent_hash` used to render
the plan.

Under generic `sign-hash`, the daemon cannot verify that the digest a Petal
submits equals a digest derived from the rendered plan. WYSIWYG therefore holds
byte-for-byte only for trusted Petals in the MVP. The daemon still validates the
Petal's signing attestation against the sealed Petal policy snapshot before
signing. Exact-digest grants close this gap for actions that can fully
materialize signing payloads before approval.

For batch actions, such as Polymarket onboarding, `intent_hash` must commit to
the ordered step list. The Petal must execute exactly that ordered list; no
step may be substituted after approval. The daemon terms must set
`max_signatures` to the number of signing steps, and the sealed action must
include each step's allowed `intent` string.

## 6. Data Model

### 6.1 Sealed Action

```text
SealedAction {
  schema: "bloom.sealed_action.v1",
  action_id,
  wallet,
  surface,              // origin projection: requests | wallets | polymarket | ...
  petal_id,
  petal_digest,
  petal_version,
  executor_kind,        // first_party | wasm
  network,
  account,
  action_kind,
  value_movement,
  authority_change,
  canonical_subject_schema,
  canonical_subject_bytes,
  plan,
  policy_checks,
  daemon_terms,
  petal_policy,
  petal_policy_digest,
  policy_version,
  created_ms,
  expires_ms,
}
```

`intent_hash` is the content address of the canonical representation consumed
by the Petal: `BLAKE3("bloom.intent.v1" || canonical_bytes)`, lowercase
full-length hex (see §5.2). It is distinct from the WebAuthn challenge hash,
which uses the `bloom.approval.v1` domain tag (§5.7).

Field meanings:

- `schema`: version tag for this sealed action record.
- `action_id`: globally unique concrete outbox id. It is never `latest`.
- `wallet`: Bloom wallet name that owns the authority being used.
- `surface`: staging/projection origin, such as `wallets`, `requests`,
  `polymarket`, or `hyperliquid`. Informational, but signed.
- `petal_id`: stable logical executor id, such as `evm-wallet`,
  `polymarket`, `hyperliquid`, `paid-http`, `defi`, or `wallet-policy`.
- `petal_digest`: daemon-recorded digest of the exact first-party component or
  WASM module allowed to consume the grant.
- `petal_version`: human/debug version for audit and compatibility.
- `executor_kind`: `first_party` for current Rust components, `wasm` for
  dynamically loaded Petals.
- `network`: chain, venue network, or logical network selected by the action.
- `account`: wallet address, venue subaccount, or other account identifier the
  Petal will act for.
- `action_kind`: normalized action class, such as `evm_tx_confirm`,
  `polymarket_order`, `hyperliquid_approve_agent`, or `policy_update`.
- `value_movement`: true when funds, exposure, fees, or spend can change.
- `authority_change`: true when policy, credentials, keys, approvals, sessions,
  or delegated authority can change.
- `canonical_subject_schema`: version tag for the Petal-specific subject bytes.
- `canonical_subject_bytes`: immutable canonical bytes the Petal executes from;
  not a mutable VFS path.
- `plan`: daemon-rendered human review text derived from the canonical subject.
- `policy_checks`: daemon-computed rule results shown in the plan and audit.
- `daemon_terms`: `DaemonGrantTerms` copied into any grant minted for the action.
- `petal_policy`: sealed `PetalPolicySnapshot` bytes for this action.
- `petal_policy_digest`: digest of `petal_policy`, also bound into the approval
  challenge.
- `policy_version`: monotonic wallet-policy/config version observed at sealing.
- `created_ms`: daemon sealing time.
- `expires_ms`: latest time the sealed action may be approved or executed.

All fields are needed for the MVP except `petal_version`, which is not a
security boundary but is retained for audit readability, migration, and
operator debugging. `executor_kind` is retained because first-party and WASM
Petals share the model but have different digest provenance during the
transition.

### 6.2 Approval Challenge

```text
ApprovalChallenge {
  schema: "bloom.approval_challenge.v1",
  action_id,
  wallet,
  surface,
  petal_id,
  petal_digest,
  intent_hash,
  server_nonce,
  assurance,
  daemon_terms_digest,
  petal_policy_digest,
  policy_version,
  expiry_ms,
}
```

The daemon issues and persists `server_nonce`. The nonce is single-use and must
survive restart after consumption. A daemon restart between challenge issuance
and ceremony completion invalidates the live ceremony channel; the action must
be re-challenged before a grant can be minted.

`intent_hash` is lowercase, full-length, untruncated hex. `wallet` is the Bloom
wallet name, not merely an address; the sealed action may also carry the wallet
address as part of its canonical subject. `daemon_terms_digest` is a
collision-resistant digest of canonical `SealedAction.daemon_terms`.
`petal_policy_digest` is a collision-resistant digest of canonical
`SealedAction.petal_policy`. These digests, `policy_version`, and `expiry_ms`
are daemon-issued. A client may echo them in `approval.json`, but any mismatch
from the issued challenge is rejected.

`assurance` in the challenge is the daemon's required proof level for this
specific action: `standard` accepts WebAuthn user presence, while `hardened`
requires user verification. The client cannot lower it by editing
`approval.json`; verification compares the approval to the daemon-issued
challenge.

The challenge intentionally contains only compact routing, identity, nonce,
digest, and expiry fields. It does not repeat `network`, `account`,
`action_kind`, or policy bodies because those are already committed by
`intent_hash`, `daemon_terms_digest`, and `petal_policy_digest`.

### 6.3 Signed Approval

The only approval file is:

```text
/outbox/pending/<action_id>/approval.json
```

Schema:

```text
SignedApproval {
  schema: "bloom.approval.v1",
  action_id,
  wallet,
  surface,
  petal_id,
  petal_digest,
  intent_hash,
  server_nonce,
  assurance,
  daemon_terms_digest,
  petal_policy_digest,
  policy_version,
  expiry_ms,
  signer_transport: "browser_webauthn" | "native_ctap2",
  credential_id,
  webauthn_assertion,
}
```

`webauthn_assertion` includes the standard credential id, authenticator data,
client data JSON, signature, and optional user handle. It does not include PRF
output.

`signer_transport` records how the WebAuthn assertion was collected. The normal
MVP path is `browser_webauthn`, using the existing local browser ceremony.
`native_ctap2` is reserved for a future direct CTAP2/FIDO2 device flow that
talks to the authenticator without a browser. This is transport/audit metadata,
not a different authority level; assurance is still enforced from authenticator
flags. Older names such as `passkey_ctap` are too vague and should not be used
in this target schema.

### 6.4 Sealed Approval Grant

Grants are in-memory only:

```text
SealedApprovalGrant {
  grant_id,
  wallet,
  action_id,
  intent_hash,
  petal_id,
  petal_digest,
  petal_version,
  daemon_terms,
  petal_policy_digest,
  policy_version,
  issued_ms,
  expiry_ms,
  max_signatures,
  consumed_signature_count,
  revoked,
}
```

Grant state must be held behind a daemon API that exposes only signing methods,
never key extraction.

Recommended MVP defaults:

```text
expiry_ms = now + 120 seconds
max_signatures = action declared cap, default 1
attestation required for every sign-hash request
grant persistence = never
```

`expiry_ms` must be less than or equal to the signed approval expiry. On grant
consume, expiry, revoke, daemon shutdown, or Petal failure, any decrypted wallet
key material held for that grant must be zeroized.
Concurrent grants are allowed only if they bind different `action_id` values;
there must be at most one live grant per `(wallet, action_id, petal_id,
petal_digest)`.

For `max_signatures > 1`, the decrypted wallet key or unwrapped wallet DEK may
remain in memory only behind the grant API until the final permitted signature,
expiry, revoke, or failure. PRF output itself must still be zeroized immediately
after deriving the wrap key or unwrapping the wallet DEK.

Field meanings:

- `grant_id`: daemon-local unique id for audit and revocation.
- `wallet`: wallet name whose key may be used.
- `action_id`: sealed outbox action this grant belongs to.
- `intent_hash`: immutable action hash the grant is bound to.
- `petal_id`, `petal_digest`, `petal_version`: exact Petal identity allowed to
  consume the grant.
- `daemon_terms`: signer limits copied from the sealed action.
- `petal_policy_digest`: digest of the sealed policy snapshot that signing
  attestations must satisfy.
- `policy_version`: wallet-policy/config version used when sealing.
- `issued_ms`: grant mint time.
- `expiry_ms`: grant expiry, no later than the signed approval expiry.
- `max_signatures`: total wallet signatures allowed under this grant.
- `consumed_signature_count`: number of signatures already produced.
- `revoked`: in-memory kill switch set by failure, expiry handling, explicit
  revoke, or daemon shutdown.

The grant does not need `require_attestation`: `sign-hash` always requires a
structured attestation in this model, including for actions that are "only"
authority-changing. The grant also does not need `attested_signature_count`
because a valid consumed signature is necessarily attested; failed attestation
attempts belong in audit records, not grant state. Grants must not carry a
`persisted` field. Persistence is forbidden, not configurable; on restart a new
challenge and ceremony are required before wallet-key signing can resume.

## 7. VFS Layout

### 7.1 Central Action Outbox

```text
/outbox/
  pending/
    <action_id>/
      intent.json              # sealed canonical action projection
      intent_hash
      plan.md
      policy_check.json
      challenge.json
      approval.json            # writable signed approval
      status.json
      result.json
  sent/
    <action_id>/...
  failed/
    <action_id>/...
  latest -> pending/<action_id>
```

`latest` resolves to the most recently staged pending action, determined by the
modification time of `intent.json` (which is immutable after staging per §5.2,
so later artefact writes like `approval.json` do not affect ordering). If no
actions are pending, `latest` is absent. It is an ergonomic
shortcut, not an authorization primitive — approvals must bind concrete
`action_id` values and must never bind `latest` (§5.7).

Writing to `approval.json` is allowed, but provenance is irrelevant. The daemon
must verify the signature, nonce, expiry, intent hash, Petal identity, and grant
contract summary.
For wallet-signing actions, a valid approval file alone is insufficient to mint
a grant unless the live ceremony also delivered PRF output over the trusted
ceremony channel.

### 7.2 Venue Projections

Venue paths remain ergonomic origins and status views:

```text
/requests/pending/<id> -> /outbox/pending/<action_id> projection
/wallets/<w>/chains/<c>/outbox/pending/<id> -> /outbox/pending/<action_id>
/polymarket/trade/<w>/drafts/<id> -> /outbox/pending/<action_id>
/hyperliquid/<network>/agent_sessions/<w>/<id> -> /outbox/pending/<action_id>
```

The projection may expose venue-specific files, but authorization files are
central. Do not create venue-specific approval files.

### 7.3 Session Actions

Actions that mint standing venue credentials, such as a Hyperliquid agent key,
also go through `/outbox/pending/<action_id>`. After approval and execution, the
venue credential may authorize later bounded operations without another user
ceremony. Those later operations still write central audit records and must be
checked against the frozen session caps.

Bloom supports two session classes:

1. **Delegated-credential sessions**, where the approved action mints a venue
   credential distinct from the owner wallet key, such as a Hyperliquid agent
   key.
2. **Owner-signing sessions**, where the approved action authorizes the daemon
   to keep the owner wallet signing key resident in daemon memory behind a
   frozen, host-enforced session policy for longer than a single action.

Owner-signing sessions are necessary for chains or venues that do not provide a
native delegation mechanism and where Bloom must support long-running agent
work without deploying onchain contracts. They are more sensitive than
delegated-credential sessions because the owner key remains the signer, so they
must be explicit in the plan and audit copy and must use `assurance =
"hardened"` unless wallet policy sets an even stricter requirement.

Concrete required use case: an agent may be approved once to send up to
`100 USDC` per rolling day to a known address from an EVM wallet, without
requiring a passkey ceremony for each transfer and without deploying an onchain
contract. The initial Sealed Approval action mints an
`evm_owner_signing_session` with a sealed policy snapshot that fixes:

```text
wallet
chain_id
token_contract = USDC
recipient
rolling_window = 24h
max_amount = 100 USDC
allowed_method = ERC20.transfer(recipient, amount)
max_fee_policy
ttl
fail_safe_behavior
```

Later agent writes stage session-use transfer requests against that session. A
session-use request does not carry a fresh `approval.json`; it binds to the
approved `session_id`, sealed session scope, and current budget state, and it
must produce a central audit record. The daemon may sign and broadcast only if
the request exactly matches the sealed session scope, the daily budget has not
been exhausted, fee policy passes, the session is live, and the signing
attestation matches the constructed ERC-20 transfer digest. Any different
token, recipient, method, chain, amount over the remaining daily budget, policy
expansion, or expired/revoked/lost session must stage a new Sealed Approval
action.

No onchain enforcement is implied for owner-signing sessions. The security
boundary is local daemon enforcement plus frozen caps and audit. If the daemon
restarts, crashes, or loses the in-memory signer, the session becomes unusable
or orphaned and requires a fresh Sealed Approval ceremony to resume. The owner
key, wallet DEK, PRF output, and grants must never be written to disk to
preserve the session.

All standing sessions must be:

- minted only by a Sealed Approval action;
- stored outside the VFS with owner-only filesystem permissions when they have
  persistent non-wallet secret material; owner-signing sessions may persist only
  non-secret session metadata and caps;
- scoped to wallet, venue, network, action classes, caps, and TTL;
- revocable;
- frozen at mint time so later policy edits cannot widen a live credential;
- audited centrally on mint, use, expiry, revoke, and recovery;
- limited to one live session per `(wallet, venue, network)` unless a spec
  for safe concurrency exists.

Each session type must explicitly choose fail-safe or fail-stale behavior for
monitor failures. High-cap sessions should fail safe by halting new actions and
attempting risk-reducing cleanup. If a session is intentionally fail-stale, its
status must surface `stale_since_ms` and the central audit must record the
staleness.

Revoking owner-signing sessions on OS sleep, wake, and lock-screen events is
future hardening work, not an MVP requirement. Until platform-specific event
hooks are implemented, the MVP must still revoke or orphan sessions on daemon
restart/crash, explicit revoke, expiry, budget exhaustion, and loss of
in-memory signing material.

## 8. Petal Signing Host API

Future WASM Petals and first-party Petals use the same logical host API.
This spec aligns with the Petal route-file WIT in
`bloom-petal-polymarket/petal/wit`:

```text
bloom:vfs/readwrite.{lookup, list, read, write}
bloom:sign/signing.sign-hash(wallet, hash32, intent, attestation)
```

Do not invent Sealed-Approval-specific projection methods. Petals use the
standard VFS import for ordinary route behavior and the generic signing import
when a grant permits signing.

That WIT currently lives in the sibling Petal repository, not this repository.
Implementing this spec must either import/adapt that WIT or add an equivalent
target WIT here before dynamically loaded Petals can use it. The current sibling
WIT has only `sign-hash(wallet, hash32, intent)`; it must grow the
`attestation` parameter and the policy/context imports below.

Minimum interface:

```text
seal_context() -> { action_id, wallet, intent_hash, petal_id, petal_digest }
get-policy() -> PetalPolicySnapshot
sign-hash(wallet, hash32, intent, attestation) -> signature
audit(event)
vfs.lookup/list/read/write(path, ...)
```

`seal_context()` returns the daemon-injected execution context for the currently
running sealed action. It is not a request from the Petal to create or mutate a
seal. The host uses it to expose the already-bound `action_id`, `wallet`,
`intent_hash`, `petal_id`, and `petal_digest` so Petal code can tag logs,
construct attestations, and fail closed if route-local state does not match the
sealed action. The host must source this from daemon-controlled sealed action
state, not from VFS paths or Petal-supplied input.

`sign-hash` signs an arbitrary 32-byte digest supplied by the Petal. The daemon
must not expose protocol-specific typed signing functions as the primary model.
Typed signing may be added later as an optimization or safer mode, but dynamic
Petals must be able to request generic digest signatures through the grant.

`get-policy()` returns only the sealed `PetalPolicySnapshot` committed by the
current sealed action's `petal_policy_digest`; it never returns live
`policy.toml`. A policy edit after sealing does not change the injected bytes
for an already-sealed action.

`attestation` is a structured claim whose schema is selected by `petal_id` and
`intent`. It must contain the policy-relevant facts needed for the daemon to
check the signing request against the sealed Petal policy snapshot. For MVP, the
daemon trusts the approved Petal that the attestation honestly describes
`hash32`.

`sign-hash` must enforce:

```text
exists active grant
grant.wallet == wallet
grant.intent_hash == current sealed intent hash
grant.petal_id == current petal id
grant.petal_digest == current petal digest
grant.expiry_ms > now
grant.consumed_signature_count < grant.max_signatures
intent string is allowed by DaemonGrantTerms.allowed_sign_intents
attestation schema is allowed for petal_id + intent
attestation satisfies the sealed PetalPolicySnapshot
```

For MVP, do not require exact signing digest pre-commitment and do not require
the daemon to decode arbitrary Petal signing payloads. The grant is
Petal-scoped and sealed-intent-scoped. Runtime semantic checks are performed by
validating the Petal's attestation against the sealed Petal policy snapshot.

This is an explicit trust boundary: Sealed Approval ensures the user approved a
specific sealed action for a specific Petal, and the daemon checks the Petal's
attested facts against daemon-owned policy. It does not, by itself, prove a
malicious Petal cannot lie about the relationship between `hash32` and the
attestation. Petal trust, package review, reproducibility, remote attestation,
exact digest grants, or preimage verification are separate future hardening
layers. Until those land, only trusted first-party or reviewed Petals should
receive signing grants.

The host must still reject:

- grants for the wrong wallet, action, Petal id, or Petal digest;
- expired or revoked grants;
- signature requests beyond `max_signatures`;
- `intent` strings not declared in the daemon terms;
- attestations that exceed the sealed Petal policy snapshot;
- signing attempts from ordinary VFS `write` paths that did not enter through
  sealed Petal execution.

Existing first-party signing and policy implementations must be migrated to this
logical API instead of retaining private signer lanes:

- EVM wallet outbox signing currently runs through `bloom-tx` policy checks and
  keystore signer access; it must execute as the `evm-wallet` first-party Petal
  with sealed `PolicyCaps`, allow/deny lists, budget state, and EVM signing
  attestations.
- Polymarket native code currently has `bloom-polymarket` order/onboarding
  policy and signing helpers, and the future Petal in
  `../bloom-petal-polymarket` imports `bloom:sign/signing@0.1.0`. Both must use
  `seal_context`, `get-policy`, and attested `sign-hash`.
- Hyperliquid native code currently has `bloom-hyperliquid` EIP-712 signing and
  `HyperliquidPolicy` checks for orders, `approveAgent`, transfers, and
  sessions. Those checks become the sealed `PetalPolicySnapshot` for the
  `hyperliquid` first-party Petal.
- Paid HTTP and DeFi signing/session flows must likewise stage central sealed
  actions and request signatures only through the grant host API.

## 9. Policy, Caps, and Petal Policy Snapshots

Every sealed action must carry policy checks, daemon grant terms, and a sealed
Petal policy snapshot.

The authoritative policy source is the wallet policy. Petal manifests and route
metadata may declare required capabilities and signing intent hints, but they do
not grant authority. At staging time, the daemon combines:

1. wallet policy;
2. the Petal identity and manifest/route metadata;
3. the staged action's declared economic and authority facts;
4. current budget/session state;

and produces:

1. `DaemonGrantTerms`: host-enforced signer boundaries;
2. `PetalPolicySnapshot`: the Petal-specific policy/config slice used for
   semantic runtime checks.

Daemon grant terms are host-enforced at signing time:

```text
DaemonGrantTerms {
  max_ttl_secs,
  max_signatures,
  allowed_sign_intents,
  assurance,
  extra
}
```

Field meanings:

- `max_ttl_secs`: maximum grant lifetime the daemon may mint for this action.
- `max_signatures`: maximum wallet signatures allowed across the action.
- `allowed_sign_intents`: exact `intent` strings the Petal may pass to
  `sign-hash`, such as `polymarket.order.v2`,
  `hyperliquid.approve_agent`, or `wallet_policy.sign`.
- `assurance`: required approval strength copied into the challenge.
- `extra`: daemon-owned extension map for Petal-specific host terms that are
  not yet first-class fields. Unknown required keys must fail closed.

`DaemonGrantTerms` does not need `require_attestation`: attestation is mandatory
for every `sign-hash` call. If a future exact-typed signing method does not need
attestation, that should be modeled as a different host method or an explicit
signing intent, not as a per-grant boolean that can accidentally disable the
MVP safety check.

Petal policy snapshots are daemon-owned policy/config projections injected into
the Petal and validated by the daemon against signing attestations:

```text
PetalPolicySnapshot {
  policy_version,
  wallet,
  petal_id,
  petal_digest,
  caps,             // Petal-specific amount/daily/session limits
  hard_rules,
  step_up_rules,
  config,           // Petal-specific daemon-owned config, including endpoints
  budget_state,
  session_scope,
}
```

Field meanings:

- `policy_version`: monotonic version of the wallet policy/config snapshot used
  to produce this policy.
- `wallet`: wallet name the snapshot applies to.
- `petal_id`: Petal this snapshot was produced for.
- `petal_digest`: exact Petal digest expected to use the snapshot.
- `caps`: Petal-specific limits. Examples include EVM `PolicyCaps`,
  Polymarket `max_order_usd`/`max_daily_usd`, Hyperliquid
  `max_notional_usd`/`max_position_usd`/`max_loss_usd`, payment request caps,
  or session TTL/spend caps.
- `hard_rules`: non-overridable daemon or wallet rules, such as geoblock
  failures, denylist hits, disabled venues, unknown action kinds, and fail-closed
  missing monitor/snapshot data.
- `step_up_rules`: rules that can be exceeded only by Sealed Approval and only
  up to explicit ceilings.
- `config`: daemon-owned Petal configuration needed at runtime, including
  endpoints, chain ids, relayer/CLOB/Gamma URLs, private-orderflow settings, or
  protocol constants.
- `budget_state`: frozen spend/exposure/session counters used to check caps
  during execution.
- `session_scope`: frozen standing-authority scope when the action mints or
  uses a venue session credential.

For a Polymarket Petal, `PetalPolicySnapshot` may include market/slug rules,
max order size, daily cap, geoblock behavior, CLOB/Gamma endpoints, builder-key
settings, and any other daemon-owned configuration the Petal needs to enforce
runtime policy. The Petal reads this via `get-policy()`; it must not read live
wallet policy for an already-sealed action.

Precedence is:

```text
wallet policy + Petal metadata + staged action facts
  -> daemon-produced SealedAction.daemon_terms
  -> daemon-produced SealedAction.petal_policy
  -> daemon-issued ApprovalChallenge.daemon_terms_digest + petal_policy_digest
  -> SignedApproval must exactly match challenge digests + policy_version
  -> SealedApprovalGrant copied from verified sealed action/challenge
```

User-writable files never widen daemon terms or Petal policy snapshots. Any
mismatch rejects the approval.

Because generic `sign-hash` does not let the daemon inspect `hash32`, runtime
economic cap enforcement uses signing attestations. The daemon validates the
attestation against the sealed Petal policy snapshot before signing. This moves
policy checking back into the daemon while still trusting the Petal not to lie
about what `hash32` represents. Post-execution reconciliation must compare
observed receipts/results against attestations and freeze/revoke grants for
inconsistent Petal behavior.

Policy files must express whether a denial is hard or step-uppable. The plan
and challenge must report each violated rule with:

```text
rule_id
rule_class: hard | step_up | informational
outcome
message
step_up_ceiling, if applicable
```

Step-up approvals can exceed only rules marked `step_up` and only up to their
configured ceiling. Hard rules cannot be overridden.

Policy edits are themselves authority-changing sealed actions. VFS writes to
policy paths must not directly replace the active policy. They must stage a
policy-update action in the Action Outbox:

```text
write proposed policy through /wallets/<wallet>/policy.toml or policy edit path
daemon stages sealed policy_update action
plan shows policy diff and authority expansion/contraction analysis
Sealed Approval required for authority-expanding edits
Petal executes from sealed policy bytes
daemon writes policy.toml and policy signature atomically
central audit records the change
```

Expanding edits always require Sealed Approval.

Policy rules split into two sources:

- **system hard rules**: compiled or daemon-configured rules such as compliance
  geoblocks. Wallet policy cannot remove or weaken these.
- **wallet hard rules**: user-configured hard rules in wallet policy. Removing
  or weakening these is not an ordinary step-up. It must be classified as a
  `policy_hard_rule_change`, require `assurance = "hardened"`, mandatory UV,
  explicit diff review, and a sealed policy-update action. The plan must not
  present it as routine approval of the blocked action.

The first-party policy executor is the `wallet-policy` Petal. For the MVP this
is a first-party component to build in this repository, not deferred dynamic
Petal marketplace work. Its `petal_id` and `petal_digest` are bound into the
sealed policy-update action, and its `sign-hash` intent string for producing
`policy.toml.sig` must appear in `allowed_sign_intents`.

For authority-changing actions with no value movement, economic fields inside
the Petal policy snapshot may be unset. The action is then bound by
`policy_version`, `petal_policy_digest`, daemon terms, Petal identity,
assurance, and the authority-expansion analysis.

The standing-authority invariant remains:

> Anything auto-authorized under a session must be safe for anyone who can
> reach the mount: bounded in amount, constrained in destination/asset/surface,
> and limited to risk-reducing operations where applicable.

### 9.1 Cross-Bloom Autonomy Policy

Wallet policy must support cross-Bloom autonomy limits that apply before
surface-specific policy. This is how a wallet can allow low-value x402,
payment, EVM transfer, DeFi, or venue actions without requiring a fresh passkey
ceremony per action.

Example target policy:

```toml
[autonomy]
enabled = true
max_tx_usd = "0.05"
max_day_usd = "5.00"
max_week_usd = "25.00"
require_passkey_above_usd = "5.00"

[autonomy.assets]
allow = ["USDC"]
deny = []

[autonomy.destinations]
allow = ["0xKnownAddress...", "x402:merchant.example"]
deny = []

[autonomy.surfaces]
allow = ["requests", "wallets", "payments", "defi"]
deny = []
```

Autonomy limits are global wallet limits. Surface/Petal policies may be more
restrictive, but cannot widen the global autonomy policy. For example, a
`$0.01` x402 request may skip fresh approval only if it fits `[autonomy]`,
`[payments]`, merchant/destination rules, active session/capability scope, and
budget state. The same daily cap must count spend across all Bloom surfaces,
not just `/requests`.

The target parsed shape is:

```text
AutonomyPolicy {
  enabled,
  max_tx_usd,
  max_day_usd,
  max_week_usd,
  max_month_usd,
  require_passkey_above_usd,
  allowed_assets,
  denied_assets,
  allowed_destinations,
  denied_destinations,
  allowed_surfaces,
  denied_surfaces,
  allowed_action_kinds,
  denied_action_kinds,
}
```

Field meanings:

- `enabled`: master gate. Defaults to false.
- `max_tx_usd`, `max_day_usd`, `max_week_usd`, `max_month_usd`: global
  cross-surface caps parsed as integer micro-USD.
- `require_passkey_above_usd`: fresh approval threshold even when caps remain.
- `allowed_assets`/`denied_assets`: asset allow/deny sets; deny wins.
- `allowed_destinations`/`denied_destinations`: address, merchant, or venue
  destination sets; deny wins.
- `allowed_surfaces`/`denied_surfaces`: Bloom surfaces where autonomy may be
  used.
- `allowed_action_kinds`/`denied_action_kinds`: normalized action classes that
  may or may not run autonomously.

Autonomy is evaluated before Petal-specific signing. If it denies, no session
or Petal policy can override it. If it passes, the action still needs active
bounded authority: an owner-signing session, delegated session credential,
service credential, or other Sealed-Approval-minted capability.

### 9.2 Session Records and Budget Ledger

The implementation must model standing authority explicitly rather than hiding
it in an unlocked signer cache.

Target durable and in-memory records:

```text
StandingSession {
  session_id,
  wallet,
  session_kind,        // delegated_credential | owner_signing | service_auth
  surface,
  petal_id,
  petal_digest,
  policy_version,
  scope,
  budget_ledger_id,
  status,              // active | expired | revoked | orphaned | halted | stale
  created_ms,
  expires_ms,
  revoked_ms,
  orphaned_ms,
  last_error,
}

SessionScope {
  networks,
  assets,
  destinations,
  action_kinds,
  methods,
  max_tx_usd,
  max_day_usd,
  max_week_usd,
  max_month_usd,
  max_fee_policy,
  extra,
}

SessionBudgetLedger {
  ledger_id,
  wallet,
  session_id,
  window,
  reserved_micro_usd,
  spent_micro_usd,
  released_micro_usd,
  updated_ms,
}

SessionUseRequest {
  request_id,
  session_id,
  wallet,
  surface,
  petal_id,
  action_kind,
  amount_micro_usd,
  asset,
  destination,
  canonical_subject_hash,
  attestation,
  created_ms,
}

SessionUseReceipt {
  request_id,
  session_id,
  reservation_id,
  status,              // reserved | signed | broadcast | confirmed | failed | released
  tx_hash,
  spent_micro_usd,
  error,
  updated_ms,
}
```

Budget accounting must be transactional. Before signing or dispatch, the daemon
must acquire the relevant session/wallet lock, validate scope, and reserve the
amount. Caps count `reserved + spent`, not only confirmed spend, so concurrent
agent writes cannot overspend a daily cap. Failed, rejected, or expired attempts
release their reservation; confirmed results move reserved amount to spent.
Receipt reconciliation must handle retry, replacement, dropped transaction,
failed transaction, and chain reorg behavior conservatively. If reconciliation
is unavailable and a cap depends on it, fail closed or halt the session.

Session status behavior:

- `active`: may accept in-scope session-use requests.
- `expired`: TTL elapsed; no new requests.
- `revoked`: owner or daemon explicitly revoked.
- `orphaned`: persistent metadata remains, but required in-memory signing
  material or delegated secret is gone.
- `halted`: risk, reconciliation, or policy breach stopped the session.
- `stale`: monitor data is stale and this session type explicitly allows
  fail-stale behavior; otherwise use `halted`.

Agents must receive deterministic denial strings such as
`session_orphaned_requires_reapproval`, `session_budget_exhausted`, and
`session_scope_mismatch`. Reapproval stages a new sealed action, usually
pre-filled with the prior session scope, and records the orphan/reapproval in
central audit.

## 10. Local Wallet Removal and Migration

Local/passphrase wallets are not part of the target product.

Required changes:

1. Remove local wallet creation from CLI, VFS, docs, and tests.
2. Remove passphrase parameters and prompts.
3. Remove `Keystore::unlock` paths for signing.
4. Preserve read-only detection of existing local wallets only to fail closed
   with a clear migration error.
5. Provide a manual developer migration path:

```text
bloom wallet migrate-local-to-passkey <old-wallet> <new-wallet>
```

or equivalent documentation if the command is not implemented immediately.

The migration path may require the developer to supply the old private key or
old passphrase locally. It must create a new passkey wallet and must not
preserve passphrase signing behavior.

Passkey wallet creation and re-keying are the only supported wallet onboarding
paths after local wallet removal. Creation must:

1. generate or import wallet key material;
2. generate `prf.salt`;
3. run WebAuthn registration with PRF support;
4. store credential public-key material in `passkey.json`;
5. encrypt the wallet key with a wallet DEK and wrap that DEK with the
   credential's PRF-derived wrap key;
6. create and sign initial policy;
7. show/export recovery material through an explicit developer/user ceremony.

Re-keying or adding/replacing an authenticator is an authority-changing action
and must itself use Sealed Approval once a wallet already exists.

Wallets must support multiple passkeys controlling the same wallet key. The
target layout is:

```text
wallet/
  kind                         # "passkey"
  address
  pubkey
  encrypted.key                # wallet private key encrypted by wallet DEK
  policy.toml
  policy.toml.sig
  credentials/
    <credential_id>/
      passkey.json
      prf.salt
      wrapped_dek              # wallet DEK encrypted by this credential's PRF output
      label
      created_ms
      revoked_ms
```

The wallet private key is encrypted once by a random wallet data-encryption key
(`wallet_dek`). Each passkey credential wraps that `wallet_dek` using its own
WebAuthn PRF output. Adding a passkey unwraps the DEK with an existing
credential, registers the new credential, and writes a new `wrapped_dek`.
Removing a passkey revokes or deletes only that credential's wrapper. Replacing
the last passkey must require an explicit recovery/migration ceremony.

Autonomy does not introduce an `autonomous` wallet kind. A wallet that supports
autonomous agent execution is still `kind = "passkey"` at rest. Its derived
authority lives in signed policy plus runtime/durable capability records:

```text
passkey wallet root authority:
  credentials/<credential_id>/wrapped_dek
  policy.toml
  policy.toml.sig

derived authority:
  standing sessions
  delegated credentials
  service credentials
  budget ledgers
  audit records
```

Root authority operations, including policy expansion, re-keying, recovery, and
minting or expanding sessions, require Sealed Approval. Derived authority may
act without another ceremony only while it remains within signed policy, frozen
session scope, and current budget state.

## 11. Required Codebase Gap Closures

An implementation is incomplete until all items in this section are done.

### 11.1 Delete Legacy Authorization Paths

Remove:

- `write_unlocked` IPC method and CLI use;
- `.confirm_approved.json`;
- `review_approved.json`;
- policy-session marker approvals;
- local password/passphrase unlock as an authorization path;
- unwired auth fallbacks;
- tests that assert marker behavior.

### 11.2 Convert All Signing Flows to Sealed Approval

Audit every flow that can sign, broadcast, mint credentials, change policy, or
move value. It must become:

```text
stage central action
issue challenge
write/verify approval.json
mint grant
execute Petal from sealed intent
audit result
```

This includes:

- wallet EVM tx broadcast, replace, cancel;
- EVM owner-signing session minting and bounded session use, including the
  `100 USDC/day to a known address` use case;
- wallet policy edits and policy signing through the first-party
  `wallet-policy` Petal;
- paid HTTP x402/MPP confirms and session deposits;
- DeFi route execution;
- Polymarket onboarding, funding, order placement, redemption, withdrawals,
  revocations, builder-key management where authority changes;
- Hyperliquid `approveAgent`, agent session minting, `usdSend`, withdrawal or
  transfer-like actions;
- any future Petal host function that can request signatures.

### 11.3 Centralize Outbox and Audit

Create `/outbox` as the single action queue. Venue directories become
projections. Approval consumption, grant minting, Petal execution, session
actions, and settlement results write central audit records.

Per-venue logs may remain as projections or diagnostic copies, but the central
audit spine is authoritative.

The central action id must be globally unique and concrete. It must not depend
on per-venue `latest` state. Projection metadata must map venue-local ids to
central `action_id` values and must survive daemon restart.

### 11.4 Execute From Sealed Intent

Petal execution must consume sealed canonical bytes from daemon-controlled
storage. Mutable VFS files may display status or receive new staging requests;
they must not be the source of truth for signing.

### 11.5 Implement One-Ceremony Passkey Path

Combine current approval signing and passkey PRF unlock behavior into one
ceremony:

```text
navigator.credentials.get({
  publicKey.challenge = hash(approval payload),
  publicKey.extensions.prf.evalByCredential[credential_id].first = credential prf_salt,
  userVerification = required for hardened approval
})
```

The implementation may pin `allowCredentials` to one selected credential or may
offer all non-revoked wallet credentials and resolve the responding
`credential_id` from the assertion before selecting the matching `prf.salt` and
`wrapped_dek`. The PRF output must unwrap only that credential's `wrapped_dek`.

The ceremony handler returns:

- WebAuthn assertion for `approval.json`;
- PRF output to daemon memory only.

The daemon verifies the assertion, derives the wrap key, decrypts the wallet
key, mints a grant, and zeroizes temporary secret material.

### 11.6 Remove `bloom-chain` and `pipe` Signers

The proposed auth plan excludes `bloom-chain` and `pipe` because they sign
outside Sealed Approval. Remove or hard-disable those signing paths before
calling the implementation complete.

### 11.7 Build First-Party `wallet-policy` Petal

Implement the `wallet-policy` first-party Petal in this repository before
calling policy-update support complete. It must stage policy edits as sealed
actions, execute from sealed proposed policy bytes, sign `policy.toml.sig`
through the grant host API, and atomically install `policy.toml` plus
`policy.toml.sig` only after approval and execution succeed.

### 11.8 Implement EVM Owner-Signing Sessions

Implement first-party EVM owner-signing sessions for bounded agent transfers
where no onchain delegation contract is available. The MVP must support a
session that can send up to a configured daily USDC amount to a configured
recipient on a configured chain after one hardened Sealed Approval ceremony.

This implementation must:

- keep owner signing material in daemon memory only;
- persist only non-secret session metadata, frozen caps, counters, and audit;
- deny after daemon restart, crash recovery, expiry, revoke, budget exhaustion,
  or loss of in-memory signing material;
- enforce exact token, recipient, chain, method, TTL, fee policy, and rolling
  daily cap before each signature;
- audit every attempted and successful session use;
- require a new Sealed Approval for any cap, recipient, token, chain, method, or
  TTL expansion.

### 11.9 Implement Cross-Bloom Autonomy and Budgeting

Implement `[autonomy]` wallet policy and a transactional cross-Bloom budget
ledger. The policy must apply before Petal-specific policy and count spending
across `/requests`, `/wallets`, `/payments`, `/defi`, Polymarket, Hyperliquid,
and future Petals.

This implementation must:

- default autonomy to disabled;
- parse USD caps as integer micro-USD;
- enforce allow/deny sets for assets, destinations, surfaces, and action kinds;
- require active bounded authority before any autonomous signature or dispatch;
- reserve budget before signing and count `reserved + spent` against caps;
- release reservations on failed/expired attempts;
- reconcile confirmed receipts conservatively;
- fail closed or halt the session when budget state or required reconciliation
  state is unavailable.

### 11.10 Document Placeholder Petal Digests

Until first-party digest provenance is implemented, hardcode placeholder
`petal_digest` values only behind explicit constants with TODO comments stating
that they are temporary and not a real tamper-evidence boundary. Audit and
status output must identify them as placeholders. Removing placeholder digests
is required before enabling untrusted/dynamic Petals to receive signing grants.

### 11.11 Future Work: OS Lock/Sleep Revocation

Platform-specific revocation on OS sleep, wake, and lock-screen events is
future hardening work. It is not required for the MVP. The MVP must still fail
closed on daemon restart, crash recovery, explicit revoke, expiry, budget
exhaustion, and loss of in-memory signing material.

## 12. Acceptance Criteria

The codebase fully implements this spec when:

1. No command or VFS path can move value or change authority without either a
   central sealed action and signed `approval.json`, or a live standing session
   that was itself minted by a central sealed action and signed `approval.json`.
2. No passphrase/local wallet signing path remains.
3. `write_unlocked` does not exist.
4. Legacy marker files are neither produced nor consumed.
5. All approval records are `bloom.approval.v1`.
6. A normal user action needs one passkey ceremony, not separate approve and
   unlock ceremonies.
7. PRF output, decrypted wallet keys, and grants are never written to disk.
8. Grants are in-memory, short-lived, Petal-scoped, sealed-intent-scoped, and
   auditable.
9. Owner-signing sessions are in-memory-only for owner key material, bounded by
   frozen caps, revoked or orphaned on restart/crash/lost signer, and audited on
   every use.
10. First-party EVM, paid HTTP, DeFi, Polymarket, and Hyperliquid components are
   represented as Petals for authorization purposes.
11. Venue directories are projections over central `/outbox` actions.
12. Petals execute from sealed canonical bytes.
13. Hard policy rules cannot be overridden by Sealed Approval.
14. Restart cannot replay a consumed approval nonce.
15. Tests cover replay denial, stale approval denial, wrong Petal denial,
   wrong intent denial, expired grant denial, local wallet rejection, and
   absence of legacy marker behavior.
16. Tests cover PRF output never crossing VFS/projection serialization
   boundaries.
17. Tests cover daemon-terms/petal-policy digest mismatch rejection,
   disallowed `sign-hash` intent rejection, and attestation rejection when
   attested facts exceed the sealed Petal policy snapshot.
18. Tests cover plan/challenge/intent binding: changing any sealed intent field
   changes the WebAuthn challenge.
19. Tests cover multi-passkey credential selection, revoked credential
   rejection, and per-credential PRF/DEK unwrap.
20. Tests cover system hard rules being uneditable by wallet policy and wallet
   hard-rule weakening requiring hardened policy-update approval.
21. Tests cover `get-policy()` returning only the sealed, intent-committed
   Petal policy snapshot; live policy edits after sealing do not change injected
   bytes.
22. Tests cover post-execution reconciliation detecting results inconsistent
   with signing attestations and freezing/revoking the offending Petal grant.
23. Tests cover the EVM owner-signing session use case: one hardened approval
   mints a session that can send within a `100 USDC/day` configured cap to one
   configured recipient without another ceremony, while wrong token, wrong
   recipient, wrong chain, over-budget, expired, restarted, orphaned, or revoked
   sessions deny.
24. Tests cover cross-Bloom autonomy: a low-value x402 request can execute
   without fresh approval when signed policy, active bounded authority, and
   global budget allow it; the same request denies when policy is disabled,
   budget is exhausted, destination/asset/surface is blocked, or no active
   authority exists.
25. Tests cover budget reservation concurrency: `reserved + spent` prevents two
   simultaneous autonomous actions from exceeding the daily cap.
26. Tests cover deterministic session denial strings such as
   `session_orphaned_requires_reapproval`, `session_budget_exhausted`, and
   `session_scope_mismatch`.
27. Tests assert first-party placeholder `petal_digest` values are labeled as
   placeholders in audit/status output.
28. Tests document the remaining MVP trust boundary: the daemon validates
   attestations against policy, but trusts approved Petals that attestations
   honestly describe `hash32`.

## 13. Suggested Implementation Order

1. Introduce the names and schemas: `SealedAction`, `SignedApproval`,
   `SealedApprovalGrant`, `ActionOutbox`.
2. Remove local wallet creation/unlock from product surfaces; add fail-closed
   migration messaging.
3. Delete `write_unlocked` and legacy marker consumption.
4. Build central `/outbox` and projection plumbing.
5. Convert one first-party Petal end to end, preferably wallet EVM tx confirm.
6. Implement one-ceremony passkey assertion + PRF grant minting.
7. Implement placeholder first-party Petal identity constants with clear TODOs.
8. Implement cross-Bloom autonomy policy and budget ledgers.
9. Implement EVM owner-signing sessions for bounded agent transfers.
10. Convert requests, DeFi, Polymarket, and Hyperliquid.
11. Remove or hard-disable `bloom-chain` and `pipe` signers.
12. Enforce hard/step-up policy taxonomy across all policy engines.
13. Update user docs and examples to use Sealed Approval terminology.

## 14. Current Implementation Anchors

The existing branch already contains pieces that should be reused rather than
reinvented:

| Area | Current anchor |
|---|---|
| Intent hashing | `bloom-auth-api::CanonicalEnvelope::intent_hash` |
| Approval challenge hashing | `bloom-auth-api::UnsignedApproval::challenge_hash` |
| Nonce persistence and burn | `bloom-auth::AuthStore` and `StoreApprovalVerifier` |
| WebAuthn assertion verification | `bloom-keystore::KeystoreApprovalSignatureVerifier` and passkey helpers |
| PRF wallet wrapping | `crates/bloom-keystore/src/passkey.rs` |
| Hyperliquid bounded session precedent | Hyperliquid session policy and handler code |
| EVM wallet policy caps | `crates/bloom-proto/src/policy.rs` and `crates/bloom-tx/src/policy_engine.rs` |
| Polymarket policy/signing | `crates/bloom-proto/src/polymarket_policy.rs`, `crates/bloom-polymarket`, and `../bloom-petal-polymarket/petal/wit` |
| Hyperliquid policy/signing | `crates/bloom-proto/src/hyperliquid_policy.rs` and `crates/bloom-hyperliquid` |

## 15. Documentation Terminology

Use these terms:

- Sealed Approval
- Sealed Approval Ceremony
- Sealed action
- Action Outbox
- Signed approval
- Sealed Approval Grant
- Petal
- Petal-scoped grant

Avoid these terms:

- Layer B
- unlocked write
- local wallet
- passphrase wallet
- marker approval
- out-of-band approval marker
