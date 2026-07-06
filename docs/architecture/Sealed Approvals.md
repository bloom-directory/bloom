# Sealed Approvals

**Status:** architecture overview
**Audience:** Bloom engineers, Petal authors, and implementation agents

Sealed Approval is Bloom's shared authorization model for actions that move
value, change authority, spend budget, mint credentials, or consume sensitive
capability.

The trust boundary between the Bloom Machine and Petals — what is structurally
enforced and what a Petal is trusted with — is described in
[`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md). This document
describes the authorization architecture every Petal must use.

## Summary

Bloom does not authorize sensitive work because a process wrote to a file, a
path had a certain name, or a client claimed that a user approved it. Bloom
authorizes sensitive work through a sealed action and a short-lived grant.

The generic flow is:

```text
Petal stages action
Bloom Machine seals canonical intent bytes
Bloom Machine exposes central outbox action and Petal projections
Bloom Machine issues approval challenge
browser ceremony returns WebAuthn assertion + PRF output
Bloom Machine verifies signed approval
Bloom Machine mints in-memory Sealed Approval Grant
Petal executes from sealed bytes
Petal requests signatures or authority use with structured attestations
Bloom Machine enforces the grant envelope and binds each attestation
Petal enforces domain terms against the sealed policy snapshot
Bloom Machine records audit/result
```

The model is intentionally Petal-neutral. EVM transactions, paid HTTP
credentials, Polymarket onboarding, Hyperliquid owner actions, wallet policy
updates, and future WASM Petals all use the same authorization spine.

## Core Objects

**Action**

A user-meaningful unit of work such as an EVM transfer, paid HTTP payment,
Polymarket onboarding batch, Hyperliquid `approveAgent`, DeFi route, or wallet
policy update.

**Central outbox**

The canonical queue for user-verified actions:

```text
/outbox/pending/<action_id>
/outbox/sent/<action_id>
/outbox/failed/<action_id>
```

Petal-specific folders are projections and staging ergonomics. They do not own
separate approval systems.

**Sealed action**

The Bloom Machine-controlled immutable record for one action. It includes:

- concrete `action_id`;
- wallet/account;
- Petal identity;
- canonical subject bytes;
- Bloom Machine-rendered plan;
- policy checks;
- Bloom Machine grant terms;
- sealed Petal policy snapshot;
- expiry and audit metadata.

Rewriting a venue path must create a new sealed action. It must not mutate an
existing sealed action.

**Petal identity**

The identity of the code allowed to consume the grant:

```text
petal_id
petal_digest
petal_version
```

First-party built-in Petals may temporarily use documented placeholder digests.
Future dynamically loaded Petals need real build/source digest provenance.

**Approval challenge**

A Bloom Machine-issued WebAuthn challenge bound to the sealed action. It commits to
the action id, wallet, surface, Petal identity, intent hash, nonce, assurance,
Bloom Machine terms digest, Petal policy digest, policy version, and expiry.

Approvals bind concrete action ids. They must never bind `latest`.

The `approval_challenge.json` artifact also carries a `ceremony_url` for the
browser ceremony bound to the same challenge. The URL token is single-use,
derived from the challenge's `server_nonce`, and valid until the challenge's
existing `expiry_ms`; there is no separate URL expiry field. Whether the URL
is reachable only on localhost or over the open internet is described in
[`Open-Internet Sealed Approval Ceremony.md`](./Open-Internet%20Sealed%20Approval%20Ceremony.md).

The URL is not part of the challenge hash input. How agents discover this
contract is described in
[`Agent-native Documentation.md`](./Agent-native%20Documentation.md).

**Signed approval**

The `approval.json` artifact. It stores the WebAuthn assertion and echoed
Bloom Machine-issued fields. It contains no PRF output, decrypted key material, or
grant.

`approval.json` is an audit/projection artifact. It is not sufficient by itself
to mint a signing grant unless the same live ceremony delivered PRF output to
Bloom Machine memory.

**Sealed Approval Grant**

A short-lived in-memory grant minted after verification. It is bound to:

- wallet;
- action id;
- intent hash;
- Petal identity;
- Bloom Machine grant terms;
- sealed policy digest;
- signature/authority-use count;
- expiry.

Within a live grant the acting Petal may request signatures up to the signature
count until expiry. The Bloom Machine enforces this envelope but does not bind
the bytes being signed to the approval; see the trust boundary in
[`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md).

It is not persisted. Restarting the process loses the grant and requires a new
challenge/ceremony before more owner-key signing can happen.

**Signing attestation**

A structured claim from the Petal explaining what a signing request means. The
Bloom Machine binds the attestation to the signature and records it in the audit
trail; it does not verify that the claim is true. Checking the claim against
domain limits is the acting Petal's responsibility, and may in future be
delegated to a verifier Petal (see
[`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md)).

Examples of attested facts include amount, token, destination, chain, method,
order side, market, Hyperliquid action type, session id, route steps, or policy
hash.

## Ceremony

The ceremony is one browser/WebAuthn operation that returns two things:

1. a WebAuthn assertion over the Sealed Approval challenge;
2. PRF output for the wallet credential, used to decrypt signing material in
   memory.

Only the WebAuthn assertion may be serialized into `approval.json`. PRF output
must stay on the trusted local ceremony channel and in Bloom Machine memory only long
enough to derive or unwrap the signer material needed for the grant.

The ceremony UI must render the Bloom Machine-produced plan for the same sealed
action that produced the challenge. It must not reconstruct the plan by reading
mutable VFS projection files.

The ceremony page and its API must expose two completion modes, and the user
chooses between them at approval time:

- **grant**: verify the approval and mint the grant only; execution happens
  when the client retries the action;
- **grant + execute**: verify the approval, mint the grant, and execute the
  sealed action immediately in the Bloom Machine.

Auto-execution is not a silent Bloom Machine default; the user decides how the
approved action is executed.

## Interaction Modes

Sealed Approval must work in all Bloom interaction modes described in
[`Interaction Modes.md`](./Interaction%20Modes.md):

1. CLI only;
2. VFS with no long-running Bloom Machine;
3. mounted VFS with Bloom Machine.

The security model is the same in every mode. The difference is which process
owns the live ceremony channel and in-memory grant.

### CLI Only

The foreground `bloom` process owns the whole flow.

For any Petal action, the foreground command may:

```text
stage or load action
attempt execution
issue challenge if approval is required
open browser ceremony
verify and mint grant in-process
retry execution
write result
```

This is the simplest mode because the ceremony, PRF output, grant, signer
cache, and execution retry all live in one process.

### VFS With No Bloom Machine

The user is still running a foreground `bloom vfs ...` command. There is no
long-running Bloom Machine, but the CLI command can build an in-process Bloom Machine and
drive the same state machine as a domain command.

The VFS facade should reuse the Petal's foreground action helper. A VFS write
to an execute/confirm path may stage a challenge, open the browser ceremony,
mint the grant, retry the write, and finish.

### Mounted VFS With Bloom Machine

The mounted filesystem is passive from a UX perspective. A write to the mount
may stage an action or expose an approval challenge, but the Bloom Machine must never
open a browser itself. A mounted write is, however, a safe trigger for
*exposing* the ceremony URL: the client that made the write is expecting the
challenge, correlates it through the action directory it wrote to, and may
deliberately open the URL for the user or forward it over another transport.

Regardless of who opens the browser, the Bloom Machine receives PRF output into
Bloom Machine memory and mints the in-memory grant.

The normal shape is:

```text
agent writes mounted Petal staging path
agent writes mounted confirm path for <action_id>
Bloom Machine seals action, issues challenge, mints ceremony URL, and writes
  approval_challenge.json (including ceremony_url) into the pending
  directory before failing the write
confirm write returns permission denied
agent reads approval_challenge.json from the same pending directory,
  checks action_id and expiry_ms, and opens or forwards ceremony_url
user completes the ceremony and chooses grant or grant+execute
grant: Bloom Machine mints grant; agent retries the confirm write to execute
grant+execute: Bloom Machine mints grant and executes immediately
mounted projections show sent/failed/result state
```

While an unexpired challenge is pending, repeated confirm writes must return
the same challenge and the same `ceremony_url`. The Bloom Machine must not rotate the
nonce or URL on retry; a new URL is minted only after the challenge expires or
is consumed.

## Generic Petal Outbox Pattern

Every Petal action should be expressible as a sealed action in the central
outbox even when the user starts from a Petal-specific path.

The generic lifecycle is:

```text
/<petal>/.../new or Petal command
  -> validates and stages action
  -> writes Petal plan/projection
  -> writes /outbox/pending/<action_id>

/<petal>/.../<action>/confirm or Petal command
  -> loads sealed action
  -> checks policy/session/capability
  -> if grant exists, executes
  -> if grant missing, issues approval challenge and returns approval required

foreground command
  -> loads challenge
  -> runs browser ceremony
  -> verifies approval and mints grant
  -> retries execution

execution
  -> Petal runs from sealed subject bytes
  -> Bloom Machine signs or authorizes only through grant/capability APIs
  -> result and audit are recorded centrally and projected back to Petal paths
```

The path names may differ by Petal. The lifecycle may not.

## Runtime and Petal Responsibilities

The sealed-approval machinery is core Bloom runtime, not Petal code. Petals
supply domain facts; the runtime owns the authorization mechanics. The split
is structural, not a convention: the Petal API does not expose challenge
issuance, ceremony URLs, browser launching, PRF output, or grant minting, so
a Petal cannot violate these structural rules even if it tries. What a Petal is
trusted with — and can therefore still get wrong — is the correspondence between
what it signs and what was approved; that boundary is described in
[`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md).

The Bloom runtime owns, identically for every Petal:

- sealing actions and validating concrete action ids;
- issuing approval challenges and minting ceremony URLs;
- writing `approval_challenge.json`, including `ceremony_url`, into the
  pending projection before failing the triggering write;
- serving the ceremony page and API, including the grant / grant + execute
  choice and the exposure mode
  ([`Open-Internet Sealed Approval Ceremony.md`](./Open-Internet%20Sealed%20Approval%20Ceremony.md));
- never opening a browser itself;
- receiving PRF output into Bloom Machine memory, verifying approvals, and minting
  and enforcing grants;
- reusing an unexpired challenge and URL idempotently across retries;
- central audit and result recording.

Each Petal must provide:

- canonical subject bytes for each sensitive action;
- deterministic action id allocation or Bloom Machine-mediated allocation;
- human-readable plan rendering from sealed bytes;
- policy checks and sealed policy snapshot;
- Bloom Machine grant terms with exact allowed signing/authority intents;
- structured attestation for every generic signing request;
- execution from sealed bytes, not mutable projection files;
- audit events and result projection through the central runtime surfaces;
- interaction-mode support as defined in `Interaction Modes.md`.

When a Petal handler determines that approval is required, it reports
approval-required to the runtime and stops. Everything from that point until
a grant exists — challenge, URL, ceremony, verification, grant — is runtime
behavior.

Petals must not:

- sign directly from cached wallet keys outside a grant or bounded capability;
- treat VFS write origin as approval;
- consume legacy approval markers;
- read live policy for an already sealed action when a sealed snapshot exists;
- persist PRF output, decrypted keys, or grants;
- substitute action steps after approval.

## Foreground Command Decision

The normal foreground command should be the command that executes the action,
commonly named `confirm`.

The command should perform the full state machine:

```text
execute if already authorized
otherwise challenge and run ceremony
then execute
```

Avoid requiring users to run separate `approve` and `confirm` commands for the
ordinary path. A later explicit `approve` command may be useful for debugging
or workflows that intentionally approve without execution, but it is not the
default Petal contract.

## Cross-Petal Examples

**EVM wallet**

The sealed subject is an unsigned transaction or replacement/cancel action.
The grant allows the EVM wallet Petal to request exactly the configured EVM
signing intent for that action.

**Paid HTTP**

The sealed subject is the request, selected payment challenge, spending cap,
and policy facts. The grant allows the paid HTTP Petal to sign the x402 or MPP
credential needed for that request.

**Polymarket**

The sealed subject may be an onboarding batch, order, redeem, withdrawal, or
approval-revocation action. Batch actions must commit to ordered steps and
allowed signing intents for each required owner signature.

**Hyperliquid**

The sealed subject may be `approveAgent`, `usdSend`, owner recovery, or other
owner-signed actions. Once a bounded agent session exists, later trades may use
the session capability without a fresh owner-key ceremony if policy and session
limits allow it.

**DeFi**

The sealed subject is the route and any required approval/settlement steps.
Execution must preserve the approved step order and refuse substitution after
approval.

**Wallet policy**

The sealed subject is the proposed policy or authority change. Hardened
approval is required for authority expansion, credential changes, and re-keying.
