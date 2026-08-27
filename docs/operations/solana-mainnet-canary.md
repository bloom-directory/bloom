# Solana mainnet-beta canary operations

**Status:** pre-review runbook. No funding or broadcast is authorized by this
document.

This runbook executes one bounded native SOL canary using the capability
described in [`../design/solana-mainnet-canary.md`](../design/solana-mainnet-canary.md).
The ordinary Bloom production artifact remains incapable of mainnet-beta
broadcast.

## Fixed milestone-one envelope

| Fact | Required value |
| --- | ---: |
| Maximum funded balance / total-loss budget | 10,000,000 lamports (0.01 SOL) |
| Exact transfer | 5,000,000 lamports (0.005 SOL) |
| Maximum fee | 10,000 lamports (0.00001 SOL) |
| Maximum total outbound debit | 5,010,000 lamports |
| Transaction count | exactly one |
| Source | fresh final-artifact BIP-39 Solana child |
| Destination | fresh capital-owner-controlled disposable account |

The source balance must equal 10,000,000 lamports after funding. A larger,
smaller, or pre-existing balance aborts the run. Residual funds remain untouched
without a separate authorization. Raising a limit requires a new threat-model
review; lowering the exact transfer still creates a different transaction and
requires a fresh canary sheet and approval.

## Roles and separation

| Role | Authority |
| --- | --- |
| Capital Owner / Funds Approver | Chooses the loss budget and separately approves funding and broadcast. |
| Passkey Ceremony Actor | Completes the exact Broker ceremony; currently the capital owner. |
| Execution Operator | Builds, configures, observes, and reconciles; cannot approve funding or broadcast. |
| Independent Security Reviewer | Approves R1, R2, the canary design/runbook, the artifact facts, and the post-merge range-diff. Must not be the implementation author/operator. |
| Release-Key Custodian | Controls the reviewed bundle-signing private key and does not disclose it to the workspace or CI. Must be named before key generation. |
| Destination Custodian | Controls the fresh destination account; currently the capital owner. |

Record actual names and immutable review links in the canary sheet. The
independent reviewer need not participate live in the passkey ceremony, but the
review must cover the exact runbook and artifact used.

## Review and merge gate

1. Record the exact provisional-review heads for R1, R2, and the canary.
2. Obtain independent provisional approval.
3. Merge and repin Signer, Broker, release-gate, Machine, Solana, and canary
   changes bottom-up.
4. Produce `git range-diff` output from each approved head to its final merged
   head.
5. Obtain independent confirmation that the delta contains only expected
   ancestry, exact immutable pins, lockfiles, compatibility catalogs, and
   approved conflict resolution.

Any semantic code, policy, release-script, or threat-model delta returns the
affected component to full review. The author never resolves this gate alone.

## Release trust gate

The completed CI gates used `--test-signing-key`. Before candidate construction:

1. name the Release-Key Custodian;
2. generate an OpenSSH Ed25519 key on an isolated release host;
3. store the encrypted private key outside the source workspace and CI with
   mode 0600 and a protected offline backup;
4. publish the exact public key and SHA-256 fingerprint in a reviewed release
   authority record;
5. deliver that public key to the install-test host through a separate channel
   and pin it as a root-owned, non-writable trust root;
6. test that a bundle signed by a different key is refused.

The bundle public key, detached-signature public key, install-host pin, and
reviewed fingerprint must match. Key creation, backup, recovery, rotation, and
revocation are evidence-bearing custody events.

## One artifact across every environment

Build a clean candidate once with the explicit non-production canary label.
Build twice, require byte-identical archives, sign with the reviewed key, and
record the binary and bundle SHA-256 values plus every source revision.
The signed payload's `ARTIFACT_CLASS` must be exactly
`solana-mainnet-canary-v1`. Both verification and Linux installation require
the explicit `BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE=true` opt in. The
ordinary production bundle path must reject the same Machine binary.

The exact candidate bytes are copied to:

- isolated Linux installed acceptance;
- wallet backup/restore rehearsal;
- pinned local Agave execution;
- public-devnet RPC/genesis checks;
- mainnet read-only preflight and the canary run.

Do not rebuild per network. With the authorization variable absent, this binary
must refuse mainnet even though devnet remains usable. Recovery, installed
acceptance, and identity reproduction promote the candidate digest to final.
Any rebuild repeats signing, verification, installed acceptance, and recovery
binding before use.

## Network evidence gate

The hard execution gate is a separate-process Machine/Broker/Signer run against
pinned Agave v3.0.0. It must cover two active children, explicit non-default
selection, policy, passkey approval, simulation, one send, finalization,
reconciliation, restart, replay refusal, response loss, wrong child,
destination, amount, fee, stale blockhash, altered message, mixed genesis, and
unreachable endpoints.

Public devnet is a should-have funded rehearsal while faucets remain externally
unavailable. It remains a mandatory live identity test with expected genesis:

```text
EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG
```

The exact artifact must read live genesis, blockhash, fee, simulation, and
account state, reject a mismatched genesis, and refuse mainnet without an
authorization. If devnet SOL becomes available, execute the funded path too.
The independent reviewer must explicitly accept this local-hard/public-should
gate policy.

## Canary sheet

Freeze this sheet before funding:

```text
Capital Owner / Funds Approver:
Passkey Ceremony Actor:
Execution Operator:
Independent Security Reviewer:
Release-Key Custodian:
Destination Custodian:

Machine revision:
Broker revision:
Signer revision:
Service-runtime revision:
Canary binary SHA-256:
Signed bundle SHA-256:
Release public-key SHA-256:
Independent review and range-diff links:

Source address:
Source key fingerprint:
Source canonical derivation path:
Destination address:
Funded balance: 10000000 lamports
Transfer: 5000000 lamports
Fee ceiling: 10000 lamports
Transaction ceiling: 1
Authorization expiry:
Policy/approval expiry:

RPC provider A public hostname:
RPC provider B public hostname:
Observed mainnet genesis A:
Observed mainnet genesis B:
Expected mainnet genesis: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
Abort procedure:
Ambiguous-outcome procedure:
```

Authenticated RPC URLs and API keys never enter this sheet.

## Read-only mainnet preflight

Use two independently operated healthy RPC providers that support finalized
block height, historical signature status, and finalized transaction lookup.
Verify TLS ownership, health, genesis, latest blockhash, fee, and zero source
balance. Every configured endpoint must report the expected mainnet genesis.

Prove again that the ordinary production artifact refuses mainnet and that the
canary artifact also refuses while no authorization is present. Freeze the
canary sheet and obtain independent approval.

## Funding gate

Funding requires a capital-owner approval naming the final sheet digest. Fund
exactly 10,000,000 lamports, wait for finalized confirmation, and verify the
inbound signature and exact balance through both RPC providers. Any different
balance, identity, artifact, revision, or provider observation aborts.

Funding never implies broadcast approval.

## Stage and broadcast gates

Stage exactly 5,000,000 lamports to the sheet's destination. Independently
decode and compare the payer, destination, amount, recent blockhash, final valid
height, fee, genesis, selected fingerprint, and derivation path. Require the
fee to be no more than 10,000 lamports and simulate immediately before approval.

Install the exact Broker policy, complete the passkey ceremony, and create the
artifact-bound authorization with a short expiry. Verify its sibling `.spent`
claim is absent. Any changed fact starts a new stage and ceremony.

Broadcast requires a second capital-owner approval naming the staged transfer
and authorization digests. The engine claims the authorization as spent before
checking every endpoint's live genesis and sending through exactly one endpoint.
There is no retry or failover.

## Ambiguous-outcome reconciliation

The deterministic signature is the only reconciliation identity. Query both
providers with:

- `getSignatureStatuses` and `searchTransactionHistory: true`;
- `getTransaction` at `finalized`;
- `getBlockHeight` at `finalized`.

These calls follow Solana's official
[`getSignatureStatuses`](https://solana.com/docs/rpc/http/getsignaturestatuses),
[`getTransaction`](https://solana.com/docs/rpc/http/gettransaction), and
[`getBlockHeight`](https://solana.com/docs/rpc/http/getblockheight) contracts.
In particular, historical status lookup explicitly sets
`searchTransactionHistory: true`, and expiry is decided by finalized block
height passing the transaction's `lastValidBlockHeight`, as described in
Solana's [transaction confirmation and expiration
guide](https://solana.com/developers/cookbook/transactions/confirmation).

Poll every two seconds during the interactive window, for at most 15 minutes.
A timeout alone proves nothing.

`FINALIZED-ABSENT` requires all of the following:

1. both healthy providers report finalized block height greater than
   `lastValidBlockHeight + 32`;
2. both providers return no historical signature status;
3. both providers return no finalized transaction;
4. all observations agree three times, ten seconds apart.

If those facts are unavailable after 15 minutes, record
`AMBIGUOUS — RECONCILE ONLY`, poll every 60 seconds for up to 24 hours, and do
not restage or resend. Provider disagreement or degraded history support cannot
produce `FINALIZED-ABSENT`.

The authorization remains spent for success, failure, ambiguity, and
`FINALIZED-ABSENT`. A later attempt requires a fresh stage, authorization,
passkey ceremony, capital-owner approval, and independent review of any changed
sheet fact.

## Completion and evidence

Require a durable finalized receipt, independent transaction and balance
verification, a three-service restart, stable audit/receipt state, and replay
refusal. Do not sweep, retire, or move residual funds without another explicit
authorization.

Evidence may contain source revisions, artifact digests, public addresses,
transaction signatures, slots, amounts, fees, balances, sanitized receipt/audit
hashes, and test outcomes. It must exclude mnemonics, seeds, private keys, RPC
API keys or authenticated URLs, isolated-host names/IPs, local usernames or
home paths, service credentials, passkey credential IDs/user handles/PRF data,
authenticator metadata, ceremony URLs/tokens, and raw environment dumps. Scan
the evidence package before publication.

## Hard aborts

Abort before broadcast for missing review, a dirty or unpushed source,
untrusted signing key, artifact or pin mismatch, failed recovery, RPC/genesis
disagreement, unexpected balance, degraded audit or clock, failed simulation,
changed destination/amount/fee, expired authorization/approval/blockhash, or
policy mismatch. After an ambiguous send, the only valid action is
reconciliation.

## Out of scope

Repeatable sessions, aggregate budgets, multiple transactions, larger balances,
tokens, program calls, exchanges, bridges, and generic production mainnet
enablement are milestone-two work. A successful first canary does not authorize
them.
