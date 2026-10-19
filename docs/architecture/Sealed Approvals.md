# Sealed Approvals

**Status:** architecture overview; triad-aligned
**Audience:** Bloom engineers, Petal authors, and implementation agents

Sealed Approval is Bloom's sole signing-authorization concept. It authorizes
wallet-controlled signatures over Machine- or Petal-originated payloads. It
does not authorize custody changes such as wallet registration, credential
replacement, import, export, deletion, recovery, key derivation, or policy
update; those use the shared custody-ceremony framework.

The normative definitions, state machines, and wire methods are in
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).

## Authority ownership

- **Machine** owns staging, simulation, execution, broadcast, and public VFS
  projections. It has no wallet keys, approval store, decrypted-key cache, PRF
  decryptor, or direct Signer connection.
- **Broker** is the only Machine-facing authority service. It owns canonical
  Sealed Approval terms and lifecycle, review construction, policy evaluation,
  declared-usage budgets, reservations, ceremony HTTP, and authorization
  audit.
- **Signer** owns wallet and delegated keys, credentials, canonical policy,
  independent approval-enforcement state, replay counters, and cryptographic
  signing.
- **Browser** participates in the Broker-hosted ceremony. Sensitive PRF or
  custody input is HPKE-encrypted to Signer; Broker relays ciphertext and
  Machine never receives it.

Petals cannot contact Broker or Signer directly. Machine cannot request a
signature from Signer or reconstruct authority from cached projections.

## Canonical flow

```text
Petal or client stages an action in Machine
Machine calls sealed_approval.prepare on Broker
Broker validates provenance, policy, selector, limits, and review inputs
Broker calls Signer ceremony.prepare
Broker returns approval_id, ceremony_url, expiry, and review digest
Browser completes Broker's ceremony
Broker verifies and calls Signer ceremony.complete
Signer independently verifies and durably activates enforcement state
Machine later calls Broker signing.sign or signing.sign_batch
Broker evaluates policy and reserves limits
Broker presents a short-lived signed request to Signer
Signer enforces key, approval, selector, suite, counters, expiry, and replay
Machine receives only signatures and public receipts
```

Ceremony completion activates an approval only. Execution and broadcast are
separate Machine operations; there is no combined “approve and execute” or
ceremony-and-broadcast mutation.

## Sealed Approval terms

The immutable approval binds at least:

- approval and wallet identity;
- exact `KeyRef` and permitted cryptographic suite;
- an exact-payload selector or installer-pinned Petal selector;
- operation and signature limits, rate limits, declared-value limits, and
  validity window;
- canonical policy version/digest and revocation epoch; and
- the review manifest and provenance record used at preparation.

An exact selector commits to the exact payload or ordered batch. A reusable
Petal selector commits to one package hash and either its legacy singleton
route or a canonical non-empty list of route grants. Each grant binds one
route to its own allowed operation classes and installer-signed provenance
digest, avoiding Cartesian-product authority across routes and classes.
Suites and usage limits remain shared across the approval. It does not silently
become generic wallet authorization.

The canonical approval is durable in Broker. Signer stores the enforcement
projection it independently needs. Machine stores only public status and
launch projections; deleting or altering them cannot authorize a signature.

## Petal claims and trust boundary

Each reusable Petal signing operation carries a normalized `PetalUseClaim`
binding the installed package and actual executing route, operation class, suite, payload
digest, ordered hashes, declared debits and destinations, fee declaration,
nonce, and claim-assurance mode.

Broker verifies the claim's canonical form, provenance, scope, approval
limits, policy, and any configured proof or attestation verifier. In baseline
`machine_asserted` mode Broker does not decode arbitrary Petal payloads to
prove that economic claims are truthful. A compromised Petal or Machine may
therefore consume the remaining approved capacity by lying within that trust
model. Exact selectors prevent payload substitution; reusable selectors rely
on the documented claim assurance.

The `safe.transaction.confirm` operation has an additional review contract. The
trusted signing registration must declare that class to trigger Safe review.
An arbitrary EIP-712 preimage under another signing class receives that class's
ordinary exact review; Machine cannot identify a Safe transaction from its
hash alone. Correctly registering the Safe Petal is part of this boundary.
The Petal supplies one canonical Safe review envelope alongside the exact EIP-712
preimage. Machine accepts and forwards that envelope only for this operation
class, requires it for that class on the single-payload exact path, and refuses
the class on every other path — the batch request and the reusable
single-payload request both carry no envelope field, so each refuses it in its
own validation rather than relying on the other. Broker independently rebuilds
the Safe transaction hash from the envelope and rejects a malformed envelope or
one whose reconstruction does not equal the exact selector. It then reads the
transaction as the `execTransaction` call the Safe will run, with the same
built-in catalog it uses for every EVM call: inner calls, owner and threshold
changes, batches through Safe's MultiSendCallOnly and deployments through its
CreateCall. A delegatecall is read only when it enters one of those Safe
libraries, and a gas refund is not read at all. Anything Broker cannot read is
shown as exact bytes with the reason, and the owner decides.

A Safe-declaring route is limited to that one operation class for now. Machine
keys the envelope requirement on the claim's class and Broker keys it on the
classes the route's installer provenance declares, so a route that declared the
Safe class alongside a second exact-signing class could not sign the second
one.

Only the EIP-712 members are bound that way, and Broker checks nothing else.
The envelope's account of the Safe's own configuration — owner set, threshold,
guard, enabled modules, fallback handler, singleton, singleton code hash and
version — is not part of the preimage, and Broker holds no chain client, so none
of it can be corroborated. It is therefore not matched against pinned tables
either: both operands of such a check would come from the same Petal message, so
it could only refuse an honest Petal reporting a Safe the table has not heard of.
Approval text does not show it. The one fact Broker establishes about the
signer is that the envelope's owner equals the key this approval will sign
with; `safe_tx.to` is an EIP-712 member, so the selector binds the call that is
read. The exact selector remains the signing authority.

Both sides require the envelope. Machine refuses the class without one; Broker
reads the package's installer-signed provenance record, and a package declaring
the class gets no exact approval without an envelope and no reusable approval
that names the Safe class. A claim sent beside an envelope may not declare amounts, destinations
or fees: the rebuilt transaction is the review.

### Payment, authentication and exchange message reviews

Exact Petal signing can carry a bounded `bloom.message.review.v1` envelope in
the existing `PayloadSignRequest.action` field. Machine binds it into the
persisted exact-operation identity and forwards it to Broker through
`message_review_payloads`; it does not interpret the Petal's prose as facts.
Broker reconstructs EIP-712 or EIP-191 preimages, or supported Hyperliquid
ordered MessagePack actions and their Agent domain, and checks the approved
SHA-256 preimage commitment and Keccak signing hash. Every typed leaf is read
from the signed value. Known ERC-3009 and HyperCore payment claims must match
the signed debit, recipient and value limit. Quoted outputs, available balances,
fees not in the signature, proof validity and settlement remain unverified.

The known exact-message classes in Broker API's
`MESSAGE_REVIEW_OPERATION_CLASSES` require full envelopes and refuse opaque,
batch or reusable downgrades. This does not turn an existing delegated agent
grant into a fresh owner ceremony for each future action. Full per-call
interpretation and reusable scope enforcement are separate properties.

Delegated `hyperliquid.agent_action` uses also forward the full ordered action
witness through the existing `claim_assurance_evidence` channel. Broker
reconstructs and checks the actual signing preimage before reserving authority
or requesting a signature, including uses of older grants. The assurance stays
`MachineAsserted`; local session caps, market identities and venue effects are
not thereby verified. Matching Hyperliquid packages are required because old
hash-only agent callers are refused. No per-trade owner ceremony is added.

Polymarket's current caller uses the batch host API with one prepared record.
Machine forwards that complete record for exact orders, wallet permissions and
relayer batches; Broker reconstructs the ERC-7739 order or DepositWallet Batch.
The outer exact preimage/hash, selected owner and every call remain bound.
Unrecognized call contents remain explicit, and auxiliary draft labels never
become signed facts. pUSD is a separate Polygon token, not Circle USDC.

Polymarket orders remain exact approvals. The Trader persona proposed in
Bloom #352 cannot submit `polymarket.order.poly1271` with a reusable selector.
Do not remove the exact-review requirement to make that caller work. A future
delegated trading profile needs a separate versioned class, Broker verification
of each order against its approved bounds, and Signer-enforced usage limits.
Until that profile exists and is tested across the services, the persona must
use exact approval or leave automated Polymarket trading unavailable.

CLOB authentication uses the distinct immutable `polymarket.clob_auth.v1`
permission: one operation/signature, Polygon ClobAuthDomain version 1, selected
owner, nonce zero, fixed wallet attestation and a timestamp within 300 seconds
of Broker's guarded clock at use. The review describes this future profile,
not an invented exact hash. Broker reconstructs the actual 66-byte preimage
before reserving budgets or requesting a signature. Any wider profile needs a
new class; old `polymarket.onboard` reusable grants are refused at preparation
and use. The caller can refresh Polymarket server time after owner approval.
This signature can create or derive API credentials; those credentials confer
account API access and must not be described as harmless read-only login.

Broker's compiled catalog binds token units/artwork to exact chain/address
identities. Mainnet HyperCore USDC uses an explicit venue/asset identity;
test collateral and unknown assets do not borrow its mark. Protocol readers
remain bounded: Enso source inputs do not establish shortcut effects, and a
Privacy Pools direct withdrawal does not establish ZK-proof validity or relay
recipient semantics. Unknown content retains an explicit missing-coverage reason.

Enso Router V2 `safeRouteSingle`/`safeRouteMulti` also expose the actual receiver
and requested token/native balance-increase minimums. Output units come from
their own encoded token identity; native minimums never borrow transaction
value. Empty output checks warn explicitly. These requested constraints do not
prove code, shortcut effects, fees, received funds or settlement.

### Pump Solana transaction review

The four `pumpfun.buy`, `pumpfun.sell`, `pumpfun.close_token_account` and
`pumpfun.launch` classes require one raw Ed25519 message and a one-operation,
one-signature approval. Machine forwards the actual legacy or v0 message from
the existing batch host call. An app-supplied review cannot replace it. Broker
checks the selected Signer-derived fee payer and the actual message commitments,
then reads supported Pump/PumpSwap, System, Compute Budget, ATA and SPL Token
instructions from their bytes. Unknown instructions retain their raw data and
coverage reason. Token amounts without trusted mint metadata stay in raw units;
they never borrow another token's decimals or artwork.

The owner approves the full message with only its recent blockhash excluded
from the approval binding. Broker recovers that binding from the exact durable
review manifest and checks it again before reserving authority or signing.
Changing instructions, accounts, amounts, programs, lookup references or their
order requires a new review. Machine includes the same binding in its durable
request identity, so old opaque grants are replaced and blockhash-only retries
retain the reviewed identity. No SDK ABI or native Solana proof digest changes.

Blockhash refresh is permitted before the single signature is consumed. It is
not permission to sign a second transaction after the first signature exists.
Broker requires `max_operations = 1` and `max_signatures = 1`; the authority
reservation and Signer's counters enforce those limits. A changed blockhash
after signing must not receive another signature under that approval, even if
the first transaction has not expired or its submission outcome is unknown.

This is structural interpretation, with `MachineAsserted` claim assurance.
It does not establish cluster identity, blockhash freshness, address-table
contents, program code/CPI effects, token metadata, execution or settlement.
The requested priority-fee ceiling is derived only when both compute-unit limit
and price are present exactly once; it excludes base and program fees. Pump
launch may include a separate mint cosigner outside this owner-signature call.

Publish matching Gasless, Venice, Hyperliquid and Polymarket packages with the new services.
Old hash-only caller packages cannot satisfy the required exact-message review.
This is a coordinated package compatibility change, not a new SDK signing ABI
or a new wallet clear-signing mode.

### Caller and catalog migration

`reviewMode` is removed from intents, staged transactions and deploy requests.
Callers must omit it; strict deploy request decoding rejects the obsolete
field. There is no replacement opt-in flag. Broker derives the review from
the actual transaction and the registered signing class, and known message
classes require their full review envelopes.

Before shipping this combination, publish the compatible Petal packages and
update `github_source.rs` release commits, archives, package hashes, lineage
predecessors and authority routes together. Existing wallets must approve the
new package identities. A source branch or local package build is not a
published catalog release. Keep required reviews enforced while those releases
are pending; the old catalog is not compatible merely because Machine CI passes.

When combining Bloom #322 and #293 with the compiled token catalog, policy
symbols must resolve uniquely back to the same chain/address. Ambiguous tickers
must not authorize multiple tokens. Typed pUSD funding checks the user's deposit
wallet as recipient, not the pUSD contract. Use a specific recipient approval
or an explicitly approved Petal destination rule; do not widen the default
recipient allowlist to accommodate every deposit wallet.

Candidate verification records are retained under
[`tests/evidence`](../../tests/evidence). They record revisions and fixture
limits, not blanket release acceptance. In particular, the
[`route inventory`](../../tests/evidence/all-petal-route-coverage-2026-10-19.json)
and [`Enso roundtrips`](../../tests/evidence/enso-route-review-2026-10-19.json)
do not prove funded venue effects or physical-owner acceptance.

Petals always submit complete payload bytes through a payload-bearing host
call. Hash-only guest signing is unsupported. Machine may validate guest
capabilities and provenance, but only Broker can authorize and only Signer can
produce the signature.

## Ceremony and public projection

Broker owns the canonical `http://localhost:18734` ceremony application,
review, session token, origin checks, rate limiting, and browser API. Before
returning a launch URL it obtains Signer's signed ceremony contribution and
binds that contribution into the WebAuthn challenge and rendered review.

`sealed_approval.prepare` returns the public preparation fields:

```text
approval_id
state = AWAITING_CEREMONY
ceremony_url
ceremony_expires_at
review_manifest_digest
```

The URL is a single-use owner-readable launch secret. Machine may expose it
only under the originating action or deliberate CLI response; it must not log
it, expose it to a Petal, proxy ceremony HTTP, or rebuild it from local state.
Preparation is idempotent by operation ID and immutable request digest.

Browser returns the raw WebAuthn assertion to Broker. For local encrypted
custody, Browser separately HPKE-encrypts PRF output to Signer. Broker verifies
its part and relays the unchanged assertion and ciphertext through
`ceremony.complete`; Signer independently verifies the assertion, contribution,
scope, RP/origin, user verification, and encrypted-input binding before
activation.

After activation, expiry, cancellation, or failure, Machine clears the URL and
retains only terminal public status. Machine restart reconstructs projections
from Broker rather than local approval artifacts.

## Signing use

For each operation Machine sends Broker the exact payload, operation identity,
approval identity, public key reference, suite, and applicable Petal claim.
Broker loads the active approval and current canonical policy, validates the
operation, durably reserves budgets/counters, and sends Signer a short-lived
Broker-signed request.

Signer independently checks Broker authentication, approval activation,
wallet and `KeyRef`, selector, suite, operation identity, expiry, revocation,
rate backstops, signature counts, and replay. Its signing receipt and Broker's
validation receipt bind the public result to both decisions. Machine never
receives the internal Broker-to-Signer request or any backend credential.

Approval revocation, expiry, counter exhaustion, policy mismatch, Broker
unavailability, or Signer unavailability fails closed. Machine cannot fall
back to a local key, old approval artifact, retired local authorization state,
or hash-only adapter.

## Petal-scoped delegated keys

A Petal that needs a delegated identity uses the generic key-derivation custody
workflow. Signer derives and owns a child `KeyRef` whose immutable scope binds
the wallet, parent key, installer-pinned package hash, route, derivation
purpose, allowed suites, and lifecycle. Petal and Machine receive public key
metadata only. Every use still requires a matching Sealed Approval and is
independently scope-checked by Broker and Signer. Machine may provision one
reusable approval immediately after key derivation, covering only the typed
routes and route-specific classes present in both the immutable derived-key
scope and installer-signed provenance. Machine retains the public approval
binding with the `KeyRef`; the Petal receives neither an approval capability
nor another ceremony for each matching action.

For manifest-scoped Petals, canonical route patterns, operation classes,
crypto suites, and the maximum lifetime are authenticated package bounds. The
component may request narrower classes, suites, or lifetime, but Machine
rejects widening and supplies the resolved route IDs itself. Packages predating
that complete manifest scope retain their legacy request semantics only as a
compatibility path.

Petals construct venue actions through the generic custody/signing interfaces;
Machine and Signer do not implement a native venue account or submission flow.
Broker independently reads supported signing formats before owner approval.
An installed Hyperliquid Petal uses the generic derived-key scope instead of a
native Machine agent-session key.

## By-key revocation and Exact survival

`sealed_approval.revoke_for_key` revokes every Sealed Approval whose terms
bind one key. Broker resolves the set from its own journal, so a caller whose
record of approval ids is stale still stops all of the key's automation, and
the method is idempotent. Prepared and awaiting-ceremony approvals are
cancelled by the same journaled operation; a pre-stop ceremony cannot complete
into a usable approval afterwards. Machine uses it for the session `stop`
write and treats only terminal reports (revoked, failed, exhausted, expired,
cancelled, orphaned) as success.

An Exact approval drops only the scope-expiry comparison: wallet, route,
package, suite, operation class, and lifetime restrictions still bind, and
reusable approvals still expire on the key scope. Consequently a stopped or
expired Petal session can still obtain a fresh payload-specific Exact approval
within the key's remaining restrictions — that is the recovery path its
`eligible_exact_routes` projection points at, not a bypass of the stop.

## Separation from custody and policy updates

Custody ceremonies share Broker's browser origin and common ceremony status,
cancel, expiry, HPKE, and audit mechanisms, but they produce custody receipts
rather than Sealed Approval activation receipts.

Policy update is a `policy_update` custody ceremony. Machine calls
`policy.validate_update`; Broker parses the proposed bytes, verifies the
Signer-authenticated baseline, constructs the exact review, and originates the
Signer ceremony. After completion, `policy.commit_update` calls Signer's
compare-and-swap with the proposed bytes, ceremony receipt, and Broker
validation receipt. There is no direct Machine policy writer or commit path
without a completed receipt.

## Client surfaces

Foreground CLI, foreground VFS facade, and mounted VFS all use these same
Broker and Signer methods. A foreground client may deliberately open the
Broker-provided URL. A mounted write never opens a browser; it projects the URL
for the expecting client to open or forward. See
[`Interaction Modes.md`](./Interaction%20Modes.md).
