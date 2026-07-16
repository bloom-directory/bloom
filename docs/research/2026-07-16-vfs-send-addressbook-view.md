# Issue 114: VFS Send and AddressBook view

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Make Send a trusted review flow over an exact staged transaction, with AddressBook and
outgoing history supplying recipient context:

```text
/wallets/<wallet>/send.json                         preparation facts for agents
/wallets/<wallet>/send.md                           universal readable overview
/wallets/<wallet>/send.html                         optional rich overview
/wallets/<wallet>/chains/<chain>/outbox/pending/<id>/review.{json,md,html}
/addressbook/...                                    user-saved contacts
```

The overview is read-only. Agents continue to stage through the existing
`outbox/new.tx` path, and confirmation remains behind policy and Sealed Approval. HTML
must not introduce a second transaction builder or a form that bypasses the outbox.

The central rule is:

> The passkey approval must cover both the exact bytes the wallet will sign and the
> exact interpretation Bloom showed the user.

## Signing integration

There are two signatures in a passkey-wallet send:

```text
Petal or native code constructs an unsigned transaction
  -> Bloom finalizes chain, nonce, fees, value, and calldata
  -> Bloom decodes and simulates those exact bytes
  -> Bloom seals one canonical review snapshot
  -> WebAuthn approves the snapshot's intent hash
  -> the wallet key signs the exact EVM signing hash
  -> Bloom broadcasts and later records receipt-derived effects
```

The sealed snapshot should commit to the EVM signing hash, raw transaction fields,
host-verified facts, Petal package and descriptor digests, app-claimed descriptions,
policy result, and the reviewed simulation digest and validity window. The three review
formats are pure daemon-owned projections of that snapshot; HTML markup itself is not
the signed source of truth.

Any transaction-field change produces a new signing hash. Any changed descriptor or
displayed semantic claim produces a new interpretation digest. Material simulation
drift or expiry refuses signing and creates a new review. Decoder failure falls back to
an explicit raw-contract-call warning rather than blocking basic signing or inventing
meaning.

Bloom already seals the EVM signing hash, Petal identity, policy snapshot, and exact
nonce/fee/call facts in
[`tx_engine.rs`](../../crates/bloom-tx/src/tx_engine.rs). This proposal extends that
canonical subject; it does not replace Sealed Approval.

This mechanism applies only when Bloom possesses the unsigned transaction preimage. A
generic `sign-hash(hash32)` cannot be decoded safely. EIP-712 orders and other off-chain
messages need a separate typed-signing envelope; a Petal must not explain an opaque hash
and have that explanation treated as proof.

## Recipient resolution

Resolve a recipient into a typed, chain-qualified record before staging:

```json
{
  "input": "alice.eth",
  "account_id": "eip155:8453:0x1234...abcd",
  "address": "0x1234...aBcD",
  "source": "ens",
  "resolved_on_chain_id": 1,
  "resolved_at_block": 24000000,
  "resolved_at_ms": 1784217600000
}
```

Show both the user input and full resolved address. Re-resolve ENS immediately before
issuing the approval challenge; a changed result requires a new stage and review. A
saved alias should resolve through the same shared service, and its selected account
must match the transaction chain.

The AddressBook model should become `contact -> chain-qualified accounts`, rather than
one global `alias -> address`. One contact may hold accounts on multiple chains, but a
history-derived candidate should initially contain only the exact
[CAIP-10](https://standards.chainagnostic.org/CAIPs/caip-10) account observed. Legacy
TOML entries can remain readable as explicitly unscoped EVM aliases until the user
assigns chains.

First fix the current ownership bug: the daemon loads one immutable `AddressBook` copy
for wallets, simulation, and DeFi, while `AddressBookHandler::open` loads a separate
mutable copy. A VFS write can therefore persist successfully but remain unavailable to
Send until restart. All consumers need one shared, revisioned AddressBook service.

## What outgoing history can safely provide

Start with successful mined transactions from Bloom's own outbox; they have the best
local provenance. Add explorer/indexer history later as an explicitly sourced coverage
extension.

Derive counterparties from typed effects, not merely `transaction.to`:

- Native transfer: the direct destination.
- ERC-20/721/1155 transfer: the verified transfer recipient and asset contract.
- Approval: the spender is a permission subject, not a payment contact.
- Router, bridge, and arbitrary contract call: do not treat the called contract as a
  person. A beneficiary counts only when Bloom can verify that role.
- Failed, replaced, cancelled, incoming, and self-transfers: do not contribute.

After the second successful direct outgoing transfer from the same wallet to the same
chain-qualified account, surface an optional **Save contact?** suggestion. Never
auto-save. Include the two transaction hashes, first/last-seen times, assets, and
whether the destination had code at the send block. A contract or smart account may be
saved, but it must not be silently labelled a person.

Incoming senders and tiny unsolicited transfers must never become default recipients;
that would create an address-poisoning path. Agent inference may explain unusual calls,
but it cannot increment the contact counter, alter policy, or save a contact.

## Transaction interpretation

Use three layers:

1. **Bloom core decoder:** host-verifies standard native, ERC-20, ERC-721, and ERC-1155
   transfers and approvals from exact calldata, simulation, and receipts. Only these
   facts may drive policy or contact suggestions.
2. **Declarative Petal descriptor:** a Petal may ship a content-addressed, exact-context
   description using a pinned subset of draft
   [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730). Bind it to chain, contract or
   proxy context, and selector. Bloom performs parsing and rendering; protocol labels
   remain `app-claimed` unless Bloom verifies them.
3. **Executable decoder, only if proven necessary:** a future separate Component Model
   world may handle protocols that descriptors cannot express. It must be pure,
   networkless, statically matched, resource-bounded, and display-only by default.

Selector-only matches are insufficient because unrelated functions can collide. Safe's
decoder similarly distinguishes full contract-and-chain matches from partial and
function-only matches
([Safe decoder service](https://docs.safe.global/core-api/safe-decoder-service-reference)).
Simulation and receipts remain separate evidence because they report likely or actual
asset changes, not merely calldata labels
([Alchemy asset-change simulation](https://www.alchemy.com/docs/data/simulation-apis/transaction-simulation-endpoints/alchemy-simulate-asset-changes)).

Trust is per fact: a parameter value may be host-derived from bytes while its label or
business meaning is app-claimed. Conflicting claims should be shown as conflicts, not
resolved by whichever decoder ran first.

This closes a concrete current gap: the Petal outbox converts every Petal transaction
to `RawIntentBody::Raw`, so it loses typed token/NFT metadata. The sealed subject then
falls back to treating a metadata-free call as a native transfer whose recipient is the
called contract. Core interpretation must run before policy and review so a router or
token contract is not presented as the beneficiary.

## Minimal data contracts

`TransactionInterpretation` should carry the transaction digest, phase (`staged`,
`simulated`, or `mined`), decoder/descriptor provenance, verified facts, app claims,
evidence references, warnings, and conflicts. Use the existing `app-claimed` versus
`host-verified` vocabulary from the Petal parity specification.

`ContactCandidate` should carry wallet, CAIP-10 account, successful-outgoing count,
first/last seen, assets, evidence transaction hashes, destination classification, and
provenance. It is advisory state, not an AddressBook entry.

## Suggested implementation sequence

1. Replace copied AddressBook instances with one shared revisioned service; introduce
   chain-qualified contact records and compatible legacy reads.
2. Add a core `TransactionInterpretation`/effect decoder for every staged raw or typed
   EVM transaction, including transactions staged by Petals.
3. Persist exact `review.json`, `simulation.json`, and pure Markdown/HTML projections;
   bind their canonical interpretation to the existing sealed intent.
4. Derive outgoing counterparties from successful receipts and add the second-send
   contact suggestion, with poisoning and contract-recipient tests.
5. Add version-pinned declarative Petal descriptors. Introduce executable decoders only
   after real protocol fixtures demonstrate that descriptors are insufficient.

V0 is ready when a newly saved contact works immediately, ENS and raw addresses are
reviewed chain-specifically, every passkey approval is bound to the exact interpreted
transaction, and contact suggestions arise only from verified successful outgoing
effects.
