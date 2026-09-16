# Wallet Architecture

**Status:** current overview

The normative security and protocol requirements are defined by
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).
This document summarizes the implemented wallet boundary for engineers and
Petal authors.

## Authority split

- **Signer** owns wallet private keys, credential records, key derivation,
  policy compare-and-swap, counters, replay protection, and signature creation.
- **Broker** understands Bloom policy and action semantics. It owns Sealed
  Approvals, constructs exact reviews, hosts ceremonies, and sends authorized
  operations to Signer.
- **Machine** owns unsigned construction, simulation, public presentation,
  Petal execution, and the mounted VFS. It has no wallet private key, decrypted
  signer, credential secret, local approval database, or signing fallback.

Machine communicates with Broker over the authenticated local transport.
Machine never connects directly to Signer.

## Public wallet state

Machine obtains wallet lists, addresses, public keys, credential summaries,
and signed policy snapshots from Broker through `WalletProjectionReader`.
These projections are public, authenticated, and non-authoritative: altering a
Machine projection cannot authorize custody or signing.

The mounted wallet tree exposes those projections. Wallet creation, import,
credential changes, deletion, and recovery start Broker custody operations and
return ceremony information; Machine does not create or open a keystore.

## BIP-39 roots and derived accounts

The v1 BIP-39 profile accepts a standard English mnemonic only through the
Broker-hosted owner ceremony and exposes no passphrase input.
Passphrase-protected BIP-39 wallets are unsupported and rejected. Signer
stores encrypted root material behind the passkey/PRF wrapping path; Machine
and Broker never persist the mnemonic, seed, passphrase, PRF output, or child
private keys.

Import allocates the canonical EVM child at `m/44'/60'/0'/0/0`. Machine's v1
account-allocation command exposes Solana SLIP-10 children only; additional EVM
children remain unavailable until every EVM transaction and exact-signing
surface can carry an explicit account selector. This avoids creating a wallet
state that existing EVM UX cannot spend from safely.

`bloom wallet import <name>` starts the mnemonic ceremony. The recovery phrase
is entered only in the ceremony browser; it is never a command-line argument.
`bloom wallet import <name> --raw-private-key` is the explicit migration path
for an old local wallet after its secp256k1 key has been exported with the old
offline tooling. The raw key is likewise entered only in the browser. Bloom
does not accept or retain the old wallet passphrase.

Raw-key migration preserves the corresponding EVM account, but it creates an
`imported-secp256k1-scalar` wallet rather than a BIP-39 root. It cannot derive
Solana accounts. A user who needs native Solana support must create or import a
passphrase-free BIP-39 wallet and transfer assets to its derived accounts.
Existing v1 passkey wallets use `bloom wallet migrate-passkey <receipt>`; that
receipt carries public binding data, not the credential secret or root key.

Broker projects public derived accounts through `wallet.accounts`; Machine
exposes the authenticated collection as `wallets/<wallet>/accounts.json`.
A wallet Broker refuses to characterise, having no root key and no active
derived key (every child retired) or legacy BIP-32 custody, still mounts: its
numbered tree is empty and `accounts.json` carries the refusal as
`accounts_unavailable`, so it never blocks its siblings' `/wallets` tree.
Spending from it fails closed with that same reason.
Selection binds the exact `KeyRef` into approval terms and signing identity.
When multiple compatible children exist, omission or ambiguity fails closed
and names the public fingerprints and derivation paths; list order is never an
authority decision. Top-level EVM address compatibility resolves only the
canonical initial child and never falls back to another projected child.

## The numbered account tree

Numbered accounts give every derived family key a stable, permanent home
under the wallet while installed Petals and shared market data stay at
`/petals/<petal>/`:

```text
wallets/<wallet>/
├── kind, projection.json              # wallet-wide identity
├── accounts.json                      # one number per entry (null off-mapping)
├── new                                # create an account (write {request_id})
├── 0/
│   ├── account.json                   # both families, with freshness
│   ├── address.evm, address.evm.qr.*  # EVM address and QR files, when present
│   ├── address.sol, address.sol.qr.*  # Solana address and QR files, when present
│   ├── public_key                     # display-key public-key hex
│   ├── chains/<chain>/...             # chain views and the outbox, this key's
│   └── sessions/<petal>/<slot>/       # session.json + stop for derived keys
└── policy.json, policy-updates/, sealed-approvals/   # wallet-wide
```

Files that name one key (`address.evm`/`address.sol`, their QR images, and
`public_key`) live under a numbered account. Installed Petals are mounted at
`/petals/<petal>/`.

The number is the derivation path itself, not a position in a list: slot `n`
is EVM `m/44'/60'/0'/0/n` and Solana `m/44'/501'/n'/0'`. Signer owns the
numbering — a client never chooses one — and one number carries at most one
long-lived key per family. Resolving a numbered path yields an exact `KeyRef`;
approval and signing bind that exact key, and the daemon re-resolves the owner
from the path against fresh Broker membership before any approval, custody
ceremony, or signature. Machine keeps no trusted number-to-key table: the
rendering comes from the authenticated `wallet.accounts` projection, and
listings, stats, and reads carry no authority side effects (a stale projection
is marked as such in `account.json`).

Chain views and outboxes live under `wallets/<wallet>/<n>/chains/`.
Use the explicit number `0` for the canonical initial child, and the selected
entry's number for any other child.
Match its fingerprint and derivation path in `accounts.json` and verify
`<n>/account.json`; the number is a route to the key, not signing authority.

An account can hold only EVM, only Solana, or both. Its chain listing includes
configured chains for families with Broker-projected addresses; a missing
family or address never causes key allocation or fallback to another account.
Solana `address` and `balance*` leaves live directly under the numbered chain
directory. Retired keys remain readable while present in the projection but
cannot spend. Staged operations
and outboxes are fenced to the staging key, so one account can never see or
confirm another account's pending operations. A body fingerprint naming any
other account is rejected for both families.

Account creation is one owner ceremony per number: a client writes
`{"request_id": "<id>"}` to `wallets/<wallet>/new`, and Signer allocates the
EVM and Solana keys of the next number in one ceremony — every new number has
both families. Retrying with the same `request_id` returns the same ceremony
or, after success, the same account; a conflicting reuse fails; extra fields
are rejected. A legacy or imported single-key wallet is account 0 from its
root key, rendered in the root key's own family.

The session tree (`<n>/sessions/`, core stop, and the install guard) is
described in
[Petal derived key succession.md](Petal%20derived%20key%20succession.md); the
authority invariants they rely on are in
[Sealed Approvals.md](Sealed%20Approvals.md). A mnemonic recovers the
deterministic key tree; it does not recover policies, sessions, or application
secrets, and seed-only recovery never resurrects session approvals.

## Signing

Every retained wallet-signing route sends the exact structured payload to
Broker. Broker validates the payload and policy, obtains the required approval,
and calls Signer. Machine receives public operation state, receipts, and
signatures only. Raw hash-only wallet signing and
`wallets/<wallet>/sign/{message,hash,typed_data}` are not supported.

Petals may generate random bytes, implement cryptography in WASM, store opaque
secret bytes in their package-hash-namespaced private store, and use their own
application keys. Those Petal-owned keys are not Bloom wallet keys. A
Bloom-managed wallet or derived `KeyRef` remains Broker/Signer-only and is used
through the payload-bearing Petal signing protocol.

## Native EVM contract creation

The native outbox accepts an explicit `kind: "deploy"` intent with complete
initcode (including linked libraries and encoded constructor arguments) and an
optional native endowment. `StagedTx` records `ContractCreation` with `to: null`.
Calls retain an address string, including calls to the zero address. Missing
recipients on old call entries are rejected rather than interpreted as creation.

Gas estimation, pre-sign simulation, and both legacy and EIP-1559 unsigned
encoding preserve CREATE. Fee replacement retains that kind; cancellation is
still a separately authorized self-transfer. Sent-entry scanning includes
creation, and successful mined receipts persist the node's actual
`contract_address`. The plan shows the initcode hash and the conditional address
prediction from sender and nonce; constructor effects and ownership are not
verified from arbitrary bytecode.

Creation requires exact payload approval and an explicit canonical policy entry
`{"chain":"evm-<numeric-chain-id>","destination":"exact"}`. Broker verifies the
unsigned transaction preimage against the exact selector, derives the sender
from Signer's authenticated public key, and commits decoded creation/call
fields to the owner review. Machine and Broker require protocol 1.5; Signer
protocol and Petal WIT are unchanged.

`bloom deploy --wallet <wallet> --chain <chain> rpc` exposes a token-authenticated
loopback endpoint for Foundry unlocked scripts, Hardhat remote accounts, and
Ignition. It uses the native wallet/outbox rather than a separate WASM wrapper.
Every submission requires an explicit nonce and gets a durable ID committing
the normalized request, wallet, and chain. Retries return the existing entry;
conflicting nonce use fails closed. Plans, approvals, errors, signed bytes, and
receipts persist in the outbox. Automatic nonce selection includes the node's
pending transactions.

The HTTP request prepares owner review and waits for a real hash. The agent
runs `bloom deploy ... resume <id>` after approval; an idle or disconnected
client does not continue signing in the background. `list` and `status` expose
recovery, including cached artifacts during outages. See the runnable
[Foundry/Hardhat/Ignition guide](../../examples/evm-deploy/README.md) and
[bloom#221](https://github.com/bloom-directory/bloom/issues/221).

## Policy updates

The mounted policy surface uses Broker's policy custody protocol:

1. Machine sends the exact proposed policy bytes to
   `policy.validate_update`.
2. Broker parses and validates the proposal against the
   Signer-authenticated baseline, builds the exact review, and originates a
   Signer `policy_update` ceremony using the review-manifest digest.
3. Machine presents the returned operation identity, review digest,
   `ceremony_url`, and expiry. Shared ceremony status/cancel methods report the
   operation. Machine owns no challenge authority or grant state;
   `approval_challenge.json` is a read-only Broker-derived projection.
4. After ceremony completion, Machine calls `policy.commit_update` with the
   completed ceremony receipt.
5. Broker calls Signer `policy.compare_and_swap` with the proposed bytes,
   ceremony receipt, and Broker validation receipt.

A direct commit, local policy writer, `approval.json`, or `policy-session` path
is not part of the architecture.

## Degraded operation

If Broker is unavailable, Machine may continue cached public reads, unsigned
staging, and simulation where inputs are available. Signing, approvals, policy
mutations, and custody fail promptly. Broker failure never causes Machine to
open legacy authority state or start a ceremony listener.
