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
Selection binds the exact `KeyRef` into approval terms and signing identity.
When multiple compatible children exist, omission or ambiguity fails closed
and names the public fingerprints and derivation paths; list order is never an
authority decision. Top-level EVM address compatibility resolves only the
canonical initial child and never falls back to another projected child.

## The numbered account tree

**Status:** planned. This section lands with milestone M1 of the HD accounts
plan and does not describe shipped behavior yet.

Numbered accounts give every long-lived family key a stable, permanent home
under the wallet while installed Petals and shared market data stay at
`/petals/<petal>/`:

```text
wallets/<wallet>/
├── accounts.json                      # gains a number per entry
├── accounts/
│   ├── new.json                       # create an account (write)
│   ├── operations/<request-id>/status.json
│   └── 0/
│       ├── account.json               # both families with freshness
│       ├── evm/key.json, address, public_key, chains/<network>/...
│       ├── solana/key.json, address, public_key, chains/<network>/...
│       ├── petals/<petal>/<network>/...
│       └── sessions/<session-id>/...
└── policy.json, sealed-approvals/, capabilities/   # unchanged
```

The number is a permanent account slot, not a position in a list and not
necessarily a BIP-44 account field. Signer owns the binding: one slot binds at
most one long-lived key per family, a binding is unique for
`(wallet, slot, family)`, and neither a slot number nor a retired binding is
ever reused. Resolving a path yields an exact `KeyRef`; approval and signing
continue to bind that exact `KeyRef`, and Broker revalidates the slot binding
before authorizing an effect. Machine keeps no trusted number-to-key table.
Fingerprint selection remains available for diagnostics and compatibility.

Ordinary new slots use the existing derivation profiles:

| Slot | EVM path | Solana path |
|---|---|---|
| 0 | `m/44'/60'/0'/0/0` | `m/44'/501'/0'/0'` |
| 1 | `m/44'/60'/0'/0/1` | `m/44'/501'/1'/0'` |
| n | `m/44'/60'/0'/0/n` | `m/44'/501'/n'/0'` |

Wallet-level paths keep their meaning by resolving to account 0: the canonical
initial child of each family. Explicit fingerprints still override the
wallet-level default. An account can hold only EVM, only Solana, or both.
Reading a missing family returns a specific missing-key error and never
allocates a key; `account.json` reports missing, pending, active, or retired
bindings. Retired keys remain inspectable, and writes requiring a retired key
fail. Listings and metadata reads never create accounts, sessions, approvals,
or transactions.

Account creation is one owner ceremony per slot: a client writes
`{"request_id": ..., "families": ["evm", "solana"]}` to `accounts/new.json`,
Signer reserves the next slot across all allocation lifecycles, and the
returned custody ceremony activates each requested family. Retrying with the
same `request_id` returns the same operation; a conflicting reuse fails; a
failed family is retried without allocating another slot; cancellation never
recycles the reserved number. If one family succeeds and another fails, the
successful binding is kept and the partial result stays visible.

Existing keys keep their addresses and history. Existing default-profile
children pair into slots by derivation ordinal, never by list order; a
supported non-default path is bound explicitly to an unused slot; imported
single keys occupy slot 0 with no HD path. A mnemonic recovers the
deterministic key tree; it does not recover labels, exceptional slot grouping,
allocation history, policies, sessions, or application secrets — a full Bloom
backup restores those, and seed-only recovery never resurrects session
approvals. Staged operations, outboxes, and receipts are indexed by the exact
key and network, so one account can never see or confirm another account's
pending operations.

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
