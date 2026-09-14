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
├── accounts.json                      # one number per entry (null off-mapping)
├── new                                # create an account (write {request_id})
├── 0/
│   ├── account.json                   # both families, with freshness
│   ├── chains/<chain>/...             # chain views and the outbox, this key's
│   ├── petals/<petal>/...             # installed Petals, account-scoped
│   └── sessions/<petal>/<slot>/       # session.json + stop for derived keys
└── policy.json, sealed-approvals/, capabilities/   # unchanged
```

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

Wallet-level paths keep their meaning by resolving to account 0: the canonical
initial child of each family, even after further children exist. The
wallet-level outbox is account 0's outbox with the same fence as the numbered
tree — it stages from account 0's key, shows only the entries that key staged,
and a body fingerprint naming any other account is an error for both families;
staging from account N goes through `wallets/<wallet>/<n>/`. An
account can hold only EVM, only Solana, or both; reading a missing family
returns a specific missing-key error and never allocates a key. Retired keys
remain readable but cannot spend. Staged operations and outboxes are fenced to
the staging key, so one account can never see or confirm another account's
pending operations.

Account creation is one owner ceremony per number: a client writes
`{"request_id": "<id>"}` to `wallets/<wallet>/new`, and Signer allocates the
EVM and Solana keys of the next number in one ceremony — every new number has
both families. Retrying with the same `request_id` returns the same ceremony
or, after success, the same account; a conflicting reuse fails; extra fields
are rejected. A legacy or imported single-key wallet is account 0 from its
root key, rendered in the root key's own family.

Account-scoped Petal dispatch and the session tree (`<n>/sessions/`, core
stop, and the install guard) are described in
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
