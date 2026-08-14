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
