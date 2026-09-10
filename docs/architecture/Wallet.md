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
