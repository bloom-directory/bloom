# Solana mainnet-beta canary: how to run one

This runbook sends one bounded native SOL transfer on mainnet-beta through the
full Machine → Broker → Signer path (BIP-39 child, passkey ceremony, broadcast,
reconciliation). The mechanism is described in
[`../design/solana-mainnet-canary.md`](../design/solana-mainnet-canary.md).

The only things that make a mainnet send possible are in code: a binary built
with the `mainnet-canary` feature, and one authorization file bound to that
binary. There is no sign-off, reviewer, custodian, or CI prerequisite. Build
it, write the file, run it.

## 1. Build the canary Machine

```sh
BLOOM_MAINNET_CANARY_ARTIFACT=1 \
  cargo build --release -p bloom --features mainnet-canary
sha256sum target/release/bloom     # needed for the authorization file
```

Without `BLOOM_MAINNET_CANARY_ARTIFACT=1` the build fails on purpose; that is
the whole guard against a release accidentally carrying the feature. Broker
and Signer are unchanged — use whatever builds you already run on devnet.

## 2. Configure the mainnet chain

```toml
[solana_chains.solana-mainnet]
name = "solana-mainnet"
allow_broadcast = true
expected_genesis_hex = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
[[solana_chains.solana-mainnet.endpoints]]
url = "https://<your mainnet RPC>"
weight = 100
```

Config validation only accepts this on a canary binary that holds an
authorization naming `solana-mainnet` (step 4); a production binary rejects it.

## 3. Wallet and funding

Create (or use) a BIP-39 wallet and allocate a Solana child exactly as on
devnet. Note the address, key fingerprint, and derivation path
(`m/44'/501'/<account>'/0'`) from `wallet address`. Fund the address with the
amount you are willing to lose. The authorization's `max_balance_lamports` is
checked against the *live* balance at send, so fund at or below that number.

## 4. Write the authorization

Point `BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION` at a JSON file:

```json
{
  "schema": "bloom.solana-mainnet-canary/1",
  "artifact_sha256": "<sha256 of target/release/bloom>",
  "chain": "solana-mainnet",
  "wallet": "<wallet name>",
  "key_fingerprint": "<hex fingerprint from wallet address>",
  "derivation_path": "m/44'/501'/0'/0'",
  "source_address": "<base58 source>",
  "destination": "<base58 destination>",
  "max_balance_lamports": 10000000,
  "transfer_lamports": 5000000,
  "max_fee_lamports": 10000,
  "max_transactions": 1,
  "expires_ms": <unix ms, e.g. now + 1h>
}
```

Rules enforced by the binary (`bloom-proto/src/canary.rs`):
`max_transactions` must be `1`; `transfer_lamports + max_fee_lamports` must
fit in `max_balance_lamports`; the derivation path must be canonical; the
artifact hash must match the running binary; the file is refused after
`expires_ms`. A sibling `<file>.spent` is created *before* the send and the
authorization is dead afterwards, success or not — for another transaction,
write a new file.

## 5. Stage, approve, broadcast

Same commands as devnet, with the Machine started as
`BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION=<path> bloom ...`. Stage a
transfer of exactly `transfer_lamports` to `destination`, complete the passkey
ceremony, broadcast. The engine re-checks every value in the file against the
staged transfer and the live balance immediately before the single send; any
mismatch refuses. Boot logs
`daemon.solana_mainnet_admitted_under_canary_authorization` when the
authorization is accepted and `daemon.solana_mainnet_refused_by_genesis` when
it is not (wrong hash, expired, spent, wrong chain).

## 6. If the response is lost

There is no retry or failover by design. Reconcile by the deterministic
signature: `getSignatureStatuses` (with `searchTransactionHistory: true`),
`getTransaction` at `finalized`, and `getBlockHeight` at `finalized`. If
finalized height has passed `lastValidBlockHeight` and no status exists, the
transaction expired unsent. Either way the authorization stays spent; write a
new one to try again.

## Scope

One transaction per authorization file. Tokens, program calls, and a generic
production mainnet switch are not covered by this mechanism.
