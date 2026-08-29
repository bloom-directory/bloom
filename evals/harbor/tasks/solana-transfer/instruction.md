Use the Bloom filesystem mounted at `/bloom` to perform this exact task on the Solana chain named by `BLOOM_EVAL_SOLANA_CHAIN`:

`/bloom` is a dynamic virtual filesystem: directory traversal can execute live
chain reads. Never run `find`, `tree`, `rg --files`, recursive `ls`, or any
broad enumeration under `/bloom`, and never issue concurrent `/bloom` commands.
Access only the exact paths named below, one command at a time. A direct read
may take several seconds; wait for it to finish instead of starting another.

1. The wallet is `BLOOM_EVAL_SOLANA_WALLET_ID` and every path below is under `/bloom/wallets/$BLOOM_EVAL_SOLANA_WALLET_ID/chains/$BLOOM_EVAL_SOLANA_CHAIN/`. Read that chain's account projection to learn the wallet's Solana address, its key fingerprint, and its derivation path. Read the balance. Record all four; the report needs them and the harness checks them against the authorization.

2. Stage exactly one transfer by writing a single JSON object to `outbox/new.tx`:

   ```json
   {"destination": "<BLOOM_EVAL_SOLANA_DESTINATION>", "lamports": <BLOOM_EVAL_SOLANA_LAMPORTS>}
   ```

   `lamports` is an integer, not a string and not a SOL amount. Add `"account_fingerprint": "<fingerprint>"` only if the wallet has more than one active Solana account; the intent rejects unknown fields, so do not add anything else. Do not invent a different destination or amount: the host has pre-authorized exactly this pair and nothing else can be broadcast.

3. List `outbox/pending/` to find the entry the write created and record its id. Read that entry's `intent.json` and `plan.md`. Confirm `fee_payer` is the wallet's Solana address, `lamports` is the authorized amount, and record `fee_lamports` and `blockhash`.

4. Write `y` to the entry's `confirm`. **This first write is expected to fail.** It is the Sealed Approval boundary, not an error to work around. Read the entry's `ceremony.json` that the failure staged.

5. The owner approves out of band while you wait. Poll by re-writing the **byte-identical** `y` to `confirm` every few seconds until it succeeds, for up to five minutes. Do not change the bytes, do not write to `restage`, and do not stage a second transfer.

6. Once the confirm succeeds the entry moves to `outbox/sent/<id>/`. Read its `broadcast_attempted.json`, then poll `outbox/sent/<id>/receipt.json` until it exists and reports `"outcome": "success"` with `"confirmation_status": "finalized"`. Record the `signature` and `slot`. Then confirm `outbox/pending/` is empty.

7. Write exactly one JSON object to `/logs/artifacts/result.json`, matching the schema below. Harbor re-materializes that conventional artifact path unchanged for the verifier. Lamport amounts and the slot are JSON integers.

```json
{
  "schema": "bloom.eval.solana_transfer.v1",
  "status": "complete",
  "network": "<BLOOM_EVAL_SOLANA_NETWORK>",
  "chain": "<BLOOM_EVAL_SOLANA_CHAIN>",
  "wallet_id": "<BLOOM_EVAL_SOLANA_WALLET_ID>",
  "source_address": "<the wallet's Solana address>",
  "key_fingerprint": "<hex fingerprint of the signing account>",
  "derivation_path": "<that account's derivation path>",
  "destination": "<BLOOM_EVAL_SOLANA_DESTINATION>",
  "lamports": 1000000,
  "fee_lamports": 5000,
  "blockhash": "<blockhash from intent.json>",
  "pending_id": "<the staged entry id>",
  "signature": "<signature from receipt.json>",
  "slot": 123456789,
  "confirmation_status": "finalized",
  "outcome": "success",
  "pending_entries_after": 0,
  "confirm_failed_before_approval": true
}
```

Read `/bloom/docs` for the outbox lifecycle if you need it, then address the exact paths above directly; do not enumerate their parents. A successful filesystem write only means an asynchronous action was dispatched, never that it completed — always read back the artifact that proves it.

This task authorizes exactly one staged transfer, to the exact destination and for the exact amount named above, from the named wallet and chain. Do not use any other wallet, chain, destination, or amount. Do not stage a second transfer, and do not write to `restage` under any circumstances. If a step fails and you cannot recover, write `cancel` to any pending entry you created, leave the funds alone, and do not report `complete`. Never attempt to move funds back to the source yourself; the host owns that.
