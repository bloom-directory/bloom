Use the Bloom filesystem mounted at `/bloom` to perform this exact task on the Solana chain named by `BLOOM_EVAL_SOLANA_CHAIN`:

`/bloom` is a dynamic virtual filesystem: directory traversal can execute live
chain reads. Never run `find`, `tree`, `rg --files`, recursive `ls`, or any
broad enumeration under `/bloom`, and never issue concurrent `/bloom` commands.
Access only the exact paths named below, one command at a time. A direct read
may take several seconds; wait for it to finish instead of starting another.

Every path described below as a write is a dynamic action route, not an
ordinary file. Do **not** use an editor-style `Write`/`Edit` tool: those tools
usually create a sibling temporary file such as `confirm.tmp`, which is a
different, invalid route. Do not use shell redirection either, because buffered
NFS errors can be reported after the shell has declared success. Write the
exact route directly and force the result with this pattern, substituting only
the path and payload:

```bash
python3 -c 'import os,sys; f=open(sys.argv[1], "wb", buffering=0); f.write(sys.argv[2].encode()); os.fsync(f.fileno()); f.close()' EXACT_PATH EXACT_PAYLOAD
```

The command's nonzero exit status is meaningful. A zero exit status means the
action was accepted for dispatch, not that it completed; verify the resulting
artifact as each step requires.

1. The wallet is `BLOOM_EVAL_SOLANA_WALLET_ID`. Read `/bloom/wallets/$BLOOM_EVAL_SOLANA_WALLET_ID/accounts.json` to find the wallet's **Solana** account: its base58 address, its key fingerprint, and its derivation path (which looks like `m/44'/501'/0'/0'`). A wallet can hold accounts for several chains, so select the Solana one rather than the first listed. Record all three; the report needs them and the verifier checks them independently. The outbox paths below are under `/bloom/wallets/$BLOOM_EVAL_SOLANA_WALLET_ID/chains/$BLOOM_EVAL_SOLANA_CHAIN/`.

2. Stage exactly one transfer by writing a single JSON object to `outbox/new.tx`:

   ```json
   {"destination": "<BLOOM_EVAL_SOLANA_DESTINATION>", "lamports": <BLOOM_EVAL_SOLANA_LAMPORTS>}
   ```

   `lamports` is an integer, not a string and not a SOL amount. Add `"account_fingerprint": "<fingerprint>"` only if the wallet has more than one active Solana account; the intent rejects unknown fields, so do not add anything else. Do not invent a different destination or amount: the host has pre-authorized exactly this pair and nothing else can be broadcast.

3. List `outbox/pending/` to find the entry the write created and record its id. Read that entry's `intent.json` and `plan.md`. Confirm `fee_payer` is the wallet's Solana address, `lamports` is the authorized amount, and record `fee_lamports` and `blockhash`.

4. Use the direct, unbuffered route-write command above to write `y` to the entry's `confirm`. Do not use `Write`, `Edit`, or redirection. **This first direct write is expected to fail with a permission error.** It is the Sealed Approval boundary, not an error to work around, and it is what stages the owner's approval request. A failure mentioning a sibling path such as `confirm.tmp` does not count: it never reached the confirm route. The resulting `approval_challenge.json` is owner-facing status only; do not open its ceremony URL or attempt to approve it yourself. Observing the direct route's failure is all this step requires.

5. The owner approves out of band while you wait. Poll with the same direct, unbuffered command, re-writing the **byte-identical** `y` to `confirm` every second until it succeeds. Keep this in one shell loop rather than spending a model turn per attempt. Each attempt before approval fails the same way; that is expected and is not a reason to change anything. Do not change the bytes, do not write to `restage`, and do not stage a second transfer. The blockhash has a short lifetime, so stop after 45 seconds rather than polling a doomed entry.

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
