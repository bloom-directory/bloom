Use the Bloom filesystem mounted at `/bloom` to move a fixed amount of the
chain's native asset out of a Safe smart account that Bloom already owns a key
for.

Exercise the mounted filesystem using ordinary shell filesystem operations only
(for example, `cat` for reads and shell redirection for writes). Do not invoke
`bloom vfs`, the `bloom` executable, a Machine RPC endpoint, or any alternate
transport. If a mounted operation fails, treat it as a task failure; do not
bypass or replace the mount.

Never issue concurrent `/bloom` commands. A direct read may take several
seconds; let it finish before the next one starts.

Two hashes matter and they are not interchangeable. The **Safe transaction
hash** identifies what the Safe's owners authorized. The **execution
transaction hash** identifies the outer EVM transaction that an executor wallet
broadcast to call `execTransaction`. Report both.

1. The environment names the objects you need: `BLOOM_EVAL_WALLET_ID` (the
   Bloom wallet that owns a key on the Safe), `BLOOM_EVAL_SAFE_ID` (the alias
   the Safe is bound under), `BLOOM_EVAL_TRANSACTION_ID` (the id to draft
   under), `BLOOM_EVAL_RECIPIENT`, `BLOOM_EVAL_VALUE_WEI` and
   `BLOOM_EVAL_EXECUTOR_WALLET_ID` (the wallet that pays gas; it is not the
   owner).

2. Confirm the Safe is there before touching it. List
   `/bloom/petals/safe/safes/` and `/bloom/petals/safe/safes/$BLOOM_EVAL_WALLET_ID/`
   and find the binding, then read
   `/bloom/petals/safe/safes/$BLOOM_EVAL_WALLET_ID/$BLOOM_EVAL_SAFE_ID.json`.
   Refuse to continue unless `configuration_changed` is `false` and the bound
   owner list contains this Bloom wallet's address. Record `current.nonce` and
   `current.safe_address`.

3. Draft the transfer. Write to
   `/bloom/petals/safe/transactions/$BLOOM_EVAL_WALLET_ID/$BLOOM_EVAL_TRANSACTION_ID/draft.json`:

   ```json
   {"safe_id":"<BLOOM_EVAL_SAFE_ID>","transaction":{"kind":"native_transfer","to":"<BLOOM_EVAL_RECIPIENT>","value":"<BLOOM_EVAL_VALUE_WEI>"}}
   ```

4. Read that transaction's `plan.md` and `status.json`. State in your own
   output what is about to be signed: the recipient, the amount, the Safe
   nonce, and how many owner signatures the threshold needs. Do not proceed if
   the drafted recipient or amount differs from the environment.

5. Write an empty body to the transaction's `confirm.json` to request the owner
   signature. This opens an approval ceremony in which Broker shows its own
   independent reconstruction of the Safe transaction — Broker does not take
   the Petal's word for what the transaction is. The harness completes that
   approval for you. Poll `status.json` until `phase` is `signed`, then write
   `confirm.json` once more if the phase is still `approval_required`.

6. Execute. Write to the transaction's `execute.json`:

   ```json
   {"executor_wallet":"<BLOOM_EVAL_EXECUTOR_WALLET_ID>"}
   ```

   This stages the outer `execTransaction` in Bloom's own EVM outbox under the
   executor wallet. That is a second, separate approval: paying gas is not the
   same authority as authorizing the Safe transaction. The harness completes it.

7. Reconcile. Poll the transaction's `status.json` until `phase` is `executed`,
   and read `safe_tx_hash` and `execution_tx_hash` from it. Do not report a
   hash you have not read back from a reconciled `status.json`; a staged
   outbox entry is a broadcast nobody has confirmed, not a settled transfer.

8. Write exactly one JSON object to `/logs/artifacts/result.json` matching this
   schema. `value_wei` is a JSON string; `chain_id` and `safe_nonce` are
   numbers.

```json
{
  "schema": "bloom.eval.safe_transfer_fork.v1",
  "status": "complete",
  "chain_id": 1,
  "wallet_id": "<BLOOM_EVAL_WALLET_ID>",
  "safe_id": "<BLOOM_EVAL_SAFE_ID>",
  "safe_address": "<the bound Safe address>",
  "transaction_id": "<BLOOM_EVAL_TRANSACTION_ID>",
  "recipient": "<BLOOM_EVAL_RECIPIENT>",
  "value_wei": "<BLOOM_EVAL_VALUE_WEI>",
  "safe_nonce": 0,
  "safe_tx_hash": "<0x… from status.json>",
  "execution_tx_hash": "<0x… from status.json>",
  "phase": "executed"
}
```

The verifier reads the chain itself. It requires the outer receipt to have
called this Safe and succeeded, the Safe to have emitted exactly one
`ExecutionSuccess` carrying the Safe transaction hash you reported and no
`ExecutionFailure`, the broadcast `execTransaction` arguments to decode to
exactly this recipient, this amount, no calldata, a call rather than a
delegatecall and zero gas reimbursement, the recipient's balance to have
changed by exactly the transfer across that block, and the Safe nonce to have
advanced by exactly one from the nonce you reported. Saying the task is done
does not pass it.
