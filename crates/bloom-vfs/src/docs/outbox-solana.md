# Outbox

Write one JSON body to `send.tx` to send SOL:

```json
{"destination":"<address>","lamports":10000000}
```

The write asks the owner and gives their approval link. Then write `y` to
the `confirm` it names: it sends once they have approved. Writing `cancel`
there discards the entry.

`new.tx` takes the same body and only stages it. `latest/` is the entry
staged last, and `plan.md` in it is what will be signed.

The confirm answers with the result, `sent/<id>/receipt.json`. A refusal is in `failed/<id>/`.
`docs/examples/solana-account-aware-reads-and-transfer.md` has the details.
