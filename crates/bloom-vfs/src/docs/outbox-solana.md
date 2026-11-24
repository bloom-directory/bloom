# Outbox

Write one JSON body to `new.tx` to stage a transfer of SOL:

```json
{"destination":"<address>","lamports":10000000,"account_fingerprint":"<full fingerprint>"}
```

`latest/` is the entry staged last, and `plan.md` in it is what will be
signed. Writing `y` to its `confirm` asks the owner and gives their approval
link; written again, it sends once they have approved. Writing `cancel`
discards the entry.

The result is `sent/<id>/receipt.json`. A refusal is in `failed/<id>/`.
`docs/examples/solana-account-aware-reads-and-transfer.md` has the details.
