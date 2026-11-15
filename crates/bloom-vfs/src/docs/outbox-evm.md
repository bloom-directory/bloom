# Outbox

Write a body to `send.tx`, in one of these forms:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

That stages it and asks the owner, giving their approval link. `latest/` is
that entry, before and after it is sent: `plan.md` is what will be signed,
writing `y` to `confirm` waits for the approval and sends, and then
`receipt.json` holds the result. `new.tx` takes the same body and only stages
it; `cancel` written to `confirm` discards an entry.

Several staged entries can go under one approval: stage each through
`new.tx`, write `<chain>:pending` (or their `chain:id` references in order) to
`../../../confirm-batch` for the link, then write it again: it waits for the
approval and sends. Reading that file gives the hashes. `pending/`, `sent/`
and `failed/` hold every entry by id.
