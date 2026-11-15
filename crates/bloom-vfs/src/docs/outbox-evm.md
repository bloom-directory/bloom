# Outbox

Write a body to `new.tx` to stage a transaction, in one of these forms:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

`latest/` is the entry staged last, before and after it is sent. Its
`plan.md` is what will be signed. Writing `y` to its `confirm` asks the owner
and gives their approval link; written again, it waits for the approval and
sends. Then `receipt.json` holds the result. Writing `cancel` to `confirm`
discards the entry. `pending/`, `sent/` and `failed/` hold every entry by id.

Several staged entries can go under one approval: write `<chain>:pending`
(or their `chain:id` references in order) to `../../../confirm-batch` for the
link, then write it again: it waits for the approval and sends. Reading that
file gives the hashes.

Each step can be one command: write `new.tx`, write `latest/confirm` and
read `latest/plan.md`; then write `latest/confirm` again and read
`latest/receipt.json`.
