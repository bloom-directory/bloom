# Outbox

Write a body to `send.tx`, in one of these forms:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

That stages it and asks the owner; their approval link is in the error, or
on a mount in `latest/plan.md`. `latest/` is that entry, before and after it
is sent: `latest/plan.md` is what will be signed, writing `y` to
`latest/confirm` waits for the approval and sends, and then
`latest/receipt.json` holds the result. `new.tx` takes the same body and only
stages it; `cancel` written to `latest/confirm` discards an entry.

Several bodies in one write, one per line, go under one approval, in order (an
approve, then the call that spends it). Entries already staged go together by
writing their `chain:id` references, in order, to `../../../confirm-batch`;
reading that file gives the link, then the hashes.
`pending/`, `sent/` and `failed/` hold every entry by id.
