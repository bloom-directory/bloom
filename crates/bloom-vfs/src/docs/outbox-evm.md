# Outbox

Write a body to `send.tx`, in one of these forms:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"call","contract":"0x...","method":"supply(address,uint256,address,uint16)","args":["0x...","1000000","0x...",0]}
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  calldata you built
```

`call` encodes the arguments for you (a struct is a JSON array); `value`
is in wei.

That stages it, asks the owner, waits for their approval, sends, and
answers with what was signed, the approval link, the receipt of each entry
and the account's balances on that chain, each with what it changed by (on
a mount the write is refused; read `latest/plan.md` for the link, write `y`
to `latest/confirm`, then read `latest/receipt.json`). If the answer says it
was not sent yet, write `y` to `latest/confirm`: it waits again, then sends.
`new.tx` takes the same body and only
stages it; `cancel` written to `latest/confirm` discards an entry, with the rest of
its batch.

Several bodies in one write, one per line, go under one approval, in order (an
approve, then the call that spends it). Entries already staged go together by
writing their `chain:id` references, in order, to `../../../confirm-batch`;
reading that file gives the link, then the hashes.
`pending/`, `sent/` and `failed/` hold every entry by id.
