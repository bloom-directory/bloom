# Outbox

Write one body to `new.tx` to stage a transaction:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

`latest/` is the entry staged last, and `plan.md` in it is what will be
signed. Writing `y` to its `confirm` asks the owner and gives their approval
link; written again, it waits for the approval and sends. Writing `cancel`
discards the entry.

The result is `sent/<id>/receipt.json`. A refusal is in `failed/<id>/`.
