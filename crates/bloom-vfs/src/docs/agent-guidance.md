# Bloom

Bloom holds this machine's wallets. You propose; the owner approves each
action on a Broker browser page; Bloom signs and sends. Reach paths with
`bloom vfs cat|ls <path>` and `bloom vfs write <path> '<body>'` (this file is
`/AGENTS.md`). Balances are in `wallets/<wallet>/<n>/holdings.json` and below,
under Next Actions; `docs/` has one short file per refused or failed write.

To send, approve or call a contract, use the account's outbox,
`wallets/<wallet>/<n>/chains/<chain>/outbox/`. Write a body to `send.tx`:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"call","contract":"0x...","method":"supply(address,uint256,address,uint16)","args":["0x...","1000000","0x...",0]}
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  calldata you built
```

`call` encodes the arguments (a struct is a JSON array); `value` is in wei.
Bodies on separate lines go under one approval, in order (an approve, then the
call that spends it); Bloom simulates them first and names a line that would
revert. A swap, loan, stake or bridge is an approve and a `call` to the
protocol's contract. `petals/` holds venue packages; read one's `README.md`
only when the request names its venue. Nothing signs off-chain messages
(permits, EIP-712 data).

The write answers with what will be signed, the owner's approval link and the
confirm path. Write `y` there: it waits for the approval, sends, and answers
with each receipt and the balance changes. `new.tx` only stages; `cancel` to the
confirm path discards the entry. On a mount a write answers nothing: read
`latest/plan.md`, then `latest/receipt.json`.

## Rules

- Secrets (mnemonics, recovery secrets, passkeys) go only in the Broker page,
  never in a write, shell argument, environment variable or log.
- Give the human the approval link unchanged and say what you asked for. Then
  confirm in the same turn: the confirm waits for them.
- A refusal (`Operation not permitted`, or `policy denied`) is final. Do not
  change policy, switch accounts or try another interface to get around it.
  If it refused a contract you chose, such as a router, use one for the same
  action that `wallets/<wallet>/policy.json` allows; never change a payee.
  Propose a policy change only when the owner asks; to add a payee, write
  `{"add_destinations":[{"chain":"<chain>","destination":"0x..."}]}` to
  `wallets/<wallet>/policy.json`.
- An error does not show whether the operation happened. Read the result
  before retrying, and never stage a payment again while one is pending or
  its outcome is unknown.
- Report a failed or partly completed request as a failure, naming the steps
  that did not complete.
