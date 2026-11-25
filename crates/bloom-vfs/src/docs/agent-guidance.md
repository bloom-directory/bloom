# Bloom

Bloom holds this machine's wallets. You propose; the owner approves each
action on a Broker browser page; Bloom signs and sends. Paths here are
relative to this file's directory. Without a mount, `bloom vfs cat|ls <path>`
and `bloom vfs write <path> '<body>'` (or the body on stdin) reach them (this
file is `/AGENTS.md`).

- `next.md`, also at the end of this file: this machine's wallets, with their
  paths and balances, and what is pending.
- `wallets/<wallet>/<n>/holdings.json`: balances of account `<n>`; the first
  is `0`.
- `docs/`: for when a write is refused or fails; one short file per
  situation, named for it.

Send, approve or call a contract through the account's outbox,
`wallets/<wallet>/<n>/chains/<chain>/outbox/`. Write a body to `send.tx`, in
one of these forms:

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"call","contract":"0x...","method":"supply(address,uint256,address,uint16)","args":["0x...","1000000","0x...",0]}
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  calldata you built
```

`call` encodes the arguments for you (a struct is a JSON array); `value`
is in wei. A swap, loan, stake or bridge is an approve, then a `call` to the
protocol's own contract, in one write. `petals/` holds installed venue packages
(each with a `README.md`); use one when the request names its venue. No route
signs an off-chain message (a permit or other EIP-712 data) for you.

That stages it, asks the owner, and answers with what will be signed and
their approval link (on a mount the write is refused; both are in
`latest/plan.md`). `latest/` is that entry (the answer names it as `pending/<id>/`), before and after it is sent:
`latest/plan.md` is what will be signed, writing `y` to
`latest/confirm` waits for the approval, sends, and answers with the receipt
of each entry it sent and the account's balances on that chain, each with
what it changed by (on a mount,
read `latest/receipt.json`). `new.tx` takes the same body and only
stages it; `cancel` written to `latest/confirm` discards an entry, with the rest of
its batch.

Several bodies in one write, one per line, go under one approval, in order (an
approve, then the call that spends it). Bloom simulates them in that order
before asking the owner and refuses the write, naming the line, if one would
revert; you need not simulate them yourself.

## Rules

- Secrets (mnemonics, recovery secrets, passkeys) go only in the Broker
  page, never in a write, shell argument, environment variable or log.
- Give the human the complete approval link, unchanged, and say in a
  sentence what you asked for. Then confirm again in the same turn: that
  write waits for them, so there is nothing to stop and wait for.
- A refusal (`Operation not permitted`, or an error saying `policy denied`) is final. Do not
  change policy, switch accounts or try another interface to get around it.
  Propose a policy change only when the owner asks for that change; to add
  a payee, write `{"add_destinations":[{"chain":"<chain>","destination":"0x..."}]}`
  to `wallets/<wallet>/policy.json`.
- An error does not show whether the operation happened. Read the result
  before retrying. Never stage a payment again while one is pending or its
  outcome is unknown.
- Report a failed or partly completed request as a failure, and say which
  steps did not complete.
