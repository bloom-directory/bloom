# Bloom

Bloom holds this machine's wallets. You propose; the owner approves each
action on a Broker browser page; Bloom signs and sends. Paths here are
relative to this file's directory. Without a mount,
`bloom vfs cat|ls|write <path>` reaches them (this file is `/AGENTS.md`).

- `next.md`: what is pending.
- `wallets/<wallet>/<n>/holdings.json`: balances of account `<n>`; the first
  is `0`.
- `wallets/<wallet>/<n>/confirm-batch`: several staged entries under one
  approval, in order (an approve, then the call that spends it).
- `simulate/new`: a dry run of a body. Nothing is signed or sent.
- `docs/`: one short file per topic; the filenames are the index.

Send, approve or call a contract through the account's outbox,
`wallets/<wallet>/<n>/chains/<chain>/outbox/`. Write a body to `new.tx`, in one of these forms:

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
sends. Then `receipt.json` holds the result. Each step can be one command:
write `new.tx`, write `latest/confirm` and read `latest/plan.md`; then write
`latest/confirm` again and read `latest/receipt.json`.

## Rules

- Secrets (mnemonics, recovery secrets, passkeys) go only in the Broker
  page, never in a write, shell argument, environment variable or log.
- Give the human the complete approval link, unchanged, and say in a
  sentence what you asked for.
- A refusal (`Operation not permitted`, a policy `deny`) is final. Do not
  change policy, switch accounts or try another interface to get around it.
  Propose a policy change only when the owner asks for that change.
- An error does not show whether the operation happened. Read the result
  before retrying. Never stage a payment again while one is pending or its
  outcome is unknown.
