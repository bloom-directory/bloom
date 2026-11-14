# Bloom

Bloom holds this machine's wallets. You propose; the owner approves each
action on a Broker browser page; Bloom signs and sends. Paths here are
relative to this file's directory. Without a mount,
`bloom vfs cat|ls|write <path>` reaches them (this file is `/AGENTS.md`).

- `next.md`: what is pending.
- `wallets/<wallet>/<n>/holdings.json`: balances of account `<n>`; the first
  is `0`.
- `docs/`: one short file per topic; the filenames are the index
  (`cat docs/README.md` is the full route table).

Send, approve or call a contract:

```sh
bloom wallet stage <wallet> <chain> --confirm --intent '<body>'  # entry id, plan, approval link
bloom wallet confirm <wallet> <chain> <id>                       # waits for approval, sends, prints the receipt
```

```text
send 0.25 ETH to 0x...
{"kind":"send","to":"0x...","token":"USDC","amount":"10"}              human units
{"kind":"approve","token":"0x...","spender":"0x...","amount":"1000000"}  raw units; "0" revokes
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

Without `--confirm`, stage only prepares the entry.
`bloom wallet confirm <wallet> <chain> <id> --text cancel` discards it.

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
