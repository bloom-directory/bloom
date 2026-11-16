# Bloom

Bloom holds this machine's wallets. You propose; the owner approves each
action on a Broker browser page; Bloom signs and sends. Paths here are
relative to this file's directory. Without a mount,
`bloom vfs cat|ls|write <path>` reaches them (this file is `/AGENTS.md`).

- `next.md`: this machine's wallets, with their paths, and what is pending.
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
{"kind":"raw","to":"0x...","data":"0x...","value":"0"}                  any contract call
{"kind":"call","contract":"0x...","method":"transfer(address,uint256)","args":["0x...","1"]}
```

That stages it and asks the owner, giving their approval link. `latest/` is
that entry, before and after it is sent: `latest/plan.md` is what will be
signed, writing `y` to `latest/confirm` waits for the approval and sends, and
then `latest/receipt.json` holds the result. `new.tx` takes the same body and
only stages it; `cancel` written to `latest/confirm` discards an entry.

Several bodies in one write, one per line, go under one approval, in order (an
approve, then the call that spends it).

## Rules

- Secrets (mnemonics, recovery secrets, passkeys) go only in the Broker
  page, never in a write, shell argument, environment variable or log.
- Give the human the complete approval link, unchanged, and say in a
  sentence what you asked for. Then confirm again in the same turn: that
  write waits for them, so there is nothing to stop and wait for.
- A refusal (`Operation not permitted`, a policy `deny`) is final. Do not
  change policy, switch accounts or try another interface to get around it.
  Propose a policy change only when the owner asks for that change.
- An error does not show whether the operation happened. Read the result
  before retrying. Never stage a payment again while one is pending or its
  outcome is unknown.
- Report a failed or partly completed request as a failure, and say which
  steps did not complete.
