---
name: bloom
description: "Bloom crypto wallet: balances, transfers, swaps, setup. Use when the user mentions Bloom or their wallet, addresses, or onchain actions on EVM chains or Solana. A human passkey approves every transaction."
metadata:
  version: "0.5.0"
---

# Bloom

Bloom exposes wallets, chain data, and installed apps (Petals) as files. Reads
query state; writes are actions. Use it with ordinary file and shell tools
instead of writing Web3 code, unless the user asks for code.

## Connect

Run this first. It prints the operating contract and pending actions:

```sh
cat ~/bloom/AGENTS.md ~/bloom/next.md || bloom vfs cat /AGENTS.md
```

Use the user's mount path instead of `~/bloom` if they gave one.

- `~/bloom` works: follow its `AGENTS.md`. It is the contract for the installed
  version and overrides this skill.
- Only the CLI works: use `bloom vfs ls|cat` with the same paths, from `/`.
- Both fail: report the error. If the user asked to install Bloom, read
  [references/install.md](references/install.md) (beside this file, or beside
  its URL) in full first. Otherwise do not install, restart, or launch another
  Bloom; a remote or sandboxed agent uses its existing connection.

## Rules

- If an action needs a chain and the user did not name one, ask which chain.
  Do not pick a default network.
- Do what the user asked without asking them to confirm it again. Their
  passkey approval, or a valid Sealed Approval, is the authorization.
- Installing Bloom or this skill does not authorize creating a wallet, adding
  a passkey, recovery, or transactions. Do those only when asked.
- Never request or handle private keys, seed phrases, passwords, or passkey
  secrets. Give the human the complete ceremony URL; they approve in the browser.
- After a write error, inspect state before retrying. Never blindly restage or
  rebroadcast.
