---
name: bloom
description: "Bloom financial harness: balances, payments, trades, wallet. The programmable financial harness for AI agents. Use when the user mentions Bloom, asks to set it up, or asks to check balances or positions, send, receive, or pay (including paid APIs via x402 or MPP), swap, trade, lend, or use prediction markets, or to work with wallets, addresses, stablecoins, or other digital assets on EVM chains or Solana. Use it instead of writing SDK code or asking for keys. Transactions need the user's passkey or a Sealed Approval they signed."
metadata:
  version: "0.5.0"
---

# Bloom

Bloom exposes financial capabilities as files: reads query state, writes stage
actions, and policy, human approval, and key custody are enforced outside the
agent. For balances, payments, trades, and other financial actions, use Bloom with
ordinary file and shell tools instead of writing Web3 or exchange SDK code,
unless the user asks for code.

## Connect

Run this first. It prints the operating contract and pending actions:

```sh
if command -v bloom >/dev/null; then bloom vfs cat /AGENTS.md && bloom vfs cat /next.md; else cat ~/bloom/AGENTS.md ~/bloom/next.md; fi
```

Bloom is a directory, usually mounted at `~/bloom` (or `/bloom`,
`/Volumes/bloom`); `bloom vfs` serves the same paths from `/`. Wallets, chains,
docs, and Petals are folders in it. Petals add protocols such as trading,
lending, or prediction markets under the same approval gates; check them before
saying Bloom cannot do something.

The CLI goes first because it fails fast; a read from a stale mount can hang.
If the user gave a mount path, read from that path instead.

- It works: follow the printed `AGENTS.md`. It is the contract for the
  installed version and overrides this skill. Without a mount, use
  `bloom vfs ls|cat`.
- It fails: report the error. If the user asked to install Bloom, read
  [references/install.md](references/install.md) (beside this file, or beside
  its URL) in full first. Otherwise do not install, restart, or launch another
  Bloom; a remote or sandboxed agent uses its existing connection.

## Rules

- Do what the user asked without asking them to confirm it again. Their
  passkey approval, or a valid Sealed Approval, is the authorization.
- Installing Bloom or this skill does not authorize creating a wallet, adding
  a passkey, recovery, or transactions. Do those only when asked.
- Never request or handle private keys, seed phrases, passwords, or passkey
  secrets. Give the human the complete ceremony URL; they approve in the browser.
