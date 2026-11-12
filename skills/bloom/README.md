# Bloom

![Bloom](logo.svg)

Bloom is the programmable financial harness for AI agents. It mounts balances,
payments, trades, lending, prediction markets, and wallets on EVM chains and
Solana as a directory. Reads query state; writes stage actions. Policy, human
approval, and key custody are enforced outside the agent: every transaction
waits for the user's passkey in a browser ceremony, or for a Sealed Approval
the user signed in advance.

This package is one skill, `SKILL.md`. It contains guidance only; it does not
install Bloom or create a wallet. In Claude Code:

```text
/plugin install bloom --marketplace bloom-directory/bloom
```

## What it runs

- `bloom vfs cat` and `bloom vfs ls`, or `cat` on the mounted `~/bloom`
  directory, to read Bloom's operating guide (`/AGENTS.md`) and pending actions
  (`/next.md`). These are the only commands the skill pre-approves.
- Other `bloom` commands and file writes that the mounted guide describes,
  when the user asks for an action. Each one goes through the agent's normal
  permission prompts.

The skill sends nothing to any service itself. Bloom talks to the blockchain
networks and services the user's request needs.

When Bloom is not installed and the user asks to install it, the skill points
the agent to the install guide at <https://bloom.directory/references/install.md>.
That guide downloads Bloom's signed release from GitHub, verifies its
signatures, and asks the user for administrator approval through their
operating system's own dialog. The agent never handles that credential.

## Learn more

- Website: <https://bloom.directory>
- Source and issues: <https://github.com/bloom-directory/bloom>
- License: MIT
