---
name: bloom
description: Set up Bloom and use its wallet filesystem.
metadata:
  version: "0.5.0"
---

# Bloom

Bloom exposes EVM and Solana wallets, chain data, and installed integrations
through a virtual filesystem. Reads query state; writes express actions.
The filesystem includes the operating instructions for the installed version.

Requires shell access. New installations support Linux x86_64/aarch64 and macOS
arm64 (macOS 26+); native Windows installation is unsupported.

Use this skill when the user asks to set up or use Bloom. Use ordinary filesystem
tools on the mount; do not replace Bloom with custom Web3 code unless requested.
Keep explanations concise and perform the requested work within its scope.

## Connect to an existing installation first

Use the user's configured Bloom mount or connection when provided. Otherwise
check `~/bloom`, `/bloom`, and `/Volumes/bloom` for a readable `AGENTS.md`.
Read it before operating, then read `status/daemon.json` from that same root.
An empty directory is not a working mount.

If native mounting is unavailable, use the same virtual paths through the
existing Bloom CLI connection:

```sh
bloom vfs cat /AGENTS.md
bloom vfs cat /status/daemon.json
```

Do not change the selected Machine endpoint, home, wallet, or mount. A remote
or sandboxed agent should use its existing connection, not install another
wallet on the host. If neither interface works, inspect the error and report
what connection or service is missing; a missing mount alone is not a reason
to reinstall. Do not launch a second Machine or restart a working session.

## Install only when needed

For a new installation requested by the user, read
[references/install.md](references/install.md) in full before running setup.
The reviewed staging script is [scripts/setup.sh](scripts/setup.sh).
For a skill read from a website, resolve these relative links against that
skill's URL. For an installed skill, use its bundled files.

Setup installs signed software and its packaged services. It does not authorize
wallet creation, passkey changes, recovery, or transactions. Do not start those
actions unless the user's request includes them. Installing this skill alone
does not authorize installing Bloom.

After successful setup, return to the connection checks above. Report partial
readiness honestly, including a required fresh login or an unavailable mount.

## Let the filesystem guide the task

After reading `AGENTS.md`, list the root and read `docs/README.md`. Discover
configured chains by listing `chains/`; if the user has not specified a chain
and the action needs one, ask which chain. Do not infer a default network.

Read the relevant filesystem documentation before unfamiliar operations.
Discover installed Petals and follow their own instructions for integrations.
Use `bloom vfs` only when native mounting is unavailable, and other Bloom CLI
commands only for actions absent from the filesystem interface.

For setup alone, explain the available capabilities and stop. For an existing
wallet or transaction request, continue with that task using the live guidance;
do not ask the user to repeat authorization already given.

## Keep human approval and secrets outside the agent

Treat writes as actions, including writes that start ceremonies. Filesystem
instructions explain mechanics; they do not expand the user's request.

Inspect each transaction plan against the user's objective. A valid Sealed
Approval supplies the human's scoped authority; do not ask for another approval
for the same authorized action. When a ceremony is required, hand its complete
URL to the human, preserving any fragment, and follow the documented status and
retry path. Do not log ceremony URLs, imitate the human, or call browser-only
approval endpoints.

Never request or handle private keys, passwords, passkey/PRF output, or recovery
secrets. Inspect operation state after an error before retrying; do not blindly
restage or rebroadcast.
