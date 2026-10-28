# Working with Bloom

This file is the operating contract for agents using the mounted Bloom virtual
filesystem. Treat the directory containing this file as the VFS root and keep
all paths mount-relative. Work from a scratch directory outside the mount.

## Start with discovery

Do not assume a wallet, chain, Petal, or action exists. Inspect the live mount:

```sh
ls
cat next.md
cat docs/README.md
```

`next.md` summarizes actions needing attention. `docs/README.md` is the route
reference. Read `docs/examples.md` only for the procedure you are about to
run; `docs/wallets.md` covers wallet creation, recovery, passkeys, sessions
and policy updates, which most tasks never touch.

## Infer, then ask

Settle from state what state can settle: with one wallet, use it; with funds on
one chain, use that chain; a venue's usual network is the default. Ask the
human only for what Bloom cannot know, such as which market or which
recipient, and ask as soon as you see the gap, before scanning balances or
staging anything. Never guess a missing fact.

## Authority and safety

Machine exposes this VFS; Broker controls approval ceremonies and policy;
Signer holds wallet keys and signs. Secret ceremony input belongs only in the
Broker-hosted browser flow, never in a VFS write, shell argument, environment
variable, fixture, or log. Forward the ceremony URL to the human who controls
the passkey, complete with any `#` fragment and unchanged host and port.

Projection and metadata reads are local public state. Chain, balance, ENS,
price, and status reads may contact configured services and consume provider
quota. Petal reads follow the installed package's documentation.

Every write is an operation: it may stage work, begin a ceremony, consume
reusable authority, or broadcast after authorization. Read the target
directory and the resulting projection before retrying or continuing.

## What an error means

An error alone does not establish whether an earlier operation completed or
whether retrying a write is safe.

- **No such file or directory**: the path is absent in the requested state. A
  transfer that advanced out of `pending/` no longer has its old pending path;
  check its resulting state instead of repeating the write.
- **Permission denied**: on a confirm, fresh owner approval is usually
  required; read `approval_challenge.json` in the same action directory.
  Read-only targets also deny, so not every denial starts a ceremony.
- **Operation not permitted**: policy or a safety check refused the operation.
  Read `policy_check.json` where exposed. Repeating the write does not remove
  the gate; tell the human.
- **Invalid argument**: the body was rejected. Re-read the target file's own
  help before writing again.
- **Input/output error**: a backend failed. On an EVM outbox confirm, read
  `last_error.json` beside the pending entry; `kind: policy_approval_required`
  means the owner must first allow the Petal, through the ceremony link in
  `error`. For a possibly submitted transaction, reconcile by its recorded
  hash or signature; never blindly restage or rebroadcast.

If a write seems to have done nothing, list the outbox states (`pending/`,
`sent/`, `failed/`) before writing again. Re-issuing a broadened version of a
correct action is how it becomes an incorrect one.

## Wallet and account identity

`wallets/<wallet>/accounts.json` is the authenticated projection of the
wallet's accounts. Each entry has a `number`; `wallets/<wallet>/<n>/` is that
account, with `account.json` (its EVM and Solana keys), `address.evm`,
`address.sol`, and `chains/<chain>/` for every configured chain, including the
chain's `balance.json` and its `outbox/`. Never select an account by list
position or address alias; a single-key wallet is account 0, used explicitly as
`wallets/<wallet>/0/...`.

Balances live only under the account: `wallets/<wallet>/<n>/chains/<chain>/`
holds `balance.json` for the native asset and `tokens/<contract>/balance.json`
for tokens. `ls wallets/<wallet>/<n>/chains` lists every configured chain;
`status/chains/<chain>/status.json` reports chain health.

Writing `{"request_id":"<id>"}` to `wallets/<wallet>/new` creates another
account number through an owner ceremony. Writing a petname to `wallets/new`
requests asynchronous passkey registration; it does not create a local wallet.
Both, with recovery, passkeys, delegated sessions and Sealed Approvals, are in
`docs/wallets.md`. Read `wallets/registrations/<petname>/status.json` for a
registration's state.

## The transaction loop

Use this loop for native transfers and for Petal actions that project into the
central outbox:

1. Discover the exact wallet, account, chain, and route.
2. Read the write target first: `cat .../outbox/new.tx` or a Petal's `new`
   describes the body it accepts. Then stage once.
3. List `pending/` and identify the new action by its `intent.json` and
   `plan.md`, never by wildcard, sequence number, `latest`, or position.
4. Confirm only that inspected action.
5. If the confirm is denied, read the action's `approval_challenge.json`,
   verify its wallet, action, intent and expiry, and give its `ceremony_url` to
   the human.
6. Poll the challenge; `state` turns from `awaiting_ceremony` to `active` when
   they finish. Then write `confirm` to its `retry_path`; the approval does not
   broadcast on its own. Retrying earlier is safe and starts no new ceremony.
   For `expired`, `cancelled` or `refused`, tell the human.
7. Read `sent/<id>/` or `failed/<id>/` before reporting the result; listing
   `sent/` alone does not prove confirmation.

Do not restage while an approval is pending. `confirm.override` is not an
escape hatch: use it only when the policy projection explicitly permits it and
the human has accepted the displayed warning. For Solana, check the account
fingerprint, derivation path and fee payer in `intent.json`, and reconcile an
ambiguous send by its signature. Procedures are in `docs/examples.md`.

## Petals

Installed applications live under `petals/<name>/`; `docs/petals.md` lists
them. Read the package's `README.md`, then the write file you intend to use:
every Petal write file returns its request format when read, for example
`cat petals/<name>/<route>/<wallet>/0/new`. Account-dependent routes name the
wallet and account number in their path. Keep every follow-up, including the
outbox confirmation, in that same account.

If a write file's help does not answer a question, tell the human what is
missing. Do not fetch or read the Petal's source code to work out a format.

Paid HTTP requests live under `requests/` and are actions: inspect the plan,
payment protocol, maximum amount, wallet and approval before confirming. A
timeout does not prove non-payment; read the request's receipt before acting
again, and never restage an unresolved payment.

## Updating wallet policy

Replacing `wallets/<wallet>/policy.json` starts a Broker ceremony. Prepare the
complete proposal outside the mount and keep the exact same proposed bytes
through `policy.validate_update`, human approval, and the
`policy.commit_update` retry; reformatting the proposal creates a different
request. Commands are in `docs/wallets.md`.

## Reporting Bloom problems

If the Feedback Petal is installed, `petals/feedback/README.md` gives its
submission format. You may submit one concise, sanitized report for a distinct
Bloom failure, misleading documentation, or missing capability that blocked the
task, unless the user has disabled reporting. Never include logs, credentials,
addresses, balances, transaction details, or local paths. A timeout has an
unknown outcome: retry the same submission ID rather than filing a new report.

## Local development chains

A local Anvil node is not configured by default. To use one, ask the operator
to add it to the Machine configuration (`~/.bloom/config.toml`) and restart
Bloom, then confirm it with `ls chains/`:

```toml
[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
display_name = "Anvil (local)"
native_symbol = "ETH"
native_decimals = 18
```
