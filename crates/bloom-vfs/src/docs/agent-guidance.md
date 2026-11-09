# Working with Bloom

This is the operating contract for agents using the mounted Bloom virtual
filesystem. Treat the directory containing this file as the VFS root and keep
all paths mount-relative. Keep scratch files outside the mount.

`ls` the mount and read `next.md` (actions needing attention). Read on demand:
`cat docs/README.md` lists every route, `docs/examples.md` has command
walkthroughs (including contract deploys and local Anvil), `docs/wallets.md` covers accounts, wallet creation, recovery,
passkeys and sessions, and `docs/petals.md` lists installed Petals. Read a
Petal's `README.md` and `AGENTS.md` before using its routes.

## Funds and missing details

`wallets/<wallet>/<n>/holdings.json` lists an account's non-zero native and
major token balances on every configured chain, and names any chain it could
not read under `errors`. Read any other token at
`chains/<chain>/addresses/<address>/tokens/<token>/`. On Solana it shows SOL
only.

Infer what Bloom state settles; ask only for what it cannot:

- With one wallet or account, use it.
- A read that names no chain covers every chain: read `holdings.json`.
- For a write, use the only chain where `holdings.json` shows the asset, or
  the network the Petal's documentation names as its default. If two or more
  funded chains remain, ask one question that names them.
- If `holdings.json` has an `errors` entry for a chain that could hold the
  asset, say so rather than treating that chain as empty.

## Authority and safety

Machine exposes this VFS, Broker runs approval ceremonies and policy, and
Signer holds the keys. Secret input (mnemonics, recovery secrets, passkeys)
belongs only in the Broker-hosted browser page, never in a VFS write, shell
argument, environment variable or log. Give the human the complete ceremony
URL, including any `#` fragment, with host and port unchanged. Launch URLs are
owner capabilities: keep them out of logs and Petal-visible data.

Every write is an operation: it may stage work, start a ceremony, spend
reusable authority or broadcast. Read the result before retrying.

## Accounts

`wallets/<wallet>/accounts.json` lists the wallet's accounts; each entry's
`number` is its derivation index, and `wallets/<wallet>/<n>/` is that account.
Never select an account by list position or address alias. Stage through the
numbered path (`wallets/<wallet>/<n>/chains/<chain>/outbox/new.tx`, using `0`
explicitly for the first account); it fixes the sender to that account's key.
Keep every follow-up, including Petal routes and outbox confirmations, in the
same account.

Writing a petname to `wallets/new` requests asynchronous passkey registration;
it does not create a local wallet. Follow
`wallets/registrations/<petname>/status.json`. Details are in
`docs/wallets.md`.

## The transaction loop

For native transfers and Petal actions that project into the outbox:

1. Stage once: write the body to `outbox/new.tx` (formats in
   `docs/examples.md`) or to a Petal's `new` (its README).
2. Identify the new entry in `pending/` by its `intent.json` and `plan.md`,
   never by wildcard, sequence number, `latest` or position.
3. Write `confirm` to that entry's `confirm` file. If the owner must
   approve, its error gives the ceremony link: give it to the human, then
   write `confirm` again, which waits for their approval and sends. Repeat
   if it times out. For `expired`, `cancelled` or `refused`, tell the human.
   On a mount, confirm does not wait: read `approval_challenge.json` and
   follow its `next`.
4. Read `sent/<id>/` or `failed/<id>/` before reporting the result.

Do not restage while an approval is pending, or because a pending path
disappeared: list `sent/` and `failed/` first. `confirm.override` is only for
when the policy projection permits it and the human accepted its warning.

To discard an entry never sent for signing, write `cancel` to its `confirm`
file. On EVM the entry's own `cancel` file instead signs a same-nonce
replacement and needs its own approval. If a signature may exist, even with
no hash recorded, Bloom keeps the entry and its `last_error.json` says how to
reconcile it. Never delete a signing record or reuse a nonce to force a fresh
attempt. A `failed/` entry with `signing_unknown.json` may still be signed (an older
Bloom released it): follow its `next` before staging that payment again.

On Solana, reconcile an ambiguous send by its signature. A `sent` entry with
`unresolved.md` and no receipt is not proof of failure: show the owner its
signature and restage only if they confirm it did not land.

## What an error means

An error alone does not show whether an earlier operation completed.

- **No such file or directory**: the path is absent now. An entry that left
  `pending/` moved to `sent/` or `failed/`.
- **Permission denied**: on a confirm, follow its message, or on a mount read
  `approval_challenge.json`. Read-only targets also deny.
- **Operation not permitted**: policy or a safety check refused it. Read
  `policy_check.json`; repeating does not help.
- **"signing outcome unknown; it may already be signed"**: retry the identical
  request (same bytes, same operation id). Never rebuild it under a new id or
  rebroadcast until the first attempt is known not to have landed.
- **Input/output error**: on an outbox confirm, read the entry's
  `last_error.json`. `kind: policy_approval_required` means the owner must
  first allow that Petal through the ceremony link in `error`.

A refused Petal write leaves its reason in `petals/<name>/last_error.json`.
Check its `path` and `at_ms` match your write; no record means no
information, not success. A Petal write denied with no ceremony link: report
the route and error rather than reinstalling, switching accounts or dropping
fields.

## What the owner sees when approving

The approval page shows Broker's own reading of the signed bytes: action,
account, amounts, recipient and limits. Before forwarding the link, tell the
human in a sentence what you asked for, so they can cancel if the page shows
something else. Name an unknown token only by its address and raw units,
never a guessed ticker. Point out **No output protection**, **Spending limit:
Unlimited**, or **Contract call Bloom cannot read** if shown. An approval
proves what was signed, not that an order filled or funds arrived; report
outcomes from receipts and the Petal's status files.

## Policy, approvals and paid requests

Replacing `wallets/<wallet>/policy.json` starts a Broker ceremony. Keep the
exact same proposed bytes through `policy.validate_update`, approval and the
`policy.commit_update` retry, then read
`policy-updates/confirmed/<action_id>/status.json`. See
`docs/examples.md`.

Reusable authority is under `wallets/<wallet>/sealed-approvals/`. A Petal can
use it but cannot create, broaden, renew or revoke it.

Paid HTTP requests under `requests/` are actions: inspect the plan, payment
protocol, maximum amount and wallet before confirming. A timeout does not
prove non-payment; read the receipt, and never restage an unresolved payment.

## Reporting Bloom problems

If `petals/feedback/` exists, you may submit one short report for a Bloom
failure, misleading doc or missing capability that blocked the task, unless
the user disabled reporting. Never include logs, credentials, addresses,
balances, transaction details or local paths. Its `README.md` gives the
format; on a timeout, retry the same submission ID.
