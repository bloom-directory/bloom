# Working with Bloom

This file is the operating contract for agents using the mounted Bloom virtual
filesystem. It is not a development guide. Treat the directory containing this
file as the VFS root and keep all paths mount-relative.

## Start with discovery

Do not assume a wallet, chain, Petal, or action exists. Inspect the live mount:

```sh
ls
cat next.md
cat docs/README.md
```

`next.md` summarizes actions needing attention. Read the relevant walkthrough
in `docs/examples.md` before using an unfamiliar write surface. For Petal work,
use `docs/petals.md` to discover installed packages, then read that package's
`README.md` and `AGENTS.md` before using its routes.

## Authority and safety

Machine exposes this VFS; Broker controls approval ceremonies and policy;
Signer holds Bloom wallet keys and signs. Secret ceremony input belongs only
in the Broker-hosted browser flow, never a VFS write, shell argument,
environment variable, fixture, or log. Forward the ceremony URL to the human
who controls the passkey.

Classify reads before using them:

- Projection and metadata reads are local public state.
- Chain, balance, ENS, price, and status reads may contact configured services.
  They do not authorize or broadcast a transaction, but can fail, consume
  provider quota, or disclose the queried public identifier to that provider.
- Petal reads follow the installed package's documentation, declared
  capabilities, and network policy. Do not assume they are local or free.

Treat every write as an operation. Writes may stage work, begin a ceremony,
consume reusable authority, or broadcast after authorization. Read the target
directory and inspect the resulting projection before retrying or continuing.

## What an error means

Use the error class to decide what to inspect. An error alone does not establish
whether an earlier operation completed or whether retrying a write is safe.

- **No such file or directory** — the path is absent in the requested state.
  A discarded transfer or one that advanced out of `pending/` no longer has its
  old pending path. Check the exact action's resulting state; absence alone
  does not prove your write succeeded. Do not repeat an operation merely to
  make the old path reappear.
- **Permission denied** — access was denied. On a confirm operation this can
  mean fresh owner approval is required; look for `approval_challenge.json` in
  the same action directory. Read-only or unsupported write targets can also
  deny access, so do not assume every denial starts a ceremony.
- **Operation not permitted** — policy or a broadcast gate refused the
  operation. Inspect `policy_check.json` where exposed and the chain's broadcast
  configuration and status. Repeating the write does not remove the gate.
- **Input/output error** — a backend or I/O operation failed. Inspect action
  state and diagnostics before considering a retry. For a possibly submitted
  transaction, reconcile by its recorded hash or signature; never blindly
  restage or rebroadcast.

If you write to a control file and then cannot find what you wrote, check
whether the transfer moved to `sent/` or `failed/` before assuming the write
was lost. Listing the wallet's outbox states is cheaper than re-issuing the
write, and re-issuing a broadened version of it is how a correct action becomes
an incorrect one.

## Wallet and account identity

Read `wallets/<wallet>/projection.json` and `accounts.json` to select the
wallet and account. Account-sensitive operations bind the public-key
fingerprint and derivation path. Never select by directory order, list
position, or an address alias.

Use full fingerprints in persistent paths and records. Solana account paths
are `wallets/<wallet>/chains/<chain>/accounts/<full-fingerprint>/`; the
chain-level balance alias works only when selection is unambiguous. Unique
fingerprint prefixes, where accepted as input, are interactive convenience
only. Resolve ambiguity against `accounts.json`.

## Creating a wallet

Writing a petname to `wallets/new` requests asynchronous passkey registration;
it does not create a local wallet. Read
`wallets/registrations/<petname>/status.json`, verify `requested_name`, and
forward `ceremony_url` to the human. Wait for `ceremony_state: COMPLETED`,
then read `result.json` and the new wallet projection. Cancel through that
registration's `cancel` control before acceptance. Do not start a second
registration merely because the first is waiting. Commands are in the
wallet-creation walkthrough in `docs/examples.md`.

## The transaction loop

Use this loop for native Machine transaction surfaces and for Petal actions that
project into the central outbox:

1. Discover the exact wallet, chain, account, and route.
2. Stage once through the documented `new` or `new.tx` write target.
3. List the resulting pending directory and identify the exact new action by
   reading its `intent.json`, `plan.md`, and simulation or policy projections.
4. Never use a wildcard, sequence number, `latest`, or list position as action
   identity.
5. Confirm only the exact inspected action.
6. If approval is required, validate the challenge and hand its ceremony URL to
   the human.
7. After the ceremony completes, retry only the exact documented `retry_path`.
8. Read the sent, failed, or receipt projection before reporting success.

A confirm write may return permission denied while projecting
`approval_challenge.json`. Verify the challenge's wallet, action, intent, and
expiry before presenting its ceremony URL. This is a waiting state, not a
reason to restage. After human approval, retry only its exact `retry_path`.

`confirm.override` is not a general escape hatch. Use it only when the
inspected policy projection explicitly permits that control and the human has
explicitly accepted the displayed warning.

For Solana, check the account fingerprint, derivation path, and fee payer in
`intent.json`; account identity remains there after submission. Correlate the
signature in `broadcast_attempted.json` with `receipt.json` and inspect the
outcome and confirmation status. Receipts have no account fingerprint and
private signing sidecars are not mounted. Genesis checks must pass before
broadcast; ambiguous sends reconcile by signature, never blind retry or
endpoint failover. See the Solana walkthrough in `docs/examples.md`.

## Sealed Approvals

Reusable authority is Broker-owned and projected under:

```text
wallets/<wallet>/sealed-approvals/
wallets/<wallet>/capabilities/
```

Read the active approval, scope, limits, expiry, and remaining capacity before
relying on it. A Petal may request use of a Sealed Approval, but it cannot mint,
broaden, renew, or revoke authority itself. If fresh approval is required, use
the central action's `approval_challenge.json` and `retry_path`; do not
invent a Petal-local approval flow.

## Updating wallet policy

Replacing `wallets/<wallet>/policy.json` starts a Broker ceremony. Prepare
the complete proposal outside the mount and keep the exact same proposed bytes
through `policy.validate_update`, human approval, and the
`policy.commit_update` retry. Inspect the update's status and challenge, then
verify the committed policy and terminal status. Editing or reformatting the
proposal creates a different request. Commands are in the policy-update
walkthrough in `docs/examples.md`.

## Petals and paid requests

Installed applications live only under `petals/<name>/`. Native Hyperliquid
and native `defi/intents` routes are retired. Discover the installed package
and use its local instructions instead of guessing a route from an older
example.

Paid HTTP operations live under `requests/`. They are actions, not ordinary
reads: inspect the request plan, selected payment protocol, maximum amount,
wallet, and approval projection before confirming. Keep vendor-specific request
syntax in the relevant Petal or request documentation rather than assuming a
provider contract from this root guide.
