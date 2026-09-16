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

When a person — rather than an agent — needs to see their wallet, `views/`
holds read-only pages they can open in a browser straight from the mount:
`views/index.html` for what they hold and what needs them, plus `wallets`,
`receive`, `activity`, `next-moves`, `contacts`, `policy`, `chains` and
`markets`. Give them the file path and let the browser render it; do not
paste the HTML into a transcript, and keep reading the canonical values from
the JSON leaves. When the answer must live inside the chat itself, quote
`views/briefing.md` — the same Today briefing as pasteable Markdown. These
pages observe only: their one local script sorts and selects, and nothing in
them approves or executes an action. A person who wants them to look
different edits `~/.bloom/skin.css` on the host. See `views/AGENTS.md`.

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

`wallets/<wallet>/accounts.json` is the authenticated Broker projection of a
BIP-39 wallet's public derived accounts. It includes public fingerprints,
derivation paths, lifecycle state, supported suites, and chain projections; it
never contains a mnemonic, seed, passphrase, PRF output, or private child key.
Do not choose the first account in this list. Choose the numbered account path for the intended sender; wallet-level
outboxes use account 0.

Each entry in `accounts.json` carries a `number`, and `wallets/<wallet>/<n>/`
is that account: `account.json` shows its EVM and Solana keys (path, address,
fingerprint, lifecycle), and `wallets/<wallet>/<n>/chains/<chain>/...` is the
same chain view as `wallets/<wallet>/chains/<chain>/...` read through account
`n`'s key for that chain's family. A number is the derivation path itself (EVM
`m/44'/60'/0'/0/<n>`, Solana `m/44'/501'/<n>'/0'`), so it is stable across
restarts and reorderings. A legacy or imported single-key wallet is account 0.
Outbox entries under an account are only the ones its key staged; another
account's entry is not found there. Staging works through the numbered path
(`wallets/<wallet>/<n>/chains/<chain>/outbox/new.tx`), which fixes the sender
to that account's key; a body fingerprint naming another account is an error.
The wallet-level `wallets/<wallet>/chains/...` path stages from account 0.

Mnemonic import is an owner custody ceremony, not a mounted agent write. V1
accepts the standard mnemonic and exposes no passphrase input;
passphrase-protected mnemonics are unsupported. BIP-39 registration and import
create the canonical EVM and Solana account-number-zero children together.

To create another account number, write `{"request_id":"<id>"}` to
`wallets/<wallet>/new`. The ceremony creates both the EVM and Solana keys under
the one number Signer chooses. Reusing the same request ID resumes or returns
that same account creation. Reading `new` reports `failed`, `expired`, or
`cancelled` when a ceremony terminates unsuccessfully. That result remains
attached to its request ID; write a new request ID to start another ceremony.

### Account-scoped Petals and sessions

Installed Petals also run under `wallets/<wallet>/<n>/petals/<petal>/...` with
the same routes as `/petals/<petal>/...`. Account 0 and the flat mount list
every installed Petal; a nonzero account runs only Petals whose `petal.toml`
declares `[account] aware = true` — an unaware Petal is not found there and
the message names the missing declaration. The host injects the trusted
identity (`bloom.wallet`, `bloom.account`, and, when the route's family is
unambiguous, `bloom.owner_key_fingerprint`) next to `bloom.route_id`; a caller
context entry using the `bloom.` prefix is rejected before injection.

Every key a Petal derived through a numbered account is mounted at
`wallets/<wallet>/<n>/sessions/<petal>/<key-slot>/session.json`. It reports
the delegating owner key, the delegated key and addresses, the scope (routes,
operation classes, suites, lifetime), the recorded approvals, and the truthful
`signing_authority`: `pending`, `active`, `stopped`, `expired`, or
`package_replaced` (the installed package no longer matches the scope's
hash; `routes_known` is false then). Writing to the sibling `stop` file
revokes the session's approvals through the Broker; it is idempotent, works
after the Petal is uninstalled, and after it succeeds only Exact-selector
signing for the scope's remaining operation classes may still be available
(`eligible_exact_routes` lists those routes). Replacing or removing an
installed package that still has active or unresolved pending sessions is refused with their mounted
paths unless the owner passes `--force` to `petal install` or
`petal uninstall` — the stranded sessions then read `package_replaced`, and
their `stop` still revokes them.

Session `expires_at_ms` is the expiry of the approval terms accepted by Broker,
not the time the Petal last polled. Old records without that expiry report null
and remain guarded until stopped or forcibly removed. Durable signing retries
are bound to the full selected key, so accounts using the same route keep
separate approval identities.

A wallet's chains are listed at `wallets/<wallet>/chains` and include both
EVM chains and any configured Solana chains — `ls wallets/<wallet>/chains`
enumerates both together. Solana chains route through the exact same
`wallets/<wallet>/chains/<chain>/outbox/...` route family described below
(stage at `outbox/new.tx`, confirm/cancel under `outbox/pending/<id>/`,
inspect `outbox/{pending,sent,failed}/<id>/`) — there is no separate
Solana-specific surface to look for.

Newly generated Bloom configuration includes `solana-mainnet` for reads, with
broadcasting disabled. Existing configurations keep their configured networks;
devnet and local validators are opt-in. If an owner enables mainnet broadcasting,
wallet policy and the approval ceremony still apply. Discover the available
networks with `ls wallets/<wallet>/chains` rather than assuming a network exists.

### Reading Solana balances

A Solana chain directory exposes an account-addressed surface:

```sh
ls  wallets/<wallet>/chains/<solana-chain>/accounts/       # one dir per active child
cat wallets/<wallet>/chains/<solana-chain>/accounts/<fingerprint>/address
cat wallets/<wallet>/chains/<solana-chain>/accounts/<fingerprint>/balance
```

Directory names are the **full** lowercase account fingerprint. A body
`account_fingerprint` in `new.tx` may be a prefix, but it must name the
path's own account: the wallet-level outbox stages from account 0 and refuses
any other account's fingerprint, so transfers from account `n` belong on
`wallets/<wallet>/<n>/chains/<chain>/outbox/new.tx`. A prefix is never a
path — a prefix that is unique today stops being unique when another account
is allocated.

`chains/<chain>/balance`, `balance.raw` and `balance.json` resolve to account
0: the canonical initial child while it is active, and a failure naming the
canonical `accounts/<fingerprint>/` paths once it is not. Bloom will not pick
another account for you, because spending from the wrong one is not
recoverable.

Listing accounts, stat-ing any leaf, and reading `address` need only Bloom's
own projection, so they keep working when a Solana node is unreachable. Only
`balance*` contacts the chain. If a balance read fails but `address` still
works, inspect chain health and RPC errors before retrying.

Chain health lives once per chain, not per wallet:

```sh
cat status/chains/<solana-chain>/status.json   # health, slot, genesis, broadcast posture
cat status/chains/<solana-chain>/connected
```

`status.json` still renders when calls fail — the failed fields are `null`
and `errors` says why. `broadcast.eligible` means an attempt is *permitted*
(broadcast enabled, genesis verified on every endpoint); it does not promise
a transaction will land.

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
reason to restage. After human approval, retry only its exact `retry_path`;
`plan_path` and `retry_path` name the outbox the confirm was written through
(`wallets/<wallet>/<n>/chains/...` for account `n`, the wallet-level path for
account 0).

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
```

Read the active approval, scope, limits, expiry, and remaining capacity before
relying on it. A Petal may request use of a Sealed Approval, but it cannot mint,
broaden, renew, or revoke authority itself. If fresh approval is required, use
the central action's `approval_challenge.json` and `retry_path`; do not
invent a Petal-local approval flow.

For a native Solana transfer, the challenge is projected beside the pending
wallet transfer instead:

```sh
cat wallets/<wallet>/chains/<solana-chain>/outbox/pending/<id>/approval_challenge.json
printf 'confirm\n' > wallets/<wallet>/chains/<solana-chain>/outbox/pending/<id>/confirm
```

Use the challenge's `retry_path` verbatim after the owner completes its
`ceremony_url`; verify `tx_id`, `wallet`, `chain`, amount, destination, and
`expiry_ms` first. `plan_path` and `retry_path` name the outbox the confirm was
written through: `wallets/<wallet>/<n>/chains/...` for account `n`, the
wallet-level path for account 0's wallet-level outbox.

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

A paid request's confirm and cancel operations are serialized. Once execution
has started, cancellation cannot undo the payment. A timeout or interrupted
confirmation does not prove non-payment: inspect the exact request's receipt
and merchant outcome before taking further action. Before transmission, the
existing receipt records the full possible charge as unresolved. Unresolved
charges remain in recorded spending, including after a restart or timeout;
receiving a response updates the same receipt without counting it twice. Other
requests can proceed within any remaining budget. Do not repeat an unresolved
payment by restaging it. A failed merchant retry still counts toward recorded
spending.
