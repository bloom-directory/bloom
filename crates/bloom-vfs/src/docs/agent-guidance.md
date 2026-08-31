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
cat docs/examples.md
cat docs/petals.md
```

`next.md` summarizes actions that currently need attention. `docs/petals.md`
lists installed Petals. For a Petal, read both `petals/<name>/README.md` and
`petals/<name>/AGENTS.md` before using its routes.

## Authority and safety

Bloom has three real processes:

```text
Machine <-> Broker <-> Signer
```

- Machine exposes this VFS, public wallet projections, staging, simulation,
  broadcast, and reconciliation.
- Broker owns WebAuthn ceremonies, policy decisions, Sealed Approvals, and
  authorization.
- Signer owns encrypted custody, derivation, replay protection, and signatures.

Machine never holds mnemonics, private keys, PRF outputs, or signing authority.
Never provide secret ceremony input through a VFS write, shell argument,
environment variable, fixture, or log. A ceremony URL is safe to forward to the
human who controls the passkey; ceremony input remains in the Broker-hosted
browser flow.

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

## Wallet and account identity

```sh
ls wallets/
cat wallets/<wallet>/projection.json
cat wallets/<wallet>/accounts.json
cat wallets/<wallet>/address
cat wallets/<wallet>/address.qr.svg
```

Never select a wallet or account by directory order, list position, or an
address alias. Account-sensitive operations bind the public-key fingerprint and
derivation path. Use the full fingerprint in persistent paths and records.

Solana wallets can have several compatible children. The chain-level balance
alias works only when selection is unambiguous. Prefer an account-specific path:

```sh
cat wallets/<wallet>/chains/solana/accounts/<full-fingerprint>/address
cat wallets/<wallet>/chains/solana/accounts/<full-fingerprint>/balance.json
```

If an input accepts a unique fingerprint prefix, treat that only as interactive
convenience. Ambiguity fails closed; inspect `accounts.json` and use the full
fingerprint.

## Creating a wallet

Wallet creation is asynchronous passkey registration:

```sh
printf 'main\n' > wallets/new
cat wallets/registrations/main/status.json
```

The write only requests the petname and does not create a local wallet. Read the
petname-keyed projection, verify its `requested_name`, and forward its
`ceremony_url` to the human. Poll the same `status.json` until
`ceremony_state` is `COMPLETED`, then read `result.json` and the new wallet
projection. Before acceptance, cancel with:

```sh
printf 'cancel\n' > wallets/registrations/main/cancel
```

Do not infer success from the initial write or create a second registration
while the first ceremony is merely waiting.

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

Example staging shape:

```sh
printf 'send 0.01 ETH to 0x...\n' \
  > wallets/<wallet>/chains/<chain>/outbox/new.tx
ls wallets/<wallet>/chains/<chain>/outbox/pending/
cat wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/intent.json
cat wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/plan.md
echo y > wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/confirm
```

The confirm write may return permission denied while Broker creates
`approval_challenge.json`. That is a waiting state, not a reason to restage:

```sh
cat wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/approval_challenge.json
```

Before presenting the ceremony, check that the challenge identifies the same
wallet, action, intent, and expiry you inspected. After human approval, retry
the challenge's exact `retry_path`. Never retry a different action and never
blindly repeat staging after an ambiguous result.

`confirm.override` is not a general escape hatch. Use it only when the
inspected policy projection explicitly permits that control and the human has
explicitly accepted the displayed warning.

For Solana, verify the selected Ed25519 account fingerprint in the staged
intent, signing request, and receipt. Broadcast also requires the configured
genesis pin to agree with every live endpoint. An ambiguous send reconciles by
signature; do not request a blind retry or endpoint failover.

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

`wallets/<wallet>/policy.json` is the canonical public policy projection.
Updating it is a Broker ceremony, not a local file edit:

1. Read the current bytes and prepare the complete replacement.
2. Write the proposal to `wallets/<wallet>/policy.json`.
3. Read `wallets/<wallet>/policy-updates/latest/status.json` and
   `approval_challenge.json`.
4. Broker runs `policy.validate_update`; forward the ceremony URL to the human.
5. After approval, retry the exact same proposed bytes. Broker then runs
   `policy.commit_update`.
6. Verify the committed projection and terminal update status.

Do not merge, normalize, or regenerate the proposal between validation and
commit. The exact same proposed bytes are the authorized object.

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
