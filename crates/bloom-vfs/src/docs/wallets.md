# Wallets, passkeys, sessions and policy

Read this when a task creates or recovers a wallet, adds a passkey, inspects
delegated sessions or Sealed Approvals, or changes wallet policy. Ordinary
transfers and Petal actions do not need it.

## Creating a wallet

Writing a petname to `wallets/new` requests asynchronous passkey registration;
it does not create a local wallet. Read
`wallets/registrations/<petname>/status.json`, verify `requested_name`, and
forward `ceremony_url` to the human. Wait for `ceremony_state: COMPLETED`,
then read `result.json` and the new wallet projection. Cancel through that
registration's `cancel` control before acceptance. Do not start a second
registration merely because the first is waiting.

```sh
printf 'main\n' > wallets/new
cat wallets/registrations/main/status.json     # requested_name, ceremony_url
cat wallets/registrations/main/status.json     # poll until ceremony_state is COMPLETED
cat wallets/registrations/main/result.json
cat wallets/main/projection.json
printf 'cancel\n' > wallets/registrations/main/cancel   # before acceptance only
```

Pass the complete Broker URL to the human, including any `#` fragment, with
its hostname, scheme and port unchanged. A localhost ceremony needs a browser
on the Bloom host; an assigned HTTPS relay ceremony can use another device.
Launch URLs are owner access capabilities: keep them out of logs and
Petal-visible data. Mnemonic import is an owner custody ceremony, not a
mounted write; a mnemonic, private key, passkey response or PRF output never
belongs in the mount. BIP-39 registration and import create the EVM and
Solana account-number-zero children together.

## Recovering a wallet

To recover a wallet after losing its passkeys, write only its name to
`wallets/recover`. Read `wallets/recoveries/<petname>/status.json`, verify
`requested_name`, and forward the complete `ceremony_url` to the human. The
recovery ID and secret, and the replacement passkey, belong only in the
Broker-hosted browser page. A spent one-use URL disappears from status while
the operation remains readable and cancellable (`cancel` beside it). After
`SUCCEEDED`, read `result.json`.

Recovery replaces the wallet's passkeys rather than adding one: the
replacement becomes the only active passkey and every other passkey, on any
device, is revoked. Tell the human that their other devices can no longer
approve until they add passkeys again. A cancelled or expired operation can be
started again with a fresh write to `wallets/recover`.

## Accounts

To create another account number, write `{"request_id":"<id>"}` to
`wallets/<wallet>/new`. The ceremony creates both the EVM and Solana keys
under the one number Signer chooses. Reusing the same request ID resumes or
returns that same creation. Reading `new` reports `failed`, `expired`, or
`cancelled` when a ceremony ends unsuccessfully; that result stays attached to
its request ID, so write a new ID to start another ceremony.

A number is the derivation path itself (EVM `m/44'/60'/0'/0/<n>`, Solana
`m/44'/501'/<n>'/0'`), so it is stable across restarts and reorderings. The
files that name one key live only beneath a numbered account:
`wallets/<wallet>/<n>/address.evm`, `address.sol`, each with `.qr.svg` and
`.qr.png` variants, and `public_key`. An outbox under an account holds only
the actions that account's key staged; a body `account_fingerprint` in
`new.tx` may be a unique prefix but must name the path's own account.

Solana `balance*` leaves contact the chain; `address` and account listings
need only Bloom's projection and keep working when a node is unreachable.
`status/chains/<solana-chain>/status.json` renders even when calls fail, with
the failed fields `null` and `errors` saying why; `broadcast.eligible` means an
attempt is permitted, not that a transaction will land. Submission requires
the chain's pinned genesis; devnet and local validators are opt-in.

## Check passkeys before hosted approvals

A localhost passkey cannot approve on the hosted relay domain, even in the
same browser. Before a hosted signing or policy ceremony, check
`status/ceremonies.json` and the wallet's `passkeys/` entries (`surface` and
`state`). If the wallet has only local passkeys, explain that hosted approvals
require a remote passkey and, with the human's agreement, add one as below.
Then resume the original operation with its unchanged proposal or intent.

## Adding a passkey

`wallets/<wallet>/passkeys/` lists the wallet's passkeys, one directory each,
named `<created date>-<surface>-<digest>`, holding `surface` (`local` for
this host's browser, `remote` for the relay), `created`, `state`,
`credential_id`, and `name`.

```sh
echo remote > wallets/<wallet>/passkeys/new
cat wallets/<wallet>/passkeys/latest/url      # forward the complete link to the human
cat wallets/<wallet>/passkeys/latest/status   # awaiting_user, then a final state
```

Use `remote` unless the human asks for this host's browser; an empty write
picks `remote` when the relay is available and `local` otherwise. The human
opens the link on the new device, gets an approval link and a six-digit code,
opens the approval link on a device that already has a passkey for the wallet,
checks that both pages show the same code, and approves there. Bloom chooses
which existing passkey approves.

When `status` stops being `awaiting_user`:

- `succeeded`: enrolled. Ask the human what to call it and write that to the
  passkey's `name`; `by-name/<name>` then links to it. Names carry no
  authority.
- `already_registered`: nothing was added and nothing is wrong; that device's
  provider already holds one of this wallet's passkeys, usually through
  passkey sync. Do not retry.
- `cancelled`, `expired` or `failed`: nothing changed. Start again with a
  fresh write to `new` only if the human still wants the passkey.

If the write to `new` fails with *Operation not permitted*, no active passkey
could approve an addition on any usable surface; repeating does not help.
Check `passkeys/` and the relay status. If `/status/ceremonies.json` reports
`stage: credentials_expired`, remote approvals stay paused until the owner
runs the `command` in `/status/ceremonies-repair.json`; localhost approvals
still work.

The link is single-use and disappears once opened while `status` stays
readable. Write to `latest/cancel` to abandon an enrollment. Every enrollment
stays under `enrollments/<operation>/`; writing `new` again while one to the
same surface is waiting reuses it.

## Delegated sessions

Every key a Petal derived from one of an account's family keys is mounted at
`wallets/<wallet>/<n>/sessions/<petal>/<key-slot>/session.json`: the
delegating owner key, the delegated key and addresses, the scope (routes,
operation classes, suites, lifetime), the recorded approvals, and the truthful
`signing_authority` (`pending`, `active`, `stopped`, `expired`, or
`package_replaced`). Writing to the sibling `stop` file revokes the session's
approvals through the Broker; it is idempotent and works after the Petal is
uninstalled. `expires_at_ms` is the expiry of the approval terms, not the time
the Petal last polled.

## Sealed Approvals

Reusable authority is Broker-owned and projected under
`wallets/<wallet>/sealed-approvals/`. Read the active approval, scope,
limits, expiry, and remaining capacity before relying on it. A Petal may
request use of a Sealed Approval but cannot mint, broaden, renew, or revoke
authority. If fresh approval is required, use the central action's
`approval_challenge.json` and `retry_path`; do not invent a Petal-local
approval flow.

## Updating wallet policy

Replacing `wallets/<wallet>/policy.json` starts a Broker ceremony. Prepare
the complete proposal outside the mount and keep the exact same proposed bytes
through `policy.validate_update`, human approval, and the
`policy.commit_update` retry. Editing or reformatting the proposal creates a
different request.

```sh
cat wallets/alice/policy.json > proposed-policy.json      # edit the complete proposal
cp proposed-policy.json wallets/alice/policy.json
cat wallets/alice/policy-updates/latest/status.json
cat wallets/alice/policy-updates/latest/approval_challenge.json   # verify, then forward its ceremony URL
cp proposed-policy.json wallets/alice/policy.json          # after approval: the same bytes
cat wallets/alice/policy.json                              # verify the committed policy
```
