# Wallets, accounts and passkeys

Read the section you need. The mount's `AGENTS.md` has the rules every task
uses.

## Accounts

`wallets/<wallet>/accounts.json` is the authenticated Broker projection of a
wallet's public derived accounts: fingerprints, derivation paths, lifecycle
state, suites and chain projections. It never contains a mnemonic, seed,
passphrase, PRF output or private key.

Each entry's `number` is the derivation path itself (EVM `m/44'/60'/0'/0/<n>`,
Solana `m/44'/501'/<n>'/0'`), so it is stable across restarts and
reorderings. A single-key wallet is account 0. `wallets/<wallet>/<n>/` holds
`account.json` (its EVM and Solana keys), `address.evm`, `address.sol` (each
with `.qr.svg` and `.qr.png`), `public_key`, and `chains/<chain>/` for every
configured chain of its key families. The wallet directory itself has no key
files.

Outbox entries under an account are only the ones its key staged. A body
`account_fingerprint` in `new.tx` may be a unique prefix, but it must name the
path's own account; one naming another account is rejected.

To create another account number, write `{"request_id":"<id>"}` to
`wallets/<wallet>/new`. The ceremony creates both the EVM and Solana keys under
the number Signer chooses. Reusing the request ID resumes or returns that same
creation. Reading `new` reports `failed`, `expired` or `cancelled` when a
ceremony ends unsuccessfully; write a new request ID to start another.

Mnemonic import is an owner custody ceremony, not a mounted write. It accepts
a standard mnemonic without a passphrase. BIP-39 registration and import create
the EVM and Solana account-zero keys together.

## Solana accounts and chain health

Choose the intended Solana entry in `accounts.json` by its full fingerprint and
derivation path, use its `number` as `<n>`, and verify the key in
`wallets/<wallet>/<n>/account.json`. `address`, `balance`, `balance.raw` and
`balance.json` live under `wallets/<wallet>/<n>/chains/<solana-chain>/`.
Listing accounts and reading `address` need no RPC; only `balance*` contacts
the chain.

Chain health is per chain: `status/chains/<chain>/status.json` renders even
when calls fail (failed fields are `null`, `errors` says why).
`broadcast.eligible` means an attempt is permitted (genesis verified on every
endpoint), not that it will land. Solana submission requires a valid pinned
genesis; the default `solana-mainnet` configuration includes it.

## Creating a wallet

Writing a petname to `wallets/new` requests asynchronous passkey registration;
it does not create a local wallet. Read
`wallets/registrations/<petname>/status.json`, verify `requested_name`, and
forward `ceremony_url` to the human. Wait for `ceremony_state: COMPLETED`,
then read `result.json` and the new wallet projection. Cancel through the
registration's `cancel` control before acceptance. Do not start a second
registration because the first is waiting. Commands are in
`docs/examples.md`.

A localhost ceremony needs a browser on the Bloom host; an assigned HTTPS relay
ceremony can use another device.

Create a wallet only when the owner asks. `main`'s default policy, from the
Petals chosen at setup, is proposed only once every chosen Petal is
installed: until then `bloom wallet default-policy main` names the missing
ones and proposes nothing, and once they are installed it proposes the whole
policy in one ceremony. Forward its link like any other ceremony URL.

## Recovering a wallet

To recover a wallet after losing its passkeys, write only its name to
`wallets/recover`. Read `wallets/recoveries/<petname>/status.json`, verify
`requested_name`, and forward the complete `ceremony_url`. The recovery ID,
secret and replacement passkey belong only in the Broker-hosted page. A spent
one-use URL disappears from status while the operation stays readable and
cancellable. After `SUCCEEDED`, read `result.json`.

Recovery replaces the wallet's passkeys: the replacement becomes the only
active passkey, and every other passkey, on any device, is revoked. Tell the
human their other devices cannot approve until they add passkeys again. A
cancelled or expired recovery can be started again with a fresh write.

## Passkeys and hosted approvals

A localhost passkey cannot approve on the hosted relay domain, even in the same
browser. Before a hosted ceremony, check `status/ceremonies.json` and the
wallet's `passkeys/` entries (`surface`, `state`). If the wallet has only local
passkeys, explain that hosted approvals need a remote passkey and, with the
human's agreement, add one as below, then resume the original operation
unchanged.

`wallets/<wallet>/passkeys/` lists one directory per passkey, named
`<created date>-<surface>-<digest>`, holding `surface` (`local` or `remote`),
`created`, `state`, `credential_id` and `name`.

To add a passkey on another device, write its surface to `new` and follow
`latest`. Use `remote` unless the human asks for this host's browser; an empty
write picks `remote` when the relay is available.

```sh
echo remote > wallets/<wallet>/passkeys/new
cat wallets/<wallet>/passkeys/latest/url      # forward the complete link
cat wallets/<wallet>/passkeys/latest/status   # awaiting_user, then a final state
```

The human opens the link on the new device. That page shows an approval link
and a six-digit code; they open the approval link on a device that already has
a passkey for the wallet, check both pages show the same code, and approve.
Bloom chooses which existing passkey approves.

When `status` leaves `awaiting_user`:

- `succeeded`: enrolled. Ask the human what to call it and write that to the
  passkey's `name` (`by-name/<name>` then links to it). Names are local labels
  with no authority.
- `already_registered`: nothing added and nothing wrong. That device's
  provider already holds one of the wallet's passkeys, usually through sync.
  Do not retry.
- `cancelled`, `expired` or `failed`: nothing changed. Start again only if the
  human still wants it.

*Operation not permitted* on `new` means no active passkey can approve an
addition on a usable surface, for example only remote passkeys while the relay
is down. Tell the human and check `passkeys/` and the relay status.

If `status/ceremonies.json` shows `stage: credentials_expired`, remote
approvals are paused until the owner runs the `command` in
`status/ceremonies-repair.json` (it needs `sudo`). Localhost approvals still
work.

The link is single-use. Write to `latest/cancel` to abandon an enrollment.
Every enrollment stays under `enrollments/<operation>/`.

## Delegated sessions

Every key a Petal derived from an account's key is at
`wallets/<wallet>/<n>/sessions/<petal>/<key-slot>/session.json`: the
delegating and delegated keys, scope, approvals, `expires_at_ms` (the expiry of
the approval terms) and `signing_authority` (`pending`, `active`, `stopped`,
`expired` or `package_replaced`). Writing the sibling `stop` file revokes the
session's approvals through Broker; it is idempotent and works after the Petal
is uninstalled. Afterwards only Exact-selector signing may remain
(`eligible_exact_routes`). Replacing or removing a package with live sessions
is refused unless the owner passes `--force` to `petal install` or
`petal uninstall`; those sessions then read `package_replaced` and `stop`
still revokes them.

## Outbox recovery

`bloom wallet confirm` exits 3 when owner approval is pending and 4 when
confirmation has no recorded result yet; `--text cancel` discards an unsigned
entry. Discard is refused while another operation is active, and an expired
entry that may be signed stays pending.

An unreadable signing record does not prove nothing signed: preserve it,
inspect Broker operation status and the chain nonce, and restore it from backup
before retrying. An already broadcast transaction needs
`bloom wallet cancel` and its own approval. Dropping a reservation does not
renumber later rows: restage with an explicit nonce to fill a gap.
