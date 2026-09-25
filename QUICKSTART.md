# Quickstart

Bloom exposes a mounted virtual filesystem, with production authority split
across three processes:

```text
mounted filesystem / CLI -> Machine -> Broker -> Signer
```

Machine owns public projections, staging, simulation, and result display.
Broker owns policy validation, Sealed Approvals, ceremonies, and authorization.
Signer alone owns keys and produces signatures. Machine never connects to
Signer directly and has no authority fallback when Broker is unavailable.

The normative contract is
[`docs/specs/2026-07-23-triad-process-architecture.md`](./docs/specs/2026-07-23-triad-process-architecture.md).

## 1. Start the separate-process developer profile

This launcher runs the real Machine, Broker, and Signer protocols separately.
It does not claim production UID isolation, but it preserves the authority
boundaries and genuine passkey flow.

Check out `bloom`, `bloom-broker`, and `bloom-signer` side by side. Create the
canonical Machine config once; the launcher copies it into the isolated
developer root:

```sh
cargo run -p bloom -- init
```

For a no-mount or fast Machine edit loop, use the services-only workflow in
[`DEVELOPMENT.md`](./DEVELOPMENT.md). The mounted workflow below additionally
requires the platform mount prerequisites described there.

```sh
mkdir -p ~/.bloom/triad-dev/machine-home \
  /tmp/bloom-triad-mount /tmp/bloom-triad-logs

scripts/triad-dev-launch.sh \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --mount /tmp/bloom-triad-mount \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

Use ordinary filesystem tools from the mount:

```sh
cd /tmp/bloom-triad-mount
cat docs/README.md
cat status/daemon.json
ls chains
```

## 2. Register a wallet

Registration is a Broker custody operation completed by Signer. The write
projects a browser ceremony; it does not create custody inside Machine.

```sh
printf 'alice\n' > wallets/new
cat wallets/registrations/alice/status.json
```

The registration projection is keyed by the requested wallet petname. Verify
that `requested_name` is `alice` before opening its `ceremony_url`, polling it,
or cancelling it. Complete
the passkey ceremony and wait for `ceremony_state` to become `COMPLETED`, then
inspect the public wallet projection:

```sh
cat wallets/alice/0/address.evm
cat wallets/alice/0/public_key
cat wallets/alice/policy.json
```

If Broker or Signer is unavailable, custody and signing fail promptly. Public
reads, staging, and simulation may remain available; Machine never substitutes
another authority path.

## 3. Stage, review, and confirm

For an Anvil example, first run `anvil --port 8545` in another terminal.

```sh
printf '%s\n' \
  'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil' \
  > wallets/alice/0/chains/anvil/outbox/new.tx

ls wallets/alice/0/chains/anvil/outbox/pending
cat wallets/alice/0/chains/anvil/outbox/pending/<id>/plan.md
printf 'confirm\n' \
  > wallets/alice/0/chains/anvil/outbox/pending/<id>/confirm
```

When fresh owner approval is required, the confirm returns permission denied
after projecting `approval_challenge.json`. Verify its action identity, exact
review, and expiry, complete the Broker ceremony, then retry the same confirm:

```sh
cat outbox/pending/<action_id>/approval_challenge.json
printf 'confirm\n' \
  > wallets/alice/0/chains/anvil/outbox/pending/<id>/confirm
```

Broker authorizes the sealed payload and asks Signer to sign. Machine receives
only the public result under `outbox/sent/` or `outbox/failed/`.

## 4. Update policy

`wallets/<wallet>/policy.json` is the canonical writable policy surface. Keep
the proposal bytes unchanged across the ceremony:

```sh
cat wallets/alice/policy.json > /tmp/alice-policy.json
# Edit the complete canonical JSON document.
cp /tmp/alice-policy.json wallets/alice/policy.json
cat wallets/alice/policy-updates/latest/status.json
cat wallets/alice/policy-updates/latest/approval_challenge.json
```

The first write calls Broker `policy.validate_update`. Broker verifies the
Signer-authenticated baseline, parses the proposal, constructs the exact
review, and originates a `policy_update` custody ceremony. Complete it, then
retry the exact bytes:

```sh
cp /tmp/alice-policy.json wallets/alice/policy.json
cat wallets/alice/policy-updates/latest/status.json
```

Machine supplies the completed custody receipt to Broker
`policy.commit_update`. Broker then invokes Signer's authenticated
compare-and-swap. Changed proposal bytes or a changed baseline fail closed.

## 5. Prepare a Sealed Approval

Reusable signing capacity is durable Broker/Signer authority. Machine forwards
canonical requests and projects only public status and limits:

```sh
cp approval-prepare.json wallets/alice/sealed-approvals/new.json
cat wallets/alice/sealed-approvals/new.json
cat wallets/alice/sealed-approvals/active.json
cat wallets/alice/sealed-approvals/<id>/status.json
cat wallets/alice/sealed-approvals/<id>/limits.json
```

Complete the owner ceremony before use. Broker enforces subject, operation
classes, limits, expiry, revocation, counters, and current policy; Signer
enforces structural receipt bindings for every signature.

## 6. Petals

Petals are external packages. Discover installed route contracts instead of
assuming built-in venue APIs:

```sh
cat docs/petals.md
find petals -path '*/meta/route-contract.json' -maxdepth 4 -print
```

Petal payload signing travels through Machine to Broker and Signer. A Petal
that needs a delegated identity receives a public Petal-scoped `KeyRef`; its
private sub-key remains inside Signer.

## Local verification

Use local tests and a Tart VM for macOS packaging or service isolation:

```sh
cargo test -p bloom-it --test triad_release --locked
cargo test -p bloom-it --test linux_packaging --locked
```

## Ceremony surfaces

`bloom ceremony surfaces` (also `bloom vfs cat /status/ceremonies.json`) reports
Signer-approved desired exposure and Broker-confirmed effective readiness.
A pending certificate or route is not working remote access. Treat an
incomplete provisioning stage as retryable setup work.

Wallet creation and import use Broker's default surface. Use
`bloom wallet new main --local` or `bloom wallet import main --local` to request
the canonical localhost surface. For the mounted registration control, the
plain wallet name retains default selection; an explicit local request is
`{"name":"main","surface_selection":"local"}` written to `/wallets/new`.
A live registration cannot change surfaces on retry: cancel it before starting
an attempt on another surface. Wallet secret input remains in the browser.

Copy the full returned ceremony URL, including its fragment. Localhost requires
a browser on the Bloom host. Remote ceremonies use that installation's assigned
HTTPS hostname. The two origins require distinct RP-specific passkeys, even
when both are stored in the same password manager. A synchronized copy is not
independent redundancy. Completing an approval activates authority; execution
and broadcast remain separate operations.

Installed administration uses `bloom-signer admin` directly. For your login:

```sh
# Linux
sudo /usr/libexec/bloom/current/bloom-signer admin status --login-uid "$(id -u)"
# macOS
sudo /usr/local/libexec/bloom/current/bloom-signer admin status --login-uid "$(id -u)"
```

Use `status`, `remote-enabled`, `localhost-only` or `provision`; help works
without `sudo`. The installer already provisions within its root step.
`provision` retries hosted setup with the installation's protected identity;
it never accepts an arbitrary domain.

To add a passkey on another device, such as a phone, run
`bloom wallet add-passkey main`. The new passkey is remote by default; add
`--to local` for a browser on this host. Open the returned URL on the new
device first and keep that page open. It gives you an approval link: open it on
a device that already has a passkey for the wallet (the page can share or copy
it), compare the six-digit code, and approve there. Then return to the new
device to create its passkey. Bloom chooses which existing passkey approves,
preferring one on the new passkey's own surface. The new credential becomes
active only after both steps finish; wallet addresses remain unchanged.
Refreshing or closing the new device's page before completion requires a fresh
pairing. If the new device already holds one of the wallet's passkeys, for
example through iCloud Keychain or another passkey provider that syncs, nothing
is added and the page says that device can already approve for the wallet.

Machine status and VFS cannot switch modes. Localhost-only switching requires
local credential coverage for every active passkey-dependent wallet; coverage
does not prove the authenticator is still available. Enroll missing local
access through Broker before retrying. Relay outage never extends a ceremony
or makes a remote-only credential work on localhost.

If source access is lost, open the installation's ceremony origin to begin
recovery with the wallet ID and saved recovery-record ID. The landing page does
not collect the secret. Enter the saved secret only in the resulting recovery
ceremony, and create the replacement passkey. Recovery preserves wallet addresses,
revokes all previous wallet passkeys, and issues a new single-use recovery record;
save that record before closing the result. The old recovery factor cannot be
used again. Encrypted result retrieval lasts 15 minutes after commit and requires
the original browser key. Losing that key does not undo recovery or permit the
server to encrypt the record to a new key.
