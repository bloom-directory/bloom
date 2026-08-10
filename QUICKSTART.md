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
cat wallets/alice/address
cat wallets/alice/public_key
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
  > wallets/alice/chains/anvil/outbox/new.tx

ls wallets/alice/chains/anvil/outbox/pending
cat wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
printf 'confirm\n' \
  > wallets/alice/chains/anvil/outbox/pending/<id>/confirm
```

When fresh owner approval is required, the confirm returns permission denied
after projecting `approval_challenge.json`. Verify its action identity, exact
review, and expiry, complete the Broker ceremony, then retry the same confirm:

```sh
cat outbox/pending/<action_id>/approval_challenge.json
printf 'confirm\n' \
  > wallets/alice/chains/anvil/outbox/pending/<id>/confirm
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
packaging/triad/release/test-machine-authority-boundary.sh
packaging/triad/release/check-machine-authority-boundary.sh --require-clean
```
