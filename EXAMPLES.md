# Bloom mounted-filesystem examples

These examples describe the current triad architecture:

```text
mounted filesystem -> Machine -> Broker -> Signer
```

Machine stages actions and projects public state. Broker owns policy checks,
Sealed Approvals, ceremonies, and authorization. Signer owns all private keys
and signing. There is no Machine authority fallback.

Examples assume Bloom is mounted at `/bloom`. See
[`QUICKSTART.md`](./QUICKSTART.md) for the separate-process launcher.

## Public reads

```sh
ls /bloom/chains
cat /bloom/chains/ethereum/head/number
cat /bloom/chains/base/gas/current.json
cat /bloom/prices/spot/eth.usd
cat /bloom/status/daemon.json

ls /bloom/wallets
cat /bloom/wallets/alice/address
cat /bloom/wallets/alice/public_key
cat /bloom/wallets/alice/kind
cat /bloom/wallets/alice/policy.json
```

Wallet paths are authenticated public projections, not key storage.

## Register a wallet

```sh
printf 'alice\n' > /bloom/wallets/new
cat /bloom/wallets/registrations/alice/status.json
```

The registration projection is keyed by the requested wallet petname. Verify
that `requested_name` is `alice` before opening its `ceremony_url`, polling it,
or cancelling it. Broker
originates the custody ceremony and Signer creates the key after owner
authentication. Machine exposes only the resulting public projection. Import,
recovery, rebind, credential changes, and deletion use the same custody boundary
and never accept secret material through the mount.

## Stage, review, and confirm

```sh
printf '%s\n' \
  'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx

ls /bloom/wallets/alice/chains/anvil/outbox/pending
cat /bloom/wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
printf 'confirm\n' \
  > /bloom/wallets/alice/chains/anvil/outbox/pending/<id>/confirm
```

If fresh owner approval is required, the write returns permission denied after
the central action projects a challenge:

```sh
cat /bloom/outbox/pending/<action_id>/approval_challenge.json
```

Verify the action identity, exact review, and expiry. Complete the Broker-owned
ceremony, then retry the same mounted confirm. Broker authorizes the sealed
payload and Signer signs it; Machine never handles a signing key.

```sh
cat /bloom/outbox/sent/<action_id>/status.json
cat /bloom/outbox/sent/<action_id>/result.json
```

## Update policy

The only writable policy surface is the complete canonical JSON document:

```sh
cat /bloom/wallets/alice/policy.json > /tmp/alice-policy.json
# Edit the complete document, retaining canonical JSON encoding.
cp /tmp/alice-policy.json /bloom/wallets/alice/policy.json
cat /bloom/wallets/alice/policy-updates/latest/status.json
cat /bloom/wallets/alice/policy-updates/latest/approval_challenge.json
```

The initial write calls `policy.validate_update`. Broker verifies the current
Signer-authenticated baseline, parses the proposal, constructs the exact
review, and starts a `policy_update` custody ceremony. Complete it and retry
the exact proposed bytes:

```sh
cp /tmp/alice-policy.json /bloom/wallets/alice/policy.json
cat /bloom/wallets/alice/policy-updates/latest/status.json
```

Machine passes the completed custody receipt to `policy.commit_update`.
Broker calls Signer's policy compare-and-swap with the proposal, ceremony
receipt, and Broker validation receipt. Conflicting baselines fail closed.

## Prepare and inspect a Sealed Approval

```sh
cp approval-prepare.json \
  /bloom/wallets/alice/sealed-approvals/new.json
cat /bloom/wallets/alice/sealed-approvals/new.json
cat /bloom/wallets/alice/sealed-approvals/active.json
cat /bloom/wallets/alice/sealed-approvals/<id>/status.json
cat /bloom/wallets/alice/sealed-approvals/<id>/limits.json
```

Complete the returned owner ceremony before use. Broker durably enforces the
exact subject, operation classes, counters, expiry, revocation, and current
policy. Signer verifies the structural authorization for every signature.
Machine only projects public ceremony and capacity state.

Renew or revoke with canonical Broker request documents:

```sh
cp approval-renew.json \
  /bloom/wallets/alice/sealed-approvals/<id>/renew
cp approval-revoke.json \
  /bloom/wallets/alice/sealed-approvals/<id>/revoke
```

## Chain and contract reads

```sh
cat /bloom/chains/ethereum/blocks/19000000/full.json
cat /bloom/chains/ethereum/tx/<hash>/receipt.json
cat /bloom/chains/ethereum/addresses/<address>/balance.json
cat /bloom/chains/base/addresses/<address>/tokens/<token>/balance.json
cat /bloom/chains/ethereum/contracts/<contract>/abi
cat /bloom/chains/ethereum/contracts/<contract>/methods/decimals.sig
```

Large virtual collections may not be enumerable; address known block numbers,
transaction hashes, contracts, and token addresses directly.

## Simulation

```sh
cat <<'JSON' > /bloom/simulate/new
{
  "chain": "anvil",
  "from": "0x0000000000000000000000000000000000000001",
  "to": "0x0000000000000000000000000000000000000002",
  "value": "0",
  "data": "0x"
}
JSON

cat /bloom/simulate/latest/result.json
cat /bloom/simulate/latest/plan.md
```

Simulation is unsigned and creates no signing authority.

## Watches

```sh
cat <<'EOF' > /bloom/watch/new
kind = "block"
chain = "anvil"
EOF

tail -f /bloom/watch/<id>/live
cat /bloom/watch/<id>/history.jsonl
```

## Installed Petals

Petals are external packages with immutable manifests and route contracts:

```sh
cat /bloom/docs/petals.md
find /bloom/petals -path '*/meta/route-contract.json' -maxdepth 4 -print
cat /bloom/petals/<name>/meta/route-contract.json
```

Payload-bearing Petal signing follows Machine to Broker to Signer. A Petal may
request a public, Petal-scoped delegated `KeyRef`; only Signer can access the
corresponding private sub-key.

## Hyperliquid (external Petal)

Bloom has no built-in Hyperliquid authority surface. Install a compatible
Hyperliquid Petal and discover its mounted contract under `/bloom/petals/`.

## Polymarket (external Petal)

Bloom no longer includes a native `bloom polymarket` command or `/polymarket/`
VFS handler. Polymarket is not provisioned by default while its migrated Petal
is unreleased. Install a compatible package explicitly; it is then available at
`/petals/polymarket/`:

```sh
bloom petals install ../bloom-petal-polymarket
bloom vfs cat /petals/polymarket/meta/route-contract.json
```

The installed route contract describes the supported workflow for that exact
Petal version.

## Pure tools

```sh
cat /bloom/tools/keccak/hello
cat /bloom/tools/sha256/hello
cat /bloom/tools/address/checksum/0xd8da6bf26964af9d7eed9e03e53415d37aa96045
cat /bloom/tools/unit/parse/1.5/18
cat /bloom/tools/unit/format/1500000/6
```

These helpers are deterministic and hold no wallet authority.
