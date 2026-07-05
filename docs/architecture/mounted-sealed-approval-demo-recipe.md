# Mounted Sealed Approval ERC20 demo recipe

Status: this recipe documents the intended manual end-to-end path for the mounted Sealed Approval demo. It assumes a local daemon serving the mounted tree and the browser ceremony service on `http://localhost:18734`.

## Prerequisites

```sh
# From the bloom repo
cargo build -p bloom
command -v anvil
```

If `anvil` is missing, install Foundry before running the demo.

## Terminal 1: local chain

```sh
anvil --host 127.0.0.1 --port 8545 --chain-id 31337
```

Expected: anvil prints funded development accounts and listens on `http://127.0.0.1:8545`.

## Terminal 2: daemon + mounted VFS

```sh
mkdir -p /tmp/bloom-mount
RUST_LOG=info cargo run -p bloom -- serve --mount /tmp/bloom-mount
```

Expected artifacts:

```sh
ls /tmp/bloom-mount
ls /tmp/bloom-mount/outbox
ls /tmp/bloom-mount/wallets
```

## Provision ERC20 demo state

Use the existing ERC20 E2E/acceptance assets where possible:

```sh
# Reuse the repo's acceptance harness for anvil/mock ERC20 setup.
scripts/acceptance.sh
```

For a pure manual run, deploy `MockERC20`, create/import a passkey wallet, fund its native gas balance, and mint/fund ERC20 into that wallet using the same fixture values used by `crates/bloom-it/tests/erc20_e2e.rs`.

Expected:

- wallet appears under `/tmp/bloom-mount/wallets/<wallet>`;
- chain appears under `/tmp/bloom-mount/wallets/<wallet>/chains/31337` or configured chain alias;
- ERC20 balance is visible before transfer.

## Stage transfer through wallet Petal projection

The exact staging file depends on the current wallet projection shape. Use `/docs/agent-guidance.md` and the per-wallet `README.md` from the mount to discover the live staging path, then stage an ERC20 transfer.

Example shape:

```sh
WALLET=<wallet>
CHAIN=31337
TOKEN=<mock_erc20_address>
TO=<recipient_address>
AMOUNT=1000000000000000000

# Example only: adapt to the mounted staging file advertised by the tree.
printf 'token = "%s"\nto = "%s"\namount = "%s"\n' "$TOKEN" "$TO" "$AMOUNT" \
  > /tmp/bloom-mount/wallets/$WALLET/chains/$CHAIN/outbox/new.tx
```

Expected:

```sh
ls /tmp/bloom-mount/outbox/pending
ACTION_ID=$(basename "$(find /tmp/bloom-mount/outbox/pending -mindepth 1 -maxdepth 1 -type d | head -1)")
cat /tmp/bloom-mount/outbox/pending/$ACTION_ID/plan.md
cat /tmp/bloom-mount/outbox/pending/$ACTION_ID/status.json
```

`status.json` should include Petal identity such as `petal_id`, and the wallet projection should point at the same action id.

## Confirm: challenge projection + permission denied

```sh
# Confirm through the Petal/wallet projection for the staged item.
printf 'confirm\n' > /tmp/bloom-mount/wallets/$WALLET/chains/$CHAIN/outbox/pending/<wallet_projection_id>/confirm
```

Expected:

- shell write fails with permission denied;
- central challenge exists before the write returns:

```sh
cat /tmp/bloom-mount/outbox/pending/$ACTION_ID/approval_challenge.json
```

Validate:

```sh
jq -r .action_id /tmp/bloom-mount/outbox/pending/$ACTION_ID/approval_challenge.json
jq -r .expiry_ms /tmp/bloom-mount/outbox/pending/$ACTION_ID/approval_challenge.json
jq -r .ceremony_url /tmp/bloom-mount/outbox/pending/$ACTION_ID/approval_challenge.json
```

Expected:

- `.action_id == "$ACTION_ID"`;
- `.expiry_ms` is in the future;
- `.ceremony_url` is present;
- repeating the same confirm before expiry reuses the same `server_nonce`, `expiry_ms`, and `ceremony_url`.

## Grant-only variant

```sh
open "$(jq -r .ceremony_url /tmp/bloom-mount/outbox/pending/$ACTION_ID/approval_challenge.json)"
```

In the browser, choose **grant**.

Expected: browser ceremony succeeds and only an in-memory daemon grant is minted. Then retry:

```sh
printf 'confirm\n' > /tmp/bloom-mount/wallets/$WALLET/chains/$CHAIN/outbox/pending/<wallet_projection_id>/confirm
```

Expected artifacts:

```sh
ls /tmp/bloom-mount/outbox/sent/$ACTION_ID || ls /tmp/bloom-mount/outbox/failed/$ACTION_ID
cat /tmp/bloom-mount/outbox/sent/$ACTION_ID/result.json 2>/dev/null || cat /tmp/bloom-mount/outbox/failed/$ACTION_ID/result.json
cat /tmp/bloom-mount/outbox/sent/$ACTION_ID/status.json 2>/dev/null || cat /tmp/bloom-mount/outbox/failed/$ACTION_ID/status.json
```

Verify ERC20 balances changed by exactly `AMOUNT` plus no unexpected token movement.

## Grant + execute variant

Repeat staging for a second transfer. On the ceremony page, choose **grant + execute**.

Expected:

- ceremony mints the in-memory grant;
- daemon dispatches execution immediately from the sealed action bytes;
- central and wallet projections transition together to `sent` or `failed`;
- `result.json`/audit artifacts are visible under the final central action directory.

## Runtime/Petal split

Generic runtime behavior:

- challenge lifecycle and unexpired challenge reuse;
- `ceremony_url` projection and exclusion from signed challenge hash;
- central `/outbox/pending/<action_id>` artifact projection;
- mounted confirm denial as permission denied;
- grant minting and signer cache reuse via existing sealed ceremony plumbing.

ERC20 demo glue:

- ERC20 staging/broadcast via `TxEngine`;
- EVM sealed subject and `PetalHost::sign_hash` attestation;
- balance verification against the local MockERC20/anvil fixture.
