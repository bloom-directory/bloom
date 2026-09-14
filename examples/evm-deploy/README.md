# Deploy with a Bloom wallet

Use Foundry or Hardhat for building and scripting while Bloom retains the wallet
key and exact owner approvals. This example deploys a payable `DeploymentBox(7)`,
a registry pointing to that box, and a separate call setting the box to `9`.
No wallet private key is provided to the project, build tool, or agent.

Tested with Foundry/Anvil 1.7.1, Hardhat 3.15.0, ethers 6.17.0, and the pinned
Ignition plugins in `package-lock.json`. Solana deployment is not included.

## Setup

Run matching Bloom Machine and Broker builds supporting Machine/Broker protocol
1.5. Have a funded Bloom wallet, a configured EVM chain, and `bloom serve` running.
For a local test, start Anvil and configure the `anvil` chain with its RPC URL and
`allow_broadcast = true`. Use a test wallet funded on that local chain.

Through the normal wallet policy-update ceremony, add an `allowed_destinations`
entry for the target **numeric chain ID**, preserving the rest of your policy:

```json
{"chain":"evm-31337","destination":"exact"}
```

For Ethereum the chain is `evm-1`. This opt-in allows the native deployment
workflow to prepare exact transactions on that chain; it does not approve their
signatures. Each deployment, factory call, and initialization call still needs
its own owner approval. Read the mounted agent guidance for the existing policy
prepare/commit commands. No signing key or passkey material belongs in a policy
file or this project.

From this example directory, start the adapter in one terminal:

```sh
umask 077
bloom deploy --wallet alice --chain anvil rpc > rpc.json
```

The JSON contains the selected public address and an ephemeral submission URL.
Keep `rpc.json` private and out of Git. The URL stops working when the adapter
exits; starting it again creates a new URL while durable submissions remain in
Machine's outbox. With a nondefault Machine endpoint, add `--connect unix:/path`
to all Bloom commands.

## Foundry

In another terminal:

```sh
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$(jq -r .rpc_url rpc.json)" \
  --sender "$(jq -r .from rpc.json)" \
  --unlocked --broadcast --slow
```

The adapter prints the transaction plan, a durable `deploy-…` ID, and the
Broker ceremony URL to its terminal. The owner reviews and completes that
ceremony. Then the agent continues that exact submission:

```sh
bloom deploy --wallet alice --chain anvil resume deploy-REPLACE_WITH_ID
```

If the ceremony is still pending, this returns its details without signing.
Repeat the same command after completion. Foundry's waiting request receives
the real broadcast hash and proceeds to its next transaction. An RPC wait is
bounded to two minutes; timeout does not cancel, sign, or restage the job.

Existing scripts should use `vm.startBroadcast()` or its public-address
overload. Remove private-key reads such as `vm.envUint("PRIVATE_KEY")`. Factory
calls (including CREATE2) retain their normal calldata and script behavior.
Bloom only predicts an address for direct CREATE; factory scripts determine
and verify their own addresses.

## Hardhat and Ignition

```sh
npm ci
npx hardhat run scripts/deploy.ts --network bloom
# Or use Ignition's dependency graph and durable journal:
npx hardhat ignition deploy ignition/modules/Deployment.ts --network bloom
```

Use the same ceremony and `bloom deploy … resume ID` flow for each transaction.
The network uses `accounts: "remote"`; the script wraps the provider's signer in
`NonceManager` so every submission has an explicit nonce. The adapter requires
nonces to distinguish retries from intentionally repeated equal transactions.
Ignition supplies its own nonces. Keep the framework's broadcast/journal files.

On local chain ID 31337, Ignition also needs an upstream node implementing
`hardhat_metadata` (tested with Anvil). Bloom returns its real instance ID so
Ignition can detect resets; Bloom does not invent or maintain Ignition state.

## Inspect, recover, or cancel

```sh
bloom deploy --wallet alice --chain anvil list
bloom deploy --wallet alice --chain anvil status deploy-REPLACE_WITH_ID
bloom deploy --wallet alice --chain anvil resume deploy-REPLACE_WITH_ID
```

Status exposes the plan, transaction, approval projection, last continuation
error, and mined receipt. Cached plans and receipts remain inspectable during
RPC/Broker outages. A broadcast hash is not mining success. Inspect the receipt
outcome and actual `contract_address`; verify deployed code and ownership as
appropriate. Source verification is a separate optional explorer step.

If a client loses a response, inspect/continue the existing ID and retry the
**same transaction including nonce and fee fields**. The same normalized request
returns the same outbox entry and hash, including after engine restart. A changed
request using a reserved nonce is rejected; it must use the existing outbox
replacement/cancellation flow. Signed-byte broadcast recovery runs before a new
signature can be requested. Never restart a whole non-idempotent deployment
script blindly: Foundry's `--resume` and Ignition's reconciliation retain the
framework's state. Confirmed Foundry resume and Ignition reruns are tested not to
send another transaction; arbitrary user scripts can have their own side effects.

Deployment jobs remain pending until explicitly continued or cancelled; owner
approval ceremonies keep their independent expiry and can be renewed on retry.
To cancel or bump, use the existing native wallet outbox controls for the same
ID (`bloom wallet cancel --help` and `bloom wallet replace --help`). Cancellation after signing/broadcast may need
its own exact approval. A client disconnect never releases a reserved nonce.

The adapter binds only to `127.0.0.1`, rejects browser Origin headers and incorrect
Host headers, and accepts a bounded, authenticated RPC surface. It does not
support raw/hash signing, unlocking, node administration, nonempty access lists,
authorization lists, blob transactions, or chain-specific transaction encodings.
There is no reusable permission to sign arbitrary script output.

## Repeat the compatibility test

From the Bloom repository:

```sh
cargo build -p bloom
BLOOM_TEST_FOUNDRY_PROJECT=/path/to/multicall-scripting \
  cargo test -p bloom-it --test deployment_rpc -- --ignored --nocapture
```

The optional project path is copied using Solidity sources plus `foundry.toml`;
credential files and the original project's build directories are not used.
The test launches the actual CLI HTTP adapter and Machine IPC against Anvil,
with a test Broker fixture explicitly acting as the owner. It exercises Foundry,
Hardhat, Ignition, response loss, persisted submission reuse, unmined nonces,
authentication failures, and cached receipts. It is not a live passkey ceremony
or a mainnet deployment.
