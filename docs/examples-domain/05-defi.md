# Enso Petal

Enso route discovery and swap execution are provided by the optional
[bloom-petal-enso](https://github.com/bloom-directory/bloom-petal-enso)
package. Bloom core no longer exposes a native `/defi` subtree. Install the
Petal, inspect its consent summary, and confirm that it appears at
`/petals/enso/`:

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-enso
bloom petals ls
bloom vfs ls /petals/enso
```

Source installs execute the package's declared build command as the current
OS user. Pin an explicit release tag or commit with `--ref` when
reproducibility matters.

## Configure the API key

Write the Enso credential into the Petal's secret store:

```sh
bloom vfs write /petals/enso/settings/api-key \
  --data 'your-enso-api-key'
bloom vfs cat /petals/enso/settings/status.json
```

The Petal secret store is preferred. A runtime `enso-api-key` setting is only
a compatibility fallback and is reported as unencrypted configuration.

## Create and review a swap

```sh
bloom vfs write /petals/enso/intents/alice/new \
  --data 'swap 100 usdc to eth on base'
bloom vfs ls /petals/enso/intents/alice

session='<session-id-from-the-list>'
bloom vfs cat "/petals/enso/intents/alice/$session/plan.md"
bloom vfs cat "/petals/enso/intents/alice/$session/route.json"
bloom vfs cat "/petals/enso/intents/alice/$session/tx.json"
bloom vfs cat "/petals/enso/intents/alice/$session/simulation.json"
```

Treat `plan.md` and the simulation as review material. Route discovery does
not authorize signing or broadcast.

## Confirm and broadcast

The first confirmation asks the Petal to stage the reviewed transaction into
Bloom's standard wallet outbox:

```sh
bloom vfs write "/petals/enso/intents/alice/$session/confirm" \
  --data confirm
```

For an ERC-20 route that needs approval, this confirmation stages only an
exact-amount approval. Confirm that outbox entry, wait for its successful
receipt, then confirm the Petal session again. The Petal simulates and stages
the swap only after the allowance is on-chain; it never places an approval and
swap in the outbox together.

The outbox still owns the final broadcast ceremony:

```sh
bloom vfs cat \
  /wallets/alice/chains/base/outbox/pending/<id>/plan.md
bloom vfs write \
  /wallets/alice/chains/base/outbox/pending/<id>/confirm \
  --data confirm
```

Inspect the receipt and the Petal's settlement state after broadcast:

```sh
bloom vfs cat \
  /wallets/alice/chains/base/outbox/sent/<id>/receipt.json
bloom vfs cat \
  "/petals/enso/intents/alice/$session/settlement.json"
bloom vfs cat \
  "/petals/enso/intents/alice/$session/status.json"
```

## Safety properties

- The wallet's signed `[defi]` policy is evaluated at intent creation and
  again at Petal confirmation.
- Source asset, amount, sender, and native value are checked against the Enso
  Router V2 calldata envelope.
- Simulation must pass before the route is staged.
- ERC-20 approvals are exact-amount and sequenced before the swap.
- Broadcast still requires the wallet outbox owner gate.
- Settlement requires a successful source receipt and the quoted destination
  balance increase.

The Router V2 action bytes are opaque to this Petal version. When
`require_calldata_verification = false`, the plan warns that receiver and
minimum output need operator review. Do not use that mode for unattended
value movement.

The installed package is the authority for its current routes. Read
`/petals/enso/README.md`, `/petals/enso/AGENTS.md`, and
`/petals/enso/meta/route-contract.json` when those documentation routes are
present.
