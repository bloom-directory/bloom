# Working with bloom

bloom exposes Ethereum workflows as a virtual filesystem. Prefer inspecting the
tree with normal filesystem tools when it is mounted, or with `bloom vfs` when it
is not mounted.

To mount the tree, run a mount-enabled build as `bloom serve --mount`. With no
path argument, the mount point is `/bloom` on Linux and `/Volumes/bloom` on
macOS; pass `bloom serve --mount <path>` to choose another existing directory.
Mounting uses the platform NFS client and may require elevated privileges.

Useful commands:

- `bloom vfs ls /` lists the VFS root.
- `bloom vfs ls /docs` lists the embedded documentation.
- `bloom vfs cat /docs/README.md` reads the VFS overview.
- `bloom vfs cat /docs/examples.md` reads workflow examples.

For more information, start in the `/docs` folder. It contains the canonical
VFS usage notes and examples exposed by the mounted tree.

## Security model

bloom gatekeeps every value-moving action through capabilities:

- **Reads are always safe.** No signing, no ceremony, no wallet needed for chain
  state, balances, prices, books, candles, account state.
- **Direct writes require owner approval.** The outbox stage-confirm flow,
  one-off Hyperliquid exchange orders, and Polymarket trades each cross an
  owner gate (passkey ceremony or local passphrase unlock).
- **Automated action uses a capability.** Create a bounded session/capability
  first — the human approves the bounds once, then the agent operates inside
  them without re-prompting until expiry, breach, or revocation.
- **The owner key is never handed off.** For capabilities that depend on owner
  signing (EVM, Polymarket — the target model, not yet shipped), the key will
  reside in daemon RAM for a bounded window and auto-lock on expiry.
  Hyperliquid already uses an ephemeral agent key that does not need the
  owner key after session creation.

To see what a wallet can do without a human, check its per-chain state and
outbox, or its Hyperliquid sessions under `/hyperliquid/<net>/agent_sessions/`.
A read-only `/wallets/<wallet>/capabilities/` roll-up and a VFS-root `/next.md`
aggregator are in active development (see
`docs/plans/2026-06-20-agent-obvious-capability-model.md`).

Read `/hyperliquid/README.md` for Hyperliquid trading (session-first).
Read `/polymarket/README.md` for prediction-market trading.
Read `/defi/README.md` for DeFi intents via Enso shortcuts.

## Paid HTTP

Paid HTTP requests live under `/requests`. Agents should stage the request,
read `plan.md`, and confirm only when the quoted cost, network, asset, and
merchant match the task. Bloom handles x402 internally; agents should not look
for a separate `/x402` path.

Example paid search:

```sh
bloom vfs write /requests/new \
  --data 'POST https://api.exa.ai/search wallet=<wallet> max_amount_usd=0.05
content-type: application/json

{"query":"latest Base USDC x402 developer tools","numResults":5,"type":"auto"}'

bloom vfs cat /requests/latest/plan.md
bloom vfs write /requests/latest/confirm --data confirm
bloom vfs cat /requests/latest/response/body
bloom vfs cat /requests/latest/receipt.json
```

Wallet-native paid endpoints that passed live checks:

```sh
# Pre-swap token safety for Base USDC + WETH.
bloom vfs write /requests/new \
  --data 'GET https://x402.fiasignals.com/token-safety/batch?chain=base&token_addresses=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0x4200000000000000000000000000000000000006 wallet=<wallet> max_amount_usd=0.05'

# Hyperliquid trader score.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/hyperliquid/score wallet=<wallet> max_amount_usd=0.03
content-type: application/json

{"user":"0x..."}'

# Polymarket ghost-fill risk.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/polymarket/risk wallet=<wallet> max_amount_usd=0.03
content-type: application/json

{"wallet":"0x..."}'

# Onchain data routing to GraphQL or REST.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/route wallet=<wallet> max_amount_usd=0.02
content-type: application/json

{"request":"Find the best subgraph for Uniswap V3 pools on Base and give me a ready GraphQL query for top pools by TVL"}'
```

Prefer request-local USD caps. If `plan.md` says policy is denied, do not retry
blindly; inspect the wallet policy or ask the human to change it.

## Hyperliquid (session-first)

Hyperliquid trading has two signing models:

- **Agent sessions (RECOMMENDED):** one `approveAgent` ceremony creates an
  ephemeral trading key. The agent trades inside policy bounds without further
  human prompts. The session auto-expires and auto-flattens positions on breach.
  Create at `/hyperliquid/mainnet/agent_sessions/<wallet>/new.json`.
  Trade through the session at
  `/hyperliquid/mainnet/agent_sessions/<wallet>/<session>/order.json`.

- **Direct exchange writes (ADVANCED):** owner-signed one-off actions for
  emergencies. Requires the wallet to be unlocked. Paths under
  `/hyperliquid/<network>/exchange/<wallet>/...`.

## Polymarket

Prediction-market trading lives under `/polymarket` and is driven by the
`bloom polymarket ...` commands. It is **opt-in and human-gated**: a wallet
trades only after `[polymarket] enabled = true` is set in its `policy.toml`, and
today every value-moving action opens a fresh passkey review ceremony. A
Polymarket capability primitive (scoped approve, TTL, caps) is in active
development — see `docs/plans/2026-06-20-agent-obvious-capability-model.md`.

Start at `/docs/examples.md` (the Polymarket section) and read
`docs/polymarket-integration.md` in the repo for the full spec. Funds move only
through the CLI; the VFS surface stages and reviews, it never signs.

## Passkey policy mode

For passkey wallets, policy edits must be re-signed with
`bloom wallet sign-policy <wallet>`. The browser page lets the human choose:

- `Ask me every time`: money-moving actions need a fresh passkey review.
- `Let Bloom use these rules`: agents may proceed only when every signed policy
  check passes.

Do not treat `under_policy` as a blanket unlock. It is permission to act inside
the wallet's signed caps, allowlists, and surface-specific rules.
