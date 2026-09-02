# Agentic wallet

Bloom's first application is an Ethereum wallet that an agent can operate through a virtual filesystem.

Instead of giving an agent a Web3 SDK, RPC credentials, and bespoke signing code, Bloom gives it a directory tree:

```text
/bloom/
  chains/<chain>/...          # read chain state
  wallets/<name>/...          # inspect wallets, stage txs, sign messages
  simulate/...                # dry-run calls
  prices/...                  # token prices
  ens/...                     # ENS resolution
  tools/...                   # ABI, keccak, units, EIP-712 helpers
```

The happy path for a new user is:

```text
Tell your agent: "Read https://bloom.directory/SKILL.md and set up Bloom."
```

That skill instructs the agent to install or build `bloom`, run `bloom init`, inspect `/docs`, and prefer `bloom vfs` or the mounted `/bloom` filesystem over custom Web3 code.

## What the wallet enables

An agent using Bloom can:

- inspect live balances, nonces, blocks, gas, contracts, storage, events, NFTs, ENS, prices, and address history through file reads;
- create or import encrypted local wallets without exposing private keys through the filesystem;
- stage native ETH, ERC-20, NFT, contract-call, signing, and DeFi intents by writing plain-language or structured files;
- use installed Petals for venue integrations such as Hyperliquid, with
  delegated keys confined to Signer and scoped to the installed Petal;
- read a generated `plan.md` before any transaction is signed;
- confirm a staged transaction only after user approval;
- make free or paid HTTP requests through `/requests`, with paid HTTP 402
  challenges staged for review before any x402 or Tempo MPP credential is
  signed;
- enforce wallet policy: spend caps, allow/deny lists, contract-call gates, private orderflow preferences, and audit logging;
- use twelve read-ready public EVM mainnets immediately after `bloom init`: Ethereum, Base, Tempo, Robinhood Chain, Arbitrum, Optimism, Polygon, BNB Smart Chain, Avalanche, Gnosis, Linea, and HyperEVM, plus Arc Testnet (`arc-testnet`) and local Anvil.

Arc support is testnet-only at present: `arc-testnet` (chain ID 5042002) is the sole Arc entry, and an Arc mainnet entry is pending Arc mainnet launch. Unlike the other default networks, Arc pays gas in USDC rather than ETH, so plan previews on that chain are denominated in USDC.

Mainnet and L2 broadcast routing is enabled by default. Live sends still require the applicable signing, policy, confirmation, and Sealed Approval gates.

## First five minutes

```sh
# 1. Install/build Bloom, then initialize the default home.
bloom init

# 2. See what the agent can read.
bloom vfs ls /
bloom vfs cat /docs/README.md
bloom vfs cat /chains/ethereum/head/number
bloom vfs cat /prices/spot/eth.usd

# 3. Create a demo wallet. Passkey is the default — Broker launches a WebAuthn
# ceremony in the browser and Signer retains all private key material.
bloom wallet new alice
bloom wallet list

# 4. Stage a devnet transaction when Anvil is running.
bloom vfs write \
  /wallets/alice/chains/anvil/outbox/new.tx \
  --data 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil'

# 5. Review the generated plan before confirming.
bloom vfs ls /wallets/alice/chains/anvil/outbox/pending
bloom vfs cat /wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
```

## Paid HTTP requests

Bloom can make ordinary HTTP requests through the same filesystem model. If a
server responds with an HTTP 402 payment challenge, Bloom stages a payment plan
and waits for explicit confirmation before signing or spending. Agents should
use the `/requests` surface instead of protocol-specific x402 or Tempo MPP
paths.

```sh
bloom vfs write /requests/new \
  --data 'GET https://example.com/paid-api'
bloom vfs cat /requests/latest/plan.md
bloom vfs write /requests/latest/confirm --data confirm
bloom vfs cat /requests/latest/response/body
bloom vfs cat /requests/latest/receipt.json
```

For structured requests, include a wallet and spending cap:

```toml
method = "POST"
url = "https://api.example.com/inference"
wallet = "research"
max_amount_usd = "0.05"

[headers]
content-type = "application/json"

[body]
inline = '{"prompt":"summarize this document"}'
```

Example: paid web search through Exa's x402 endpoint:

```sh
bloom vfs write /requests/new \
  --data 'POST https://api.exa.ai/search wallet=research max_amount_usd=0.05
content-type: application/json

{"query":"latest Base USDC x402 developer tools","numResults":5,"type":"auto"}'

bloom vfs cat /requests/latest/plan.md
bloom vfs write /requests/latest/confirm --data confirm
bloom vfs cat /requests/latest/response/body
bloom vfs cat /requests/latest/receipt.json
```

Use a low `max_amount_usd` and read `plan.md` before confirmation. In a live
test, Exa quoted and settled `$0.007` USDC on Base for one search request.

Examples that passed live wallet-native checks:

```sh
# Pre-swap token safety for Base USDC + WETH. Live test: $0.03 USDC.
bloom vfs write /requests/new \
  --data 'GET https://x402.fiasignals.com/token-safety/batch?chain=base&token_addresses=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0x4200000000000000000000000000000000000006 wallet=research max_amount_usd=0.05'

# Hyperliquid trader score. Live test: $0.02 USDC.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/hyperliquid/score wallet=research max_amount_usd=0.03
content-type: application/json

{"user":"0x..."}'

# Polymarket ghost-fill risk. Live test: $0.02 USDC.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/polymarket/risk wallet=research max_amount_usd=0.03
content-type: application/json

{"wallet":"0x..."}'

# Onchain data routing to GraphQL or REST. Live test: $0.01 USDC.
bloom vfs write /requests/new \
  --data 'POST https://graphadvocate.com/route wallet=research max_amount_usd=0.02
content-type: application/json

{"request":"Find the best subgraph for Uniswap V3 pools on Base and give me a ready GraphQL query for top pools by TVL"}'
```

These examples produce pre-trade risk checks, venue-specific wallet
intelligence, or onchain data routes that can affect a wallet action.

Paid requests are denied by default. Change them only through the paying
wallet's canonical `policy.json` custody flow, and keep both global and
request-local caps tight. Start from the current complete document rather than
constructing a partial policy:

```sh
cat /bloom/wallets/research/policy.json > proposed-policy.json
# Edit the payments fields in proposed-policy.json while preserving the full
# canonical policy document, then stage the exact bytes through Broker.
cp proposed-policy.json /bloom/wallets/research/policy.json
cat /bloom/wallets/research/policy-updates/latest/status.json
cat /bloom/wallets/research/policy-updates/latest/approval_challenge.json
# Complete the projected policy_update ceremony, then retry identical bytes.
cp proposed-policy.json /bloom/wallets/research/policy.json
```

The confirm path re-checks the current wallet policy. Hard denials block the
request; warnings require the wallet policy's override sentinel instead of a
plain `confirm` write. Request artifacts redact sensitive headers such as
`authorization`, API keys, and payment credentials.

The pre-triad paid-request design is retained as historical protocol context in
[`docs/specs/2026-06-15-paid-http-requests.md`](./specs/2026-06-15-paid-http-requests.md);
its authority sections are explicitly superseded by the triad architecture.

## Wallet policy and passkey review

Each wallet has one canonical `policy.json`. Different sections cover different
surfaces:

- `[approval]` decides whether Bloom must ask before each money-moving action or may act later inside signed rules.
- `[limits]` provides cross-surface USD budgets for autonomous execution.
- `[caps]` applies broad EVM transaction caps.
- `[defi]`, `[polymarket]`, and `[payments]` add surface-specific limits. Petal
  authority is additionally bound to installer-pinned package and route scope.

Writing `policy.json` first calls Broker `policy.validate_update`. Broker builds
the exact review and originates a `policy_update` custody ceremony; Signer
authenticates its completion. Retrying the exact proposed bytes calls
`policy.commit_update`, after which Broker carries the completed ceremony and
validation receipts to Signer's policy compare-and-swap. Changed bytes or a
changed baseline fail closed. Machine never signs or installs policy itself.

## Why filesystem-first matters

Agents are already good at navigating files. Bloom turns wallet operations into ordinary file operations, so agents can discover capabilities with `ls`, read docs with `cat`, stage actions with writes, and explain the plan before asking the user to approve anything.

Petals and the broader Bloom architecture extend this model: small, composable, verifiable programs exposed as paths. The wallet is the first killer app because it makes the filesystem abstraction concrete today: safe agent-controlled onchain workflows with a human approval loop.
