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
- read a generated `plan.md` before any transaction is signed;
- confirm a staged transaction only after user approval;
- enforce wallet policy: spend caps, allow/deny lists, contract-call gates, private orderflow preferences, and audit logging;
- use ten major read-ready EVM networks immediately after `bloom init`: Ethereum, Base, Arbitrum, Optimism, Polygon, BNB Smart Chain, Avalanche, Gnosis, Linea, and HyperEVM, plus local Anvil.

Mainnet and L2 broadcasts are disabled by default. Bloom is useful immediately for reads, simulation, planning, and local devnet sends; live broadcasts require explicit config changes.

## First five minutes

```sh
# 1. Install/build Bloom, then initialize the default home.
bloom init

# 2. See what the agent can read.
bloom vfs ls /
bloom vfs cat /docs/README.md
bloom vfs cat /chains/ethereum/head/number
bloom vfs cat /prices/spot/eth.usd

# 3. Create a demo wallet. Private keys stay in the encrypted keystore,
# not in /bloom.
BLOOM_PASSPHRASE=devonly bloom wallet new alice --passphrase devonly
bloom wallet list

# 4. Stage a devnet transaction when Anvil is running.
bloom vfs write \
  /wallets/alice/chains/anvil/outbox/new.tx \
  --data 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil'

# 5. Review the generated plan before confirming.
bloom vfs ls /wallets/alice/chains/anvil/outbox/pending
bloom vfs cat /wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
```

## Why filesystem-first matters

Agents are already good at navigating files. Bloom turns wallet operations into ordinary file operations, so agents can discover capabilities with `ls`, read docs with `cat`, stage actions with writes, and explain the plan before asking the user to approve anything.

Petals and the broader Bloom architecture extend this model: small, composable, verifiable programs exposed as paths. The wallet is the first killer app because it makes the filesystem abstraction concrete today: safe agent-controlled onchain workflows with a human approval loop.
