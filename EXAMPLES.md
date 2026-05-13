# bloom Examples

`bloom` (binary `bloom`) presents Ethereum and EVM L2s as a virtual
filesystem. Reads are blockchain queries, writes are transaction
intents, and `tail -f` is a live event stream. This document collects
every notable surface as a runnable shell example, assuming the VFS is
mounted at `/bloom/` (the daemon's default NFS mount path).

Every command below is plain `cat`, `ls`, `echo > path`, or `tail -f`
— there is no separate API. Where an example targets the real network,
the addresses and transaction hashes are real Ethereum mainnet (chain
name `ethereum`, id 1) or Base mainnet (chain name `base`, id 8453)
and can be reproduced live (subject to backend configuration —
Etherscan-backed paths require an Etherscan API key, RPC-only paths
do not).

## Contents

1. [Quickstart](#1-quickstart)
2. [Conventions](#2-conventions)
3. [Chain reads — `chains/`](#3-chain-reads--chains)
4. [NFTs — ERC-721 / ERC-1155](#4-nfts--erc-721--erc-1155)
5. [Wallets — keys, balances, signing](#5-wallets--keys-balances-signing)
6. [Outbox — stage, confirm, broadcast](#6-outbox--stage-confirm-broadcast)
7. [Simulate — `eth_call` with overrides](#7-simulate--eth_call-with-overrides)
8. [Watch — subscriptions](#8-watch--subscriptions)
9. [DeFi intents (Enso shortcuts)](#9-defi-intents-enso-shortcuts)
10. [Tools — keccak, abi, rlp, eip-712, units](#10-tools--keccak-abi-rlp-eip-712-units)
11. [ENS — forward, text, contenthash](#11-ens--forward-text-contenthash)
12. [Prices (DefiLlama)](#12-prices-defillama)
13. [Addressbook](#13-addressbook)
14. [Status, audit, RPC endpoints](#14-status-audit-rpc-endpoints)
15. [Docs (vendored)](#15-docs-vendored)
16. [Address reference](#16-address-reference)

---

## 1. Quickstart

```sh
# Long-running daemon (also installs the UDS at ~/.bloom/run/bloom.sock).
bloom serve &

# Optional: NFS mount so the rest of this doc runs verbatim.
#   build with `cargo build --features bloom-daemon/mount` first.
bloom mount /bloom

# Without a mount, every `cat /bloom/...` below maps 1:1 to:
#   bloom vfs cat /...
# and likewise for `ls`, `echo > path`, and `tail -f`.
```

Mainnet broadcasts are gated by two flags in `~/.bloom/config.toml`
— top-level `block_mainnet_broadcast = false` (the kill-switch) AND
the chain entry's `allow_broadcast = true`. Both default off; staging
and reads work regardless.

## 2. Conventions

- Chain segment is `ethereum`, `base`, `anvil`, etc. — exactly the
  names registered in `~/.bloom/config.toml`.
- Addresses are 0x-prefixed; the VFS accepts any case but emits
  EIP-55 checksum form on read.
- Etherscan-backed paths only mount when `[etherscan]` is configured
  and the matching `[backends]` entry resolves to `"etherscan"`.
  Annotations like `# requires backends.address_history = "etherscan"`
  appear inline when relevant.
- Some leaves are JSON-bodied: write the JSON to the leaf path, then
  read the same path. The handler keeps the last body keyed by path
  and reading without writing first uses defaults.

---

## 3. Chain reads — `chains/`

The chain-read surface lives in `crates/bloom-vfs/src/handlers/{chains,chains_contracts,chains_history}.rs`.

### Chain discovery

```sh
ls /bloom/chains/                                   # registered chains: ethereum, base, anvil, ...
ls /bloom/chains/ethereum/                          # chain_id, head/, blocks/, addresses/, tx/, gas/, contracts/
cat /bloom/chains/ethereum/chain_id                 # → 1
cat /bloom/chains/base/chain_id                     # → 8453
```

### Head

`head/` exposes the latest block as four leaves; the rest of the
header lives inside `full.json`.

```sh
ls /bloom/chains/ethereum/head/                     # number, hash, timestamp, full.json
cat /bloom/chains/ethereum/head/number              # decimal block number
cat /bloom/chains/ethereum/head/hash                # 0x-prefixed block hash
cat /bloom/chains/ethereum/head/timestamp           # unix seconds
cat /bloom/chains/ethereum/head/full.json           # full block (header + tx hashes)

# parent_hash, gas_used, base_fee_per_gas, miner all live inside full.json:
cat /bloom/chains/ethereum/head/full.json | jq '.header.parentHash, .header.gasUsed, .header.baseFeePerGas, .header.miner'
```

### Blocks

A specific block exposes only `full.json` (header + tx list). Per-tx
detail is under `tx/<hash>/`.

```sh
ls /bloom/chains/ethereum/blocks/19000000/          # full.json
cat /bloom/chains/ethereum/blocks/19000000/full.json
cat /bloom/chains/ethereum/blocks/19000000/full.json | jq '.transactions | length'
# Note: there is no "latest" alias — use head/ or look up by number.
```

### Gas

Single JSON leaf with the legacy gas price; EIP-1559 base fee lives
in `head/full.json` (`baseFeePerGas`).

```sh
cat /bloom/chains/ethereum/gas/current.json         # {"gas_price_wei": <legacy gasPrice>}
cat /bloom/chains/ethereum/head/full.json | jq '.header.baseFeePerGas'
```

### Addresses (core, RPC-only)

```sh
# vitalik.eth
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/balance       # wei (decimal)
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/balance.eth   # "1.234 ETH"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nonce
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/code          # 0x for EOA
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/is_contract   # true / false

# A contract (USDC) — same leaves, code is non-empty:
cat /bloom/chains/ethereum/addresses/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/is_contract
cat /bloom/chains/ethereum/addresses/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/code | head -c 32

# ENS reverse (only when an ENS-capable chain is configured):
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/ens   # → vitalik.eth
```

### ERC-20 holdings (per address)

The on-tree path is `tokens/<token>/`, not `erc20/<token>/`.
Allowances are not exposed here — read them via the token contract's
`allowance.read` method (below).

```sh
ls /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/
# → balance, balance.raw, balance.formatted, symbol, decimals

cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/balance.formatted   # "1234.56 USDC"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/symbol            # → WETH

# Same shape on Base (USDC on Base):
cat /bloom/chains/base/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913/balance.formatted
```

### Transactions and receipts

Path is `tx/<hash>/...` (singular). `error.json` is exposed at this
level and only resolves when the receipt's status is `reverted`; the
revert decoder uses trace internally — there is no separate `trace`
leaf.

```sh
ls /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/
# → receipt.json, status, block_number, gas_used, logs.json, full.json, error.json

# First-ever ETH transaction (block 46147, Aug 2015):
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/full.json
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/status
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/block_number   # 46147
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/receipt.json
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/logs.json

# error.json: only resolves on a reverted tx; tries the tiered revert decoder.
# The DAO hack tx (June 2016) — substitute any reverted hash:
cat /bloom/chains/ethereum/tx/0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b/error.json
# Reading error.json on a successful tx returns NotFound ("did not revert").
```

### Contracts: source and ABI

```sh
ls /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/
# With Etherscan: source, abi, methods/, events/, storage/, proxy/, nft/
# Without Etherscan: storage/, proxy/, nft/

cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/source   # requires backends.contract_metadata = "etherscan"
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/abi
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/abi | jq '.[] | select(.type=="function") | .name'
```

### Contracts: methods (`.read`, `.tx`, `.sig`)

`methods/<name>.read` and `methods/<name>.tx` are **writable** leaves:
write a JSON body `{"args":[...], "selector"?, "block"?, "from"?}`,
then read the same path. Reading without writing first uses
`{"args":[]}`. `.sig` is read-only.

```sh
# Canonical signature + selector — no body needed:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/decimals.sig
# decimals() returns (uint8)
# selector: 0x313ce567

# A no-arg read (USDC.decimals()):
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/decimals.read
# → {"decoded":[6],"raw":"0x...0006","selector":"0x313ce567"}

# Read with args — USDC.balanceOf(vitalik.eth):
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read

# Pin a historical block:
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"],"block":"19000000"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read

# .tx — returns calldata only, no broadcast:
echo '{"args":["0x70997970C51812dc3A010C7d01b50e0d17dc79C8","1000000"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.tx
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.tx
# → {"to":"0xA0b8...eB48","selector":"0xa9059cbb","calldata":"0x..."}

# Disambiguate overloads via selector:
echo '{"args":[...], "selector":"0xa9059cbb"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.read

# Read allowance via the token's allowance() method:
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045","0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/allowance.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/allowance.read
```

### Contracts: events (`recent`, `query`, `live`)

`recent` returns the last ~200 logs over the last ~10_000 blocks.
`query` is writable JSON: `{from_block?, to_block?, topics?, where?}`.
`live` is a long-poll tail with a per-`(chain, addr, event)` cursor.

```sh
# All three need backends.contract_metadata = "etherscan" (for the ABI).

# Recent USDC Transfer events:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/recent

# Custom block range via /query:
echo '{"from_block":"19000000","to_block":"19000100"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Filter by indexed param name (`where`) — Transfer(from, to, value):
echo '{
  "from_block":"19000000",
  "to_block":"19010000",
  "where":{"from":"0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"}
}' > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Filter by positional topics — topic0 is filled in from the event sig:
# keccak256("Transfer(address,address,uint256)") = 0xddf252ad...3b3ef
echo '{
  "from_block":"19000000",
  "topics":[null,"0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"]
}' > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Live tail — each read emits logs since the last cursor and advances it:
tail -f /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/live
```

### Contracts: storage and proxy

```sh
# Direct eth_getStorageAt — slot is decimal or 0x-hex (RPC-only).
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/storage/0
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/storage/0x0

# EIP-1967 proxy (USDC is a transparent proxy):
ls /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/
# → implementation, admin, beacon
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/implementation
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/admin

# Non-proxy contract (WETH):
cat /bloom/chains/ethereum/contracts/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/proxy/implementation
# → not a proxy

# AAVE V3 Pool / Lido stETH (both proxies):
cat /bloom/chains/ethereum/contracts/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2/proxy/implementation
cat /bloom/chains/ethereum/contracts/0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84/proxy/implementation
```

### Address history (Etherscan-backed)

Default page size 50, sorted descending; pagination is not exposed at
the path layer in v1.

```sh
# All four require backends.address_history = "etherscan":
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/txs            # native txs
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/internal_txs   # internal calls
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs      # ERC-20 transfers
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc721_txs     # ERC-721 transfers

# ERC-1155 history is under nfts/, not at the address root:
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/erc1155_txs

# Same on Base:
cat /bloom/chains/base/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs

# Slice with jq:
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs \
  | jq '.[] | {hash, tokenSymbol, value, from, to}'
```

### Cheatsheet — full ERC-20 read

```sh
TOKEN=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48   # USDC
HOLDER=0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045  # vitalik.eth
SPENDER=0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D # Uniswap V2 Router

cat /bloom/chains/ethereum/contracts/$TOKEN/methods/symbol.read | jq '.decoded[0]'
cat /bloom/chains/ethereum/contracts/$TOKEN/methods/decimals.read | jq '.decoded[0]'

echo '{"args":["'$HOLDER'"]}' > /bloom/chains/ethereum/contracts/$TOKEN/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/$TOKEN/methods/balanceOf.read | jq '.decoded[0]'

echo '{"args":["'$HOLDER'","'$SPENDER'"]}' > /bloom/chains/ethereum/contracts/$TOKEN/methods/allowance.read
cat /bloom/chains/ethereum/contracts/$TOKEN/methods/allowance.read | jq '.decoded[0]'
```

---

## 4. NFTs — ERC-721 / ERC-1155

The NFT surface lives under two trees on every chain:

- `chains/<chain>/contracts/<a>/nft/...` — collection-level views.
- `chains/<chain>/addresses/<a>/nfts/...` — per-holder views and
  per-token detail.

ERC-721 vs ERC-1155 is auto-detected via `IERC165.supportsInterface`
and cached per `(chain_id, contract)` for the daemon's lifetime.
The optional `standard` field on a `nft_transfer` intent skips the
probe — useful for non-standard contracts.

### Collection reads — `chains/<chain>/contracts/<a>/nft/`

```sh
# BAYC: ERC-165 detection + name + symbol + supply (RPC-only).
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/kind          # → erc721
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/name          # → BoredApeYachtClub
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/symbol        # → BAYC
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/total_supply  # → 10000 (or "unknown")

# ERC-1155 collection (OpenSea Shared Storefront):
cat /bloom/chains/ethereum/contracts/0x495f947276749Ce646f68AC8c248420045cb7b5e/nft/kind          # → erc1155

# CryptoPunks: ERC-165 returns erc721, but transferFrom is non-standard.
# `nft_transfer` will encode the standard ERC-721 selector that the contract
# does NOT implement — use the dedicated CryptoPunks methods via a `call` intent.
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/kind
```

### Per-token collection lookups

```sh
# CryptoPunks #5822 owner.
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/owner_of/5822

# Pudgy Penguins #6873 tokenURI.
cat /bloom/chains/ethereum/contracts/0xBd3531dA5CF5857e7CfAA92426877b022e612cf8/nft/token_uri/6873

# Nouns #1 owner.
cat /bloom/chains/ethereum/contracts/0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03/nft/owner_of/1

# isApprovedForAll(owner, operator) — has vitalik.eth approved an operator on BAYC?
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/is_approved_for_all/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/0x1E0049783F008A0085193E00003D00cd54003c71
```

For ERC-1155, `owner_of` returns the literal `not applicable`
(1155 has no single owner per id). Use the per-holder `balance` leaf.

### Per-holder reads — `chains/<chain>/addresses/<a>/nfts/`

```sh
# requires backends.address_history = "etherscan"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/erc721_txs
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/erc1155_txs

# Best-effort holdings: reduces in/out from the ERC-721 history.
# Carries a "caveat" field; out-of-band transfers and reorgs will skew it.
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/owned.json
```

`owned.json` schema:

```json
{
  "caveat": "best-effort: reduced from etherscan tx history; not authoritative",
  "tokens": [
    { "contract": "0x...", "token_id": "1234", "standard": "erc721" }
  ]
}
```

### Per-token reads — `nfts/<contract>/<token_id>/`

Six leaves per token: `owner`, `uri`, `metadata.json`, `balance`,
`is_owner`, `approved`. RPC-only except `metadata.json`, which fetches
the URI over HTTP/IPFS (1 MiB body cap, 5 s timeout). The `<a>` segment
is the holder context — used for `balance` / `is_owner`.

```sh
# BAYC #1, viewed from Vitalik's holder context.
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/owner
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/uri

# external HTTP fetch
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/metadata.json

cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/balance     # 0 or 1 for ERC-721
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/is_owner
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/approved

# ERC-1155 — token id is parsed as decimal. The metadata URI's `{id}` is
# substituted with the lowercase 64-char hex form (no 0x) per the spec.
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/uri
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/balance
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/metadata.json
```

### NFT writes — outbox intents

The destination `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` below is
**Anvil dev account #1** — a labeled test recipient. Replace with a
real address (or ENS name) for mainnet use.

#### `nft_transfer` — ERC-721

```sh
# JSON form. safe defaults to true (encodes safeTransferFrom).
echo '{
  "kind": "nft_transfer",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "1"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Legacy unsafe transfer (skips onERC721Received).
echo '{
  "kind": "nft_transfer",
  "contract": "0xED5AF388653567Af2F388E6224dC7C4b3241C544",
  "to":       "vitalik.eth",
  "token_id": "1234",
  "safe":     false
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Shell shorthand (no `#` prefix on the token id):
echo 'nft transfer 0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D 1 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
echo 'nft transfer 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 6873 to vitalik.eth on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

#### `nft_transfer` — ERC-1155 (with amount and optional data)

```sh
# Move 3 copies of token 10 on the OpenSea Shared Storefront.
echo '{
  "kind":     "nft_transfer",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "10",
  "standard": "erc1155",
  "amount":   "3"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# With optional `data` payload (forwarded to onERC1155Received):
echo '{
  "kind":     "nft_transfer",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "10",
  "standard": "erc1155",
  "amount":   "1",
  "data":     "0xdeadbeef"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Shell shorthand: the `amount <n>` clause flips the standard hint to erc1155.
echo 'nft transfer 0x495f947276749Ce646f68AC8c248420045cb7b5e 10 amount 3 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

#### `nft_approve` — ERC-721 per-token (ERC-1155 rejected)

```sh
# Doodles #1234 to a marketplace operator.
echo '{
  "kind":     "nft_approve",
  "contract": "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "1234"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Shell shorthand:
echo 'nft approve 0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e 1234 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Revoke: pass the zero address as operator.
echo '{
  "kind":     "nft_approve",
  "contract": "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e",
  "operator": "0x0000000000000000000000000000000000000000",
  "token_id": "1234"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# ERC-1155 rejection — per-token approve fails at staging:
echo '{
  "kind":     "nft_approve",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "10"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
ls /bloom/wallets/alice/chains/ethereum/outbox/failed/
cat /bloom/wallets/alice/chains/ethereum/outbox/failed/0001-*/error
# => ERC-1155 has no per-token approval; use nft_approve_all
```

#### `nft_approve_all` — operator-wide (`setApprovalForAll`)

The engine attaches a `nft.approve_all` policy line to the staged plan:
`approved: true` triggers `PolicyOutcome::Warn` ("operator-wide
approval — review carefully"); `approved: false` is `Pass` (revoke).

```sh
# Grant operator-wide approval on BAYC. Triggers WARN.
echo '{
  "kind":     "nft_approve_all",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "approved": true
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Shell shorthand:
echo 'nft set_approval_for_all 0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 true on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Revoke (no WARN):
echo '{
  "kind":     "nft_approve_all",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "approved": false
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

#### Inspect, then confirm

```sh
ls /bloom/wallets/alice/chains/ethereum/outbox/pending/
# 0001-7f3c.../

cat /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/plan.md
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/confirm
ls /bloom/wallets/alice/chains/ethereum/outbox/sent/
```

---

## 5. Wallets — keys, balances, signing

### List, create, import, watch

```sh
ls /bloom/wallets/

# Shorthand: plain name = create a local wallet called 'alice'.
echo alice > /bloom/wallets/new

# Full TOML: create a fresh local wallet.
cat <<'EOF' > /bloom/wallets/new
name = "alice"
kind = "local"
passphrase = "devonly"
EOF

# Import an existing private key (BLOOM_PASSPHRASE applies if 'passphrase' is omitted).
cat <<'EOF' > /bloom/wallets/new
name = "imported"
kind = "import"
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
passphrase = "devonly"
EOF

# Watch-only (no private key, signing disabled).
cat <<'EOF' > /bloom/wallets/new
name = "vitalik"
kind = "watch"
address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
EOF
```

Wallet names match `[A-Za-z0-9_-]{1,64}`. Local/import wallets are
encrypted at rest with argon2id + chacha20poly1305 and are locked on
daemon start; you must `wallet unlock` before signing or confirming.
The unlock survives across VFS calls under `bloom serve`; one-shot CLI
re-locks every invocation.

### Per-wallet leaves

```sh
cat /bloom/wallets/alice/address          # 0x... (EIP-55 checksum)
cat /bloom/wallets/alice/public_key       # 0x04... uncompressed secp256k1
cat /bloom/wallets/alice/kind             # local | watch
cat /bloom/wallets/alice/policy.toml      # current policy

# Per-chain native balance + nonce.
cat /bloom/wallets/alice/chains/base/balance       # raw wei
cat /bloom/wallets/alice/chains/base/balance.eth   # human "0.123 ETH"
cat /bloom/wallets/alice/chains/base/balance.raw
cat /bloom/wallets/alice/chains/base/nonce
```

ERC-20 reads are not under `wallets/` — they live under the chain
reader at `chains/<c>/addresses/<addr>/tokens/<token>/...`:

```sh
ALICE=$(cat /bloom/wallets/alice/address)
cat /bloom/chains/base/addresses/$ALICE/tokens/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913/balance.formatted
```

### Signing

All three sign endpoints write the resulting hex signature to a
`<kind>.sig` file in the keystore directory. The wallet must be unlocked.

```sh
# EIP-191 personal_sign over a UTF-8 message.
echo -n 'gm bloom' > /bloom/wallets/alice/sign/message
cat ~/.bloom/keystore/alice/sign/message.sig

# Raw 32-byte hash (must be 0x-hex, exactly 32 bytes).
echo -n '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8' \
  > /bloom/wallets/alice/sign/hash
cat ~/.bloom/keystore/alice/sign/hash.sig

# EIP-712 typed data — example: EIP-2612 permit for USDC on mainnet.
cat <<'EOF' > /bloom/wallets/alice/sign/typed_data
{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Permit": [
      {"name":"owner","type":"address"},
      {"name":"spender","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {
    "name": "USD Coin",
    "version": "2",
    "chainId": 1,
    "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
  },
  "message": {
    "owner": "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045",
    "spender": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "value": "1000000",
    "nonce": "0",
    "deadline": "1893456000"
  }
}
EOF
cat ~/.bloom/keystore/alice/sign/typed_data.sig
```

Permit2 typed data has the same shape — swap `domain.name` to
`"Permit2"`, `verifyingContract` to
`0x000000000022D473030F116dDEE9F6B43aC78BA3`, and use the Permit2
`PermitSingle` / `PermitBatch` types.

---

## 6. Outbox — stage, confirm, broadcast

The outbox is scoped per `wallet/chain`. Every staged tx gets a
`<seq>-<hash>` directory id under `pending/`, `sent/`, or `failed/`.
Demo against `anvil` or `base`; mainnet is always shown as a path —
the kill-switch (`block_mainnet_broadcast` + per-chain
`allow_broadcast`) gates the actual `confirm` write.

### Stage an intent

`outbox/new.tx` accepts shell shorthand, JSON, or TOML.

```sh
# Native send, shell shorthand.
echo 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx

# Native send, JSON.
cat <<'EOF' > /bloom/wallets/alice/chains/anvil/outbox/new.tx
{
  "kind": "send",
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "0.01 eth",
  "chain": "anvil"
}
EOF

# ERC-20 transfer (token + value with a unit triggers ERC-20 encoding).
# Below: send 10 USDC on Base to a test recipient.
cat <<'EOF' > /bloom/wallets/alice/chains/base/outbox/new.tx
{
  "kind": "send",
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "10",
  "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "chain": "base"
}
EOF

# Generic call: WETH deposit() with 0.05 ETH attached on Base.
cat <<'EOF' > /bloom/wallets/alice/chains/base/outbox/new.tx
{
  "kind": "call",
  "contract": "0x4200000000000000000000000000000000000006",
  "method": "deposit()",
  "args": [],
  "value": "0.05 eth",
  "chain": "base"
}
EOF
```

Staging always: parses the intent, fills nonce + fees, simulates,
runs policy, and writes `pending/<id>/{intent.json, plan.md,
policy_check.json}`. A failed simulation or `Deny` policy outcome
surfaces as a write error — nothing lands in `pending/`.

### Review

```sh
ls /bloom/wallets/alice/chains/anvil/outbox/pending/
ID=$(ls /bloom/wallets/alice/chains/anvil/outbox/pending/ | head -n1)

cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/plan.md
```

`plan.md` is rendered from the `StagedTx`:

```
# Staged tx 0001-21699

Wallet: alice
From:   0x70997970C51812dc3A010C7d01b50e0d17dc79C8
To:     0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
Chain:  anvil (id 31337)
Value:  0.01 ETH (10000000000000000 wei)
Nonce:  3
Gas:    limit=21000 max_fee=1500000000 prio=1000000000
Data:   (none)

## Policy
- No policy rules configured.

## Confirm
Write `y` to `confirm` to broadcast, `cancel` to discard, `override` to bypass soft policy warnings.
```

```sh
cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/intent.json
cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/policy_check.json
```

Note: there is no separate `tx.json` — the on-disk file is
`intent.json`, which carries every field of the staged record.

### Confirm (broadcast)

`confirm`, `replace`, and `cancel` are virtual writable files: they
appear in `ls` of any pending entry even before they exist on disk.
Empty bodies are rejected.

```sh
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/confirm

# Override token to bypass soft-policy warnings (Warn only; Deny is never overridable):
echo override > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/confirm
```

After a successful broadcast the daemon moves the directory to
`sent/<id>/` and writes a `tx_hash` file:

```sh
ls /bloom/wallets/alice/chains/anvil/outbox/sent/$ID/
# intent.json  plan.md  policy_check.json  tx_hash

HASH=$(cat /bloom/wallets/alice/chains/anvil/outbox/sent/$ID/tx_hash)
cat /bloom/chains/anvil/tx/$HASH/receipt.json
```

The receipt is exposed under the chain reader, not the outbox.

### Replace and cancel

```sh
# Replace: bumped fees + substituted intent body. Same nonce, the
# original record stays in place; engine writes replacement_intent.json
# and replacement_tx_hash alongside.
cat <<'EOF' > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/replace
send 0.02 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil
EOF

# Cancel: fires a self-send replacement at the same nonce with a >=10% bump.
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/cancel
```

### Mainnet broadcast

The same paths work for `chain = "ethereum"`, but the daemon refuses
to broadcast unless both knobs are flipped:

- top-level `block_mainnet_broadcast = false`
- per-chain `allow_broadcast = true`

Stage + review still work read-only with the defaults; only the
`confirm` write fails.

---

## 7. Simulate — `eth_call` with overrides

Sessions are in-memory; lifetime is the daemon process.

### Create a session

```sh
ls /bloom/simulate/                    # new   last

# Native send simulation (no signing, no broadcast).
cat <<'EOF' > /bloom/simulate/new
{
  "kind": "send",
  "from": "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045",
  "to":   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "0.1 eth",
  "chain": "ethereum"
}
EOF

ID=$(cat /bloom/simulate/last)         # sim-0001
ls /bloom/simulate/$ID/
# intent.json  plan.md  simulation.json  state-override.json  trace.json
```

`from` is honoured at the simulate layer (overrides bind to the right
account); the underlying intent parser ignores it.

### Read results

```sh
cat /bloom/simulate/$ID/simulation.json   # SimResult: success, gas_used, return_data_hex
cat /bloom/simulate/$ID/plan.md           # short markdown summary
cat /bloom/simulate/$ID/trace.json        # debug_traceCall, or {"unsupported": "..."}
cat /bloom/simulate/$ID/intent.json
```

### State overrides

Drop a JSON map onto `state-override.json` and the session re-runs
synchronously against the original intent. The shape is the standard
`eth_call` overrides object: balance / nonce / code / storage (or
`stateDiff`) per address.

```sh
# Force USDC balance for vitalik.eth to 1,000,000 USDC (1e12 raw, slot 9 layout).
cat <<'EOF' > /bloom/simulate/$ID/state-override.json
{
  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {
    "stateDiff": {
      "0xb1a3aff1b2eb541fcfdab3ee7339183b39bcb6f72d4a4d3eb2d6d8f95c54a3a4": "0x00000000000000000000000000000000000000000000000000000000e8d4a51000"
    }
  }
}
EOF

cat /bloom/simulate/$ID/simulation.json

# Simpler override — zero a sender's native balance to test the revert path:
cat <<'EOF' > /bloom/simulate/$ID/state-override.json
{
  "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045": { "balance": "0x0" }
}
EOF
cat /bloom/simulate/$ID/simulation.json
# {"success": false, "revert_reason": "insufficient funds ...", ...}
```

### eth_call against overridden state

`/simulate` is the `eth_call`-with-overrides surface — there is no
separate `eth_call/<to>/<calldata>` path. Stage a `call` intent with
`state_override` inline:

```sh
cat <<'EOF' > /bloom/simulate/new
{
  "kind": "call",
  "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "method": "balanceOf(address)",
  "args": ["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"],
  "chain": "ethereum",
  "state_override": {
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {
      "stateDiff": {
        "0xb1a3aff1b2eb541fcfdab3ee7339183b39bcb6f72d4a4d3eb2d6d8f95c54a3a4": "0x00000000000000000000000000000000000000000000000000000000e8d4a51000"
      }
    }
  }
}
EOF
ID=$(cat /bloom/simulate/last)
cat /bloom/simulate/$ID/simulation.json    # return_data_hex carries the balance
```

NFT intents go through the wallet outbox stage path. Enso routes go
through `defi/intents/`.

---

## 8. Watch — subscriptions

Subscriptions are TOML specs written to `watch/new`. Each gets an id
`w-NNNN`. The executor ticks every 2 s, polls the relevant RPC, and
appends a JSONL line to a per-watch `live` file when something
changes. When `live` exceeds 1 MiB it rotates to
`history.jsonl.<n>`.

For `Block` and `Event` specs, when the chain client reports
`supports_subscriptions = true` the executor also spawns a per-spec
WebSocket supervisor that drives `eth_subscribe` directly. The poll
loop continues as a watchdog; both paths share a per-spec
`(blockHash, logIndex)` ring buffer so duplicates from overlap or
reorgs are dropped silently.

### Subscribe

```sh
# 1. Balance watch on vitalik.eth.
cat <<'EOF' > /bloom/watch/new
kind = "balance"
wallet = "alice"
address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
threshold_wei = "0"
comparator = ">"
note = "any balance change"
EOF

# 2. Block watch.
cat <<'EOF' > /bloom/watch/new
kind = "block"
wallet = "alice"
chain = "base"
EOF

# 3. Gas-price watch (fires when below 25 gwei).
cat <<'EOF' > /bloom/watch/new
kind = "gas_price"
wallet = "alice"
chain = "ethereum"
threshold_gwei = 25.0
EOF

# 4. Event watch — WETH Transfer on mainnet.
cat <<'EOF' > /bloom/watch/new
kind = "event"
wallet = "alice"
chain = "ethereum"
contract = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
EOF

ls /bloom/watch/
# new   w-0001   w-0002   w-0003   w-0004
```

### Tail and read

```sh
tail -f /bloom/watch/w-0001/live
cat /bloom/watch/w-0001/history.jsonl
cat /bloom/watch/w-0001/history.jsonl.1
ls /bloom/watch/w-0001/
# spec.toml   live   history.jsonl   history.jsonl.1   delete

cat /bloom/watch/w-0001/spec.toml
# id = "w-0001"
# wallet = "alice"
# created_ms = "1731177900000"
# note = "any balance change"
#
# [kind]
# kind = "balance"
# address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
# threshold_wei = "0"
# comparator = ">"

echo y > /bloom/watch/w-0001/delete
```

`spec.toml` is the only metadata leaf. Last-seen state is in-process
(via the dedup ring buffer); consumers reason about progress from the
timestamp on each `live` / `history` record.

---

## 9. DeFi intents (Enso shortcuts)

The `defi/intents/<wallet>/` surface is an "intent compiler": it turns
a natural-language or JSON DeFi request into one or more concrete
`RawIntent`s using the Enso Shortcuts API and forwards them — on
confirm — into the wallet outbox.

There are always two confirms:

1. `defi/intents/<wallet>/<id>/confirm` — stages the routed plan
   into `wallets/<w>/chains/<c>/outbox/pending/<tx-id>/`.
2. `wallets/<w>/chains/<c>/outbox/pending/<tx-id>/confirm` — the
   actual broadcast, where ordering, gas, and policy checks live.

Sessions are in-memory only and evaporate on daemon restart; the
outbox entry is the durable artefact.

### Session layout

```
defi/
  intents/
    <wallet>/
      new                 (writable; creates a session)
      <session-id>/
        intent.txt        (original NL intent)
        route.json        (full Enso RouteResponse)
        plan.md           (human narrative)
        tx.json           (the prepared RawIntent list)
        simulation.json   (eth_call result; recomputed on each cat)
        confirm           (writable; stages tx.json into outbox)
```

Session IDs look like `0001-12345` (seq + ms suffix).

### Lifecycle: USDC → ETH on Ethereum (auto-approve)

```sh
# 1) Open a session — default chain is `ethereum`.
echo 'swap 100 usdc to eth' > /bloom/defi/intents/alice/new

# 2) See sessions.
ls /bloom/defi/intents/alice/
# new
# 0001-12345

# 3) Inspect.
ls /bloom/defi/intents/alice/0001-12345/
# intent.txt  route.json  plan.md  tx.json  simulation.json  confirm

cat /bloom/defi/intents/alice/0001-12345/plan.md
# # DeFi intent
#
# Intent:    swap 100 usdc to eth
# Chain:     ethereum (id 1)
# From:      0xAlice...
# Token in:  0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48  amount=100000000
# Token out: 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
# Slippage:  50 bps
# Tx to:     0x<EnsoRouter>
#
# ## Auto-approve
# Existing allowance for 0xA0b8...eB48 -> 0x<EnsoRouter> is below 100000000.
# An ERC-20 `approve(spender, max)` will be staged ahead of the swap.

# 4) Read the prepared RawIntent list. For ERC-20 -> ETH with insufficient
#    allowance, this is [approve(token, spender, max), raw(swap)].
cat /bloom/defi/intents/alice/0001-12345/tx.json

# 5) Optional dry-run via eth_call. Reverts get tiered-decoded.
cat /bloom/defi/intents/alice/0001-12345/simulation.json

# 6) First confirm: stage both intents into the wallet outbox.
echo y > /bloom/defi/intents/alice/0001-12345/confirm

# 7) Outbox now has two pending entries (approve, then swap).
ls /bloom/wallets/alice/chains/ethereum/outbox/pending/

# 8) Second confirm: the actual broadcast. Approve must mine first.
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/<approve-id>/confirm
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/<swap-id>/confirm
```

### JSON-explicit and slippage override

The handler accepts NL-only `echo '...' > new`, or a JSON body with
`intent`, optional `chain`, and optional `slippage_bps`. The `intent`
field itself stays in NL form — it's what the Enso parser consumes.

```sh
echo '{"intent":"swap 100 usdc to eth","chain":"ethereum"}' \
  > /bloom/defi/intents/alice/new

# Override the 50-bps default slippage:
echo '{"intent":"swap 100 usdc to eth","slippage_bps":100}' \
  > /bloom/defi/intents/alice/new

# To feed an explicit token address, embed the hex in the NL string:
echo 'swap 100 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 to ETH' \
  > /bloom/defi/intents/alice/new
```

NL-only writes always use the 50-bps default; only the JSON form
carries `slippage_bps`.

### More swap examples

```sh
# ETH -> USDC on Ethereum (native in, no approve; tx.value carries ETH).
echo 'swap 0.5 eth to usdc' > /bloom/defi/intents/alice/new

# USDC -> DAI on Base (different chain, auto-approve).
# Base USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
# Base DAI:  0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb
echo 'swap 100 usdc to 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb on base' \
  > /bloom/defi/intents/alice/new

# ETH -> stETH on Lido (Lido stETH: 0xae7a...fE84).
echo 'swap 1 eth to 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84' \
  > /bloom/defi/intents/alice/new
```

The handler resolves only `USDC` by symbol on Base today; everything
else needs the explicit hex address in the NL string.

---

## 10. Tools — keccak, abi, rlp, eip-712, units

`tools/` exposes pure helpers in two flavours: stateless one-shots
where the input fits in the path, and write-then-read sessions where
the input is JSON written to `in.json` and the result is read from
`out.hex` / `out.json`. Sessions auto-expire after 5 minutes idle.

### One-shots

```sh
# keccak — full hash.
cat /bloom/tools/keccak/hello%20world
# 0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad

# Event topic via keccak:
cat /bloom/tools/keccak/Transfer(address,address,uint256)
# 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef

# selector — 4-byte function selector.
cat /bloom/tools/selector/transfer(address,uint256)     # 0xa9059cbb
cat /bloom/tools/selector/approve(address,uint256)      # 0x095ea7b3

# EIP-55 checksum.
cat /bloom/tools/address/checksum/0xd8da6bf26964af9d7eed9e03e53415d37aa96045
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045

cat /bloom/tools/sha256/hello%20world
cat /bloom/tools/blake3/hello%20world

cat /bloom/tools/hex/encode/hello                       # 0x68656c6c6f
cat /bloom/tools/hex/decode/0x68656c6c6f                # hello
cat /bloom/tools/base64/encode/hello                    # aGVsbG8=
cat /bloom/tools/base64/decode/aGVsbG8=                 # hello

cat /bloom/tools/unit/parse/1.5/eth                     # 1500000000000000000
cat /bloom/tools/unit/parse/25/gwei                     # 25000000000
cat /bloom/tools/unit/format/1500000000000000000/18     # 1.5
```

### ABI / RLP / EIP-712 sessions

```sh
# ABI encode.
echo '{"sig":"transfer(address,uint256)","args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045","1000000"]}' \
  > /bloom/tools/abi/encode/s1/in.json
cat /bloom/tools/abi/encode/s1/out.hex
# 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000000000f4240

# ABI decode.
echo '{"types":["address","uint256"],"data":"0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000000000f4240"}' \
  > /bloom/tools/abi/decode/s1/in.json
cat /bloom/tools/abi/decode/s1/out.json

# RLP.
echo '{"value":["0x83","0xff",["0x01"]]}' > /bloom/tools/rlp/encode/r1/in.json
cat /bloom/tools/rlp/encode/r1/out.hex                  # 0xc6818381ffc101
echo '{"data":"0xc6818381ffc101"}' > /bloom/tools/rlp/decode/r1/in.json
cat /bloom/tools/rlp/decode/r1/out.json

# EIP-712 hash.
cat <<'JSON' > /bloom/tools/eip712/hash/m1/in.json
{
  "domain": {},
  "types": {
    "EIP712Domain": [],
    "Person": [{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
    "Mail": [{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]
  },
  "primaryType": "Mail",
  "message": {
    "from": {"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":   {"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!"
  }
}
JSON
cat /bloom/tools/eip712/hash/m1/out.hex
```

`namehash` is not currently wired into the `tools/` handler —
`bloom_ens::namehash` exists if you need the EIP-137 node value
offline.

---

## 11. ENS — forward, text, contenthash

The `ens/` surface is forward-only and read-only. Reverse resolution
lives at `chains/<chain>/addresses/<addr>/ens` (per spec §3.2).

```sh
# Forward (resolve to address).
cat /bloom/ens/vitalik.eth/address
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045
# Unresolved names return the literal string `unresolved`.

# Reverse — chain-rooted.
cat /bloom/chains/mainnet/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/ens

# Text records — any key; unset keys return `not set`.
cat /bloom/ens/vitalik.eth/text/url
cat /bloom/ens/vitalik.eth/text/com.twitter
cat /bloom/ens/brantly.eth/text/email

# `avatar` is a shortcut for the avatar text record.
cat /bloom/ens/vitalik.eth/avatar
# (same as)
cat /bloom/ens/vitalik.eth/text/avatar

# EIP-1577 contenthash, returned as 0x-prefixed hex.
cat /bloom/ens/ens.eth/content_hash

# List a name's surface.
ls /bloom/ens/vitalik.eth/
# address  avatar  content_hash  text
```

---

## 12. Prices (DefiLlama)

Backed by DefiLlama, keyless and rate-limited; results cached for 30 s.

Coin segment forms:

- bare symbol — `eth`, `usdc`, `btc`
- `<chain>:<address>` — `ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`
- `coingecko:<slug>` — `coingecko:lido`

```sh
# Spot — `.usd` returns the scalar; bare returns the JSON quote.
cat /bloom/prices/spot/eth.usd
cat /bloom/prices/spot/btc.usd
cat /bloom/prices/spot/usdc.usd
cat /bloom/prices/spot/eth
# {"price": ..., "symbol": "ETH", "decimals": 18, "timestamp": ..., "confidence": ...}

# 24h change — there is no `.usd` variant on this path.
cat /bloom/prices/change_24h/eth
cat /bloom/prices/change_24h/usdc
```

---

## 13. Addressbook

A local petname directory persisted to `<home>/addressbook.toml`.
Reads return the EIP-55 checksum address with a trailing newline.

```sh
ls /bloom/addressbook/
# new  vitalik  weth  usdc

cat /bloom/addressbook/vitalik
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045

# Set an alias — write the address directly, or post `alias=0x…` to `new`.
echo "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045" > /bloom/addressbook/vitalik
echo "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" > /bloom/addressbook/weth
echo "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" > /bloom/addressbook/usdc
echo "vitalik=0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045" > /bloom/addressbook/new

# Remove — write `delete` (case-insensitive) or an empty body:
echo "delete" > /bloom/addressbook/vitalik
: > /bloom/addressbook/vitalik
```

---

## 14. Status, audit, RPC endpoints

The `status/` tree is the daemon's introspection layer: uptime and
version, per-chain RPC reachability, the audit-log digest, cache and
outbox counts, the active backend mapping, and a per-endpoint health
snapshot for every configured RPC URL.

### Daemon

```sh
ls /bloom/status/                                      # daemon.json, version, uptime, started_at, home, chains/, audit/, cache/, policies/, wallets/, outbox/, backends/
cat /bloom/status/version                              # daemon version, e.g. 0.0.0
cat /bloom/status/uptime                               # "Ns" under a minute, "HH:MM:SS" otherwise
cat /bloom/status/started_at                           # RFC3339 UTC
cat /bloom/status/home                                 # absolute home dir, e.g. /home/you/.bloom
cat /bloom/status/daemon.json                          # JSON: {version, started_unix_ms, started_at, uptime_secs, home, chains}
```

### Chains

```sh
ls /bloom/status/chains/                               # registered chain names
ls /bloom/status/chains/ethereum/                      # chain_id, connected, block_number, rpc_url, endpoints/
cat /bloom/status/chains/ethereum/chain_id             # → 1
cat /bloom/status/chains/ethereum/connected            # "true" / "false" — RPC ping with 750 ms timeout, 2 s cached
cat /bloom/status/chains/ethereum/block_number         # latest block from the same probe
cat /bloom/status/chains/ethereum/rpc_url              # first configured RPC URL, redacted (api keys → ***)
cat /bloom/status/chains/base/chain_id                 # → 8453
```

`connected` and `block_number` share a 2-second handler-level probe
cache plus a 5-second router cache; tight polling is safe. URL
redaction strips long opaque trailing segments and obvious key query
params (`apikey`, `api_key`, `key`, `token`, `access_token`).

### Per-endpoint health (WP-3)

Every configured RPC endpoint gets an indexed directory under
`status/chains/<chain>/endpoints/<idx>/`. Indices are zero-based,
stable for the daemon's lifetime, and map to the `endpoints` array
in the chain's `ChainSpec`. Leaves are populated by the active probe
loop in `crates/bloom-rpc/src/transport.rs` (15 s tick, 2 s timeout,
direct `eth_blockNumber` per endpoint, bypassing the alloy
`FallbackLayer`).

```sh
ls /bloom/status/chains/ethereum/endpoints/            # 0, 1, 2, ...
ls /bloom/status/chains/ethereum/endpoints/0/          # url, score, cooldown_until, latency_ms, success_rate, last_block
cat /bloom/status/chains/ethereum/endpoints/0/url
cat /bloom/status/chains/ethereum/endpoints/0/score            # composite score in [0,1] (3-decimal text)
cat /bloom/status/chains/ethereum/endpoints/0/latency_ms       # EWMA round-trip ms (alpha=0.3)
cat /bloom/status/chains/ethereum/endpoints/0/success_rate     # rolling success rate over last 10 probes
cat /bloom/status/chains/ethereum/endpoints/0/last_block       # last block seen via this endpoint
cat /bloom/status/chains/ethereum/endpoints/0/cooldown_until   # Unix-seconds deadline if parked, blank if healthy
```

Cooldown semantics:

- 5 consecutive failures arm a 60 s cooldown.
- 2 consecutive successes during cooldown clear it.
- A fresh cooldown within 5 minutes of a recovery escalates to 600 s.
- Rate-limit responses (HTTP 429) feed `Retry-After` to the cooldown
  duration via `BloomRetryPolicy` in `crates/bloom-rpc/src/policy.rs`.

The WP-4 WebSocket fast path adds no VFS leaves; `supports_subscriptions`
and `ws_provider` live entirely inside `RpcEngine`. WS reachability
shows up indirectly via `watch.subscribe_blocks.ended_falling_back_to_poll`
log lines and per-watch state under `/bloom/watch/<id>/`.

### Audit

The audit log file at `~/.bloom/audit.jsonl` is **out-of-band**
— not exposed through the VFS. `status/audit/` exposes the chain's
tip and a recent-window:

```sh
ls /bloom/status/audit/                                # head, count, last
cat /bloom/status/audit/head                           # rolling digest (one line of hex)
cat /bloom/status/audit/count                          # total records appended
cat /bloom/status/audit/last                           # JSON array of the last 10 records
```

Verify the chain advanced after a write:

```sh
before=$(cat /bloom/status/audit/head)
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/0001-abc/confirm
after=$(cat /bloom/status/audit/head)
[ "$before" != "$after" ] && echo "audit chain advanced"
```

### Cache, wallets, outbox, policies

```sh
ls /bloom/status/cache/                                # etherscan_entries, prices_entries
cat /bloom/status/cache/etherscan_entries
cat /bloom/status/cache/prices_entries                 # currently always 0

ls /bloom/status/wallets/                              # count
cat /bloom/status/wallets/count

ls /bloom/status/outbox/                               # pending_count
cat /bloom/status/outbox/pending_count

ls /bloom/status/policies/                             # block_mainnet_broadcast
cat /bloom/status/policies/block_mainnet_broadcast     # "true" / "false"
```

Per-wallet policy is **not** under `status/`; it lives at
`/bloom/wallets/<wallet>/policy.toml`.

### Backends

```sh
ls /bloom/status/backends/                             # contract_metadata, address_history, event_logs, storage_reads, proxy_detection, summary.json
cat /bloom/status/backends/contract_metadata           # → "etherscan"
cat /bloom/status/backends/address_history             # → "etherscan"
cat /bloom/status/backends/event_logs                  # → "rpc"
cat /bloom/status/backends/storage_reads               # → "rpc"
cat /bloom/status/backends/proxy_detection             # → "rpc"
cat /bloom/status/backends/summary.json                # JSON map of all of the above
```

`status/backends/*` is read-only. Switching a backend is done by
editing `~/.bloom/config.toml` under `[backends]` and restarting
the daemon — the config file is not VFS-writable.

---

## 15. Docs (vendored)

`/bloom/docs/` is the daemon's vendored help. The bytes are
`include_str!`'d at compile time from `crates/bloom-vfs/src/docs/`,
so the content is stable for the daemon's lifetime — there is no
on-disk copy to mutate.

```sh
ls /bloom/docs/                                        # README.md, examples.md
cat /bloom/docs/README.md
cat /bloom/docs/examples.md
```

These update with the binary; refresh them after a workspace update
just by `cat`ing them again.

---

## 16. Address reference

All addresses below are real and live as of this writing. They appear
in examples throughout the document; substitute your own as needed.

### Ethereum mainnet (chain `ethereum`, id 1)

| Symbol | Address |
| ------ | ------- |
| ETH (native sentinel) | `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` |
| WETH | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` |
| USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` |
| DAI  | `0x6B175474E89094C44Da98b954EedeAC495271d0f` |
| WBTC | `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` |
| Lido stETH | `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84` |
| AAVE V3 Pool | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` |
| Uniswap V2 Router | `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D` |
| Uniswap V3 Router | `0xE592427A0AEce92De3Edee1F18E0157C05861564` |
| Uniswap V3 Factory | `0x1F98431c8aD98523631AE4a59f267346ea31F984` |
| ENS Registry | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` |
| Beacon Deposit | `0x00000000219ab540356cBB839Cbe05303d7705Fa` |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` |

### NFT collections (Ethereum mainnet)

| Collection | Address | Standard |
| ---------- | ------- | -------- |
| CryptoPunks | `0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb` | non-standard 721 |
| BAYC | `0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D` | ERC-721 |
| Pudgy Penguins | `0xBd3531dA5CF5857e7CfAA92426877b022e612cf8` | ERC-721 |
| Doodles | `0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e` | ERC-721 |
| Nouns | `0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03` | ERC-721 |
| Azuki | `0xED5AF388653567Af2F388E6224dC7C4b3241C544` | ERC-721 |
| ENS NameWrapper | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` | ERC-721 |
| OpenSea Shared Storefront | `0x495f947276749Ce646f68AC8c248420045cb7b5e` | ERC-1155 |

### Holder addresses

| Name | Address |
| ---- | ------- |
| vitalik.eth | `0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045` |
| Pranksy | `0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459` |
| Anvil dev acct #1 (test recipient) | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |

### Base mainnet (chain `base`, id 8453)

| Symbol | Address |
| ------ | ------- |
| WETH | `0x4200000000000000000000000000000000000006` |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| DAI  | `0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb` |
| Uniswap V3 SwapRouter02 | `0x2626664c2603336E57B271c5C0b26F421741e481` |

### Real Ethereum mainnet tx hashes

| Description | Hash |
| ----------- | ---- |
| First-ever ETH transaction (block 46147, Aug 2015) | `0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060` |
| The DAO hack (June 2016) | `0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b` |
