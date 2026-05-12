# `chains/` — domain examples

This doc walks the read-only chain surface as it exists in `crates/bloom-vfs/src/handlers/chains.rs` (plus `chains_contracts.rs` and `chains_history.rs`). Every example assumes the VFS is mounted at `/bloom/` (the daemon's default NFS path), so a shell can drive it with plain `cat`, `ls`, `echo`, and `tail -f`. Chains used below are `ethereum` (mainnet) and `base` (Base mainnet); the registered set is whatever your `~/.bloom/config.toml` configures. Etherscan-backed paths (`source`, `abi`, `methods/*`, `events/*`, address `txs`/`internal_txs`/`erc20_txs`/`erc721_txs`) only mount when `[etherscan]` is configured and the relevant `[backends]` entry resolves to `"etherscan"`. RPC-only paths (`storage`, `proxy`, `nft/...`, head/blocks/balance/code/tx) work with no Etherscan key.

## Chain discovery

```sh
ls /bloom/chains/                                   # registered chain names (e.g. ethereum, base, anvil)
ls /bloom/chains/ethereum/                          # chain_id, head/, blocks/, addresses/, tx/, gas/, contracts/
cat /bloom/chains/ethereum/chain_id                 # → 1
cat /bloom/chains/base/chain_id                     # → 8453
```

## Head

`head/` exposes the latest block as four leaves; the rest of the header
lives inside `full.json`.

```sh
ls /bloom/chains/ethereum/head/                     # number, hash, timestamp, full.json
cat /bloom/chains/ethereum/head/number              # decimal block number
cat /bloom/chains/ethereum/head/hash                 # 0x-prefixed block hash
cat /bloom/chains/ethereum/head/timestamp           # unix seconds
cat /bloom/chains/ethereum/head/full.json           # full block (header + tx hashes)
# parent_hash, gas_used, base_fee_per_gas, miner, etc. are inside full.json:
cat /bloom/chains/ethereum/head/full.json | jq '.header.parentHash, .header.gasUsed, .header.baseFeePerGas, .header.miner'
```

## Blocks

A specific block exposes only `full.json` (header + tx list). Use `jq`
to slice into transactions / receipts when needed; per-tx detail is
under `tx/<hash>/`.

```sh
ls /bloom/chains/ethereum/blocks/19000000/          # full.json
cat /bloom/chains/ethereum/blocks/19000000/full.json
cat /bloom/chains/ethereum/blocks/19000000/full.json | jq '.transactions | length'
# Note: there is no "latest" block alias — use head/full.json or look up by number.
```

## Gas

Single JSON leaf with the legacy gas price; EIP-1559 base fee / priority
fee live inside `head/full.json` (`baseFeePerGas`).

```sh
ls /bloom/chains/ethereum/gas/                      # current.json
cat /bloom/chains/ethereum/gas/current.json         # {"gas_price_wei": <legacy gasPrice>}
cat /bloom/chains/ethereum/head/full.json | jq '.header.baseFeePerGas'
```

## Addresses (core, RPC-only)

`addresses/<addr>/` lists `balance`, `balance.eth`, `balance.raw`,
`nonce`, `code`, `is_contract`, plus `tokens/` and `nfts/` subdirs. ENS
reverse and the Etherscan history files only appear when the matching
backend is wired (see further below).

```sh
# vitalik.eth
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/balance       # wei (decimal)
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/balance.eth   # "1.234567 ETH"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nonce
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/code          # 0x for EOA
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/is_contract   # true / false

# A contract (USDC) — same leaves, code is non-empty:
cat /bloom/chains/ethereum/addresses/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/is_contract
cat /bloom/chains/ethereum/addresses/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/code | head -c 32

# storage_root is not a dedicated leaf — pull it from head/full.json or
# a specific block, or read individual slots via contracts/<addr>/storage/<slot>.
```

ENS reverse resolution (only when an ENS-capable chain is configured):

```sh
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/ens   # → vitalik.eth (or "unresolved")
```

## Address ERC-20 holdings

The on-tree path is `tokens/<token>/`, not `erc20/<token>/`. Per-token
allowance is **not** exposed at this address-scoped path; use
`contracts/<token>/methods/allowance.read` to read allowances.

```sh
ls /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/
# → balance, balance.raw, balance.formatted, symbol, decimals

cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/balance.formatted   # "1234.56 USDC"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/symbol            # → WETH
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0x6B175474E89094C44Da98b954EedeAC495271d0f/decimals          # → 18

# Same shape on Base (USDC on Base):
cat /bloom/chains/base/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/tokens/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913/balance.formatted

# Allowance: read it via the token's allowance() method.
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045","0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/allowance.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/allowance.read
# requires backends.contract_metadata = "etherscan"
```

## Transactions and receipts

The leaf path is `tx/<hash>/...` (singular). All seven leaves are
listed below; `error.json` is exposed at this level and only resolves
when the receipt's status is `reverted`.

```sh
ls /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/
# → receipt.json, status, block_number, gas_used, logs.json, full.json, error.json

# First-ever ETH transaction (block 46147, Aug 2015):
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/full.json
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/status         # success / reverted
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/block_number   # 46147
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/gas_used
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/receipt.json
cat /bloom/chains/ethereum/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060/logs.json

# error.json: only resolves on a reverted tx; tries the tiered revert decoder.
# The DAO hack tx (June 2016, mainnet) — substitute any reverted hash you have:
cat /bloom/chains/ethereum/tx/0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b/error.json
# Reading error.json on a successful tx returns NotFound ("did not revert").
# There is no `trace` leaf at this path — the revert decoder uses trace internally.
```

## Contracts: source and ABI

```sh
ls /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/
# With Etherscan: source, abi, methods/, events/, storage/, proxy/, nft/
# Without Etherscan: storage/, proxy/, nft/

cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/source   # requires backends.contract_metadata = "etherscan"
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/abi      # requires backends.contract_metadata = "etherscan"
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/abi | jq '.[] | select(.type=="function") | .name'
```

## Contracts: methods (`.read`, `.tx`, `.sig`)

`methods/<name>.read` and `methods/<name>.tx` are **writable** leaves:
write a JSON body `{"args":[...], "selector"?, "block"?, "from"?}`
to the same path, then read it back. The handler keeps the last body
keyed by path; reading without writing first uses the default
`{"args":[]}`. `.sig` is read-only.

```sh
# Canonical signature + selector — no body needed:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/decimals.sig
# decimals() returns (uint8)
# selector: 0x313ce567

# requires backends.contract_metadata = "etherscan" (needs the verified ABI)

# A no-arg read (USDC.decimals()):
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/decimals.read
# → {"decoded":[6],"raw":"0x...0006","selector":"0x313ce567"}

# Read with args — USDC.balanceOf(vitalik.eth):
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
# → {"decoded":["<wei-as-string>"], "raw":"0x...", "selector":"0x70a08231"}

# Pin a historical block:
echo '{"args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"],"block":"19000000"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read

# Disambiguate overloads via selector:
echo '{"args":[...], "selector":"0xa9059cbb"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.read

# .tx — returns calldata only, no broadcast (pipe the JSON into the wallet outbox to send):
echo '{"args":["0x70997970C51812dc3A010C7d01b50e0d17dc79C8","1000000"]}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.tx
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/transfer.tx
# → {"to":"0xA0b8...eB48","selector":"0xa9059cbb","calldata":"0x..."}

# Simulate as a different sender:
echo '{"args":[...], "from":"0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/methods/balanceOf.read

# Methods/ does not pre-list names — `ls methods/` is empty; cat by ABI name directly.
```

## Contracts: events (`recent`, `query`, `live`)

`recent` is the last ~200 logs over the last ~10_000 blocks (or chain
length). `query` is writable JSON: `{from_block?, to_block?, topics?, where?}`.
`live` is a long-poll tail driven by a per-`(chain,addr,event)` cursor.

```sh
# All three need backends.contract_metadata = "etherscan" (for the ABI).

# Recent USDC Transfer events:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/recent

# Custom block range via /query — write JSON, read same leaf:
echo '{"from_block":"19000000","to_block":"19000100"}' \
  > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Filter by indexed param name (`where`) — Transfer(from, to, value):
echo '{
  "from_block":"19000000",
  "to_block":"19010000",
  "where":{"from":"0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"}
}' > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Filter by positional topics — topic0 is filled in from the event sig
# (keccak256("Transfer(address,address,uint256)") = 0xddf252ad...3b3ef);
# pass null at index 0 to keep alignment, then topics 1..3 for the
# indexed args (address topics may be passed as 0x-40-hex, the handler
# zero-pads to 32 bytes):
echo '{
  "from_block":"19000000",
  "topics":[null,"0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"]
}' > /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/query

# Live tail — each read emits logs since the last cursor and advances it.
# Cursor is shared per (chain, addr, event) across clients (v1 trade-off).
tail -f /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/events/Transfer/live
```

## Contracts: storage

Direct `eth_getStorageAt` — slot is decimal **or** `0x`-hex (any length
up to 32 bytes; the handler reinterprets short hex as a numeric slot).
RPC-only, no Etherscan needed.

```sh
# Slot 0 in decimal — for a typical ERC-20 this is `_balances` mapping root or owner depending on layout:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/storage/0
# → 0x000...<32 bytes>

# Same slot in 0x-hex:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/storage/0x0

# An EIP-1967 implementation slot read directly via storage/ (the proxy/ subdir is a friendlier API):
cat /bloom/chains/ethereum/contracts/0x00000000219ab540356cBB839Cbe05303d7705Fa/storage/0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
```

## Contracts: proxy

EIP-1967 / EIP-1822 well-known slots, decoded as a checksummed address.
If the slot is empty the leaf returns the literal `not a proxy\n`.
RPC-only.

```sh
ls /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/
# → implementation, admin, beacon

# USDC is a transparent proxy — implementation resolves; admin is the proxy admin:
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/implementation
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/admin
cat /bloom/chains/ethereum/contracts/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/proxy/beacon          # → "not a proxy" for non-beacon proxies

# WETH is a non-proxy contract:
cat /bloom/chains/ethereum/contracts/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/proxy/implementation  # → not a proxy

# AAVE V3 Pool (proxy):
cat /bloom/chains/ethereum/contracts/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2/proxy/implementation

# Lido stETH (proxy):
cat /bloom/chains/ethereum/contracts/0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84/proxy/implementation
```

## Address history (Etherscan-backed)

These leaves only mount when `backends.address_history = "etherscan"`
and an Etherscan client is wired. Each returns a JSON array of recent
records (default page size 50, sorted descending — pagination params
are not exposed at the path level in v1, so the response is the most
recent page).

```sh
# All four require backends.address_history = "etherscan":
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/txs            # native txs
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/internal_txs   # internal calls
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs      # ERC-20 transfers
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc721_txs     # ERC-721 transfers

# ERC-1155 transfers are not exposed at the address root in v1 — they live under nfts/:
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/erc1155_txs
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/erc721_txs
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/owned.json

# Same on Base:
cat /bloom/chains/base/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs

# Slice with jq:
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/erc20_txs \
  | jq '.[] | {hash, tokenSymbol, value, from, to}'
```

## Cheatsheet: ERC-20 read with the verified ABI

A whole-cluster recipe for the common case:

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
