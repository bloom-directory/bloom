# ERC-20 token reads

This directory exposes ERC-20 balances and metadata for the parent
address. It is **address-keyed**: you supply the token contract address
as a path segment, then read a leaf under it.

## Path grammar

    chains/<chain>/addresses/<holder>/tokens/<token>/<leaf>

- `<holder>` — the account whose balance you want (the parent address).
- `<token>` — the ERC-20 **contract address** (0x…, any case). You
  provide this; the directory does not enumerate every token in
  existence. See `known.json` for common and recently-seen tokens.

## Leaves under `<token>/`

| leaf           | content                                                        |
|----------------|----------------------------------------------------------------|
| `balance`      | human display line, e.g. `1.5 USDC`                            |
| `balance.raw`  | integer balance in base units (no decimals applied)           |
| `balance.json` | structured: `{chain, asset, address, symbol, decimals, raw, formatted, display, metadata_status}` |
| `symbol`       | token symbol, e.g. `USDC`                                      |
| `decimals`     | token decimals, e.g. `6`                                       |

There is no `balance.formatted` leaf — the formatted value lives in the
`formatted` field of `balance.json` (and `balance` is the display line).

## When metadata can't be read

`symbol()` / `decimals()` are read on-chain and can fail (a revert, a
non-standard token, or an RPC outage — these are indistinguishable at the
node). Bloom does **not** substitute placeholder metadata; degraded reads
are visibly degraded:

- `symbol`, `decimals`, and `balance` (the display line) **return an
  error** rather than a fabricated `?` / `18` / mis-scaled amount.
- `balance.raw` always works — it needs no metadata.
- `balance.json` always works and carries provenance: `metadata_status`
  is `"ok"` or `"fallback"`. On `"fallback"`, `symbol`/`decimals`/
  `formatted`/`display` are `null` and only `raw` is trustworthy.

## Discovery

- `known.json` — common tokens for this chain plus, when an
  address-history backend is available, tokens this address has recently
  transferred. Its `discovery_backend` field tells you whether
  history-based discovery is active (`etherscan`) or unavailable
  (`unsupported`, `rpc`, `indexer`).
- `erc20_txs` (one level up, at `addresses/<holder>/erc20_txs`) lists
  ERC-20 transfer history when the backend supports it. If it returns
  `unsupported`, direct balance reads here still work.

## Example

    cat chains/base/addresses/0xabc…/tokens/known.json
    cat chains/base/addresses/0xabc…/tokens/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913/balance.json
