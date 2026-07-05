# DeFi intents

The `defi/intents/<wallet>/` surface is an "intent compiler" that turns a natural-language or JSON DeFi request into one or more concrete `RawIntent`s using the Enso Shortcuts API, and then forwards them — on confirm — into the same wallet outbox the rest of bloom uses. The full lifecycle is: write an intent under `defi/intents/<wallet>/new` to open a session; review the routed plan, full Enso response, prepared `RawIntent`s, and an `eth_call` simulation under `defi/intents/<wallet>/<id>/`; write to that session's `confirm` to stage the resulting tx (or `[approve, swap]` pair) into `wallets/<wallet>/chains/<chain>/outbox/pending/<tx-id>/`; then write to the outbox's own `confirm` to actually broadcast. There are always two confirms — one to commit the route into the outbox, one to actually broadcast each pending tx — and the second confirm is where ordering, gas, and policy checks live. Sessions are file-backed under `~/.bloom/defi/<wallet>/sessions/`, so they survive one-shot CLI invocations and daemon restarts; the outbox entry is still the durable artefact for the staged transaction.

All paths below are rooted at `/bloom/`. Mainnet broadcast is gated by `block_mainnet_broadcast=false` and per-chain `allow_broadcast=true` in daemon config; the `ethereum` examples below are written as if those are off (demonstration; broadcast disabled by default), and the `base` examples assume per-chain broadcast was opted in.

## Session layout

```
defi/
  intents/
    <wallet>/
      new                 (writable; create a session)
      <session-id>/
        intent.txt        (original NL or JSON intent)
        route.json        (full Enso RouteResponse)
        plan.md           (human narrative)
        tx.json           (the prepared RawIntent list)
        simulation.json   (eth_call result; reads recompute on each cat)
        confirm           (writable; stages tx.json into the outbox)
```

Session IDs look like `0001-12345` (seq + ms suffix).

## Lifecycle: NL swap, USDC -> ETH on Ethereum

This walks the whole pipeline end to end. USDC is an ERC-20, so the auto-approve path applies.

```
# 1) Open a session by writing an NL intent. Default chain is `ethereum`.
echo 'swap 100 usdc to eth' > /bloom/defi/intents/alice/new

# 2) See which sessions exist for this wallet (plus the writable `new` file).
ls /bloom/defi/intents/alice/
# -> new
#    0001-12345

# 3) Inspect what's inside the session.
ls /bloom/defi/intents/alice/0001-12345/
# -> intent.txt  route.json  plan.md  tx.json  simulation.json  confirm

# 4) Read the original intent verbatim.
cat /bloom/defi/intents/alice/0001-12345/intent.txt
# swap 100 usdc to eth

# 5) Read the human plan. Because USDC is ERC-20 and current allowance to the
#    Enso router is below 100e6, the plan announces an auto-approve step.
cat /bloom/defi/intents/alice/0001-12345/plan.md
# # DeFi intent
#
# Intent:    swap 100 usdc to eth
# Chain:     ethereum (id 1)
# From:      0xAlice...
# Token in:  0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48  amount=100000000 (raw)
# Token out: 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  amountOut=...
# Slippage:  50 bps
# Tx to:     0x<EnsoRouter>
# ...
#
# ## Auto-approve
# Existing allowance for 0xA0b8...eB48 -> 0x<EnsoRouter> is below 100000000
# (raw). An ERC-20 `approve(spender, max)` will be staged ahead of the swap
# and must broadcast first; both sit in the same outbox and will be reviewed
# before sending.
#
# ## Confirm
# Write any non-empty content to `confirm` to stage 2 txs through the
# wallet's outbox; review there before broadcasting.

# 6) Read the full Enso response (calldata, value, route description, gas).
cat /bloom/defi/intents/alice/0001-12345/route.json
# {
#   "tx": {
#     "to":   "0x<EnsoRouter>",
#     "from": "0xAlice...",
#     "data": "0x...calldata...",
#     "value": "0"
#   },
#   "amountOut": "...",
#   "gas":       "210000",
#   "route":     [...],
#   "priceImpact": 0.07
# }

# 7) Read the ordered RawIntent list that will be staged. For ERC-20 -> ETH
#    with insufficient allowance this is `[approve(token,spender,max), raw]`.
cat /bloom/defi/intents/alice/0001-12345/tx.json
# [
#   {
#     "body": {
#       "Approve": {
#         "token":   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
#         "spender": "0x<EnsoRouter>",
#         "amount":  "max"
#       }
#     },
#     "chain": "ethereum",
#     "gas":   "auto",
#     "nonce": null
#   },
#   {
#     "body": {
#       "Raw": {
#         "to":    "0x<EnsoRouter>",
#         "value": "0",
#         "data":  "0x...calldata..."
#       }
#     },
#     "chain": "ethereum",
#     "gas":   "auto",
#     "nonce": null
#   }
# ]

# 8) Optional: dry-run via eth_call. Reverts get tiered-decoded into a
#    structured `decoded_error`. Reads recompute on each cat.
cat /bloom/defi/intents/alice/0001-12345/simulation.json
# { "success": true, "return_data": "0x...", "gas_estimate": "210000" }

# 9) First confirm: stage both intents into the wallet outbox.
echo y > /bloom/defi/intents/alice/0001-12345/confirm

# 10) The outbox now has two pending entries (approve, then swap). The
#     daemon writes intent.json + plan.md + policy_check.json per id and
#     advertises confirm/replace/cancel as writable control files.
ls /bloom/wallets/alice/chains/ethereum/outbox/pending/
# -> 0001-...   (approve)
#    0002-...   (swap)

ls /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-.../
# -> intent.json  plan.md  policy_check.json  confirm  replace  cancel

cat /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-.../plan.md
# (per-tx plan: signed payload preview, gas, policy notes)

# 11) Second confirm — the actual broadcast. The two entries were staged
#     before either broadcast, so the nonce auto-increment gave them
#     consecutive slots (approve = N, swap = N+1), and a depends_on link makes
#     the swap's confirm refuse until the approve mines. The approve must
#     broadcast and mine before the swap; review both, then confirm in order.
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-.../confirm
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/0002-.../confirm

# 12) After broadcast, entries migrate to outbox/sent/.
ls /bloom/wallets/alice/chains/ethereum/outbox/sent/
```

Note: this is the `ethereum` flow, gated as "demonstration; broadcast disabled by default" until both `block_mainnet_broadcast=false` (daemon-wide) and `allow_broadcast=true` (per-chain) are set in config. The first nine steps work locally regardless; only step 11 actually hits the network.

## JSON-explicit equivalent

The handler accepts either a single-line NL string or a JSON body with `intent`, optional `chain`, and optional `slippage_bps`. The `intent` field itself stays in NL form — it is what the Enso intent parser consumes.

```
echo '{"intent":"swap 100 usdc to eth","chain":"ethereum"}' \
  > /bloom/defi/intents/alice/new
```

The handler is happy with `kind: "enso"` for symmetry with the wallet outbox parser (`{"kind":"enso","intent":"..."}`), but `kind` is optional. There is no addresses-only JSON form on the `defi/intents` surface — to feed an explicit token address, embed it in the NL string and the parser will treat it as a hex token (and consult `erc20_decimals()` for human-unit amounts):

```
echo 'swap 100 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 to ETH' \
  > /bloom/defi/intents/alice/new
```

## Overriding slippage

The default is 50 bps (0.5%). Override with the JSON form:

```
echo '{"intent":"swap 100 usdc to eth","slippage_bps":100}' \
  > /bloom/defi/intents/alice/new

cat /bloom/defi/intents/alice/0002-.../plan.md | grep Slippage
# Slippage:  100 bps
```

NL-only writes always use the 50-bps default; only the JSON form carries `slippage_bps`.

## Concrete swap examples

### 1. USDC -> ETH on Ethereum (ERC-20 in, auto-approve)

USDC is `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`. ETH is the native sentinel
`0xeeee...eeee`. Because the source is ERC-20, the handler checks
`erc20_allowance(USDC, alice, EnsoRouter)`; if it's below the requested 100e6,
an `approve(EnsoRouter, max)` is auto-prepended.

```
# NL form
echo 'swap 100 usdc to eth' > /bloom/defi/intents/alice/new

# JSON-explicit equivalent (slippage default 50 bps)
echo '{"intent":"swap 100 usdc to eth","chain":"ethereum"}' \
  > /bloom/defi/intents/alice/new

cat /bloom/defi/intents/alice/<id>/tx.json
# [ { "body": { "Approve": { "token": "0xA0b86991...", "spender": "0x<EnsoRouter>",
#                            "amount": "max" } }, "chain": "ethereum", ... },
#   { "body": { "Raw":     { "to":    "0x<EnsoRouter>", "value": "0",
#                            "data":  "0x..." } },                       ... } ]

echo y > /bloom/defi/intents/alice/<id>/confirm
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/<approve-id>/confirm
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/<swap-id>/confirm
```

(demonstration; broadcast disabled by default)

### 2. ETH -> USDC on Ethereum (native in, no approve)

Native ETH uses the `0xeeee...eeee` sentinel; the handler skips the allowance
check entirely and produces a single `[swap]` intent. `tx.value` carries the
ETH amount.

```
echo 'swap 0.5 eth to usdc' > /bloom/defi/intents/alice/new

# JSON-explicit equivalent
echo '{"intent":"swap 0.5 eth to usdc","chain":"ethereum"}' \
  > /bloom/defi/intents/alice/new

cat /bloom/defi/intents/alice/<id>/tx.json
# [ { "body": { "Raw": { "to":    "0x<EnsoRouter>",
#                        "value": "500000000000000000",
#                        "data":  "0x..." } }, "chain": "ethereum", ... } ]

echo y > /bloom/defi/intents/alice/<id>/confirm
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/<swap-id>/confirm
```

(demonstration; broadcast disabled by default)

### 3. USDC -> DAI on Base (different chain, auto-approve)

Base USDC is `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`. Base DAI is
`0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb`. Note: the handler's
`resolve_token_symbol` table has `USDC` for chain 8453 but no `DAI` entry, so
this example uses the explicit DAI hex address in the NL string. The `chain`
field can be supplied either via `on base` in NL form or as the JSON `chain`
field.

```
# NL form, chain via 'on base'
echo 'swap 100 usdc to 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb on base' \
  > /bloom/defi/intents/alice/new

# JSON-explicit equivalent
echo '{"intent":"swap 100 usdc to 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb","chain":"base"}' \
  > /bloom/defi/intents/alice/new

cat /bloom/defi/intents/alice/<id>/plan.md
# Chain:     base (id 8453)
# Token in:  0x833589fcd6edb6e08f4c7c32d4f71b54bda02913  amount=100000000 (raw)
# Token out: 0x50c5725949a6f0c72e6c4a641f24049a917db0cb  amountOut=...

# Auto-approve fires because USDC is ERC-20.
cat /bloom/defi/intents/alice/<id>/tx.json
# [ approve(USDC -> EnsoRouter, max), raw(swap) ]

echo y > /bloom/defi/intents/alice/<id>/confirm
echo y > /bloom/wallets/alice/chains/base/outbox/pending/<approve-id>/confirm
echo y > /bloom/wallets/alice/chains/base/outbox/pending/<swap-id>/confirm
```

This is the chain to use for end-to-end exercise: per-chain `allow_broadcast=true`
on Base is the safer place to actually take the route to broadcast.

### 4. ETH -> stETH on Lido (single-step, optional)

The Enso route surface is generic — anything Enso can express as a single
shortcut to a target contract works through `defi/intents`. For ETH -> stETH
on Lido (`0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`), pass the explicit hex
target since the symbol table doesn't include `STETH`:

```
echo 'swap 1 eth to 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84' \
  > /bloom/defi/intents/alice/new

# JSON-explicit equivalent
echo '{"intent":"swap 1 eth to 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84","chain":"ethereum"}' \
  > /bloom/defi/intents/alice/new
```

Whether Enso routes this as a Lido `submit()` or a market buy depends on
liquidity and the routing strategy — the route response is opaque here, so
read `route.json` and `plan.md` before confirming. (demonstration; broadcast
disabled by default)

## Token reference

These are the addresses the symbol table resolves (from `bloom_defi::resolve_token_symbol`) plus the rest from this doc that you can paste into NL strings as hex tokens.

### Ethereum mainnet (chain `ethereum`, id 1)

| Symbol | Address |
| ------ | ------- |
| ETH (native) | `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` |
| WETH | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` |
| USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` |
| DAI  | `0x6B175474E89094C44Da98b954EedeAC495271d0f` |
| WBTC | `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` |
| Lido stETH | `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84` |
| AAVE V3 Pool | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` |

### Base mainnet (chain `base`, id 8453)

| Symbol | Address |
| ------ | ------- |
| WETH | `0x4200000000000000000000000000000000000006` |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| DAI  | `0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb` |

The handler resolves only `USDC` by symbol on Base today; for everything else, paste the hex address into the NL string.
