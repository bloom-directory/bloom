# bloom virtual filesystem

This is the help file vendored into the daemon.

## Top-level layout

- `chains/<chain>/` — read-only chain views: head, blocks, tx, addresses,
  contracts (`source`/`abi`/`methods`/`events`/`storage`/`proxy`),
  gas oracle, ERC-20 balances under `addresses/<a>/tokens/<token>/...`.
- `wallets/<name>/` — managed wallets, outbox write surface, history,
  allowances, ENS reverse, sign / EIP-712 surfaces.
- `defi/intents/` — Enso-mediated DeFi intents (write `quote` / `execute`).
- `watch/` — long-running subscriptions (head, addr, log) executed by the
  daemon and persisted to JSONL.
- `simulate/` — out-of-band tx simulation with state overrides
  (`eth_call` / `debug_traceCall`).
- `tools/` — pure helpers: `keccak`, `selector`, `address/checksum`,
  `sha256`, `blake3`, `hex`, `base64`, `unit/{parse,format}`, `abi`,
  `rlp`, `eip712`.
- `status/` — daemon health, RPC pool, audit head, cache stats, version.
- `docs/` — this file and examples.
- `ens/` — forward / reverse / text / contenthash resolution.
- `prices/` — DefiLlama price oracle (current / historical).
- `addressbook/` — local petname directory.

## Reading

Reads are RPC / API queries. Examples:

```sh
cat /bloom/chains/anvil/head/number
cat /bloom/chains/ethereum/blocks/19000000/json
cat /bloom/wallets/alice/chains/anvil/balance.eth
cat /bloom/wallets/alice/chains/ethereum/history.json
cat /bloom/tools/keccak/hello
cat /bloom/tools/abi/decode/<sig>/<hex>
cat /bloom/ens/vitalik.eth/address
cat /bloom/ens/vitalik.eth/avatar
cat /bloom/ens/vitalik.eth/text/url
cat /bloom/prices/spot/eth.usd
cat /bloom/addressbook/alice
```

NFT reads (auto-detects ERC-721 vs ERC-1155 via ERC-165):

```sh
# Per-holder views (transfer history requires etherscan-backed history).
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/erc721_txs
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/erc1155_txs
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/owned.json   # best-effort

# Per-token reads (RPC-only):
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/owner
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/uri
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/metadata.json
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/balance
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/is_owner
cat /bloom/chains/ethereum/addresses/0xd8da.../nfts/<contract>/<id>/approved

# Collection-level views:
cat /bloom/chains/ethereum/contracts/<contract>/nft/kind          # erc721 | erc1155 | unknown
cat /bloom/chains/ethereum/contracts/<contract>/nft/name
cat /bloom/chains/ethereum/contracts/<contract>/nft/symbol
cat /bloom/chains/ethereum/contracts/<contract>/nft/total_supply
cat /bloom/chains/ethereum/contracts/<contract>/nft/owner_of/<id>
cat /bloom/chains/ethereum/contracts/<contract>/nft/token_uri/<id>
cat /bloom/chains/ethereum/contracts/<contract>/nft/is_approved_for_all/<owner>/<operator>
```

## Writing (stage-confirm)

Native send (canonical):

```sh
echo 'send 0.01 eth to 0xabc... on anvil' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx
ls /bloom/wallets/alice/chains/anvil/outbox/pending/
cat /bloom/wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/<id>/confirm
```

ERC-20 send (token symbol resolved via address book / token registry):

```sh
echo 'send 100 USDC to alice on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

NFT writes — three intent kinds, ERC-721 + ERC-1155, ERC-165
auto-detected:

```sh
# Transfer ERC-721 #1234 to Bob (encodes `safeTransferFrom`):
echo 'nft transfer 0xb47e3...3bbb #1234 to 0x70997...79C8' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Per-token approve (ERC-721 only — ERC-1155 is rejected):
echo 'nft approve 0xb47e3...3bbb #1234 operator 0x111...111' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Operator-wide approval — always policy-warned:
echo 'nft set_approval_for_all 0xb47e3...3bbb operator 0x111...111 approved true' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

JSON form supports `"standard": "erc721"|"erc1155"` to skip the
auto-detect probe, and `"safe": false` on `nft_transfer` to use the
legacy `transferFrom` selector. ERC-1155 transfers accept an
`"amount"` (defaults to `"1"`) and an optional `"data"` payload.

Replace / cancel pending tx:

```sh
echo replace > /bloom/wallets/alice/chains/ethereum/outbox/pending/<id>/replace
echo cancel  > /bloom/wallets/alice/chains/ethereum/outbox/pending/<id>/cancel
```

DeFi intent (Enso shortcuts) — natural language is the canonical input;
JSON works too. Requires an `[enso]` block in `~/.bloom/config.toml`
with an API key (`BLOOM_ENSO_KEY`):

```sh
echo 'swap 0.1 eth to USDC on base' \
  > /bloom/defi/intents/alice/new
ls /bloom/defi/intents/alice/
cat /bloom/defi/intents/alice/<sess>/plan.md
echo y > /bloom/defi/intents/alice/<sess>/confirm
```

ERC-20 token-in routes auto-prepend an `approve(spender, max)` ahead
of the swap when the current allowance is insufficient.

Subscribe + read (TOML body, kinds: `block`, `balance`, `gas_price`,
`event`):

```sh
cat <<'EOF' > /bloom/watch/new
kind = "block"
chain = "anvil"
EOF
tail -f /bloom/watch/<id>/live              # in-process running state
cat    /bloom/watch/<id>/history.jsonl     # rotated archive (1 MiB each)
```

Sign arbitrary message / raw hash / EIP-712 typed data:

```sh
echo 'hello world' > /bloom/wallets/alice/sign/message
cat /bloom/wallets/alice/sign/message.sig
cat eip712.json     > /bloom/wallets/alice/sign/typed_data
cat /bloom/wallets/alice/sign/typed_data.sig
```

Address book petnames:

```sh
echo '0x000000000000000000000000000000000000beef' \
  > /bloom/addressbook/alice
cat /bloom/addressbook/alice
```

Mainnet broadcasts are **disabled by default**. Configure via
`~/.bloom/config.toml` (`block_mainnet_broadcast = false` is required
to allow live broadcasts).

See `examples.md` for end-to-end demos.
