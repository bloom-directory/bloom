# Bloom virtual filesystem

Bloom is an agentic Ethereum wallet exposed as a virtual filesystem.
Agents can inspect chains with reads, stage wallet actions with writes,
and review generated plans before any transaction is signed.

If you are setting Bloom up for a user, start from
`https://bloom.directory/SKILL.md`; it is the canonical agent setup
prompt.

## Running

Use `bloom serve` for a long-running daemon with JSON-RPC IPC only. To expose
the same VFS through the kernel NFS client, use a binary built with the `mount`
feature and pass `--mount`:

```sh
bloom serve --mount              # /bloom on Linux, /Volumes/bloom on macOS
bloom serve --mount /tmp/bloom   # explicit mount path
```

The mount point must already exist and the platform mount command may require
elevated privileges. Without a mount, the same paths are available through
`bloom vfs ls`, `bloom vfs cat`, and `bloom vfs write`.

## Top-level layout

- `chains/<chain>/` — read-only chain views: head, blocks, tx, addresses,
  contracts (`source`/`abi`/`methods`/`events`/`storage`/`proxy`),
  gas oracle, ERC-20 balances under `addresses/<a>/tokens/<token>/...`.
- `wallets/<name>/` — managed wallets, outbox write surface, history,
  allowances, ENS reverse, sign / EIP-712 surfaces.
- `defi/intents/` — Enso-mediated DeFi intents (write `quote` / `execute`).
- `hyperliquid/` — HyperCore reads plus signed exchange and agent-session
  writes; see `docs/hyperliquid-integration.md` for the reviewer-facing map.
- `polymarket/` — prediction-market reads, onboarding, and trade drafts
  (opt-in + human-gated; drive with `bloom polymarket ...`; see `docs/examples.md`).
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

Default config includes read-ready RPCs for Ethereum, Base, Arbitrum,
Optimism, Polygon, BNB Smart Chain, Avalanche, Gnosis, Linea, HyperEVM,
and local Anvil. Live-network broadcasts remain disabled until the user
opts in via config.

## Reading

Reads are RPC / API queries. Examples:

```sh
cat /bloom/chains/anvil/head/number
cat /bloom/chains/ethereum/blocks/19000000/full.json
cat /bloom/wallets/alice/address                     # the owner/signer EOA
cat /bloom/wallets/alice/addresses.json              # owner/signer + role addresses (see "Wallet addresses & roles")
cat /bloom/wallets/alice/chains/anvil/balance        # "1.5 ETH" (display); also balance.raw, balance.json
cat /bloom/wallets/alice/chains/ethereum/history.json
cat /bloom/tools/keccak/hello
cat /bloom/tools/abi/decode/<sig>/<hex>
cat /bloom/ens/vitalik.eth/address
cat /bloom/ens/vitalik.eth/avatar
cat /bloom/ens/vitalik.eth/text/url
cat /bloom/prices/spot/eth.usd
cat /bloom/addressbook/alice
```

Some virtual collections, such as `chains/<chain>/blocks/`, are too large to
enumerate. Address known block numbers directly; each block directory exposes
`full.json`.

Transaction-by-hash reads expose a small directory of receipt and transaction
views. The hash directory resolves only when the configured RPC returns a
transaction; malformed or unknown hashes surface as `NotFound`:

```sh
TX=0x...
ls /bloom/chains/ethereum/tx/$TX/
cat /bloom/chains/ethereum/tx/$TX/status
cat /bloom/chains/ethereum/tx/$TX/gas_used
cat /bloom/chains/ethereum/tx/$TX/block_number
cat /bloom/chains/ethereum/tx/$TX/full.json
cat /bloom/chains/ethereum/tx/$TX/receipt.json
cat /bloom/chains/ethereum/tx/$TX/logs.json
cat /bloom/chains/ethereum/tx/$TX/error.json
```

ERC-20 token reads (you supply the token contract address):

```sh
A=0xd8da...
# Discovery: ls the dir, then read its self-describing meta-files.
ls  /bloom/chains/base/addresses/$A/tokens/
cat /bloom/chains/base/addresses/$A/tokens/README.md   # path grammar + leaf names
cat /bloom/chains/base/addresses/$A/tokens/known.json  # common + recently-seen tokens

# Per-token reads under <token> (an ERC-20 contract address):
T=0x833589fcd6edb6e08f4c7c32d4f71b54bda02913   # Base USDC
cat /bloom/chains/base/addresses/$A/tokens/$T/balance        # "1.5 USDC"
cat /bloom/chains/base/addresses/$A/tokens/$T/balance.raw    # base units
cat /bloom/chains/base/addresses/$A/tokens/$T/balance.json   # {symbol,decimals,raw,formatted,...}
cat /bloom/chains/base/addresses/$A/tokens/$T/symbol
cat /bloom/chains/base/addresses/$A/tokens/$T/decimals
```

If `symbol()`/`decimals()` can't be read (revert, non-standard token, or
RPC outage), `symbol`/`decimals`/`balance` error out instead of returning
placeholder `?`/`18`; `balance.raw` still works and `balance.json` carries
`metadata_status: "ok" | "fallback"` (with `null` fields on fallback).

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

## Wallet addresses & roles

A wallet has **one owner/signer key** but may be associated with additional
**role addresses** that it controls but does not equal. Conflating them is a
real hazard — e.g. reporting a Polymarket deposit wallet's balance as "the
wallet's balance."

- `wallets/<w>/address` — the **owner/signer EOA**. This is the wallet itself:
  the key that signs, and the address you fund for gas/native transfers.
- `wallets/<w>/addresses.json` — the canonical "who is this wallet" answer:

  ```json
  {
    "wallet": "alice",
    "kind": "passkey",
    "owner":  "0x5c3d…4456",
    "signer": "0x5c3d…4456",
    "policy_status": "unsigned",
    "roles": {
      "polymarket_deposit_wallet": {
        "address": "0x3855…0166",
        "source": "live_factory_resolved",
        "fundable": true,
        "note": "Polymarket trade funder/maker — NOT the wallet owner."
      }
    }
  }
  ```

  `owner` and `signer` are the same EOA. Role addresses (e.g. the Polymarket
  deposit/funder wallet, derived from the owner) appear under `roles`; sending
  funds there does not change ownership. `roles` is empty when no role address
  is known. `policy_status` (`signed`/`unsigned`/`stale`/`not_applicable`)
  reports whether a passkey wallet's policy is signed — `unsigned`/`stale` block
  **writes/broadcast**, but never block these read-only leaves.

Read-only leaves (`address`, `addresses.json`, `public_key`, `kind`, balances)
always work, even when a passkey wallet's `policy.toml` is unsigned or stale.
The policy signature only gates staging/broadcast/signing.

## Batch signing (policy sessions)

To avoid a passkey prompt per `$1` transaction, mint a **bounded session** with
one ceremony. It authorizes only the listed transactions, on the listed chains,
up to a total USD cap, until it expires:

```sh
echo '{"chains":[42161,8453],"max_usd":10,"ttl_secs":600,"pending_ids":["0001-a","0001-b"]}' \
  > /bloom/wallets/alice/policy-session/new          # passkey ceremony renders the envelope
cat /bloom/wallets/alice/policy-session/active.json   # live sessions + remaining budget
echo y > /bloom/wallets/alice/policy-session/<id>/revoke
```

Confirms that fall inside the bounds (chain ∈ list, id ∈ list, not expired,
cumulative USD ≤ cap) broadcast without another prompt; anything outside
re-prompts. The session lives only in memory and expires independently of the
unlocked key.

## Writing (stage-confirm)

On `confirm`, before broadcasting, Bloom:
- **simulates** the tx (`eth_call`) against current state and refuses to
  broadcast one that would revert (write `override` instead of `y` to force);
- enforces **same-chain dependencies**: a tx with a `depends_on` (e.g. a swap
  that follows its `approve`) is refused until the predecessor has mined
  **successfully** — "waiting to confirm" while unconfirmed, blocked if it
  reverted. A background reconciler records each sent tx's mined outcome in a
  `receipt.json` next to the entry.

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

Deposit to Hyperliquid is a first-class goal:

```sh
echo 'deposit 5 USDC to hyperliquid' > /bloom/defi/intents/alice/new
```

It stages a USDC transfer to the Hyperliquid Bridge2 contract on Arbitrum
(the deposit primitive). Guardrails, before anything is staged:
- only **native USDC on Arbitrum** is credited — a non-Arbitrum source is
  rejected with guidance to consolidate to Arbitrum USDC first (sending
  Base/Polygon USDC straight to the bridge does **not** credit);
- deposits **below 5 USDC are refused** (the bridge does not credit them and
  does not auto-return them);
- cross-chain dust deposits warn when gas likely exceeds value.

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
