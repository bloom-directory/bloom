# Examples

These examples assume the VFS is mounted. Start a mount-enabled daemon first:

```sh
bloom serve --mount              # /bloom on Linux, /Volumes/bloom on macOS
bloom serve --mount /tmp/bloom   # explicit mount path
```

If the tree is not mounted, use the equivalent `bloom vfs cat`, `bloom vfs ls`,
and `bloom vfs write` commands against paths without the mount prefix.

## Local Anvil round-trip

```sh
# 1. Start anvil
anvil --port 8545

# 2. In another terminal, create a wallet (passkey is the default; for a
#    passphrase wallet in dev, use --local --allow-passphrase-wallet
#    --passphrase-file <path>)
bloom wallet new alice

# 3. Inspect chain
cat /bloom/chains/anvil/head/number
cat /bloom/chains/anvil/chain_id

# 4. Stage a send
echo '{"to":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","value":"0.1 eth","chain":"anvil"}' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx

# 5. Inspect plan
ls /bloom/wallets/alice/chains/anvil/outbox/pending/
cat /bloom/wallets/alice/chains/anvil/outbox/pending/0001-*/plan.md

# 6. Confirm
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/0001-*/confirm

# 7. Inspect receipt
ls /bloom/wallets/alice/chains/anvil/outbox/sent/
```

## Tools

```sh
cat /bloom/tools/keccak/abc                     # hex digest
cat /bloom/tools/address/checksum/0xabc...      # EIP-55 form
cat /bloom/tools/unit/parse/1.5/eth             # → 1500000000000000000
cat /bloom/tools/unit/format/1500000000000000000/18  # → 1.5
```

## NFTs (ERC-721 / ERC-1155)

```sh
# CryptoPunks #5822 — collection view (RPC-only, no etherscan needed):
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/kind
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/name
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/owner_of/5822

# BoredApe #1 — per-holder view (history needs an etherscan API key):
cat /bloom/chains/ethereum/addresses/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nfts/erc721_txs
cat /bloom/chains/ethereum/addresses/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nfts/owned.json

# Per-token detail (auto-detects ERC-1155 and substitutes the {id}
# placeholder in the metadata URI):
cat /bloom/chains/ethereum/addresses/0x.../nfts/0x.../1/owner
cat /bloom/chains/ethereum/addresses/0x.../nfts/0x.../1/uri
cat /bloom/chains/ethereum/addresses/0x.../nfts/0x.../1/metadata.json
cat /bloom/chains/ethereum/addresses/0x.../nfts/0x.../1/is_owner       # true/false
cat /bloom/chains/ethereum/addresses/0x.../nfts/0x.../1/balance         # always 1 for ERC-721
```

`metadata.json` follows `data:`, `ipfs://`, and `http(s)://` URIs (1 MiB
ceiling, 5s timeout). For ERC-1155 contracts the `{id}` placeholder in
the returned URI is substituted with the lowercase 64-char hex form of
the token id, per spec.

## NFT writes (transfer / approve)

NFT writes go through the same `outbox/new.tx` stage-confirm pipeline
as native sends. Three intent kinds are wired in. Each one auto-detects
ERC-721 vs ERC-1155 via ERC-165 (the optional `standard` field skips
the probe — useful for non-standard contracts).

```sh
# 1. Transfer ERC-721 #1234 to Bob (encodes safeTransferFrom by default;
#    set "safe": false to use the legacy `transferFrom`):
echo '{
  "kind": "nft_transfer",
  "contract": "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "1234"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Same intent in shell form:
echo 'nft transfer 0xb47e3...3bbb #1234 to 0x70997...79C8' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# 2. Per-token approve (ERC-721 only; ERC-1155 has no per-token approval
#    and the engine rejects it with a clear error):
echo 'nft approve 0xb47e3...3bbb #1234 operator 0x111...111' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# 3. setApprovalForAll — operator-wide. This always trips a policy WARN
#    so the resulting plan.md flags the broad scope before you confirm.
echo '{
  "kind": "nft_approve_all",
  "contract": "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb",
  "operator": "0x1111111111111111111111111111111111111111",
  "approved": true
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# 4. ERC-1155 transfer with explicit amount:
echo '{
  "kind": "nft_transfer",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "0x...id...",
  "standard": "erc1155",
  "amount":   "3"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

Inspect the plan before confirming — it shows the decoded NFT action,
the contract / counterparty, the token id, and any policy warnings:

```sh
cat /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/plan.md
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/confirm
```

## Polymarket (prediction markets)

Trading is **opt-in, human-gated, and binary-markets-only**. Read
`docs/polymarket-integration.md` for the full spec; this is the happy path.

Prerequisites:

```toml
# ~/.bloom/config.toml — the block must be present; fields default
# (chain_id = 137, builder_key_mode = "auto").
[polymarket]

# A Polygon chain entry to settle + broadcast funding on (same shape as other
# chains); broadcast must be enabled for the funding tx.
[chains.polygon]
chain_id = 137
allow_broadcast = true
```

```toml
# ~/.bloom/keystore/<wallet>/policy.toml — trading is refused until this opts in.
[polymarket]
enabled = true
max_order_usd = "5"     # per-order cap (decimal string)
max_daily_usd = "20"    # trailing-24h posted cap
max_price = "0.90"      # per-share price ceiling
# allowed_slugs / denied_slugs / allowed_condition_ids / denied_condition_ids
```

Happy path (self-contained commands; no `bloom serve` needed). Value-moving
steps open a passkey ceremony — run them in the foreground with a human present,
or use a local wallet with `BLOOM_PASSPHRASE` set for headless runs:

```sh
# Onboard: deploy the deposit wallet, approve the V2 contracts, mint CLOB creds,
# sync buying power. Optionally fund inline with --target-pusd/--max-spend.
bloom polymarket onboard alice --target-pusd 5 --max-spend 8

# Or fund separately (target-denominated swap, bounded by --max-spend), or
# execute a request staged via the VFS at polymarket/fund/<wallet>/new:
bloom polymarket fund alice --target-pusd 5 --max-spend 8
bloom polymarket fund alice --request <request-id>

# Draft an order (dry-run shows the reviewable plan; nothing signs), then confirm:
bloom polymarket order alice <market-slug> yes 3 --max-price 0.70 --dry-run
bloom polymarket confirm alice <draft-id>

# Exit + housekeeping:
bloom polymarket sell alice <market-slug> yes <shares> --min-price 0.50
bloom polymarket cancel alice <order-id>
bloom polymarket obligations alice            # read-only: open positions + next exit
bloom polymarket redeem alice <market-slug>   # after resolution (redeemable positions)
bloom polymarket withdraw-pusd alice all      # deposit wallet → owner EOA
bloom polymarket revoke-approvals alice       # withdraw the V2 spending approvals
```

Caveats: only true binary YES/NO markets trade; geoblock is fail-closed (refuses
in restricted regions); orders use the gasless deposit wallet (signatureType 3);
keep deposit-wallet balances small — this is a hot wallet, and the terminal/browser
review hash is a local consistency check, not a hardware trusted display. Drafts
and receipts are readable at `polymarket/trade/<wallet>/{drafts,receipts}/...`.
