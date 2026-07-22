# Examples

These examples use paths under the Bloom VFS root.

## Local Anvil round-trip

```sh
# 1. Inspect the mounted chain and wallet.
cat /bloom/chains/anvil/head/number
cat /bloom/wallets/alice/address
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

## Creating a wallet (asynchronous passkey registration)

```sh
# 1. Start registration — this is NOT a local wallet and does not block.
printf 'main\n' > /bloom/wallets/new

# 2. Read status and the ceremony URL, and open/forward the URL to a human.
cat /bloom/wallets/registrations/main/status.json
cat /bloom/wallets/registrations/main/ceremony_url

# 3. Poll status until "state" is "completed", then read the new wallet.
cat /bloom/wallets/registrations/main/status.json
cat /bloom/wallets/main/address
```

Requires a running `bloom serve` daemon. Cancel a live registration with
`printf 'x' > /bloom/wallets/registrations/main/cancel`.

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

## Polymarket (external Petal)

Bloom does not ship a native Polymarket CLI or root-level VFS subtree.
`bloom init` provisions the pinned default package; inspect the route contract
served by that exact package version:

```sh
bloom init
bloom vfs cat /petals/polymarket/meta/route-contract.json
```

The installed Petal owns its routes and venue-specific state. Bloom supplies the
generic HTTP, chain-read, storage, outbox, signing, and approval host contracts.
