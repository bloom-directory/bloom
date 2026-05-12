# NFT examples (ERC-721 / ERC-1155)

These examples assume the bloom VFS is mounted at `/bloom/`. The NFT
surface lives under two trees on every chain:

- `chains/<chain>/contracts/<a>/nft/...` — collection-level views.
- `chains/<chain>/addresses/<a>/nfts/...` — per-holder views and
  per-token detail.

ERC-721 vs ERC-1155 is auto-detected via `IERC165.supportsInterface`
and the result cached per `(chain_id, contract)` for the lifetime of
the daemon. Detection is shared between reads and writes, so the
first read warms the cache for the staging path. The optional
`standard` field on a `nft_transfer` intent skips the probe — useful
for non-standard contracts (CryptoPunks is the canonical example;
its transfer is non-standard, so the engine will reject ERC-721
transfers and you must call its native methods via a `call` intent).

For collection reads that need only `name`/`symbol`, no Etherscan
key is required — they are pure RPC. History feeds (`erc721_txs`,
`erc1155_txs`, `owned.json`) require a configured
`backends.address_history = "etherscan"` endpoint. Each example that
hits Etherscan or an external HTTP fetch is annotated inline.

---

## Collection reads — `chains/<chain>/contracts/<a>/nft/`

### Kind, name, symbol, totalSupply

```sh
# BAYC: ERC-165 detection + name + symbol + supply (RPC-only).
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/kind
# => erc721

cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/name
# => BoredApeYachtClub

cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/symbol
# => BAYC

cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/total_supply
# => 10000   (or "unknown" if the contract does not expose totalSupply)
```

`total_supply` is a soft probe: if the call reverts (some 1155 and
older 721 contracts don't expose `totalSupply()`) the leaf returns
the literal string `unknown` rather than erroring.

ERC-1155 collection on the OpenSea Shared Storefront:

```sh
cat /bloom/chains/ethereum/contracts/0x495f947276749Ce646f68AC8c248420045cb7b5e/nft/kind
# => erc1155
```

CryptoPunks — note the caveat:

```sh
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/kind
# => erc721 (it does answer ERC-165, but its `transferFrom` is non-standard;
#    `nft_transfer` will encode the standard ERC-721 selector which the
#    contract does NOT implement. Use the dedicated CryptoPunks methods
#    via a `call` intent for actual transfers.)
```

### Per-token collection lookups

`owner_of/<token_id>` and `token_uri/<token_id>` are directories whose
leaf names are the token id in decimal:

```sh
# CryptoPunks #5822 owner.
cat /bloom/chains/ethereum/contracts/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb/nft/owner_of/5822

# Pudgy Penguins #6873 tokenURI (just the URI string, not the metadata).
cat /bloom/chains/ethereum/contracts/0xBd3531dA5CF5857e7CfAA92426877b022e612cf8/nft/token_uri/6873

# Nouns #1 owner — Nouns DAO holds the auctioneer pattern, the owner is
# the winning bidder (or the treasury for unsold auctions).
cat /bloom/chains/ethereum/contracts/0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03/nft/owner_of/1
```

For ERC-1155, `owner_of` returns the literal `not applicable` (1155
has no single owner per id). Use the per-holder `balance` leaf.

### `isApprovedForAll(owner, operator)`

Two address segments under the `is_approved_for_all/` dir, in that
order. Useful for checking whether vitalik.eth has greenlit a
marketplace on a given collection:

```sh
# Has vitalik.eth approved the OpenSea conduit (example operator) on BAYC?
cat /bloom/chains/ethereum/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/is_approved_for_all/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/0x1E0049783F008A0085193E00003D00cd54003c71
# => true / false
```

---

## Per-holder reads — `chains/<chain>/addresses/<a>/nfts/`

These three top-level leaves rely on Etherscan (`backends.address_history`):

```sh
# Vitalik's ERC-721 transfer history.
# requires backends.address_history = "etherscan"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/erc721_txs

# Pranksy's ERC-1155 transfer history.
# requires backends.address_history = "etherscan"
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/erc1155_txs

# Best-effort holdings: reduces in/out from the ERC-721 history. Carries
# a "caveat" field flagging that this is not authoritative — out-of-band
# transfers, missed history, or reorgs will skew the result. Page-capped.
# requires backends.address_history = "etherscan"
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/owned.json
```

Output schema for `owned.json`:

```json
{
  "caveat": "best-effort: reduced from etherscan tx history; not authoritative",
  "tokens": [
    { "contract": "0x...", "token_id": "1234", "standard": "erc721" }
  ]
}
```

---

## Per-token reads — `nfts/<contract>/<token_id>/`

Six leaves: `owner`, `uri`, `metadata.json`, `balance`, `is_owner`,
`approved`. All are RPC-only except `metadata.json`, which fetches
the URI over HTTP/IPFS. These are valid for any holder-context path
— the `<a>` in the URL is the holder you're asking about for
`balance` and `is_owner`, and is irrelevant for `owner`/`uri`.

### ERC-721 example: BAYC #1, viewed from Vitalik's holder context

```sh
# The actual on-chain owner.
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/owner

# Token URI (just the URI).
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/uri

# Pretty-printed metadata. Fetches the URI over HTTP / IPFS / data:.
# Caps: 1 MiB body, 5s total timeout. ipfs:// is rewritten to
# https://ipfs.io/ipfs/<cid>. data: URIs are decoded inline (base64
# or URL-encoded JSON).
# external HTTP fetch
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/metadata.json

# `balance` is always 0 or 1 for ERC-721; `is_owner` is the boolean form.
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/balance
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/is_owner

# Per-token approved operator (ERC-721 only). For ERC-1155 this leaf
# returns the literal "not applicable".
cat /bloom/chains/ethereum/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/nfts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/1/approved
```

### ERC-1155 example: OpenSea Shared Storefront, large hex id

ERC-1155 token ids are commonly 256-bit and emitted in hex. The VFS
parses decimal strings, so for hex ids convert first or pass the
decimal form. The metadata URI returned by the contract may contain
the literal `{id}` placeholder — bloom substitutes it with the
lowercase 64-char hex form (no `0x`) before the HTTP fetch, per the
ERC-1155 metadata spec.

```sh
# Token id 0x000000000000000000000000000000000000000000000000000000000000000a
# is decimal 10. URI for token id 10 on OpenSea Shared Storefront:
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/uri

# Pranksy's balance of that id.
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/balance

# Metadata: if the contract's URI is "https://api.opensea.io/api/v1/metadata/0x495f.../{id}",
# bloom fetches "https://api.opensea.io/api/v1/metadata/0x495f.../000...000000000a".
# external HTTP fetch
cat /bloom/chains/ethereum/addresses/0xd387a6e4e84a6c86bd90c158c6028a58cc8ac459/nfts/0x495f947276749Ce646f68AC8c248420045cb7b5e/10/metadata.json
```

### Base mainnet — same shape

```sh
# An ERC-721 collection on Base. Same per-token leaves apply; only the
# chain segment changes.
cat /bloom/chains/base/contracts/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D/nft/kind
```

---

## Writes — outbox intents

NFT writes use the same stage / inspect / confirm pipeline as any
other tx: drop a JSON or shell-shorthand body into
`outbox/new.tx`, read the resulting `pending/<seq>-<hash>/plan.md`,
then write `y` to `confirm`. Three intents are wired in:
`nft_transfer`, `nft_approve` (ERC-721 single-token), and
`nft_approve_all` (`setApprovalForAll`, both standards).

The destination `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` used
below is **Anvil dev account #1** — a clearly-labeled test recipient.
Replace with a real address (or ENS name like `vitalik.eth`) for
mainnet use.

### `nft_transfer` — ERC-721, JSON form

`safe` defaults to `true`, which encodes `safeTransferFrom`. Set
`safe: false` for legacy `transferFrom`:

```sh
# Move BAYC #1 from `alice` to the test recipient. Standard auto-
# detected; the engine emits safeTransferFrom(address,address,uint256).
echo '{
  "kind": "nft_transfer",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "1"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

Legacy unsafe transfer (skips `onERC721Received` callback):

```sh
echo '{
  "kind": "nft_transfer",
  "contract": "0xED5AF388653567Af2F388E6224dC7C4b3241C544",
  "to":       "vitalik.eth",
  "token_id": "1234",
  "safe":     false
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

### `nft_transfer` — ERC-721, shell shorthand

The shell parser accepts `nft transfer <contract> <token_id> to <addr>
[on <chain>]` (no `#` prefix on the id):

```sh
# Same as the JSON BAYC #1 transfer above.
echo 'nft transfer 0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D 1 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Pudgy Penguins #6873 to vitalik.eth.
echo 'nft transfer 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 6873 to vitalik.eth on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

### `nft_transfer` — ERC-1155 with amount and optional data

ERC-1155 transfers carry an `amount` (defaults to 1 if omitted) and
an opaque `data` blob (defaults to empty `0x`). Pass `standard:
"erc1155"` to skip the ERC-165 probe, or omit it and let the engine
auto-detect:

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

# Same with optional `data` payload (forwarded to onERC1155Received).
echo '{
  "kind":     "nft_transfer",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "to":       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "10",
  "standard": "erc1155",
  "amount":   "1",
  "data":     "0xdeadbeef"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

Shell shorthand for ERC-1155 (the `amount <n>` clause flips the
standard hint to erc1155, so no JSON is needed):

```sh
echo 'nft transfer 0x495f947276749Ce646f68AC8c248420045cb7b5e 10 amount 3 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

### `nft_approve` — ERC-721 per-token

Encodes `approve(operator, tokenId)`. The engine probes via ERC-165
first; if the contract is ERC-1155 the stage **fails** with:

```
ERC-1155 has no per-token approval; use nft_approve_all
```

ERC-721 approve example (Doodles #1234 to a marketplace operator):

```sh
echo '{
  "kind":     "nft_approve",
  "contract": "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "1234"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Equivalent shell shorthand:
echo 'nft approve 0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e 1234 to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Revoke: pass the zero address as operator.
echo '{
  "kind":     "nft_approve",
  "contract": "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e",
  "operator": "0x0000000000000000000000000000000000000000",
  "token_id": "1234"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

Rejection example — the OpenSea Shared Storefront is ERC-1155, so a
per-token approve fails at staging:

```sh
echo '{
  "kind":     "nft_approve",
  "contract": "0x495f947276749Ce646f68AC8c248420045cb7b5e",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "token_id": "10"
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Inspect the failure: the failed/ slot will hold the rejected intent
# with the engine error. Nothing lands in pending/.
ls /bloom/wallets/alice/chains/ethereum/outbox/failed/
cat /bloom/wallets/alice/chains/ethereum/outbox/failed/0001-*/error
# => ERC-1155 has no per-token approval; use nft_approve_all
```

### `nft_approve_all` — operator-wide (`setApprovalForAll`)

Same selector for ERC-721 and ERC-1155. The engine attaches a
`nft.approve_all` policy line to the staged plan:

- `approved: true`  -> `PolicyOutcome::Warn` ("operator-wide
  approval ... — review carefully")
- `approved: false` -> `PolicyOutcome::Pass` (revocation)

Because of the WARN, the resulting `plan.md` flags the broad scope
explicitly before you confirm. Some policies may further escalate
this to a write-override-token requirement; check `plan.md`.

```sh
# Grant operator-wide approval on BAYC. Triggers the WARN line.
echo '{
  "kind":     "nft_approve_all",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "approved": true
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Shell shorthand (note: verb is `set_approval_for_all`, with operator
# before the boolean):
echo 'nft set_approval_for_all 0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 true on ethereum' \
  > /bloom/wallets/alice/chains/ethereum/outbox/new.tx

# Revoke a previously-granted operator-wide approval (no WARN).
echo '{
  "kind":     "nft_approve_all",
  "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
  "operator": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "approved": false
}' > /bloom/wallets/alice/chains/ethereum/outbox/new.tx
```

### Inspect the plan, then confirm

After any of the writes above, the daemon writes a numbered pending
slot. The plan markdown decodes the NFT action, the contract,
counterparty, token id, ERC-1155 amount when set, and any policy
checks (including the `nft.approve_all` WARN):

```sh
ls /bloom/wallets/alice/chains/ethereum/outbox/pending/
# 0001-7f3c.../

cat /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/plan.md

# Confirm.
echo y > /bloom/wallets/alice/chains/ethereum/outbox/pending/0001-*/confirm

# Receipt lands under sent/.
ls /bloom/wallets/alice/chains/ethereum/outbox/sent/
```

If a policy WARN surfaced a write-override requirement, the daemon
will reject the plain `y` and you'll need to write the override
token instead — see the policy-engine docs for the exact form.

---

## Quick reference

| Path | Standard | Returns |
|------|----------|---------|
| `contracts/<a>/nft/kind` | both | `erc721` / `erc1155` / `unknown` |
| `contracts/<a>/nft/{name,symbol,total_supply}` | both | scalar (or `unknown` for supply) |
| `contracts/<a>/nft/owner_of/<id>` | 721 | checksum address (1155: `not applicable`) |
| `contracts/<a>/nft/token_uri/<id>` | both | URI string ({id} substituted for 1155) |
| `contracts/<a>/nft/is_approved_for_all/<o>/<op>` | both | `true` / `false` |
| `addresses/<a>/nfts/erc721_txs` | 721 | etherscan-backed history |
| `addresses/<a>/nfts/erc1155_txs` | 1155 | etherscan-backed history |
| `addresses/<a>/nfts/owned.json` | 721 | best-effort holdings (caveat) |
| `addresses/<a>/nfts/<c>/<id>/owner` | 721 | checksum address |
| `addresses/<a>/nfts/<c>/<id>/uri` | both | URI string |
| `addresses/<a>/nfts/<c>/<id>/metadata.json` | both | fetched body (1 MiB / 5 s ceiling) |
| `addresses/<a>/nfts/<c>/<id>/balance` | both | uint (0/1 for 721) |
| `addresses/<a>/nfts/<c>/<id>/is_owner` | both | `true` / `false` |
| `addresses/<a>/nfts/<c>/<id>/approved` | 721 | checksum address (1155: `not applicable`) |
