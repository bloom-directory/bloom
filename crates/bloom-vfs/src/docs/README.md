# Bloom virtual filesystem

Bloom is an agentic Ethereum wallet exposed as a virtual filesystem.
Agents can inspect chains with reads, stage wallet actions with writes,
and review generated plans before any transaction is signed.

All paths below are relative to the Bloom VFS root.

## Top-level layout

- `chains/<chain>/` — read-only chain views: head, blocks, tx, addresses,
  contracts (`source`/`abi`/`methods`/`events`/`storage`/`proxy`),
  gas oracle, ERC-20 balances under `addresses/<a>/tokens/<token>/...`.
- `wallets/<name>/` — managed wallets, outbox write surface, history,
  allowances, ENS reverse, sign / EIP-712 surfaces.
- `defi/intents/` — Enso-mediated DeFi intents (write `quote` / `execute`).
- `petals/<name>/` — installed wallet extensions. Read `docs/petals.md` for
  the exact installed names, mount directories, consent summaries, and
  declared capabilities.
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

Default config includes read-ready RPCs for Ethereum, Base, Tempo, Robinhood
Chain, Arbitrum, Optimism, Polygon, BNB Smart Chain, Avalanche, Gnosis, Linea,
HyperEVM, and local Anvil. Per-chain broadcasting is enabled by default;
value-moving actions still require the applicable approval gates.

## Reading

Reads are RPC / API queries. Examples:

```sh
cat /bloom/chains/anvil/head/number
cat /bloom/chains/ethereum/blocks/19000000/full.json
cat /bloom/wallets/alice/address                     # the owner/signer EOA
cat /bloom/wallets/alice/addresses.json              # owner/signer addresses (see "Wallet addresses & roles")
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

## Creating a wallet

`wallets/new` starts an asynchronous Broker custody registration. The write
does not create a Machine-local wallet and returns before the owner ceremony
completes:

```sh
printf 'main\n' > /bloom/wallets/new
cat /bloom/wallets/registrations/main/status.json
```

The registration projection is keyed by the requested wallet petname. Verify
that `requested_name` in `status.json` is `main` before opening its
`ceremony_url`, polling it, or cancelling it. Poll until `ceremony_state` is
`COMPLETED`; only then does
`wallets/main/address` exist. Write `cancel` to
`wallets/registrations/<petname>/cancel` to cancel a live registration. Broker
owns ceremony orchestration and Signer owns custody. If either is unavailable,
the operation fails closed; Machine has no local fallback. Import, recovery,
rebind, and deletion likewise use Broker custody ceremonies, never mounted
secret input.

## Wallet addresses & roles

A wallet has **one owner/signer key**. Petals may associate it with additional
venue-specific addresses that it controls but does not equal. Conflating them
is a real hazard — e.g. reporting a Polymarket deposit wallet's balance as
"the wallet's balance."

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
    "roles": {}
  }
  ```

  `owner` and `signer` are the same EOA. `roles` is currently empty; Petals do
  not augment this Bloom-owned response. Query a Petal's own account route for
  venue-specific addresses. For example, after Polymarket onboarding:

  ```sh
  cat /bloom/petals/polymarket/account/alice/status.json
  # Read `deposit_wallet` from the response; it is not the owner EOA.
  ```

  `policy_status` reports the Broker-projected policy state. An invalid or
  stale projection blocks **writes/broadcast**, but never these public leaves.

Read-only leaves (`address`, `addresses.json`, `public_key`, `kind`, balances)
always work when their authenticated public projection is available. Machine
does not validate policy using a local signature file.

## Reusable authority (sealed approvals)

Reusable signing authority is owned durably by Broker and Signer. Machine does
not mint authority or keep an in-memory authorization bypass. Prepare an approval
by writing the canonical `ApprovalPrepareRequest` JSON produced by the client
to the mounted wallet path:

```sh
cp approval-prepare.json /bloom/wallets/alice/sealed-approvals/new.json
cat /bloom/wallets/alice/sealed-approvals/new.json       # exact ceremony projection
cat /bloom/wallets/alice/sealed-approvals/active.json    # Broker-backed active approvals
cat /bloom/wallets/alice/sealed-approvals/<id>/status.json
cat /bloom/wallets/alice/sealed-approvals/<id>/limits.json
```

Complete the returned browser ceremony before using the approval. Renewal and
revocation also accept their canonical Broker request JSON; they never mutate
authority locally in Machine:

```sh
cp approval-renew.json /bloom/wallets/alice/sealed-approvals/<id>/renew
cp approval-revoke.json /bloom/wallets/alice/sealed-approvals/<id>/revoke
cp approval-revoke-all.json /bloom/wallets/alice/sealed-approvals/revoke_all
```

Broker enforces the approval subject, operation classes, limits, expiry, and
revocation on every signing request. An absent or unavailable Broker fails
closed; mounted projections are display and orchestration state, not authority.

## Updating wallet policy

The only writable policy surface is the complete canonical JSON document at
`wallets/<wallet>/policy.json`. The first exact write stages
`policy.validate_update`; Broker authenticates the baseline, validates the
proposed bytes, builds the review, and originates a `policy_update` custody
ceremony:

```sh
cat /bloom/wallets/alice/policy.json > proposed-policy.json
cp proposed-policy.json /bloom/wallets/alice/policy.json
cat /bloom/wallets/alice/policy-updates/latest/status.json
cat /bloom/wallets/alice/policy-updates/latest/approval_challenge.json
```

Complete the ceremony at the projected `ceremony_url`, then retry the **exact
same proposed bytes**. Machine passes Broker's completed custody receipt to
`policy.commit_update`; Broker invokes Signer's authenticated policy
compare-and-swap. Changed bytes require fresh validation and review, while a
changed baseline fails closed.

```sh
cp proposed-policy.json /bloom/wallets/alice/policy.json
cat /bloom/wallets/alice/policy-updates/latest/status.json
```

The mounted status and challenge files are public projections of operation,
review, receipt, ceremony, and commit state. Receipt authority remains between
Broker and Signer. Machine has no direct policy writer.

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

The pre-installed Enso Petal accepts natural-language or JSON swap intents at
its own application mount:

```sh
echo 'swap 0.1 eth to USDC on base' \
  > /bloom/petals/enso/intents/alice/new
ls /bloom/petals/enso/intents/alice/
cat /bloom/petals/enso/intents/alice/<sess>/plan.md
cat /bloom/petals/enso/intents/alice/<sess>/simulation.json
echo confirm > /bloom/petals/enso/intents/alice/<sess>/confirm
```

If an ERC-20 approval is required, the first Petal confirmation stages only
the exact-amount approval. Broadcast it, wait for a successful receipt, and
confirm the Petal session again to simulate and stage the swap. Read the
installed Petal's `/petals/enso/README.md` for its current route contract.

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

Legacy arbitrary message, raw-hash, and typed-data signing leaves fail closed.
Installed Petals must use their declared payload-bearing Broker signing route;
transactions use the staged outbox path. Machine never writes signatures into
a local keystore.

Address book petnames:

```sh
echo '0x000000000000000000000000000000000000beef' \
  > /bloom/addressbook/alice
cat /bloom/addressbook/alice
```

See `examples.md` for end-to-end demos.
