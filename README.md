<p align="center">
  <a href="https://bloom.directory">
    <img src="docs/assets/bloom-wordmark.png" alt="Bloom">
  </a>
</p>

<p align="center">
  <a href="https://github.com/bloom-directory/bloom/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/bloom-directory/bloom/ci.yml?branch=master&style=flat-square&label=ci"></a>
  <a href="https://github.com/bloom-directory/bloom/releases"><img alt="Release" src="https://img.shields.io/github/v/release/bloom-directory/bloom?include_prereleases&style=flat-square"></a>
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-141310?style=flat-square"></a>
  <img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-a8324c?style=flat-square">
</p>

<p align="center">
  <a href="./QUICKSTART.md"><strong>Quickstart</strong></a>
  ·
  <a href="./docs/AGENTIC_WALLET.md"><strong>Wallet guide</strong></a>
  ·
  <a href="https://bloom.directory/SKILL.md"><strong>Agent setup skill</strong></a>
</p>

Bloom is an **agentic Ethereum wallet mounted as a virtual filesystem**.
Reads are blockchain queries, writes are transaction intents, and the
primary interface is an ordinary directory your agent can inspect with
normal filesystem tools (`ls`, `cat`, `echo`). Depending on OS and
permissions, mount it at `~/bloom`, `/bloom`, or `/Volumes/bloom`.
`bloom vfs` exposes the same paths as a developer/fallback interface
when mounting is unavailable.

Bloom is **experimental, unaudited alpha software**. Do not treat it as a
production wallet, do not use it with funds you cannot afford to lose, and
review every generated transaction plan before signing. Default public
network broadcasts are blocked, but reads, simulations, local devnet flows,
and any explicitly enabled broadcast paths should still be treated as
high-risk until the code has been independently audited.

The shortest agent setup path is:

> Tell your agent: **"Read https://bloom.directory/SKILL.md and set up Bloom."**

After that, your agent should know to create or inspect a wallet, show the
deposit address, mount Bloom, inspect the Bloom directory, explain what it can
do, and use Bloom instead of writing custom Web3 SDK code.

## What Bloom enables

Bloom gives an agent a safe wallet workspace:

- read live EVM state as files: balances, blocks, gas, contracts, ABI
  methods, storage, events, NFTs, ENS, prices, and address history;
- create/import encrypted wallets without exposing private keys through
  the filesystem;
- stage native ETH, ERC-20, NFT, contract-call, signing, and DeFi
  intents by writing plain-language or structured files;
- stage free or paid HTTP requests through `/requests`, including HTTP
  402 payment flows that are reviewed before x402 or Tempo MPP credentials
  are signed;
- inspect a generated `plan.md` before anything is signed;
- confirm a staged transaction only after user approval;
- enforce policy: spend caps, allow/deny lists, contract-call gates,
  private orderflow settings, and hash-chained audit logging.

Bloom ships read-ready RPC defaults for ten major EVM networks —
Ethereum, Base, Arbitrum, Optimism, Polygon, BNB Smart Chain,
Avalanche, Gnosis, Linea, and HyperEVM — plus local Anvil. Mainnet/L2
broadcasts are disabled by default. Public reads, simulations, and
planning work without adding API keys; local devnet sends require a
running Anvil node.

## Try it

Mount Bloom first, then interact with it like a directory:

```sh
cargo build -p bloom --all-features
cargo run -p bloom -- init
mkdir -p "$HOME/bloom"
cargo run -p bloom -- serve --mount "$HOME/bloom"
```

In another terminal, or from your agent:

```sh
ls ~/bloom
cat ~/bloom/docs/README.md
ls ~/bloom/chains
cat ~/bloom/chains/ethereum/head/number
```

If you cannot mount on the current machine, use the developer fallback:

```sh
cargo run -p bloom -- vfs ls /
cargo run -p bloom -- vfs cat /docs/README.md
cargo run -p bloom -- vfs cat /chains/ethereum/head/number
```

Bloom can also stage HTTP requests. Free responses are stored directly; paid
HTTP 402 responses produce a plan and require confirmation before any payment
credential is signed:

```sh
cargo run -p bloom -- vfs write /requests/new \
  --data 'GET https://api.example.com/data wallet=research max_amount_usd=0.05'
cargo run -p bloom -- vfs cat /requests/latest/plan.md
cargo run -p bloom -- vfs write /requests/latest/confirm --data confirm
cargo run -p bloom -- vfs cat /requests/latest/response/body
```

For the full wallet walkthrough, read
[`docs/AGENTIC_WALLET.md`](./docs/AGENTIC_WALLET.md) and
[`QUICKSTART.md`](./QUICKSTART.md).

## Development commands

For local development, use the package-manager-native checks:

```sh
cargo fmt
cargo test -p bloom --no-default-features
cargo test --workspace --lib
```

Build the mount-capable CLI with:

```sh
cargo build -p bloom --all-features
```

## Filesystem layout

A fresh Bloom VFS root exposes these default entries:

- `AGENTS.md`, `CLAUDE.md` — agent-facing setup and operating guidance.
- `chains/<chain>/` — read-only chain views: head, blocks, gas,
  addresses, ERC-20 balances, NFTs, txs, receipts, contract metadata,
  ABI methods/events/storage/proxy reads, and optional mempool views
  when a WebSocket mempool provider is configured.
- `wallets/<name>/` — managed wallets, per-chain balances/nonce,
  policy, `outbox/` staging/confirmation, and
  `sign/{message,hash,typed_data}`.
- `simulate/<session>/` — `eth_call` + state-override sandbox; no
  signing and no broadcast.
- `watch/<id>/` — poll-based subscriptions for balances, blocks, gas,
  and events with `live` tails and rotated history archives.
- `tools/` — pure helpers (`keccak`, `selector`, `address/checksum`,
  `sha256`, `blake3`, `hex`, `base64`, `unit/{parse,format}`, `abi`,
  `rlp`, `eip712`).
- `prices/{spot,change_24h}/<coin>` — DefiLlama keyless price oracle.
- `addressbook/<alias>` — local petname directory.
- `ens/<name>.eth` — ENS forward resolution as a read surface.
- `petals/<name>/` — installed local petal app surfaces.
- `requests/` — free and paid HTTP requests. Paid HTTP 402 challenges are
  staged under `pending/`, exposed as `plan.md`, and only signed after a
  confirm write.
- `polymarket/` — Polymarket market/account reads, onboarding, trade draft
  review, and pUSD funding request staging. Funding requests can be executed
  through foreground `bloom vfs write --unlock-wallet`; trade drafts can be
  posted the same way at `/polymarket/trade/<wallet>/drafts/<id>/confirm`.
- `status/` — daemon health, chain probes, audit head/count, cache
  counts, policy flags, wallet/outbox counts, and backend declarations.
- `docs/` — in-tree help, vendored from `crates/bloom-vfs/src/docs/`.

Config-gated surfaces may add more entries. For example,
`defi/intents/<wallet>/` appears when Enso is configured: write a
natural-language intent, inspect `plan.md`, then confirm to stage into
the wallet outbox.

See [QUICKSTART.md](./QUICKSTART.md) for an Anvil-backed walkthrough
and [docs/AUDIT.md](./docs/AUDIT.md) for the per-surface implementation
map and live-network verification log. See
[docs/parity/VFS_CLI_PARITY_LEDGER.md](./docs/parity/VFS_CLI_PARITY_LEDGER.md)
for the current VFS/CLI workflow parity matrix.

## Architecture

Bloom is a Rust Cargo workspace. The main user-facing/runtime crates are:

| Crate | Responsibility |
|-------|----------------|
| `bloom` | CLI binary; thin client plus in-process daemon driver. |
| `bloom-daemon` | Wires home dir, config, chains, keystore, VFS, IPC, ENS, watches, and optional feature adapters. |
| `bloom-vfs` | Path router, handler trait, per-path caching, and vendored docs. |
| `bloom-evm` / `bloom-rpc` | RPC pools, per-chain engines, chain reads, and provider health. |
| `bloom-tx` | Tx staging, simulation, signing, broadcast, nonce management, and policy enforcement. |
| `bloom-keystore` | Encrypted local key storage and signer integration. |
| `bloom-mempool` | Optional pending-transaction indexing for configured WebSocket providers. |
| `bloom-defi` | Enso Shortcuts client and natural-language DeFi intent support. |
| `bloom-watch` | Subscription registry and polling executor. |
| `bloom-mount` | NFSv4 mount adapter behind the `mount` feature. |
| `bloom-tools` | Pure crypto/encoding helpers. |
| `bloom-etherscan` | Etherscan multichain client and on-disk TTL cache. |
| `bloom-ens` | ENS namehash plus forward/reverse/text/contenthash resolution. |
| `bloom-prices` | DefiLlama keyless price oracle. |
| `bloom-proto` | Shared config, audit, address book, intent, policy, plan, path, and unit types. |

The workspace also includes protocol, chain-node, petal, macro, test,
and example crates used by the broader Bloom runtime and examples.

## Security defaults

- **Mainnet broadcasts disabled by default.** Set
  `block_mainnet_broadcast = false` plus a per-chain `allow_broadcast =
  true` in `~/.bloom/config.toml` to opt a chain into broadcasting.
- **Private keys are never readable through the FS.** The keystore
  lives outside the mount; only `address` and `public_key` are
  exposed.
- **Encrypted at rest.** Local keys use argon2id KDF plus
  chacha20poly1305 envelopes.
- **Hash-chained audit log.** Every write and side-effecting read is
  appended to `<home>/audit.jsonl`; read the head digest at
  `status/audit/head`.
- **Stage-confirm write flow.** A staged tx becomes a transaction only
  when a non-empty confirm file is written.
- **Policy enforcement before signing.** Per-wallet `policy.toml`
  enforces caps, recipient allow/deny lists, contract-call gates,
  private orderflow settings, and automation thresholds.
- **Passkey policy review is plain-language first.** `bloom wallet
  sign-policy <wallet>` opens a local review page where the user chooses
  whether Bloom must ask before every money-moving action or may act later
  only when the action passes the signed policy. Technical hashes and raw
  policy TOML stay behind advanced details.
- **Private orderflow is opt-in and fail-closed.** On unsupported
  chains, private broadcast returns an error instead of silently falling
  back to public RPC.

## Limitations

- **Single-user daemon.** No daemon-level auth or multi-tenant
  isolation; the mount inherits the OS user's permissions on
  `~/.bloom`.
- **Mainnet broadcast requires two opt-ins.** A live tx requires both
  the global `block_mainnet_broadcast = false` and a per-chain
  `allow_broadcast = true`. Forgetting the second is the most common
  cause of "stage works, confirm 403s".
- **Embedded indexer deferred.** Address activity, ERC-20 / ERC-721
  history, and contract source / ABI are served via Etherscan; no
  local block-by-block index yet. The selected backend is visible under
  `status/backends/`.
- **Mempool support is provider-gated.** Alchemy pending-transaction
  feeds are wired at daemon startup. The generic `eth_subscribe` path
  exists in `bloom-mempool` but is not enabled by default until tx-body
  enrichment is complete.
- **Watch executor is poll-based.** `bloom-evm` is HTTP-first, so the
  executor polls on an interval rather than using a WebSocket fast path.
- **NFT support has sharp edges.** Reads cover holder and collection
  views; writes flow through wallet outbox intents. ERC-1155 per-token
  approval is rejected clearly; mints use generic contract-call intents.
- **Hardware wallets, smart accounts (4337), and distributed sync**
  remain stretch goals.

## License

Licensed under the MIT License. See [LICENSE](./LICENSE).
