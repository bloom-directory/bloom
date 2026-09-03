<p align="center">
  <a href="https://bloom.directory">
    <img src="docs/assets/bloom-wordmark.png" alt="Bloom">
  </a>
</p>

<p align="center">
  <a href="https://github.com/bloom-directory/bloom/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/bloom-directory/bloom/ci.yml?branch=master&style=flat-square&label=ci"></a>
  <a href="https://github.com/bloom-directory/bloom/releases"><img alt="Release" src="https://img.shields.io/github/v/release/bloom-directory/bloom?include_prereleases&style=flat-square"></a>
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-141310?style=flat-square"></a>
  <img alt="Rust 1.94+" src="https://img.shields.io/badge/rust-1.94%2B-a8324c?style=flat-square">
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
- stage native ETH, ERC-20, NFT, contract-call, signing, and installed-Petal
  DeFi intents by writing plain-language or structured files;
- stage free or paid HTTP requests through `/requests`, including HTTP
  402 payment flows that are reviewed before x402 or Tempo MPP credentials
  are signed;
- inspect a generated `plan.md` before anything is signed;
- confirm a staged transaction only after user approval;
- enforce policy: spend caps, allow/deny lists, contract-call gates,
  private orderflow settings, and hash-chained audit logging.
- request [private, advisory intent reviews](docs/coordination.md) from explicitly
  enrolled Bloom peers over Iroh, evaluated by locally pinned zero-authority Petals.

Bloom ships read-ready RPC defaults for major EVM networks — Ethereum,
Base, Tempo, Robinhood Chain, Arbitrum, Optimism, Polygon, BNB Smart Chain,
Avalanche, Gnosis, Linea, and HyperEVM — plus local Anvil. Per-chain
broadcasting is enabled by default; set `allow_broadcast = false` on a chain to
disable it.
Public reads, simulations, and planning work without adding API keys;
local devnet sends require a running Anvil node.

## Try it

Mount Bloom first, then interact with it like a directory:

```sh
cargo build -p bloom
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
cargo test -p bloom
cargo test --workspace --lib
cargo build -p bloom
```

## Filesystem layout

A fresh Bloom VFS root exposes these default entries:

- `AGENTS.md`, `CLAUDE.md` — agent-facing setup and operating guidance.
- `chains/<chain>/` — read-only chain views: head, blocks, gas,
  addresses, ERC-20 balances, NFTs, txs, receipts, contract metadata,
  ABI methods/events/storage/proxy reads, and optional mempool views
  when a WebSocket mempool provider is configured.
- `wallets/<name>/` — Broker-projected wallets, per-chain balances/nonce,
  canonical policy custody, and `outbox/` staging/confirmation. Legacy raw
  signing leaves fail closed; transactions and Petals use payload-bearing
  Broker signing routes.
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
- `petals/` — installed local Petal app surfaces. `bloom init` provisions the
  pinned Near Intents and
  [Enso](https://github.com/bloom-directory/bloom-petal-enso) packages;
  unreleased migrated venue Petals are installed explicitly.
  Read `docs/petals.md` in the VFS for the exact installed set, mount
  directories, summaries, and declared capabilities.
- `requests/` — free and paid HTTP requests. Paid HTTP 402 challenges are
  staged under `pending/`, exposed as `plan.md`, and only signed after a
  confirm write.
- `status/` — daemon health, chain probes, audit head/count, cache
  counts, policy flags, wallet/outbox counts, and backend declarations.
- `docs/` — in-tree help, vendored from `crates/bloom-vfs/src/docs/`.

Application-specific surfaces live under `petals/`, not in Bloom core. For
example, the Enso Petal accepts swap intents at
`petals/enso/intents/<wallet>/new`, exposes a reviewable `plan.md`, and stages
confirmed transactions into the standard wallet outbox.

See [QUICKSTART.md](./QUICKSTART.md) for an Anvil-backed walkthrough.
[docs/AUDIT.md](./docs/AUDIT.md) preserves the dated 2026-05-09
implementation map and live-network verification log. The
[VFS/CLI parity ledger](./docs/parity/VFS_CLI_PARITY_LEDGER.md) is retained as
a dated historical snapshot, not as current product documentation.

## Architecture

Bloom is a Rust Cargo workspace. The main user-facing/runtime crates are:

| Crate | Responsibility |
|-------|----------------|
| `bloom` | Machine CLI/runtime; reads, stages, simulates, and delegates every authority operation to Broker. |
| `bloom-daemon` | Wires key-free public projections, config, chains, VFS, IPC, ENS, watches, and execution adapters. |
| `bloom-machine-client` | Authenticated Machine-to-Broker client and rollback-safe public projection cache. |
| [`bloom-service-runtime`](https://github.com/bloom-directory/bloom-service-runtime) (external) | Independently auditable RPC wire, local transport, activation, audit-checkpoint, and trusted-time substrate. |
| `bloom-vfs` | Path router, handler trait, per-path caching, and vendored docs. |
| `bloom-evm` / `bloom-rpc` | RPC pools, per-chain engines, chain reads, and provider health. |
| `bloom-tx` | Unsigned transaction staging, simulation, Broker signing orchestration, broadcast, and nonce management. |
| `bloom-mempool` | Optional pending-transaction indexing for configured WebSocket providers. |
| `bloom-watch` | Subscription registry and polling executor. |
| `bloom-mount` | NFSv4 adapter that mounts Bloom's VFS as an ordinary filesystem. |
| `bloom-tools` | Pure crypto/encoding helpers. |
| `bloom-etherscan` | Etherscan multichain client and on-disk TTL cache. |
| `bloom-ens` | ENS namehash plus forward/reverse/text/contenthash resolution. |
| `bloom-prices` | DefiLlama keyless price oracle. |
| `bloom-proto` | Shared config, audit, address book, intent, policy, plan, path, and unit types. |

The workspace also includes protocol, chain-node, petal, macro, test,
and example crates used by the broader Bloom runtime and examples.

## Security defaults

- **Broadcast routing enabled by default.** Per-chain `allow_broadcast`
  defaults to `true`. Signing, policy, confirmation, and Sealed Approval
  gates still apply.
- **Machine contains no wallet keys.** Custody and signing cross Machine's
  authenticated Broker edge; Signer alone owns private keys and delegated
  Petal sub-keys. The mount exposes only public projections and signatures
  needed for execution.
- **Hash-chained audit log.** Every write and side-effecting read is
  appended to `<home>/audit.jsonl`; read the head digest at
  `status/audit/head`.
- **Stage-confirm write flow.** A staged tx becomes a transaction only
  when a non-empty confirm file is written.
- **Policy custody before signing.** The writable `policy.json` surface uses
  Broker `policy.validate_update`, a Signer-completed `policy_update` custody
  ceremony, and receipt-only `policy.commit_update`.
- **Private orderflow is opt-in and fail-closed.** On unsupported
  chains, private broadcast returns an error instead of silently falling
  back to public RPC.

## Limitations

- **Per-login Machine surface.** Production Broker and Signer run as isolated
  service principals and authenticate local RPC peers. The mounted Machine
  surface remains scoped to its enrolled login.
- **Broadcast config is not an approval boundary.** Set a chain's
  `allow_broadcast = false` to disable broadcast on that chain. Value-moving
  actions still pass Bloom's signing, policy, and confirmation controls.
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
