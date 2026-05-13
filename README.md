# bloom

`bloom` (binary: `bloom`) presents Ethereum and EVM L2s as a virtual
filesystem: reads are blockchain queries, writes are transaction intents,
and `tail -f` is a live event stream. A single Rust daemon owns the
plumbing — RPC, signing, broadcast, caching — and exposes it as POSIX
paths so an agent can drive onchain workflows with `cat`, `ls`, and
`echo` instead of a Web3 SDK.

**Status:** v1 functional. Long-running daemon (`bloom serve`) with a UDS
JSON-RPC IPC, in-process VFS, and an optional NFSv4 mount adapter. Live
verified end-to-end on Base mainnet (`tests/docker/run.sh --enso-live`).

## Architecture

The workspace is split into 15 crates:

| Crate | Responsibility |
|-------|----------------|
| `bloom` | CLI binary; thin client + driver of the in-process daemon. |
| `bloom-daemon` | Wires the daemon: home dir, config, chains, keystore, VFS, IPC, ENS adapter, watch executor. |
| `bloom-vfs` | Path router, handler trait, per-path caching, vendored docs, 11 handler modules. |
| `bloom-chain` | RPC pool and per-chain engine (head, blocks, addresses, ERC-20). |
| `bloom-tx` | Tx engine: stage, simulate, sign, broadcast, nonce manager, policy enforcement. |
| `bloom-keystore` | Encrypted local key storage (argon2id + chacha20poly1305) and signer. |
| `bloom-defi` | Enso Shortcuts client + natural-language intent parser. |
| `bloom-watch` | Subscription registry + polling executor task with rotated event logs. |
| `bloom-mount` | NFSv4 mount adapter (feature `mount`). |
| `bloom-tools` | Pure helpers: keccak / sha256 / blake3 / hex / base64 / ABI / RLP / EIP-712 hash. |
| `bloom-etherscan` | Etherscan v2 multichain client + on-disk TTL cache. |
| `bloom-ens` | ENS namehash + forward / reverse / text / contenthash resolution. |
| `bloom-prices` | DefiLlama keyless price oracle. |
| `bloom-proto` | Shared types: paths, configs (`Config`/`BackendsConfig`), audit records, address book, intents, policy, plan, units. |
| `bloom-it` | Integration-test harness crate. |

See `docs/specs/2026-05-08-bloom-design.md` for the full design and
`docs/AUDIT.md` for the per-section spec-to-artifact map.

## Build and run

```sh
cargo build --workspace
cargo test --workspace --lib
cargo run -p bloom -- status
```

Two ways to drive the VFS:

- **One-shot CLI** — every `bloom vfs cat|ls|write` invocation builds the
  in-process daemon, performs the op, and exits. No socket needed.
- **Long-running daemon** — `bloom serve` listens on a UDS JSON-RPC
  socket at `~/.bloom/run/bloom.sock`. Subsequent `bloom vfs` calls
  detect the socket and route through it, sharing daemon state (unlock
  cache, watches, defi sessions, etherscan cache). `bloom ipc call <method>`
  speaks the JSON-RPC directly.
- **NFS mount** (optional) — build with `cargo build -p bloom --features mount`
  or use a full-feature release binary, then run `bloom serve --mount [PATH]`
  to expose the VFS as a real POSIX filesystem over the kernel NFS client.
  With no path, the mount point defaults to `/bloom` on Linux and
  `/Volumes/bloom` on macOS. The mount point must already exist and the
  platform mount command may require elevated privileges.

## Filesystem layout

The VFS is rooted at the selected mount path (for example `/bloom/` on
Linux or `/Volumes/bloom/` on macOS) with these top-level trees:

- `chains/<chain>/` — read-only chain views: head, blocks, addresses,
  ERC-20 balances, txs, receipts, gas, etherscan-backed history. The
  contract surface lives under `chains/<c>/contracts/<a>/`:
  - `source`, `abi` — verified Etherscan source / ABI (cached 7 days).
  - `methods/<name>.{read,tx,sig}` — ABI-driven calldata. `.read`
    encodes args, runs `eth_call`, and decodes the return value;
    `.tx` returns `{to, selector, calldata}` without broadcasting
    (pipe into the wallet outbox to send); `.sig` is the canonical
    Solidity signature plus selector. `.read` and `.tx` accept a
    JSON body `{"args":[…], "selector"?, "block"?, "from"?}` — pass
    `selector` to disambiguate overloads.
  - `events/<name>/{recent,query,live}` — ABI-decoded `eth_getLogs`.
    `recent` returns the last ~200 logs over the last ~10_000 blocks;
    `query` accepts `{from_block?, to_block?, topics?, where?}` for
    custom filters; `live` is a long-poll tail with a per-handler
    cursor.
  - `storage/<slot>` — raw `eth_getStorageAt` (slot is decimal or
    `0x`-hex).
  - `proxy/{implementation,admin,beacon}` — well-known EIP-1967 /
    EIP-1822 slot reads, returning a checksummed address or
    `not a proxy\n` when the slot is empty.
- `wallets/<name>/` — managed wallets, per-chain balances/nonce, the
  `outbox/` write surface, and `sign/{message,hash,typed_data}` for
  EIP-191 / raw / EIP-712 signatures.
- `defi/intents/<wallet>/` — Enso shortcuts: write a natural-language
  intent, read the routed `plan.md`, then `confirm` to stage into the
  wallet outbox. ERC-20 token-in routes auto-prepend an
  `approve(spender, max)` intent when the current allowance is
  insufficient. Default slippage is 50 bps (overridable per-request).
- `watch/<id>/` — subscriptions; tail `live` for the in-process state
  or read rotated `history.jsonl[.n]` archives. Kinds: `balance`,
  `block`, `gas_price`, `event`. Live files rotate at 1 MiB.
- `simulate/<session>/` — `eth_call` + state-override sandbox; no
  signing, no broadcast.
- `tools/` — pure helpers (`keccak`, `selector`, `address/checksum`,
  `sha256`, `blake3`, `hex`, `base64`, `unit/{parse,format}`, `abi`,
  `rlp`, `eip712`).
- `prices/{spot,change_24h}/<coin>` — DefiLlama keyless price oracle.
- `addressbook/<alias>` — local petname directory.
- `ens/<name>.eth` — ENS forward resolution as a read surface.
- `status/` — daemon health, chain probes, audit head/count, cache
  counts, policy flags, wallet/outbox counts, and the live
  `status/backends/<feature>` declaration of which data source
  (etherscan / rpc / indexer) each surface is wired to.
- `docs/` — in-tree help, vendored from `crates/bloom-vfs/src/docs/`.

See [QUICKSTART.md](./QUICKSTART.md) for an Anvil-backed walkthrough
and [docs/AUDIT.md](./docs/AUDIT.md) for the per-surface implementation
map and live-network verification log.

## Security defaults

- **Mainnet broadcasts disabled by default.** Set
  `block_mainnet_broadcast = false` plus a per-chain `allow_broadcast =
  true` in `~/.bloom/config.toml` to opt a chain into broadcasting.
- **Private keys are never readable through the FS.** The keystore
  lives outside the mount; only `address` and `public_key` are
  exposed.
- **Encrypted at rest** — argon2id KDF + chacha20poly1305 per-key
  envelope.
- **Hash-chained audit log** at `<home>/audit.jsonl`. Every write and
  side-effecting read is appended through the VFS router; entries
  reference the prior hash so tampering is detectable. Read the head
  digest at `status/audit/head`.
- **Stage-confirm is the only write mode.** A staged tx becomes a
  transaction only when a non-empty confirm file is written.
- **Policy enforcement** runs before signing — per-wallet
  `policy.toml` enforces caps (max ETH per tx, per-tx USD,
  rolling-24h USD totals priced via DefiLlama), recipient allow /
  deny lists, contract-call gating, and an automation surface
  (`auto_confirm_below_eth`, configurable override sentinel).

## Limitations

- **Single-user daemon.** No daemon-level auth or multi-tenant
  isolation; the mount inherits the OS user's permissions on
  `~/.bloom`. Multi-user mode is a stretch goal in the spec.
- **Mainnet broadcast disabled by default.** A live tx requires both
  the global `block_mainnet_broadcast = false` (config default already
  blocks mainnet) and a per-chain `allow_broadcast = true`. Forgetting
  to flip the second is the most common cause of "stage works,
  confirm 403s".
- **Embedded indexer deferred.** Address activity, ERC-20 / ERC-721
  history, and contract source / ABI are served via Etherscan v2; no
  local block-by-block index. The boundary between Etherscan-backed
  and RPC-backed surfaces is declared explicitly in `config.toml`
  under `[backends]` (one of `etherscan`, `rpc`, `indexer`):
  - `contract_metadata` — `chains/<c>/contracts/<a>/{source,abi,...}`
    (default `etherscan`).
  - `address_history` — `chains/<c>/addresses/<a>/{txs,internal_txs,
    erc20_txs,erc721_txs}` (default `etherscan`).
  - `event_logs` — `chains/<c>/contracts/<a>/events/...`
    (default `rpc`).
  - `storage_reads` — `chains/<c>/contracts/<a>/storage/<slot>`
    (default `rpc`).
  - `proxy_detection` — `chains/<c>/contracts/<a>/proxy/...`
    (default `rpc`).

  `indexer` is reserved for the future embedded indexer; selecting it
  today returns a clear "not yet implemented" error. The live config
  is readable at `status/backends/<feature>` and
  `status/backends/summary.json`.
- **Mempool surface not implemented.** The spec's `chains/<c>/mempool/`
  tree is not wired up — it depends on provider-specific APIs
  (Alchemy / Blocknative).
- **Watch executor is poll-based.** `bloom-chain` is HTTP-only, so the
  executor polls every 2s. No websocket fast path yet; per-spec
  latency is bounded by the tick interval.
- **NFT surface ships in both directions.** Reads:
  `chains/<c>/addresses/<a>/nfts/` (per-holder transfer history,
  best-effort `owned.json`, and per-token
  `owner / uri / metadata.json / balance / is_owner / approved`
  under `<contract>/<token_id>/`) and `chains/<c>/contracts/<a>/nft/`
  (collection `kind / name / symbol / total_supply`, `owner_of/<id>`,
  `token_uri/<id>`, `is_approved_for_all/<o>/<op>`). ERC-721 vs
  ERC-1155 is auto-detected via ERC-165 with the ERC-1155 `{id}`
  placeholder substituted for `uri` reads. Writes flow through the
  wallet outbox via three intent kinds — `nft_transfer` (encodes
  `safeTransferFrom` / `transferFrom`, ERC-721 + ERC-1155, optional
  `safe`/`amount`/`data`), `nft_approve` (per-token, ERC-721 only —
  ERC-1155 is rejected with a clear error), and `nft_approve_all`
  (`setApprovalForAll`, policy-warned because it grants operator-wide
  control). Mints are issued via the generic `call` intent against
  the contract's mint method.
- **Hardware wallets, smart accounts (4337), and distributed sync**
  remain stretch goals.

## License

Licensed under the MIT License. See [LICENSE](./LICENSE).
