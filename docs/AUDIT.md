# bloom full-spec audit

**Audit date:** 2026-05-09
**Spec audited:** `docs/specs/2026-05-08-bloom-design.md`
**Workspace:** 15 crates · `cargo build --workspace` clean ·
`cargo clippy --workspace --all-targets -- -D warnings` clean.
**Acceptance:** `scripts/acceptance.sh` passes scenarios 1 (native
send) + 2 (ERC-20 transfer) end-to-end against Anvil. Scenarios 3 + 4
(Uniswap V2 + Enso on a mainnet fork) auto-skip without
`BLOOM_MAINNET_RPC`.
**Live:** `tests/docker/run.sh --enso-live` exercises Enso + Aave on
Base mainnet through the mounted filesystem surface.

This document is the prompt-to-artifact checklist required by the
goal's quality gates. Statuses below: **shipped**, **partial**, or
**deferred** — partial entries note what's missing.

## §9 — Audit log wiring (router)

Every successful VFS write and every successful side-effecting read
appends a hash-chained record (`crates/bloom-proto/src/audit.rs`,
`AuditLog::append`). Wiring lives in `crates/bloom-vfs/src/router.rs`
and is constructed by `crates/bloom-daemon/src/lib.rs::Daemon::from_home`.

Record schema (`AuditRecord.kind` + `AuditRecord.data`):

| `kind`       | When                              | `data` shape                                                                |
|--------------|-----------------------------------|-----------------------------------------------------------------------------|
| `vfs.write`  | After any successful write/delete | `{ "path": "/<full path>", "actor": "local", "details": { "sha256": "<hex>", "size": <bytes> } }` |
| `vfs.read`   | After a successful read whose handler returned `is_read_side_effecting=true` | `{ "path": "/<full path>", "actor": "local", "details": {} }` |

Failed operations are NOT recorded — we err on the side of fewer
entries to keep the chain useful for verification. The `actor` field
is currently a placeholder (`"local"`) until the IPC / NFS transports
plumb authenticated identity through.

## §10 — Router-level cache

Reads are cached at the router layer when the dispatched handler
returns `Some(ttl)` from `Handler::cache_ttl`. The cache is an LRU
bounded at 4096 entries (`crates/bloom-vfs/src/cache.rs::PathCache`).
Writes invalidate the exact path *and* every cached entry under the
same top-level prefix (handler-mount segment).

Default TTLs (handler overrides):

| Handler | Path | TTL |
|---|---|---|
| chains | `chains/<c>/chain_id` | 1 day |
| chains | `chains/<c>/head/*` | 1s |
| chains | `chains/<c>/gas/*` | 2s |
| chains | `chains/<c>/tx/<hash>/*` | 60s |
| chains | `chains/<c>/addresses/<a>/{balance,balance.eth,balance.raw,nonce}` | 5s |
| chains | `chains/<c>/addresses/<a>/{code,is_contract}` | 1 day |
| chains | `chains/<c>/addresses/<a>/{txs,internal_txs,erc20_txs,erc721_txs}` | 30s |
| chains | `chains/<c>/contracts/<a>/{source,abi}` | 7 days |
| chains | `chains/<c>/blocks/<n>/*` | 5 min |
| status | `status/chains/...` | 5s |
| status | `status/{cache,wallets,outbox}/*` | 5s |
| status | `status/{version,started_at,home}` | 1 day |
| prices | `prices/...` | 30s |

Other handlers default to no router cache (they either compute pure
data or rely on their own internal caches, e.g. the etherscan client).

## §3 — VFS surfaces

| Surface | VFS path(s) | Status | Implementation / Tests |
|---|---|---|---|
| Chains: head/safe/finalized, gas, fee history, eth_call, receipts, tx lookups, logs | `chains/<chain>/...` | shipped | `crates/bloom-vfs/src/handlers/chains.rs` + `chains_history.rs` |
| ERC-20 reads (balance / symbol / decimals) | `chains/<chain>/addresses/<a>/tokens/<token>/{balance,balance.raw,balance.formatted,symbol,decimals}` | shipped | `chains.rs` + `crates/bloom-chain/src/lib.rs::ChainClient::erc20_*` |
| Tx lookups | `chains/<chain>/tx/<hash>/{receipt.json,status,block_number,gas_used,logs.json,full.json}` | shipped | `chains.rs` (eth_getTransactionByHash + receipt) |
| Etherscan history (txs, internal, ERC-20, ERC-721, source, abi) | `chains/<chain>/addresses/<a>/{txs,internal_txs,erc20_txs,erc721_txs}` and `chains/<chain>/contracts/<a>/{source,abi}` | shipped | `chains_history.rs` + `crates/bloom-etherscan/src/lib.rs` (TTL cache in `cache.rs`) |
| Wallets: VFS-driven creation (local / import / watch) | `wallets/new` (writable) | shipped | `wallets.rs::write_new_wallet` + `parse_new_wallet_spec` |
| Wallets: metadata, balance, nonce, policy round-trip | `wallets/<w>/{address,public_key,kind,policy.toml,chains/<c>/{balance,balance.eth,balance.raw,nonce}}` | shipped | `wallets.rs`; covered by outbox tests + `acceptance.sh` |
| Wallets: outbox stage / confirm | `wallets/<w>/chains/<c>/outbox/{new.tx,pending/<id>/{plan.md,policy_check.json,confirm},sent/<id>/*,failed/<id>/*}` | shipped | `wallets.rs::write_outbox` → `crates/bloom-tx/src/tx_engine.rs`. Intents: `send` (native + ERC-20), `approve`, `call`, `raw`, plus NFT writes — `nft_transfer` (auto-detects ERC-721 vs ERC-1155, optional `safe`/`amount`/`data`), `nft_approve` (per-token, ERC-721 only), `nft_approve_all` (`setApprovalForAll`, policy-warned). |
| Wallets: sign — EIP-191 + raw hash + EIP-712 | `wallets/<w>/sign/{message,hash,typed_data}` (+ `.sig`) | shipped | `wallets.rs::write_sign` |
| DeFi (Enso intents, route quoting, stage-confirm) | `defi/intents/<wallet>/{new,<sess>/{intent.txt,route.json,plan.md,tx.json,simulation.json,confirm}}` | shipped | `crates/bloom-vfs/src/handlers/defi.rs` + `crates/bloom-defi/src/lib.rs` |
| Watch (subscriptions, executor task, events tail) | `watch/{new,<id>/{spec.toml,live,history.jsonl[.n],delete}}` | shipped | `crates/bloom-vfs/src/handlers/watch.rs` + `crates/bloom-watch/src/{lib.rs,executor.rs}`; executor started by `Daemon::from_home` |
| Simulate (eth_call + state override + best-effort trace) | `simulate/{new,last,<id>/{intent.json,state-override.json,simulation.json,plan.md,trace.json}}` | shipped | `crates/bloom-vfs/src/handlers/simulate.rs` |
| Tools (keccak, selector, address checksum, sha256, blake3, hex, base64, units, ABI encode/decode, RLP, EIP-712 hash) | `tools/{keccak,selector,address/checksum,sha256,blake3,hex,base64,unit/{parse,format},abi,rlp,eip712}/...` | shipped | `crates/bloom-vfs/src/handlers/tools.rs` + `crates/bloom-tools/src/lib.rs` (units helpers come from `crates/bloom-proto/src/units.rs`). |
| Status / diagnostics | `status/{version,uptime,started_at,home,daemon.json,chains/<c>/{connected,block_number,rpc_url},audit/{head,count,last},cache/{etherscan,prices}_entries,policies/block_mainnet_broadcast,wallets/count,outbox/pending_count}` | shipped | `crates/bloom-vfs/src/handlers/status.rs` |
| Docs (embedded examples for each surface) | `docs/...` | shipped | `crates/bloom-vfs/src/handlers/docs.rs` + `crates/bloom-vfs/src/docs/` |
| Address book (petname round-trip) | `addressbook/{<alias>,new}` | shipped | `crates/bloom-vfs/src/handlers/addressbook.rs` + `crates/bloom-proto/src/address.rs` |
| Prices (DefiLlama, keyless) | `prices/{spot/<coin>(.usd),change_24h/<coin>}` | shipped | `crates/bloom-vfs/src/handlers/prices.rs` + `crates/bloom-prices/src/lib.rs` |
| ENS forward resolution surface | `ens/<name>.eth` | shipped | ENS handler (forward resolve via `crates/bloom-ens` against the canonical mainnet registry) |
| NFTs (`addresses/<a>/nfts/...`, `contracts/<a>/nft/...`) | — | shipped | `crates/bloom-vfs/src/handlers/chains_nfts.rs` + chains.rs routing. Per-holder views (`erc721_txs`, `erc1155_txs`, `owned.json`, per-token `owner/uri/metadata.json/balance/is_owner/approved`) and collection views (`kind`, `name`, `symbol`, `total_supply`, `owner_of/<id>`, `token_uri/<id>`, `is_approved_for_all/<o>/<op>`). ERC-721 vs ERC-1155 auto-detected via ERC-165 (cached). ERC-1155 `{id}` placeholder substitution applied; metadata.json supports `data:`, `ipfs://`, `http(s)://`. ChainClient NFT helpers in `crates/bloom-chain/src/lib.rs`; ERC-1155 transfer history via `crates/bloom-etherscan/src/lib.rs::get_nft1155_tx`. Writes (transfers / per-token approve / set-approval-for-all) flow through the wallet outbox — see the wallets row. |
| Mempool (`chains/<c>/mempool/...`) | — | deferred | Spec §3.2 surface; depends on provider-specific APIs. |
| Contract methods / events / storage / proxy subtrees | `chains/<c>/contracts/<a>/{methods,events,storage,proxy}/...` | shipped | `crates/bloom-vfs/src/handlers/chains_contracts.rs` — ABI-driven `methods/<m>.{read,tx,sig}` (writable JSON body, eth_call + decode, no broadcast), `events/<e>/{recent,query,live}` (eth_getLogs + alloy log decoding, per-(chain,addr,event) live cursor), `storage/<slot>` and `proxy/{implementation,admin,beacon}` (EIP-1967 + EIP-1822). Methods/events gated behind `contract_metadata = etherscan` (ABI source); storage/proxy stay RPC-only. ABI cache TTL 60s. |

## §4 — Daemon

| Requirement | Status | Artifact |
|---|---|---|
| Long-running daemon (`bloom serve`) | shipped | `crates/bloom/src/main.rs::Cmd::Serve` → `IpcServer::serve` |
| Persistent unlock cache (in-memory) | shipped | `crates/bloom-keystore/src/lib.rs::Keystore::unlock` (process-scoped; no on-disk persistence) |
| Watch executor in daemon | shipped | `crates/bloom-watch/src/executor.rs::WatchExecutor`, instantiated and started by `crates/bloom-daemon/src/lib.rs::Daemon::from_home` |
| UDS JSON-RPC IPC (`lookup`, `read`, `write`, `list`, `version`, `chains`, `shutdown`) | shipped | `crates/bloom-daemon/src/ipc.rs`; CLI surface via `Cmd::Ipc(IpcCmd::Call)` |
| VFS auto-routes through socket when present | shipped | `crates/bloom/src/main.rs` checks `default_socket_path` for `Vfs::{Cat,Ls,Write}` |
| Audit log wired into the router | shipped | `AuditLog` opened by `Daemon::from_home`; VFS router appends a hash-chained record on every write and on side-effecting reads. Read head/count/last via `status/audit/...`. |
| Per-path TTL cache exposed via status | shipped | `status/cache/{etherscan,prices}_entries` (`crates/bloom-vfs/src/handlers/status.rs`) |
| Optional NFS mount adapter | shipped (feature-gated) | `crates/bloom-mount/src/{lib.rs,adapter.rs,server.rs}` behind `mount`; re-exported via `bloom-daemon/Cargo.toml` `mount = ["bloom-mount/mount"]`. `Daemon::mount(path).await` delegates to `bloom_mount::serve_nfs` and returns an `NfsMountHandle`. The adapter buffers out-of-order NFS WRITE chunks (8 MiB cap), refreshes the directory `change` attribute on every getattr (out-of-band entries become visible without remount), and the handle's `Drop` issues a best-effort `umount -l -f` if `unmount()` was not called. |

## §5–§6 — Indexing, ENS, token metadata

| Requirement | Status | Artifact |
|---|---|---|
| Etherscan v2 multichain client + on-disk cache | shipped | `crates/bloom-etherscan/src/{lib.rs,cache.rs}` |
| Embedded indexer | deferred | Activity / history served via Etherscan; no local block index. The Etherscan↔RPC boundary is now explicit per-feature via `[backends]` in `Config` (`crates/bloom-proto/src/config.rs::BackendsConfig`); selecting `indexer` returns a clear "not yet implemented" error. Live config readable at `status/backends/<feature>` and `status/backends/summary.json`. |
| Per-feature backend declaration (etherscan / rpc / indexer) | shipped | `crates/bloom-proto/src/config.rs::BackendsConfig`; gating in `crates/bloom-vfs/src/handlers/chains.rs::ChainsHandler::require_etherscan_backend`; surface in `crates/bloom-vfs/src/handlers/status.rs` (`status/backends/...`). |
| ENS forward + reverse resolution | shipped | `crates/bloom-ens/src/lib.rs::EnsClient::{resolve,reverse,text,content_hash}` |
| ENS plumbed into tx engine recipient resolution | shipped | `crates/bloom-tx/src/tx_engine.rs::RecipientResolver` + `crates/bloom-daemon/src/ens_resolver.rs::EnsAdapter` |
| ENS as a VFS surface | shipped | `ens/<name>.eth` read returns the resolved address. |
| Token metadata + ERC-20 transfer encoding in send path | shipped | `crates/bloom-tx/src/tx_engine.rs` (`RawIntent.token` triggers ERC-20 transfer encoding); `acceptance.sh` scenario 2 |

## §7 — Tx engine

| Requirement | Status | Artifact |
|---|---|---|
| Native ETH sends | shipped | `tx_engine.rs`; `acceptance.sh` scenario 1; live verified on Base. |
| ERC-20 sends | shipped | `tx_engine.rs` (`RawIntent.token` branch); `acceptance.sh` scenario 2; live verified via Enso roundtrip. |
| Direct contract `call` intents | shipped | `RawIntent::call` (method + args); covered by tx-engine tests and mount-driven transaction flows. |
| EIP-1559 + legacy fallback per chain spec | shipped | `crates/bloom-proto/src/chain.rs::ChainSpec.legacy_tx`; `tx_engine.rs` branches accordingly. |
| Replacement / cancel | shipped | `tx_engine.rs::replace_with_intent` substitutes (to/value/data) from the posted body and bumps fees ≥10%; cancel is a same-nonce self-send. |
| Per-wallet `policy.toml` enforcement | shipped | `crates/bloom-tx/src/policy_engine.rs` — per-tx + rolling 24h USD caps backed by `Outbox::sum_usd_since`, allow/deny lists, contract-call gating; results land at `pending/<id>/policy_check.json`. |
| USD-priced policy caps via DefiLlama | shipped | `bloom-tx/src/oracle.rs` (`PriceOracle` trait) wired to `bloom-daemon/src/price_oracle.rs::PricesOracle` over `bloom-prices`. |
| Reverse ENS at `chains/<chain>/addresses/<addr>/ens` | shipped | `bloom-vfs/src/handlers/chains.rs` (`with_ens` builder); cross-checked by `EnsClient::reverse`. |

## §10 — Security

| Requirement | Status | Artifact |
|---|---|---|
| `block_mainnet_broadcast` default-on | shipped | `Config::default()` (config.rs:100) sets it `true`; mainnet chain-id list checked at broadcast time. |
| Per-chain `allow_broadcast` opt-in | shipped | `ChainSpec.allow_broadcast`; daemon refuses to send when false. |
| Encrypted keystore (argon2id + chacha20poly1305) | shipped | `crates/bloom-keystore`. |
| Hash-chained audit log | shipped | `crates/bloom-proto/src/audit.rs::AuditLog`; wired into the VFS router. |
| Stage-confirm only write mode for txs | shipped | `tx_engine.rs::confirm` requires non-empty body. |
| Daemon-level multi-user auth | deferred | Single-user only; spec §6.4 marked stretch. |

## §11 — Tests, demo, quality gates

| Gate | Status |
|---|---|
| `cargo fmt` clean | passing |
| `cargo clippy --workspace --all-targets -- -D warnings` | passing |
| `cargo test --workspace --lib` | passing |
| Anvil-backed tests (RPC, no mocks) | passing — `simulate::tests::anvil_*`, `acceptance.sh` |
| Acceptance demo (native + ERC-20 on Anvil) | passing — `scripts/acceptance.sh` |
| Acceptance demo (Uniswap V2 + Enso on mainnet fork) | gated on `BLOOM_MAINNET_RPC`; auto-skips with a clear message. |
| Dockerized NFS kernel-mount test | harness at `tests/docker/{Dockerfile,docker-compose.yml,lib.sh,run.sh,test*.sh}`. Native suite `cargo test -p bloom-mount --features mount` passing. |
| Dockerized workspace tests | passing — `tests/docker/run.sh --workspace`. |
| Dockerized fork-mode end-to-end | passing — `tests/docker/run.sh --fork` (compose profile `fork`) drives a native send + chain reads through the mount against an anvil fork of Base; no Enso key needed. |
| Dockerized Enso/Aave on a fork | passing — `tests/docker/run.sh --enso` (compose profile `enso`) exercises the Enso → Aave flow against an anvil fork; gated on `BLOOM_ENSO_KEY`. |
| Live broadcast on Base mainnet | passing — `tests/docker/run.sh --enso-live` exercises Enso + Aave with real Base broadcasts. |

## Live-network verification (Base mainnet)

| Surface | Live target | Evidence |
|---|---|---|
| Base mainnet RPC | `https://mainnet.base.org` (chain_id 8453) | `vfs cat /chains/base/head/number` |
| Ethereum mainnet RPC | `https://ethereum-rpc.publicnode.com` | `vfs cat /chains/ethereum/head/number` |
| DefiLlama keyless price oracle | `coins.llama.fi` | `vfs cat /prices/spot/eth.usd` |
| Etherscan v2 multichain (txlist) | `api.etherscan.io/v2` chainid=1 | `vfs cat /chains/ethereum/addresses/0xd8dA…6045/txs` |
| ENS canonical-registry forward resolution | mainnet via tx-engine resolver | staged `send 0.0001 eth to vitalik.eth on ethereum` → `plan.md` shows `To: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045` |
| VFS-based wallet creation (round-trip) | local | `vfs write /wallets/new --data 'bob'` → `vfs cat /wallets/bob/address` |
| Native ETH send (live) | Base, chain_id 8453 | `0xd4a496fb…3c40` — 0.001 ETH dest1→dest2 |
| Enso swap (live) | Base, ETH → USDC via Enso router | `0x016fc370…9fc3` — 0.001 ETH → 2.306996 USDC |
| Enso swap + Aave V3 deposit (live) | Base, ETH → aBaseUSDC | `0xab687461…e3ce` — 0.001 ETH → 2.308456 aBaseUSDC |
| Aave V3 unwind | Base, aBaseUSDC → ETH via Enso route | exercised by `tests/docker/run.sh --enso-live` cleanup path. No Aave-specific code path: aToken→ETH goes through the same `EnsoClient::route` surface as any other swap; the auto-approve hop in `defi.rs` covers the aToken allowance. |

## Known limitations / deferred items

1. **NFT writes** — `nft_transfer` / `nft_approve` / `nft_approve_all`
   ship through the wallet outbox (ERC-721 + ERC-1155, ERC-165
   auto-detection, policy-warned operator approvals). `owned.json`
   remains best-effort (reduced from etherscan tx history, not
   authoritative — see the `caveat` field in the response). Mint
   intents are not modelled separately; mints are issued via the
   generic `call` intent against the contract's mint method.
2. **Mempool subtree** (`chains/<c>/mempool/...`) — not implemented;
   depends on provider-specific APIs.
3. **Embedded block indexer** — activity / history rely on Etherscan
   v2; without an `[etherscan]` config block, those paths return
   `NotFound`.
4. **Mainnet-fork acceptance scenarios.** `acceptance.sh` skips
   scenarios 3 + 4 unless `BLOOM_MAINNET_RPC` is set.
5. **Multi-user daemon auth** — single-user only.
6. **Hardware wallets, smart accounts (4337), distributed sync** —
   all spec stretch goals; not started.
7. **Live event tail cursor is per-handler-process, not per-client.**
   `events/<e>/live` reuses a single `(chain,addr,event)` cursor
   across readers; concurrent tails will race for "what's new since
   last read". Documented in
   `crates/bloom-vfs/src/handlers/chains_contracts.rs` under "Live tail
   caveat".

## Files map

```
crates/
├── bloom                # CLI (clap)
├── bloom-daemon         # Daemon orchestration + UDS IPC + ENS adapter + watch start
├── bloom-vfs            # Path router + 11 handler modules
├── bloom-chain          # alloy provider pool, ChainRegistry, ERC-20 reads
├── bloom-tx             # Tx engine, intent parser, policy_engine, RecipientResolver, PriceOracle, Outbox (rolling-USD)
├── bloom-keystore       # argon2id + chacha20poly1305 encrypted keystore
├── bloom-defi           # Enso shortcuts client + natural-language intent parser
├── bloom-watch          # Subscription registry + executor task + event log rotation
├── bloom-tools          # Pure crypto/abi/encoding utilities
├── bloom-etherscan      # Etherscan v2 client + TTL cache
├── bloom-ens            # ENS namehash + forward / reverse / text / contenthash
├── bloom-prices         # DefiLlama keyless price oracle
├── bloom-mount          # NFSv4 adapter (feature `mount`)
├── bloom-proto          # Shared types: AddressBook, AuditLog, Config, BackendsConfig, HomeDir, ChainSpec, RawIntent, Policy, StagedTx, units
└── bloom-it             # Integration-test harness
```

## Verification commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo build --release -p bloom
scripts/acceptance.sh                              # native + ERC-20 on Anvil
BLOOM_MAINNET_RPC=... scripts/acceptance.sh          # adds Uniswap V2 + Enso scenarios
tests/docker/run.sh                                 # NFS kernel-mount harness (default)
tests/docker/run.sh --workspace                     # workspace tests inside container
tests/docker/run.sh --fork                          # native send + chain reads via anvil-fork
tests/docker/run.sh --enso                          # Enso → Aave flow via anvil-fork (needs BLOOM_ENSO_KEY)
tests/docker/run.sh --enso-live                     # live Base broadcasts
```
