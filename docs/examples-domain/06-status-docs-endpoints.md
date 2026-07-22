# `status/`, `docs/`, and per-endpoint health — domain examples

The `status/` tree is the daemon's introspection layer: uptime and version, per-chain RPC reachability, the audit-log digest, cache and outbox counts, the active backend mapping, and a per-endpoint health snapshot for every configured RPC URL. The `docs/` tree is the daemon's vendored help (the same markdown checked into `crates/bloom-vfs/src/docs/`). The per-endpoint leaves under `status/chains/<chain>/endpoints/<idx>/` are the RPC-robustness fleet view added in WP-3 (commit `9f5eab6`): one directory per configured endpoint, populated by a 15 s active probe loop with EWMA latency, success-rate sampling, and a cooldown state machine. All examples below assume the VFS is mounted at `/bloom/`.

A point of caution on naming: leaves are exactly what the source advertises. There is no `status/chains/<chain>.json`, no `status/chains/summary.json`, no `outbox/list.json`, no `wallets/list.json`, no `cache/count`, and no `audit/tail.jsonl`. Per-wallet policy lives at `/bloom/wallets/<wallet>/policy.toml` (handled by the wallets handler, not status). Use the listings below as the authoritative shape.

## Daemon

```sh
ls /bloom/status/                                      # daemon.json, version, uptime, started_at, home, chains/, audit/, cache/, policies/, wallets/, outbox/, backends/, update/
cat /bloom/status/version                              # daemon version (text, e.g. 0.0.0)
cat /bloom/status/uptime                               # "Ns" under a minute, "HH:MM:SS" otherwise (text)
cat /bloom/status/started_at                           # RFC3339 UTC, e.g. 2026-05-10T08:30:00Z (text)
cat /bloom/status/home                                 # absolute home dir, e.g. /home/you/.bloom (text)
cat /bloom/status/daemon.json                          # JSON: { version, started_unix_ms, started_at, uptime_secs, home, chains: [..] }
```

`daemon.json` is the one-shot summary; the individual text leaves exist for shell-friendly reads (`cat status/uptime` is more ergonomic than piping `daemon.json` through `jq`).

## Chains

The chain registry lists registered chain names; each name is a directory with five leaves and an `endpoints/` subdir. There is no per-chain JSON aggregate at this layer — read the individual leaves.

```sh
ls /bloom/status/chains/                               # registered chain names (one dir per chain)
ls /bloom/status/chains/ethereum/                      # chain_id, connected, block_number, rpc_url, endpoints/
cat /bloom/status/chains/ethereum/chain_id             # decimal chain id, e.g. 1
cat /bloom/status/chains/ethereum/connected            # "true" / "false" — RPC ping with 750 ms timeout, 2 s cached
cat /bloom/status/chains/ethereum/block_number         # latest block from the same probe; errors if unreachable
cat /bloom/status/chains/ethereum/rpc_url              # first configured RPC URL, redacted (api keys → ***)
cat /bloom/status/chains/base/chain_id                 # → 8453
cat /bloom/status/chains/base/connected                # → true
```

The `connected` / `block_number` leaves share a 2-second handler-level probe cache and an additional 5-second router cache, so polling them in a tight loop is safe. URL redaction strips long opaque trailing path segments (≥20 alnum chars, e.g. Alchemy/Infura keys) and obvious query params (`apikey`, `api_key`, `key`, `token`, `access_token`).

## Per-endpoint health (WP-3)

Every configured RPC endpoint gets an indexed directory under `status/chains/<chain>/endpoints/<idx>/`. Indices are zero-based and stable for the daemon's lifetime — they map directly to the `endpoints` array in the chain's `ChainSpec`. The leaves are populated by the active probe loop in `crates/bloom-rpc/src/transport.rs`, which issues a direct `eth_blockNumber` against each HTTP endpoint every 15 s with a 2 s timeout, bypassing the alloy `FallbackLayer` so probes measure individual endpoints.

```sh
ls /bloom/status/chains/ethereum/endpoints/            # 0, 1, 2, ... — one dir per configured endpoint
ls /bloom/status/chains/ethereum/endpoints/0/          # url, score, cooldown_until, latency_ms, success_rate, last_block
cat /bloom/status/chains/ethereum/endpoints/0/url      # the endpoint URL, redacted (text)
cat /bloom/status/chains/ethereum/endpoints/0/score    # composite score in [0,1] (3-decimal text), 70% success + 30% latency
cat /bloom/status/chains/ethereum/endpoints/0/latency_ms       # EWMA round-trip latency in ms (alpha=0.3)
cat /bloom/status/chains/ethereum/endpoints/0/success_rate     # rolling success rate over the last 10 probes (3-decimal text)
cat /bloom/status/chains/ethereum/endpoints/0/last_block       # last block observed via this endpoint (decimal, blank if none yet)
cat /bloom/status/chains/ethereum/endpoints/0/cooldown_until   # Unix-seconds wall-clock deadline if parked, blank if healthy
cat /bloom/status/chains/ethereum/endpoints/1/score    # peek at the second endpoint in the failover pool
```

Cooldown semantics (from `crates/bloom-rpc/src/health.rs`):

- 5 consecutive failures arm a 60 s cooldown. The `cooldown_until` leaf becomes a Unix-seconds timestamp.
- 2 consecutive successes during cooldown clear it; `cooldown_until` reverts to blank.
- A fresh cooldown within 5 minutes of a recovery escalates to 600 s (chronic-failer).
- Rate-limit responses (HTTP 429) feed `Retry-After` to `record_failure` as a `backoff_hint`, which is used as the cooldown duration instead of the 60 s default. See `BloomRetryPolicy` in `crates/bloom-rpc/src/policy.rs`.

Important scope note: cooldowns are observability-only today. Alloy's `FallbackLayer` does not expose a runtime hook to evict cooled-down endpoints, so the parallel fan-out still queries them. The `success_rate` and `cooldown_until` leaves are the operator's signal that a given endpoint is degraded.

### WebSocket fast path (WP-4)

The WP-4 commit (`c369dc0`) added per-chain WS-backed `subscribe_*` providers used by the watch executor. It did **not** add new VFS leaves — `supports_subscriptions` and the lazy `ws_provider` live entirely inside `RpcEngine`. WS reachability today shows up indirectly: the watch executor logs `watch.subscribe_blocks.ended_falling_back_to_poll` / `watch.subscribe_logs.ended_falling_back_to_poll` and the HTTP poll loop continues. The closest VFS-visible signal is per-watch state under `/bloom/watch/<id>/`, not under `status/`.

## Audit

The audit log is a hash-chained JSONL file written for every state-mutating operation (sign, broadcast, outbox confirm, etc). The log file itself lives at `~/.bloom/audit.jsonl` and is **out-of-band** — it is not exposed through the VFS. What `status/audit/` exposes is the chain's tip and metadata:

```sh
ls /bloom/status/audit/                                # head, count, last
cat /bloom/status/audit/head                           # hex of the most recent record's digest (rolling head, one line)
cat /bloom/status/audit/count                          # total records appended (decimal)
cat /bloom/status/audit/last                           # JSON array of the last 10 records (pretty-printed)
```

`status/audit/last` is the right surface for tailing recent events from inside the VFS — not `audit/tail.jsonl` (no such leaf exists). For the full append-only stream, read `~/.bloom/audit.jsonl` directly with normal Unix tools.

### Verifying chain integrity

The `head` leaf is a digest that depends on every prior record. After any write that should produce an audit entry (e.g. confirming an outbox tx), capture the head before and after and confirm it changed:

```sh
before=$(cat /bloom/status/audit/head)
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/0001-abc/confirm
after=$(cat /bloom/status/audit/head)
[ "$before" != "$after" ] && echo "audit chain advanced"
```

To verify the chain is fully intact (no tampering of intermediate records), recompute digests over `~/.bloom/audit.jsonl` end-to-end and compare the final digest to `status/audit/head`. The hashing scheme is the one in `bloom_proto::AuditLog::append` — out-of-band tooling territory, not a VFS leaf.

## Cache, wallets, outbox, policies

Counts only — no list surfaces here. (For the wallet list, use `/bloom/wallets/`. For pending outbox detail, use `/bloom/wallets/<wallet>/chains/<chain>/outbox/pending/`.)

```sh
ls /bloom/status/cache/                                # etherscan_entries, prices_entries
cat /bloom/status/cache/etherscan_entries              # files in the on-disk etherscan cache (decimal)
cat /bloom/status/cache/prices_entries                 # currently always 0 — no public accessor on PricesClient yet

ls /bloom/status/wallets/                              # count
cat /bloom/status/wallets/count                        # number of registered wallets

ls /bloom/status/outbox/                               # pending_count
cat /bloom/status/outbox/pending_count                 # total pending tx ids across all wallets and chains
```

Per-wallet policy is **not** under `status/`; it lives at `/bloom/wallets/<wallet>/policy.toml` (read+write, handled by the wallets handler).

## Backends

`status/backends/` declares which backend implementation is wired to each feature. Each leaf is one of `etherscan`, `rpc`, or `indexer`. The five features are fixed by the daemon's surface contract.

```sh
ls /bloom/status/backends/                             # contract_metadata, address_history, event_logs, storage_reads, proxy_detection, summary.json
cat /bloom/status/backends/contract_metadata           # → "etherscan" (default; verified source/ABI lookups)
cat /bloom/status/backends/address_history             # → "etherscan" (default; paginated tx history)
cat /bloom/status/backends/event_logs                  # → "rpc"        (default; eth_getLogs)
cat /bloom/status/backends/storage_reads               # → "rpc"        (eth_getStorageAt; rpc-only)
cat /bloom/status/backends/proxy_detection             # → "rpc"        (EIP-1967 / EIP-1822 slot reads)
cat /bloom/status/backends/summary.json                # JSON map of all of the above
```

Switching the backend for a feature is done by editing `~/.bloom/config.toml` under `[backends]` and restarting the daemon. That config file is **out-of-band** and not VFS-writable — `status/backends/*` is read-only in the handler (the `Entry::file` helper sets mode `0o444` and there is no `write` impl). The `status/backends/*` surface reflects the live config snapshot, not a writable dial.

## Docs

`/bloom/docs/` is the daemon's vendored help. The bytes are `include_str!`'d at compile time from `crates/bloom-vfs/src/docs/README.md` and `examples.md`, so the content is stable for the daemon's lifetime — there is no on-disk copy to mutate. Both files are mode `0o444`.

```sh
ls /bloom/docs/                                        # README.md, examples.md
cat /bloom/docs/README.md                              # top-level layout, reading/writing patterns, NFT cheatsheet
cat /bloom/docs/examples.md                            # end-to-end demos: anvil round-trip, tools, NFTs
```

If you want to refresh what the daemon ships with after a workspace update, just `cat` these — they update with the binary.

## Update checker

`status/update/` is the daemon's self-update view. A long-lived `bloom serve` daemon refreshes it every 5 minutes by GETting `https://api.github.com/repos/bloom-directory/bloom/releases/latest` and caching the response at `~/.bloom/cache/update_cache.json`. Short-lived in-process CLI commands only read that cache; they do not contact GitHub. Set `BLOOM_DISABLE_UPDATE_CHECK=1` to disable the automatic daemon refresher; explicit `bloom update check` still performs a check.

```sh
ls /bloom/status/update/                               # installed, latest, available, behind_by, checked_at, release_url, summary.json
cat /bloom/status/update/installed                      # this binary's compiled-in version (always known, even with no cache)
cat /bloom/status/update/latest                         # latest known GitHub release tag (e.g. "0.2.0"), empty line if unknown
cat /bloom/status/update/available                     # "out_of_date" | "up_to_date" | "unknown"
cat /bloom/status/update/behind_by                     # weighted version distance (major*10000 + minor*100 + patch): 0 if up to date or unknown
cat /bloom/status/update/checked_at                     # RFC3339 of the last successful refresh
cat /bloom/status/update/release_url                    # HTML URL of the latest release, empty line if unknown
cat /bloom/status/update/summary.json                   # all of the above, JSON
```

The leaves are read-only. The `update/` directory is only advertised when the daemon is running (the in-process `Daemon::from_home` always wires an update-snapshot producer; tests that construct a `StatusHandler` directly without a producer see no `update` entry). Force a refresh with `bloom update check`; print the cached snapshot with `bloom update status`. The CLI's `bloom status` subcommand also prints a one-line `update_available:` line and a stderr hint when the cached snapshot says you're behind.
