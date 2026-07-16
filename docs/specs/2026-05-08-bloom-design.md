# bloom Design (Draft v0)

**Date:** 2026-05-08
**Status:** Initial draft for iteration. Spec only — no implementation.
**Inspiration:** [`bloom`](../../../bloom/docs/superpowers/specs/2026-04-10-bloom-mvp-design.md) — Bloom's NFSv4-mounted, daemon-backed, signature-attributed virtual filesystem.

> This document casts a wide net. Many sections include alternatives,
> open questions, and "stretch" features marked clearly. The goal of v0
> is to surface decisions, not to be the implementable artifact. Sections
> tagged **[STRETCH]** are deliberately out of an MVP cut; sections tagged
> **[OPEN]** need a decision before implementation.

---

## 0. Motivation

LLM agents are extremely good at filesystems and shells. They are
mediocre-to-poor at multi-step JSON-RPC plumbing, ABI encoding, signing
flows, gas estimation, and the dozen different Ethereum-adjacent APIs
needed to *do* anything onchain. Every existing "AI x Ethereum" interface
solves this by giving the agent a bespoke tool API or SDK, which:

- forces the agent to learn a new vocabulary per provider,
- buries side effects inside opaque function calls,
- makes auditing / replaying / staging / cancelling actions awkward,
- doesn't compose with shell tools the agent already wields well
  (`cat`, `tail -f`, `cp`, `ls`, `grep`, `jq`, `diff`).

**bloom presents Ethereum (and a growing set of EVM L2s) as a virtual
filesystem.** Reads are blockchain queries; writes are intents that
become transactions; symlinks are aliases (ENS, contract names);
`tail -f` is a live event stream; `diff` is a state comparison. A single
Rust daemon owns the plumbing — RPC, Etherscan, Enso, key management,
signing, broadcast, indexing, caching — and exposes it as POSIX paths.

The agent never imports a Web3 SDK. It writes files.

---

## 1. Scope & Non-Goals

### In scope (target v1)

- A single Rust daemon (`bloom` / `bloom`) exposing a virtual
  filesystem at a configurable mount path (default `/bloom`).
- Mount via NFSv4.1 + `embednfs` on Linux and macOS 26+ (same
  approach as bloom; NFS is friendlier than FUSE for cross-platform,
  user-mode, and macOS-without-system-extension reasons).
- Read-only views of: chain head state, blocks, transactions, accounts,
  contracts (ABI + verified source), token balances, NFT holdings,
  prices, gas, ENS.
- Write surface: managed wallets with encrypted keys; `outbox/`-style
  intent submission; two-stage commit (stage → simulate → confirm →
  broadcast); receipt and trace files appearing post-confirmation.
- Multi-chain from day one (Ethereum mainnet + at least: Optimism,
  Base, Arbitrum, Polygon). Each chain is a sub-tree.
- DeFi via Enso Shortcuts (route + bundle): write a structured or
  natural-language intent, get back a plan + calldata, confirm to send.
- Streaming: live event tails for blocks, mempool (where supported),
  contract events, wallet activity, via append-only log files.
- Pluggable RPC providers (Alchemy, Infura, public, local Anvil).
- Etherscan (or Etherscan-compatible: Routescan, Blockscout) for
  verified contract source / ABI fetching.
- Optional onchain query tools: simulation (Tenderly-style or local
  EVM execution), gas estimation, state overrides.
- Identity & auth: per-wallet encrypted keystore using passphrase or
  OS keychain integration; per-wallet policy (spend caps, allow-lists,
  required confirmations).
- CLI: `bloom init | up | wallet {new,import,list} | watch | …`.
- Audit log: every read with side effects (provider call) and every
  write is appended to a tamper-evident local log.

### Out of scope for v1 / **[STRETCH]**

- Hardware wallets (Ledger / Trezor) — design hooks present.
- Multi-sig orchestration (Safe / Gnosis flows) — design hooks present.
- Account abstraction (ERC-4337) userop submission.
- MEV / Flashbots bundles, private mempool.
- Cross-chain bridging UX beyond what Enso provides.
- Solana / non-EVM chains (architecture allows; we don't ship adapters).
- Distributed peer sync (this is the bloom MVP feature; bloom is
  single-node by default — see §12 for an optional sync mode).
- A WASM/petal execution layer.
- Windows.

---

## 2. Architecture Overview

```
                 ┌──────────────────────────────────────┐
   kernel NFS    │  embednfs (FileSystem trait impl)    │
   client at     │              = mount                 │
   /bloom        └────────────────┬─────────────────────┘
                                  │
                                  ▼
        ┌──────────────────────────────────────────────────┐
        │                   VFS Router                     │
        │   path → handler dispatch (regex / trie)         │
        │   responsible for path semantics, perms, caching │
        └─┬────────┬────────┬────────┬────────┬───────────┘
          │        │        │        │        │
          ▼        ▼        ▼        ▼        ▼
       chains/  wallets/  defi/   ens/   prices/  watch/  …  (handlers)
          │        │        │        │
          ▼        ▼        ▼        ▼
        ┌────────────────────────────────────────────────┐
        │              Service Layer (engines)           │
        │ ┌──────────┬──────────┬─────────┬────────────┐ │
        │ │ rpc-pool │ etherscan│  enso   │  prices    │ │
        │ │ (alloy)  │  client  │ client  │ (CG/Pyth)  │ │
        │ └──────────┴──────────┴─────────┴────────────┘ │
        │ ┌──────────┬──────────┬─────────┬────────────┐ │
        │ │ keystore │ tx-engine│ indexer │ subscriber │ │
        │ │ (signer) │(broadcast│ (logs/  │ (ws stream │ │
        │ │          │ +confirm)│ history)│  → fanout) │ │
        │ └──────────┴──────────┴─────────┴────────────┘ │
        └────────────────────────────────────────────────┘
                                  │
                                  ▼
        ┌────────────────────────────────────────────────┐
        │              Storage / Cache Layer             │
        │   ~/.bloom/{config,keystore,cache,logs}/   │
        │   - SQLite for metadata + audit log            │
        │   - blob cache for ABIs, source, RPC results   │
        │   - per-path TTLs                              │
        └────────────────────────────────────────────────┘
```

**Why one daemon, not a library?** Same reasons as bloom: a single
serialization point for writes, persistent connections (RPC websocket
subscriptions, QUIC to Enso), a single signer holding decrypted key
material, a single coherent cache, observability and audit centralised.

**Why NFS, not FUSE?**

- macOS FUSE requires a kernel extension (macFUSE) with system-extension
  approval per macOS release. NFSv4.1 client is in the OS.
- bloom established the pattern; reusing it means a portable codebase.
- NFS is well-understood; agents can `ls`/`cat`/`tail -f` against it
  without any awareness of the filesystem type.

**[OPEN-A]** Should bloom re-use bloom's NFS substrate (a
`bloom-mount` crate factored out), or vendor its own copy? See §13.

---

## 3. The Filesystem (Core Interface)

This is the heart of the spec. The path layout is the API.

### 3.1 Top-level layout

```
/bloom/
├── chains/                # read-only chain views
│   ├── ethereum/          # mainnet
│   ├── optimism/
│   ├── base/
│   ├── arbitrum/
│   ├── polygon/
│   └── <chain>/
├── wallets/               # writable: managed local wallets
│   └── <name>/
├── defi/                  # cross-cutting Enso intents
│   └── intents/
├── ens/                   # ENS name resolution (symlinks)
│   └── <name>.eth
├── prices/                # price oracle (read-only)
│   └── <symbol>           # e.g. ETH-USD, BTC-USD
├── watch/                 # subscriptions, live tails
│   └── <name>/
├── simulate/              # tx simulation sandbox (stage tx, get trace)
│   └── <session>/
├── tools/                 # one-shot operations (encode/decode/etc.)
│   ├── abi/
│   ├── hash/
│   ├── keccak
│   └── encode/
├── status/                # daemon health, RPC pool, rate limits, audit
└── docs/                  # human-readable usage, kept in-tree
    ├── README.md
    ├── examples/
    └── schemas/
```

### 3.2 `chains/<chain>/` — chain-scoped read-only view

```
chains/ethereum/
├── chain_id                  # "1"
├── head/                     # current head block (auto-refresh)
│   ├── number                # decimal block number, plain text
│   ├── hash                  # 0x-prefixed
│   ├── timestamp             # ISO8601
│   ├── base_fee
│   ├── miner
│   └── full.json             # entire block w/ tx hashes
├── blocks/
│   ├── latest -> ../head
│   ├── <number>/             # snapshot directory; lazily materialised
│   │   └── (same shape as head/)
│   └── <hash>/
├── tx/
│   └── <hash>/
│       ├── status            # "pending" | "success" | "reverted"
│       ├── tx.json           # raw signed tx
│       ├── receipt.json      # null until mined
│       ├── trace.json        # debug_traceTransaction (provider-dependent)
│       ├── decoded.json      # ABI-decoded calldata + logs (best effort)
│       └── etherscan         # symlink/URL alias for browser
├── addresses/<addr>/
│   ├── balance               # wei (decimal); see also balance.eth, balance.usd
│   ├── balance.eth
│   ├── balance.usd
│   ├── nonce
│   ├── code                  # hex bytecode; empty for EOAs
│   ├── is_contract           # "true"/"false"
│   ├── tokens/
│   │   └── <token-addr>/
│   │       ├── symbol
│   │       ├── balance       # human-decimal (ERC20 decimals applied)
│   │       ├── balance.raw   # raw integer
│   │       └── balance.usd
│   ├── nfts/
│   │   └── <collection-addr>/
│   │       └── <token-id>    # metadata file
│   ├── activity/             # paged tx history (Etherscan-backed)
│   │   ├── recent.jsonl      # last N as jsonl
│   │   └── page/<n>.jsonl
│   └── ens                   # reverse ENS, if any
├── contracts/<addr>/
│   ├── abi.json              # from Etherscan or sourcify
│   ├── source/               # verified source files, mirroring layout
│   │   ├── Foo.sol
│   │   └── …
│   ├── metadata.json         # compiler, settings, name, proxy info
│   ├── implementation        # symlink to impl contract if proxy
│   ├── bytecode
│   ├── methods/              # one entry per ABI function
│   │   ├── <method>.read     # write args (JSON), read returns result
│   │   ├── <method>.tx       # write args, get a stageable tx file
│   │   └── <method>.sig      # 4-byte selector, returns text
│   ├── events/<event>/
│   │   ├── recent.jsonl      # last N
│   │   ├── live              # live tail file (append-only stream)
│   │   └── query             # write filter JSON, read filtered jsonl
│   └── storage/<slot>        # raw storage read; slot in hex or decimal
├── gas/
│   ├── current.json          # base fee + suggested priority fees
│   ├── history.jsonl         # rolling window, last N blocks
│   └── estimate              # write tx JSON, read estimated gas
├── mempool/                  # provider-dependent (Alchemy, Blocknative)
│   ├── live                  # tail
│   └── <hash>/               # appears if observed
└── rpc.toml                  # endpoints + chain config (operator)
```

### 3.3 `wallets/<name>/` — managed local wallets (writable)

```
wallets/alice/
├── address                  # 0x...  (chain-agnostic; EVM is one address)
├── public_key
├── kind                     # "local" | "hardware" | "watch-only" | "smart"
├── policy.toml              # spending limits, allow/deny, confirms
├── settings.toml            # default chain, default gas strategy, …
├── chains/<chain>/
│   ├── balance              # native token, human-decimal
│   ├── balance.eth          # alias for ethereum
│   ├── balance.raw          # wei
│   ├── balance.usd
│   ├── nonce
│   ├── tokens/<addr>/balance
│   ├── nfts/                # holdings on this chain
│   ├── positions/           # DeFi positions (Enso / DeBank) [STRETCH]
│   │   └── <protocol>/<id>.json
│   ├── inbox                # live tail of incoming events for this addr
│   ├── activity/recent.jsonl
│   └── outbox/              # **the write surface — see §3.4**
│       ├── new.tx           # writing here begins staging
│       ├── pending/<id>/    # staged, not yet sent
│       ├── sent/<hash>/     # broadcast
│       └── failed/<id>/     # rejected (sim or send)
└── sign/                    # arbitrary message signing
    ├── new                  # write a message; .sig appears
    └── eip712/              # EIP-712 typed data signing
```

### 3.4 The **outbox** pattern (write semantics)

This is the most important UX choice in the spec. Strawman:

**Mode: "stage-confirm" (default, two-stage commit)**

1. Agent writes a tx description into
   `wallets/alice/chains/ethereum/outbox/new.tx`. Format: JSON, TOML,
   or shell-like single-line (`send 0.01 ETH to 0xabcd...`).
2. Daemon parses, fills defaults (nonce, gas, chainId), simulates,
   and creates a directory `outbox/pending/<id>/` containing:

   ```
   pending/<id>/
   ├── intent.json            # original parsed intent
   ├── tx.json                # the prepared, unsigned tx
   ├── simulation.json        # dry-run result (success/revert, return data)
   ├── trace.json             # call trace
   ├── decoded.json           # ABI-decoded summary, where possible
   ├── plan.md                # human-readable narrative ("send 0.01 ETH …")
   ├── gas_estimate
   ├── usd_value              # quoted at submission
   ├── policy_check.json      # which policy rules pass/fail/warn
   └── confirm                # WRITE here to broadcast; otherwise auto-expires
   ```

3. The stage is purely informational until `confirm` is written. Writing
   any non-empty content to `confirm` (e.g. `echo y > .../confirm`)
   triggers signing + broadcast. The daemon then:
   - signs with the wallet's key,
   - submits via the RPC pool,
   - moves the dir to `outbox/sent/<txhash>/`,
   - links `chains/<chain>/tx/<hash>/` into the wallet's view,
   - appends to `wallets/alice/activity/recent.jsonl`.
4. Removing the pending directory cancels.
5. Pending entries auto-expire after a configurable TTL (default 1h)
   to prevent zombie nonces.

**Mode: "one-shot"** *(opt-in via wallet policy)*

Writing a tx file *with* an `auto_confirm: true` field, OR writing into
a special `outbox/auto/` directory, skips the staging step. Useful for
trusted automated workflows. Subject to policy caps (e.g. max value).

**Mode: "interactive prompt"** *(opt-in)*

Daemon writes to `wallets/alice/prompts/<id>` with the plan and waits
for an out-of-band confirmation (e.g. CLI prompt, push notification).
The agent sees the prompt file but cannot self-confirm.

**[OPEN-B]** Default mode: stage-confirm seems clearly safest; should
it be the only mode in v1, with `auto`/`interactive` as v1.5?

**Tx intent file shapes** (all accepted):

```json
{ "to": "0xabc...", "value": "0.01 eth", "data": "0x", "chain": "ethereum" }
```

```toml
to = "vitalik.eth"
value = "10 usdc"
chain = "ethereum"
gas = "auto"
priority = "fast"
```

```sh
# shell-style single line
send 10 USDC to vitalik.eth on ethereum --priority fast
```

```json
# contract method call
{ "contract": "0xUniV2Router", "method": "swapExactTokensForTokens",
  "args": [...], "value": "0" }
```

```json
# Enso intent
{ "kind": "enso",
  "intent": "swap 1 ETH to USDC and deposit to Aave v3",
  "chain": "ethereum" }
```

The daemon's intent parser (§5.4) is responsible for normalising all
of these into a concrete tx (or a *bundle* of txs, in the Enso case).

### 3.5 `defi/intents/` — Enso-powered DeFi entry point

```
defi/intents/<wallet>/
├── new                      # write intent; daemon creates session
└── <session-id>/
    ├── intent.txt           # original
    ├── route.json           # Enso route response
    ├── bundle.json          # Enso bundle response (if multi-step)
    ├── plan.md              # human narrative w/ slippage, fees
    ├── tx.json              # the eventual tx
    ├── simulation.json
    └── confirm
```

Confirming routes the underlying tx through the wallet's normal outbox
pipeline — Enso integration is "intent compiler", not a parallel
broadcast path.

### 3.6 `watch/` — subscriptions

```
watch/
├── new                      # write a watch spec (see below)
└── <name>/
    ├── spec.toml
    ├── live                 # append-only file, tail -f-able
    └── history.jsonl
```

Watch specs:

```toml
# example: watch all transfers to my wallet
kind = "transfer"
to   = "alice"               # resolves to wallets/alice
chain = "ethereum"
```

```toml
# watch a contract event
kind = "event"
contract = "0x..."
event = "Swap"
chain = "ethereum"
```

```toml
# watch a price threshold
kind = "price"
pair = "ETH-USD"
condition = "below 2000"
```

The daemon backs subscriptions with provider WebSocket connections
where possible, and falls back to polling.

### 3.7 `simulate/<session>/` — tx sandbox

For agents to test before committing. Same shape as a pending tx, but
never broadcasts. Optionally allows state overrides
(`simulate/<session>/state-override.json`).

### 3.8 `tools/` — pure helpers

```
tools/
├── keccak                   # echo "hello" > tools/keccak/in; cat tools/keccak/out
├── abi/encode               # write {abi, args}; read calldata
├── abi/decode               # write {abi, calldata}; read decoded
├── address/checksum         # write addr; read EIP-55 checksummed
├── unit/parse               # "1.5 eth" -> wei
├── unit/format              # wei -> human
└── eip712/hash              # write typed data; read 32-byte hash
```

These have no external dependencies and no auth — handy primitives that
agents can compose.

### 3.9 `status/` — observability

```
status/
├── daemon.json              # version, uptime, mount info
├── rpc/<chain>/             # per-chain RPC pool stats (latency, errors)
├── etherscan.json           # rate limit budget
├── enso.json
├── audit.jsonl              # append-only audit log of all writes
└── cache.json               # cache hit rates by path family
```

### 3.10 General path semantics

- Files have synthetic POSIX modes:
  - read-only blockchain data: `0444`
  - writable wallet outbox / intent dirs: `0755` for dirs, `0644` files
  - secret key material: never readable via the FS (keystore is
    *outside* the mount; only `public_key` is exposed)
- Reads block until the underlying source returns. Default RPC timeout
  10s, configurable.
- Reads are cached per-path with a TTL appropriate to the data:
  - chain head fields: 1s (or 0 if WS subscription is live)
  - balance / nonce: 5s
  - block by number: forever (immutable past finality)
  - contract source / ABI: 7d
- `ls` of unbounded directories (e.g. `chains/ethereum/blocks/`) returns
  an empty listing. The directory is *materialise-on-demand*: looking
  up `blocks/12345/` works even though it isn't listed. This matches
  how `/proc/<pid>/` works on Linux.
- Stat returns sensible mtimes (block timestamp; nonce/balance use the
  last-refresh time).
- Symlinks: `ens/vitalik.eth` resolves to
  `chains/ethereum/addresses/0xd8da...`. Per-chain ENS subtrees on
  L2s where available.

---

## 4. Daemon Architecture (Internal)

### 4.1 Modules

| Module        | Responsibility                                                                 |
|---------------|--------------------------------------------------------------------------------|
| `mount`       | NFS server (`embednfs`); translates ops to VFS calls; mount/unmount           |
| `vfs`         | Path router; per-handler dispatch; permissions; caching                        |
| `chain`       | Per-chain state engine (head tracking, block fetch, tx fetch, indexing)       |
| `rpc`         | Multi-provider RPC pool (alloy-rs); failover, rate-limit, ws subscriptions    |
| `etherscan`   | Etherscan-family client; ABI / source / activity                              |
| `enso`        | Enso Shortcuts client (route, bundle)                                         |
| `prices`      | Price oracle aggregator (CoinGecko + Pyth + onchain fallback)                 |
| `keystore`    | Encrypted key storage; signer; passphrase / OS keychain                       |
| `policy`      | Per-wallet spend caps, allow/deny lists, required confirmations               |
| `tx_engine`   | Stage / simulate / sign / broadcast / confirm; nonce manager; replacement    |
| `subscriber`  | Watch engine; ws listeners; fan-out to log files                              |
| `intent`      | Parses textual / JSON / TOML / shell intents into concrete txs                |
| `audit`       | Append-only tamper-evident log (hash-chained)                                 |
| `cache`       | Tiered cache (mem + sqlite + disk blob); per-key TTL                          |
| `cli`         | `bloom` command-line                                                           |

### 4.2 Process / thread model

Single `tokio` runtime. Tasks:

- one NFS server task
- one task per RPC provider connection (HTTP and WS)
- one task per chain (head subscription, reorg handling)
- one task per active watch
- one task per wallet for nonce management
- a worker pool for opportunistic background fetches (decoding, ABI
  prefetch, etc.)

### 4.3 Caching

Keyed by `(chain_id, kind, identifier)`. Storage tiers:

1. In-memory LRU (hot path: balances, head, recent blocks).
2. SQLite (`~/.bloom/cache.db`) for structured data (txs, blocks,
   activity pages, ABIs).
3. Blob directory (`~/.bloom/blobs/`) for source code archives,
   large logs.

Negative caching for not-found / not-a-contract.

### 4.4 RPC pool

- N providers per chain, ordered by priority.
- Round-robin within the same priority for read calls; sticky for the
  same `eth_call` block-tag to ensure consistency.
- Health checking: rolling latency p50/p95, error rate.
- Demote on threshold; auto-promote after backoff.
- WebSocket subs: prefer one provider; fall back if subs drop.
- Per-method rate limiter (Etherscan, Alchemy free tier limits).
- All calls flow through a tracing span for the audit log.

### 4.5 Reorg handling

- Daemon tracks last K blocks per chain (configurable, default 64).
- Tx receipts noted as "tentative" until N confirmations
  (configurable per wallet policy; default chain-aware: 12 mainnet,
  finalised marker on L2s).
- On reorg, affected txs are re-evaluated; receipts rewritten with a
  visible `reorg.log` note in the tx directory.

### 4.6 Nonce management

- Per (wallet, chain) atomic counter, persisted.
- On startup: reconcile against `eth_getTransactionCount(pending)`.
- Pending txs not yet mined are tracked; daemon offers a `replace`
  helper at `outbox/pending/<id>/replace` to bump gas.

---

## 5. External Integrations

### 5.1 RPC providers

- Default: Alchemy + Infura + a public node (per chain), configurable.
- Local node mode: point at Anvil / Hardhat / Reth-dev for dev/test.
- Endpoint config per chain in `chains/<chain>/rpc.toml`, editable
  via the FS itself (writable file in the chain subtree).
  - **[OPEN-C]** Editing chain config via the FS is conceptually neat
    but creates a chicken-and-egg with daemon restart. Alternative:
    config lives outside the mount in `~/.bloom/config/`.

### 5.2 Etherscan

- Etherscan multi-chain API (single key, many chains) preferred.
- Used for: verified source, ABI, activity (tx history), token
  metadata, internal txs.
- Sourcify fallback for source where Etherscan doesn't have it.

### 5.3 Enso Shortcuts

- API: `POST /shortcuts/route` for swaps & single-position changes;
  `POST /v1/shortcuts/bundle` for multi-step intents.
- Daemon translates a `defi/intents/<wallet>/new` write into an Enso
  call, materialises the response under `<session-id>/`, and (on
  confirm) pipes the resulting calldata into the wallet's outbox.
- Slippage and value protections are surfaced in `plan.md` and checked
  against wallet `policy.toml`.

### 5.4 Prices

- CoinGecko for general spot, with API key support.
- Pyth for high-frequency / on-demand updates.
- Onchain fallback: Uniswap V3 TWAP for arbitrary tokens (when no
  centralised quote is available).
- Exposed at `prices/<base>-<quote>` (latest), `prices/history/...`
  for ranges.

### 5.5 Indexer (optional)

For activity that's painful to backfill from RPC alone (NFTs, large
event histories), the daemon can be configured to use:

- The Graph (subgraph-as-datasource per protocol),
- Goldsky / Alchemy webhooks (push-based),
- a small embedded indexer that tails logs and persists to SQLite.

**[OPEN-D]** Indexer scope in v1: probably just "use Etherscan-style
APIs"; embedded indexer is **[STRETCH]**.

---

## 6. Identity, Keys, Auth

### 6.1 Wallets

A wallet is identified by name (local handle) and Ethereum address.
Backing storage:

```
~/.bloom/keystore/
└── <name>/
    ├── pubkey
    ├── address
    ├── kind                  # local | hw | watch | smart
    ├── encrypted.key         # local: scrypt/argon2id-encrypted secp256k1
    │                         # hw: device fingerprint + path
    │                         # watch: empty
    │                         # smart: owner ref + smart-account address
    └── policy.toml
```

- Local keys: secp256k1, argon2id KDF + xchacha20poly1305, same
  pattern as bloom's identity key. Encrypted at rest.
- The decrypted private key never leaves the daemon process. The
  `wallets/<name>/` mount tree exposes only public data.

### 6.2 Unlock model

- `bloom wallet unlock <name>` prompts passphrase; key in memory until
  daemon stop or `bloom wallet lock`.
- Optional: OS keychain (macOS Keychain / Linux Secret Service)
  integration; auto-unlock on daemon start with user consent.
- Optional: per-tx passphrase prompt for high-value txs (policy-driven).

### 6.3 Policy

`wallets/<name>/policy.toml`:

```toml
# spend caps
[caps]
per_tx_usd        = 100
per_day_usd       = 1000
require_confirm_above_usd = 25

# allow/deny
[contracts]
allow = ["uniswap-v2", "0x..." ]   # allow these contract calls
deny  = ["0xevilcontract..."]

[tokens]
allow = ["ETH", "USDC", "USDT", "DAI"]
deny  = []

# automation
[automation]
auto_confirm_below_usd = 1     # 0 disables auto-confirm
require_2fa            = false # [STRETCH]: TOTP/push for confirms
```

Policy violations are surfaced in `policy_check.json` of the staged
tx; hard violations block confirm; soft violations require an extra
override flag (`echo override > .../confirm`).

### 6.4 Daemon-level auth (multi-user)

- v1: single-user daemon. The mount is owned by the OS user.
- **[STRETCH]** Multi-user mode: every NFS request carries a uid; the
  VFS maps to a wallet bound to that uid. Mostly relevant for shared
  servers and beyond MVP.

### 6.5 Hardware wallets **[STRETCH]**

- `kind = "hardware"`. Signing requests forward to a connected device
  (USB / WebUSB) and surface a `prompts/<id>` file blocking until the
  user confirms on the device. Trezor / Ledger HID adapters as Rust
  crates exist; design is straightforward but out of v1 scope.

### 6.6 Smart accounts (4337) **[STRETCH]**

- `kind = "smart"` wallets are owned by another wallet. Outbox writes
  produce userops, not txs; broadcast goes to a bundler.

---

## 7. Tx Lifecycle Detail

```
   write outbox/new.tx
            │
            ▼
   intent::parse  ──► error file at outbox/failed/<id>/
            │
            ▼
   tx_engine::stage
     - fill defaults (nonce, chain, gas)
     - resolve ENS, contract names, units
     - simulate (eth_call / debug_traceCall / state override)
     - run policy checks
     - write pending/<id>/* artefacts
            │
            ▼
   wait for confirm  (TTL → expire → outbox/failed/<id>)
            │
            ▼
   tx_engine::sign   (keystore in-memory key)
            │
            ▼
   tx_engine::broadcast (rpc-pool, eth_sendRawTransaction)
            │
            ▼ on accepted
   move pending/<id> → sent/<txhash>
   write chains/<chain>/tx/<hash>/* (status=pending)
            │
            ▼ on receipt observed
   write receipt.json, decoded.json, trace.json
   mark status = success | reverted
   update wallet activity feed, balances cache
            │
            ▼ on N confirms
   mark finalised
            │
            ▼ on reorg
   re-evaluate; status may flip
```

Replacement: writing `replace` (with new gas) inside a sent/<hash>
that is still pending issues a same-nonce replacement tx. Cancelling:
writing `cancel` issues a self-send replacement tx.

---

## 8. Streaming and Live Data

The agent should be able to do:

```sh
tail -f /bloom/wallets/alice/chains/ethereum/inbox
tail -f /bloom/chains/ethereum/contracts/0xUNI/events/Swap/live
tail -f /bloom/watch/whale-alerts/live
```

Implementation:

- "live" files are real append-only log files maintained by the
  subscriber engine.
- NFS doesn't natively notify; the kernel pulls. Setting attribute
  caching to zero (as bloom does: `noac` / `actimeo=0`) plus the
  client's `tail -f` polling cadence is sufficient for human-scale
  reactivity (sub-second).
- For lower latency, an out-of-band Unix socket
  (`~/.bloom/events.sock`) streams the same events as JSON Lines
  for clients that want push.

Rotation: live files are rotated at a size threshold; older content
moves to `history.jsonl.<n>`. Subscribers use a sentinel record to
bridge rotation cleanly.

---

## 9. CLI Surface (`bloom`)

```
bloom init                          # config + first wallet, prompt passphrase
bloom up                            # start daemon, mount /bloom
bloom down                          # graceful stop, unmount
bloom status                        # mirror of /bloom/status/daemon.json
bloom wallet new <name>             # generate or import
bloom wallet import <name> <key|file|mnemonic>
bloom wallet list
bloom wallet unlock <name>
bloom wallet lock <name>
bloom wallet export <name>          # encrypted only; refuses plaintext
bloom send <wallet> <amount> <to>   # convenience over outbox
bloom watch <spec>                  # convenience over watch/new
bloom chain add <name> --rpc <url> --etherscan <url>  # custom chain
bloom doctor                        # prints diagnostics, RPC health
bloom tail <path>                   # follows a /bloom path
bloom whois <addr>                  # resolves ENS / contract name
```

The CLI is a thin wrapper over the FS; everything `bloom` does is also
doable by writing files into `/bloom`.

---

## 10. Security

### 10.1 Threat model

In scope:

- Local malicious processes attempting to drain a wallet via the FS:
  mitigated by per-wallet unlock + policy + stage-confirm default.
- Compromised RPC provider: mitigated by multi-provider quorum on
  reads (optional, **[STRETCH]**); receipts always re-checked across
  providers.
- Etherscan returning a wrong ABI: mitigated by checking
  bytecode-against-source via Sourcify when available; flagged in
  `metadata.json`.
- Replay of confirms: confirms are bound to the staged tx hash; if
  the staged content changes (e.g. nonce), confirm must be re-issued.
- Audit log tampering: hash-chained `audit.jsonl` (each entry
  references prior hash); operator can pin a digest externally.

Out of scope:

- A compromised daemon binary. Trust the binary.
- Kernel-level filesystem attacks.
- Side channels on shared hosts.

### 10.2 Mount permissions

- The mount is bound to localhost (`127.0.0.1`) NFS.
- POSIX uid is whoever runs the daemon; cross-user access requires
  multi-user mode (**[STRETCH]**).
- The `wallets/` subtree is browseable; key material lives outside.

### 10.3 Phishing-resistance via plan.md

Every staged tx writes a human-readable `plan.md`:

```
# Send 0.5 ETH

To:    vitalik.eth (0xd8da6bf26964af9d7eed9e03e53415d37aa96045)
From:  alice (0x...)
Chain: ethereum (1)
Value: 0.5 ETH ≈ $1,820 USD
Gas:   ~21,000 @ 12 gwei base + 1 gwei tip ≈ $0.65
Nonce: 14

This transfers 0.5 ETH to vitalik.eth.
No contract interaction.

ALERTS: none
POLICY: per_tx_usd=$2000 ≥ $1820 ✓
```

For contract calls, `plan.md` shows the decoded call (function name,
args), token approvals being granted, and any known-bad-address flags.

---

## 11. Testing Strategy

### 11.1 Unit

- VFS path router: every path family round-trips through dispatch.
- Intent parser: every example shape in §3.4 parses correctly.
- Cache TTLs: stale data not returned past TTL; revalidation correct.
- Keystore: round-trip encrypt/decrypt; wrong passphrase fails;
  corrupt file errors.
- Policy: caps and allow/deny enforced; soft-vs-hard distinction.

### 11.2 Module integration

- Anvil-backed tests: spin up an Anvil instance, point the chain
  module at it, exercise read/write/event flows end-to-end with no
  mocking of RPC.
- Etherscan-backed tests: use a recorded fixture proxy
  (`vcr`-style) for ABI/source fetches; live test with rate-limit
  budget guard.
- Enso: stub server + a smoke test against the live API for one
  representative route.

### 11.3 NFS integration (kernel mount)

Same model as bloom §6.3: privileged-runner CI lane, real `mount.nfs4`
on Linux and `mount_nfs` on macOS, against a daemon backed by Anvil.

### 11.4 Acceptance

A scripted scenario: spin up Anvil with a funded account, import
the key into bloom, stage and confirm:

1. native send,
2. ERC20 transfer,
3. Uniswap V2 swap (real router contract, forked mainnet state),
4. Enso intent ("swap 1 ETH to USDC and deposit into Aave v3"
   on a fork).

All four must complete via FS writes only, with sensible plan.md and
post-receipt state visible at the expected paths.

### 11.5 Tools

`cargo nextest` + `proptest` for parsers + an `anvil-fixtures` crate
that boots an Anvil per test class.

---

## 12. **[STRETCH]** Distributed sync (bloom-style)

For collaborative agents, an optional sync mode borrowed directly from
bloom: a `wallets/<name>/shared/` namespace where signed intent files
can be replicated to peer daemons over QUIC, allowing one agent to
*propose* a tx that another (e.g. a human-controlled approver, or a
co-signer) confirms. Reuses bloom's xDSA + signed sidecar design;
intentionally out of v1.

---

## 13. Code organisation **[OPEN-A revisited]**

Two plausible shapes:

**A. Standalone repo, vendoring NFS substrate.**
Easier; bloom evolves independently. Code duplication risk.

**B. `bloom-mount` extracted from bloom, depended on by both.**
Cleaner long-term; requires bloom to stabilise its NFS adapter as a
public crate.

Suggested: **A** for v1, with a clear "shared crate extraction" task
queued once both stabilise. Either way, the `vfs` layer (path router,
handlers) is bloom's own.

Tentative crates inside the repo:

```
crates/
├── bloom          # CLI binary
├── bloom-daemon   # daemon binary; depends on the rest
├── bloom-vfs      # path router + handler trait + caching
├── bloom-chain    # rpc pool, chain engine, indexer
├── bloom-tx       # tx engine, intent parser, policy
├── bloom-keystore # signer + key encryption
├── bloom-defi     # Enso client + DeFi abstractions
├── bloom-watch    # subscriptions
├── bloom-mount    # NFS adapter (likely bloom-mount once factored out)
└── bloom-proto    # shared types (paths, configs, audit records)
```

---

## 14. Dependency surface (sketch)

| Purpose                          | Crate                         |
|----------------------------------|-------------------------------|
| EVM RPC + types + signing        | `alloy` (rs-alloy)            |
| NFSv4.1 server                   | `embednfs` (or shared)        |
| Async runtime                    | `tokio`                       |
| HTTP client                      | `reqwest`                     |
| WebSocket                        | `tokio-tungstenite`           |
| TLS                              | `rustls`                      |
| Hashing                          | `blake3`, `sha3`              |
| Argon2id KDF                     | `argon2`                      |
| Symmetric cipher                 | `chacha20poly1305`            |
| CBOR / JSON                      | `serde`, `ciborium`, `serde_json` |
| TOML                             | `toml`                        |
| SQLite                           | `rusqlite` or `sqlx`          |
| CLI                              | `clap`                        |
| Tracing / logs                   | `tracing`                     |
| Property tests                   | `proptest`                    |
| Test runner                      | `cargo-nextest`               |
| Anvil fixture                    | `anvil` (foundry crate)       |

---

## 15. Open questions (not blocking spec discussion)

- **[OPEN-A]** Reuse bloom's NFS substrate as a shared crate, or vendor?
- **[OPEN-B]** Default outbox mode; should v1 ship only `stage-confirm`?
- **[OPEN-C]** Where does daemon config live — inside the mount,
  outside, or both with a writable view?
- **[OPEN-D]** Embedded indexer in v1 or `[STRETCH]`?
- **[OPEN-E]** Per-chain RPC config UX — config file vs. `bloom chain
  add` CLI vs. writable file inside the mount.
- **[OPEN-F]** How aggressively should the daemon prefetch (e.g.
  decoding all events of a contract on first read)? Affects RPC
  bills.
- **[OPEN-G]** Should the daemon emit *typed* metric events (Prom-
  exporter-friendly) or rely on tracing logs alone for v1?
- **[OPEN-H]** `tx/<hash>/decoded.json` requires ABI knowledge. What
  do we show when ABI is unknown — raw 4-byte and a TODO file? Look
  up via 4byte.directory? Best-effort heuristic decode?
- **[OPEN-I]** Identity reuse: should a single "operator" identity
  (xDSA, like bloom) sign the audit log, so multi-machine operators
  can attest to actions, even without v1 sync?
- **[OPEN-J]** Naming. Is `bloom` (the binary) too cute / confusable
  with English name? `bloometh`? `efs`?

---

## 16. Discussion seeds (deliberately broad — to be pruned)

These are ideas worth surfacing in iteration. None are committed.

1. **Time-travel reads.** `chains/ethereum/at/<block>/addresses/<addr>/balance`
   for arbitrary historical state via archive RPC. Cheap, very useful.
2. **State proofs.** `addresses/<addr>/balance.proof` returns a
   Merkle-Patricia proof against the block state root, so a paranoid
   verifier (or another agent) can independently check the daemon
   wasn't lying.
3. **Forking sandbox.** `simulate/<session>/` could optionally back
   itself with a private Anvil fork; `state-override.json` writes
   apply locally; the agent can rehearse a whole sequence of writes
   before any real tx. The same code path runs against a real chain
   later.
4. **DSL for batched intents.** A `.bloom` file format that the agent
   can write to compose multi-step intents (e.g. "for each NFT in
   my wallet, list at floor + 5%"), executed atomically when
   confirmed. Sits on top of Enso bundles.
5. **First-class tokens-as-paths.** `tokens/USDC` (ENS-like alias),
   `tokens/USDC/transfer` writes a stageable transfer; abstracts away
   the token contract address.
6. **Address book.** `addressbook/<alias>` writable file maps human
   names to addresses; used for `to:` resolution in intents.
7. **Plan annotations from external tools.** Every staged tx has a
   `plan.md` and an empty `notes/` dir; a security tool (e.g. Wallet
   Guard / Pocket Universe-style) can drop annotations there before
   the user confirms.
8. **Append-only chain of confirms.** A `confirms.jsonl` per wallet
   that other entities (a co-signer, a hardware device, an org policy
   bot) write into; the tx broadcasts only when all required confirms
   are present. Step toward multi-sig without Safe complexity.
9. **Replay graph.** `tx/<hash>/replay/` provides a directory you can
   `cp -r` into your own outbox to clone a tx (with new from/nonce);
   useful for "do what that whale did".
10. **Diffable state.** `addresses/<addr>/snapshot/<label>` saves a
    snapshot file for `diff` against later snapshots — agent-native
    state comparison.
11. **EIP-712 typed-data namespace.** `wallets/<name>/sign/eip712/<id>/`
    where `domain.json` + `types.json` + `message.json` is written;
    daemon hashes/signs.
12. **Permit / approve safety net.** Approvals always show, in plan.md,
    the historical revocation cost and any known scam patterns
    (infinite approvals to unverified contracts get a hard warning).
13. **Conditional transactions / TWAPs.** `outbox/twap.tx` describes
    an order to be split over time; daemon manages execution. Could
    use Enso or onchain Cowswap.
14. **Notification subsystem.** `watch/<name>/notify.toml` says where
    to ping (webhook, mac OS notification, email, ntfy.sh) when an
    event matches. Agents already have file events; humans need pings.
15. **Schema-versioned paths.** Top-level `/bloom/v1/...` so the layout
    can evolve without breaking scripts; `/bloom/latest -> v1`.
16. **A Petname directory.** Per bloom's later vision: stable, signed
    human names for contracts and addresses. Useful in plan.md.
17. **A WASM "petal" runner.** Agents could drop a small WASM module
    into `tools/run/<name>` that the daemon executes against current
    chain state — closes the loop with bloom's larger vision.
18. **Read-only Slack/Discord-style social layer.** `wallets/<name>/inbox`
    receives signed messages addressed to the wallet's address (via a
    public messaging protocol — XMTP, EFP, etc.), giving agents a
    notion of "mailbox".
19. **Yield search.** `defi/yield/<token>` lists best-known yields
    across protocols (via Enso) and lets you just `cp` into outbox to
    enter.
20. **Audit-log signing.** Audit log entries countersigned with an
    operator key, so an external service can verify the daemon's
    actions without trusting it.

---

## 17. What v0 of *this spec* still needs

Before this spec is implementable, we need to:

- Pick from the OPEN list (especially A, B, C, D, J).
- Choose v1 chain set + RPC providers.
- Decide on the indexer path (Etherscan only vs embedded).
- Lock the intent file shape(s) and write a small grammar.
- Decide on default policy.toml shape.
- Decide on outbox confirm semantics in detail (file content,
  sentinel name, expiry, replace/cancel verbs).
- Decide on multi-user ergonomics (single-user v1 confirmed?).
- Run an "ideas round" with a small agent team specifically tasked
  with adversarial / novel ideas (see §18 below).

---

## 18. Iteration plan

This document is v0. Suggested iteration:

1. **v0 → v1 (this conversation).** Resolve OPEN-A through OPEN-J,
   converge on the §1 scope, prune §16 to a committed list and a
   deferred list.
2. **v1 → v2 (agent team round).** Spawn N specialised agents
   ("DeFi user", "security auditor", "mempool wizard", "developer
   experience zealot", "skeptic") and ask each to read v1 and
   propose 5 changes / additions / removals. Merge.
3. **v2 → v3 (implementation pass).** Convert into an executable
   plan with clear phases (mount, chain, wallet, outbox, defi,
   watch, polish).

No code yet.
