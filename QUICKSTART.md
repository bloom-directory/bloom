# Quickstart

A short wallet-first walkthrough of the `bloom` CLI. Bloom is an agentic
Ethereum wallet exposed as a virtual filesystem: every `cat` / `ls` /
`write` here is what an agent would otherwise do through the mounted
`/bloom/` tree.

If you are delegating setup to an agent, the fastest path is:

```text
Read https://bloom.directory/SKILL.md and set up Bloom.
```

## Agent-first shape

Bloom's primary surface is the VFS. Use `init` to create the home directory,
`wallet` commands for explicit key management, and `vfs cat|ls|write` for the
same paths an agent sees through the mount. There is no separate top-level
onboarding dashboard; first-run setup is just the same primitives in sequence:
create a wallet, show its deposit QR, then inspect balances and staged actions
through the VFS.

Fund the deposit address, then review every staged plan before signing. Caps
and allow/deny live in each wallet's `policy.toml`; value-moving actions still
go through the stage → review → confirm outbox flow. Polymarket trading
additionally requires `bloom polymarket onboard <wallet>` (see `AGENTS.md`).
Re-display a deposit address any time with `bloom wallet address <name> --qr`.

## Prerequisites

- Rust toolchain — pinned via `rust-toolchain.toml` (installed
  automatically by `rustup` when you run `cargo` in this repo).
- Foundry's [`anvil`](https://book.getfoundry.sh/anvil/) for the
  local devnet used below.

## 1. Initialise a fresh home

`BLOOM_HOME` overrides the home directory (default `~/.bloom`).
Using a tmp path keeps the demo isolated.

```sh
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- init
```

This prints the home dir, config path, and configured chains. The
default config registers ten read-ready public EVM chains (Ethereum,
Base, Arbitrum, Optimism, Polygon, BNB Smart Chain, Avalanche, Gnosis,
Linea, HyperEVM) plus `anvil` at `http://127.0.0.1:8545`. Live-network
broadcasts are blocked by default (`block_mainnet_broadcast = true` and
per-chain `allow_broadcast = false`).

## 2. Start a local devnet

In a second terminal:

```sh
anvil --port 8545
```

Leave it running. Anvil prints ten funded test accounts; we'll mostly
ignore them and create our own wallet.

## 3. Create a wallet

The default wallet kind is **passkey** (WebAuthn) — a browser ceremony runs
and no passphrase is needed. For a quick local demo you can instead create a
**passphrase** wallet with `--local` (non-interactive creation also needs
`--allow-passphrase-wallet` and `--passphrase-file`):

```sh
# Passkey wallet (default) — opens a browser WebAuthn ceremony:
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- wallet new alice

# Passphrase wallet for dev/CI (writes a RECOVERY.txt next to the key):
echo devonly > /tmp/pw.txt
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- wallet new alice \
  --local --allow-passphrase-wallet --passphrase-file /tmp/pw.txt

# Equivalent VFS write (what an agent would do over the mount).
# Plain text body = create a passkey wallet with that name.
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs write /wallets/new --data 'alice'

# Full TOML form for import / watch / passphrase:
#   name = "alice"
#   kind = "local"        # or "passkey" (default) | "import" | "watch"
#   private_key = "0x..." # required for import
#   address = "0x..."     # required for watch
#   passphrase = "..."    # required for local/import
#   allow_passphrase_wallet = true  # required for local/import
```

You'll get back something like `created wallet 'alice': 0x...`. List
wallets to confirm:

```sh
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- wallet list
```

## 4. Inspect the chain through the VFS

The same paths an agent would `cat` over NFS work via `bloom vfs cat`:

```sh
BLOOM_HOME=/tmp/bloom-demo \
  cargo run -p bloom -- vfs cat /chains/anvil/head/number

BLOOM_HOME=/tmp/bloom-demo \
  cargo run -p bloom -- vfs ls /chains/anvil/head
```

Status, docs, and the keyless DefiLlama oracle are also reachable:

```sh
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs cat /docs/README.md
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs cat /status/daemon.json
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs cat /prices/spot/eth.usd
```

## 5. Stage a transaction

Writing to the wallet's outbox starts the stage-confirm flow. Through
an NFS mount this would be:

```sh
echo 'send 0.01 eth to 0xabc... on anvil' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx
```

Without the mount, the equivalent is:

```sh
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs write \
  /wallets/alice/chains/anvil/outbox/new.tx \
  --data 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil'
```

The daemon parses the intent, fills defaults, simulates, runs policy
checks, and writes a `pending/<id>/` directory under the same outbox.

## 6. Inspect the plan, then confirm

List pending entries and read the human-readable plan:

```sh
BLOOM_HOME=/tmp/bloom-demo \
  cargo run -p bloom -- vfs ls /wallets/alice/chains/anvil/outbox/pending

BLOOM_HOME=/tmp/bloom-demo \
  cargo run -p bloom -- vfs cat /wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
```

Confirm by writing any non-empty content to the `confirm` file. Because
the v1 one-shot CLI rebuilds the daemon per invocation, the keystore
unlock is process-scoped — use `wallet confirm` to unlock and broadcast
in one shot:

```sh
BLOOM_HOME=/tmp/bloom-demo \
  cargo run -p bloom -- wallet confirm alice anvil <id> \
    --passphrase devonly --text y
```

When `bloom serve` is running, the unlock survives across calls and you
can write to `…/pending/<id>/confirm` directly (this applies to passphrase /
local wallets — the example below uses one):

```sh
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- wallet unlock alice \
  --passphrase devonly
BLOOM_HOME=/tmp/bloom-demo cargo run -p bloom -- vfs write \
  /wallets/alice/chains/anvil/outbox/pending/<id>/confirm --data y
```

> **Passkey wallets:** the direct VFS `confirm` write over the serve socket is
> not available for passkey-gated wallets — the WebAuthn ceremony binds
> `localhost` and the system browser and is only reachable from the foreground
> CLI. Stop `bloom serve` (or let the CLI fall back to the in-process path) and
> run `bloom wallet confirm <wallet> <chain> <id> --text y` to drive the
> browser ceremony, obtain the Sealed Approval grant, and broadcast in one shot.

The daemon signs, broadcasts, moves the directory to `sent/<id>/`
(with `tx_hash` inside), and links the tx into
`chains/anvil/tx/<hash>/`. Removing the pending directory (or letting
it expire after the configured TTL) cancels the stage.

## What's shipped

- **One-shot CLI** — `bloom vfs cat|ls|write` and `bloom wallet
  new|import|list|unlock|stage|confirm` build the in-process daemon
  per invocation.
- **Long-running daemon** — `bloom serve` exposes a UDS JSON-RPC at
  `~/.bloom/run/bloom.sock`. Talk to it with `bloom ipc call
  <method>` (raw JSON-RPC) or any `bloom vfs` call (auto-routes through
  the socket when it exists).
- **NFS mount adapter** — feature-gated. Build with
  `cargo build --features bloom-daemon/mount` and call
  `Daemon::mount(path)` to expose the VFS over NFSv4.
- **Watch executor** — write a TOML spec to `watch/new`, tail
  `watch/<id>/live` for the running state, or read
  `watch/<id>/history.jsonl[.n]` for the rotated event log.
- **Simulate** — write to `simulate/new` to get an `eth_call` + state
  override result and a rendered plan, all without staging.
- **Etherscan-backed history** —
  `chains/<c>/addresses/<a>/{txs,internal_txs,erc20_txs,erc721_txs}`
  and contract `source` / `abi`. Requires an `[etherscan]` block in
  `config.toml`.
- **ERC-20 reads** — `chains/<c>/addresses/<a>/tokens/<token>/{balance,
  balance.raw,balance.json,symbol,decimals}` (live `eth_call`).
- **ENS** — recipient names like `vitalik.eth` resolve in tx intents
  via the canonical mainnet registry; forward resolution is also
  exposed at `ens/<name>.eth`.
- **DeFi intents** — `defi/intents/<wallet>/...` (Enso shortcuts).
  Mounted whenever an `[enso]` block is present in `config.toml`.
  Requires an Enso API key (`BLOOM_ENSO_KEY` or `ENSO_API_KEY`); the
  client returns `MissingKey` otherwise. ERC-20 token-in routes
  auto-stage an `approve(spender, max)` ahead of the swap when
  needed; default slippage is 50 bps.
- **Prices** — keyless DefiLlama at `prices/spot/<coin>(.usd)` and
  `prices/change_24h/<coin>`.
- **Hyperliquid** — perp and spot market data, order books, candles,
  account state at `/hyperliquid/<network>/...`. Agent sessions
  (one-time approveAgent, then bounded trading) at
  `/hyperliquid/<network>/agent_sessions/<wallet>/...`. One-off
  owner-signed writes at `/hyperliquid/<network>/exchange/<wallet>/...`
  labeled ADVANCED. Read `/hyperliquid/README.md`.
- **Polymarket** — prediction-market trading via CLI (`bloom polymarket
  ...`). VFS staging at `/polymarket/...`; pUSD funding requests can be
  confirmed with `bloom vfs write /polymarket/fund/<wallet>/<id>/confirm
  --unlock-wallet <wallet> --data confirm`, and trade drafts can be posted with
  `bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm
  --unlock-wallet <wallet> --data confirm`. Exit actions also have VFS parity:
  cancel runs directly at `/polymarket/trade/<wallet>/orders/<order-id>/cancel`
  (no unlock — risk-reducing, CLOB creds only), while redeem, revoke-approvals,
  and pUSD withdraw are owner-signed and confirm through the foreground path
  (`/polymarket/redeem/<wallet>/<slug>/confirm`,
  `/polymarket/revoke-approvals/<wallet>/request/confirm`,
  `/polymarket/withdraw/<wallet>/pusd/confirm` with
  `--data '{"confirm":true,"amount":"..."}'`). A capability primitive (scoped
  approve, TTL, caps) is in active development — see
  `docs/plans/2026-06-20-agent-obvious-capability-model.md`.
  Read `/polymarket/README.md`.
- **Zero-config chain reads** — Ethereum, Base, Arbitrum, Optimism,
  Polygon, BNB Smart Chain, Avalanche, Gnosis, Linea, HyperEVM, and
  Anvil are present after `bloom init`; live-network broadcasts remain
  opt-in.
- **Address book** — `addressbook/<alias>` round-trips via FS.
- **EIP-712 / personal_sign / raw-hash signing** — write to
  `wallets/<w>/sign/{message,hash,typed_data}`; the signature lands at
  the `.sig` companion file.

See [docs/AUDIT.md](./docs/AUDIT.md) for the prompt-to-artifact map
of every spec section to its implementation and tests.

## Playground

For an interactive experience with two preconfigured chains
(dockerized Anvil + read-only Base) and three imported wallets, run:

```sh
scripts/play.sh
```

It builds `bloom` in release mode, starts Anvil in Docker, writes a
playground config to `~/.bloom-play/config.toml`, imports
`alice` / `bob` / `carol` from Anvil's deterministic mnemonic
(passphrase `play`), runs `bloom serve` in the background, and drops
you into a subshell with a `bloom` shell function pinned to the play
home. Exit the subshell to tear everything down.

## End-to-end acceptance

`scripts/acceptance.sh` boots Anvil, imports the funded test key, stages a
native ETH send and an ERC-20 transfer, and verifies the mounted Sealed
Approval gate: initial confirm is denied, `approval_challenge.json` is
written in both the wallet projection and central `/outbox/pending/<action_id>`
store, and the challenge includes a local `ceremony_url`. Optional Uniswap V2 /
Enso scenarios on a mainnet fork run when `BLOOM_MAINNET_RPC` is set.

`tests/docker/run.sh` is the dockerized harness with six modes:

- `--mount` (default) — privileged container exercising the NFS
  kernel mount (`tests/docker/test.sh`).
- `--workspace` — runs `cargo test --workspace --lib` in the build
  image; no privileges needed.
- `--fork` — sandboxed end-to-end via `docker compose --profile fork`:
  spins up an anvil fork of Base, exercises wallet/outbox + chain
  reads through the mount. No Enso key required.
- `--enso` — `docker compose --profile enso`: same anvil fork, runs
  the full Enso → Aave intent flow. Requires `BLOOM_ENSO_KEY`.
- `--mempool` — `docker compose --profile mempool`: spins up an
  in-container WebSocket mock that emulates Alchemy's
  `alchemy_pendingTransactions` feed and asserts the daemon's
  `chains/<c>/mempool/{status.json,recent.jsonl}` surface populates.
  No external keys required.
- `--enso-live` — runs the Enso + Aave flow against Base **mainnet**
  with real funds through the mounted filesystem surface. Gated on
  a sourced `test.env` with `BLOOM_ENSO_KEY`, `BLOOM_LIVE_HOME`,
  `BLOOM_LIVE_DEST1`, and `BLOOM_PASSPHRASE`.

Shared scaffolding (logging, mount lifecycle, pending-stage helpers,
receipt assertions, deterministic Anvil constants) lives in
`tests/docker/lib.sh`; the unified `docker-compose.yml` selects modes
via Compose profiles.

## Watch the mempool

If you have a WebSocket-capable RPC for a chain (an Alchemy key, or
any Geth/Erigon node with WS enabled), add a `[mempool.<chain>]`
section to `~/.bloom-eth/config.toml`:

```toml
[mempool.ethereum]
provider = "alchemy"
ws_url = "wss://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
```

`provider = "generic_eth_subscribe"` works against any node that
implements `eth_subscribe("newPendingTransactions")`.

Restart the daemon, then tail the live mempool:

```sh
bloom vfs cat /eth/chains/ethereum/mempool/status.json   # subscription + counts
bloom vfs cat /eth/chains/ethereum/mempool/live          # long-polls up to ~25s; returns one or more JSON lines when txs arrive, or an empty body if the deadline elapses
bloom vfs cat /eth/chains/ethereum/mempool/recent.jsonl | head
bloom vfs cat /eth/chains/ethereum/mempool/by_address/0xYourAddress/pending.jsonl
```

To opt a wallet into private orderflow:

```toml
# wallets/<name>/policy.toml
[private]
enabled = true
provider = "mev_blocker"   # or "flashbots"
```

Future broadcasts from that wallet on supported chains route through
the configured private RPC instead of the public one. The current
Flashbots adapter supports Ethereum mainnet and Sepolia; MEV-Blocker
is mainnet-only. Unsupported chains return an explicit
`PrivateNotSupportedOnChain` error rather than silently broadcasting
publicly.

To run the opt-in Sepolia live send test, fund the same keystore wallet
used by `--enso-live` with Sepolia ETH, then run:

```sh
set -a && source test.env && set +a
BLOOM_RUN_SEPOLIA_PRIVATE_SEND=1 \
BLOOM_SEPOLIA_RPC_URL="https://your-sepolia-rpc" \
cargo test -p bloom-mempool --features live-providers \
  --test it_flashbots_sepolia_send -- --nocapture
```

Required env: `BLOOM_LIVE_HOME`/`BETH_LIVE_HOME`,
`BLOOM_LIVE_DEST1`/`BETH_LIVE_DEST1`,
`BLOOM_PASSPHRASE`/`BETH_PASSPHRASE`,
`BLOOM_SEPOLIA_RPC_URL`/`BETH_SEPOLIA_RPC_URL`, and
`BLOOM_RUN_SEPOLIA_PRIVATE_SEND=1`. Optional env:
`BLOOM_LIVE_WALLET`/`BETH_LIVE_WALLET` (defaults to `dest1`),
`BLOOM_SEPOLIA_RECIPIENT`/`BETH_SEPOLIA_RECIPIENT`,
`BLOOM_SEPOLIA_TRANSFER_WEI`/`BETH_SEPOLIA_TRANSFER_WEI`
(defaults to `100000000000000`),
`BLOOM_SEPOLIA_PRIORITY_FEE_WEI`/`BETH_SEPOLIA_PRIORITY_FEE_WEI`,
`BLOOM_SEPOLIA_MAX_FEE_PER_GAS_WEI`/`BETH_SEPOLIA_MAX_FEE_PER_GAS_WEI`,
and `BLOOM_SEPOLIA_FLASHBOTS_URL`/`BETH_SEPOLIA_FLASHBOTS_URL`.
