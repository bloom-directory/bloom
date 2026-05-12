# Quickstart

A short Anvil-backed walkthrough of the `beth` CLI. The CLI's `vfs`
subcommands are the v1 substitute for the optional NFS mount: every
`cat` / `ls` / `write` here is what an agent would otherwise do
through the mounted `/eth/` tree.

## Prerequisites

- Rust toolchain — pinned via `rust-toolchain.toml` (installed
  automatically by `rustup` when you run `cargo` in this repo).
- Foundry's [`anvil`](https://book.getfoundry.sh/anvil/) for the
  local devnet used below.

## 1. Initialise a fresh home

`BETH_HOME` overrides the home directory (default `~/.bloom-eth`).
Using a tmp path keeps the demo isolated.

```sh
BETH_HOME=/tmp/beth-demo cargo run -p beth -- init
```

This prints the home dir, config path, and configured chains. The
default config registers an `anvil` chain at `http://127.0.0.1:8545`
and leaves `block_mainnet_broadcast = true` (broadcasts blocked).

## 2. Start a local devnet

In a second terminal:

```sh
anvil --port 8545
```

Leave it running. Anvil prints ten funded test accounts; we'll mostly
ignore them and create our own wallet.

## 3. Create a wallet

The keystore encrypts the key with `BETH_PASSPHRASE` (argon2id +
chacha20poly1305). For a demo, any passphrase works.

The CLI shortcut and the VFS write are equivalent — wallets are
first-class VFS citizens:

```sh
# CLI shortcut
BETH_HOME=/tmp/beth-demo BETH_PASSPHRASE=devonly \
  cargo run -p beth -- wallet new alice --passphrase devonly

# Equivalent VFS write (what an agent would do over the mount).
# Plain text body = create a local wallet with that name.
BETH_HOME=/tmp/beth-demo BETH_PASSPHRASE=devonly \
  cargo run -p beth -- vfs write /wallets/new --data 'alice'

# Full TOML form for import / watch:
#   name = "alice"
#   kind = "import"        # or "local" (default) | "watch"
#   private_key = "0x..."  # required for import
#   address = "0x..."      # required for watch
#   passphrase = "..."     # optional; falls back to BETH_PASSPHRASE
```

You'll get back something like `created wallet 'alice': 0x...`. List
wallets to confirm:

```sh
BETH_HOME=/tmp/beth-demo cargo run -p beth -- wallet list
```

## 4. Inspect the chain through the VFS

The same paths an agent would `cat` over NFS work via `beth vfs cat`:

```sh
BETH_HOME=/tmp/beth-demo \
  cargo run -p beth -- vfs cat /chains/anvil/head/number

BETH_HOME=/tmp/beth-demo \
  cargo run -p beth -- vfs ls /chains/anvil/head
```

Status, docs, and the keyless DefiLlama oracle are also reachable:

```sh
BETH_HOME=/tmp/beth-demo cargo run -p beth -- vfs cat /docs/README.md
BETH_HOME=/tmp/beth-demo cargo run -p beth -- vfs cat /status/daemon.json
BETH_HOME=/tmp/beth-demo cargo run -p beth -- vfs cat /prices/spot/eth.usd
```

## 5. Stage a transaction

Writing to the wallet's outbox starts the stage-confirm flow. Through
an NFS mount this would be:

```sh
echo 'send 0.01 eth to 0xabc... on anvil' \
  > /eth/wallets/alice/chains/anvil/outbox/new.tx
```

Without the mount, the equivalent is:

```sh
BETH_HOME=/tmp/beth-demo cargo run -p beth -- vfs write \
  /wallets/alice/chains/anvil/outbox/new.tx \
  --data 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil'
```

The daemon parses the intent, fills defaults, simulates, runs policy
checks, and writes a `pending/<id>/` directory under the same outbox.

## 6. Inspect the plan, then confirm

List pending entries and read the human-readable plan:

```sh
BETH_HOME=/tmp/beth-demo \
  cargo run -p beth -- vfs ls /wallets/alice/chains/anvil/outbox/pending

BETH_HOME=/tmp/beth-demo \
  cargo run -p beth -- vfs cat /wallets/alice/chains/anvil/outbox/pending/<id>/plan.md
```

Confirm by writing any non-empty content to the `confirm` file. Because
the v1 one-shot CLI rebuilds the daemon per invocation, the keystore
unlock is process-scoped — use `wallet confirm` to unlock and broadcast
in one shot:

```sh
BETH_HOME=/tmp/beth-demo \
  cargo run -p beth -- wallet confirm alice anvil <id> \
    --passphrase devonly --text y
```

When `beth serve` is running, the unlock survives across calls and you
can write to `…/pending/<id>/confirm` directly:

```sh
BETH_HOME=/tmp/beth-demo cargo run -p beth -- wallet unlock alice \
  --passphrase devonly
BETH_HOME=/tmp/beth-demo cargo run -p beth -- vfs write \
  /wallets/alice/chains/anvil/outbox/pending/<id>/confirm --data y
```

The daemon signs, broadcasts, moves the directory to `sent/<id>/`
(with `tx_hash` inside), and links the tx into
`chains/anvil/tx/<hash>/`. Removing the pending directory (or letting
it expire after the configured TTL) cancels the stage.

## What's shipped

- **One-shot CLI** — `beth vfs cat|ls|write` and `beth wallet
  new|import|list|unlock|stage|confirm` build the in-process daemon
  per invocation.
- **Long-running daemon** — `beth serve` exposes a UDS JSON-RPC at
  `~/.bloom-eth/run/beth.sock`. Talk to it with `beth ipc call
  <method>` (raw JSON-RPC) or any `beth vfs` call (auto-routes through
  the socket when it exists).
- **NFS mount adapter** — feature-gated. Build with
  `cargo build --features beth-daemon/mount` and call
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
  balance.raw,balance.formatted,symbol,decimals}` (live `eth_call`).
- **ENS** — recipient names like `vitalik.eth` resolve in tx intents
  via the canonical mainnet registry; forward resolution is also
  exposed at `ens/<name>.eth`.
- **DeFi intents** — `defi/intents/<wallet>/...` (Enso shortcuts).
  Mounted whenever an `[enso]` block is present in `config.toml`.
  Requires an Enso API key (`BETH_ENSO_KEY` or `ENSO_API_KEY`); the
  client returns `MissingKey` otherwise. ERC-20 token-in routes
  auto-stage an `approve(spender, max)` ahead of the swap when
  needed; default slippage is 50 bps.
- **Prices** — keyless DefiLlama at `prices/spot/<coin>(.usd)` and
  `prices/change_24h/<coin>`.
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

It builds `beth` in release mode, starts Anvil in Docker, writes a
playground config to `~/.bloom-eth-play/config.toml`, imports
`alice` / `bob` / `carol` from Anvil's deterministic mnemonic
(passphrase `play`), runs `beth serve` in the background, and drops
you into a subshell with a `beth` shell function pinned to the play
home. Exit the subshell to tear everything down.

## End-to-end acceptance

`scripts/acceptance.sh` boots Anvil, imports the funded test key, and
drives a native ETH send and an ERC-20 transfer through the
stage-confirm-broadcast loop on a local devnet. Optional Uniswap V2 /
Enso scenarios on a mainnet fork run when `BETH_MAINNET_RPC` is set.

`tests/docker/run.sh` is the dockerized harness with six modes:

- `--mount` (default) — privileged container exercising the NFS
  kernel mount (`tests/docker/test.sh`).
- `--workspace` — runs `cargo test --workspace --lib` in the build
  image; no privileges needed.
- `--fork` — sandboxed end-to-end via `docker compose --profile fork`:
  spins up an anvil fork of Base, exercises wallet/outbox + chain
  reads through the mount. No Enso key required.
- `--enso` — `docker compose --profile enso`: same anvil fork, runs
  the full Enso → Aave intent flow. Requires `BETH_ENSO_KEY`.
- `--mempool` — `docker compose --profile mempool`: spins up an
  in-container WebSocket mock that emulates Alchemy's
  `alchemy_pendingTransactions` feed and asserts the daemon's
  `chains/<c>/mempool/{status.json,recent.jsonl}` surface populates.
  No external keys required.
- `--enso-live` — runs the Enso + Aave flow against Base **mainnet**
  with real funds through the mounted filesystem surface. Gated on
  a sourced `test.env` with `BETH_ENSO_KEY`, `BETH_LIVE_HOME`,
  `BETH_LIVE_DEST1`, and `BETH_PASSPHRASE`.

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
beth vfs cat /eth/chains/ethereum/mempool/status.json   # subscription + counts
beth vfs cat /eth/chains/ethereum/mempool/live          # blocks until next pending tx
beth vfs cat /eth/chains/ethereum/mempool/recent.jsonl | head
beth vfs cat /eth/chains/ethereum/mempool/by_address/0xYourAddress/pending.jsonl
```

To opt a wallet into private orderflow (mainnet only):

```toml
# wallets/<name>/policy.toml
[private]
enabled = true
provider = "mev_blocker"   # or "flashbots"
```

Future broadcasts from that wallet on chain id 1 route through the
configured private RPC instead of the public one. Non-mainnet chains
return an explicit `PrivateNotSupportedOnChain` error rather than
silently broadcasting publicly.
