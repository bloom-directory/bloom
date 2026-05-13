#!/usr/bin/env bash
# scripts/play.sh — interactive bloom playground.
#
# Brings up a containerized anvil and drops the user into a subshell
# wired up to a fresh bloom home with two chains:
#   - anvil (chain_id 31337, broadcast enabled, points at the docker anvil)
#   - base  (chain_id 8453, broadcast disabled — read-only mainnet)
#
# The play home defaults to ~/.bloom-play. Set BLOOM_PLAY_HOME to
# override. Each invocation wipes and recreates the home so previous
# stages don't leak in (set BLOOM_PLAY_PERSIST=1 to keep the existing
# home).
#
# Cleanup: on exit, the local daemon and the anvil container are both
# stopped. Docker volumes/images are not removed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"

BLOOM_BIN="${BLOOM_BIN:-$REPO_ROOT/target/release/bloom}"
PLAY_HOME="${BLOOM_PLAY_HOME:-$HOME/.bloom-play}"
COMPOSE_FILE="$REPO_ROOT/docker/playground/docker-compose.yml"
DAEMON_LOG="${BLOOM_PLAY_DAEMON_LOG:-/tmp/bloom-play-daemon.log}"

log()  { printf '\033[1;36m[play]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[play:fail]\033[0m %s\n' "$*"; exit 1; }

require_cmd docker curl

# docker compose v2 lives under the `docker` plugin namespace; v1 is the
# standalone `docker-compose` binary. Pick whichever is available.
detect_docker_compose

# Build bloom on demand. Release build keeps the playground responsive.
if [ ! -x "$BLOOM_BIN" ]; then
    log "building bloom (release)..."
    (cd "$REPO_ROOT" && cargo build --release -p bloom)
fi
[ -x "$BLOOM_BIN" ] || fail "bloom binary not found at $BLOOM_BIN"

# Bring up the anvil container.
log "starting docker stack ($(basename "$COMPOSE_FILE"))"
"${DC[@]}" -f "$COMPOSE_FILE" up -d anvil

cleanup() {
    log "tearing down playground"
    if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
    "${DC[@]}" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Wait for anvil's JSON-RPC to answer eth_chainId.
log "waiting for anvil rpc"
wait_eth_rpc http://127.0.0.1:8545 30 1 || fail "anvil did not become ready on :8545"

# Initialize the play home. Wipe by default so each session starts clean.
if [ "${BLOOM_PLAY_PERSIST:-0}" != "1" ]; then
    rm -rf "$PLAY_HOME"
fi
mkdir -p "$PLAY_HOME"
"$BLOOM_BIN" --home "$PLAY_HOME" init >/dev/null 2>&1 || true

# Overwrite config.toml with the playground topology. We disable
# block_mainnet_broadcast at the top level so the operator decides per
# chain via allow_broadcast — anvil broadcasts, base does not.
cat > "$PLAY_HOME/config.toml" <<'EOF'
stage_ttl = "30m"
block_mainnet_broadcast = false
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
allow_broadcast = true
display_name = "Anvil (local docker)"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false

[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["https://mainnet.base.org"]
allow_broadcast = false
display_name = "Base (read-only)"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false
EOF

# Import anvil's deterministic accounts as alice/bob/carol so the user
# has spendable test ETH on chain anvil. Skip if the wallet already
# exists (BLOOM_PLAY_PERSIST=1 case).
import_if_missing() {
    local name=$1
    local key=$2
    if "$BLOOM_BIN" --home "$PLAY_HOME" wallet list 2>/dev/null \
        | awk '{print $1}' | grep -qx "$name"; then
        return 0
    fi
    BLOOM_PASSPHRASE=play "$BLOOM_BIN" --home "$PLAY_HOME" wallet import \
        "$name" "$key" --passphrase play >/dev/null
}

log "importing anvil keys (passphrase: play)"
import_if_missing alice "$ANVIL_KEY_0"
import_if_missing bob   "$ANVIL_KEY_1"
import_if_missing carol "$ANVIL_KEY_2"

# Start the daemon. We use `serve` so VFS reads/writes from the play
# subshell hit the same in-memory state.
log "starting bloom daemon (log: $DAEMON_LOG)"
"$BLOOM_BIN" --home "$PLAY_HOME" serve >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Daemon needs a moment to bind the IPC socket.
SOCKET="$PLAY_HOME/run/bloom.sock"
ready=0
for _ in $(seq 1 30); do
    if [ -S "$SOCKET" ]; then
        ready=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        log "daemon log:"
        cat "$DAEMON_LOG" >&2
        fail "daemon exited before opening $SOCKET"
    fi
    sleep 0.25
done
[ "$ready" -eq 1 ] || fail "daemon did not open $SOCKET within 7.5s"

# Drop the user into an interactive shell with BLOOM_HOME pointing at
# the play home. The custom rcfile keeps the user's normal aliases
# while making `bloom` resolve to the playground binary and home.
RCFILE="$(mktemp -t bloom-play-rc.XXXXXX)"
cat > "$RCFILE" <<EOF
# Sourced by the bloom playground subshell.
[ -f "\$HOME/.bashrc" ] && . "\$HOME/.bashrc"

export BLOOM_PLAY_HOME='$PLAY_HOME'
export BLOOM_BIN='$BLOOM_BIN'

bloom() {
    "\$BLOOM_BIN" --home "\$BLOOM_PLAY_HOME" "\$@"
}
export -f bloom

PS1='\[\033[1;35m\](bloom-play)\[\033[0m\] \w\$ '
EOF
trap 'rm -f "$RCFILE"; cleanup' EXIT INT TERM

cat <<EOF

┌──────────────────────────────────────────────────────────────────┐
│  bloom playground                                            │
│                                                                  │
│  Home:    $PLAY_HOME
│  Anvil:   http://127.0.0.1:8545  (chain_id 31337, broadcasts ok) │
│  Base:    mainnet RPC            (chain_id 8453, read-only)      │
│  Wallets: alice / bob / carol    (passphrase: play)              │
│                                                                  │
│  Try:                                                            │
│    bloom status                                                   │
│    bloom vfs ls /                                                 │
│    bloom vfs ls /chains                                           │
│    bloom vfs cat /chains/anvil/head/number                        │
│    bloom vfs cat /chains/base/head/number                         │
│    bloom wallet list                                              │
│    bloom wallet stage alice anvil --intent \\                     │
│      '{"to":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",        │
│        "value":"1 ETH","chain":"anvil"}'                         │
│                                                                  │
│  Type 'exit' to leave (anvil + daemon will stop).                │
└──────────────────────────────────────────────────────────────────┘

EOF

# Use bash --rcfile to inherit the user's environment but layer the
# playground-specific bits on top. -i keeps it interactive.
bash --rcfile "$RCFILE" -i || true
