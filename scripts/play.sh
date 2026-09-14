#!/usr/bin/env bash
# scripts/play.sh — interactive bloom playground.
#
# Brings up a containerized anvil and drops the user into a subshell
# wired up to a fresh, read-only bloom home with two chains:
#   - anvil (chain_id 31337, read-only, points at the docker anvil)
#   - base  (chain_id 8453, broadcast disabled — read-only mainnet)
#
# The play home defaults to ~/.bloom-play. Set BLOOM_PLAY_HOME to
# override. Each invocation wipes and recreates the home so previous
# stages don't leak in (set BLOOM_PLAY_PERSIST=1 to keep the existing
# home).
#
# Wallet registration, import, and signing intentionally remain in the
# Broker/Signer browser ceremony; this Machine-only playground never accepts
# raw keys or wallet-secret inputs.
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

# Overwrite config.toml with a custody-free, read-only playground topology.
cat > "$PLAY_HOME/config.toml" <<'EOF'
stage_ttl = "30m"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
allow_broadcast = false
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
│  Anvil:   http://127.0.0.1:8545  (chain_id 31337, read-only)     │
│  Base:    mainnet RPC            (chain_id 8453, read-only)      │
│  Wallets: register/import through the triad browser ceremony     │
│                                                                  │
│  Try:                                                            │
│    bloom status                                                   │
│    bloom vfs ls /                                                 │
│    bloom vfs ls /chains                                           │
│    bloom vfs cat /chains/anvil/head/number                        │
│    bloom vfs cat /chains/base/head/number                         │
│    bloom wallet list                                              │
│                                                                  │
│  Type 'exit' to leave (anvil + daemon will stop).                │
└──────────────────────────────────────────────────────────────────┘

EOF

# Use bash --rcfile to inherit the user's environment but layer the
# playground-specific bits on top. -i keeps it interactive.
bash --rcfile "$RCFILE" -i || true
