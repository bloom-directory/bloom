#!/usr/bin/env bash

# Shared helpers for dockerized mount integration tests. Caller must
# define LOG_PREFIX before sourcing when it wants a custom prefix.

: "${LOG_PREFIX:=docker-test}"

GREEN=$'\033[32m' YELLOW=$'\033[33m' RED=$'\033[31m' RESET=$'\033[0m'

log()  { printf '%s[%s]%s %s\n' "$GREEN"  "$LOG_PREFIX" "$RESET" "$*" >&2; }
warn() { printf '%s[%s]%s %s\n' "$YELLOW" "$LOG_PREFIX" "$RESET" "$*" >&2; }
fail() { printf '%s[%s]%s %s\n' "$RED"    "$LOG_PREFIX" "$RESET" "$*" >&2; exit 1; }

# ---------- shared mount layout ----------
# The chain tests mount at /bloom so user-facing paths read
# `/bloom/wallets/...`. The basic mount test overrides MNT/SENTINEL before
# sourcing this file. PIDFILE/LOGFILE are stable across all of them.
: "${MNT:=/bloom}"
: "${SENTINEL:=/.bloom-mounted}"
: "${PIDFILE:=/tmp/mount_demo.pid}"
: "${LOGFILE:=/tmp/mount_demo.log}"

# ---------- home dir prep ----------
prepare_home_dir() {
    local home_dir=$1
    mkdir -p "$MNT" "$home_dir"
    rm -rf "$home_dir"/*
}

write_base_config() {
    local home_dir=$1 rpc_url=$2 display_name=$3

    log "writing config.toml (rpc: $rpc_url)"
    cat > "$home_dir/config.toml" <<EOF
stage_ttl = "30m"
default_chain = "base"

[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["$rpc_url"]
allow_broadcast = false
display_name = "$display_name"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false
EOF
}

build_mount_demo() {
    log "cargo build --release --features mount --example mount_demo"
    cargo build \
        --release \
        --package bloom-daemon \
        --features mount \
        --example mount_demo >&2

    EXAMPLE_BIN=${CARGO_TARGET_DIR:-target}/release/examples/mount_demo
    if [[ ! -x "$EXAMPLE_BIN" ]]; then
        EXAMPLE_BIN=${CARGO_TARGET_DIR:-target}/debug/examples/mount_demo
    fi
    [[ -x "$EXAMPLE_BIN" ]] || fail "could not find mount_demo binary"
}

# Spawn the Machine-only mount demo. Custody fixtures belong to the real triad
# acceptance suite; this helper deliberately has no secret-bearing inputs.
start_mount_demo() {
    local mnt=$1 home_dir=$2 pidfile=$3 logfile=$4

    log "spawning mount_demo (mount=$mnt home=$home_dir)"
    RUST_LOG="${RUST_LOG:-info}" \
        "$EXAMPLE_BIN" "$mnt" "$home_dir" >"$logfile" 2>&1 &
    echo $! > "$pidfile"
    DAEMON_PID=$(cat "$pidfile")
    log "  pid=$DAEMON_PID, logging to $logfile"
}

cleanup_mount_demo() {
    local mnt=$1 pidfile=$2 logfile=$3

    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            log "stopping mount_demo (pid=$pid)"
            kill -TERM "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    umount "$mnt" 2>/dev/null || true
    if [[ -f "$logfile" ]]; then
        echo '::group::mount_demo log (tail)' >&2
        tail -n 200 "$logfile" >&2 || true
        echo '::endgroup::' >&2
    fi
}

wait_for_mount() {
    local sentinel=$1 pid=$2 logfile=$3 budget=${4:-90}

    log "waiting for $sentinel"
    for i in $(seq 1 "$budget"); do
        if [[ -f "$sentinel" ]]; then
            log "  sentinel found after ${i}s"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo 'mount_demo exited before mount; tail of log:' >&2
            tail -n 60 "$logfile" >&2 || true
            exit 1
        fi
        sleep 1
    done
    fail "timed out waiting for mount sentinel"
}

assert_json_file_starts_with() {
    local path=$1 expect=$2 label=${3:-$path}

    [[ -s "$path" ]] || fail "$label is empty at $path"
    local head1
    head1=$(head -c1 "$path")
    [[ "$head1" == "$expect" ]] \
        || fail "$label does not start with '$expect' (got '$head1') at $path"
}

read_chain_head_breadcrumb() {
    local mnt=$1 chain=$2

    echo '::group::chain head' >&2
    HEAD_NUMBER=$(cat "$mnt/chains/$chain/head/number" | tr -d '\n')
    log "chain head: block $HEAD_NUMBER"
    echo '::endgroup::' >&2
}
