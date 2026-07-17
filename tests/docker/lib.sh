#!/usr/bin/env bash

# Shared helpers for dockerized mount integration tests. Caller must
# define LOG_PREFIX before sourcing when it wants a custom prefix.

: "${LOG_PREFIX:=docker-test}"

GREEN=$'\033[32m' YELLOW=$'\033[33m' RED=$'\033[31m' RESET=$'\033[0m'

log()  { printf '%s[%s]%s %s\n' "$GREEN"  "$LOG_PREFIX" "$RESET" "$*" >&2; }
warn() { printf '%s[%s]%s %s\n' "$YELLOW" "$LOG_PREFIX" "$RESET" "$*" >&2; }
fail() { printf '%s[%s]%s %s\n' "$RED"    "$LOG_PREFIX" "$RESET" "$*" >&2; exit 1; }

require_env() {
    local name
    for name in "$@"; do
        [[ -n "${!name:-}" ]] || fail "$name not set"
    done
}

# ---------- shared mount layout ----------
# The chain tests (enso, fork) mount at /bloom so user-facing paths read
# `/bloom/wallets/...`. The basic mount test overrides MNT/SENTINEL before
# sourcing this file. PIDFILE/LOGFILE are stable across all of them.
: "${MNT:=/bloom}"
: "${SENTINEL:=/.bloom-mounted}"
: "${PIDFILE:=/tmp/mount_demo.pid}"
: "${LOGFILE:=/tmp/mount_demo.log}"

# ---------- shared fixtures ----------
# Anvil's deterministic accounts (cast wallet new --mnemonic 'test ...').
# We pin the addresses + key so every fork-mode test reads from the same
# wallet without each script re-deriving them.
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEST1=0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266
RECIPIENT=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

# Base mainnet token addresses used by the DeFi tests.
USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
AUSDC=0x4e65fE4DbA92790696d040ac24Aa414708F5c0AB

# ---------- home dir prep ----------
prepare_home_dir() {
    local home_dir=$1
    mkdir -p "$MNT" "$home_dir"
    rm -rf "$home_dir"/*
}

# Live-mode only: copy the canonical keystore from the read-only mount
# into the throwaway home so an in-container daemon write can't corrupt
# it. Bails if the requested wallet is missing.
prepare_live_home() {
    local home_dir=$1 wallet=$2
    [[ -d /bloom-live-home/keystore ]] \
        || fail "/bloom-live-home/keystore missing (mount via run.sh --enso-live)"
    log "copying live keystore -> $home_dir/keystore (in-container, throwaway)"
    cp -r /bloom-live-home/keystore "$home_dir/keystore"
    [[ -d "$home_dir/keystore/$wallet" ]] \
        || fail "no '$wallet' entry under /bloom-live-home/keystore"
}

write_base_config() {
    local home_dir=$1 rpc_url=$2 display_name=$3
    local enso_key=${4:-}

    log "writing config.toml (rpc: $rpc_url)"
    cat > "$home_dir/config.toml" <<EOF
stage_ttl = "30m"
default_chain = "base"

[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["$rpc_url"]
allow_broadcast = true
display_name = "$display_name"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false
EOF

    if [[ -n "$enso_key" ]]; then
        cat >> "$home_dir/config.toml" <<EOF

[enso]
api_key = "$enso_key"
EOF
    fi
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

top_up_anvil_balance() {
    local rpc_url=$1 address=$2 wei_hex=${3:-0x8AC7230489E80000}

    log "anvil_setBalance $address := 10 ETH"
    curl -fsS -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"anvil_setBalance","params":["'"$address"'","'"$wei_hex"'"]}' \
        "$rpc_url" \
        | sed -n 's/.*"result":\([^,}]*\).*/  result=\1/p' >&2 \
        || fail "anvil_setBalance failed (fork RPC unreachable?)"
}

# Spawn mount_demo. When `wallet` is empty the test-fixture env vars are
# omitted entirely (mount_demo treats *unset* differently from *set to
# empty* — an empty BLOOM_TEST_WALLET_NAME would otherwise trip the
# unlock branch with a blank name).
start_mount_demo() {
    local mnt=$1 home_dir=$2 pidfile=$3 logfile=$4
    local wallet=${5:-} import_key=${6:-} passphrase=${7:-}

    log "spawning mount_demo (mount=$mnt home=$home_dir)"
    if [[ -n "$wallet" ]]; then
        BLOOM_TEST_WALLET_NAME="$wallet" \
        BLOOM_TEST_WALLET_KEY="$import_key" \
        BLOOM_TEST_WALLET_PASSPHRASE="$passphrase" \
        RUST_LOG="${RUST_LOG:-info}" \
            "$EXAMPLE_BIN" "$mnt" "$home_dir" >"$logfile" 2>&1 &
    else
        RUST_LOG="${RUST_LOG:-info}" \
            "$EXAMPLE_BIN" "$mnt" "$home_dir" >"$logfile" 2>&1 &
    fi
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

pending_set() {
    local outbox=$1
    ls "$outbox/pending" 2>/dev/null | sort -u | tr '\n' '|' || true
}

pending_diff() {
    local before=$1 after=$2
    comm -13 \
        <(printf '%s' "$before" | tr '|' '\n' | sort -u) \
        <(printf '%s' "$after"  | tr '|' '\n' | sort -u) \
        | grep -v '^$' || true
}

first_new_pending_stage() {
    pending_diff "$1" "$2" | head -n1 || true
}

wait_for_new_pending_stages() {
    local outbox=$1 before=$2 budget=${3:-300}
    local after stages

    for i in $(seq 1 "$budget"); do
        after=$(pending_set "$outbox")
        stages=$(pending_diff "$before" "$after")
        if [[ -n "$stages" ]]; then
            log "  stage appeared after ${i}s"
            printf '%s\n' "$stages"
            return 0
        fi
        if [[ -n "${DAEMON_PID:-}" ]] && ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            fail "mount_demo died while waiting for stage"
        fi
        sleep 1
    done
    return 1
}

# Newest entry under defi/intents/<wallet> excluding the sink `new`.
# Used to learn the session id created by the most recent intent post.
latest_session() {
    local wallet=$1
    ls "$MNT/defi/intents/$wallet" 2>/dev/null \
        | grep -v '^new$' | sort | tail -n1 || true
}

# Confirm a single staged tx and echo the resulting tx hash. Caller
# decides whether to wait for a receipt afterwards (see wait_receipt_status).
confirm_stage_and_get_hash() {
    local outbox=$1 stage=$2
    echo y > "$outbox/pending/$stage/confirm"
    cat "$outbox/sent/$stage/tx_hash" 2>/dev/null | tr -d '\n' || true
}

# Poll a tx receipt without failing on miss. Returns 0 on success, 1 on
# revert or timeout. wait_tx_success below stays for the strict-success
# call sites; this variant is for the unwind path that needs to keep
# going on transient flakes.
wait_receipt_status() {
    local chain=$1 hash=$2 budget=${3:-90}
    local s
    for _ in $(seq 1 "$budget"); do
        s=$(cat "$MNT/chains/$chain/tx/$hash/status" 2>/dev/null | tr -d '\n' || true)
        case "$s" in
            success)  return 0 ;;
            reverted) warn "tx $hash reverted"; return 1 ;;
        esac
        sleep 1
    done
    warn "tx $hash did not confirm within ${budget}s"
    return 1
}

wait_tx_success() {
    local mnt=$1 chain=$2 hash=$3 budget=${4:-60} label=${5:-tx}
    local status=

    log "polling /chains/$chain/tx/$hash/status (${budget}s budget)"
    for i in $(seq 1 "$budget"); do
        status=$(cat "$mnt/chains/$chain/tx/$hash/status" 2>/dev/null | tr -d '\n' || true)
        case "$status" in
            success)
                log "  status=success after ${i}s"
                return 0
                ;;
            reverted)
                fail "$label reverted on-chain (hash=$hash)"
                ;;
            *)
                sleep 1
                ;;
        esac
    done
    fail "$label did not confirm within ${budget}s (last status='$status')"
}

assert_json_file_starts_with() {
    local path=$1 expect=$2 label=${3:-$path}

    [[ -s "$path" ]] || fail "$label is empty at $path"
    local head1
    head1=$(head -c1 "$path")
    [[ "$head1" == "$expect" ]] \
        || fail "$label does not start with '$expect' (got '$head1') at $path"
}

assert_tx_receipt_paths() {
    local tx_dir=$1

    echo '::group::tx receipt paths' >&2

    BLOCK_NUMBER=$(cat "$tx_dir/block_number" 2>/dev/null | tr -d '\n' || true)
    [[ -n "$BLOCK_NUMBER" && "$BLOCK_NUMBER" =~ ^[0-9]+$ ]] \
        || fail "block_number empty or non-numeric ('$BLOCK_NUMBER') at $tx_dir/block_number"
    log "  block_number: $BLOCK_NUMBER"

    GAS_USED=$(cat "$tx_dir/gas_used" 2>/dev/null | tr -d '\n' || true)
    [[ -n "$GAS_USED" && "$GAS_USED" =~ ^[0-9]+$ ]] \
        || fail "gas_used empty or non-numeric ('$GAS_USED') at $tx_dir/gas_used"
    log "  gas_used: $GAS_USED"

    local spec f expect path sz
    for spec in 'receipt.json:{' 'logs.json:[' 'full.json:{'; do
        f="${spec%:*}"
        expect="${spec##*:}"
        path="$tx_dir/$f"
        assert_json_file_starts_with "$path" "$expect" "$f"
        sz=$(wc -c <"$path" | tr -d ' ')
        log "  $f: ok (${sz}B)"
    done
    echo '::endgroup::' >&2
}

read_chain_head_breadcrumb() {
    local mnt=$1 chain=$2

    echo '::group::chain head' >&2
    HEAD_NUMBER=$(cat "$mnt/chains/$chain/head/number" | tr -d '\n')
    log "chain head: block $HEAD_NUMBER"
    echo '::endgroup::' >&2
}

read_wallet_balance_breadcrumb() {
    local mnt=$1 chain=$2 wallet=$3 address=$4

    echo '::group::wallet native balance' >&2
    BAL_NATIVE=$(cat "$mnt/chains/$chain/addresses/$address/balance" | tr -d '\n')
    log "$wallet ($address) native balance: $BAL_NATIVE"
    echo '::endgroup::' >&2
}
