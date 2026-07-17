#!/usr/bin/env bash
# tests/docker/test_mempool_mock.sh — dockerized mempool mock smoke test.
#
# Verifies that the daemon's chains/<chain>/mempool/{status.json,recent.jsonl}
# VFS surface populates within ~30 seconds when fed by the in-container
# mempool-mock-ws sidecar (which emulates Alchemy's alchemy_pendingTransactions
# WebSocket subscription).
#
# Driven inside a bloom-test-mempool container brought up by
# tests/docker/docker-compose.yml under the `mempool` profile
# (see run.sh --mempool).
#
# Required env (set by docker-compose.yml's mempool profile):
#   BASE_FORK_INTERNAL_URL      RPC URL the daemon hits (anvil-fork:8545)
#   MEMPOOL_MOCK_WS_URL         WS URL of the mock server (ws://mempool-mock:9551)
#   BLOOM_TEST_WALLET_PASSPHRASE passphrase for the test wallet

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=mempool-test
source "$SCRIPT_DIR/lib.sh"

# MNT/PIDFILE/LOGFILE/SENTINEL come from lib.sh defaults.
# DEST1/ANVIL_KEY come from lib.sh fixtures.
HOME_DIR=/tmp/bloom-mempool-home
WALLET=dest1
CHAIN=base

WALLET_PASSPHRASE="${BLOOM_TEST_WALLET_PASSPHRASE:-}"
[[ -n "$WALLET_PASSPHRASE" ]] || fail "BLOOM_TEST_WALLET_PASSPHRASE not set"
[[ -n "${BASE_FORK_INTERNAL_URL:-}" ]] || fail "BASE_FORK_INTERNAL_URL not set"
[[ -n "${MEMPOOL_MOCK_WS_URL:-}" ]] || fail "MEMPOOL_MOCK_WS_URL not set"
RPC_URL="$BASE_FORK_INTERNAL_URL"

prepare_home_dir "$HOME_DIR"

# Write base config (chains.base section) then append the mempool section.
write_base_config "$HOME_DIR" "$RPC_URL" "Base (forked)"

log "appending mempool config (provider=alchemy ws=$MEMPOOL_MOCK_WS_URL)"
cat >> "$HOME_DIR/config.toml" <<EOF

[mempool.base]
provider = "alchemy"
ws_url = "$MEMPOOL_MOCK_WS_URL"
max_index_size = 1000
EOF

build_mount_demo

# Top up the test wallet on the fork so the daemon can query balances
# without hitting zero-balance paths.
top_up_anvil_balance "$RPC_URL" "$DEST1"

start_mount_demo "$MNT" "$HOME_DIR" "$PIDFILE" "$LOGFILE" \
    "$WALLET" "$ANVIL_KEY" "$WALLET_PASSPHRASE"
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 90

# ---------- assert mempool surface populates within ~30 seconds ----------
log "waiting for mempool to ingest from mock"
ingested=0
for i in $(seq 1 30); do
    status=$(cat "$MNT/chains/$CHAIN/mempool/status.json" 2>/dev/null || echo '{}')
    if grep -q '"subscribed": *true' <<<"$status"; then
        observed=$(grep -oE '"observed_pending": *[0-9]+' <<<"$status" \
            | grep -oE '[0-9]+$' || echo 0)
        if (( observed > 0 )); then
            log "mempool ingested $observed tx after ${i}s"
            ingested=$observed
            break
        fi
    fi
    sleep 1
done

if (( ingested == 0 )); then
    warn "mempool did not ingest any tx within 30s — dumping daemon log"
    cat "$LOGFILE" >&2 || true
    fail "mempool status.json never reached observed_pending > 0"
fi

# ---------- assert recent.jsonl contains at least one fixture hash ----------
RECENT="$MNT/chains/$CHAIN/mempool/recent.jsonl"
log "reading $RECENT"
recent_content=$(cat "$RECENT" 2>/dev/null || echo '')

if [[ -z "$recent_content" ]]; then
    fail "recent.jsonl is empty"
fi

# At least one of the three fixture hashes must appear.
found=0
for prefix in 0x1111 0x2222 0x3333; do
    if grep -q "$prefix" <<<"$recent_content"; then
        log "  found fixture hash prefix $prefix in recent.jsonl"
        found=1
        break
    fi
done

if (( found == 0 )); then
    warn "recent.jsonl content (first 5 lines):"
    head -n 5 <<<"$recent_content" >&2 || true
    fail "recent.jsonl does not contain any expected fixture hash prefix"
fi

log "===== mempool mock integration test PASSED ====="
exit 0
