#!/usr/bin/env bash
# Dockerized, custody-free chain-read test against an Anvil fork.
#
# Signing is covered through the real Machine/Broker/Signer acceptance suite.
# This Machine-only mount harness must never grow a raw-key or wallet-secret
# shortcut merely to manufacture a signing identity.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=fork-test
source "$SCRIPT_DIR/lib.sh"

HOME_DIR=/tmp/bloom-fork-home
CHAIN=base

[[ -n "${BASE_FORK_INTERNAL_URL:-}" ]] || fail "BASE_FORK_INTERNAL_URL not set"
RPC_URL="$BASE_FORK_INTERNAL_URL"

prepare_home_dir "$HOME_DIR"
write_base_config "$HOME_DIR" "$RPC_URL" "Base (forked)"
build_mount_demo
start_mount_demo "$MNT" "$HOME_DIR" "$PIDFILE" "$LOGFILE"
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 90

read_chain_head_breadcrumb "$MNT" "$CHAIN"
[[ "$HEAD_NUMBER" =~ ^[0-9]+$ ]] || fail "chain head is not numeric: $HEAD_NUMBER"

HEAD_JSON="$MNT/chains/$CHAIN/head/full.json"
GAS_JSON="$MNT/chains/$CHAIN/gas/current.json"
assert_json_file_starts_with "$HEAD_JSON" "{" "head full.json"
assert_json_file_starts_with "$GAS_JSON" "{" "gas current.json"
grep -q 'gas_price_wei' "$GAS_JSON" \
    || fail "gas current.json missing gas_price_wei"

BLOCK_JSON="$MNT/chains/$CHAIN/blocks/$HEAD_NUMBER/full.json"
assert_json_file_starts_with "$BLOCK_JSON" "{" "block full.json"

log "===== fork-mode chain-read test PASSED ====="
