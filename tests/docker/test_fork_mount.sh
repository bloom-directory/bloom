#!/usr/bin/env bash
# tests/docker/test_fork_mount.sh — dockerized fork-mode mount test.
#
# Sibling of test_enso_aave.sh, but limited to the wallet/outbox +
# chain read surface. No Enso, no DeFi route. The point is to prove
# that an agent with shell access to /bloom/ can:
#
#   1. Stage a plain native-ETH transfer via /bloom/wallets/<w>/chains/<c>/outbox/new.tx
#   2. Broadcast it via /bloom/wallets/<w>/chains/<c>/outbox/pending/<id>/confirm
#   3. Stage a SECOND tx and replace it (same nonce, bumped fees + fresh
#      calldata) via /bloom/wallets/<w>/chains/<c>/outbox/pending/<id>/replace
#   4. Read tx receipt + chain head + gas via /bloom/chains/<c>/...
#
# All writes go through the kernel NFS mount; nothing uses `bloom ipc
# call` shortcuts. If this passes, the fork-mode mount surface is
# wired correctly end-to-end.
#
# Driven inside a bloom-test-fork container brought up by
# tests/docker/docker-compose.yml under the `fork` profile
# (see run.sh --fork).
#
# Required env (set by docker-compose.yml's fork profile)
#   BASE_FORK_INTERNAL_URL        RPC URL the daemon hits (anvil-fork:8545)
#   BLOOM_TEST_WALLET_PASSPHRASE   passphrase for the imported test wallet

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=fork-test
source "$SCRIPT_DIR/lib.sh"

# MNT/PIDFILE/LOGFILE/SENTINEL come from lib.sh defaults.
# DEST1/RECIPIENT/ANVIL_KEY come from lib.sh fixtures.
HOME_DIR=/tmp/bloom-fork-home
WALLET=dest1
CHAIN=base

WALLET_PASSPHRASE="${BLOOM_TEST_WALLET_PASSPHRASE:-}"
[[ -n "$WALLET_PASSPHRASE" ]] || fail "BLOOM_TEST_WALLET_PASSPHRASE not set"
[[ -n "${BASE_FORK_INTERNAL_URL:-}" ]] || fail "BASE_FORK_INTERNAL_URL not set"
RPC_URL="$BASE_FORK_INTERNAL_URL"

prepare_home_dir "$HOME_DIR"
write_base_config "$HOME_DIR" "$RPC_URL" "Base (forked)"
build_mount_demo

# ---------- top up the test wallet on the fork ----------
# Anvil account[0] starts at 10k ETH on a fresh anvil, but a *fork*
# inherits real Base state, so the address may have nothing on real
# Base. Force 10 ETH so subsequent broadcasts have gas room.
top_up_anvil_balance "$RPC_URL" "$DEST1"

# ---------- spawn the mount daemon ----------
start_mount_demo "$MNT" "$HOME_DIR" "$PIDFILE" "$LOGFILE" "$WALLET" "$ANVIL_KEY" "$WALLET_PASSPHRASE"
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 90

# ---------- breadcrumbs ----------
read_chain_head_breadcrumb "$MNT" "$CHAIN"
read_wallet_balance_breadcrumb "$MNT" "$CHAIN" "$WALLET" "$DEST1"

[[ -n "$BAL_NATIVE" && "$BAL_NATIVE" != "0" ]] || fail "$WALLET native balance is 0 after anvil_setBalance"

# ---------- 1. stage + confirm a native-ETH send via the outbox ----------
OUTBOX="$MNT/wallets/$WALLET/chains/$CHAIN/outbox"
PENDING_BEFORE=$(pending_set "$OUTBOX")

# Value carries an explicit unit. Without one, parse_amount defaults to
# "wei" and rejects fractional digits, so "0.001" fails amount parsing —
# which the engine surfaces as HandlerError::Backend, which the mount
# adapter maps to FsError::Io, which the kernel surfaces to userspace
# as EIO. Use "0.001 eth" so it parses as 1e15 wei.
INTENT_BODY_1=$(printf '{"to":"%s","value":"0.001 eth"}' "$RECIPIENT")
log "stage tx (outbox/new.tx <- '$INTENT_BODY_1')"
printf '%s' "$INTENT_BODY_1" > "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/new.tx"

# `stage` is synchronous wrt our in-process VFS, so the new pending dir
# is visible as soon as the write returns. Diff to find the id.
PENDING_AFTER=$(pending_set "$OUTBOX")
STAGE_1=$(first_new_pending_stage "$PENDING_BEFORE" "$PENDING_AFTER")
[[ -n "$STAGE_1" ]] || fail "no pending stage produced after outbox/new.tx write"
log "  stage id: $STAGE_1"

STAGE_DIR_1="$MNT/wallets/$WALLET/chains/$CHAIN/outbox/pending/$STAGE_1"
echo '::group::stage 1 plan.md' >&2
cat "$STAGE_DIR_1/plan.md" >&2 || true
echo '::endgroup::' >&2

# Verify the stage advertises the writable control files (these are
# virtual sinks the handler returns even before they exist on disk).
log "verify stage advertises confirm/replace/cancel"
ls "$STAGE_DIR_1" >&2
for ctrl in confirm replace cancel; do
    # The mount only exposes these as writable files; ls follows the
    # readdir reply, so the names should appear without erroring.
    if ! ls "$STAGE_DIR_1" 2>/dev/null | grep -q "^${ctrl}\$"; then
        warn "  $ctrl not advertised under $STAGE_DIR_1 (continuing)"
    fi
done

# Confirm the first stage — broadcasts on the fork.
log "confirm stage 1 (broadcast on fork)"
echo y > "$STAGE_DIR_1/confirm"

# After confirm returns, the stage moves to sent/<id> and tx_hash is
# readable.
HASH_1=$(cat "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/sent/$STAGE_1/tx_hash" \
    | tr -d '\n' || true)
[[ -n "$HASH_1" ]] || fail "tx_hash missing after broadcast of stage 1"
log "  tx hash: $HASH_1"

# ---------- 2. stage a SECOND tx and replace it (bump fees + new calldata)
# The first tx was confirmed and moved to sent/, so the wallet's nonce
# advanced. A second stage uses the new nonce; we then replace it
# in-place (same nonce, bumped fees, possibly different calldata).
PENDING_BEFORE=$(pending_set "$OUTBOX")

INTENT_BODY_2=$(printf '{"to":"%s","value":"0.0005 eth"}' "$RECIPIENT")
log "stage tx 2 (outbox/new.tx <- '$INTENT_BODY_2')"
printf '%s' "$INTENT_BODY_2" > "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/new.tx"

PENDING_AFTER=$(pending_set "$OUTBOX")
STAGE_2=$(first_new_pending_stage "$PENDING_BEFORE" "$PENDING_AFTER")
[[ -n "$STAGE_2" ]] || fail "no pending stage produced after second outbox/new.tx write"
log "  stage id: $STAGE_2"

STAGE_DIR_2="$MNT/wallets/$WALLET/chains/$CHAIN/outbox/pending/$STAGE_2"

# Replace with a fresh intent — same wallet, but value drops to almost
# zero (and fees auto-bump by 10%). The replace handler broadcasts.
INTENT_REPLACE=$(printf '{"to":"%s","value":"0.00001 eth"}' "$RECIPIENT")
log "replace stage 2 (outbox/pending/$STAGE_2/replace <- '$INTENT_REPLACE')"
printf '%s' "$INTENT_REPLACE" > "$STAGE_DIR_2/replace"

# `replace_with_intent` writes replacement_tx_hash next to the original
# pending entry. Read it back through the mount.
REPLACE_HASH=$(cat "$STAGE_DIR_2/replacement_tx_hash" | tr -d '\n' || true)
[[ -n "$REPLACE_HASH" ]] || fail "replacement_tx_hash missing after replace"
log "  replacement hash: $REPLACE_HASH"
[[ "$REPLACE_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]] \
    || fail "replacement hash not a 32-byte hex ('$REPLACE_HASH')"

# ---------- 3. read-heavy chain reads against the broadcast tx ----------
# Use HASH_1 (stage 1) for the receipt reads — it confirmed cleanly on
# the fork. Anvil mines blocks at 1s intervals so the receipt should
# appear within a couple of polls.
wait_tx_success "$MNT" "$CHAIN" "$HASH_1" 60 "stage 1 tx"

# Read 1: chain head full.json — the daemon wraps the latest block as
# pretty-printed JSON. Assert non-empty + starts with `{`.
HEAD_JSON="$MNT/chains/$CHAIN/head/full.json"
log "read head json: $HEAD_JSON"
assert_json_file_starts_with "$HEAD_JSON" "{" "head full.json"

# Read 2: tx receipt for the broadcast tx. Multiple files under the
# tx subtree — verify the high-value ones are populated. (This mirrors
# the assertions test_enso_aave.sh runs after a successful broadcast.)
TX_DIR="$MNT/chains/$CHAIN/tx/$HASH_1"
log "read tx receipt subtree: $TX_DIR"
assert_tx_receipt_paths "$TX_DIR"

# Read 3: gas/current.json — exposes the current gas_price_wei. The
# fork RPC always answers eth_gasPrice, so this should never be empty.
GAS_JSON="$MNT/chains/$CHAIN/gas/current.json"
log "read gas json: $GAS_JSON"
assert_json_file_starts_with "$GAS_JSON" "{" "gas current.json"
# Cheap key sniff — no jq in the container, but grep -q is fine for a
# regression check.
grep -q 'gas_price_wei' "$GAS_JSON" \
    || fail "gas current.json missing 'gas_price_wei' field"

# Read 4 (bonus): block by number — the latest mined block via the
# numeric path. Confirms the /chains/<c>/blocks/<n>/full.json route
# resolves end to end (a path test.sh doesn't cover).
BLOCK_JSON="$MNT/chains/$CHAIN/blocks/$BLOCK_NUMBER/full.json"
log "read block json: $BLOCK_JSON"
assert_json_file_starts_with "$BLOCK_JSON" "{" "block full.json"

log "===== fork-mode mount integration test PASSED ====="
exit 0
