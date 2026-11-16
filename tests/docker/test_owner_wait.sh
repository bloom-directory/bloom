#!/usr/bin/env bash
# In-container check of the owner-approval wait through the kernel NFS
# client. `owner_wait_mount` serves one stub outbox entry whose owner
# approves APPROVE_AFTER seconds after the first confirm. Asserts:
#   1. the first confirm is refused at once, and the link is readable;
#   2. the kernel re-sending the refused write does not reach the handler;
#   3. a repeated confirm blocks until the owner approves, then succeeds,
#      and the entry is sent exactly once.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=owner-wait-test
MNT=/mnt/bloom
SENTINEL=/mnt/.bloom-mounted
source "$SCRIPT_DIR/lib.sh"

APPROVE_AFTER=10
ENTRY="$MNT/wallets/w/0/chains/c/outbox/pending/e1"

log "cargo build --release -p bloom-mount --features mount --example owner_wait_mount"
cargo build --release --package bloom-mount --features mount --example owner_wait_mount >&2
EXAMPLE_BIN=${CARGO_TARGET_DIR:-target}/release/examples/owner_wait_mount

"$EXAMPLE_BIN" "$MNT" "$APPROVE_AFTER" >"$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"
DAEMON_PID=$(cat "$PIDFILE")
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 60

# Seconds a confirm took, and whether the kernel reported it as written.
confirm() {
    local started=$SECONDS
    if { printf y > "$ENTRY/confirm"; } 2>/tmp/confirm.err; then
        confirm_ok=1
    else
        confirm_ok=0
    fi
    confirm_took=$((SECONDS - started))
    log "confirm ok=$confirm_ok took=${confirm_took}s err=[$(cat /tmp/confirm.err)]"
}

confirm
[ "$confirm_ok" -eq 0 ] || fail "the first confirm must be refused"
[ "$confirm_took" -le 2 ] || fail "the first confirm must not wait (took ${confirm_took}s)"
grep -q 'http://localhost/c/e1' "$ENTRY/approval_challenge.json" \
    || fail "the approval link is not readable beside the entry"

# Past the adapter's replay window: a late kernel re-send would show here.
sleep 3
counts=$(cat "$ENTRY/counts")
[ "$counts" = "writes=1 sent=0" ] || fail "the refused write reached the handler again: $counts"

confirm
[ "$confirm_ok" -eq 1 ] || fail "the repeated confirm must succeed once the owner approves"
[ "$confirm_took" -ge 3 ] || fail "the repeated confirm did not wait for the owner (took ${confirm_took}s)"
[ "$confirm_took" -le "$APPROVE_AFTER" ] || fail "the repeated confirm outlasted the approval (took ${confirm_took}s)"

sleep 3
counts=$(cat "$ENTRY/counts")
case "$counts" in
    *"sent=1") ;;
    *) fail "the entry must be sent exactly once: $counts" ;;
esac
log "counts after the repeat: $counts"

echo "owner wait behaves on a kernel mount"
