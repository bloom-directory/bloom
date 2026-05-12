#!/usr/bin/env bash
# In-container driver for the bloom NFS mount integration test.
#
# Runs inside the Dockerfile next to this script. Steps:
#   1. Build the `mount_demo` example (the only thing that pulls in
#      embednfs); skip a full workspace build to keep the test loop
#      tight.
#   2. Spawn the example pointing at /mnt/bloom with a fresh home dir.
#   3. Wait for the .bloom-mounted sentinel the example drops.
#   4. Exercise a few VFS paths through the kernel mount.
#   5. SIGTERM the example so it unmounts cleanly, then exit.
#
# The script is intentionally chatty: when something goes wrong inside
# the container the host-side `run.sh` only sees the exit code, so we
# print breadcrumbs that show up in `docker run` stdout.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=mount-test

# This test mounts at /mnt/bloom (not the chain tests' /bloom) so the
# sentinel sits at /mnt/.bloom-mounted. Override before sourcing.
MNT=/mnt/bloom
SENTINEL=/mnt/.bloom-mounted
source "$SCRIPT_DIR/lib.sh"

HOME_DIR=/tmp/bloom-home

prepare_home_dir "$HOME_DIR"
build_mount_demo
# No wallet, no chain config — this test is mount-surface only.
start_mount_demo "$MNT" "$HOME_DIR" "$PIDFILE" "$LOGFILE"
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 60

# ---- exercise the VFS through the NFS mount ------------------------
echo "::group::ls $MNT"
ls -la "$MNT"
echo "::endgroup::"

fail_count=0

echo "::group::cat $MNT/status/version"
if ! cat "$MNT/status/version"; then
    echo "FAIL: status/version unreadable" >&2
    fail_count=1
fi
echo "::endgroup::"

echo "::group::ls $MNT/chains"
if ! ls "$MNT/chains"; then
    echo "FAIL: chains/ unlistable" >&2
    fail_count=1
fi
echo "::endgroup::"

echo "::group::cat $MNT/tools/keccak/abc"
if ! cat "$MNT/tools/keccak/abc"; then
    echo "FAIL: tools/keccak/abc unreadable" >&2
    fail_count=1
fi
echo "::endgroup::"

# ---- exercise a write through the kernel mount --------------------
# Regression for the synthetic-handler write path. Linux's NFSv4
# client routinely upgrades small writes to DATA_SYNC/FILE_SYNC, and
# the embednfs server enforces `actual_stability >= requested`. The
# adapter used to hard-code UNSTABLE in its WRITE reply, so a single
# `printf '%s' BODY > /bloom/<writable>` failed with EREMOTEIO (the
# kernel-side surface of NFS4ERR_SERVERFAULT) — even though the
# handler had already accepted the body. The fix lives in
# `crates/bloom-mount/src/adapter.rs::write` (honour the requested
# stability level after an eager flush).
#
# `watch/new` is a good test target: the handler accepts a small
# TOML body, no chain network is required, and the side effect
# (a new watch spec dir) is observable through ordinary `ls`.
echo "::group::write $MNT/watch/new"
WATCH_BODY='kind = "block"
chain = "base"
note = "mount-write regression"
'
set +e
{ printf '%s' "$WATCH_BODY" > "$MNT/watch/new"; } 2> /tmp/write.err
write_status=$?
set -e
write_err=$(cat /tmp/write.err 2>/dev/null || true)
echo "write status=$write_status err=[$write_err]"
if [ "$write_status" -ne 0 ]; then
    echo "FAIL: watch/new write rejected by mount (status=$write_status)" >&2
    fail_count=1
fi
echo "::endgroup::"

# Verify the body reached the handler: at least one non-`new` entry
# should appear under watch/. If the write was silently dropped,
# only `new` would be listed.
echo "::group::verify $MNT/watch contents"
ls -la "$MNT/watch" || true
watch_entries=$(ls "$MNT/watch" 2>/dev/null | grep -v '^new$' | wc -l)
if [ "$watch_entries" -lt 1 ]; then
    echo "FAIL: write did not create a watch entry (got $watch_entries)" >&2
    fail_count=1
fi
echo "watch entries beyond 'new': $watch_entries"
echo "::endgroup::"

if [ "$fail_count" -ne 0 ]; then
    echo "one or more VFS ops failed" >&2
    exit 1
fi

echo "all VFS ops succeeded"
exit 0
