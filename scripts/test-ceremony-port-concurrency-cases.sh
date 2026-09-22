#!/usr/bin/env bash
# Focused failure-mode tests for scripts/test-ceremony-port-concurrency.sh:
# port normalization and guards, a launcher that never becomes ready, PID
# capture on startup failure, and a child that survives SIGTERM. Stub
# launchers/children stand in for real Triads; nothing here binds a port
# or needs the custody Triad. Run: ./scripts/test-ceremony-port-concurrency-cases.sh
set -uo pipefail

export BLOOM_CONCURRENCY_SOURCED=1
# shellcheck disable=SC1090
source "$(dirname "${BASH_SOURCE[0]}")/test-ceremony-port-concurrency.sh"

work="$(mktemp -d /tmp/bct.XXXXXX)"
STUBS=""
passed=0; failed=0; DIE_MSG=""

cleanup_cases() {
  for stub in $STUBS; do
    kill -9 "$stub" 2>/dev/null || true
    wait "$stub" 2>/dev/null || true
  done
  rm -rf -- "$work" 2>/dev/null || true
}
trap cleanup_cases EXIT

# In-process die: record the message and return instead of exiting, so
# failure paths are assertable without subshells.
die() { DIE_MSG="$*"; return 99; }

report() {
  # report STATUS NAME [DETAIL]
  if [ "$1" -eq 0 ]; then
    passed=$((passed + 1)); printf 'ok - %s\n' "$2"
  else
    failed=$((failed + 1)); printf 'not ok - %s: %s\n' "$2" "${3:-}"
  fi
}

# Fast knobs: never wait on real Triad timescales here.
startup_timeout_secs=2
stop_timeout_secs=3
machine_config=/dev/null
transcript=""

# 1. Port normalization: canonical forms and rejections.
for pair in "28735:28735" "0028735:28735" "018734:18734" "80:80" "1:1" "65535:65535"; do
  input="${pair%%:*}"; want="${pair#*:}"
  if got="$(normalize_port "$input" 2>/dev/null)"; then
    [ "$got" = "$want" ] && report 0 "normalize $input" || report 1 "normalize $input" "got $got want $want"
  else
    report 1 "normalize $input" "rejected, want $want"
  fi
done
for bad in "" "0" "00" "65536" "18446744073709570350" "bogus" "-1" "28 735"; do
  if normalize_port "$bad" >/dev/null 2>&1; then
    report 1 "reject $bad" "accepted"
  else
    report 0 "reject ${bad:-<empty>}"
  fi
done

# 2. Port guards on normalized values.
guard_case() {
  # guard_case A B WANT_STATUS WANT_MSG_FRAGMENT NAME
  port_a=$1; port_b=$2
  DIE_MSG=""
  status=0
  check_ports >/dev/null 2>&1 || status=$?
  if [ "$status" -eq "$3" ] && { [ -z "${4:-}" ] || printf '%s' "$DIE_MSG" | grep -qF "$4"; }; then
    report 0 "$5"
  else
    report 1 "$5" "status=$status msg=$DIE_MSG"
  fi
}
guard_case 28735 28736 0 "" "distinct ports pass"
guard_case 018734 28736 99 "custody" "zero-padded custody port rejected"
guard_case 028735 28735 99 "differ" "zero-padded duplicate ports rejected"
guard_case 18734 28736 99 "custody" "custody port rejected"
guard_case 28735 18734 99 "custody" "custody port rejected (B)"
guard_case bogus 28736 99 "integer" "non-numeric port rejected"

# Stub launchers for the process-handling cases.
cat > "$work/stub-never-ready.sh" <<'EOF'
#!/bin/sh
sleep 30
EOF
cat > "$work/stub-fail-fast.sh" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$work/stub-ready.sh" <<'EOF'
#!/bin/sh
echo "$$" > "${STUB_PID_FILE:?}"
: > "${STUB_READY_FILE:?}"
sleep 5
EOF
cat > "$work/stub-ignore-term.sh" <<'EOF'
#!/bin/sh
trap '' TERM
sleep 30
EOF
chmod +x "$work"/stub-*.sh

# 3. A launcher that never becomes ready fails bounded, not forever.
launcher="$work/stub-never-ready.sh"
got=""
start=$(date +%s)
status=0
launch_candidate got NR 28735 "$work/nr" "$work/nr/run/machine.sock" "$work/nr/run/ready" "$work/nr.log" >/dev/null 2>&1 || status=$?
elapsed=$(( $(date +%s) - start ))
if [ "$status" -ne 0 ] && [ "$elapsed" -lt 20 ] && printf '%s' "$DIE_MSG" | grep -q "startup"; then
  report 0 "never-ready launcher fails bounded"
else
  report 1 "never-ready launcher fails bounded" "status=$status elapsed=${elapsed}s msg=$DIE_MSG"
fi
# The timed-out stub is still sleeping: track it for the EXIT trap.
STUBS="$STUBS $got"

# 4. A fast-failing launch still records the child PID for cleanup.
launcher="$work/stub-fail-fast.sh"
got=""
status=0
launch_candidate got FF 28735 "$work/ff" "$work/ff/run/machine.sock" "$work/ff/run/ready" "$work/ff.log" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 0 ] && printf '%s' "$got" | grep -qE '^[0-9]+$'; then
  report 0 "failed launch records child PID"
else
  report 1 "failed launch records child PID" "status=$status got=$got"
fi

# 5. A child that survives SIGTERM fails bounded instead of hanging.
"$work/stub-ignore-term.sh" &
survivor=$!
STUBS="$STUBS $survivor"
start=$(date +%s)
status=0
stop_candidate "$survivor" "$work/nonexistent.sock" TERMTEST >/dev/null 2>&1 || status=$?
elapsed=$(( $(date +%s) - start ))
if [ "$status" -ne 0 ] && [ "$elapsed" -lt 20 ] && printf '%s' "$DIE_MSG" | grep -q "SIGTERM"; then
  report 0 "SIGTERM-surviving child fails bounded"
else
  report 1 "SIGTERM-surviving child fails bounded" "status=$status elapsed=${elapsed}s msg=$DIE_MSG"
fi
kill -9 "$survivor" 2>/dev/null || true
wait "$survivor" 2>/dev/null || true

# 6. A healthy launch assigns the real child PID.
export STUB_PID_FILE="$work/ready.pid" STUB_READY_FILE="$work/ok/ready"
launcher="$work/stub-ready.sh"
got=""
status=0
launch_candidate got OK 28735 "$work/ok" "$work/ok/run/machine.sock" "$work/ok/ready" "$work/ok.log" >/dev/null 2>&1 || status=$?
pidfile="$(cat "$work/ready.pid" 2>/dev/null || true)"
if [ "$status" -eq 0 ] && [ -n "$got" ] && [ "$got" = "$pidfile" ]; then
  report 0 "healthy launch assigns real child PID"
else
  report 1 "healthy launch assigns real child PID" "status=$status got=$got file=$pidfile"
fi
if [ -n "$got" ]; then kill "$got" 2>/dev/null || true; wait "$got" 2>/dev/null || true; fi

# 7. Contender attribution: the stub journal emulates per-unit filtering,
# so only the contender's exact units can satisfy the assertion.
UNIT_SCOPE="bloom-triad-dev-$(id -u)-"
CTR=CTRTOKEN
OTHER=OTHERTOKEN
journalctl() {
  units=""; prev=""
  for arg in "$@"; do
    if [ "$prev" = "-u" ]; then units="$units $arg"; fi
    prev="$arg"
  done
  for u in $units; do
    printf '%s\n' "$STUB_JOURNAL" | grep -F "$u" || true
  done
}
conflict_line() {
  # conflict_line UNIT_FAMILY_SUFFIX TOKEN ADDR
  printf 'systemd[1762]: %s%s-broker-ceremony-%s.socket: Failed to create listening socket (%s): Address already in use\n' \
    "$UNIT_SCOPE" "$2" "$1" "$3"
}
CTR_V4_LINES="$(conflict_line ipv4 "$CTR" 127.0.0.1:28735)
$(conflict_line ipv4 "$CTR" 127.0.0.1:28735)"
CTR_V6_LINES="$(conflict_line ipv6 "$CTR" '[::1]:28735')"
OTHER_LINES="$(conflict_line ipv4 "$OTHER" 127.0.0.1:28735)
$(conflict_line ipv6 "$OTHER" '[::1]:28735')"

# 7a. Both exact units with conflicts: accepted.
STUB_JOURNAL="$CTR_V4_LINES
$CTR_V6_LINES"
status=0
DIE_MSG=""
require_contender_conflict "$CTR" 28735 "2026-01-01 00:00:00" >/dev/null 2>&1 || status=$?
[ "$status" -eq 0 ] && report 0 "attribution accepts contender pair" || report 1 "attribution accepts contender pair" "status=$status msg=$DIE_MSG"

# 7b. Only another runtime's matching pair: rejected.
STUB_JOURNAL="$OTHER_LINES"
status=0
DIE_MSG=""
require_contender_conflict "$CTR" 28735 "2026-01-01 00:00:00" >/dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && report 0 "attribution rejects unrelated runtime pair" || report 1 "attribution rejects unrelated runtime pair" "accepted"

# 7c. Only one of the two units shows a conflict: rejected (both required).
STUB_JOURNAL="$CTR_V4_LINES"
status=0
DIE_MSG=""
require_contender_conflict "$CTR" 28735 "2026-01-01 00:00:00" >/dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && report 0 "attribution requires both units" || report 1 "attribution requires both units" "accepted"
unset -f journalctl

# 8. Contender-path PID retention: a contender that ignores SIGTERM keeps
# its handle for EXIT cleanup instead of losing it.
cat > "$work/stub-contender-ignore-term.sh" <<'EOF'
#!/bin/sh
trap '' TERM
sleep 30
EOF
chmod +x "$work/stub-contender-ignore-term.sh"
launcher="$work/stub-contender-ignore-term.sh"
collide_root="$work/ct"
run_root="$work"
machine_config=/dev/null
port_a=28735
contender_deadline_secs=2
stop_timeout_secs=2
contender_pid=""
status=0
DIE_MSG=""
run_contender >/dev/null 2>&1 || status=$?
if [ "$status" -ne 0 ] && printf '%s' "$contender_pid" | grep -qE '^[0-9]+$' && kill -0 "$contender_pid" 2>/dev/null; then
  report 0 "contender failure retains PID for cleanup"
else
  report 1 "contender failure retains PID for cleanup" "status=$status pid=$contender_pid msg=$DIE_MSG"
fi
if [ -n "$contender_pid" ]; then kill -9 "$contender_pid" 2>/dev/null || true; wait "$contender_pid" 2>/dev/null || true; contender_pid=""; fi

printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
