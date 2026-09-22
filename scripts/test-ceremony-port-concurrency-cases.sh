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

# 7. Failed-unit parsing skips the ● row marker.
systemctl() {
  printf '● zeta.socket loaded failed failed Zeta listener\n'
  printf 'alpha.service loaded failed failed Alpha task\n'
  printf '\n'
}
units="$(failed_unit_names)"
unset -f systemctl
want="$(printf 'alpha.service\nzeta.socket')"
if [ "$units" = "$want" ]; then
  report 0 "failed-unit parsing skips marker"
else
  report 1 "failed-unit parsing skips marker" "got: $units"
fi

printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
