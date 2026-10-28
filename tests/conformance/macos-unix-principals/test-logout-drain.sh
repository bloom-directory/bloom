#!/usr/bin/env bash
# Exercise the real drain check without a Mac or live services.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -f "$scratch/check" "$scratch/count" "$scratch/settled"; rmdir "$scratch"' EXIT
awk '
  /launchctl bootout "\$session_label"/ { copying=1; next }
  copying && /^for ceremony_host in/ { exit }
  copying { print }
' "$here/run-disposable.sh" > "$scratch/check"
[[ -s "$scratch/check" ]]
export scratch
for scenario in transient stuck; do
  rm -f "$scratch/count" "$scratch/settled"
  export scenario
  if bash -eu <<'TEST'
broker_uid=502
signer_uid=503
pgrep() {
  if [[ -f "$scratch/settled" ]]; then
    [[ "$scenario" == stuck ]]
    return
  fi
  # The first pair of queries sees the gap before a queued launchd start.
  count=$(cat "$scratch/count" 2>/dev/null || printf 0)
  count=$((count + 1))
  printf '%s' "$count" > "$scratch/count"
  [[ "$count" -gt 2 ]]
}
sleep() {
  [[ "$1" == 15 ]] || return 1
  touch "$scratch/settled"
}
source "$scratch/check"
TEST
  then status=0; else status=$?; fi
  case "$scenario:$status" in
    transient:0|stuck:1) printf 'PASS %s logout drain\n' "$scenario" ;;
    *) printf 'Unexpected %s result: %s\n' "$scenario" "$status" >&2; exit 1 ;;
  esac
done
