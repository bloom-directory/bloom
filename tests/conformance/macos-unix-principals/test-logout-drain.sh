#!/usr/bin/env bash
# Exercise the real drain check without a Mac or live services.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$here/logout-drain.sh"
for scenario in clean delayed stuck restart_pending; do
  if (
    elapsed=0
    sleep() { elapsed=$((elapsed + $1)); SECONDS=$((SECONDS + $1)); }
    pgrep() { [[ "$scenario" == stuck ]]; }
    launchctl() {
      if [[ "$scenario" == restart_pending ]]; then
        printf 'state = not running\nlast exit code = 1\n'
      elif [[ "$scenario" == stuck || ( "$scenario" == delayed && "$elapsed" -lt 18 ) ]]; then
        printf 'state = running\nlast exit code = 1\n'
      else
        printf 'state = not running\nlast exit code = 0\n'
      fi
    }
    wait_for_logout_services 502 503 system/broker system/signer || exit 1
    [[ "$elapsed" -ge 15 ]]
  ); then status=0; else status=$?; fi
  case "$scenario:$status" in
    clean:0|delayed:0|stuck:1|restart_pending:1) printf 'PASS %s logout drain\n' "$scenario" ;;
    *) printf 'Unexpected %s result: %s\n' "$scenario" "$status" >&2; exit 1 ;;
  esac
done
