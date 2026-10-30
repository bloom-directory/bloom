#!/usr/bin/env bash
# Successful exits suppress failure-only KeepAlive; a process gap alone does not.
wait_for_logout_services() {
  local broker_uid="$1" signer_uid="$2" broker_label="$3" signer_label="$4"
  local deadline status label stopped
  sleep 15
  deadline=$((SECONDS + 15))
  while [[ $SECONDS -lt $deadline ]]; do
    stopped=true
    for label in "$broker_label" "$signer_label"; do
      status="$(launchctl print "$label")" || return 1
      if ! grep -Eq '^[[:space:]]*state = (not running|exited)$' <<<"$status" ||
        ! grep -Eq '^[[:space:]]*last exit code = 0$' <<<"$status"
      then
        stopped=false
      fi
    done
    if [[ "$stopped" == true ]] &&
      ! pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 &&
      ! pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  echo "services did not exit successfully after login-session logout" >&2
  return 1
}
