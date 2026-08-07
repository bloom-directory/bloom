#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: run-two-login.sh PAYLOAD_DIR LOGIN_UID_A LOGIN_USER_A LOGIN_UID_B LOGIN_USER_B [UPGRADE_PAYLOAD [FAILING_UPGRADE_PAYLOAD]]" >&2
  exit 64
}

[[ $# -ge 5 && $# -le 7 ]] || usage
payload="$(cd "$1" && pwd -P)"
login_uid_a="$2"
login_user_a="$3"
login_uid_b="$4"
login_user_b="$5"
upgrade_payload=""
failing_upgrade_payload=""
if [[ $# -ge 6 ]]; then
  upgrade_payload="$(cd "$6" && pwd -P)"
fi
if [[ $# -eq 7 ]]; then
  failing_upgrade_payload="$(cd "$7" && pwd -P)"
fi
for login_uid in "$login_uid_a" "$login_uid_b"; do
  [[ "$login_uid" =~ ^[1-9][0-9]*$ ]] || usage
done
for login_user in "$login_user_a" "$login_user_b"; do
  [[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || usage
done
[[ "$login_uid_a" != "$login_uid_b" && "$login_user_a" != "$login_user_b" ]] || usage

[[ "$EUID" -eq 0 && "$(uname -s)" == "Darwin" ]] || {
  echo "two-login W0 requires root on a disposable macOS host" >&2
  exit 77
}
marker="/private/var/db/bloom-w0-disposable-host"
if [[ "${BLOOM_RUN_MACOS_UNIX_W0:-}" != "true" ]] ||
  [[ ! -f "$marker" || -L "$marker" ]] ||
  ! grep -Fx 'bloom-macos-unix-w0-disposable-v1' "$marker" >/dev/null
then
  echo "two-login W0 host is not explicitly marked disposable" >&2
  exit 77
fi
[[ "$(<"$payload/PLATFORM_CLAIM")" == "macos-unix-principals-w0" ]] || {
  echo "two-login W0 payload has the wrong platform claim" >&2
  exit 65
}
for additional_payload in "$upgrade_payload" "$failing_upgrade_payload"; do
  [[ -z "$additional_payload" ]] && continue
  [[ "$(<"$additional_payload/PLATFORM_CLAIM")" == "macos-unix-principals-w0" ]] || {
    echo "two-login W0 upgrade payload has the wrong platform claim" >&2
    exit 65
  }
done
for pair in "$login_uid_a:$login_user_a" "$login_uid_b:$login_user_b"; do
  login_uid="${pair%%:*}"
  login_user="${pair#*:}"
  [[ "$(id -u "$login_user")" == "$login_uid" ]] || {
    echo "two-login W0 login name and UID do not match" >&2
    exit 65
  }
  launchctl print "gui/$login_uid" >/dev/null 2>&1 || {
    echo "two-login W0 requires active GUI domains for both selected users" >&2
    exit 69
  }
done

triad_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
installer="$triad_source/release/install-macos.sh"
machine_binary="/usr/local/libexec/bloom/current/bloom"
session_plist="/Library/LaunchAgents/com.bloom.session.plist"
scratch="$(mktemp -d /private/tmp/bloom-w0-two-login.XXXXXX)"
installed_a=false
installed_b=false
tested_payload="$payload"

cleanup() {
  status=$?
  if [[ "$installed_b" == true ]] &&
    [[ -f "/Library/Application Support/BloomTriad/enrollments/$login_uid_b.json" ]]
  then
    "$installer" uninstall / "$login_uid_b" "delete-bloom-login-$login_uid_b" || true
  fi
  if [[ "$installed_a" == true ]] &&
    [[ -f "/Library/Application Support/BloomTriad/enrollments/$login_uid_a.json" ]]
  then
    "$installer" uninstall / "$login_uid_a" "delete-bloom-login-$login_uid_a" || true
  fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT

assert_unused_enrollment() {
  login_uid="$1"
  for path in \
    "/Library/Application Support/BloomTriad/enrollments/$login_uid.json" \
    "/Library/Application Support/BloomTriad/config/$login_uid" \
    "/private/var/db/bloom/$login_uid" \
    "/private/var/run/bloom/$login_uid"
  do
    [[ ! -e "$path" && ! -L "$path" ]] || {
      echo "two-login W0 refuses to adopt existing Bloom state at $path" >&2
      exit 65
    }
  done
  for kind_and_name in \
    "Users bloom-broker-$login_uid" \
    "Users bloom-signer-$login_uid" \
    "Groups bloom-broker-$login_uid" \
    "Groups bloom-signer-$login_uid" \
    "Groups bloom-machine-broker-$login_uid" \
    "Groups bloom-broker-signer-$login_uid" \
    "Groups bloom-revoke-$login_uid"
  do
    kind="${kind_and_name%% *}"
    name="${kind_and_name#* }"
    if dscl . -read "/$kind/$name" >/dev/null 2>&1; then
      echo "two-login W0 refuses to adopt Directory Service record $kind/$name" >&2
      exit 65
    fi
  done
}

field() {
  login_uid="$1"
  key="$2"
  plutil -extract "$key" raw -o - \
    "/Library/Application Support/BloomTriad/enrollments/$login_uid.json"
}

payload_release_digest() {
  selected_payload="$1"
  manifest="$selected_payload/SHA256SUMS"
  [[ -f "$manifest" && ! -L "$manifest" ]] || {
    echo "two-login W0 payload has no regular signed manifest" >&2
    exit 65
  }
  digest="$(shasum -a 256 "$manifest" | awk '{print $1}')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "two-login W0 payload release digest is invalid" >&2
    exit 65
  }
  printf '%s\n' "$digest"
}

wait_for_services_to_stop() {
  login_uid="$1"
  broker_uid="$(field "$login_uid" broker_uid)"
  signer_uid="$(field "$login_uid" signer_uid)"
  deadline=$((SECONDS + 20))
  while [[ $SECONDS -lt $deadline ]]; do
    if ! pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 &&
      ! pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1
    then
      return
    fi
    sleep 0.1
  done
  echo "two-login W0 services did not stop for login UID $login_uid" >&2
  exit 1
}

assert_unused_enrollment "$login_uid_a"
assert_unused_enrollment "$login_uid_b"

"$installer" install / "$login_uid_a" "$login_user_a" "$payload"
installed_a=true
release_digest="$(field "$login_uid_a" release_digest)"
[[ "$(field "$login_uid_a" state)" == "active" ]]
sudo -u "$login_user_a" \
  "$machine_binary" serve triad-health-check "$release_digest"

# Leave A enrolled and its socket-activated LaunchDaemons loaded, but remove its
# login-session sentinel so B can become the first canonical-listener owner.
launchctl bootout "gui/$login_uid_a/com.bloom.session"
wait_for_services_to_stop "$login_uid_a"
if /usr/bin/nc -z -w 1 127.0.0.1 18734; then
  echo "login A retained the canonical listener after its sentinel stopped" >&2
  exit 1
fi

"$installer" install / "$login_uid_b" "$login_user_b" "$payload"
installed_b=true
[[ "$(field "$login_uid_b" release_digest)" == "$release_digest" ]]
[[ "$(field "$login_uid_b" state)" == "active" ]]
sudo -u "$login_user_b" \
  "$machine_binary" serve triad-health-check "$release_digest"

launchctl bootstrap "gui/$login_uid_a" "$session_plist"
session_socket_a="/private/var/run/bloom/$login_uid_a/session/session.sock"
deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline && ! -S "$session_socket_a" ]]; do
  sleep 0.1
done
[[ -S "$session_socket_a" ]] || {
  echo "login A session sentinel did not return" >&2
  exit 1
}

broker_uid_a="$(field "$login_uid_a" broker_uid)"
machine_broker_gid_a="$(field "$login_uid_a" machine_broker_gid)"
startup_status_a="/private/var/run/bloom/$login_uid_a/status/broker-startup.json"

if [[ -n "$upgrade_payload" ]]; then
  prior_digest="$release_digest"
  upgrade_digest="$(payload_release_digest "$upgrade_payload")"
  [[ "$upgrade_digest" != "$prior_digest" ]]
  "$installer" install / "$login_uid_a" "$login_user_a" "$upgrade_payload"
  for login_uid in "$login_uid_a" "$login_uid_b"; do
    [[ "$(field "$login_uid" release_digest)" == "$upgrade_digest" ]] || {
      echo "two-login upgrade did not publish one complete release" >&2
      exit 1
    }
  done
  [[ "$(readlink /usr/local/libexec/bloom/current)" == \
    "releases/$upgrade_digest" ]]
  release_digest="$upgrade_digest"
  tested_payload="$upgrade_payload"

  if [[ -n "$failing_upgrade_payload" ]]; then
    failing_digest="$(payload_release_digest "$failing_upgrade_payload")"
    [[ "$failing_digest" != "$release_digest" ]]
    set +e
    "$installer" install \
      / \
      "$login_uid_a" \
      "$login_user_a" \
      "$failing_upgrade_payload"
    failing_status=$?
    set -e
    [[ "$failing_status" -ne 0 ]] || {
      echo "two-login failing upgrade unexpectedly committed" >&2
      exit 1
    }
    [[ ! -e "/Library/Application Support/BloomTriad/upgrade-transaction" ]] || {
      echo "two-login failing upgrade left an unrecovered transaction" >&2
      exit 1
    }
    for login_uid in "$login_uid_a" "$login_uid_b"; do
      [[ "$(field "$login_uid" release_digest)" == "$release_digest" ]] || {
        echo "two-login upgrade rollback split the installed release" >&2
        exit 1
      }
    done
    [[ "$(readlink /usr/local/libexec/bloom/current)" == \
      "releases/$release_digest" ]]
  fi

  # Sequential upgrade validation deliberately leaves the ordinary loaded-job
  # set restored. Normalize B as owner so the cross-login fatal path below has
  # a deterministic second Broker.
  broker_label_a="system/com.bloom.broker.$login_uid_a"
  broker_label_b="system/com.bloom.broker.$login_uid_b"
  broker_plist_a="/Library/LaunchDaemons/com.bloom.broker.$login_uid_a.plist"
  broker_plist_b="/Library/LaunchDaemons/com.bloom.broker.$login_uid_b.plist"
  launchctl bootout "$broker_label_a" 2>/dev/null || true
  launchctl bootout "$broker_label_b" 2>/dev/null || true
  launchctl bootstrap system "$broker_plist_b"
  deadline=$((SECONDS + 20))
  while [[ $SECONDS -lt $deadline ]]; do
    if sudo -u "$login_user_b" \
      "$machine_binary" serve triad-health-check "$release_digest"
    then
      break
    fi
    sleep 1
  done
  sudo -u "$login_user_b" \
    "$machine_binary" serve triad-health-check "$release_digest"
  launchctl bootstrap system "$broker_plist_a"
fi

deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline && ! -f "$startup_status_a" ]]; do
  sleep 0.1
done
[[ -f "$startup_status_a" ]] || {
  echo "second Broker did not publish its fatal listener incident" >&2
  exit 1
}

if machine_failure="$(
  sudo -u "$login_user_a" \
    "$machine_binary" serve triad-health-check "$release_digest" 2>&1
)"
then
  echo "second Broker reported healthy while login B owned the canonical listener" >&2
  exit 1
fi
grep -F \
  'Bloom Broker startup failed: another login session owns the Bloom ceremony listener' \
  <<<"$machine_failure" >/dev/null

[[ "$(stat -f '%u:%g:%Lp' "$startup_status_a")" == \
  "$broker_uid_a:$machine_broker_gid_a:640" ]]
[[ "$(plutil -extract schema raw -o - "$startup_status_a")" == \
  "bloom.broker-startup.1" ]]
[[ "$(plutil -extract state raw -o - "$startup_status_a")" == "fatal" ]]
[[ "$(plutil -extract incident raw -o - "$startup_status_a")" == \
  "another_login_session" ]]
[[ "$(plutil -extract message raw -o - "$startup_status_a")" == \
  "another login session owns the Bloom ceremony listener" ]]
if lsof -nP -a -u "bloom-broker-$login_uid_a" -iTCP -sTCP:LISTEN |
  grep . >/dev/null
then
  echo "second Broker opened a fallback TCP listener" >&2
  exit 1
fi
sudo -u "$login_user_b" \
  "$machine_binary" serve triad-health-check "$release_digest"

# End B's complete GUI launchd domain. A's already-failed Broker must acquire
# the freed port through failure-only KeepAlive before any new Machine request.
launchctl bootout "gui/$login_uid_b"
deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline ]]; do
  if ! launchctl print "gui/$login_uid_b" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if launchctl print "gui/$login_uid_b" >/dev/null 2>&1; then
  echo "login B GUI domain did not terminate" >&2
  exit 1
fi
wait_for_services_to_stop "$login_uid_b"

deadline=$((SECONDS + 30))
while [[ $SECONDS -lt $deadline ]]; do
  if lsof -nP -a -u "bloom-broker-$login_uid_a" \
    -iTCP@127.0.0.1:18734 -sTCP:LISTEN |
    grep 18734 >/dev/null
  then
    break
  fi
  sleep 0.25
done
lsof -nP -a -u "bloom-broker-$login_uid_a" \
  -iTCP@127.0.0.1:18734 -sTCP:LISTEN |
  grep 18734 >/dev/null || {
  echo "waiting Broker did not acquire the canonical listener through KeepAlive" >&2
  exit 1
}
[[ ! -e "$startup_status_a" ]] || {
  echo "waiting Broker retained its startup failure after acquiring the listener" >&2
  exit 1
}
sudo -u "$login_user_a" \
  "$machine_binary" serve triad-health-check "$release_digest"

if [[ -n "${BLOOM_MACOS_W0_EVIDENCE_DIR:-}" ]]; then
  evidence_dir="$BLOOM_MACOS_W0_EVIDENCE_DIR"
  [[ "$evidence_dir" == /* && -d "$evidence_dir" && ! -L "$evidence_dir" ]] || {
    echo "BLOOM_MACOS_W0_EVIDENCE_DIR must be an existing absolute directory" >&2
    exit 65
  }
  subject_digest="$(
    "$triad_source/release/macos-conformance-subject.sh" "$tested_payload"
  )"
  for criterion in mui_05 mui_06 two_login_lifecycle; do
    temporary="$evidence_dir/.$criterion.$$.new"
    printf '%s\n' "$subject_digest" > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$evidence_dir/$criterion.pass"
  done
  if [[ -n "$upgrade_payload" && -n "$failing_upgrade_payload" ]]; then
    temporary="$evidence_dir/.mui_09.$$.new"
    printf '%s\n' "$subject_digest" > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$evidence_dir/mui_09.pass"
  fi
fi

echo "two-login macOS Unix-principal W0 passed"
