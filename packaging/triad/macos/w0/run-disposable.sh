#!/usr/bin/env bash
set -Eeuo pipefail

report_error() {
  status=$?
  echo "macOS W0 failed at line ${BASH_LINENO[0]} (status $status)" >&2
  return "$status"
}
trap report_error ERR

usage() {
  echo "usage: run-disposable.sh PAYLOAD_DIR LOGIN_UID LOGIN_USER" >&2
  exit 64
}

[[ $# -eq 3 ]] || usage
payload="$(cd "$1" && pwd -P)"
login_uid="$2"
login_user="$3"
[[ "$login_uid" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || usage

[[ "$EUID" -eq 0 && "$(uname -s)" == "Darwin" ]] || {
  echo "W0 requires root on a disposable macOS host" >&2
  exit 77
}
marker="/private/var/db/bloom-w0-disposable-host"
if [[ "${BLOOM_RUN_MACOS_UNIX_W0:-}" != "true" ]] ||
  [[ ! -f "$marker" || -L "$marker" ]] ||
  ! grep -Fx 'bloom-macos-unix-w0-disposable-v1' "$marker" >/dev/null
then
  echo "W0 host is not explicitly marked disposable" >&2
  exit 77
fi
[[ "$(<"$payload/PLATFORM_CLAIM")" == "macos-unix-principals-w0" ]] || {
  echo "W0 payload has the wrong platform claim" >&2
  exit 65
}
[[ "$(id -u "$login_user")" == "$login_uid" ]] || {
  echo "W0 login name and UID do not match" >&2
  exit 65
}
launchctl print "gui/$login_uid" >/dev/null 2>&1 || {
  echo "W0 requires an active GUI login for the selected user" >&2
  exit 69
}

triad_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
installer="$triad_source/release/install-macos.sh"
enrollment="/Library/Application Support/BloomTriad/enrollments/$login_uid.json"
rotation_fixtures="$(mktemp -d /private/tmp/bloom-w0-rotation.XXXXXX)"
process_probe_dir="$(mktemp -d /private/tmp/bloom-w0-process.XXXXXX)"
foreign_listener_pid=""
network_listener_pid=""
hostile_session_pid=""
edge_manifest=""
edge_backup=""

capture_failure_evidence() {
  evidence_dir="${BLOOM_MACOS_W0_EVIDENCE_DIR:-}"
  [[ -n "$evidence_dir" && -d "$evidence_dir" ]] || return 0
  for service in broker signer; do
    source_log="/private/var/db/bloom/$login_uid/$service/$service.log"
    if [[ -f "$source_log" && ! -L "$source_log" ]]; then
      install -m 0644 "$source_log" "$evidence_dir/$service.log" || true
    fi
    launchctl print "system/com.bloom.$service.$login_uid" \
      > "$evidence_dir/$service-launchctl.txt" 2>&1 || true
    chmod 0644 "$evidence_dir/$service-launchctl.txt" 2>/dev/null || true
  done
  launchctl print "gui/$login_uid/com.bloom.session" \
    > "$evidence_dir/session-launchctl.txt" 2>&1 || true
  chmod 0644 "$evidence_dir/session-launchctl.txt" 2>/dev/null || true
  find "/private/var/run/bloom/$login_uid" -xdev -ls \
    > "$evidence_dir/runtime-tree.txt" 2>&1 || true
  chmod 0644 "$evidence_dir/runtime-tree.txt" 2>/dev/null || true
}

cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    capture_failure_evidence
  fi
  if [[ -n "$hostile_session_pid" ]]; then
    kill "$hostile_session_pid" 2>/dev/null || true
    wait "$hostile_session_pid" 2>/dev/null || true
  fi
  if [[ -n "$network_listener_pid" ]]; then
    kill "$network_listener_pid" 2>/dev/null || true
    wait "$network_listener_pid" 2>/dev/null || true
  fi
  if [[ -n "$foreign_listener_pid" ]]; then
    kill "$foreign_listener_pid" 2>/dev/null || true
    wait "$foreign_listener_pid" 2>/dev/null || true
  fi
  if [[ -n "$edge_backup" && -e "$edge_backup" ]]; then
    rm -f -- "$edge_manifest"
    mv "$edge_backup" "$edge_manifest"
  fi
  if [[ -n "$edge_manifest" && -f "$edge_manifest" && ! -L "$edge_manifest" ]]; then
    chown root:wheel "$edge_manifest" 2>/dev/null || true
    chmod 0644 "$edge_manifest" 2>/dev/null || true
  fi
  if [[ -f "$enrollment" ]]; then
    "$installer" uninstall / "$login_uid" "delete-bloom-login-$login_uid" || true
  fi
  rm -rf -- "$rotation_fixtures" "$process_probe_dir"
  exit "$status"
}
trap cleanup EXIT

echo "macOS W0 preflight passed; checking fresh service-principal names"
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
    echo "W0 refuses to adopt pre-existing Directory Service record $kind/$name" >&2
    exit 65
  fi
done

echo "macOS W0 installing the verified candidate"
"$installer" install / "$login_uid" "$login_user" "$payload"

field() {
  plutil -extract "$1" raw -o - "$enrollment"
}

broker_uid="$(field broker_uid)"
signer_uid="$(field signer_uid)"
broker_gid="$(field broker_gid)"
signer_gid="$(field signer_gid)"
machine_broker_gid="$(field machine_broker_gid)"
broker_signer_gid="$(field broker_signer_gid)"
revoke_gid="$(field revoke_gid)"
[[ "$(field state)" == "active" ]] || {
  echo "installer published the enrollment before activation completed" >&2
  exit 1
}

assert_record() {
  kind="$1"
  name="$2"
  attribute="$3"
  expected="$4"
  record="$(dscl -plist . -read "/$kind/$name" "$attribute")"
  if observed="$(
    plutil -extract "dsAttrTypeStandard:$attribute".0 raw -o - - <<<"$record" 2>/dev/null
  )"; then
    attribute_key="dsAttrTypeStandard:$attribute"
  elif observed="$(
    plutil -extract "dsAttrTypeNative:$attribute".0 raw -o - - <<<"$record" 2>/dev/null
  )"; then
    attribute_key="dsAttrTypeNative:$attribute"
  else
    echo "$kind/$name is missing required attribute $attribute" >&2
    exit 1
  fi
  if plutil -type "$attribute_key".1 -o - - <<<"$record" >/dev/null 2>&1; then
    echo "$kind/$name has multiple values for $attribute" >&2
    exit 1
  fi
  [[ "$observed" == "$expected" ]] || {
    echo "$kind/$name $attribute: expected $expected, observed $observed" >&2
    exit 1
  }
}

assert_record Users "bloom-broker-$login_uid" UniqueID "$broker_uid"
assert_record Users "bloom-broker-$login_uid" PrimaryGroupID "$broker_gid"
assert_record Users "bloom-broker-$login_uid" IsHidden 1
assert_record Users "bloom-broker-$login_uid" UserShell /usr/bin/false
assert_record Users "bloom-signer-$login_uid" UniqueID "$signer_uid"
assert_record Users "bloom-signer-$login_uid" PrimaryGroupID "$signer_gid"
assert_record Users "bloom-signer-$login_uid" IsHidden 1
assert_record Users "bloom-signer-$login_uid" UserShell /usr/bin/false

dseditgroup -o checkmember -m "$login_user" "bloom-machine-broker-$login_uid" >/dev/null
dseditgroup -o checkmember -m "bloom-broker-$login_uid" "bloom-machine-broker-$login_uid" >/dev/null
dseditgroup -o checkmember -m "bloom-broker-$login_uid" "bloom-broker-signer-$login_uid" >/dev/null
dseditgroup -o checkmember -m "bloom-signer-$login_uid" "bloom-broker-signer-$login_uid" >/dev/null
if dseditgroup -o checkmember -m "$login_user" "bloom-broker-signer-$login_uid" >/dev/null 2>&1; then
  echo "Machine login unexpectedly belongs to the Broker-Signer group" >&2
  exit 1
fi

assert_metadata() {
  path="$1"
  expected="$2"
  observed="$(stat -f '%u:%g:%Lp' "$path")"
  [[ "$observed" == "$expected" ]] || {
    echo "$path: expected $expected, observed $observed" >&2
    exit 1
  }
}

assert_metadata "/private/var/db/bloom/$login_uid/broker" "$broker_uid:$broker_gid:700"
assert_metadata "/private/var/db/bloom/$login_uid/signer" "$signer_uid:$signer_gid:700"
assert_metadata "/private/var/run/bloom/$login_uid" "0:0:711"
assert_metadata "/private/var/run/bloom/$login_uid/containment" "0:0:755"
assert_metadata \
  "/private/var/run/bloom/$login_uid/machine-broker" \
  "$broker_uid:$machine_broker_gid:710"
assert_metadata \
  "/private/var/run/bloom/$login_uid/broker-signer" \
  "$signer_uid:$broker_signer_gid:710"
assert_metadata "/private/var/run/bloom/$login_uid/revoke" "0:0:711"
assert_metadata \
  "/private/var/run/bloom/$login_uid/revoke/broker" \
  "$broker_uid:$revoke_gid:710"
assert_metadata \
  "/private/var/run/bloom/$login_uid/revoke/signer" \
  "$signer_uid:$revoke_gid:710"
assert_metadata \
  "/private/var/run/bloom/$login_uid/session" \
  "$login_uid:$revoke_gid:710"
assert_metadata \
  "/private/var/run/bloom/$login_uid/status" \
  "$broker_uid:$machine_broker_gid:750"

broker_probe="/private/var/db/bloom/$login_uid/broker/w0-private"
signer_probe="/private/var/db/bloom/$login_uid/signer/w0-private"
broker_checkpoint_probe="/private/var/db/bloom/$login_uid/broker/audit-checkpoints/w0-private"
signer_checkpoint_probe="/private/var/db/bloom/$login_uid/signer/audit-checkpoints/w0-private"
install -o "bloom-broker-$login_uid" -g "bloom-broker-$login_uid" -m 0600 /dev/null "$broker_probe"
install -o "bloom-signer-$login_uid" -g "bloom-signer-$login_uid" -m 0600 /dev/null "$signer_probe"
install \
  -o "bloom-broker-$login_uid" \
  -g "bloom-broker-$login_uid" \
  -m 0600 \
  /dev/null \
  "$broker_checkpoint_probe"
install \
  -o "bloom-signer-$login_uid" \
  -g "bloom-signer-$login_uid" \
  -m 0600 \
  /dev/null \
  "$signer_checkpoint_probe"
sudo -u "$login_user" test ! -r "$broker_probe"
sudo -u "$login_user" test ! -r "$signer_probe"
sudo -u "$login_user" test ! -r "$broker_checkpoint_probe"
sudo -u "$login_user" test ! -r "$signer_checkpoint_probe"
sudo -u "bloom-broker-$login_uid" test ! -r "$signer_probe"
sudo -u "bloom-broker-$login_uid" test ! -r "$signer_checkpoint_probe"
sudo -u "bloom-signer-$login_uid" test ! -r "$broker_probe"
sudo -u "bloom-signer-$login_uid" test ! -r "$broker_checkpoint_probe"
rm -f -- "$broker_checkpoint_probe" "$signer_checkpoint_probe"
sudo -u "$login_user" test ! -r \
  "/Library/Application Support/BloomTriad/config/$login_uid/installer/identity.json"
sudo -u "$login_user" test ! -r \
  "/Library/Application Support/BloomTriad/config/$login_uid/broker/identity.json"
sudo -u "$login_user" test ! -r \
  "/Library/Application Support/BloomTriad/config/$login_uid/signer/identity.json"
sudo -u "$login_user" test ! -r \
  "/private/var/db/bloom/$login_uid/signer/signer.db"
sudo -u "bloom-broker-$login_uid" test ! -r \
  "/Library/Application Support/BloomTriad/config/$login_uid/signer/config.json"
sudo -u "bloom-broker-$login_uid" test ! -r \
  "/private/var/db/bloom/$login_uid/signer/signer.db"
sudo -u "bloom-signer-$login_uid" test ! -r \
  "/Library/Application Support/BloomTriad/config/$login_uid/broker/config.json"

launchctl print "system/com.bloom.broker.$login_uid" >/dev/null
launchctl print "system/com.bloom.signer.$login_uid" >/dev/null
launchctl print "gui/$login_uid/com.bloom.session" >/dev/null

broker_checkpoint_dir="/private/var/db/bloom/$login_uid/broker/audit-checkpoints"
signer_checkpoint_dir="/private/var/db/bloom/$login_uid/signer/audit-checkpoints"
first_checkpoint() {
  for candidate in "$1"/*.jcs; do
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}
for attempt in {1..100}; do
  broker_checkpoint="$(first_checkpoint "$broker_checkpoint_dir" || true)"
  signer_checkpoint="$(first_checkpoint "$signer_checkpoint_dir" || true)"
  [[ -n "$broker_checkpoint" && -n "$signer_checkpoint" ]] && break
  sleep 0.1
done
[[ -n "${broker_checkpoint:-}" && -n "${signer_checkpoint:-}" ]] || {
  echo "Broker/Signer did not persist their initial authenticated peer audit heads" >&2
  exit 1
}
assert_metadata "$broker_checkpoint" "$broker_uid:$broker_gid:600"
assert_metadata "$signer_checkpoint" "$signer_uid:$signer_gid:600"
sudo -u "$login_user" test ! -r "$broker_checkpoint"
sudo -u "$login_user" test ! -r "$signer_checkpoint"
sudo -u "bloom-broker-$login_uid" test ! -r "$signer_checkpoint"
sudo -u "bloom-signer-$login_uid" test ! -r "$broker_checkpoint"

pf_rules="$(pfctl -a "com.bloom.triad/$login_uid" -sr)"
assert_pf_principal() {
  principal_uid="$1"
  principal_name="$2"
  grep -E \
    "user[[:space:]]+(=[[:space:]]+)?(<?$principal_uid|$principal_name)([[:space:]]|$)" \
    <<<"$pf_rules" >/dev/null || {
    echo "loaded Bloom pf rules omit $principal_name ($principal_uid):" >&2
    printf '%s\n' "$pf_rules" >&2
    exit 1
  }
}
assert_pf_principal "$broker_uid" "bloom-broker-$login_uid"
assert_pf_principal "$signer_uid" "bloom-signer-$login_uid"

for socket in \
  "/private/var/run/bloom/$login_uid/machine-broker/broker.sock" \
  "/private/var/run/bloom/$login_uid/broker-signer/signer.sock" \
  "/private/var/run/bloom/$login_uid/revoke/broker/control.sock" \
  "/private/var/run/bloom/$login_uid/revoke/signer/control.sock" \
  "/private/var/run/bloom/$login_uid/session/session.sock"
do
  deadline=$((SECONDS + 20))
  while [[ ! -S "$socket" && $SECONDS -lt $deadline ]]; do
    sleep 1
  done
  [[ -S "$socket" ]] || {
    echo "Bloom service did not create $socket" >&2
    exit 1
  }
done

assert_metadata \
  "/private/var/run/bloom/$login_uid/machine-broker/broker.sock" \
  "$broker_uid:$machine_broker_gid:660"
assert_metadata \
  "/private/var/run/bloom/$login_uid/broker-signer/signer.sock" \
  "$signer_uid:$broker_signer_gid:660"
assert_metadata \
  "/private/var/run/bloom/$login_uid/revoke/broker/control.sock" \
  "$broker_uid:$revoke_gid:660"
assert_metadata \
  "/private/var/run/bloom/$login_uid/revoke/signer/control.sock" \
  "$signer_uid:$revoke_gid:660"
assert_metadata \
  "/private/var/run/bloom/$login_uid/session/session.sock" \
  "$login_uid:$revoke_gid:660"

release_digest="$(field release_digest)"
machine_binary="/usr/local/libexec/bloom/current/bloom"
session_socket="/private/var/run/bloom/$login_uid/session/session.sock"
session_label="gui/$login_uid/com.bloom.session"
session_plist="/Library/LaunchAgents/com.bloom.session.plist"
broker_label="system/com.bloom.broker.$login_uid"
signer_label="system/com.bloom.signer.$login_uid"

edge_manifest="/Library/Application Support/BloomTriad/config/$login_uid/edge-manifest.json"
run_reinstall_with_substitution() {
  set +e
  "$installer" install / "$login_uid" "$login_user" "$payload"
  substitution_status=$?
  set -e
}

assert_substitution_rejected() {
  substitution="$1"
  [[ "$substitution_status" -ne 0 ]] || {
    echo "installer accepted $substitution edge-manifest tampering" >&2
    exit 1
  }
}

chmod 0666 "$edge_manifest"
run_reinstall_with_substitution
chmod 0644 "$edge_manifest"
assert_substitution_rejected mode

chown "$login_user" "$edge_manifest"
run_reinstall_with_substitution
chown root:wheel "$edge_manifest"
assert_substitution_rejected owner

edge_backup="$rotation_fixtures/edge-manifest.json"
mv "$edge_manifest" "$edge_backup"
ln -s "$edge_backup" "$edge_manifest"
run_reinstall_with_substitution
rm "$edge_manifest"
mv "$edge_backup" "$edge_manifest"
assert_substitution_rejected symlink

mv "$edge_manifest" "$edge_backup"
ln "$edge_backup" "$edge_manifest"
run_reinstall_with_substitution
rm "$edge_manifest"
mv "$edge_backup" "$edge_manifest"
assert_substitution_rejected hard-link
assert_metadata "$edge_manifest" "0:0:644"
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"

unrelated_user="nobody"
id "$unrelated_user" >/dev/null 2>&1 || {
  echo "W0 cannot resolve the unrelated local nobody principal" >&2
  exit 69
}
for socket in \
  "/private/var/run/bloom/$login_uid/machine-broker/broker.sock" \
  "/private/var/run/bloom/$login_uid/broker-signer/signer.sock" \
  "/private/var/run/bloom/$login_uid/revoke/broker/control.sock" \
  "/private/var/run/bloom/$login_uid/revoke/signer/control.sock"
do
  if sudo -u "$unrelated_user" /usr/bin/nc -z -w 1 -U "$socket"; then
    echo "unrelated local UID opened protected Unix endpoint $socket" >&2
    exit 1
  fi
done
if sudo -u "$login_user" \
  /usr/bin/nc -z -w 1 -U \
  "/private/var/run/bloom/$login_uid/broker-signer/signer.sock"
then
  echo "Machine login opened the Broker-to-Signer data endpoint" >&2
  exit 1
fi

assert_principal_cannot_replace() {
  principal="$1"
  protected_path="$2"
  sudo -u "$principal" test ! -w "$protected_path"
  sudo -u "$principal" test ! -w "$(dirname "$protected_path")"
}

for protected_path in \
  "$machine_binary" \
  "/Library/LaunchDaemons/com.bloom.broker.$login_uid.plist" \
  "/Library/LaunchDaemons/com.bloom.signer.$login_uid.plist" \
  "$session_plist" \
  "/Library/Application Support/BloomTriad/config/$login_uid/edge-manifest.json" \
  "/etc/pf.anchors/com.bloom.triad.$login_uid"
do
  for principal in \
    "$login_user" \
    "bloom-broker-$login_uid" \
    "bloom-signer-$login_uid"
  do
    assert_principal_cannot_replace "$principal" "$protected_path"
  done
done

chmod 0755 "$process_probe_dir"
/usr/bin/xcrun --sdk macosx clang \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  "$triad_source/macos/w0/task-access-probe.c" \
  -o "$process_probe_dir/task-access-probe"
chmod 0755 "$process_probe_dir/task-access-probe"
for service_and_uid in \
  "broker $broker_uid" \
  "signer $signer_uid"
do
  service="${service_and_uid%% *}"
  service_uid="${service_and_uid#* }"
  service_pid="$(pgrep -u "$service_uid" -x "bloom-$service" | head -n 1)"
  [[ "$service_pid" =~ ^[1-9][0-9]*$ ]] || {
    echo "W0 could not resolve the live $service PID" >&2
    exit 1
  }
  if sudo -u "$login_user" \
    "$process_probe_dir/task-access-probe" "$service_pid"
  then
    echo "Machine login obtained task access to $service" >&2
    exit 1
  fi
  sample_output="$process_probe_dir/sample-$service_pid.txt"
  install \
    -o "$login_user" \
    -g "$(id -gn "$login_user")" \
    -m 0600 \
    /dev/null \
    "$sample_output"
  set +e
  sudo -u "$login_user" \
    /usr/bin/sample "$service_pid" 1 1 -file "$sample_output" \
    >/dev/null 2>&1
  sample_status=$?
  set -e
  if [[ "$sample_status" -eq 0 ]] ||
    grep -F 'Call graph:' "$sample_output" >/dev/null 2>&1
  then
    echo "Machine login sampled $service process memory" >&2
    exit 1
  fi
done

sudo -u "$login_user" \
  /usr/bin/nc -d -U "$session_socket" >/dev/null 2>&1 &
hostile_session_pid=$!
deadline=$((SECONDS + 5))
while kill -0 "$hostile_session_pid" 2>/dev/null &&
  [[ $SECONDS -lt $deadline ]]
do
  sleep 0.05
done
if kill -0 "$hostile_session_pid" 2>/dev/null; then
  echo "session sentinel did not reject an unauthorized login-UID peer" >&2
  exit 1
fi
wait "$hostile_session_pid" 2>/dev/null || true
hostile_session_pid=""
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"

launchctl bootout "$session_label"
deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline ]]; do
  if ! pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 &&
    ! pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1
  then
    break
  fi
  sleep 0.1
done
if pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 ||
  pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1
then
  echo "services did not drain after the login-session sentinel disappeared" >&2
  exit 1
fi
if curl --silent --max-time 1 http://127.0.0.1:18734/ >/dev/null 2>&1; then
  echo "Broker retained the ceremony listener after session logout" >&2
  exit 1
fi
launchctl print "$broker_label" >/dev/null
launchctl print "$signer_label" >/dev/null
launchctl bootstrap "gui/$login_uid" "$session_plist"
deadline=$((SECONDS + 20))
while [[ $SECONDS -lt $deadline ]]; do
  if [[ -S "$session_socket" ]] &&
    sudo -u "$login_user" \
      "$machine_binary" \
      serve triad-health-check \
      "$release_digest"
  then
    break
  fi
  sleep 1
done
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"

ceremony_headers=""
deadline=$((SECONDS + 20))
while [[ $SECONDS -lt $deadline ]]; do
  if ceremony_headers="$(
    curl --silent --show-error --max-time 2 --dump-header - \
      --output /dev/null http://127.0.0.1:18734/ 2>/dev/null
  )" &&
    grep -Fi \
      'x-bloom-ceremony-owner: bloom-broker-v1' \
      <<<"$ceremony_headers" >/dev/null
  then
    break
  fi
  sleep 1
done
grep -Fi \
  'x-bloom-ceremony-owner: bloom-broker-v1' \
  <<<"$ceremony_headers" >/dev/null || {
  echo "Broker did not publish the canonical ceremony-owner marker" >&2
  exit 1
}

broker_plist="/Library/LaunchDaemons/com.bloom.broker.$login_uid.plist"
broker_log="/private/var/db/bloom/$login_uid/broker/broker.log"
broker_state="/private/var/db/bloom/$login_uid/broker"
broker_startup_status="/private/var/run/bloom/$login_uid/status/broker-startup.json"
containment_status="/private/var/run/bloom/$login_uid/containment/status.json"
launchctl bootout "$broker_label"
broker_durable_before="$(
  find "$broker_state" -type f ! -name broker.log -exec shasum -a 256 {} \; |
    LC_ALL=C sort |
    shasum -a 256 |
    awk '{print $1}'
)"
/usr/bin/nc -lk 127.0.0.1 18734 >/dev/null 2>&1 &
foreign_listener_pid=$!
deadline=$((SECONDS + 10))
while [[ $SECONDS -lt $deadline ]]; do
  lsof -nP -a -p "$foreign_listener_pid" -iTCP@127.0.0.1:18734 -sTCP:LISTEN |
    grep 18734 >/dev/null && break
  sleep 0.05
done
kill -0 "$foreign_listener_pid"
# Broker has been deliberately unloaded, so the containment monitor cannot
# publish a new healthy attestation for that enrollment. Wait beyond the exact
# configured freshness bound before restarting Broker. The stale prior
# Bloom-owner observation must not classify this non-Bloom listener as another
# login session.
containment_maximum_age_ms="$(
  plutil -extract network_containment.maximum_age_ms raw -o - \
    "/Library/Application Support/BloomTriad/config/$login_uid/broker/config.json"
)"
[[ "$containment_maximum_age_ms" =~ ^[1-9][0-9]*$ ]]
sleep "$(( (containment_maximum_age_ms + 999) / 1000 + 1 ))"
launchctl bootstrap system "$broker_plist"
deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline ]]; do
  if grep -F \
    'fatal canonical ceremony listener ownership conflict at 127.0.0.1:18734; no fallback port will be used' \
    "$broker_log" >/dev/null 2>&1
  then
    break
  fi
  sleep 0.1
done
grep -F \
  'fatal canonical ceremony listener ownership conflict at 127.0.0.1:18734; no fallback port will be used' \
  "$broker_log" >/dev/null
assert_metadata \
  "$broker_startup_status" \
  "$broker_uid:$machine_broker_gid:640"
[[ "$(plutil -extract schema raw -o - "$broker_startup_status")" == \
  "bloom.broker-startup.1" ]]
[[ "$(plutil -extract state raw -o - "$broker_startup_status")" == "fatal" ]]
[[ "$(plutil -extract incident raw -o - "$broker_startup_status")" == \
  "foreign_or_unverifiable_process" ]]
[[ "$(plutil -extract address raw -o - "$broker_startup_status")" == \
  "127.0.0.1:18734" ]]
[[ "$(plutil -extract message raw -o - "$broker_startup_status")" == \
  "a foreign or unverifiable process owns the Bloom ceremony listener" ]]
if foreign_machine_failure="$(
  sudo -u "$login_user" \
    "$machine_binary" \
    serve triad-health-check "$release_digest" 2>&1
)"
then
  echo "Machine reported healthy while a foreign process owned the ceremony port" >&2
  exit 1
fi
if ! grep -F \
  'Bloom Broker startup failed: a foreign or unverifiable process owns the Bloom ceremony listener' \
  <<<"$foreign_machine_failure" >/dev/null
then
  echo "Machine did not report the authenticated foreign-listener diagnostic:" >&2
  printf '%s\n' "$foreign_machine_failure" >&2
  stat -f 'startup diagnostic metadata: %u:%g:%Lp links=%l bytes=%z' \
    "$broker_startup_status" >&2
  echo "startup diagnostic content:" >&2
  sudo -u "$login_user" cat "$broker_startup_status" >&2 || true
  exit 1
fi
if lsof -nP -a -u "bloom-broker-$login_uid" -iTCP -sTCP:LISTEN |
  grep . >/dev/null
then
  echo "Broker opened a fallback TCP listener after the canonical bind conflict" >&2
  exit 1
fi
broker_durable_after="$(
  find "$broker_state" -type f ! -name broker.log -exec shasum -a 256 {} \; |
    LC_ALL=C sort |
    shasum -a 256 |
    awk '{print $1}'
)"
[[ "$broker_durable_after" == "$broker_durable_before" ]] || {
  echo "a Broker that lost the canonical listener mutated durable authority state" >&2
  exit 1
}
kill "$foreign_listener_pid"
wait "$foreign_listener_pid" 2>/dev/null || true
foreign_listener_pid=""
# Multiple fatal starts while the port is occupied can put launchd into a
# failure-backoff interval. Prove failure-only KeepAlive recovery without
# imposing a shorter deadline than launchd's scheduler.
deadline=$((SECONDS + 60))
while [[ $SECONDS -lt $deadline ]]; do
  if sudo -u "$login_user" \
    "$machine_binary" \
    serve triad-health-check \
    "$release_digest"
  then
    break
  fi
  sleep 1
done
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"
[[ ! -e "$broker_startup_status" ]] || {
  echo "Broker retained a stale startup diagnostic after acquiring the listener" >&2
  exit 1
}

if sudo -u "bloom-signer-$login_uid" \
  /usr/bin/nc -z -G 2 -w 2 127.0.0.1 18734
then
  echo "Signer opened a forbidden IPv4 loopback TCP connection" >&2
  exit 1
fi

/usr/bin/nc -6 -l ::1 18735 >/dev/null 2>&1 &
network_listener_pid=$!
sleep 0.2
kill -0 "$network_listener_pid"
if sudo -u "bloom-signer-$login_uid" \
  /usr/bin/nc -6 -z -G 2 -w 2 ::1 18735
then
  echo "Signer opened a forbidden IPv6 loopback TCP connection" >&2
  exit 1
fi
kill "$network_listener_pid"
wait "$network_listener_pid" 2>/dev/null || true
network_listener_pid=""

default_interface="$(
  route -n get default |
    awk '$1 == "interface:" { print $2; exit }'
)"
host_ipv4="$(ipconfig getifaddr "$default_interface")"
[[ -n "$host_ipv4" && "$host_ipv4" != 127.* ]] || {
  echo "W0 could not resolve a non-loopback IPv4 test address" >&2
  exit 69
}
/usr/bin/nc -l "$host_ipv4" 18736 >/dev/null 2>&1 &
network_listener_pid=$!
sleep 0.2
kill -0 "$network_listener_pid"
for service_user in "bloom-broker-$login_uid" "bloom-signer-$login_uid"; do
  if sudo -u "$service_user" \
    /usr/bin/nc -z -G 2 -w 2 "$host_ipv4" 18736
  then
    echo "$service_user opened a forbidden non-loopback IPv4 TCP connection" >&2
    exit 1
  fi
done
kill "$network_listener_pid"
wait "$network_listener_pid" 2>/dev/null || true
network_listener_pid=""

assert_udp_blocked() {
  service_user="$1"
  address_family="$2"
  address="$3"
  port="$4"
  probe="$rotation_fixtures/udp-$port"
  : > "$probe"
  /usr/bin/nc "$address_family" -u -l "$address" "$port" > "$probe" 2>/dev/null &
  network_listener_pid=$!
  sleep 0.2
  kill -0 "$network_listener_pid"
  printf 'bloom-w0-udp-probe\n' |
    sudo -u "$service_user" \
      /usr/bin/nc "$address_family" -u -w 1 "$address" "$port" \
      >/dev/null 2>&1 || true
  sleep 0.2
  kill "$network_listener_pid" 2>/dev/null || true
  wait "$network_listener_pid" 2>/dev/null || true
  network_listener_pid=""
  [[ ! -s "$probe" ]] || {
    echo "$service_user emitted a forbidden UDP packet to $address" >&2
    exit 1
  }
}

assert_udp_blocked "bloom-signer-$login_uid" -4 127.0.0.1 18737
assert_udp_blocked "bloom-signer-$login_uid" -6 ::1 18738
assert_udp_blocked "bloom-broker-$login_uid" -4 "$host_ipv4" 18739

assert_metadata "$containment_status" "0:0:644"
deadline=$((SECONDS + 20))
while [[ $SECONDS -lt $deadline ]]; do
  if sudo -u "$login_user" \
    "$machine_binary" \
    serve triad-health-check \
    "$release_digest"
  then
    break
  fi
  sleep 1
done
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"

pfctl -a "com.bloom.triad/$login_uid" -F rules
deadline=$((SECONDS + 10))
while [[ $SECONDS -lt $deadline ]]; do
  if [[ -f "$containment_status" ]] &&
    [[ "$(plutil -extract available raw -o - "$containment_status")" == "false" ]]
  then
    break
  fi
  sleep 1
done
[[ "$(plutil -extract available raw -o - "$containment_status")" == "false" ]] || {
  echo "packet-filter monitor did not report the removed anchor" >&2
  exit 1
}
if sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"
then
  echo "Broker remained ready after its packet-filter anchor disappeared" >&2
  exit 1
fi
pfctl \
  -a "com.bloom.triad/$login_uid" \
  -f "/etc/pf.anchors/com.bloom.triad.$login_uid"
"$machine_binary" serve triad-pf-monitor-once
sudo -u "$login_user" \
  "$machine_binary" \
  serve triad-health-check \
  "$release_digest"

current_good_payload="$payload"
installed_acceptance_inputs=0
for value in \
  "${BLOOM_MACOS_INSTALLED_ACCEPTANCE_MAIN_ROOT:-}" \
  "${BLOOM_MACOS_INSTALLED_ACCEPTANCE_BROKER_ROOT:-}" \
  "${BLOOM_MACOS_INSTALLED_ACCEPTANCE_SIGNER_ROOT:-}" \
  "${BLOOM_MACOS_W0_EVIDENCE_DIR:-}"
do
  [[ -z "$value" ]] || installed_acceptance_inputs=$((installed_acceptance_inputs + 1))
done
if [[ "$installed_acceptance_inputs" -ne 0 ]]; then
  [[ "$installed_acceptance_inputs" -eq 4 ]] || {
    echo "installed acceptance requires all three source roots and the evidence directory" >&2
    exit 65
  }
  "$triad_source/macos/w0/run-installed-acceptance.sh" \
    "$current_good_payload" \
    "$login_uid" \
    "$login_user" \
    "$BLOOM_MACOS_INSTALLED_ACCEPTANCE_MAIN_ROOT" \
    "$BLOOM_MACOS_INSTALLED_ACCEPTANCE_BROKER_ROOT" \
    "$BLOOM_MACOS_INSTALLED_ACCEPTANCE_SIGNER_ROOT" \
    "$BLOOM_MACOS_W0_EVIDENCE_DIR"
fi

"$installer" uninstall / "$login_uid" "delete-bloom-login-$login_uid"
[[ ! -e "$enrollment" ]]
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
    echo "W0 uninstall left Directory Service record $kind/$name" >&2
    exit 1
  fi
done

if [[ -n "${BLOOM_MACOS_W0_EVIDENCE_DIR:-}" ]]; then
  subject_digest="$(
    "$triad_source/release/macos-conformance-subject.sh" "$current_good_payload"
  )"
  for criterion in \
    mui_02 \
    mui_03 \
    mui_04 \
    mui_07 \
    mui_08 \
    mui_10 \
    negative_access
  do
    temporary="$BLOOM_MACOS_W0_EVIDENCE_DIR/.$criterion.$$.new"
    printf '%s\n' "$subject_digest" > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$BLOOM_MACOS_W0_EVIDENCE_DIR/$criterion.pass"
  done
fi

echo "Bloom macOS Unix-principal disposable W0 isolation checks passed"
