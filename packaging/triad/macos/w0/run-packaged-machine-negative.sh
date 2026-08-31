#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: run-packaged-machine-negative.sh MACHINE_BINARY LOGIN_UID LOGIN_USER BROKER_UID SIGNER_UID MACHINE_IDENTITY EDGE_MANIFEST BROKER_ROOT" >&2
  exit 64
}

[[ $# -eq 8 ]] || usage
machine_binary="$1"
login_uid="$2"
login_user="$3"
broker_uid="$4"
signer_uid="$5"
machine_identity="$6"
edge_manifest="$7"
broker_root="$(cd "$8" && pwd -P)"
[[ "$EUID" -eq 0 && "$(uname -s)" == "Darwin" ]] || exit 77
[[ "$login_uid" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$broker_uid" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$signer_uid" =~ ^[1-9][0-9]*$ ]] || usage
[[ -x "$machine_binary" && ! -L "$machine_binary" ]] || exit 65
[[ -f "$machine_identity" && ! -L "$machine_identity" ]] || exit 65
[[ -f "$edge_manifest" && ! -L "$edge_manifest" ]] || exit 65
[[ -f "$broker_root/Cargo.toml" && ! -L "$broker_root/Cargo.toml" ]] || exit 65

marker="/private/var/db/bloom-w0-disposable-host"
if [[ "${BLOOM_RUN_MACOS_UNIX_W0:-}" != "true" ]] ||
  [[ ! -f "$marker" || -L "$marker" ]] ||
  ! grep -Fx 'bloom-macos-unix-w0-disposable-v1' "$marker" >/dev/null
then
  echo "packaged Machine runtime negative requires a disposable W0 host" >&2
  exit 77
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
work="$(mktemp -d /private/tmp/bloom-ma13-runtime.XXXXXX)"
runtime="$work/runtime"
clean_home="$work/clean-home"
broker_socket="$runtime/machine-broker/broker.sock"
signer_socket="/private/var/run/bloom/$login_uid/broker-signer/signer.sock"
signer_socket_dir="$(dirname "$signer_socket")"
machine_socket="$runtime/machine/machine.sock"
mount_dir="$work/mount"
broker_connected="$runtime/machine-broker/connected"
signer_connected="$runtime/hostile-signer/connected"
broker_user="bloom-broker-$login_uid"
signer_user="bloom-signer-$login_uid"
broker_label="system/com.bloom.broker.$login_uid"
broker_plist="/Library/LaunchDaemons/com.bloom.broker.$login_uid.plist"
signer_label="system/com.bloom.signer.$login_uid"
signer_plist="/Library/LaunchDaemons/com.bloom.signer.$login_uid.plist"
broker_listener_pid=""
signer_listener_pid=""
machine_service_pid=""
rpc_fixture_pid=""
fs_usage_pid=""
broker_was_loaded=false
signer_was_loaded=false
signer_socket_dir_owner=""
signer_socket_dir_group=""
signer_socket_dir_mode=""

report_error() {
  local status=$?
  local line="$1"
  echo "packaged Machine runtime negative failed at line $line (status $status)" >&2
  return "$status"
}
trap 'report_error "$LINENO"' ERR

cleanup() {
  status=$?
  trap - ERR EXIT INT TERM
  for pid in "$machine_service_pid" "$broker_listener_pid" "$signer_listener_pid" "$rpc_fixture_pid" "$fs_usage_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if mount | grep -F " on $mount_dir " >/dev/null 2>&1; then
    /sbin/umount "$mount_dir" 2>/dev/null || true
  fi
  chflags -R nouchg "$clean_home" 2>/dev/null || true
  chmod -R u+rwX "$clean_home" 2>/dev/null || true
  if [[ -n "$signer_socket_dir_mode" ]]; then
    chown "$signer_socket_dir_owner:$signer_socket_dir_group" "$signer_socket_dir" \
      2>/dev/null || true
    chmod "$signer_socket_dir_mode" "$signer_socket_dir" 2>/dev/null || true
  fi
  if [[ "$signer_was_loaded" == true ]] &&
    ! launchctl print "$signer_label" >/dev/null 2>&1
  then
    launchctl bootstrap system "$signer_plist" >/dev/null 2>&1 || true
  fi
  if [[ "$broker_was_loaded" == true ]] &&
    ! launchctl print "$broker_label" >/dev/null 2>&1
  then
    launchctl bootstrap system "$broker_plist" >/dev/null 2>&1 || true
  fi
  if mount | grep -F " on $mount_dir " >/dev/null 2>&1; then
    echo "retaining packaged Machine diagnostics because its mount is still active: $work" >&2
    status=1
  else
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

/usr/bin/xcrun --sdk macosx clang \
  -std=c11 -Wall -Wextra -Werror \
  "$script_dir/hostile-unix-listener.c" \
  -o "$work/hostile-unix-listener"
chmod 0755 "$work/hostile-unix-listener"

mkdir -p \
  "$runtime/machine" \
  "$runtime/machine-broker" \
  "$runtime/hostile-signer" \
  "$clean_home" \
  "$mount_dir"
chown "$login_uid" "$runtime/machine"
chown "$broker_uid" "$runtime/machine-broker"
chown "$signer_uid" "$runtime/hostile-signer"
chown -R "$login_uid" "$clean_home"
chown "$login_uid" "$mount_dir"
chmod 0755 \
  "$work" \
  "$runtime" \
  "$runtime/machine" \
  "$runtime/machine-broker" \
  "$runtime/hostile-signer"
chmod 0755 "$mount_dir"
chmod 0700 "$clean_home"

# Build the out-of-process deterministic ceremony driver before tracing the
# packaged Machine. The driver talks only to the real Broker HTTP ceremony
# surface; it cannot mint or stamp a Machine projection.
cargo_binary="${BLOOM_MACOS_ACCEPTANCE_CARGO:-$(command -v cargo)}"
[[ "$cargo_binary" == /* && -x "$cargo_binary" ]] || exit 69
fixture_environment=()
[[ -z "${BLOOM_MACOS_ACCEPTANCE_CARGO_HOME:-}" ]] ||
  fixture_environment+=("CARGO_HOME=$BLOOM_MACOS_ACCEPTANCE_CARGO_HOME")
[[ -z "${BLOOM_MACOS_ACCEPTANCE_RUSTUP_HOME:-}" ]] ||
  fixture_environment+=("RUSTUP_HOME=$BLOOM_MACOS_ACCEPTANCE_RUSTUP_HOME")
[[ -z "${BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR:-}" ]] ||
  fixture_environment+=("CARGO_TARGET_DIR=$BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR")
sudo -H -u "$login_user" env "${fixture_environment[@]}" \
  "$cargo_binary" build \
    --quiet \
    --manifest-path "$broker_root/Cargo.toml" \
    --locked \
    -p bloom-broker-debug-driver
debug_target="${BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR:-$broker_root/target}"
debug_driver="$debug_target/debug/bloom-broker-debug-driver"
[[ -x "$debug_driver" && ! -L "$debug_driver" ]] || exit 69

# The deterministic chain fixture supplies public planning and simulation
# inputs only. Unknown methods fail and broadcast is explicitly forbidden.
rpc_ready="$work/rpc.ready"
/usr/bin/python3 "$script_dir/degraded-json-rpc.py" 0 "$rpc_ready" &
rpc_fixture_pid=$!
deadline=$((SECONDS + 10))
while [[ ! -f "$rpc_ready" && $SECONDS -lt $deadline ]]; do
  kill -0 "$rpc_fixture_pid" 2>/dev/null || exit 1
  sleep 0.05
done
[[ -f "$rpc_ready" ]] || exit 1
rpc_port="$(<"$rpc_ready")"
[[ "$rpc_port" =~ ^[1-9][0-9]*$ ]] || exit 65
mkdir -p "$clean_home/cache"
chown "$login_uid" "$clean_home/cache"
chmod 0700 "$clean_home/cache"
# Keep the test home intentionally small but valid. Degraded authority does not
# bypass normal Machine configuration validation.
printf '%s\n' \
  'default_chain = "anvil"' \
  '' \
  '[petals]' \
  'preinstalled = []' \
  '' \
  '[chains.anvil]' \
  'name = "anvil"' \
  'chain_id = 31337' \
  "rpc_urls = [\"http://127.0.0.1:$rpc_port\"]" \
  'allow_broadcast = true' |
  sudo -u "$login_user" /usr/bin/tee "$clean_home/config.toml" >/dev/null
chmod 0600 "$clean_home/config.toml"

# Poison every legacy authority root before the first packaged Machine process
# starts. Root ownership, mode 000, and user-immutable files make accidental
# open/migration attempts fail loudly; the syscall trace below independently
# proves the Machine never touches them.
legacy_poison_files=(
  "$clean_home/keystore/legacy-poison-keystore.json"
  "$clean_home/auth/auth.sqlite"
  "$clean_home/auth/challenges/legacy-poison-challenge.json"
  "$clean_home/auth/grants/legacy-poison-grant.json"
  "$clean_home/policy-session/legacy-poison-policy-session.json"
  "$clean_home/signer-cache/legacy-poison-signer-cache.bin"
)
legacy_poison_roots=(
  "$clean_home/keystore"
  "$clean_home/auth"
  "$clean_home/auth/challenges"
  "$clean_home/auth/grants"
  "$clean_home/policy-session"
  "$clean_home/signer-cache"
)
for poison in "${legacy_poison_files[@]}"; do
  mkdir -p "$(dirname "$poison")"
  printf 'BLOOM_MA05_LEGACY_AUTHORITY_POISON:%s\n' "$(basename "$poison")" >"$poison"
done
chown -R root:wheel \
  "$clean_home/keystore" \
  "$clean_home/auth" \
  "$clean_home/policy-session" \
  "$clean_home/signer-cache"
find \
  "$clean_home/keystore" \
  "$clean_home/auth" \
  "$clean_home/policy-session" \
  "$clean_home/signer-cache" \
  -type d -exec chmod 000 {} +
for poison in "${legacy_poison_files[@]}"; do
  chmod 000 "$poison"
  chflags uchg "$poison"
done
legacy_manifest() {
  local poison root
  for root in "${legacy_poison_roots[@]}"; do
    printf 'D\t%s\t%s\n' \
      "${root#"$clean_home"/}" \
      "$(stat -f '%u:%g:%Lp:%Sf:%l' "$root")"
  done
  for poison in "${legacy_poison_files[@]}"; do
    printf 'F\t%s\t%s\t%s\n' \
      "${poison#"$clean_home"/}" \
      "$(stat -f '%u:%g:%Lp:%Sf:%z:%l' "$poison")" \
      "$(shasum -a 256 "$poison" | awk '{print $1}')"
  done
}
legacy_manifest >"$work/legacy-before.manifest"

# fs_usage is the strongest practical read/open evidence available in the
# disposable macOS W0 host. Do not give it a command-name filter: a filtered
# fs_usage exits when no matching process exists, but this tracer must span
# every future packaged Bloom process. At the end we post-filter the global
# trace to exact `bloom.<pid>` process columns before inspecting paths. That
# also excludes setup activity from mkdir, chmod, jq, the debug driver, etc.
/usr/bin/fs_usage -w -f pathname >"$work/all-fs-usage.log" 2>&1 &
fs_usage_pid=$!
sleep 0.2
kill -0 "$fs_usage_pid"

# Create the public fixture wallet through the installed Machine -> real
# authenticated Broker -> real Signer custody path, complete its ceremony with
# the separate deterministic authenticator, and then fetch the projection over
# the authenticated Machine-Broker transport. Nothing in this path can stamp
# AuthenticatedBroker locally.
authenticator_seed="ma05-packaged-authenticated-projection"
installed_broker_socket="/private/var/run/bloom/$login_uid/machine-broker/broker.sock"
[[ -S "$installed_broker_socket" ]] || {
  echo "real installed Broker socket is absent before authenticated projection seeding" >&2
  exit 1
}
[[ "$(stat -f '%u' "$installed_broker_socket")" == "$broker_uid" ]]
sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_BROKER_SOCKET="$installed_broker_socket" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  BLOOM_LOG_OUTPUT=json-stderr \
  "$machine_binary" --home "$clean_home" serve \
    --endpoint "unix:$machine_socket" \
    >"$work/seed-machine-service.log" 2>&1 &
machine_service_pid=$!
deadline=$((SECONDS + 15))
while [[ ! -S "$machine_socket" && $SECONDS -lt $deadline ]]; do
  kill -0 "$machine_service_pid" 2>/dev/null || {
    cat "$work/seed-machine-service.log" >&2
    exit 1
  }
  sleep 0.05
done
[[ -S "$machine_socket" ]] || {
  cat "$work/seed-machine-service.log" >&2
  echo "packaged Machine seeding service did not publish its IPC socket" >&2
  exit 1
}
if ! sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
    wallet new ma05-cached \
  >"$work/registration.log" 2>&1
then
  cat "$work/registration.log" >&2
  exit 1
fi
registration_url="$(sed -n 's/^ceremony_url: //p' "$work/registration.log")"
[[ "$registration_url" == http://localhost:18734/ceremony/* ]] || {
  cat "$work/registration.log" >&2
  exit 1
}
if ! sudo -H -u "$login_user" \
  "$debug_driver" complete "$registration_url" "$authenticator_seed" \
  >"$work/registration-complete.log" 2>&1
then
  cat "$work/registration-complete.log" >&2
  exit 1
fi
wallet_id="$(jq -r '.wallet_id // empty' "$work/registration-complete.log")"
[[ "$wallet_id" == "ma05-cached" ]] || {
  cat "$work/registration-complete.log" >&2
  echo "wallet registration did not preserve the requested authoritative wallet ID" >&2
  exit 1
}

deadline=$((SECONDS + 15))
while [[ $SECONDS -lt $deadline ]]; do
  if sudo -H -u "$login_user" env \
    BLOOM_HOME="$clean_home" \
    BLOOM_MACHINE_IDENTITY="$machine_identity" \
    BLOOM_EDGE_MANIFEST="$edge_manifest" \
    "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
      wallet projection "$wallet_id" \
    >"$work/live-projection.log" 2>"$work/live-projection.stderr"
  then
    break
  fi
  sleep 0.1
done
if [[ ! -s "$work/live-projection.log" ]]; then
  cat "$work/live-projection.stderr" >&2
  exit 1
fi
wallet_address="$(jq -r '.keys[0].addresses[0] // empty' "$work/live-projection.log")"
[[ "$wallet_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || exit 1

# Install one explicit destination so the later confirm reaches the Broker
# signing boundary rather than stopping at Machine's advisory deny-all view.
jq -nc \
  --arg wallet "$wallet_id" \
  --arg destination "$wallet_address" \
  '{wallet_id:$wallet,maximum_approval_lifetime_ms:2592000000,allowed_petal_packages:[],allowed_destinations:[{chain:"anvil",destination:$destination}],required_verifiers:[]}' \
  >"$work/live-policy.json"
chown "$login_uid" "$work/live-policy.json"
chmod 0600 "$work/live-policy.json"
sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
    wallet update-policy "$wallet_id" \
    --file "$work/live-policy.json" >"$work/policy-prepare-live.log" 2>&1
policy_operation_id="$(sed -n 's/^operation_id: //p' "$work/policy-prepare-live.log")"
policy_ceremony_url="$(sed -n 's/^ceremony_url: //p' "$work/policy-prepare-live.log")"
[[ "$policy_operation_id" =~ ^[0-9a-f]{64}$ ]]
[[ "$policy_ceremony_url" == http://localhost:18734/ceremony/* ]]
sudo -H -u "$login_user" \
  "$debug_driver" complete "$policy_ceremony_url" "$authenticator_seed" --sign-count 2 \
  >"$work/policy-complete-live.log" 2>&1
sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
    wallet commit-policy "$policy_operation_id" \
  >"$work/policy-commit-live.log" 2>&1

broker_log="/private/var/log/bloom/$login_uid/broker.jsonl"
signer_log="/private/var/log/bloom/$login_uid/signer.jsonl"
newsyslog_config="/etc/newsyslog.d/bloom-$login_uid.conf"
for service_log in "$broker_log" "$signer_log"; do
  sudo -u "$login_user" test -r "$service_log"
  if sudo -u "$login_user" test -w "$service_log"; then
    echo "enrolled user can write canonical service log $service_log" >&2
    exit 1
  fi
done
for protected_state in \
  "/private/var/db/bloom/$login_uid/broker/journal.db" \
  "/private/var/db/bloom/$login_uid/signer/journal.db"
do
  if sudo -u "$login_user" test -r "$protected_state"; then
    echo "enrolled user can read protected service state $protected_state" >&2
    exit 1
  fi
done
grep -F "$policy_operation_id" "$broker_log" >/dev/null
grep -F "$policy_operation_id" "$signer_log" >/dev/null
/usr/bin/python3 - "$work/seed-machine-service.log" "$policy_operation_id" <<'PY'
import json
import pathlib
import sys

events = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
operation_id = sys.argv[2]
if not any(
    event.get("fields", {}).get("operation_id") == operation_id
    and event.get("fields", {}).get("event") in {
        "machine.policy_update.transition",
        "machine.durable_mutation",
        "rpc.request_completed",
    }
    for event in events
):
    raise SystemExit("Machine structured log omitted the policy operation ID")
PY

# Force the package-owned rotation while both services remain loaded. Their
# per-event writers must reopen the canonical path rather than retaining the
# renamed inode.
/usr/sbin/newsyslog -F -f "$newsyslog_config"
sudo -u "$login_user" "$machine_binary" serve triad-health-check "$(
  plutil -extract build_digest raw -o - \
    "/Library/Application Support/BloomTriad/config/$login_uid/broker/config.json"
)" >/dev/null
/usr/bin/python3 - "$broker_log.0" "$signer_log.0" "$broker_log" "$signer_log" <<'PY'
import json
import pathlib
import sys

for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    lines = path.read_text().splitlines()
    if not lines:
        raise SystemExit(f"rotated/current service log is empty: {path}")
    for line in lines:
        json.loads(line)
PY
for service_log in "$broker_log" "$signer_log"; do
  sudo -u "$login_user" test -r "$service_log"
  if sudo -u "$login_user" test -w "$service_log"; then exit 1; fi
done
sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
    wallet projection "$wallet_id" \
  >"$work/live-projection.log" 2>"$work/live-projection.stderr"
jq -e \
  --arg address "$wallet_address" \
  --arg wallet "$wallet_id" \
  '.verification == "authenticated_broker" and .freshness == "fresh" and .wallet.wallet_id == $wallet and .keys[0].addresses[0] == $address' \
  "$work/live-projection.log" >/dev/null
/usr/bin/python3 - "$work/live-projection.log" "$wallet_address" <<'PY'
import base64
import json
import pathlib
import sys

projection = json.loads(pathlib.Path(sys.argv[1]).read_text())
encoded = projection["policy"]["canonical_policy"]
encoded += "=" * (-len(encoded) % 4)
policy = json.loads(base64.urlsafe_b64decode(encoded))
expected = {"chain": "anvil", "destination": sys.argv[2]}
if expected not in policy["allowed_destinations"]:
    raise SystemExit("authenticated policy projection omitted the MA-05 destination")
PY
[[ -s "$clean_home/cache/wallet-projections.json" ]]
kill "$machine_service_pid"
wait "$machine_service_pid" 2>/dev/null || true
machine_service_pid=""
rm -f "$machine_socket"
cp "$clean_home/cache/wallet-projections.json" "$work/authenticated-projection-cache.json"
approval_issued_ms="$(($(date +%s) * 1000))"
approval_expires_ms="$((approval_issued_ms + 600000))"
jq -c \
  --arg issued "$approval_issued_ms" \
  --arg expires "$approval_expires_ms" \
  '{
    operation_id:"1111111111111111111111111111111111111111111111111111111111111111",
    terms:{
      subject:{kind:"cli",client_id:"bloom-cli",command_class:"ma05.degraded"},
      wallet_id:.wallet.wallet_id,
      key_ref:.keys[0].key_ref,
      allowed_crypto_suites:[.keys[0].supported_crypto_suites[0]],
      selector:{kind:"exact",ordered_payload_digests:["2222222222222222222222222222222222222222222222222222222222222222"],ordered_hashes:["3333333333333333333333333333333333333333333333333333333333333333"]},
      limits:{max_operations:"1",max_signatures:"1",operation_rate_limits:[],signature_rate_limits:[],value_limits:[]},
      activation_mode:{kind:"boot_bound"},
      wallet_revocation_epoch:.wallet.wallet_revocation_epoch,
      policy_version:.wallet.policy_version,
      policy_digest:.wallet.policy_digest,
      provenance_digest:"5555555555555555555555555555555555555555555555555555555555555555",
      request_nonce:"00000000000000000000000000000000",
      issued_at_ms:$issued,
      not_before_ms:$issued,
      expires_at_ms:$expires,
      renewal_of:null
    },
    canonical_plan_facts_digest:"6666666666666666666666666666666666666666666666666666666666666666"
  }' "$work/live-projection.log" >"$work/approval-request.json"
chown "$login_uid" "$work/approval-request.json"
chmod 0600 "$work/approval-request.json"

# The real installed Broker must be stopped. The replacement has the Broker
# OS principal but deliberately cannot authenticate a triad response.
launchctl print "$broker_label" >/dev/null
launchctl print "$signer_label" >/dev/null
broker_was_loaded=true
signer_was_loaded=true
launchctl bootout "$broker_label"
launchctl bootout "$signer_label"
deadline=$((SECONDS + 15))
while { pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 ||
  pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1; } &&
  [[ $SECONDS -lt $deadline ]]
do
  sleep 0.1
done
if pgrep -u "$broker_uid" -x bloom-broker >/dev/null 2>&1 ||
  pgrep -u "$signer_uid" -x bloom-signer >/dev/null 2>&1
then
  echo "installed Broker/Signer did not stop for the packaged Machine negative" >&2
  exit 1
fi

# The installed 0710 parent normally makes a direct Machine attempt fail at
# pathname traversal before accept(2), which would make a zero-connection
# sentinel ambiguous. On this disposable host only, record its exact metadata
# and add other-execute while both real services are stopped. The hostile
# socket is then reachable, so a zero accept marker proves no direct connector
# attempt rather than merely re-proving the OS ACL. Cleanup restores metadata
# before either LaunchDaemon is bootstrapped.
[[ -d "$signer_socket_dir" && ! -L "$signer_socket_dir" ]] || exit 65
signer_socket_dir_owner="$(stat -f '%u' "$signer_socket_dir")"
signer_socket_dir_group="$(stat -f '%g' "$signer_socket_dir")"
signer_socket_dir_mode="$(stat -f '%Lp' "$signer_socket_dir")"
chmod 0711 "$signer_socket_dir"

sudo -u "$broker_user" \
  "$work/hostile-unix-listener" "$broker_socket" "$broker_connected" &
broker_listener_pid=$!
sudo -u "$signer_user" \
  "$work/hostile-unix-listener" "$signer_socket" "$signer_connected" &
signer_listener_pid=$!
deadline=$((SECONDS + 5))
while [[ (! -S "$broker_socket" || ! -S "$signer_socket") && $SECONDS -lt $deadline ]]; do
  sleep 0.05
done
[[ -S "$broker_socket" && -S "$signer_socket" ]] || {
  echo "hostile runtime listeners did not become ready" >&2
  exit 1
}

run_machine_with_deadline() {
  local output="$1"
  local command_pid deadline machine_status
  shift
  sudo -H -u "$login_user" env \
    BLOOM_HOME="$clean_home" \
    BLOOM_BROKER_SOCKET="$broker_socket" \
    BLOOM_MACHINE_IDENTITY="$machine_identity" \
    BLOOM_EDGE_MANIFEST="$edge_manifest" \
    "$machine_binary" --connect "unix:$machine_socket" "$@" >"$output" 2>&1 &
  command_pid=$!
  deadline=$((SECONDS + 8))
  while kill -0 "$command_pid" 2>/dev/null && [[ $SECONDS -lt $deadline ]]; do
    sleep 0.05
  done
  if kill -0 "$command_pid" 2>/dev/null; then
    kill "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
    echo "packaged Machine hung with its authority service unavailable" >&2
    return 124
  fi
  if wait "$command_pid"; then
    machine_status=0
  else
    machine_status=$?
  fi
  return "$machine_status"
}

run_login_with_deadline() {
  local output="$1"
  local command_pid deadline command_status
  shift
  sudo -H -u "$login_user" "$@" >"$output" 2>&1 &
  command_pid=$!
  deadline=$((SECONDS + 8))
  while kill -0 "$command_pid" 2>/dev/null && [[ $SECONDS -lt $deadline ]]; do
    sleep 0.05
  done
  if kill -0 "$command_pid" 2>/dev/null; then
    kill "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
    echo "mounted filesystem operation hung with authority unavailable" >&2
    return 124
  fi
  if wait "$command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  return "$command_status"
}

mounted_write_with_deadline() {
  local output="$1"
  local path="$2"
  local body="$3"
  run_login_with_deadline "$output" /bin/sh -c \
    'printf "%s\n" "$2" > "$1"' bloom-mounted-write "$path" "$body"
}

audit_sequence() {
  if [[ ! -s "$clean_home/audit.jsonl" ]]; then
    echo 0
    return
  fi
  /usr/bin/tail -n 1 "$clean_home/audit.jsonl" | jq -er '.sequence'
}

assert_mounted_effect_denied() {
  local label="$1"
  local path="$2"
  local body="$3"
  local start_sequence="$4"
  local audit="$clean_home/audit.jsonl"
  local evidence="$work/$label-mounted-effect.json"
  local payload_sha256 payload_size deadline
  payload_sha256="0x$(printf '%s\n' "$body" | shasum -a 256 | awk '{print $1}')"
  payload_size="$(printf '%s\n' "$body" | LC_ALL=C wc -c | tr -d ' ')"
  deadline=$((SECONDS + 8))
  while [[ $SECONDS -lt $deadline ]]; do
    if /usr/bin/python3 - \
      "$audit" "$start_sequence" "$path" "$payload_sha256" "$payload_size" \
      >"$evidence" <<'PY'
import json
import pathlib
import re
import sys

audit_path, start_raw, expected_path, expected_digest, size_raw = sys.argv[1:]
start = int(start_raw)
expected_size = int(size_raw)
records = []
try:
    lines = pathlib.Path(audit_path).read_text().splitlines()
except FileNotFoundError:
    raise SystemExit(1)
for line in lines:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        continue
    if record.get("sequence", 0) > start:
        records.append(record)

for intent in records:
    details = intent.get("data", {}).get("details", {})
    if not (
        intent.get("kind") == "machine.effect.intent"
        and intent.get("service_id") == "bloom-machine"
        and intent.get("data", {}).get("actor") == "local"
        and intent.get("data", {}).get("path") == expected_path
        and details.get("operation") == "vfs.write"
        and details.get("payload_sha256") == expected_digest
        and details.get("payload_size") == expected_size
    ):
        continue
    correlation = details.get("correlation_id")
    for result in records:
        result_details = result.get("data", {}).get("details", {})
        error = result_details.get("result", {}).get("error", "")
        if (
            result.get("kind") == "machine.effect.result"
            and result.get("service_id") == "bloom-machine"
            and result.get("sequence", 0) > intent.get("sequence", 0)
            and result.get("data", {}).get("actor") == "local"
            and result.get("data", {}).get("path") == expected_path
            and result_details.get("operation") == "vfs.write"
            and result_details.get("correlation_id") == correlation
            and result_details.get("outcome") == "error"
            and isinstance(error, str)
            and re.search(
                r"Broker|authenticated Machine-to-Broker edge", error, re.IGNORECASE
            )
            and re.search(
                r"unavailable|service[_ -]unavailable|requires Broker exact signing",
                error,
                re.IGNORECASE,
            )
        ):
            print(json.dumps({"intent": intent, "result": result}, sort_keys=True))
            raise SystemExit(0)
raise SystemExit(1)
PY
    then
      break
    fi
    sleep 0.05
  done
  [[ -s "$evidence" ]] || {
    tail -n 20 "$audit" >&2 || true
    echo "$label mounted write lacked a correlated signed Broker-unavailable error result" >&2
    exit 1
  }

  # Opening the same journal with the installed production executable verifies
  # the complete hash chain and every Machine application-identity signature.
  run_login_with_deadline \
    "$work/$label-audit-status.log" \
    env \
      BLOOM_HOME="$clean_home" \
      BLOOM_MACHINE_IDENTITY="$machine_identity" \
      BLOOM_EDGE_MANIFEST="$edge_manifest" \
      "$machine_binary" --home "$clean_home" --connect "unix:$machine_socket" \
        audit status || {
    cat "$work/$label-audit-status.log" >&2
    echo "$label Machine audit signature verification failed" >&2
    exit 1
  }
  jq -e \
    '.service_id == "bloom-machine" and .mutation_degradation == null' \
    "$work/$label-audit-status.log" >/dev/null
}

# Launch the installed production executable in its long-running Machine
# service mode. macOS packages `bloom`; `serve` is its Machine service mode
# (there is no separately installed bloom-machine payload or Machine plist).
sudo -H -u "$login_user" env \
  BLOOM_HOME="$clean_home" \
  BLOOM_BROKER_SOCKET="$broker_socket" \
  BLOOM_MACHINE_IDENTITY="$machine_identity" \
  BLOOM_EDGE_MANIFEST="$edge_manifest" \
  "$machine_binary" --home "$clean_home" serve \
    --endpoint "unix:$machine_socket" --mount "$mount_dir" \
    >"$work/machine-service.log" 2>&1 &
machine_service_pid=$!
deadline=$((SECONDS + 30))
while { [[ ! -S "$machine_socket" ]] ||
  ! mount | grep -F " on $mount_dir " >/dev/null 2>&1 ||
  ! sudo -u "$login_user" /bin/ls "$mount_dir" >/dev/null 2>&1; } &&
  [[ $SECONDS -lt $deadline ]]
do
  kill -0 "$machine_service_pid" 2>/dev/null || {
    cat "$work/machine-service.log" >&2
    echo "packaged production Machine service exited during degraded startup" >&2
    exit 1
  }
  sleep 0.05
done
if [[ ! -S "$machine_socket" ]] ||
  ! mount | grep -F " on $mount_dir " >/dev/null 2>&1 ||
  ! sudo -u "$login_user" /bin/ls "$mount_dir" >/dev/null 2>&1
then
  cat "$work/machine-service.log" >&2
  echo "packaged production Machine service did not publish its IPC socket and kernel mount" >&2
  exit 1
fi

# A key-free read path remains usable through that exact packaged service with
# Broker stopped. This exercises a clean production home before authority
# negatives and proves no legacy authority file remains open in the process.
run_machine_with_deadline \
  "$work/status.log" \
  --home "$clean_home" status || {
  cat "$work/status.log" >&2
  echo "packaged Machine did not preserve its degraded read/status path" >&2
  exit 1
}

run_login_with_deadline \
  "$work/cached-wallet-address.log" \
  /bin/cat "$mount_dir/wallets/$wallet_id/address" || {
  cat "$work/cached-wallet-address.log" >&2
  echo "packaged Machine did not preserve cached reads through its kernel mount" >&2
  exit 1
}
grep -Fx "$wallet_address" "$work/cached-wallet-address.log" >/dev/null

degraded_intent="send 0.000000000000000001 eth to $wallet_address on anvil"
mounted_write_with_deadline \
  "$work/stage.log" \
  "$mount_dir/wallets/$wallet_id/chains/anvil/outbox/new.tx" \
  "$degraded_intent" || {
  cat "$work/stage.log" >&2
  echo "packaged Machine did not preserve unsigned staging through its kernel mount with Broker stopped" >&2
  exit 1
}

simulation_intent="$(jq -nc \
  --arg address "$wallet_address" \
  '{kind:"send",from:$address,to:$address,value:"0.000000000000000001 eth",chain:"anvil"}')"
mounted_write_with_deadline \
  "$work/simulate.log" \
  "$mount_dir/simulate/new" \
  "$simulation_intent" || {
  cat "$work/simulate.log" >&2
  echo "packaged Machine did not preserve simulation through its kernel mount with Broker stopped" >&2
  exit 1
}
run_login_with_deadline \
  "$work/simulate-result.log" \
  /bin/cat "$mount_dir/simulate/last" || {
  cat "$work/simulate-result.log" >&2
  echo "packaged Machine did not expose the degraded simulation result" >&2
  exit 1
}
grep -E '^sim-[0-9]+' "$work/simulate-result.log" >/dev/null
sim_id="$(tr -d '\r\n' <"$work/simulate-result.log")"
run_login_with_deadline \
  "$work/simulation.json" \
  /bin/cat "$mount_dir/simulate/$sim_id/simulation.json" || {
  cat "$work/simulate.log" >&2
  echo "packaged Machine did not expose a completed mounted simulation" >&2
  exit 1
}
jq -e \
  '.success == true and .gas_used == 21000 and .return_data_hex == "0x" and .logs == [] and .chain == "anvil"' \
  "$work/simulation.json" >/dev/null || {
  cat "$work/simulation.json" >&2
  echo "packaged Machine simulation did not return the deterministic fixture result" >&2
  exit 1
}

run_login_with_deadline \
  "$work/pending.log" \
  /bin/ls -1 "$mount_dir/wallets/$wallet_id/chains/anvil/outbox/pending"
staged_id="$(sed -n '1p' "$work/pending.log")"
[[ -n "$staged_id" ]] || {
  cat "$work/pending.log" >&2
  echo "packaged Machine staging did not create a pending public plan" >&2
  exit 1
}
signing_audit_start="$(audit_sequence)"
if mounted_write_with_deadline \
  "$work/signing.log" \
  "$mount_dir/wallets/$wallet_id/chains/anvil/outbox/pending/$staged_id/confirm" \
  y
then
  signing_status=0
else
  signing_status=$?
fi
[[ "$signing_status" -ne 124 ]] || {
  cat "$work/signing.log" >&2
  echo "packaged Machine signing write hung with Broker stopped" >&2
  exit 1
}
assert_mounted_effect_denied \
  signing \
  "/wallets/$wallet_id/chains/anvil/outbox/pending/$staged_id/confirm" \
  y \
  "$signing_audit_start"
# macOS NFS may acknowledge a close before surfacing a handler denial. The
# authoritative negative is that the exact pending plan remains pending and no
# sent entry appears after the mounted write has been observed.
run_login_with_deadline \
  "$work/signing-pending.log" \
  /bin/test -d \
  "$mount_dir/wallets/$wallet_id/chains/anvil/outbox/pending/$staged_id" || {
  cat "$work/signing.log" >&2
  echo "packaged Machine changed pending signing state without Broker authority" >&2
  exit 1
}
if run_login_with_deadline \
  "$work/signing-sent.log" \
  /bin/test -e \
  "$mount_dir/wallets/$wallet_id/chains/anvil/outbox/sent/$staged_id"
then
  echo "packaged Machine produced a sent transaction without Broker authority" >&2
  exit 1
fi

run_login_with_deadline \
  "$work/policy-before.log" \
  /bin/cat "$mount_dir/wallets/$wallet_id/policy.json"
jq -nc \
  --arg wallet "$wallet_id" \
  '{allowed_destinations:[{chain:"anvil",destination:"0x0000000000000000000000000000000000000003"}],allowed_petal_packages:[],maximum_approval_lifetime_ms:600000,required_verifiers:[],wallet_id:$wallet}' \
  >"$work/proposed-policy.json"
chown "$login_uid" "$work/proposed-policy.json"
chmod 0600 "$work/proposed-policy.json"
proposed_policy="$(<"$work/proposed-policy.json")"
policy_audit_start="$(audit_sequence)"
if mounted_write_with_deadline \
  "$work/policy.log" \
  "$mount_dir/wallets/$wallet_id/policy.json" \
  "$proposed_policy"
then
  policy_status=0
else
  policy_status=$?
fi
[[ "$policy_status" -ne 124 ]] || {
  cat "$work/policy.log" >&2
  echo "packaged Machine policy mutation hung with Broker stopped" >&2
  exit 1
}
assert_mounted_effect_denied \
  policy \
  "/wallets/$wallet_id/policy.json" \
  "$proposed_policy" \
  "$policy_audit_start"
run_login_with_deadline \
  "$work/policy-after.log" \
  /bin/cat "$mount_dir/wallets/$wallet_id/policy.json"
/usr/bin/cmp -s "$work/policy-before.log" "$work/policy-after.log" || {
  echo "packaged Machine changed its authenticated policy projection without Broker authority" >&2
  exit 1
}
run_login_with_deadline \
  "$work/policy-pending.log" \
  /bin/ls -A "$mount_dir/wallets/$wallet_id/policy-updates/pending"
[[ ! -s "$work/policy-pending.log" ]] || {
  cat "$work/policy-pending.log" >&2
  echo "packaged Machine staged policy authority state without Broker authority" >&2
  exit 1
}

approval_request="$(<"$work/approval-request.json")"
approval_audit_start="$(audit_sequence)"
if mounted_write_with_deadline \
  "$work/approval.log" \
  "$mount_dir/wallets/$wallet_id/sealed-approvals/new.json" \
  "$approval_request"
then
  approval_status=0
else
  approval_status=$?
fi
[[ "$approval_status" -ne 124 ]] || {
  cat "$work/approval.log" >&2
  echo "packaged Machine approval mutation hung with Broker stopped" >&2
  exit 1
}
assert_mounted_effect_denied \
  approval \
  "/wallets/$wallet_id/sealed-approvals/new.json" \
  "$approval_request" \
  "$approval_audit_start"
run_login_with_deadline \
  "$work/approval-after.log" \
  /bin/cat "$mount_dir/wallets/$wallet_id/sealed-approvals/new.json"
/usr/bin/python3 - "$work/approval-after.log" <<'PY'
import json
import pathlib
import sys

projection = json.loads(pathlib.Path(sys.argv[1]).read_text())
if projection != {
    "schema": "bloom.approval_prepare_request.v1",
    "write": "complete ApprovalPrepareRequest JSON",
}:
    raise SystemExit("approval mutation produced state without Broker authority")
PY
if lsof -nP -a -p "$machine_service_pid" -Fn | grep -E \
  '/(keystore|auth|auth\.sqlite|challenges?|grants?|policy-session|signer-cache)(/|$|\.)' \
  >/dev/null
then
  echo "packaged production Machine service opened legacy authority state" >&2
  lsof -nP -a -p "$machine_service_pid" >&2 || true
  exit 1
fi

# Cached projection reads must remain available after every denied authority
# operation. The hostile same-principal endpoint was consumed by the first
# mounted projection refresh and never supplied an authenticated response;
# this second read therefore proves the mount continues to use only its
# key-free cache.
if run_login_with_deadline \
  "$work/projection.log" \
  /bin/ls -1 "$mount_dir/wallets"
then
  projection_status=0
else
  projection_status=$?
fi
[[ "$projection_status" -eq 0 ]] || {
  cat "$work/projection.log" >&2
  echo "packaged Machine mount lost its cached projection after authority denial" >&2
  exit 1
}
grep -Fx "$wallet_id" "$work/projection.log" >/dev/null
grep -E 'Broker.*unavailable|authority.*unavailable|authenticated Machine-to-Broker edge' \
  "$work/machine-service.log" >/dev/null || {
  cat "$work/machine-service.log" >&2
  echo "packaged Machine did not report its unavailable authority edge" >&2
  exit 1
}

if run_machine_with_deadline \
  "$work/custody.log" \
  --home "$clean_home" wallet new ma13-runtime-negative
then
  custody_status=0
else
  custody_status=$?
fi
[[ "$custody_status" -ne 0 && "$custody_status" -ne 124 ]] || {
  cat "$work/custody.log" >&2
  echo "packaged Machine did not fail the Broker-hostile custody request promptly" >&2
  exit 1
}
grep -Ei \
  'custody.*authenticated Machine-to-Broker edge|authenticated Broker.*(unavailable|failed)|Broker.*unavailable|service[_ -]unavailable' \
  "$work/custody.log" >/dev/null || {
  cat "$work/custody.log" >&2
  echo "packaged Machine custody denial did not identify the unavailable authenticated Broker edge" >&2
  exit 1
}
deadline=$((SECONDS + 3))
while [[ ! -f "$broker_connected" && $SECONDS -lt $deadline ]]; do sleep 0.05; done
[[ -f "$broker_connected" ]] || {
  echo "packaged production Machine service did not exercise the hostile Broker socket" >&2
  exit 1
}
[[ ! -e "$signer_connected" ]] || {
  echo "packaged Machine connected directly to the hostile Signer sentinel" >&2
  exit 1
}

legacy_manifest >"$work/legacy-after.manifest"
/usr/bin/cmp -s "$work/legacy-before.manifest" "$work/legacy-after.manifest" || {
  diff -u "$work/legacy-before.manifest" "$work/legacy-after.manifest" >&2 || true
  echo "packaged Machine accessed, migrated, or changed poisoned legacy authority state" >&2
  exit 1
}
for root in "${legacy_poison_roots[@]}"; do
  [[ "$(find "$root" -type f | wc -l | tr -d ' ')" -ge 1 ]] || exit 1
done
runtime_forbidden="$(find "$runtime" \
  \( -name keystore -o -name auth -o -name auth.sqlite -o -name challenge -o \
     -name challenges -o -name grant -o -name grants -o \
     -name policy-session -o -name signer-cache \) -print -quit)"
[[ -z "$runtime_forbidden" ]] || {
  echo "packaged Machine created legacy authority state: $runtime_forbidden" >&2
  exit 1
}

# Stop and flush the future-process tracer only after every packaged Machine
# operation has completed. fs_usage's final column identifies the process as
# `name.pid`; filter exactly to packaged `bloom` processes before considering
# paths so setup tools cannot create either the positive or negative evidence.
kill "$fs_usage_pid"
wait "$fs_usage_pid" 2>/dev/null || true
fs_usage_pid=""
LC_ALL=C awk \
  '$0 ~ /(^|[[:space:]])bloom\.[0-9]+([[:space:]]|$)/ { print }' \
  "$work/all-fs-usage.log" >"$work/machine-fs-usage.log"
grep -F "$clean_home/config.toml" "$work/machine-fs-usage.log" >/dev/null || {
  cat "$work/all-fs-usage.log" >&2
  echo "fs_usage did not capture a known packaged Machine filesystem access" >&2
  exit 1
}
for root in "${legacy_poison_roots[@]}"; do
  if grep -F "$root" "$work/machine-fs-usage.log" >/dev/null; then
    grep -F "$root" "$work/machine-fs-usage.log" >&2 || true
    echo "packaged Machine attempted to access poisoned legacy authority root: $root" >&2
    exit 1
  fi
done

# Keep the Signer sentinel alive until every Machine command and state check
# has finished, then prove it observed no direct connector attempt.
kill -0 "$signer_listener_pid"
kill -0 "$machine_service_pid"
echo "packaged Machine runtime negative passed"
