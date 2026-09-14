#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/scripts/lib/bounded-process.sh"
broker_repo="$(cd "${repo_root}/../bloom-broker" && pwd -P)"
launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-300}"

die() { printf 'MA-03 projection fidelity: %s\n' "$*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || die "jq is required"
[ -x "$launcher" ] || die "triad developer launcher is not executable: $launcher"
case "$startup_timeout_secs" in *[!0-9]*|'') die "startup timeout must be an integer" ;; esac

# Keep Unix-domain socket paths below macOS SUN_LEN even when TMPDIR expands to
# a long per-login /var/folders path.
run_root="$(mktemp -d "${BLOOM_MA03_TMPDIR:-/tmp}/bloom-ma03.XXXXXX")"
developer_root="${run_root}/developer"
machine_home="${developer_root}/machine-home"
mount_dir="${run_root}/mount"
log_dir="${run_root}/logs"
machine_socket="${run_root}/run/machine.sock"
ready_file="${run_root}/run/ready"
launcher_log="${run_root}/launcher.log"
launcher_pid=""
mkdir -p "$machine_home" "$mount_dir" "$log_dir" "$(dirname "$machine_socket")"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  stop_stack || true
  if [ "$status" -eq 0 ]; then
    rm -rf -- "$run_root"
  else
    printf 'MA-03 diagnostics retained at: %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

stop_stack() {
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  launcher_pid=""
  rm -f -- "$ready_file" "$machine_socket"
  attempts=0
  while mount | grep -F " on ${mount_dir} " >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || die "Machine mount remained active after shutdown"
    sleep 0.1
  done
}

start_stack() {
  : > "$launcher_log"
  BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=1 "$launcher" \
    --developer-root "$developer_root" \
    --machine-home "$machine_home" \
    --mount "$mount_dir" \
    --machine-socket "$machine_socket" \
    --log-dir "$log_dir" \
    --ready-file "$ready_file" >"$launcher_log" 2>&1 &
  launcher_pid=$!
  deadline=$(( $(date +%s) + startup_timeout_secs ))
  while [ ! -f "$ready_file" ]; do
    kill -0 "$launcher_pid" 2>/dev/null || {
      cat "$launcher_log" >&2
      die "triad developer stack exited during startup"
    }
    [ "$(date +%s)" -lt "$deadline" ] || {
      cat "$launcher_log" >&2
      die "triad developer stack did not become ready"
    }
    sleep 0.1
  done
  # shellcheck disable=SC1090
  source "${log_dir}/triad.env"
  bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-${repo_root}/target/debug/bloom}"
  driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:-${broker_repo}/target/debug/bloom-broker-debug-driver}"
  [ -x "$bloom_bin" ] && [ -x "$driver_bin" ] || die "integration binaries are missing"
}

cli() {
  "$bloom_bin" --home "$machine_home" "$@"
}

mounted() {
  case "$1" in
    /*) printf '%s%s\n' "$mount_dir" "$1" ;;
    *) die "internal VFS path is not absolute: $1" ;;
  esac
}

bounded_mounted_command() {
  path="$1"
  label="$2"
  shift 2
  deadline_secs="${BLOOM_MA08_MOUNT_READ_TIMEOUT_SECS:-15}"
  case "$deadline_secs" in *[!0-9]*|'') die "mounted-read timeout must be an integer" ;; esac
  [ "$deadline_secs" -ge 1 ] || die "mounted-read timeout must be positive"
  output="${run_root}/bounded-read.$$.${RANDOM}"
  "$@" "$path" > "$output" 2>/dev/null &
  read_pid=$!
  deadline=$(( $(date +%s) + deadline_secs ))
  while kill -0 "$read_pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      # A macOS NFS client can remain in an uninterruptible read after the
      # userspace deadline. Stop the serving Machine first so the syscall is
      # released, then fail with the exact mounted surface instead of hanging
      # acceptance indefinitely.
      if [ -f "${log_dir}/machine.pid" ]; then
        kill "$(tr -d '[:space:]' < "${log_dir}/machine.pid")" 2>/dev/null || true
      fi
      kill "$read_pid" 2>/dev/null || true
      rm -f -- "$output"
      printf 'MA-03 projection fidelity: %s exceeded %ss at mounted path %s\n' \
        "$label" "$deadline_secs" "$path" >&2
      return 124
    fi
    sleep 0.05
  done
  if ! wait "$read_pid"; then
    rm -f -- "$output"
    # A not-yet-created projection is normal in the polling callers. Preserve
    # the hard timeout above, but represent ordinary lookup misses as empty.
    return 0
  fi
  command cat "$output"
  rm -f -- "$output"
}

bounded_mounted_read() {
  bounded_mounted_command "$1" "$2" /bin/cat
}

bounded_mounted_list() {
  bounded_mounted_command "$1" "$2" env LC_ALL=C /bin/ls -1
}

complete_launch() {
  launch_output="$1"
  seed="$2"
  shift 2
  ceremony_url="$(printf '%s\n' "$launch_output" | sed -n 's/^ceremony_url: //p')"
  [ -n "$ceremony_url" ] || die "custody launch omitted ceremony_url"
  "$driver_bin" complete "$ceremony_url" "$seed" "$@"
}

assert_projection_pair() {
  wallet_id="$1"
  label="$2"
  attempts=0
  vfs_projection=""
  while [ "$attempts" -lt 100 ]; do
    vfs_projection="$(bounded_mounted_read \
      "$(mounted "/wallets/${wallet_id}/projection.json")" \
      "${label} wallet projection read")"
    if printf '%s' "$vfs_projection" | jq -e . >/dev/null 2>&1; then
      break
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  # Observe through the long-lived Machine first. A separate CLI process uses
  # the same atomic cache file, so putting it second avoids turning the test
  # itself into an external-writer race against the mounted reader.
  cli_projection="$(cli wallet projection "$wallet_id")"
  for projection in "$cli_projection" "$vfs_projection"; do
    printf '%s' "$projection" | jq -e --arg wallet "$wallet_id" '
      .wallet.wallet_id == $wallet and
      .source_protocol == "bloom.machine-broker.v1" and
      .verification == "authenticated_broker" and
      (.keys | type == "array") and (.credentials | type == "array")
    ' >/dev/null || die "${label}: invalid public projection"
  done
  cli_normalized="$(printf '%s' "$cli_projection" | jq -cS 'del(.observed_at_ms, .freshness)')"
  vfs_normalized="$(printf '%s' "$vfs_projection" | jq -cS 'del(.observed_at_ms, .freshness)')"
  [ "$cli_normalized" = "$vfs_normalized" ] ||
    die "${label}: CLI and mounted VFS disagree"
  printf '%s\n' "$cli_projection"
}

assert_no_legacy_record() {
  for wallet_id in "$@"; do
    [ ! -e "${machine_home}/keystore/${wallet_id}" ] ||
      die "Machine created a legacy keystore record for ${wallet_id}"
  done
  [ ! -e "${machine_home}/auth/auth.sqlite" ] || die "Machine created legacy auth.sqlite"
  [ ! -e "${machine_home}/signer-cache" ] || die "Machine created a legacy signer cache"
}

wait_for_fixture_record() {
  request_id="$1"
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    while IFS= read -r record_name; do
      [ -n "$record_name" ] || continue
      record_path="$(mounted "/petal-key-requests/${record_name}")"
      record="$(bounded_mounted_read "$record_path" \
        "Petal key request record read")"
      if printf '%s' "$record" | jq -e --arg request_id "$request_id" '
        .request_id == $request_id and .status == "awaiting_user" and
        (.ceremony_url | type == "string")
      ' >/dev/null 2>&1; then
        printf '%s\n' "$record"
        return 0
      fi
    done < <(bounded_mounted_list "$(mounted /petal-key-requests)" \
      "Petal key request directory read")
    attempts=$((attempts + 1))
    sleep 0.05
  done
  die "Petal key derivation ceremony did not appear through the mounted VFS"
}

wait_for_fixture_stage() {
  expected="$1"
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    fixture_body="$(bounded_mounted_read \
      "$(mounted /petals/triad-authority-fixture/session.json)" \
      "fixture Petal session read")"
    fixture_stage="$(printf '%s' "$fixture_body" | jq -r '
      if .stage == "key" then "key:" + (.outcome.state // "")
      else .stage // "" end
    ' 2>/dev/null || true)"
    if [ "$fixture_stage" = "$expected" ]; then
      printf '%s\n' "$fixture_body"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  die "fixture Petal did not reach mounted stage ${expected}"
}

wait_for_approval_prepare() {
  wallet_id="$1"
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    approval_body="$(bounded_mounted_read \
      "$(mounted "/wallets/${wallet_id}/sealed-approvals/new.json")" \
      "Sealed Approval ceremony projection read")"
    if printf '%s' "$approval_body" | jq -e '
      (.approval_id | test("^[0-9a-f]{64}$")) and
      (.ceremony_url | type == "string")
    ' >/dev/null 2>&1; then
      printf '%s\n' "$approval_body"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  die "fixture Sealed Approval prepare did not appear through the mounted VFS"
}

wait_for_approval_active() {
  wallet_id="$1"
  approval_id="$2"
  attempts=0
  while [ "$attempts" -lt 20 ]; do
    approvals="$(bounded_mounted_read \
      "$(mounted "/wallets/${wallet_id}/sealed-approvals/active.json")" \
      "Sealed Approval active-list projection read")"
    if printf '%s' "$approvals" | jq -e --arg approval_id "$approval_id" '
      any(.approvals[]?; .approval_id == $approval_id and .state == "ACTIVE")
    ' >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.25
  done
  die "fixture Sealed Approval did not become active through the mounted VFS"
}

assert_machine_secret_artifacts() {
  machine_pid_file="${log_dir}/machine.pid"
  [ -f "$machine_pid_file" ] || die "triad launcher omitted the Machine PID diagnostic"
  machine_pid="$(tr -d '[:space:]' < "$machine_pid_file")"
  case "$machine_pid" in *[!0-9]*|'') die "triad launcher published a malformed Machine PID" ;; esac
  kill -0 "$machine_pid" 2>/dev/null || die "Machine exited before MA-08 artifact capture"

  artifact_dir="${run_root}/machine-artifacts"
  mkdir -p "$artifact_dir"
  machine_diagnostic="${artifact_dir}/machine-sample.txt"
  # A stack diagnostic is useful and portable on macOS; it complements the
  # full memory/core capture required by the Tart acceptance profile.
  if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/sample ]; then
    sample_timeout_secs="${BLOOM_MA08_SAMPLE_TIMEOUT_SECS:-10}"
    bloom_bounded_process "$sample_timeout_secs" "${artifact_dir}/sample.log" \
      /usr/bin/sample "$machine_pid" 1 1 -file "$machine_diagnostic" ||
      printf 'sample unavailable for this developer login\n' > "$machine_diagnostic"
  else
    ps -o pid=,ppid=,state=,command= -p "$machine_pid" > "$machine_diagnostic"
  fi

  require_capture="${BLOOM_MA08_REQUIRE_MEMORY_CAPTURE:-0}"
  request_capture="${BLOOM_MA08_CAPTURE_MEMORY:-$require_capture}"
  case "$require_capture:$request_capture" in
    0:0|0:1|1:1) ;;
    *) die "BLOOM_MA08_REQUIRE_MEMORY_CAPTURE and BLOOM_MA08_CAPTURE_MEMORY must be 0 or 1" ;;
  esac
  machine_core=""
  if [ "$request_capture" -eq 1 ]; then
    capture_timeout_secs="${BLOOM_MA08_MEMORY_CAPTURE_TIMEOUT_SECS:-180}"
    case "$(uname -s)" in
      Darwin)
        machine_core="${artifact_dir}/machine.core"
        if ! command -v lldb >/dev/null 2>&1 ||
          ! bloom_bounded_process "$capture_timeout_secs" "${artifact_dir}/lldb.log" \
              lldb --batch -p "$machine_pid" \
              -o "process save-core ${machine_core}" \
              -o "process detach" ||
          [ ! -s "$machine_core" ]
        then
          machine_core=""
        fi
        ;;
      Linux)
        if command -v gcore >/dev/null 2>&1 &&
          bloom_bounded_process "$capture_timeout_secs" "${artifact_dir}/gcore.log" \
            gcore -o "${artifact_dir}/machine.core" "$machine_pid"
        then
          machine_core="${artifact_dir}/machine.core.${machine_pid}"
          [ -s "$machine_core" ] || machine_core=""
        fi
        ;;
      *) ;;
    esac
    if [ -z "$machine_core" ] && [ "$require_capture" -eq 1 ]; then
      die "MA-08 acceptance requires a readable full Machine memory/core capture; enable debugger task access in the disposable Tart VM"
    fi
  fi

  signer_database="${developer_root}/state/signer/signer.db"
  [ -f "$signer_database" ] || die "Signer database is unavailable for MA-08 decryptability control"
  scanner_args=(
    assert-machine-secret-confinement
    --signer-db "$signer_database"
    --authenticator-seed replacement-auth
    --artifact "$machine_home"
    --artifact "${log_dir}/machine.log"
    --artifact "$artifact_dir"
  )
  "$driver_bin" "${scanner_args[@]}"
  if [ -z "$machine_core" ]; then
    printf 'MA-08 portable lane: filesystem and Machine diagnostics scanned; full memory/core capture is enforced by BLOOM_MA08_REQUIRE_MEMORY_CAPTURE=1 in Tart acceptance\n'
  else
    printf 'MA-08 acceptance lane: live Machine full memory/core artifact scanned (%s)\n' "$machine_core"
  fi
}

printf 'Building deterministic ceremony driver...\n'
if [ -z "${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:-}" ]; then
  (cd "$broker_repo" && cargo build -p bloom-broker-debug-driver)
fi
start_stack

# Machine exposes credential replacement and the explicit legacy-passkey
# receipt migration workflow. Prove the exact user-visible CLI inventory and
# that neither operation is exposed as an unaudited mounted mutation surface.
wallet_help="$(cli wallet --help)"
credential_commands="$(printf '%s\n' "$wallet_help" |
  sed -n 's/^  \([a-z][a-z-]*\)  *.*/\1/p' |
  grep -E '(credential|passkey|authenticator)' || true)"
[ "$credential_commands" = "migrate-passkey
rebind-passkey" ] ||
  die "credential-change CLI inventory is not exactly migrate-passkey and rebind-passkey: ${credential_commands:-<none>}"

printf 'MA-03: registering wallet through Broker/Signer...\n'
registration_launch="$(cli wallet new ma03-registration)"
registration_result="$(complete_launch "$registration_launch" registration-auth --sign-count 1)"
registered_wallet="$(printf '%s' "$registration_result" | jq -er '.wallet_id')"
registered_projection="$(assert_projection_pair "$registered_wallet" registration)"
printf '%s' "$registered_projection" | jq -e '
  (.credentials | length) == 1 and (.keys | length) == 1
' >/dev/null || die "registration projection omitted public authority descriptors"
original_credential="$(printf '%s' "$registered_projection" | jq -er '.credentials[0].credential_id')"
wallet_entries="$(bounded_mounted_list "$(mounted "/wallets/${registered_wallet}")" \
  "wallet projection directory read")"
if printf '%s\n' "$wallet_entries" | grep -Eiq '(credential|passkey|authenticator|rebind)'; then
  die "unexpected mounted credential mutation surface is exposed"
fi

printf 'MA-03: importing wallet through Broker/Signer...\n'
mnemonic_file="${run_root}/import-mnemonic"
printf '%s\n' \
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art' \
  > "$mnemonic_file"
chmod 0600 "$mnemonic_file"
import_launch="$(cli wallet import ma03-import)"
import_result="$(complete_launch "$import_launch" import-auth \
  --sign-count 1 --mnemonic-file "$mnemonic_file")"
imported_wallet="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
[ "$imported_wallet" != "$registered_wallet" ] || die "registration and import returned one wallet"
assert_projection_pair "$imported_wallet" import >/dev/null
imported_accounts="$(cli wallet accounts "$imported_wallet")"
printf '%s' "$imported_accounts" | jq -e \
  --arg wallet "$imported_wallet" --arg evm_path "m/44'/60'/0'/0/0" '
    .wallet_id == $wallet and
    .seed_profile == "bip39-multicurve-v1" and
    any(.accounts[];
      .wallet_seed_profile == "bip39-multicurve-v1" and
      .derivation_profile == "bip44-evm-secp256k1-v1" and
      .path == $evm_path and
      .lifecycle == "ACTIVE")
  ' >/dev/null || die "mnemonic import omitted its canonical BIP-39 EVM account"
mounted_accounts="$(bounded_mounted_read \
  "$(mounted "/wallets/${imported_wallet}/accounts.json")" \
  "imported BIP-39 account projection read")"
[ "$(printf '%s' "$imported_accounts" | jq -cS .)" = \
  "$(printf '%s' "$mounted_accounts" | jq -cS .)" ] ||
  die "CLI and mounted BIP-39 account projections disagree"
assert_no_legacy_record "$registered_wallet" "$imported_wallet"

printf 'MA-03: replacing the registered wallet credential...\n'
rebind_launch="$(cli wallet rebind-passkey "$registered_wallet")"
complete_launch "$rebind_launch" registration-auth --sign-count 2 \
  --new-authenticator-seed replacement-auth >/dev/null
rebound_projection="$(assert_projection_pair "$registered_wallet" credential-replace)"
replacement_credential="$(printf '%s' "$rebound_projection" | jq -er '.credentials[0].credential_id')"
[ "$replacement_credential" != "$original_credential" ] ||
  die "credential replacement did not change the public credential descriptor"
printf '%s' "$rebound_projection" | jq -e '(.credentials | length) == 1' >/dev/null ||
  die "credential replacement left an unexpected credential set"
printf '%s' "$rebound_projection" | jq -e \
  --arg original "$original_credential" --arg replacement "$replacement_credential" '
    (.credentials | length) == 1 and
    .credentials[0].credential_id == $replacement and
    all(.credentials[]; .credential_id != $original)
  ' >/dev/null || die "CLI and mounted projection did not expose only the replacement credential"

printf 'MA-03: committing a policy update through its completed ceremony receipt...\n'
fixture_hash="$(jq -er '.records[] | select(.subject.kind == "petal" and .subject.route == "r000001") | .subject.package_hash' \
  "${developer_root}/config/provenance-catalog.json" | head -n 1)"
current_policy="$(bounded_mounted_read \
  "$(mounted "/wallets/${registered_wallet}/policy.json")" \
  "current wallet policy read")"
old_policy_version="$(printf '%s' "$rebound_projection" | jq -er '.policy.version | tonumber')"
policy_file="${run_root}/proposed-policy.json"
printf '%s' "$current_policy" | jq -cS --arg package_hash "$fixture_hash" '
  .allowed_petal_packages = ((.allowed_petal_packages + [$package_hash]) | unique | sort)
' > "$policy_file"
if ! policy_launch="$(cli wallet update-policy "$registered_wallet" --file "$policy_file" 2>&1)"; then
  die "policy update launch failed: ${policy_launch:-<no diagnostic>}"
fi
if ! policy_completion="$(complete_launch "$policy_launch" replacement-auth --sign-count 2 2>&1)"; then
  die "policy update ceremony failed: ${policy_completion:-<no diagnostic>}"
fi
policy_operation="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
[[ "$policy_operation" =~ ^[0-9a-f]{64}$ ]] || die "policy update launch omitted a valid operation_id"
if ! policy_commit="$(cli wallet commit-policy "$policy_operation" 2>&1)"; then
  die "policy commit failed: ${policy_commit:-<no diagnostic>}"
fi
policy_projection="$(assert_projection_pair "$registered_wallet" policy-update)"
new_policy_version="$(printf '%s' "$policy_projection" | jq -er '.policy.version | tonumber')"
[ "$new_policy_version" -eq $((old_policy_version + 1)) ] ||
  die "policy update did not advance the signed projection version exactly once"
printf '%s' "$policy_projection" | jq -e --arg package_hash "$fixture_hash" '
  (.policy.canonical_policy | type == "string") and
  (.wallet.policy_digest == .policy.policy_digest)
' >/dev/null || die "policy projection is internally inconsistent"
mounted_policy="$(bounded_mounted_read \
  "$(mounted "/wallets/${registered_wallet}/policy.json")" \
  "updated wallet policy read")"
printf '%s' "$mounted_policy" | jq -e --arg package_hash "$fixture_hash" '
  .allowed_petal_packages | index($package_hash) != null
' >/dev/null || die "mounted policy did not expose the committed authority change"

printf 'MA-03: deriving a Signer-owned Petal key from a mounted Petal request...\n'
request_id="ma03-key-derive-$$"
fixture_request="$(jq -nc \
  --arg request_id "$request_id" --arg wallet_id "$registered_wallet" \
  '{request_id:$request_id,wallet_id:$wallet_id,purpose:"fixture.payload",
    maximum_lifetime_ms:900000,preimage_hex:"6d613033",
    nonce_hex:"11111111111111111111111111111111",approval_hint:null}')"
printf '%s\n' "$fixture_request" > "$(mounted /petals/triad-authority-fixture/session.json)" 2>/dev/null || true
key_record="$(wait_for_fixture_record "$request_id")"
key_ceremony_url="$(printf '%s' "$key_record" | jq -er '.ceremony_url')"
before_key_count="$(printf '%s' "$policy_projection" | jq -er '.keys | length')"
"$driver_bin" complete "$key_ceremony_url" replacement-auth --sign-count 3 >/dev/null
derived_projection="$(assert_projection_pair "$registered_wallet" key-derive)"
after_key_count="$(printf '%s' "$derived_projection" | jq -er '.keys | length')"
[ "$after_key_count" -eq $((before_key_count + 1)) ] ||
  die "derived key did not appear in the public wallet projection"
printf '%s' "$derived_projection" | jq -e '
  any(.keys[]; .key_ref.derivation != null)
' >/dev/null || die "derived key projection omitted public derivation metadata"
printf '%s' "$derived_projection" | jq -e --arg replacement "$replacement_credential" '
  (.credentials | length) == 1 and
  .credentials[0].credential_id == $replacement
' >/dev/null || die "later Broker projection refresh lost the replacement credential"

printf 'MA-08: signing with the scoped child through the mounted fixture Petal...\n'
# Re-run the exact mounted request after custody completion.  The Petal must
# now reach the canonical missing-approval boundary rather than receiving any
# child secret or a Machine-minted capability.
printf '%s\n' "$fixture_request" > "$(mounted /petals/triad-authority-fixture/session.json)" 2>/dev/null || true
fixture_missing_approval="$(wait_for_fixture_stage signing_failed)"
printf '%s' "$fixture_missing_approval" | jq -e '
  .stage == "signing_failed" and (.error | contains("APPROVAL_NOT_FOUND"))
' >/dev/null || die "fixture Petal did not fail closed before Sealed Approval preparation"

fixture_key_record_path=""
while IFS= read -r record_name; do
  [ -n "$record_name" ] || continue
  candidate="/petal-key-requests/${record_name}"
  candidate_body="$(bounded_mounted_read "$(mounted "$candidate")" \
    "Petal key request candidate read")"
  if printf '%s' "$candidate_body" | jq -e --arg request_id "$request_id" \
    '.request_id == $request_id and .status == "succeeded" and .public_key != null' \
    >/dev/null 2>&1
  then
    fixture_key_record_path="$candidate"
    fixture_key_record_body="$candidate_body"
    break
  fi
done < <(bounded_mounted_list "$(mounted /petal-key-requests)" \
  "Petal key request directory read")
[ -n "$fixture_key_record_path" ] || die "completed fixture key record was not found through the mount"

fixture_key_ref="$(printf '%s' "$fixture_key_record_body" | jq -ec '.public_key.key_ref')"
fixture_provenance_digest="$(printf '%s' "$fixture_key_record_body" | jq -er '.provenance_digest')"
fixture_agent_id="$(printf '%s' "$fixture_key_record_body" | jq -c '.scope.agent_id')"
wallet_authority="$(bounded_mounted_read \
  "$(mounted "/wallets/${registered_wallet}/addresses.json")" \
  "wallet authority projection read")"
policy_version="$(printf '%s' "$wallet_authority" | jq -er '.policy_version')"
policy_digest="$(printf '%s' "$wallet_authority" | jq -er '.policy_digest')"
wallet_revocation_epoch="$(printf '%s' "$wallet_authority" | jq -er '.wallet_revocation_epoch')"
approval_now_ms="$(( $(date +%s) * 1000 ))"
# The approval must outlive Broker's custody ceremony so the completed
# activation cannot already exceed immutable terms. It remains strictly
# inside the fixture child's 15-minute scope.
approval_expires_ms="$((approval_now_ms + 600000))"
approval_operation_id="$(printf '%s' "${request_id}:approval" | shasum -a 256 | awk '{print $1}')"
approval_nonce="$(printf '%s' "${request_id}:nonce" | shasum -a 256 | awk '{print substr($1, 1, 32)}')"
approval_plan="$(jq -ncS \
  --arg wallet_id "$registered_wallet" --arg package_hash "$fixture_hash" \
  --arg route "r000001" --arg operation_class "fixture.payload" \
  --arg payload_sha256 "$(printf 'ma03' | shasum -a 256 | awk '{print $1}')" \
  '{wallet_id:$wallet_id,package_hash:$package_hash,route:$route,
    operation_class:$operation_class,payload_sha256:$payload_sha256}')"
approval_plan_digest="$(printf '%s' "$approval_plan" | shasum -a 256 | awk '{print $1}')"
approval_request="$(jq -ncS \
  --arg operation_id "$approval_operation_id" --arg wallet_id "$registered_wallet" \
  --arg package_hash "$fixture_hash" --arg route "r000001" \
  --argjson agent_id "$fixture_agent_id" --argjson key_ref "$fixture_key_ref" \
  --arg policy_version "$policy_version" --arg policy_digest "$policy_digest" \
  --arg revocation_epoch "$wallet_revocation_epoch" \
  --arg provenance_digest "$fixture_provenance_digest" --arg nonce "$approval_nonce" \
  --arg issued_at_ms "$approval_now_ms" --arg expires_at_ms "$approval_expires_ms" \
  --arg plan_digest "$approval_plan_digest" \
  '{operation_id:$operation_id,canonical_plan_facts_digest:$plan_digest,terms:{
    subject:{kind:"petal",package_hash:$package_hash,route:$route,agent_id:$agent_id},
    wallet_id:$wallet_id,key_ref:$key_ref,
    allowed_crypto_suites:["secp256k1-sha256-recoverable"],
    selector:{kind:"petal",package_hash:$package_hash,route:$route,
      allowed_operation_classes:["fixture.payload"],required_claim_assurance:"machine_asserted"},
    limits:{max_operations:"1",max_signatures:"1",operation_rate_limits:[],
      signature_rate_limits:[],value_limits:[]},
    activation_mode:{kind:"boot_bound"},wallet_revocation_epoch:$revocation_epoch,
    policy_version:$policy_version,policy_digest:$policy_digest,
    provenance_digest:$provenance_digest,request_nonce:$nonce,
    issued_at_ms:$issued_at_ms,not_before_ms:$issued_at_ms,
    expires_at_ms:$expires_at_ms,renewal_of:null}}')"
printf '%s\n' "$approval_request" > \
  "$(mounted "/wallets/${registered_wallet}/sealed-approvals/new.json")"
approval_projection="$(wait_for_approval_prepare "$registered_wallet")"
fixture_approval_id="$(printf '%s' "$approval_projection" | jq -er '.approval_id')"
approval_ceremony_url="$(printf '%s' "$approval_projection" | jq -er '.ceremony_url')"
"$driver_bin" complete "$approval_ceremony_url" replacement-auth --sign-count 4 >/dev/null
wait_for_approval_active "$registered_wallet" "$fixture_approval_id"
fixture_request="$(printf '%s' "$fixture_request" | jq -cS --arg approval_id "$fixture_approval_id" \
  '.approval_hint = $approval_id')"
printf '%s\n' "$fixture_request" > "$(mounted /petals/triad-authority-fixture/session.json)"
fixture_signed="$(wait_for_fixture_stage complete)"
printf '%s' "$fixture_signed" | jq -e '
  .stage == "complete" and
  (.public_key.key_ref_jcs | type == "array") and
  (.signature_hex | test("^[0-9a-f]+$"))
' >/dev/null || die "fixture Petal did not complete scoped payload signing"
assert_machine_secret_artifacts

printf 'MA-03: deleting the imported wallet through Broker/Signer...\n'
delete_launch="$(cli wallet delete "$imported_wallet")"
complete_launch "$delete_launch" import-auth --sign-count 2 >/dev/null
wallet_list="$(cli wallet list)"
printf '%s\n' "$wallet_list" | grep -F "$registered_wallet" >/dev/null ||
  die "retained wallet disappeared after another wallet deletion"
if printf '%s\n' "$wallet_list" | grep -F "$imported_wallet" >/dev/null; then
  die "deleted wallet remained in CLI projection discovery"
fi
[ ! -e "$(mounted "/wallets/${imported_wallet}")" ] ||
  die "deleted wallet remained in mounted VFS discovery"
assert_no_legacy_record "$registered_wallet" "$imported_wallet"

before_restart="$(printf '%s' "$derived_projection" | jq -cS 'del(.observed_at_ms, .freshness)')"
printf 'MA-03: restarting the out-of-process stack over the same authoritative state...\n'
stop_stack
start_stack
after_restart_projection="$(assert_projection_pair "$registered_wallet" restart)"
after_restart="$(printf '%s' "$after_restart_projection" | jq -cS 'del(.observed_at_ms, .freshness)')"
[ "$before_restart" = "$after_restart" ] ||
  die "retained Broker projection changed across Machine restart"
printf '%s' "$after_restart_projection" | jq -e \
  --arg original "$original_credential" --arg replacement "$replacement_credential" '
    (.credentials | length) == 1 and
    .credentials[0].credential_id == $replacement and
    all(.credentials[]; .credential_id != $original)
  ' >/dev/null ||
  die "replacement credential was not preserved solely through Broker projection across restart"
restart_list="$(cli wallet list)"
printf '%s\n' "$restart_list" | grep -F "$registered_wallet" >/dev/null ||
  die "retained wallet did not survive Machine restart"
if printf '%s\n' "$restart_list" | grep -F "$imported_wallet" >/dev/null; then
  die "deleted wallet resurrected across Machine restart"
fi
[ ! -e "$(mounted "/wallets/${imported_wallet}")" ] ||
  die "deleted wallet resurrected in the mounted VFS across restart"
assert_no_legacy_record "$registered_wallet" "$imported_wallet"

printf 'MA-03 projection fidelity passed: the sole retained credential-change surface (replacement), registration, import, policy update, Petal key derivation, deletion, and restart matched through CLI and mounted VFS; no credential add/remove Machine surface exists.\n'
