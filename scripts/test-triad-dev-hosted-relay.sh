#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/bloom-relay-launcher-test.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
launcher_args=(
  --developer-root "$test_root/developer"
  --machine-socket "$test_root/machine.sock"
  --log-dir "$test_root/logs"
  --ready-file "$test_root/ready"
)
# Omitting both pins selects the packaged ones; supplying only one fails.
if env -u BLOOM_TRIAD_DEV_RELAY_CONTROL_CA_FILE \
  BLOOM_TRIAD_DEV_RELAY_RECEIPT_KEY_FILE="$repo_root/packaging/triad/relay/receipt-public-key.hex" \
  "$repo_root/scripts/triad-dev-launch.sh" \
    "${launcher_args[@]}" --hosted-relay \
    > "$test_root/missing-pins.out" 2>&1; then
  printf 'launcher accepted hosted relay with only one trust pin\n' >&2
  exit 1
fi
grep -q 'requires both BLOOM_TRIAD_DEV_RELAY_CONTROL_CA_FILE' \
  "$test_root/missing-pins.out"
if "$repo_root/scripts/triad-dev-launch.sh" \
  "${launcher_args[@]}" --services-only --hosted-relay \
  > "$test_root/services-only.out" 2>&1; then
  printf 'launcher combined hosted relay with services-only\n' >&2
  exit 1
fi
grep -q 'requires the complete Triad' "$test_root/services-only.out"
cat > "${test_root}/fake-signer" <<'SIGNER'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = admin ] && [ "$3" = --signer-uid ] || exit 91
command="$2"
if [ "$FAKE_SCENARIO" = stuck ]; then
  trap '' TERM
  while :; do sleep 1; done
fi
count_file="${FAKE_STATE}/${command}.count"
count="$(cat "$count_file" 2>/dev/null || printf 0)"
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
if [ "$command" = provision ]; then
  case "$FAKE_SCENARIO" in
    rejected)
      printf 'relay allocation rejected\n' >&2
      exit 1 ;;
    certificate_pending)
      printf 'remote certificate and routing are pending; retry status or provision\n' >&2
      exit 1 ;;
    uri_pending)
      if [ "$count" -eq 1 ]; then
        printf 'Broker ACME account URI is pending; retry provision after account creation\n' >&2
        exit 1
      fi ;;
    *) ;;
  esac
fi
mode=remote_enabled
installation=null
effective=localhost_only
tls=false
routing=false
effective_revision=1
if [ "$FAKE_SCENARIO" = localhost ]; then mode=localhost_only; fi
if [ "$FAKE_SCENARIO" = already_ready ] ||
   [ "$FAKE_SCENARIO" = bound_pending ] ||
   [ -e "${FAKE_STATE}/provision.count" ]; then
  installation='"installation-1"'
fi
if [ "$FAKE_SCENARIO" = already_ready ] ||
   { [ "$FAKE_SCENARIO" = certificate_pending ] && [ "$command" = status ] && [ "$count" -ge 3 ]; } ||
   { [ "$FAKE_SCENARIO" = uri_pending ] && [ "$command" = status ] && [ "$count" -ge 3 ]; }; then
  effective=remote_enabled
  tls=true
  routing=true
fi
if [ "$FAKE_SCENARIO" = bound_pending ] && [ "$command" = status ] && [ "$count" -ge 3 ]; then
  effective=remote_enabled
  tls=true
  routing=true
fi
if [ "$FAKE_SCENARIO" = revision_mismatch ] || [ "$FAKE_SCENARIO" = routing_pending ]; then
  effective=remote_enabled
  tls=true
  routing=true
  if [ "$FAKE_SCENARIO" = revision_mismatch ]; then effective_revision=0; fi
  if [ "$FAKE_SCENARIO" = routing_pending ]; then routing=false; fi
fi
printf '{"installation_id":%s,"desired_mode":"%s","effective_mode":"%s","desired_revision":"1","effective_revision":"%s","remote_tls_ready":%s,"remote_routing_ready":%s,"surfaces":[{"identity":{"surface_id":"remote"},"lifecycle":"ACTIVE"}]}\n' \
  "$installation" "$mode" "$effective" "$effective_revision" "$tls" "$routing"
SIGNER
chmod +x "${test_root}/fake-signer"

run_case() {
  local scenario="$1" expected="$2" case_root="${test_root}/${1}"
  mkdir -p "$case_root/logs" "$case_root/state/admin"
  if [ "$scenario" = bound_pending ]; then
    : > "$case_root/state/admin/acme-account-bound.json"
  fi
  if FAKE_SCENARIO="$scenario" FAKE_STATE="$case_root" CASE_ROOT="$case_root" \
    FAKE_SIGNER="${test_root}/fake-signer" REPO_ROOT="$repo_root" \
    bash -c '
      set -euo pipefail
      die() { printf "%s\n" "$*" >&2; exit 1; }
      machine_cli() { [ "$*" = "serve triad-health-check digest" ]; }
      developer_root="$CASE_ROOT"
      log_dir="$CASE_ROOT/logs"
      signer_bin="$FAKE_SIGNER"
      relay_timeout_seconds=15
      case "$FAKE_SCENARIO" in
        stuck|never_ready|revision_mismatch|routing_pending) relay_timeout_seconds=3 ;;
      esac
      release_digest=digest
      session_pid=$PPID; machine_pid=$PPID; signer_pid=$PPID; broker_pid=$PPID
      relay_admin_pid=""
      source "$REPO_ROOT/scripts/lib/triad-dev-hosted-relay.sh"
      wait_for_hosted_relay
      printf "ready\n" > "$CASE_ROOT/ready"
    ' > "$case_root/out" 2>&1; then
    [ "$expected" = success ] || { printf '%s unexpectedly succeeded\n' "$scenario" >&2; exit 1; }
    [ "$(cat "$case_root/ready")" = ready ]
  else
    [ "$expected" = failure ] || { cat "$case_root/out" >&2; exit 1; }
    [ ! -e "$case_root/ready" ]
  fi
}
run_case already_ready success
[ ! -e "${test_root}/already_ready/provision.count" ]
run_case certificate_pending success
[ "$(cat "${test_root}/certificate_pending/provision.count")" = 1 ]
run_case uri_pending success
[ "$(cat "${test_root}/uri_pending/provision.count")" -ge 2 ]
run_case bound_pending success
[ ! -e "${test_root}/bound_pending/provision.count" ]
run_case localhost failure
[ ! -e "${test_root}/localhost/provision.count" ]
grep -q 'localhost_only' "${test_root}/localhost/out"
run_case rejected failure
grep -q 'relay allocation rejected' "${test_root}/rejected/out"
run_case stuck failure
grep -q 'exceeded the hosted relay timeout' "${test_root}/stuck/out"
run_case never_ready failure
grep -Eq 'did not become effective|exceeded the hosted relay timeout' \
  "${test_root}/never_ready/out"
run_case revision_mismatch failure
run_case routing_pending failure
printf 'hosted relay launcher state tests passed\n'
