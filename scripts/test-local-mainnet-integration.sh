#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_bin="${repo_root}/scripts/test-fixtures/fake-triad-dev-launcher.sh"
runner="${repo_root}/scripts/local-mainnet-integration.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/bloom-integration-test.XXXXXX")"
test_ok=0
cleanup_test() {
  if [ "$test_ok" -eq 1 ]; then
    rm -rf "$test_root"
  else
    printf 'failed test fixtures retained at: %s\n' "$test_root" >&2
  fi
}
trap cleanup_test EXIT

canonical_home="${test_root}/home"
mkdir -p "${canonical_home}/cache" \
  "${canonical_home}/petals/store/packages/fixture" \
  "${canonical_home}/petals/store/owners"
printf '%s\n' \
  '[petals]' \
  'preinstalled = ["enso", "near-intents"]' \
  > "${canonical_home}/config.toml"
printf '%s\n' '{"schema":"fixture-projection","wallets":{"test-passkey":{}}}' \
  > "${canonical_home}/cache/wallet-projections.json"
printf '%s\n' 'persistent package bytes' \
  > "${canonical_home}/petals/store/packages/fixture/package.bin"
printf '%s\n' 'fixture-package-hash' \
  > "${canonical_home}/petals/store/owners/user-choice"
mkdir "${test_root}/before"
cp "${canonical_home}/config.toml" "${test_root}/before/config.toml"
cp -R "${canonical_home}/petals" "${test_root}/before/petals"

output="$(
  printf '\n\n\n\n' | env \
    BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
    BLOOM_FAKE_STATE="${test_root}/preflight-state" \
    BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
    BLOOM_INTEGRATION_OPEN=true \
      "$runner" --wallet test-passkey
)"
grep -q 'Preflight passed' <<<"$output"
grep -q 'Fixture Petal: Signer-owned sub-key derived' <<<"$output"
grep -q 'no venue order was submitted' <<<"$output"
test -f "${test_root}/preflight-state/policy-prepared"
test -f "${test_root}/preflight-state/policy-committed"
test -f "${test_root}/preflight-state/approval-prepared"
test -f "${test_root}/preflight-state/approval-active"
test ! -e "${test_root}/preflight-state/approval-invalid"
test -f "${test_root}/preflight-state/fixture-signed"
cmp "${test_root}/before/config.toml" "${canonical_home}/config.toml"
diff -r "${test_root}/before/petals" "${canonical_home}/petals"
expected_machine_home="$(cd "${canonical_home}/triad-dev/state/machine" && pwd -P)"
recorded_machine_home="$(cat "${test_root}/preflight-state/machine-home")"
recorded_machine_home="$(cd "$recorded_machine_home" && pwd -P)"
test "$recorded_machine_home" = "$expected_machine_home"

# The real launcher refuses any Machine home outside the developer root before
# it builds or starts a service, including the persistent canonical home.
guard_home="${test_root}/guard-user"
mkdir -p "$guard_home" "${test_root}/guard-canonical"
ln -s "${test_root}/guard-canonical" "${guard_home}/.bloom"
if HOME="$guard_home" "$repo_root/scripts/triad-dev-launch.sh" \
  --developer-root "${test_root}/developer" \
  --machine-home "${guard_home}/.bloom" \
  --mount "${test_root}/guard-mount" \
  --machine-socket "${test_root}/guard.sock" \
  --log-dir "${test_root}/guard-logs" \
  --ready-file "${test_root}/guard.ready" \
  >"${test_root}/canonical-guard.out" 2>&1
then
  printf 'developer launcher unexpectedly accepted canonical ~/.bloom\n' >&2
  exit 1
fi
grep -q 'Machine home must be inside the developer root' \
  "${test_root}/canonical-guard.out"

# Substituting a policy digest in the mounted public projection must not fool
# the authority double into activating an approval. This proves the fake binds
# the complete request to its independently retained committed policy state.
if printf '\n\n\n\n' | env \
  BLOOM_INTEGRATION_TEST_HOME="${test_root}/mutated-home" \
  BLOOM_FAKE_STATE="${test_root}/mutated-approval-state" \
  BLOOM_FAKE_MUTATE_APPROVAL_POLICY_DIGEST=1 \
  BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
  BLOOM_INTEGRATION_OPEN=true \
    "$runner" --wallet test-passkey \
    >"${test_root}/mutated-approval.out" 2>&1
then
  printf 'policy-digest-substituted approval unexpectedly activated\n' >&2
  exit 1
fi
grep -q 'fixture Sealed Approval prepare did not appear through the mount' \
  "${test_root}/mutated-approval.out"
test -f "${test_root}/mutated-approval-state/approval-invalid"
test ! -e "${test_root}/mutated-approval-state/approval-prepared"
test ! -e "${test_root}/mutated-approval-state/approval-active"
test ! -e "${test_root}/mutated-approval-state/fixture-signed"

# A first run may spend more than the former ten-second deadline provisioning
# configured Petals before the server creates its IPC socket.
delayed_output="$(
  printf '\n\n\n\n' | env \
    BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
    BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
    BLOOM_INTEGRATION_OPEN=true \
    BLOOM_FAKE_STARTUP_DELAY_SECS=11 \
      "$runner" --wallet test-passkey 2>"${test_root}/delayed.err"
)"
grep -q 'Preflight passed' <<<"$delayed_output"
grep -q 'Still starting Bloom' "${test_root}/delayed.err"

if BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
  BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
  BLOOM_INTEGRATION_OPEN=true \
    "$runner" --wallet test-passkey --execute-hyperliquid \
    >"${test_root}/removed-hyperliquid.out" 2>&1
then
  printf 'removed native Hyperliquid flag unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'unknown argument: --execute-hyperliquid' "${test_root}/removed-hyperliquid.out"

if BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
  BLOOM_INTEGRATION_OPEN=true "$runner" --wallet test-passkey \
    --execute-polymarket --pm-slug fixture --pm-outcome Yes --pm-side buy \
    --pm-amount 26 --pm-price-bound 0.5 --pm-order-type FAK \
    >"${test_root}/pm-cap.out" 2>&1
then
  printf 'oversized Polymarket order unexpectedly passed validation\n' >&2
  exit 1
fi
grep -q 'maximum consideration exceeds' "${test_root}/pm-cap.out"

if BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
  BLOOM_INTEGRATION_OPEN=true "$runner" --wallet test-passkey \
    --execute-polymarket --pm-slug fixture --pm-outcome Yes --pm-side buy \
    --pm-amount 1 --pm-price-bound 0.5 --pm-order-type GTC \
    >"${test_root}/pm-order-type.out" 2>&1
then
  printf 'unsafe Polymarket order type unexpectedly passed validation\n' >&2
  exit 1
fi
grep -q 'must be FAK or FOK' "${test_root}/pm-order-type.out"

if BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
  BLOOM_INTEGRATION_OPEN=true "$runner" --wallet test-passkey \
    --execute-polymarket --pm-slug fixture --pm-outcome Yes --pm-side buy \
    --pm-amount 1 --pm-price-bound 1.1 --pm-order-type FAK \
    >"${test_root}/pm-price-bound.out" 2>&1
then
  printf 'invalid Polymarket price bound unexpectedly passed validation\n' >&2
  exit 1
fi
grep -q 'price bound must be in' "${test_root}/pm-price-bound.out"

if command -v expect >/dev/null 2>&1; then
  legacy_pm_output="${test_root}/legacy-pm.out"
  # A legacy hash-only route contract must be rejected after the generic
  # fixture proof but before the venue Petal receives a draft write.
  # shellcheck disable=SC2016
  if RUNNER="$runner" BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
    BLOOM_FAKE_STATE="${test_root}/legacy-pm-state" \
    BLOOM_FAKE_PM_SIGNING_ABI="0.1.0" \
    BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" BLOOM_INTEGRATION_OPEN=true \
    expect -c '
      set timeout 20
      log_user 1
      spawn $env(RUNNER) --wallet test-passkey --execute-polymarket \
        --pm-slug fixture --pm-outcome Yes --pm-side buy \
        --pm-amount 1 --pm-price-bound 0.5 --pm-order-type FAK
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect eof
      set result [wait]
      exit [lindex $result 3]
    ' >"$legacy_pm_output" 2>&1
  then
    printf 'legacy hash-only Polymarket route unexpectedly reached live execution\n' >&2
    exit 1
  fi
  tr -d '\r' <"$legacy_pm_output" | grep -Fxq \
    'error: local Polymarket Petal is not production-triad signing compatible; no draft was staged'
  test ! -e "${test_root}/legacy-pm-state/pm-draft-staged"
  test ! -e "${test_root}/legacy-pm-state/pm-posted"

  live_output="${test_root}/live.out"
  # Expect expands its own $env(RUNNER).
  # shellcheck disable=SC2016
  RUNNER="$runner" \
  BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
    BLOOM_FAKE_STATE="${test_root}/fake-state" \
    BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" \
    BLOOM_INTEGRATION_OPEN=true \
    expect -c '
      set timeout 20
      log_user 1
      spawn $env(RUNNER) \
        --wallet test-passkey \
        --execute-polymarket \
        --pm-slug fixture --pm-outcome Yes --pm-side buy \
        --pm-amount 1 --pm-price-bound 0.5 --pm-order-type FAK
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "to authorize the selected submission(s):"
      send "EXECUTE POLYMARKET MAINNET ORDER\r"
      expect "to request its passkey approval:"
      send "POST POLYMARKET DRAFT draft-1\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect eof
      set result [wait]
      exit [lindex $result 3]
    ' >"$live_output"
  grep -q 'PASS: the selected Polymarket mainnet submission' "$live_output"
  test -f "${test_root}/fake-state/pm-posted"

  wrong_ack_output="${test_root}/wrong-ack.out"
  # shellcheck disable=SC2016
  if RUNNER="$runner" BLOOM_INTEGRATION_TEST_HOME="${test_root}/home" \
    BLOOM_FAKE_STATE="${test_root}/wrong-ack-state" \
    BLOOM_TRIAD_DEV_LAUNCHER="$fixture_bin" BLOOM_INTEGRATION_OPEN=true \
    expect -c '
      set timeout 20
      log_user 1
      spawn $env(RUNNER) --wallet test-passkey --execute-polymarket \
        --pm-slug fixture --pm-outcome Yes --pm-side buy \
        --pm-amount 1 --pm-price-bound 0.5 --pm-order-type FAK
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "Complete the passkey ceremony in the browser, then press Return"
      send "\r"
      expect "to authorize the selected submission(s):"
      send "EXECUTE SOMETHING ELSE\r"
      expect eof
      set result [wait]
      exit [lindex $result 3]
    ' >"$wrong_ack_output" 2>&1
  then
    printf 'incorrect Polymarket acknowledgement unexpectedly succeeded\n' >&2
    exit 1
  fi
  grep -q 'mainnet acknowledgement did not match' "$wrong_ack_output"
fi

test_ok=1
printf 'local mainnet integration runner tests passed\n'
