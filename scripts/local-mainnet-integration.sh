#!/usr/bin/env bash
#
# Manual, passkey-backed mainnet integration for Bloom's local developer
# profile. The default is non-spending preflight. No order is sent unless its
# --execute-polymarket flag is present and the operator types the final
# acknowledgement at the terminal.

set -euo pipefail

readonly MAX_USD="25"
readonly FIXTURE_PACKAGE_HASH="2e2344e74b7ed11d4bb4c939671be9da72e13147dd16c3f6b6c347ae2c84d1ad"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Broker, Signer, and Machine developer state remain persistent so existing
# passkey wallets and the independently retained audit heads cannot diverge.
canonical_home="${BLOOM_INTEGRATION_TEST_HOME:-${HOME}/.bloom}"
developer_root="${BLOOM_TRIAD_DEV_ROOT:-${canonical_home}/triad-dev}"
wallet=""
execute_pm=0
pm_slug=""
pm_outcome=""
pm_side=""
pm_amount=""
pm_bound=""
pm_order_type="FAK"

usage() {
  cat <<'EOF'
Usage:
  scripts/local-mainnet-integration.sh --wallet WALLET

Non-spending preflight is the default. It still performs the real passkey
ceremonies needed to derive a fixture Petal sub-key and sign a fixture payload;
it never submits a venue order. To submit a tightly bounded mainnet order, add:

  --execute-polymarket
  --pm-slug SLUG --pm-outcome OUTCOME --pm-side buy|sell
  --pm-amount AMOUNT --pm-price-bound PRICE [--pm-order-type FAK|FOK]

Safety properties:
  * Live submission requires its explicit flag, exact arguments, and acknowledgement.
  * Polymarket is FAK/FOK only and <= $25 maximum consideration.
  * Exact plans and policy checks print before any passkey prompt.
  * The runner never directly reads or edits wallet keys or policy files.
  * Machine is built without embedded custody or signing features.

Environment:
  BLOOM_TRIAD_DEV_ROOT    Persistent Broker/Signer developer state and enrollment
                          (default: ~/.bloom/triad-dev)
  BLOOM_TRIAD_DEV_LAUNCHER
                          Deterministic shell-test launcher override
  BLOOM_INTEGRATION_OPEN  Browser opener (default: open)
  BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS
                          Server/Petal startup deadline (default: 300)
  BLOOM_INTEGRATION_POLYMARKET_PACKAGE
                          Local migrated Polymarket package checkout
  BLOOM_INTEGRATION_HYPERLIQUID_PACKAGE
                          Local migrated Hyperliquid package checkout
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_value() {
  [ "$#" -ge 2 ] || die "$1 requires a value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --wallet) need_value "$@"; wallet="$2"; shift 2 ;;
    --execute-polymarket) execute_pm=1; shift ;;
    --pm-slug) need_value "$@"; pm_slug="$2"; shift 2 ;;
    --pm-outcome) need_value "$@"; pm_outcome="$2"; shift 2 ;;
    --pm-side) need_value "$@"; pm_side="$2"; shift 2 ;;
    --pm-amount) need_value "$@"; pm_amount="$2"; shift 2 ;;
    --pm-price-bound) need_value "$@"; pm_bound="$2"; shift 2 ;;
    --pm-order-type) need_value "$@"; pm_order_type="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$wallet" ] || die "--wallet is required"
case "$wallet" in
  *[!A-Za-z0-9._-]*|'') die "wallet contains unsafe characters" ;;
esac

command -v jq >/dev/null 2>&1 || die "jq is required (brew install jq)"
browser_open="${BLOOM_INTEGRATION_OPEN:-open}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-300}"
case "$startup_timeout_secs" in
  *[!0-9]*|'') die "BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS must be an integer" ;;
esac
[ "$startup_timeout_secs" -ge 1 ] && [ "$startup_timeout_secs" -le 1800 ] ||
  die "BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS must be between 1 and 1800"

live=0
preflight_blockers=0
if [ "$execute_pm" -eq 1 ]; then
  live=1
fi

is_positive_decimal() {
  jq -en --arg value "$1" \
    '($value | test("^[0-9]+([.][0-9]+)?$")) and (($value | tonumber) > 0)' \
    >/dev/null
}

if [ "$live" -eq 1 ]; then
  command -v "$browser_open" >/dev/null 2>&1 ||
    die "browser opener '$browser_open' was not found"
  if [ "$execute_pm" -eq 1 ]; then
    for value in "$pm_slug" "$pm_outcome" "$pm_side" "$pm_amount" "$pm_bound"; do
      [ -n "$value" ] || die "all live Polymarket arguments shown in --help are required"
    done
    case "$pm_side" in buy|sell) ;; *) die "--pm-side must be buy or sell" ;; esac
    case "$pm_order_type" in FAK|FOK) ;; *) die "--pm-order-type must be FAK or FOK" ;; esac
    is_positive_decimal "$pm_amount" || die "--pm-amount must be a positive decimal"
    is_positive_decimal "$pm_bound" || die "--pm-price-bound must be a positive decimal"
    jq -en --arg p "$pm_bound" \
      '($p|tonumber) > 0 and ($p|tonumber) <= 1' >/dev/null ||
      die "Polymarket price bound must be in (0, 1]"
    if [ "$pm_side" = "buy" ]; then
      pm_max_consideration="$pm_amount"
    else
      pm_max_consideration="$(jq -nr --arg a "$pm_amount" --arg p "$pm_bound" \
        '($a|tonumber) * ($p|tonumber)')"
    fi
    jq -en --arg n "$pm_max_consideration" --arg cap "$MAX_USD" \
      '($n|tonumber) <= ($cap|tonumber)' >/dev/null ||
      die "Polymarket maximum consideration exceeds \$${MAX_USD}"
  fi
  [ -t 0 ] || die "live mode requires an interactive terminal"
fi

run_dir="$(mktemp -d "${TMPDIR:-/tmp}/bloom-mainnet-integration.XXXXXX")"
machine_home="${developer_root}/state/machine"
socket="${run_dir}/bloom.sock"
mount_dir="${run_dir}/mount"
server_log="${run_dir}/serve.log"
ready_file="${run_dir}/triad.ready"
server_pid=""
mkdir -p "$mount_dir" "${machine_home}/cache"

mounted_path() {
  case "$1" in
    /*) printf '%s%s\n' "$mount_dir" "$1" ;;
    *) die "internal VFS path is not absolute: $1" ;;
  esac
}

vcat() {
  local mounted_body
  mounted_body="$(cat "$(mounted_path "$1")")"
  [ -n "$mounted_body" ] || die "mounted VFS read returned no data: $1"
  printf '%s\n' "$mounted_body"
}

vwrite() {
  printf '%s\n' "$2" > "$(mounted_path "$1")"
}

# A command write which stages a ceremony is allowed to return either EACCES
# or success. macOS NFS can defer the handler denial; the authoritative result
# is the challenge/status file subsequently read through the same mount.
vwrite_staging() {
  vwrite "$1" "$2" 2>/dev/null || true
}

vls_names() {
  LC_ALL=C command ls -1 "$(mounted_path "$1")"
}

wait_for_fixture_stage() {
  expected="$1"
  attempts=0
  while [ "$attempts" -lt 100 ]; do
    fixture_body="$(cat "$(mounted_path "/petals/triad-authority-fixture/session.json")" 2>/dev/null || true)"
    fixture_stage="$(printf '%s' "$fixture_body" | jq -r '
      if .stage == "key" then "key:" + (.outcome.state // "")
      else .stage // ""
      end
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

wait_for_policy_status() {
  expected="$1"
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    policy_status_path="/wallets/${wallet}/policy-updates/latest/status.json"
    if [ "$expected" = "confirmed" ] && [ -n "${policy_update_action_id:-}" ]; then
      policy_status_path="/wallets/${wallet}/policy-updates/confirmed/${policy_update_action_id}/status.json"
    fi
    policy_status_body="$(cat "$(mounted_path "$policy_status_path")" 2>/dev/null || true)"
    policy_status="$(printf '%s' "$policy_status_body" | jq -r '.status // ""' 2>/dev/null || true)"
    if [ "$policy_status" = "$expected" ]; then
      printf '%s\n' "$policy_status_body"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  die "wallet policy update did not reach mounted status ${expected}"
}

wait_for_approval_prepare() {
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    approval_body="$(cat "$(mounted_path "/wallets/${wallet}/sealed-approvals/new.json")" 2>/dev/null || true)"
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
  die "fixture Sealed Approval prepare did not appear through the mount"
}

wait_for_approval_active() {
  expected_approval_id="$1"
  attempts=0
  while [ "$attempts" -lt 200 ]; do
    approvals_body="$(cat "$(mounted_path "/wallets/${wallet}/sealed-approvals/active.json")" 2>/dev/null || true)"
    if printf '%s' "$approvals_body" | jq -e --arg approval_id "$expected_approval_id" '
      any(.approvals[]?; .approval_id == $approval_id and .state == "active")
    ' >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  die "fixture Sealed Approval did not become active through the mount"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$status" -eq 0 ]; then
    rm -rf "$run_dir"
  else
    printf 'diagnostics retained at: %s\n' "$run_dir" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

triad_launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
[ -x "$triad_launcher" ] || die "triad developer launcher is not executable: $triad_launcher"
if [ -z "${BLOOM_TRIAD_DEV_LAUNCHER:-}" ]; then
  polymarket_package="${BLOOM_INTEGRATION_POLYMARKET_PACKAGE:-$(dirname "$repo_root")/bloom-petal-polymarket}"
  hyperliquid_package="${BLOOM_INTEGRATION_HYPERLIQUID_PACKAGE:-$(dirname "$repo_root")/bloom-petal-hyperliquid}"
  [ -d "$polymarket_package" ] || die "migrated Polymarket checkout is missing: $polymarket_package"
  [ -d "$hyperliquid_package" ] || die "migrated Hyperliquid checkout is missing: $hyperliquid_package"
else
  polymarket_package="${BLOOM_INTEGRATION_POLYMARKET_PACKAGE:-}"
  hyperliquid_package="${BLOOM_INTEGRATION_HYPERLIQUID_PACKAGE:-}"
fi
BLOOM_TRIAD_DEV_POLYMARKET_PACKAGE="$polymarket_package" \
BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE="$hyperliquid_package" \
BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=1 \
"$triad_launcher" \
  --developer-root "$developer_root" \
  --machine-home "$machine_home" \
  --mount "$mount_dir" \
  --machine-socket "$socket" \
  --log-dir "$run_dir" \
  --ready-file "$ready_file" >"$server_log" 2>&1 &
server_pid=$!

startup_started_at="$(date +%s)"
startup_deadline=$((startup_started_at + startup_timeout_secs))
startup_next_notice=$((startup_started_at + 10))
while [ ! -f "$ready_file" ]; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$server_log" >&2
    die "triad developer harness exited during startup"
  fi
  startup_now="$(date +%s)"
  if [ "$startup_now" -ge "$startup_deadline" ]; then
    cat "$server_log" >&2
    die "triad developer harness did not become ready within ${startup_timeout_secs}s"
  fi
  if [ "$startup_now" -ge "$startup_next_notice" ]; then
    startup_last_log="$(tail -n 1 "$server_log" 2>/dev/null || true)"
    printf 'Still starting Bloom (%ss elapsed); configured Petals may be provisioning.\n' \
      "$((startup_now - startup_started_at))" >&2
    if [ -n "$startup_last_log" ]; then
      printf '  last server log: %s\n' "$startup_last_log" >&2
    fi
    startup_next_notice=$((startup_now + 30))
  fi
  sleep 0.2
done

open_approval() {
  artifact_path="$1"
  approval_selector="${2:-.}"
  artifact="$(vcat "$artifact_path")"
  approval="$(printf '%s' "$artifact" | jq -ec "$approval_selector")"
  ceremony_url="$(printf '%s' "$approval" | jq -er '.ceremony_url')"
  expires_ms="$(printf '%s' "$approval" | jq -r '.expires_ms // .expires_at_ms // .ceremony_expires_at_ms // "unknown"')"
  printf '\nPasskey approval required:\n'
  printf '%s\n' "$artifact" | jq .
  "$browser_open" "$ceremony_url"
  printf 'Complete the passkey ceremony in the browser, then press Return (expires %s): ' \
    "${expires_ms:-unknown}"
  IFS= read -r _
}

printf '\nBloom local mainnet integration preflight\n'
printf '  authority home: %s\n  Machine overlay: %s\n  wallet:          %s\n' \
  "$developer_root" "$machine_home" "$wallet"
printf '  mode:   %s\n\n' "$([ "$live" -eq 1 ] && printf LIVE || printf NON-SPENDING)"

wallet_kind="$(vcat "/wallets/${wallet}/kind" | tr -d '[:space:]')"
[ "$wallet_kind" = "passkey" ] || die "VFS reports wallet kind '$wallet_kind', expected passkey"
wallet_address="$(vcat "/wallets/${wallet}/address" | tr -d '[:space:]')"
printf 'Passkey wallet: %s (%s)\n' "$wallet" "$wallet_address"

# A freshly registered wallet has no allowed Petal packages. Add only the
# deterministic fixture package through the canonical mounted policy custody
# lifecycle: policy.validate_update preparation, Broker-owned policy_update
# ceremony, completed custody receipt, and policy.commit_update on the exact
# write retry. This never edits policy state directly and does not make the
# production default permissive.
current_policy="$(vcat "/wallets/${wallet}/policy.json")"
printf '%s' "$current_policy" | jq -e \
  --arg wallet "$wallet" \
  '.wallet_id == $wallet and (.allowed_petal_packages | type == "array")' \
  >/dev/null || die "mounted wallet policy is malformed or names another wallet"
fixture_policy_allowed="$(printf '%s' "$current_policy" | jq -r \
  --arg package_hash "$FIXTURE_PACKAGE_HASH" \
  '.allowed_petal_packages | index($package_hash) != null')"
if [ "$fixture_policy_allowed" != "true" ]; then
  proposed_policy="$(printf '%s' "$current_policy" | jq -cS \
    --arg package_hash "$FIXTURE_PACKAGE_HASH" \
    '.allowed_petal_packages = ((.allowed_petal_packages + [$package_hash]) | unique | sort)')"
  printf '\nAuthorizing the fixture Petal package through the mounted wallet policy...\n'
  vwrite_staging "/wallets/${wallet}/policy.json" "$proposed_policy"
  policy_update_status="$(wait_for_policy_status "awaiting_custody")"
  policy_update_action_id="$(printf '%s' "$policy_update_status" | jq -er '.action_id')"
  open_approval "/wallets/${wallet}/policy-updates/latest/approval_challenge.json"
  wait_for_policy_status "ready_to_commit" >/dev/null
  vwrite "/wallets/${wallet}/policy.json" "$proposed_policy"
  wait_for_policy_status "confirmed" >/dev/null
  installed_policy="$(vcat "/wallets/${wallet}/policy.json")"
  printf '%s' "$installed_policy" | jq -e \
    --arg package_hash "$FIXTURE_PACKAGE_HASH" \
    '.allowed_petal_packages | index($package_hash) != null' \
    >/dev/null || die "committed mounted wallet policy omitted the fixture package"
  printf 'Wallet policy: fixture package committed through policy_update custody\n'
else
  printf 'Wallet policy: fixture package already allowed\n'
fi

# Prove the generic Petal authority path before checking venue compatibility:
# ordinary mounted write -> owner-mounted key ceremony -> exact retry ->
# payload-signing ceremony -> exact retry. No CLI or RPC shortcut is used.
fixture_path="/petals/triad-authority-fixture/session.json"
fixture_request_id="manual-fixture-$(date +%s)-$$"
fixture_nonce="$(printf '%s' "$fixture_request_id" | shasum -a 256 | awk '{print substr($1, 1, 32)}')"
fixture_request="$(jq -nc \
  --arg request_id "$fixture_request_id" --arg wallet_id "$wallet" \
  --arg nonce_hex "$fixture_nonce" \
  '{request_id:$request_id,wallet_id:$wallet_id,purpose:"fixture.payload",
    maximum_lifetime_ms:900000,
    preimage_hex:"66697874757265207061796c6f6164",
    nonce_hex:$nonce_hex,approval_hint:null}')"
printf '\nRequesting a Signer-owned fixture Petal sub-key through the mount...\n'
vwrite_staging "$fixture_path" "$fixture_request"
fixture_result="$(wait_for_fixture_stage "key:pending")"
printf '%s' "$fixture_result" | jq -e '
  .stage == "key" and .outcome.state == "pending" and
  (.outcome.operation_id | type == "string") and
  (.outcome.scope_digest | type == "string")
' >/dev/null || die "fixture Petal did not return a pending scoped-key operation"

fixture_key_record=""
while IFS= read -r record_name; do
  [ -n "$record_name" ] || continue
  candidate="/petal-key-requests/${record_name}"
  candidate_body="$(vcat "$candidate")"
  if printf '%s' "$candidate_body" | jq -e --arg request_id "$fixture_request_id" \
    '.request_id == $request_id and .status == "awaiting_user"' >/dev/null
  then
    fixture_key_record="$candidate"
    break
  fi
done < <(vls_names "/petal-key-requests")
[ -n "$fixture_key_record" ] || die "owner-mounted fixture key ceremony record was not found"
open_approval "$fixture_key_record"

vwrite_staging "$fixture_path" "$fixture_request"
fixture_result="$(wait_for_fixture_stage "signing_failed")"
printf '%s' "$fixture_result" | jq -e '
  .stage == "signing_failed" and
  (.error | contains("APPROVAL_NOT_FOUND"))
' >/dev/null || die "fixture Petal did not fail closed before Sealed Approval preparation"

# The Petal cannot mint its own reusable authority and the host does not
# fabricate an approval from a missing hint. Read only public authority inputs
# through owner-mounted projections, prepare the canonical Petal-scoped Sealed
# Approval through its existing mounted adapter, complete the Broker ceremony,
# then pass the returned approval ID on the exact fixture retry.
fixture_key_record_body="$(vcat "$fixture_key_record")"
fixture_key_ref="$(printf '%s' "$fixture_key_record_body" | jq -ec '.public_key.key_ref')"
fixture_provenance_digest="$(printf '%s' "$fixture_key_record_body" | jq -er '.provenance_digest')"
fixture_agent_id="$(printf '%s' "$fixture_key_record_body" | jq -c '.scope.agent_id')"
wallet_authority="$(vcat "/wallets/${wallet}/addresses.json")"
policy_version="$(printf '%s' "$wallet_authority" | jq -er '.policy_version')"
policy_digest="$(printf '%s' "$wallet_authority" | jq -er '.policy_digest')"
wallet_revocation_epoch="$(printf '%s' "$wallet_authority" | jq -er '.wallet_revocation_epoch')"
for digest_value in "$fixture_provenance_digest" "$policy_digest"; do
  printf '%s' "$digest_value" | jq -R -e 'test("^[0-9a-f]{64}$")' >/dev/null ||
    die "mounted approval authority metadata contains a malformed digest"
done
approval_now_ms="$(( $(date +%s) * 1000 ))"
approval_expires_ms="$((approval_now_ms + 240000))"
approval_operation_id="$(printf '%s' "${fixture_request_id}:approval" | shasum -a 256 | awk '{print $1}')"
approval_nonce="$(printf '%s' "${fixture_request_id}:nonce" | shasum -a 256 | awk '{print substr($1, 1, 32)}')"
approval_plan="$(jq -ncS \
  --arg wallet_id "$wallet" --arg package_hash "$FIXTURE_PACKAGE_HASH" \
  --arg route "r000001" --arg operation_class "fixture.payload" \
  --arg payload_sha256 "$(printf 'fixture payload' | shasum -a 256 | awk '{print $1}')" \
  '{wallet_id:$wallet_id,package_hash:$package_hash,route:$route,
    operation_class:$operation_class,payload_sha256:$payload_sha256}')"
approval_plan_digest="$(printf '%s' "$approval_plan" | shasum -a 256 | awk '{print $1}')"
approval_request="$(jq -ncS \
  --arg operation_id "$approval_operation_id" --arg wallet_id "$wallet" \
  --arg package_hash "$FIXTURE_PACKAGE_HASH" --arg route "r000001" \
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
printf '\nPreparing the fixture Petal Sealed Approval through the mount...\n'
vwrite "/wallets/${wallet}/sealed-approvals/new.json" "$approval_request"
approval_projection="$(wait_for_approval_prepare)"
fixture_approval_id="$(printf '%s' "$approval_projection" | jq -er '.approval_id')"
open_approval "/wallets/${wallet}/sealed-approvals/new.json"
wait_for_approval_active "$fixture_approval_id"
fixture_request="$(printf '%s' "$fixture_request" | jq -cS --arg approval_id "$fixture_approval_id" \
  '.approval_hint = $approval_id')"

vwrite "$fixture_path" "$fixture_request"
fixture_result="$(wait_for_fixture_stage "complete")"
printf '%s' "$fixture_result" | jq -e '
  .stage == "complete" and
  (.public_key.key_ref_jcs | type == "array") and
  (.signature_hex | test("^[0-9a-f]+$"))
' >/dev/null || die "fixture Petal did not complete scoped payload signing"
printf 'Fixture Petal: Signer-owned sub-key derived and payload signed through mounted files\n'

if [ "$live" -eq 0 ] || [ "$execute_pm" -eq 1 ]; then
  route_contract="$(vcat "/petals/polymarket/meta/route-contract.json")"
  printf '%s' "$route_contract" | jq -e . >/dev/null ||
    die "Polymarket Petal route contract is unavailable"
  vls_names "/petals/polymarket/onboard" >/dev/null
  vls_names "/petals/polymarket/account" >/dev/null
  vls_names "/petals/polymarket/trade" >/dev/null
  printf 'Polymarket Petal: mounted and route contract loaded\n'
  pm_triad_compatible="$(printf '%s' "$route_contract" | jq -r '
    [.. | strings] | any(contains("bloom:sign/signing@0.4.0"))
  ')"
  if [ "$pm_triad_compatible" != "true" ]; then
    printf 'Polymarket Petal: read-only preflight only; local package lacks production triad payload signing\n'
  fi
  if [ -n "$pm_slug" ]; then
    case "$pm_slug" in *[!A-Za-z0-9._-]*|'') die "Polymarket slug contains unsafe characters" ;; esac
    printf 'Requested Polymarket slug: %s\n' "$pm_slug"
  fi
fi

if [ "$live" -eq 0 ]; then
  [ "$preflight_blockers" -eq 0 ] ||
    die "preflight found an external prerequisite blocker; no order was submitted"
  printf '\nPreflight passed. Fixture passkey ceremonies completed; no venue order was submitted.\n'
  printf 'Re-run with the exact live arguments shown by --help when ready.\n'
  exit 0
fi

[ "$preflight_blockers" -eq 0 ] ||
  die "live preflight found an external prerequisite blocker; no order was staged"
[ "$pm_triad_compatible" = "true" ] ||
  die "local Polymarket Petal is not production-triad signing compatible; no draft was staged"

if [ "$execute_pm" -eq 1 ]; then
  if [ "$pm_side" = "buy" ]; then
    pm_price_json="$(jq -nc --arg p "$pm_bound" '{max_price:$p}')"
  else
    pm_price_json="$(jq -nc --arg p "$pm_bound" '{min_price:$p}')"
  fi
  pm_request="$(jq -nc \
    --arg slug "$pm_slug" --arg outcome "$pm_outcome" --arg side "$pm_side" \
    --arg amount "$pm_amount" --arg order_type "$pm_order_type" \
    --argjson bound "$pm_price_json" \
    '{slug:$slug,outcome:$outcome,side:$side,amount:$amount,order_type:$order_type} + $bound')"
  printf '\nCreating the unsigned Polymarket draft for review...\n'
  drafts_before="$(vls_names "/petals/polymarket/trade/${wallet}/drafts" 2>/dev/null || true)"
  if ! vwrite "/petals/polymarket/trade/${wallet}/new" "$pm_request"; then
    die "mounted Polymarket draft creation failed; verify onboarding, funding, market, and policy"
  fi
  drafts_after="$(vls_names "/petals/polymarket/trade/${wallet}/drafts")"
  draft_id="$(comm -13 \
    <(printf '%s\n' "$drafts_before" | sed '/^$/d' | sort) \
    <(printf '%s\n' "$drafts_after" | sed '/^$/d' | sort) | tail -n 1)"
  [ -n "$draft_id" ] ||
    die "mounted Polymarket draft was not created; verify onboarding, funding, market, and policy"
  draft_path="/petals/polymarket/trade/${wallet}/drafts/${draft_id}"
  vwrite "${draft_path}/revalidate" '{"revalidate":true}'
  printf '\nPolymarket draft plan:\n'
  vcat "${draft_path}/plan.md"
  printf '\nPolymarket policy check:\n'
  vcat "${draft_path}/policy_check.json" | jq .
  printf '\nFinal Polymarket quote:\n'
  vcat "${draft_path}/quote.json" | jq .
  printf '\nFinal Polymarket review intent:\n'
  vcat "${draft_path}/review_intent.json" | jq .
fi

mainnet_ack="EXECUTE POLYMARKET MAINNET ORDER"
printf '\nType exactly “%s” to authorize the selected submission(s): ' "$mainnet_ack"
IFS= read -r acknowledgement
[ "$acknowledgement" = "$mainnet_ack" ] || die "mainnet acknowledgement did not match"

if [ "$execute_pm" -eq 1 ]; then
  printf '\nType exactly “POST POLYMARKET DRAFT %s” to request its passkey approval: ' "$draft_id"
  IFS= read -r pm_ack
  [ "$pm_ack" = "POST POLYMARKET DRAFT ${draft_id}" ] ||
    die "Polymarket draft acknowledgement did not match"
  post_request='{"post":true,"acknowledge_warnings":true}'
  vwrite_staging "${draft_path}/post" "$post_request"
  open_approval "${draft_path}/approval.json"
  vwrite "${draft_path}/post" "$post_request"
  pm_receipt="$(vcat "/petals/polymarket/trade/${wallet}/receipts/${draft_id}/receipt.json")"
  printf '\nPolymarket receipt:\n'
  printf '%s\n' "$pm_receipt" | jq .
  printf '%s' "$pm_receipt" | jq -e '
    (.clob_status | ascii_downcase) as $status |
    ($status != "rejected") and ($status != "failed")
  ' >/dev/null || die "Polymarket receipt reports rejection/failure"
fi

printf '\nPASS: the selected Polymarket mainnet submission returned a non-error receipt.\n'
printf 'Inspect fills/positions separately; venue acceptance does not guarantee a fill.\n'
