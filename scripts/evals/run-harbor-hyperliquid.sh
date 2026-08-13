#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
task_dir="${repo_root}/evals/harbor/tasks/hyperliquid-order-cancel"
agent="${1:-}"
harbor_version="${HARBOR_VERSION:-0.21.0}"
wallet="${BLOOM_EVAL_WALLET:-}"
bloom_mount="${BLOOM_EVAL_BLOOM_MOUNT:-/bloom}"
driver="${BLOOM_EVAL_DEBUG_DRIVER_BIN:-${repo_root}/../bloom-broker/target/debug/bloom-broker-debug-driver}"
seed_file="${BLOOM_EVAL_AUTHENTICATOR_SEED_FILE:-}"
mainnet_ack="${BLOOM_EVAL_MAINNET_ACK:-}"
jobs_dir="${BLOOM_EVAL_JOBS_DIR:-${repo_root}/evals/harbor/jobs}"
lock_file="${BLOOM_EVAL_LOCK_FILE:-/tmp/bloom-harbor-mainnet.lock}"

usage() {
  cat <<'EOF'
Usage: scripts/evals/run-harbor-hyperliquid.sh claude|codex

Required environment:
  BLOOM_EVAL_WALLET                   dedicated 0x mainnet wallet
  BLOOM_EVAL_AUTHENTICATOR_SEED_FILE  0600 file for the wallet's debug credential
  BLOOM_EVAL_MAINNET_ACK               exact text: PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD

Optional environment:
  BLOOM_EVAL_DEBUG_DRIVER_BIN         built bloom-broker-debug-driver
  BLOOM_EVAL_BLOOM_MOUNT              host Bloom mount (default: /bloom)
  BLOOM_EVAL_JOBS_DIR                 Harbor output directory
  HARBOR_VERSION                      Harbor package version (default: 0.21.0)

Claude requires ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN.
Codex requires OPENAI_API_KEY or a valid ~/.codex/auth.json.
EOF
}

die() { printf 'Bloom Harbor eval: %s\n' "$*" >&2; exit 1; }

case "$agent" in claude|codex) ;; *) usage >&2; exit 2 ;; esac
[[ "$wallet" =~ ^0x[0-9a-f]{40}$ ]] || die "BLOOM_EVAL_WALLET must be a lowercase 0x address"
[ "$mainnet_ack" = PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD ] ||
  die "set BLOOM_EVAL_MAINNET_ACK=PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD to authorize this mainnet trial"
[ -n "$seed_file" ] || die "BLOOM_EVAL_AUTHENTICATOR_SEED_FILE is required"
[ -f "$seed_file" ] || die "authenticator seed file does not exist: $seed_file"
[ "$(stat -c '%a' "$seed_file")" = 600 ] || die "authenticator seed file must have mode 0600"
[ -x "$driver" ] || die "debug driver is missing or not executable: $driver"
driver_usage="$({ "$driver" 2>&1 || true; })"
grep -F -- '--authenticator-seed-file' <<<"$driver_usage" >/dev/null ||
  die "debug driver lacks --authenticator-seed-file support; build bloom-broker PR #1 or newer"
mountpoint -q "$bloom_mount" || die "Bloom is not mounted at $bloom_mount"
[ -e "$bloom_mount/petals/hyperliquid/mainnet/mids.json" ] || die "Hyperliquid mainnet Petal is not installed"
[ -e "$bloom_mount/petals/hyperliquid/mainnet/perp_meta.json" ] || die "Hyperliquid perpetual metadata route is missing"
[ -e "$bloom_mount/petals/hyperliquid/README.md" ] || die "Hyperliquid Petal README is missing"
command -v docker >/dev/null || die "docker is required"
command -v uvx >/dev/null || die "uvx is required"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"

mkdir -p "$jobs_dir"
exec 9>"$lock_file"
flock -n 9 || die "another Bloom mainnet eval holds $lock_file"

# One dedicated wallet and one trial at a time. Refuse to start over any order
# rather than guessing whether it belongs to a previous failed trial.
open_orders="$(timeout 20 cat "$bloom_mount/petals/hyperliquid/mainnet/users/$wallet/open_orders.json")" ||
  die "could not read dedicated-wallet open orders through Bloom"
printf '%s' "$open_orders" | jq -e 'type == "array"' >/dev/null || die "open-orders projection is not a JSON array"
if printf '%s' "$open_orders" | jq -e 'length != 0' >/dev/null; then
  die "dedicated wallet already has an open order; use an empty eval wallet"
fi

clearinghouse="$(timeout 20 cat "$bloom_mount/petals/hyperliquid/mainnet/users/$wallet/clearinghouse.json")" ||
  die "could not read dedicated-wallet clearinghouse state through Bloom"
printf '%s' "$clearinghouse" | jq -e '.assetPositions | type == "array"' >/dev/null ||
  die "clearinghouse projection has no assetPositions array"
if printf '%s' "$clearinghouse" | jq -e \
  'any(.assetPositions[]?; ((((.position // .).szi // "0") | tonumber?) // 0) != 0)' >/dev/null; then
  die "dedicated wallet has an open position; use an empty eval wallet"
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
random_hex="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
session_id="bloom-eval-${agent}-${stamp}-${random_hex}"
cloid="0x$(printf '%s' "$session_id" | sha256sum | cut -c1-32)"
job_name="bloom-hyperliquid-${agent}-${stamp}"
base="$bloom_mount/petals/hyperliquid/mainnet/agent_sessions/$wallet/$session_id"

create_session() {
  local body output ceremony_url
  body="$(jq -nc \
    --arg id "$session_id" \
    --arg agent_name "be-${agent}-${random_hex}" \
    '{id:$id,agent_name:$agent_name,duration_ms:1800000,max_notional_usd:"11",max_leverage:1,assets:["0"]}')"

  # Session creation is owner-signed. Keep the passkey credential on the host:
  # the evaluated container never receives the driver or seed. The second write
  # is byte-for-byte identical, as required by the Petal's pending-request digest.
  set +e
  output="$(timeout 45 bash -c 'printf %s "$1" > "$2"' _ "$body" \
    "$bloom_mount/petals/hyperliquid/mainnet/agent_sessions/$wallet/new.json" 2>&1)"
  write_status=$?
  set -e
  if [ "$write_status" -ne 0 ]; then
    ceremony_url="$(printf '%s\n' "$output" | grep -Eo 'http://localhost:18734/ceremony/[A-Za-z0-9_-]{43}' | head -n 1)"
    [ -n "$ceremony_url" ] || die "session creation failed without a canonical ceremony URL: $output"
    [ -s "$seed_file" ] || die "authenticator seed file is empty"
    "$driver" complete "$ceremony_url" --authenticator-seed-file "$seed_file" >/dev/null ||
      die "debug-driver ceremony completion failed"
    timeout 45 bash -c 'printf %s "$1" > "$2"' _ "$body" \
      "$bloom_mount/petals/hyperliquid/mainnet/agent_sessions/$wallet/new.json" ||
      die "session creation retry failed"
  fi

  timeout 20 jq -e \
    --arg wallet "$wallet" --arg id "$session_id" '
      .schema == "bloom.hyperliquid_agent_session.v1" and
      .network == "mainnet" and .wallet == $wallet and .id == $id and
      .max_notional_usd == "11" and .max_leverage == 1 and
      .assets == ["0"] and .stopped == false
    ' "$base/status.json" >/dev/null || die "created session does not match the bounded contract"
}

cleanup() {
  local status=$? cleanup_failed=0 open_orders_after session_status
  trap - EXIT INT TERM
  if [ -e "$base/cancel_all" ] && ! { [ -s "$base/status.json" ] && jq -e '.stopped == true' "$base/status.json" >/dev/null 2>&1; }; then
    timeout 30 bash -c 'printf %s host-cleanup > "$1"' _ "$base/cancel_all" >/dev/null 2>&1 ||
      cleanup_failed=1
  fi

  open_orders_after="$(timeout 20 cat "$bloom_mount/petals/hyperliquid/mainnet/users/$wallet/open_orders.json" 2>/dev/null)" ||
    cleanup_failed=1
  if [ -n "${open_orders_after:-}" ]; then
    printf '%s' "$open_orders_after" | jq -e 'type == "array"' >/dev/null 2>&1 || cleanup_failed=1
    if printf '%s' "$open_orders_after" | jq -e 'length != 0' >/dev/null 2>&1; then
      cleanup_failed=1
    fi
  else
    cleanup_failed=1
  fi

  if [ "$cleanup_failed" -eq 0 ] && [ -e "$base/stop" ] && ! { [ -s "$base/status.json" ] && jq -e '.stopped == true' "$base/status.json" >/dev/null 2>&1; }; then
    timeout 10 bash -c 'printf %s host-cleanup > "$1"' _ "$base/stop" >/dev/null 2>&1 ||
      cleanup_failed=1
  fi

  session_status="$(timeout 20 cat "$base/status.json" 2>/dev/null)" || cleanup_failed=1
  if [ -n "${session_status:-}" ]; then
    printf '%s' "$session_status" | jq -e '.stopped == true' >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    printf 'Bloom Harbor eval: ERROR: residual-state cleanup failed for %s; inspect the wallet before another run\n' "$session_id" >&2
    status=1
  fi
  exit "$status"
}

terminate() {
  trap - INT TERM
  exit 130
}

trap terminate INT TERM
trap cleanup EXIT

create_session

# Expose the complete mounted Bloom machine for normal discovery, but enforce
# task write scope in Docker: the full tree is read-only and only the four
# action files required by this task are over-mounted read-write. In particular,
# the evaluated agent cannot write the session's stop route. Owner credentials
# and the ceremony driver are never mounted into the trial.
mounts="$(jq -nc --arg bloom "$bloom_mount" --arg wallet "$wallet" --arg session "$session_id" '
  [{type:"bind",source:$bloom,target:"/bloom",read_only:true}] +
  (["order.json", "cancel.json", "update_leverage.json", "cancel_all"] | map({
      type:"bind",
      source:($bloom + "/petals/hyperliquid/mainnet/agent_sessions/" + $wallet + "/" + $session + "/" + .),
      target:("/bloom/petals/hyperliquid/mainnet/agent_sessions/" + $wallet + "/" + $session + "/" + .)
    }))')"

common=(
  --path "$task_dir"
  --env docker
  --n-concurrent 1
  --n-attempts 1
  --max-retries 0
  --job-name "$job_name"
  --jobs-dir "$jobs_dir"
  --mounts "$mounts"
  --agent-env "BLOOM_EVAL_WALLET=$wallet"
  --agent-env "BLOOM_EVAL_SESSION_ID=$session_id"
  --agent-env "BLOOM_EVAL_CLOID=$cloid"
  --verifier-env "BLOOM_EVAL_WALLET=$wallet"
  --verifier-env "BLOOM_EVAL_SESSION_ID=$session_id"
  --verifier-env "BLOOM_EVAL_CLOID=$cloid"
  --yes
)

case "$agent" in
  claude)
    if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
      die "Claude auth is missing; set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN"
    fi
    auth_args=()
    if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
      auth_args+=(--agent-env CLAUDE_FORCE_OAUTH=1)
    fi
    uvx --from "harbor==${harbor_version}" harbor run "${common[@]}" \
      --agent claude-code --model sonnet-5 "${auth_args[@]}"
    ;;
  codex)
    auth_args=()
    if [ -z "${OPENAI_API_KEY:-}" ]; then
      [ -f "$HOME/.codex/auth.json" ] || die "Codex auth is missing"
      auth_args+=(--agent-env CODEX_FORCE_AUTH_JSON=1)
    fi
    uvx --from "harbor==${harbor_version}" harbor run "${common[@]}" \
      --agent codex --model gpt-5.6-terra "${auth_args[@]}"
    ;;
esac
