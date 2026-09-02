#!/usr/bin/env bash
# Run the Solana Harbor task against a disposable local validator while reusing
# an existing Broker/Signer custody wallet. The wallet seed never leaves Signer:
# this script only drives the same owner ceremonies as the mounted workflow.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
agent="${1:-glm}"
wallet_id="${BLOOM_EVAL_SOLANA_WALLET_ID:-debug-bip39}"
developer_root="${BLOOM_EVAL_DEVELOPER_ROOT:-${HOME}/bloom-triad/developer}"
triad_root="${BLOOM_EVAL_TRIAD_ROOT:-${HOME}/bloom-triad}"
seed_file="${BLOOM_EVAL_AUTHENTICATOR_SEED_FILE:-${triad_root}/owner-auth.seed}"
machine_bin="${BLOOM_EVAL_SOLANA_MACHINE_BINARY:-${repo_root}/target/debug/bloom}"
broker_bin="${BLOOM_INTEGRATION_BROKER_BIN:-${repo_root}/../broker-solana-review/target/debug/bloom-broker}"
signer_bin="${BLOOM_INTEGRATION_SIGNER_BIN:-${repo_root}/../signer-phase2/target/debug/bloom-signer}"
driver_bin="${BLOOM_EVAL_DEBUG_DRIVER_BIN:-${repo_root}/../broker-solana-review/target/debug/bloom-broker-debug-driver}"
launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
base_config="${BLOOM_EVAL_MACHINE_CONFIG:-${triad_root}/machine-config.toml}"
counter_file="${BLOOM_EVAL_SIGN_COUNT_FILE:-${triad_root}/debug-bip39.sign-count}"
rpc_port="${BLOOM_EVAL_SOLANA_LOCAL_RPC_PORT:-18899}"
faucet_port="${BLOOM_EVAL_SOLANA_LOCAL_FAUCET_PORT:-19900}"
rpc_url="http://127.0.0.1:${rpc_port}"

die() { printf 'Bloom Solana local eval: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor-solana-local.sh [glm|codex|claude]' \
    '' \
    'Defaults to GLM-5.2 and wallet debug-bip39. The command starts and cleans' \
    'up a disposable validator, Machine, NFS mount, policy allowance, and sweep key.'
}

case "$agent" in
  glm|codex|claude) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
case "$wallet_id" in
  ''|*[!a-z0-9-]*) die "wallet id must contain only lowercase letters, digits, and hyphens" ;;
esac
case "$rpc_port:$faucet_port" in
  *[!0-9:]*) die "local RPC and faucet ports must be integers" ;;
esac
if [ "$agent" = glm ]; then
  [ -n "${GLM_API_KEY:-${ZAI_API_KEY:-${ANTHROPIC_AUTH_TOKEN:-}}}" ] ||
    die "GLM auth is missing; export GLM_API_KEY, ZAI_API_KEY, or ANTHROPIC_AUTH_TOKEN"
fi

for command in cargo docker flock jq mount.nfs4 mountpoint python3 solana \
  solana-keygen solana-test-validator ss sudo uv; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
for path in "$launcher" "$base_config" "$seed_file" "$broker_bin" \
  "$signer_bin" "$driver_bin"; do
  [ -e "$path" ] || die "required path is missing: $path"
done
[ -x "$launcher" ] || die "triad launcher is not executable: $launcher"
for binary in "$broker_bin" "$signer_bin" "$driver_bin"; do
  [ -x "$binary" ] || die "required binary is not executable: $binary"
done
[ ! -L "$seed_file" ] && [ -f "$seed_file" ] && [ "$(stat -c %a "$seed_file")" = 600 ] ||
  die "authenticator seed must be a mode-0600 regular non-symlink file: $seed_file"
[ -d "$developer_root" ] || die "developer root is missing: $developer_root"

# One Broker ceremony listener exists per developer identity. Starting a second
# triad would race its audit/custody stores even if Machine used another home.
if ss -ltn | awk '{print $4}' | grep -Eq '(^|:)18734$'; then
  die "another triad owns ceremony port 18734; obtain lifecycle handoff and retry"
fi
if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)(${rpc_port}|${faucet_port})$"; then
  die "local validator port ${rpc_port} or ${faucet_port} is already in use"
fi

mkdir -p "${triad_root}/evals"
chmod 0700 "${triad_root}/evals"
lifecycle_lock="${triad_root}/triad-lifecycle.lock"
exec 9>"$lifecycle_lock"
chmod 0600 "$lifecycle_lock"
flock -n 9 || die "another local eval owns the triad lifecycle lock"
run_root="$(mktemp -d "${triad_root}/evals/solana-local.XXXXXX")"
machine_home="$(mktemp -d "${developer_root}/eval-machine.XXXXXX")"
mount_dir="${run_root}/bloom"
log_dir="${run_root}/logs"
ready_file="${run_root}/ready"
machine_socket="${run_root}/machine.sock"
ledger="${run_root}/ledger"
sweep_key="${run_root}/sweep.json"
launcher_log="${run_root}/launcher.log"
validator_log="${run_root}/validator.log"
mkdir -p "$mount_dir" "$log_dir"
chmod 0700 "$run_root" "$machine_home" "$mount_dir" "$log_dir"

validator_pid=""
launcher_pid=""
sudo_keepalive_pid=""
policy_changed=0
cleanup_running=0

write_counter() {
  local value="$1" temporary="${counter_file}.tmp.$$"
  printf '%s\n' "$value" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$counter_file"
}

next_counter() {
  local now recorded=0
  now="$(date +%s)"
  if [ -f "$counter_file" ]; then
    read -r recorded < "$counter_file" || recorded=0
    case "$recorded" in ''|*[!0-9]*) die "invalid sign-count file: $counter_file" ;; esac
  fi
  if [ "$recorded" -gt "$now" ]; then printf '%s\n' "$recorded"; else printf '%s\n' "$now"; fi
}

complete_policy_update() {
  local policy_file="$1" counter launch ceremony_url operation_id
  counter="$(next_counter)"
  launch="$("$machine_bin" wallet update-policy "$wallet_id" --file "$policy_file")" || return 1
  ceremony_url="$(printf '%s\n' "$launch" | sed -n 's/^ceremony_url: //p')"
  operation_id="$(printf '%s\n' "$launch" | sed -n 's/^operation_id: //p')"
  [ -n "$ceremony_url" ] && [ -n "$operation_id" ] || return 1
  # Reserve before the call: Broker may consume the counter even if the local
  # driver is interrupted before returning a result.
  write_counter "$((counter + 1))"
  "$driver_bin" complete "$ceremony_url" \
    --authenticator-seed-file "$seed_file" --sign-count "$counter" >/dev/null
  "$machine_bin" wallet commit-policy "$operation_id" >/dev/null
}

cleanup() {
  local status="$?" restore_status=0
  [ "$cleanup_running" -eq 0 ] || exit "$status"
  cleanup_running=1
  trap - EXIT INT TERM HUP
  if [ "$policy_changed" -eq 1 ] && [ -S "$machine_socket" ]; then
    printf 'Bloom Solana local eval: restoring the original wallet policy...\n' >&2
    complete_policy_update "${run_root}/policy.original.json" || restore_status=1
  fi
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  if mountpoint -q "$mount_dir" 2>/dev/null; then
    sudo -n /usr/bin/umount -l -f "$mount_dir" >/dev/null 2>&1 || restore_status=1
  fi
  if [ -n "$validator_pid" ] && kill -0 "$validator_pid" 2>/dev/null; then
    kill "$validator_pid" 2>/dev/null || true
    wait "$validator_pid" 2>/dev/null || true
  fi
  if [ -n "$sudo_keepalive_pid" ] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
    kill "$sudo_keepalive_pid" 2>/dev/null || true
    wait "$sudo_keepalive_pid" 2>/dev/null || true
  fi
  if [ "$restore_status" -ne 0 ]; then
    printf 'Bloom Solana local eval: cleanup needs attention; artifacts retained at %s\n' "$run_root" >&2
    exit 1
  fi
  if [ "$status" -eq 0 ]; then
    unlink "$sweep_key" 2>/dev/null || true
    printf 'Bloom Solana local eval: passed; non-secret logs retained at %s\n' "$run_root" >&2
  else
    printf 'Bloom Solana local eval: failed; diagnostics retained at %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

# Bloom deliberately invokes mount helpers through sudo -n. Authenticate once
# in the operator's terminal, then keep that timestamp alive through cleanup;
# this avoids installing a permanent wildcard sudoers rule.
printf 'Bloom Solana local eval: sudo is needed once for the localhost NFS mount.\n' >&2
sudo -v
(
  while :; do
    sudo -n -v || exit
    sleep 45
  done
) &
sudo_keepalive_pid=$!

printf 'Bloom Solana local eval: building the PR Machine...\n' >&2
(cd "$repo_root" && cargo build -p bloom --no-default-features --features mount,triad-dev-harness)
[ -x "$machine_bin" ] || die "Machine build did not produce $machine_bin"

printf 'Bloom Solana local eval: starting local validator...\n' >&2
solana-test-validator --ledger "$ledger" --reset --quiet \
  --rpc-port "$rpc_port" --faucet-port "$faucet_port" >"$validator_log" 2>&1 &
validator_pid=$!
genesis=""
for _ in $(seq 1 300); do
  kill -0 "$validator_pid" 2>/dev/null || die "validator exited; see $validator_log"
  genesis="$(solana genesis-hash --url "$rpc_url" 2>/dev/null || true)"
  [ -n "$genesis" ] && break
  sleep 0.1
done
[ -n "$genesis" ] || die "validator did not become ready; see $validator_log"

nfs_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
awk -v port="$nfs_port" '
  /^nfs_listen_addr = / { print "nfs_listen_addr = \"127.0.0.1:" port "\""; next }
  { print }
' "$base_config" > "${machine_home}/config.toml"
{
  printf '\n[solana_chains.solana-local]\n'
  printf 'name = "solana-local"\n'
  printf 'endpoints = [{ url = "%s", weight = 100 }]\n' "$rpc_url"
  printf 'expected_genesis_base58 = "%s"\n' "$genesis"
  printf 'allow_broadcast = true\n'
} >> "${machine_home}/config.toml"
chmod 0600 "${machine_home}/config.toml"

solana-keygen new --no-bip39-passphrase --silent --outfile "$sweep_key" >/dev/null
chmod 0600 "$sweep_key"
destination="$(solana address --keypair "$sweep_key")"

printf 'Bloom Solana local eval: starting isolated Machine mount over shared custody...\n' >&2
BLOOM_INTEGRATION_MACHINE_BIN="$machine_bin" \
BLOOM_INTEGRATION_BROKER_BIN="$broker_bin" \
BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin" \
BLOOM_TRIAD_DEV_BUILD_PETALS=0 \
BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=0 \
  "$launcher" --developer-root "$developer_root" --machine-home "$machine_home" \
    --machine-socket "$machine_socket" --mount "$mount_dir" \
    --log-dir "$log_dir" --ready-file "$ready_file" >"$launcher_log" 2>&1 &
launcher_pid=$!
for _ in $(seq 1 1200); do
  kill -0 "$launcher_pid" 2>/dev/null || die "triad exited; see $launcher_log"
  [ -f "$ready_file" ] && break
  sleep 0.25
done
[ -f "$ready_file" ] || die "triad did not become ready; see $launcher_log"
# shellcheck disable=SC1090
source "${log_dir}/triad.env"

accounts=""
for _ in $(seq 1 120); do
  accounts="$("$machine_bin" wallet accounts "$wallet_id" 2>/dev/null || true)"
  printf '%s' "$accounts" | jq -e '.accounts | type == "array"' >/dev/null 2>&1 && break
  sleep 0.5
done
source_address="$(printf '%s' "$accounts" | jq -er '
  [.accounts[] | select(.derivation_profile == "bip44-solana-slip10-ed25519-v1" and .lifecycle == "ACTIVE")
   | .chain_projections[]? | .address][0]
')" || die "wallet $wallet_id has no active Solana child"

"$machine_bin" vfs cat "/wallets/${wallet_id}/policy.json" > "${run_root}/policy.original.json"
jq -cS --arg chain solana-local --arg destination "$destination" '
  .allowed_destinations = ((.allowed_destinations // []) +
    [{chain:$chain, destination:$destination}] | unique | sort)
' "${run_root}/policy.original.json" > "${run_root}/policy.eval.json"
printf 'Bloom Solana local eval: approving the fresh local-only destination...\n' >&2
complete_policy_update "${run_root}/policy.eval.json" || die "policy update ceremony failed"
policy_changed=1

solana airdrop 0.02 "$source_address" --url "$rpc_url" --commitment finalized >/dev/null

export BLOOM_EVAL_SOLANA_LANE=local
export BLOOM_EVAL_SOLANA_WALLET_ID="$wallet_id"
export BLOOM_EVAL_SOLANA_CHAIN=solana-local
export BLOOM_EVAL_SOLANA_NETWORK=localnet
export BLOOM_EVAL_SOLANA_RPC_URL="$rpc_url"
export BLOOM_EVAL_BLOOM_MOUNT="$mount_dir"
export BLOOM_EVAL_SOLANA_HOME_ROOT="$machine_home"
export BLOOM_EVAL_SOLANA_MACHINE_BINARY="$machine_bin"
export BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE="$sweep_key"
export BLOOM_EVAL_SOLANA_DESTINATION="$destination"
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$seed_file"
export BLOOM_EVAL_DEBUG_DRIVER_BIN="$driver_bin"
export BLOOM_EVAL_SIGN_COUNT_FILE="$counter_file"
export BLOOM_EVAL_JOBS_DIR="${run_root}/jobs"
export UV_CACHE_DIR="${BLOOM_EVAL_UV_CACHE_DIR:-${run_root}/uv-cache}"

printf 'Bloom Solana local eval: running Harbor with %s (%s)...\n' \
  "$agent" "${BLOOM_EVAL_MODEL:-provider default}" >&2
"${repo_root}/scripts/evals/run-harbor.sh" solana-transfer "$agent"
