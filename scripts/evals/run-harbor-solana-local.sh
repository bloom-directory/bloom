#!/usr/bin/env bash
# Run the Solana Harbor task in a dedicated local-only triad. Its identities,
# custody, wallet, audit journals, ceremony port, validator, Machine, and mount
# are independent from the developer's normal triad, so both may run at once.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
agent="${1:-glm}"
wallet_id="${BLOOM_EVAL_SOLANA_WALLET_ID:-solana-eval}"
triad_root="${BLOOM_EVAL_TRIAD_ROOT:-${HOME}/bloom-eval-triad}"
run_base="${BLOOM_EVAL_RUN_ROOT:-${TMPDIR:-/tmp}/bloom-solana-evals-${UID}}"
developer_root="${BLOOM_EVAL_DEVELOPER_ROOT:-${triad_root}/developer}"
machine_home="${BLOOM_EVAL_SOLANA_HOME_ROOT:-${developer_root}/machine-home}"
seed_file="${BLOOM_EVAL_AUTHENTICATOR_SEED_FILE:-${triad_root}/owner-auth.seed}"
broker_repo_default="${repo_root}/../bloom-broker"
signer_repo_default="${repo_root}/../bloom-signer"
[ ! -d "${repo_root}/../broker-eval-isolation" ] || broker_repo_default="${repo_root}/../broker-eval-isolation"
[ ! -d "${repo_root}/../signer-eval-isolation" ] || signer_repo_default="${repo_root}/../signer-eval-isolation"
broker_repo="${BLOOM_EVAL_BROKER_REPO:-${broker_repo_default}}"
signer_repo="${BLOOM_EVAL_SIGNER_REPO:-${signer_repo_default}}"
# Reviewed heads of bloom-broker#32 and bloom-signer#25. These PR branches were
# rebased after the eval launcher was first written, so pin the current commits
# rather than now-unreachable pre-rebase hashes.
broker_isolation_commit="25ccf8b20079e120b189714c84283eba17c937a4"
signer_isolation_commit="745befe63ecd7a0b0a104c4ffd1a092d6d347cad"
build_root="${BLOOM_EVAL_BUILD_ROOT:-${triad_root}/target}"
machine_bin="${BLOOM_EVAL_SOLANA_MACHINE_BINARY:-${build_root}/machine/debug/bloom}"
broker_bin="${BLOOM_INTEGRATION_BROKER_BIN:-${build_root}/broker/debug/bloom-broker}"
signer_bin="${BLOOM_INTEGRATION_SIGNER_BIN:-${build_root}/signer/debug/bloom-signer}"
driver_bin="${BLOOM_EVAL_DEBUG_DRIVER_BIN:-${build_root}/broker/debug/bloom-broker-debug-driver}"
launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
counter_file="${BLOOM_EVAL_SIGN_COUNT_FILE:-${triad_root}/owner-auth.sign-count}"
ceremony_port="${BLOOM_TRIAD_DEV_CEREMONY_PORT:-18735}"
rpc_port="${BLOOM_EVAL_SOLANA_LOCAL_RPC_PORT:-18899}"
faucet_port="${BLOOM_EVAL_SOLANA_LOCAL_FAUCET_PORT:-19900}"
rpc_url="http://127.0.0.1:${rpc_port}"

die() { printf 'Bloom Solana local eval: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor-solana-local.sh [smoke|glm|deepseek|codex|claude]' \
    '' \
    'Defaults to GLM-5.2 and a dedicated solana-eval wallet. The first run' \
    'creates an isolated local-only triad; later runs safely reuse it.'
}

case "$agent" in
  smoke|glm|deepseek|codex|claude) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
case "$wallet_id" in
  ''|*[!a-z0-9-]*) die "wallet id must contain only lowercase letters, digits, and hyphens" ;;
esac
case "$ceremony_port:$rpc_port:$faucet_port" in
  *[!0-9:]*) die "local RPC and faucet ports must be integers" ;;
esac
for port in "$ceremony_port" "$rpc_port" "$faucet_port"; do
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "local ports must be from 1 to 65535"
done
if [ "$agent" = glm ]; then
  [ -n "${GLM_API_KEY:-${ZAI_API_KEY:-${ANTHROPIC_AUTH_TOKEN:-}}}" ] ||
    die "GLM auth is missing; export GLM_API_KEY, ZAI_API_KEY, or ANTHROPIC_AUTH_TOKEN"
fi
if [ "$agent" = deepseek ]; then
  [ -n "${DEEPSEEK_API_KEY:-}" ] ||
    die "DeepSeek auth is missing; export DEEPSEEK_API_KEY"
fi

for command in cargo docker flock git jq mount.nfs4 mountpoint openssl python3 solana \
  solana-keygen solana-test-validator ss sudo uv; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
for path in "$launcher" "$broker_repo" "$signer_repo"; do
  [ -e "$path" ] || die "required path is missing: $path"
done
[ -x "$launcher" ] || die "triad launcher is not executable: $launcher"
git -C "$broker_repo" merge-base --is-ancestor "$broker_isolation_commit" HEAD 2>/dev/null ||
  die "Broker checkout is not based on reviewed bloom-broker#32 head $broker_isolation_commit: $broker_repo"
git -C "$signer_repo" merge-base --is-ancestor "$signer_isolation_commit" HEAD 2>/dev/null ||
  die "Signer checkout is not based on reviewed bloom-signer#25 head $signer_isolation_commit: $signer_repo"

# Port 18734 belongs to the normal triad and may remain live. This isolated
# developer-harness build uses a different exact origin on loopback.
if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${ceremony_port}$"; then
  die "another eval triad owns ceremony port ${ceremony_port}"
fi
if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)(${rpc_port}|${faucet_port})$"; then
  die "local validator port ${rpc_port} or ${faucet_port} is already in use"
fi

umask 077
mkdir -p "$run_base" "$developer_root" "$machine_home" "$build_root"
chmod 0700 "$triad_root" "$run_base" "$developer_root" "$machine_home" "$build_root"
if [ ! -e "$seed_file" ]; then
  openssl rand -hex 32 > "$seed_file"
  chmod 0600 "$seed_file"
fi
[ ! -L "$seed_file" ] && [ -f "$seed_file" ] && [ "$(stat -c %a "$seed_file")" = 600 ] ||
  die "authenticator seed must be a mode-0600 regular non-symlink file: $seed_file"
lifecycle_lock="${triad_root}/triad-lifecycle.lock"
exec 9>"$lifecycle_lock"
chmod 0600 "$lifecycle_lock"
flock -n 9 || die "another local eval owns the triad lifecycle lock"
run_root="$(mktemp -d "${run_base}/solana-local.XXXXXX")"
mount_dir="${run_root}/bloom"
log_dir="${run_root}/logs"
ready_file="${run_root}/ready"
machine_socket="${run_root}/machine.sock"
ledger="${triad_root}/validator-ledger"
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
  local policy_file="$1" launch ceremony_url operation_id
  launch="$("$machine_bin" wallet update-policy "$wallet_id" --file "$policy_file")" || return 1
  ceremony_url="$(printf '%s\n' "$launch" | sed -n 's/^ceremony_url: //p')"
  operation_id="$(printf '%s\n' "$launch" | sed -n 's/^operation_id: //p')"
  [ -n "$ceremony_url" ] && [ -n "$operation_id" ] || return 1
  complete_ceremony "$ceremony_url" >/dev/null
  "$machine_bin" wallet commit-policy "$operation_id" >/dev/null
}

complete_ceremony() {
  local ceremony_url="$1" counter
  shift
  counter="$(next_counter)"
  # Reserve before the call: Broker may consume the counter even if the local
  # driver is interrupted before returning a result.
  write_counter "$((counter + 1))"
  "$driver_bin" complete "$ceremony_url" \
    --authenticator-seed-file "$seed_file" --sign-count "$counter" "$@"
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
  unlink "${run_root}/mnemonic.txt" 2>/dev/null || true
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

printf 'Bloom Solana local eval: building isolated Machine, Broker, and Signer...\n' >&2
(cd "$repo_root" && CARGO_TARGET_DIR="${build_root}/machine" \
  cargo build -p bloom --no-default-features --features mount,triad-dev-harness)
(cd "$broker_repo" && CARGO_TARGET_DIR="${build_root}/broker" \
  cargo build -p bloom-broker --features triad-dev-harness && \
  CARGO_TARGET_DIR="${build_root}/broker" cargo build -p bloom-broker-debug-driver)
(cd "$signer_repo" && CARGO_TARGET_DIR="${build_root}/signer" \
  cargo build -p bloom-signer --features triad-dev-harness)
for binary in "$machine_bin" "$broker_bin" "$signer_bin" "$driver_bin"; do
  [ -x "$binary" ] || die "build did not produce $binary"
done

printf 'Bloom Solana local eval: starting local validator...\n' >&2
solana-test-validator --ledger "$ledger" --quiet \
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
machine_config="${machine_home}/config.toml"
machine_config_new="${machine_config}.new.$$"
{
  printf 'default_chain = "local-disabled"\n'
  printf 'nfs_listen_addr = "127.0.0.1:%s"\n' "$nfs_port"
  printf '\n[chains.local-disabled]\n'
  printf 'name = "local-disabled"\n'
  printf 'chain_id = 31337\n'
  printf 'rpc_urls = ["http://127.0.0.1:1"]\n'
  printf 'rpc_endpoints = []\n'
  printf 'allow_broadcast = false\n'
  printf 'display_name = "Disabled local EVM placeholder"\n'
  printf 'native_symbol = "ETH"\n'
  printf 'native_decimals = 18\n'
  printf 'legacy_tx = false\n'
  printf 'op_stack = false\n'
  printf '\n[solana_chains.solana-local]\n'
  printf 'name = "solana-local"\n'
  printf 'endpoints = [{ url = "%s", weight = 100 }]\n' "$rpc_url"
  printf 'expected_genesis_base58 = "%s"\n' "$genesis"
  printf 'allow_broadcast = true\n'
} > "$machine_config_new"
chmod 0600 "$machine_config_new"
mv -f "$machine_config_new" "$machine_config"

solana-keygen new --no-bip39-passphrase --silent --outfile "$sweep_key" >/dev/null
chmod 0600 "$sweep_key"
destination="$(solana address --keypair "$sweep_key")"

printf 'Bloom Solana local eval: starting the independent eval triad...\n' >&2
BLOOM_INTEGRATION_MACHINE_BIN="$machine_bin" \
BLOOM_INTEGRATION_BROKER_BIN="$broker_bin" \
BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin" \
BLOOM_TRIAD_DEV_BUILD_PETALS=0 \
BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=0 \
BLOOM_TRIAD_DEV_CEREMONY_PORT="$ceremony_port" \
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

# Bootstrap a test-only wallet on the first run. This mnemonic is a public test
# vector and the isolated Machine exposes only the local validator; it must
# never be funded or configured for a public network.
if ! "$machine_bin" wallet accounts "$wallet_id" >/dev/null 2>&1; then
  mnemonic_file="${run_root}/mnemonic.txt"
  printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art' > "$mnemonic_file"
  chmod 0600 "$mnemonic_file"
  import_launch="$("$machine_bin" wallet import "$wallet_id")" || die "wallet import launch failed"
  import_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$import_url" ] || die "wallet import did not publish a ceremony URL"
  import_result="$(complete_ceremony "$import_url" --mnemonic-file "$mnemonic_file")" ||
    die "wallet import ceremony failed"
  unlink "$mnemonic_file"
  imported_wallet="$(printf '%s' "$import_result" | jq -er '.wallet_id')" ||
    die "wallet import returned no wallet id"
  [ "$imported_wallet" = "$wallet_id" ] ||
    die "wallet import created $imported_wallet instead of $wallet_id"
fi

accounts=""
for _ in $(seq 1 120); do
  accounts="$("$machine_bin" wallet accounts "$wallet_id" 2>/dev/null || true)"
  printf '%s' "$accounts" | jq -e '.accounts | type == "array"' >/dev/null 2>&1 && break
  sleep 0.5
done
solana_accounts="$(printf '%s' "$accounts" | jq '[.accounts[] | select(.derivation_profile == "bip44-solana-slip10-ed25519-v1" and .lifecycle == "ACTIVE")] | length')" ||
  die "wallet $wallet_id account projection is unavailable"
if [ "$solana_accounts" = 0 ]; then
  allocate_launch="$("$machine_bin" wallet account-allocate "$wallet_id" \
    --profile bip44-solana-slip10-ed25519-v1)" || die "Solana account allocation launch failed"
  allocate_url="$(printf '%s\n' "$allocate_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$allocate_url" ] || die "Solana allocation did not publish a ceremony URL"
  complete_ceremony "$allocate_url" >/dev/null || die "Solana account allocation ceremony failed"
  for _ in $(seq 1 120); do
    accounts="$("$machine_bin" wallet accounts "$wallet_id" 2>/dev/null || true)"
    solana_accounts="$(printf '%s' "$accounts" | jq '[.accounts[] | select(.derivation_profile == "bip44-solana-slip10-ed25519-v1" and .lifecycle == "ACTIVE")] | length' 2>/dev/null || true)"
    [ "$solana_accounts" = 1 ] && break
    sleep 0.5
  done
fi
[ "$solana_accounts" = 1 ] || die "wallet $wallet_id must have exactly one active Solana child"
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

if [ "$agent" = smoke ]; then
  printf 'Bloom Solana local eval: running deterministic zero-token smoke...\n' >&2
  "${repo_root}/scripts/evals/run-harbor.sh" solana-transfer --smoke-only
else
  printf 'Bloom Solana local eval: running Harbor with %s (%s)...\n' \
    "$agent" "${BLOOM_EVAL_MODEL:-provider default}" >&2
  "${repo_root}/scripts/evals/run-harbor.sh" solana-transfer "$agent"
fi
