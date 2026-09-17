#!/usr/bin/env bash
# End-to-end check of the default wallet policy on a throwaway developer triad.
#
# 1. Launch a triad whose Machine config chooses Hyperliquid and Polymarket in
#    [petals.setup], with both Petals installed from local builds.
# 2. `bloom wallet new main`: the debug driver completes the wallet
#    registration ceremony, then the default-policy ceremony the command opens.
# 3. Verify main's policy allows exactly both installed package hashes, that
#    `bloom wallet default-policy main` reports it applied, and that
#    Polymarket's settings route round-trips the setup file.
#
# Binaries: BLOOM_INTEGRATION_BROKER_BIN, BLOOM_INTEGRATION_SIGNER_BIN and
# BLOOM_INTEGRATION_DEBUG_DRIVER_BIN must point at builds of the Broker and
# Signer revisions pinned in packaging/triad/release/compatibility-v1.toml.
# Petal checkouts default to siblings of this repository (BLOOM_PETALS_ROOT).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
petals_root="$(cd "${BLOOM_PETALS_ROOT:-$repo_root/..}" && pwd -P)"
launcher="$repo_root/scripts/triad-dev-launch.sh"
bloom_bin="$repo_root/target/debug/bloom"
driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:?set to the pinned bloom-broker-debug-driver}"
: "${BLOOM_INTEGRATION_BROKER_BIN:?set to the pinned bloom-broker}"
: "${BLOOM_INTEGRATION_SIGNER_BIN:?set to the pinned bloom-signer}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-600}"
AUTH_SEED="default-policy-e2e-auth"
WALLET="main"

die() { printf 'default policy e2e: %s\n' "$*" >&2; exit 1; }
say() { printf 'default policy e2e: %s\n' "$*"; }

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -x "$launcher" ] || die "launcher is not executable: $launcher"
[ -x "$driver_bin" ] || die "debug driver is not executable: $driver_bin"
[ -d "$petals_root/bloom-petal-hyperliquid/petal/hyperliquid" ] || die "build bloom-petal-hyperliquid first"
[ -d "$petals_root/bloom-petal-polymarket/petal/polymarket" ] || die "build bloom-petal-polymarket first"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# Short root: triad Unix sockets live under it and macOS caps them at 104 bytes.
run_root="$(mktemp -d /tmp/bdp.XXXXXX)"
developer_root="$run_root/developer"
machine_home="$developer_root/machine-home"
log_dir="$run_root/logs"
machine_socket="$run_root/run/machine.sock"
ready_file="$run_root/run/ready"
launcher_log="$run_root/launcher.log"
machine_config="$run_root/machine-config.toml"
new_out="$run_root/wallet-new.out"
launcher_pid=""
new_pid=""
mkdir -p "$machine_home" "$log_dir" "$(dirname "$machine_socket")"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "$new_pid" "$launcher_pid"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ "$status" -eq 0 ]; then
    rm -rf -- "$run_root" 2>/dev/null || true
  else
    printf 'default policy e2e: diagnostics retained at %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

cli() { "$bloom_bin" --home "$machine_home" "$@"; }

# 1. Machine config: a placeholder chain (nothing here reads chain state) and
#    the setup choices. The launcher forces preinstalled = [] but keeps these.
nfs_port="$(free_port)"
cat > "$machine_config" <<EOF
default_chain = "anvil"
nfs_listen_addr = "127.0.0.1:${nfs_port}"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:9"]
rpc_endpoints = []
allow_broadcast = false
display_name = "Anvil (placeholder)"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false
op_stack = false

[petals]
preinstalled = []

[petals.setup.hyperliquid]

[petals.setup.polymarket.values]
max_daily_usd = "100"
EOF
chmod 0600 "$machine_config"

say "launching the developer triad (logs: $launcher_log)"
BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
BLOOM_TRIAD_DEV_BUILD_PETALS=0 \
BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE="$petals_root/bloom-petal-hyperliquid" \
BLOOM_TRIAD_DEV_POLYMARKET_PACKAGE="$petals_root/bloom-petal-polymarket" \
  "$launcher" \
    --developer-root "$developer_root" \
    --machine-home "$machine_home" \
    --machine-socket "$machine_socket" \
    --log-dir "$log_dir" \
    --ready-file "$ready_file" >"$launcher_log" 2>&1 &
launcher_pid=$!
deadline=$(( $(date +%s) + startup_timeout_secs ))
while [ ! -f "$ready_file" ]; do
  kill -0 "$launcher_pid" 2>/dev/null || { tail -40 "$launcher_log" >&2; die "triad exited during startup"; }
  [ "$(date +%s)" -lt "$deadline" ] || { tail -40 "$launcher_log" >&2; die "triad did not become ready"; }
  sleep 1
done
# shellcheck disable=SC1090
source "$log_dir/triad.env"
say "triad ready"

grep -q '^\[petals.setup.polymarket.values\]' "$machine_home/config.toml" ||
  die "launcher dropped the [petals.setup] tables"

owner_hash() { jq -er '.hash' "$machine_home/petals/store/owners/$1.json"; }
hl_hash="$(owner_hash hyperliquid)" || die "hyperliquid is not installed"
pm_hash="$(owner_hash polymarket)" || die "polymarket is not installed"
say "installed hyperliquid ${hl_hash:0:12}, polymarket ${pm_hash:0:12}"

# 2. Create main; the command waits between the two ceremonies.
cli wallet new "$WALLET" >"$new_out" 2>&1 &
new_pid=$!

wait_for_line() {
  local prefix="$1" attempts=0 value=""
  while [ "$attempts" -lt 600 ]; do
    value="$(sed -n "s/^${prefix}//p" "$new_out" | head -1)"
    [ -n "$value" ] && { printf '%s' "$value"; return 0; }
    kill -0 "$new_pid" 2>/dev/null || { cat "$new_out" >&2; die "wallet new exited before printing ${prefix}"; }
    attempts=$((attempts + 1))
    sleep 0.2
  done
  cat "$new_out" >&2
  die "timed out waiting for ${prefix}"
}

wallet_url="$(wait_for_line 'ceremony_url: ')"
say "completing the wallet registration ceremony"
"$driver_bin" complete "$wallet_url" "$AUTH_SEED" --sign-count 1 >/dev/null ||
  die "wallet registration ceremony failed"

policy_url="$(wait_for_line 'default_policy_url: ')"
grep -q '^default_policy: approve the policy for main to allow ' "$new_out" ||
  die "default policy announcement missing: $(cat "$new_out")"
say "completing the default-policy ceremony"
if ! "$driver_bin" complete "$policy_url" "$AUTH_SEED" --sign-count 2 >"$run_root/policy-driver.out" 2>&1; then
  # A higher counter is always safe after a refused attempt; reuse never is.
  "$driver_bin" complete "$policy_url" "$AUTH_SEED" --sign-count 3 >>"$run_root/policy-driver.out" 2>&1 ||
    { cat "$run_root/policy-driver.out" >&2; die "default-policy ceremony failed"; }
fi

deadline=$(( $(date +%s) + 120 ))
while kill -0 "$new_pid" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || { cat "$new_out" >&2; die "wallet new did not finish after the policy ceremony"; }
  sleep 0.5
done
wait "$new_pid" || { cat "$new_out" >&2; die "wallet new exited non-zero"; }
new_pid=""
grep -q '^default_policy: main allows ' "$new_out" ||
  die "wallet new did not report the applied policy: $(cat "$new_out")"
say "$(grep '^default_policy: main allows ' "$new_out")"

# 3. Verify the committed policy and the idempotent resume command.
policy="$(cli vfs cat "/wallets/$WALLET/policy.json")"
# Polymarket contributes its three Polygon destinations; Hyperliquid signs
# payloads rather than transactions and contributes none.
printf '%s' "$policy" | jq -e --arg hl "$hl_hash" --arg pm "$pm_hash" '
  (.allowed_petal_packages | sort) == ([$hl, $pm] | sort) and
  ([.allowed_destinations[] | select(.chain == "polygon") | .destination] | sort) == ([
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb",
    "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf"
  ] | sort) and
  (.allowed_destinations | length) == 3 and
  (.required_verifiers | length) == 0
' >/dev/null || die "main's policy does not allow exactly the chosen Petals and their destinations: $policy"
say "policy.json allows exactly hyperliquid and polymarket, with Polymarket's Polygon destinations"

resume="$(cli wallet default-policy "$WALLET" 2>&1)" || die "default-policy resume failed: $resume"
printf '%s\n' "$resume" | grep -q '^default_policy: main allows ' ||
  die "default-policy resume did not report applied: $resume"
printf '%s\n' "$resume" | grep -q 'default_policy_url' &&
  die "default-policy resume opened another ceremony: $resume"
say "bloom wallet default-policy main reports the policy applied without a new ceremony"

# Polymarket's own settings route accepts and returns the setup file.
settings_path="/petals/polymarket/settings/$WALLET/venue.toml"
cli vfs write "$settings_path" --data "$(printf 'enabled = true\nmax_daily_usd = "100"\n')" ||
  die "writing Polymarket settings failed"
settings="$(cli vfs cat "$settings_path")"
printf '%s\n' "$settings" | grep -q '^enabled = true$' || die "settings not enabled: $settings"
printf '%s\n' "$settings" | grep -q '^max_daily_usd = "100"$' || die "settings limit wrong: $settings"
say "Polymarket settings route round-trips enabled = true and max_daily_usd = \"100\""

say "passed"
