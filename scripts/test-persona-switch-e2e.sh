#!/usr/bin/env bash
# End-to-end check of a persona switch on a throwaway developer triad.
#
# 1-4. As scripts/test-default-policy-e2e.sh: create main with Hyperliquid and
#      Polymarket chosen, and check its default policy and settings.
# 5.   `bloom wallet persona main degen`: until the owner approves its one
#      ceremony nothing changes; once approved, main's policy is replaced
#      (every catalog Petal, Degen's entries, the standing lifetime), the
#      setup is saved and Polymarket's limit resets to Degen's.
# 6.   A switch to Trader is superseded by a switch to Institutional before
#      its ceremony is approved: the first ends with nothing changed, and the
#      second replaces the policy and resets the limit.
#
# Binaries and network access as for scripts/test-default-policy-e2e.sh.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
launcher="$repo_root/scripts/triad-dev-launch.sh"
bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-$repo_root/target/debug/bloom}"
driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:?set to the pinned bloom-broker-debug-driver}"
: "${BLOOM_INTEGRATION_BROKER_BIN:?set to the pinned bloom-broker}"
: "${BLOOM_INTEGRATION_SIGNER_BIN:?set to the pinned bloom-signer}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-600}"
provisioning_timeout_secs="${BLOOM_INTEGRATION_PROVISIONING_TIMEOUT_SECS:-300}"
AUTH_SEED="default-policy-e2e-auth"
WALLET="main"

die() { printf 'default policy e2e: %s\n' "$*" >&2; exit 1; }
say() { printf 'default policy e2e: %s\n' "$*"; }

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -x "$launcher" ] || die "launcher is not executable: $launcher"
[ -x "$driver_bin" ] || die "debug driver is not executable: $driver_bin"

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
# What `bloom init` records when the setup settings write is refused because
# the wallet's account does not exist yet.
mkdir -p "$machine_home/pending-petal-settings"
: > "$machine_home/pending-petal-settings/polymarket"

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
#    the setup choices. The launcher copies it unchanged.
nfs_port="$(free_port)"
ceremony_port="$(free_port)"
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

[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["http://127.0.0.1:9"]
rpc_endpoints = []
allow_broadcast = false
display_name = "Ethereum (placeholder)"
native_symbol = "ETH"
native_decimals = 18
legacy_tx = false
op_stack = false

[chains.polygon]
name = "polygon"
chain_id = 137
rpc_urls = ["http://127.0.0.1:9"]
rpc_endpoints = []
allow_broadcast = false
display_name = "Polygon (placeholder)"
native_symbol = "POL"
native_decimals = 18
legacy_tx = false
op_stack = false

[setup]
complete = true

[setup.wallets.main.petals.hyperliquid]

[setup.wallets.main.petals.polymarket.values]
max_daily_usd = "73"
EOF
chmod 0600 "$machine_config"

say "launching the developer triad (logs: $launcher_log)"
BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
  "$launcher" \
    --ceremony-port "$ceremony_port" \
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

grep -q '^\[setup.wallets.main.petals.polymarket.values\]' "$machine_home/config.toml" ||
  die "launcher dropped the [setup] tables"

# Machine installs the catalog Petals in the background once it is ready.
owners_dir="$machine_home/petals/store/owners"
deadline=$(( $(date +%s) + provisioning_timeout_secs ))
until [ -f "$owners_dir/hyperliquid.json" ] && [ -f "$owners_dir/polymarket.json" ]; do
  kill -0 "$launcher_pid" 2>/dev/null || { tail -40 "$launcher_log" >&2; die "triad exited while installing the catalog Petals"; }
  [ "$(date +%s)" -lt "$deadline" ] || {
    grep 'petal.provisioning_finished' "$log_dir/machine.log" >&2 || true
    die "Machine did not install hyperliquid and polymarket from the catalog"
  }
  sleep 1
done

owner_hash() { jq -er '.hash' "$owners_dir/$1.json"; }
hl_hash="$(owner_hash hyperliquid)" || die "hyperliquid is not installed"
pm_hash="$(owner_hash polymarket)" || die "polymarket is not installed"
say "installed hyperliquid ${hl_hash:0:12}, polymarket ${pm_hash:0:12}"

settings_path="/petals/polymarket/settings/$WALLET/0/venue.toml"
if cli vfs cat "$settings_path" >/dev/null 2>&1; then
  die "Polymarket settings exist before wallet $WALLET does"
fi
[ -e "$machine_home/pending-petal-settings/polymarket" ] ||
  die "the pending settings marker was removed before the wallet existed"

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

# Each completion needs a higher signature counter than the last. A higher
# counter is always safe after a refused attempt; reuse never is.
sign_count=0
complete_ceremony() {
  local url="$1" label="$2"
  sign_count=$((sign_count + 1))
  if ! "$driver_bin" complete "$url" "$AUTH_SEED" --sign-count "$sign_count" >>"$run_root/driver.out" 2>&1; then
    sign_count=$((sign_count + 1))
    "$driver_bin" complete "$url" "$AUTH_SEED" --sign-count "$sign_count" >>"$run_root/driver.out" 2>&1 ||
      { cat "$run_root/driver.out" >&2; die "$label ceremony failed"; }
  fi
}

wallet_url="$(wait_for_line 'ceremony_url: ')"
say "completing the wallet registration ceremony"
complete_ceremony "$wallet_url" "wallet registration"

policy_url="$(wait_for_line 'default_policy_url: ')"
grep -q '^default_policy: approve the policy for main to allow ' "$new_out" ||
  die "default policy announcement missing: $(cat "$new_out")"
say "completing the default-policy ceremony"
complete_ceremony "$policy_url" "default-policy"

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
# Polymarket contributes `petal:polymarket` on Polygon; Hyperliquid signs
# payloads rather than transactions and contributes none.
printf '%s' "$policy" | jq -e --arg hl "$hl_hash" --arg pm "$pm_hash" '
  (.allowed_petal_packages | sort) == ([$hl, $pm] | sort) and
  [.allowed_destinations[] | {chain, destination}] == [{"chain": "polygon", "destination": "petal:polymarket"}] and
  (.required_verifiers | length) == 0
' >/dev/null || die "main's policy does not allow exactly the chosen Petals and their destinations: $policy"
say "policy.json allows exactly hyperliquid and polymarket, with petal:polymarket on Polygon"

resume="$(cli wallet default-policy "$WALLET" 2>&1)" || die "default-policy resume failed: $resume"
printf '%s\n' "$resume" | grep -q '^default_policy: main allows ' ||
  die "default-policy resume did not report applied: $resume"
printf '%s\n' "$resume" | grep -q 'default_policy_url' &&
  die "default-policy resume opened another ceremony: $resume"
say "bloom wallet default-policy main reports the policy applied without a new ceremony"

# 4. The pending settings were applied after main's account 0 appeared, with
#    the value chosen in setup, and the marker is gone.
settings="$(cli vfs cat "$settings_path")" ||
  die "Polymarket settings were not applied after wallet $WALLET was created"
printf '%s\n' "$settings" | grep -q '^enabled = true$' || die "settings not enabled: $settings"
printf '%s\n' "$settings" | grep -q '^max_daily_usd = "73"$' || die "settings limit is not the setup value: $settings"
[ ! -e "$machine_home/pending-petal-settings/polymarket" ] ||
  die "the pending settings marker was not cleared after the write succeeded"
if grep -qE 'petal.setup_settings_key_(not_stored|unchecked)' "$log_dir/machine.log" ||
  grep -q 'petal_settings_unprotected' "$new_out"; then
  grep -E 'petal.setup_settings_key_(not_stored|unchecked)' "$log_dir/machine.log" >&2 || true
  die "Polymarket did not store its settings under the pinned key; update store_key in github_source.rs"
fi
say "Polymarket settings for $WALLET/0 applied from setup: enabled = true, max_daily_usd = \"73\""

# 5. Switch main to Degen: a fresh start. Without a terminal the command
#    accepts the persona's suggestions, every canonical Petal, so wait for all
#    of them to be installed first.
deadline=$(( $(date +%s) + provisioning_timeout_secs ))
all_installed() {
  local p
  for p in polymarket hyperliquid enso near-intents feedback; do
    [ -f "$owners_dir/$p.json" ] || return 1
  done
}
until all_installed; do
  [ "$(date +%s)" -lt "$deadline" ] || die "Machine did not install every catalog Petal"
  sleep 1
done
all_hashes="$(for p in polymarket hyperliquid enso near-intents feedback; do owner_hash "$p"; done | jq -R . | jq -s 'sort')"

# Start a switch and wait for its ceremony; sets switch_pid, switch_out, switch_url.
start_switch() {
  local persona="$1"
  switch_out="$run_root/persona-$persona.out"
  cli wallet persona "$WALLET" "$persona" >"$switch_out" 2>&1 &
  switch_pid=$!
  local attempts=0
  switch_url=""
  while [ -z "$switch_url" ]; do
    switch_url="$(sed -n 's/^default_policy_url: //p' "$switch_out" | head -1)"
    [ -n "$switch_url" ] && break
    kill -0 "$switch_pid" 2>/dev/null || { cat "$switch_out" >&2; die "wallet persona $persona exited before its ceremony"; }
    attempts=$((attempts + 1)); [ "$attempts" -lt 600 ] || { cat "$switch_out" >&2; die "no ceremony for $persona"; }
    sleep 0.2
  done
}

# Wait for a switch command to exit 0; `$2` names it in failures.
finish_switch() {
  local pid="$1" label="$2" out="$3"
  local deadline=$(( $(date +%s) + 120 ))
  while kill -0 "$pid" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { cat "$out" >&2; die "$label did not finish"; }
    sleep 0.5
  done
  wait "$pid" || { cat "$out" >&2; die "$label exited non-zero"; }
}

policy_matches() {
  cli vfs cat "/wallets/$WALLET/policy.json" | jq -e --argjson hashes "$all_hashes" "$1" >/dev/null
}

start_switch degen
new_pid="$switch_pid"
# Nothing changes before the owner approves.
grep -q '^preset = "degen"$' "$machine_home/config.toml" && die "the Degen setup was saved before approval"
cli vfs cat "$settings_path" | grep -q '^max_daily_usd = "73"$' ||
  die "Polymarket's limit changed before the switch was approved: $(cli vfs cat "$settings_path")"
[ -f "$machine_home/pending-persona/$WALLET.toml" ] || die "the waiting switch was not recorded"
say "before approval the Degen switch changed nothing"
complete_ceremony "$switch_url" "Degen switch"
finish_switch "$switch_pid" "the Degen switch" "$switch_out"
new_pid=""
grep -q '^petal_settings: Polymarket reset to max_daily_usd = 10000$' "$switch_out" ||
  die "the switch did not report Polymarket's reset: $(cat "$switch_out")"
policy_matches '
  (.allowed_petal_packages | sort) == $hashes and
  (.allowed_destinations | length) == 23 and
  ([.allowed_destinations[] | select(.destination == "erc20:any-recipient") | .chain] | sort) == ["evm-1", "evm-137"] and
  .maximum_approval_lifetime_ms == 9007199254740991
' || die "the Degen switch did not replace main's policy: $(cli vfs cat "/wallets/$WALLET/policy.json")"
cli vfs cat "$settings_path" | grep -q '^max_daily_usd = "10000"$' || die "Polymarket's limit was not reset"
grep -q '^preset = "degen"$' "$machine_home/config.toml" || die "main's Degen setup was not saved"
[ ! -e "$machine_home/pending-persona/$WALLET.toml" ] || die "the approved switch was not cleared"
say "approving the Degen switch replaced main's policy (5 Petals, 23 destinations, standing lifetime), saved it and reset Polymarket to 10000"

# 6. A later switch supersedes one still waiting.
start_switch trader
trader_pid="$switch_pid"; trader_out="$switch_out"
new_pid="$trader_pid"
start_switch institutional
new_pid="$switch_pid"
finish_switch "$trader_pid" "the superseded Trader switch" "$trader_out"
grep -q 'a later persona switch for main replaced this one, so nothing of it applies' "$trader_out" ||
  die "the superseded switch did not report that it was replaced: $(cat "$trader_out")"
grep -q '^preset = "degen"$' "$machine_home/config.toml" || die "a superseded switch changed main's setup"
complete_ceremony "$switch_url" "Institutional switch"
finish_switch "$switch_pid" "the Institutional switch" "$switch_out"
new_pid=""
policy_matches '
  (.allowed_petal_packages | sort) == $hashes and
  (.allowed_destinations | length) == 21 and
  ([.allowed_destinations[] | select(.destination == "erc20:any-recipient")] | length) == 0 and
  .maximum_approval_lifetime_ms == 2592000000
' || die "the Institutional switch did not replace main's policy: $(cli vfs cat "/wallets/$WALLET/policy.json")"
cli vfs cat "$settings_path" | grep -q '^max_daily_usd = "100"$' || die "Polymarket's limit was not reset to 100"
grep -q '^preset = "custodian"$' "$machine_home/config.toml" || die "main's Institutional setup was not saved"
resume="$(cli wallet default-policy "$WALLET" 2>&1)" || die "default-policy resume failed: $resume"
printf '%s\n' "$resume" | grep -q '^default_policy: main allows ' || die "resume did not report applied: $resume"
printf '%s\n' "$resume" | grep -q 'default_policy_url' && die "resume after the switch opened a ceremony: $resume"
say "a switch to Institutional superseded a waiting Trader switch, which ended unapplied, and replaced main's policy"

say "passed"
