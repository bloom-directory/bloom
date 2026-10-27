#!/usr/bin/env bash
# End-to-end check of the default wallet policy on a throwaway developer triad.
#
# 1. Launch a triad whose Machine config chooses Hyperliquid and Polymarket in
#    [petals.setup], and wait for Machine to install both from the release
#    catalog, as it does on a release install.
# 2. `bloom wallet new main`: the debug driver completes the wallet
#    registration ceremony, then the default-policy ceremony the command opens.
# 3. Verify main's policy allows exactly both installed package hashes, that
#    `bloom wallet default-policy main` reports it applied.
# 4. Verify the Polymarket settings chosen during setup were applied to main's
#    account 0 once the wallet existed. The triad starts with the pending
#    marker `bloom init` leaves when its settings write is refused because the
#    account does not exist yet (the marker is seeded here rather than produced
#    by `bloom init`, which cannot run against a live triad). The settings must
#    be absent before the wallet exists, present afterwards with the setup
#    value rather than the catalog default, and the marker must be cleared.
#    Machine must not report that the pinned settings key went unstored.
# 5. Leave the marker again, as a stopped `wallet new` would, after the owner
#    has saved their own Polymarket settings, exactly the text the route reads
#    when nothing is stored. Resuming keeps the owner's settings, since what is
#    stored decides rather than what the route reads, and clears the marker.
# 6. Remove Hyperliquid through an ordinary policy ceremony. Resuming then
#    reports that the policy changed and proposes nothing.
#
# Binaries: BLOOM_INTEGRATION_BROKER_BIN, BLOOM_INTEGRATION_SIGNER_BIN and
# BLOOM_INTEGRATION_DEBUG_DRIVER_BIN must point at builds of the Broker and
# Signer revisions pinned in packaging/triad/release/compatibility-v1.toml.
#
# The Petals are the catalog releases, not local builds. Machine installs the
# catalog releases as soon as it starts, and a local build cannot replace one
# afterwards because the catalog has no successor record for it. Installing
# the releases downloads their pinned archives, so this needs network access.
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

[petals]
setup_complete = true

[petals.setup.hyperliquid]

[petals.setup.polymarket.values]
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

grep -q '^\[petals.setup.polymarket.values\]' "$machine_home/config.toml" ||
  die "launcher dropped the [petals.setup] tables"

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
# Polymarket contributes its four Polygon destinations; Hyperliquid signs
# payloads rather than transactions and contributes none.
printf '%s' "$policy" | jq -e --arg hl "$hl_hash" --arg pm "$pm_hash" '
  (.allowed_petal_packages | sort) == ([$hl, $pm] | sort) and
  ([.allowed_destinations[] | select(.chain == "polygon") | .destination] | sort) == ([
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb",
    "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf"
  ] | sort) and
  (.allowed_destinations | length) == 4 and
  (.required_verifiers | length) == 0
' >/dev/null || die "main's policy does not allow exactly the chosen Petals and their destinations: $policy"
say "policy.json allows exactly hyperliquid and polymarket, with Polymarket's Polygon destinations"

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

# 5. A deferred setup write never replaces settings written since, even
#    settings that read exactly like the route's default.
owner_settings="$(printf 'enabled = false\nallow_neg_risk = true\n')"
printf '%s\n' "$owner_settings" | cli vfs write "$settings_path" >/dev/null ||
  die "could not write the owner's Polymarket settings"
: > "$machine_home/pending-petal-settings/polymarket"
resume="$(cli wallet default-policy "$WALLET" 2>&1)" || die "default-policy resume failed: $resume"
printf '%s\n' "$resume" | grep -q '^default_policy: main allows ' ||
  die "default-policy resume did not report applied: $resume"
settings="$(cli vfs cat "$settings_path")"
[ "$settings" = "$owner_settings" ] ||
  die "resuming replaced the owner's Polymarket settings: $settings"
[ ! -e "$machine_home/pending-petal-settings/polymarket" ] ||
  die "the pending settings marker survived settings the owner wrote"
say "resuming kept the owner's saved Polymarket settings, though they read like the default, and cleared the stale marker"

# 6. Once the owner changes the policy, resuming proposes nothing.
policy_path="/wallets/$WALLET/policy.json"
reduced="$run_root/policy-without-hyperliquid.json"
cli vfs cat "$policy_path" | jq --arg hl "$hl_hash" '.allowed_petal_packages -= [$hl]' >"$reduced"
if cli vfs write "$policy_path" <"$reduced" >"$run_root/reduce.out" 2>&1; then
  die "removing a Petal from the policy did not ask for the owner's approval"
fi
reduce_url="$(cli vfs cat "/wallets/$WALLET/policy-updates/latest/status.json" | jq -r '.ceremony_url // empty')"
[ -n "$reduce_url" ] || die "no ceremony for the policy change: $(cat "$run_root/reduce.out")"
say "completing the owner's ceremony that removes Hyperliquid"
complete_ceremony "$reduce_url" "policy change"
cli vfs write "$policy_path" <"$reduced" >/dev/null || die "the approved policy change did not commit"
cli vfs cat "$policy_path" | jq -e --arg hl "$hl_hash" '.allowed_petal_packages | index($hl) == null' >/dev/null ||
  die "Hyperliquid is still allowed after the owner removed it"
resume="$(cli wallet default-policy "$WALLET" 2>&1)" || die "default-policy resume failed: $resume"
printf '%s\n' "$resume" | grep -q "^default_policy: main's policy has changed since the wallet was created and does not allow Hyperliquid" ||
  die "default-policy resume did not report the changed policy: $resume"
printf '%s\n' "$resume" | grep -q 'default_policy_url' &&
  die "default-policy resume proposed the removed Petal again: $resume"
cli vfs cat "$policy_path" | jq -e --arg hl "$hl_hash" '.allowed_petal_packages | index($hl) == null' >/dev/null ||
  die "Hyperliquid came back after resuming"
say "after the owner removed Hyperliquid, bloom wallet default-policy main proposes nothing"

say "passed"
