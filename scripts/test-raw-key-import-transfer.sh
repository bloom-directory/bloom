#!/usr/bin/env bash
# End-to-end acceptance for raw secp256k1 EVM key import through the real
# triad: a fixed throwaway private key is delivered only to the Broker-hosted
# ceremony through the deterministic debug driver (never through Machine), the
# resulting imported-scalar wallet is projected without derived BIP-39
# accounts, and the wallet then spends on a local anvil chain through the
# canonical stage -> Sealed Approval ceremony -> Signer signature -> broadcast
# -> reconciliation lifecycle. The on-chain sender must equal the address
# derived from the imported key.
#
# Binaries are selected with the standard launcher environment:
#   BLOOM_INTEGRATION_MACHINE_BIN / BLOOM_INTEGRATION_BROKER_BIN /
#   BLOOM_INTEGRATION_SIGNER_BIN / BLOOM_INTEGRATION_DEBUG_DRIVER_BIN
# so the exact Machine/Broker/Signer revisions under test stay explicit.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
broker_repo="$(cd "${repo_root}/../bloom-broker" && pwd -P)"
launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-${repo_root}/target/debug/bloom}"
driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:-${broker_repo}/target/debug/bloom-broker-debug-driver}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-300}"

die() { printf 'raw-import transfer e2e: %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v anvil >/dev/null 2>&1 || die "anvil (foundry) is required"
command -v cast >/dev/null 2>&1 || die "cast (foundry) is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -x "$launcher" ] || die "triad developer launcher is not executable: $launcher"
[ -x "$bloom_bin" ] || die "Machine binary is not executable: $bloom_bin"
[ -x "$driver_bin" ] || die "debug driver binary is not executable: $driver_bin"
case "$startup_timeout_secs" in *[!0-9]*|'') die "startup timeout must be an integer" ;; esac

# Throwaway determinism: private-key scalar 1 (not an anvil prefunded account),
# funded from anvil account #0 to anvil account #1. The ceremony input is the
# base64url encoding of the 32 raw key bytes, which is what Signer's
# `raw_private_key` custody field decodes.
TEST_RAW_KEY="0x0000000000000000000000000000000000000000000000000000000000000001"
TEST_RAW_KEY_B64="$(python3 -c "
import base64
key = bytes.fromhex('${TEST_RAW_KEY#0x}')
assert len(key) == 32
print(base64.urlsafe_b64encode(key).decode().rstrip('='))
")"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FUNDER_PRIV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTH_SEED="raw-import-e2e-auth"
WALLET_NAME="raw-import-e2e"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

run_root="$(mktemp -d "${TMPDIR:-/tmp}/bloom-raw-import.XXXXXX")"
developer_root="${run_root}/developer"
machine_home="${developer_root}/machine-home"
log_dir="${run_root}/logs"
machine_socket="${run_root}/run/machine.sock"
ready_file="${run_root}/run/ready"
launcher_log="${run_root}/launcher.log"
machine_config="${run_root}/machine-config.toml"
launcher_pid=""
anvil_pid=""
mkdir -p "$machine_home" "$log_dir" "$(dirname "$machine_socket")"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  if [ -n "$anvil_pid" ] && kill -0 "$anvil_pid" 2>/dev/null; then
    kill "$anvil_pid" 2>/dev/null || true
    wait "$anvil_pid" 2>/dev/null || true
  fi
  if [ "$status" -eq 0 ]; then
    # A late writer inside the shutting-down triad can race a single rm -rf
    # (ENOTEMPTY on the final rmdir); retry briefly so success runs do not
    # leave stray directories behind.
    rm_attempts=0
    while [ -e "$run_root" ] && [ "$rm_attempts" -lt 5 ]; do
      rm -rf -- "$run_root" 2>/dev/null || true
      rm_attempts=$((rm_attempts + 1))
      [ -e "$run_root" ] || break
      sleep 0.2
    done
  else
    printf 'raw-import transfer e2e diagnostics retained at: %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

cli() {
  "$bloom_bin" --home "$machine_home" "$@"
}

vcat() {
  cli vfs cat "$1"
}

vwrite() {
  cli vfs write "$1" --data "$2"
}

wait_for_file() {
  label="$1"; path="$2"; attempts=0; body=""
  while [ "$attempts" -lt 200 ]; do
    if body="$(vcat "$path" 2>/dev/null)" && [ -n "$body" ]; then
      printf '%s' "$body"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.1
  done
  die "timed out waiting for ${label}: ${path}"
}

printf 'raw-import transfer e2e: binaries\n  machine: %s\n  driver:  %s\n' "$bloom_bin" "$driver_bin"

# 1. Anvil up on a free port.
anvil_port="$(free_port)"
anvil_log="${run_root}/anvil.log"
anvil --port "$anvil_port" --host 127.0.0.1 --chain-id 31337 >"$anvil_log" 2>&1 &
anvil_pid=$!
rpc_url="http://127.0.0.1:${anvil_port}"
attempts=0
while ! cast block-number --rpc-url "$rpc_url" >/dev/null 2>&1; do
  kill -0 "$anvil_pid" 2>/dev/null || { cat "$anvil_log" >&2; die "anvil exited before RPC became ready"; }
  attempts=$((attempts + 1))
  [ "$attempts" -lt 100 ] || die "anvil RPC did not become ready"
  sleep 0.1
done
recipient_balance_before="$(cast balance --rpc-url "$rpc_url" "$RECIPIENT")"

# 2. Machine config points the anvil chain at our node and allows broadcast.
nfs_port="$(free_port)"
{
  printf 'default_chain = "anvil"\n'
  printf 'nfs_listen_addr = "127.0.0.1:%s"\n' "$nfs_port"
  printf '\n[chains.anvil]\n'
  printf 'name = "anvil"\n'
  printf 'chain_id = 31337\n'
  printf 'rpc_urls = ["%s"]\n' "$rpc_url"
  printf 'rpc_endpoints = []\n'
  printf 'allow_broadcast = true\n'
  printf 'display_name = "Anvil (local)"\n'
  printf 'native_symbol = "ETH"\n'
  printf 'native_decimals = 18\n'
  printf 'legacy_tx = false\n'
  printf 'op_stack = false\n'
} > "$machine_config"
chmod 0600 "$machine_config"

# 3. Triad up (no kernel mount; the vfs CLI is the owner surface).
: > "$launcher_log"
BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
BLOOM_INTEGRATION_MACHINE_BIN="$bloom_bin" \
  "$launcher" \
    --developer-root "$developer_root" \
    --machine-home "$machine_home" \
    --machine-socket "$machine_socket" \
    --log-dir "$log_dir" \
    --ready-file "$ready_file" >"$launcher_log" 2>&1 &
launcher_pid=$!
deadline=$(( $(date +%s) + startup_timeout_secs ))
while [ ! -f "$ready_file" ]; do
  kill -0 "$launcher_pid" 2>/dev/null || { cat "$launcher_log" >&2; die "triad developer stack exited during startup"; }
  [ "$(date +%s)" -lt "$deadline" ] || { cat "$launcher_log" >&2; die "triad developer stack did not become ready"; }
  sleep 0.1
done
# shellcheck disable=SC1090
source "${log_dir}/triad.env"

# 4. Import the raw key through the real Broker-hosted ceremony.
expected_addr="$(cast wallet address "$TEST_RAW_KEY" | tr '[:upper:]' '[:lower:]')"
[ "$expected_addr" = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf" ] ||
  die "unexpected address for the fixed test scalar: $expected_addr"
printf 'raw-import transfer e2e: importing scalar %s through the ceremony...\n' "$expected_addr"
import_launch="$(cli wallet import "$WALLET_NAME" --raw-private-key)"
import_ceremony_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$import_ceremony_url" ] || die "wallet import launch omitted ceremony_url: $import_launch"
printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p' | grep -q '^http://localhost:18734/ceremony/' ||
  die "import ceremony URL is not the canonical Broker origin: $import_ceremony_url"
import_result="$("$driver_bin" complete "$import_ceremony_url" "$AUTH_SEED" \
  --sign-count 1 --raw-private-key "$TEST_RAW_KEY_B64")"
wallet_id="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
printf 'raw-import transfer e2e: imported wallet %s\n' "$wallet_id"

# 5. Projection: authenticated Broker projection carries the imported key's
#    exact EVM address, and wallet.accounts is the imported-scalar profile
#    with no derived accounts.
projection="$(cli wallet projection "$wallet_id")"
printf '%s' "$projection" | jq -e --arg wallet "$wallet_id" --arg addr "$expected_addr" '
  .wallet.wallet_id == $wallet and
  .source_protocol == "bloom.machine-broker.v1" and
  .verification == "authenticated_broker" and
  (.wallet.root_key_ref | type == "object") and
  any(.keys[].addresses[]?; ascii_downcase == $addr)
' >/dev/null || die "imported wallet projection omitted the imported key address: $projection"
accounts="$(cli wallet accounts "$wallet_id")"
printf '%s' "$accounts" | jq -e --arg wallet "$wallet_id" '
  .wallet_id == $wallet and
  .seed_profile == "imported-secp256k1-scalar" and
  (.accounts | length) == 0
' >/dev/null || die "imported wallet must project the scalar seed profile with no derived accounts: $accounts"
[ ! -e "${machine_home}/keystore/${wallet_id}" ] || die "Machine created a legacy keystore record"
[ ! -e "${machine_home}/auth/auth.sqlite" ] || die "Machine created legacy auth.sqlite"
[ ! -e "${machine_home}/signer-cache" ] || die "Machine created a legacy signer cache"

# 6. Allowlist the transfer recipient through the canonical policy-update
#    custody ceremony: a fresh imported wallet denies every destination until
#    the owner amends the signed policy.
current_policy="$(vcat "/wallets/${wallet_id}/policy.json")"
printf '%s' "$current_policy" | jq -e --arg wallet "$wallet_id" '
  .wallet_id == $wallet and (.allowed_destinations | type == "array")
' >/dev/null || die "wallet policy projection is malformed: $current_policy"
policy_file="${run_root}/proposed-policy.json"
printf '%s' "$current_policy" | jq -cS \
  --arg chain "anvil" --arg dest "$RECIPIENT" \
  '.allowed_destinations = ((.allowed_destinations // []) + [{chain:$chain, destination:$dest}] | unique | sort)' \
  > "$policy_file"
policy_launch="$(cli wallet update-policy "$wallet_id" --file "$policy_file" 2>&1)" ||
  die "policy update launch failed: ${policy_launch:-<no diagnostic>}"
policy_ceremony_url="$(printf '%s\n' "$policy_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$policy_ceremony_url" ] || die "policy update launch omitted ceremony_url: $policy_launch"
"$driver_bin" complete "$policy_ceremony_url" "$AUTH_SEED" --sign-count 2 >/dev/null ||
  die "completing the policy-update ceremony failed"
policy_operation="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
printf '%s' "$policy_operation" | grep -Eq '^[0-9a-f]{64}$' ||
  die "policy update launch omitted a valid operation_id: $policy_launch"
cli wallet commit-policy "$policy_operation" >/dev/null ||
  die "policy commit failed"
updated_policy="$(vcat "/wallets/${wallet_id}/policy.json")"
printf '%s' "$updated_policy" | jq -e --arg dest "$RECIPIENT" '
  any(.allowed_destinations[]; .destination == $dest)
' >/dev/null || die "committed policy omitted the allowlisted recipient: $updated_policy"

# 7. Fund the imported address and observe the balance through the VFS.
cast send --rpc-url "$rpc_url" --private-key "$FUNDER_PRIV_KEY" \
  "$expected_addr" --value 10ether >/dev/null || die "funding the imported address failed"
sleep 0.25
balance="$(wait_for_file "imported wallet balance" "/wallets/${wallet_id}/chains/anvil/balance")"
printf '%s' "$balance" | grep -q '^10' || die "imported wallet balance should start with 10: $balance"
printf '%s' "$balance" | grep -q 'ETH' || die "imported wallet balance missing native symbol: $balance"

# 8. Stage a native transfer from the imported wallet.
intent="$(jq -nc --arg to "$RECIPIENT" \
  '{kind:"send", to:$to, value:"1 eth", chain:"anvil", usd_value_hint:"1"}')"
vwrite "/wallets/${wallet_id}/chains/anvil/outbox/new.tx" "$intent" ||
  die "staging the send intent failed"
pending_dir="/wallets/${wallet_id}/chains/anvil/outbox/pending"
pending_id=""
attempts=0
while [ "$attempts" -lt 100 ]; do
  pending_listing="$(cli vfs ls "$pending_dir" 2>/dev/null || true)"
  pending_id="$(printf '%s\n' "$pending_listing" | awk -F '\t' '$2 == "Dir" { print $1; exit }')"
  [ -n "$pending_id" ] && break
  attempts=$((attempts + 1))
  sleep 0.1
done
[ -n "$pending_id" ] || die "staged intent never reached ${pending_dir}"
plan="$(vcat "${pending_dir}/${pending_id}/plan.md")"
[ -n "$plan" ] || die "plan.md is empty"
policy_check="$(vcat "${pending_dir}/${pending_id}/policy_check.json")"
printf '%s' "$policy_check" | jq -e . >/dev/null || die "policy_check.json is not valid JSON"
printf 'raw-import transfer e2e: staged pending entry %s\n' "$pending_id"

# 9. First confirm must fail closed and persist the Sealed Approval ceremony.
confirm_path="${pending_dir}/${pending_id}/confirm"
if vwrite "$confirm_path" "y" >/dev/null 2>&1; then
  die "confirm succeeded before the approval ceremony completed"
fi
ceremony="$(wait_for_file "pending ceremony projection" "${pending_dir}/${pending_id}/ceremony.json")"
approval_ceremony_url="$(printf '%s' "$ceremony" | jq -er '.ceremony_url')"
printf '%s' "$ceremony" | jq -e '.approval_operation_id | test("^[0-9a-f]{64}$")' >/dev/null ||
  die "pending ceremony.json omitted a durable approval operation id: $ceremony"

# 10. Complete the approval ceremony and confirm on the exact retry.
"$driver_bin" complete "$approval_ceremony_url" "$AUTH_SEED" --sign-count 3 >/dev/null ||
  die "completing the Sealed Approval ceremony failed"
vwrite "$confirm_path" "y" || die "post-ceremony confirm retry failed"

# 11. The entry must reconcile into sent/ with a transaction hash.
sent_dir="/wallets/${wallet_id}/chains/anvil/outbox/sent"
tx_hash="$(wait_for_file "broadcast transaction hash" "${sent_dir}/${pending_id}/tx_hash" | tr -d '[:space:]')"
printf '%s' "$tx_hash" | grep -Eq '^0x[0-9a-f]{64}$' || die "malformed tx_hash: $tx_hash"
terminal_ceremony="$(vcat "${sent_dir}/${pending_id}/ceremony.json")"
printf '%s' "$terminal_ceremony" | jq -e '.sign_dispatched == true and .ceremony_url == null' >/dev/null ||
  die "terminal signing projection is not terminal: $terminal_ceremony"
sent_intent="$(vcat "${sent_dir}/${pending_id}/intent.json")"
printf '%s' "$sent_intent" | jq -e --arg hash "$tx_hash" '
  .status == "sent" and .tx_hash == $hash
' >/dev/null || die "sent intent.json is inconsistent: $sent_intent"

# 12. On-chain truth: the sender is the imported key's address, the transfer
#     landed, and the sender nonce advanced exactly once.
receipt="$(cast receipt --rpc-url "$rpc_url" --json "$tx_hash")"
printf '%s' "$receipt" | jq -e --arg addr "$expected_addr" --arg to "$(printf '%s' "$RECIPIENT" | tr '[:upper:]' '[:lower:]')" '
  (.status == "0x1" or .status == "1") and
  (.from | ascii_downcase) == $addr and
  (.to | ascii_downcase) == $to
' >/dev/null || die "on-chain receipt does not match the imported sender: $receipt"
sender_nonce="$(cast nonce --rpc-url "$rpc_url" "$expected_addr")"
[ "$sender_nonce" = "1" ] || die "imported sender nonce should be exactly 1: $sender_nonce"
recipient_balance_after="$(cast balance --rpc-url "$rpc_url" "$RECIPIENT")"
balance_delta_ok="$(python3 -c "
before = int('$recipient_balance_before'.strip(), 0)
after = int('$recipient_balance_after'.strip(), 0)
print('ok' if after - before == 10**18 else 'bad')
")"
[ "$balance_delta_ok" = "ok" ] ||
  die "recipient balance did not advance by exactly 1 ETH: before=${recipient_balance_before} after=${recipient_balance_after}"

# 13. Secret confinement: nothing about the imported scalar (hex or base64url)
#     may appear anywhere Machine wrote. The generic
#     assert-machine-secret-confinement scanner is deliberately NOT run here:
#     it hard-requires a persisted Petal-scoped child as its decryptability
#     control, which belongs to the projection-fidelity lane's flow, not to a
#     raw-import transfer that derives no Petal key.
if grep -R -F -a -q -- "${TEST_RAW_KEY#0x}" "$machine_home" "$log_dir" "$launcher_log" 2>/dev/null ||
  grep -R -F -a -q -- "$TEST_RAW_KEY" "$machine_home" "$log_dir" "$launcher_log" 2>/dev/null ||
  grep -R -F -a -q -- "$TEST_RAW_KEY_B64" "$machine_home" "$log_dir" "$launcher_log" 2>/dev/null; then
  die "imported key material leaked into Machine-owned artifacts"
fi

printf 'raw-import transfer e2e passed: wallet %s imported scalar %s through the Broker ceremony, spent it on anvil (%s), and the on-chain sender matched exactly.\n' \
  "$wallet_id" "$expected_addr" "$tx_hash"
