#!/usr/bin/env bash
# End-to-end acceptance for the BIP-39 account lifecycle through the real
# triad: a fixed throwaway mnemonic is delivered only to the Broker-hosted
# ceremony, the imported wallet's canonical EVM child (m/44'/60'/0'/0/0) is
# projected, an AccountAllocate ceremony adds a Solana child that appears in
# the account projection only after the ceremony completes, and the canonical
# EVM child then spends on a local anvil chain through the canonical stage ->
# Sealed Approval ceremony -> Signer signature -> broadcast -> reconciliation
# lifecycle. The on-chain sender must equal the address independently derived
# from the mnemonic by cast.
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

die() { printf 'bip39 transfer e2e: %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v anvil >/dev/null 2>&1 || die "anvil (foundry) is required"
command -v cast >/dev/null 2>&1 || die "cast (foundry) is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -x "$launcher" ] || die "triad developer launcher is not executable: $launcher"
[ -x "$bloom_bin" ] || die "Machine binary is not executable: $bloom_bin"
[ -x "$driver_bin" ] || die "debug driver binary is not executable: $driver_bin"
case "$startup_timeout_secs" in *[!0-9]*|'') die "startup timeout must be an integer" ;; esac

# Throwaway determinism: the canonical all-abandon test mnemonic, never funded
# outside this run. The canonical EVM child at m/44'/60'/0'/0/0 is derived
# independently with cast below, funded from anvil account #0.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
EVM_HD_PATH="m/44'/60'/0'/0/0"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FUNDER_PRIV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTH_SEED="bip39-e2e-auth"
WALLET_NAME="bip39-e2e"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

run_root="$(mktemp -d "${TMPDIR:-/tmp}/bloom-bip39.XXXXXX")"
developer_root="${run_root}/developer"
machine_home="${developer_root}/machine-home"
log_dir="${run_root}/logs"
machine_socket="${run_root}/run/machine.sock"
ready_file="${run_root}/run/ready"
launcher_log="${run_root}/launcher.log"
machine_config="${run_root}/machine-config.toml"
mnemonic_file="${run_root}/mnemonic.txt"
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
    rm_attempts=0
    while [ -e "$run_root" ] && [ "$rm_attempts" -lt 5 ]; do
      rm -rf -- "$run_root" 2>/dev/null || true
      rm_attempts=$((rm_attempts + 1))
      [ -e "$run_root" ] || break
      sleep 0.2
    done
  else
    printf 'bip39 transfer e2e diagnostics retained at: %s\n' "$run_root" >&2
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

printf 'bip39 transfer e2e: binaries\n  machine: %s\n  driver:  %s\n' "$bloom_bin" "$driver_bin"

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

# Independent derivation of the canonical child address from the mnemonic.
expected_addr="$(cast wallet address --mnemonic "$MNEMONIC" --hd-path "$EVM_HD_PATH" | tr '[:upper:]' '[:lower:]')"
printf '%s' "$expected_addr" | grep -Eq '^0x[0-9a-f]{40}$' || die "cast derived a malformed child address: $expected_addr"
printf 'bip39 transfer e2e: canonical EVM child %s at %s\n' "$expected_addr" "$EVM_HD_PATH"

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

# 4. Import the mnemonic through the real Broker-hosted browser ceremony.
printf '%s\n' "$MNEMONIC" > "$mnemonic_file"
chmod 0600 "$mnemonic_file"
printf 'bip39 transfer e2e: importing the mnemonic through the ceremony...\n'
import_launch="$(cli wallet import "$WALLET_NAME")"
import_ceremony_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$import_ceremony_url" ] || die "wallet import launch omitted ceremony_url: $import_launch"
import_result="$("$driver_bin" complete "$import_ceremony_url" "$AUTH_SEED" \
  --sign-count 1 --mnemonic-file "$mnemonic_file")"
wallet_id="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
printf 'bip39 transfer e2e: imported wallet %s\n' "$wallet_id"

# 5. The canonical EVM child is projected exactly, with its derivation path.
accounts="$(cli wallet accounts "$wallet_id")"
printf '%s' "$accounts" | jq -e --arg wallet "$wallet_id" --arg path "$EVM_HD_PATH" --arg addr "$expected_addr" '
  .wallet_id == $wallet and
  .seed_profile == "bip39-multicurve-v1" and
  ([.accounts[] | select(
      .derivation_profile == "bip44-evm-secp256k1-v1" and
      .path == $path and .lifecycle == "ACTIVE")] | length) == 1 and
  any(.accounts[]; any(.chain_projections[]?; (.address | ascii_downcase) == $addr))
' >/dev/null || die "imported wallet did not project the canonical EVM child at the derived address: $accounts"
[ "$(printf '%s' "$accounts" | jq '.accounts | length')" = "1" ] ||
  die "a fresh BIP-39 import must project exactly one account: $accounts"

# 6. AccountAllocate adds a Solana child — but only once its ceremony
#    completes. Launch, prove the projection has NOT moved, then complete.
allocate_launch="$(cli wallet account-allocate "$wallet_id" --profile bip44-solana-slip10-ed25519-v1 2>&1)" ||
  die "account allocation launch failed: ${allocate_launch:-<no diagnostic>}"
allocate_ceremony_url="$(printf '%s\n' "$allocate_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$allocate_ceremony_url" ] || die "allocation launch omitted ceremony_url: $allocate_launch"
pre_accounts="$(cli wallet accounts "$wallet_id")"
[ "$(printf '%s' "$pre_accounts" | jq '[.accounts[] | select(.derivation_profile == "bip44-solana-slip10-ed25519-v1")] | length')" = "0" ] ||
  die "the Solana child was projected before its allocation ceremony completed"
"$driver_bin" complete "$allocate_ceremony_url" "$AUTH_SEED" --sign-count 2 >/dev/null ||
  die "completing the allocation ceremony failed"
post_accounts=""
attempts=0
while [ "$attempts" -lt 100 ]; do
  post_accounts="$(cli wallet accounts "$wallet_id")"
  if [ "$(printf '%s' "$post_accounts" | jq '[.accounts[] | select(.derivation_profile == "bip44-solana-slip10-ed25519-v1" and .lifecycle == "ACTIVE")] | length')" = "1" ]; then
    break
  fi
  attempts=$((attempts + 1))
  sleep 0.1
done
printf '%s' "$post_accounts" | jq -e '
  any(.accounts[]; .derivation_profile == "bip44-solana-slip10-ed25519-v1" and .lifecycle == "ACTIVE")
' >/dev/null || die "the completed allocation ceremony never projected an active Solana child: $post_accounts"
printf 'bip39 transfer e2e: allocated an active Solana child through the ceremony\n'

# 7. Allowlist the transfer recipient through the canonical policy-update
#    ceremony (a fresh wallet denies every destination).
current_policy="$(vcat "/wallets/${wallet_id}/policy.json")"
policy_file="${run_root}/proposed-policy.json"
printf '%s' "$current_policy" | jq -cS \
  --arg chain "anvil" --arg dest "$RECIPIENT" \
  '.allowed_destinations = ((.allowed_destinations // []) + [{chain:$chain, destination:$dest}] | unique | sort)' \
  > "$policy_file"
policy_launch="$(cli wallet update-policy "$wallet_id" --file "$policy_file" 2>&1)" ||
  die "policy update launch failed: ${policy_launch:-<no diagnostic>}"
policy_ceremony_url="$(printf '%s\n' "$policy_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$policy_ceremony_url" ] || die "policy update launch omitted ceremony_url: $policy_launch"
"$driver_bin" complete "$policy_ceremony_url" "$AUTH_SEED" --sign-count 3 >/dev/null ||
  die "completing the policy-update ceremony failed"
policy_operation="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
cli wallet commit-policy "$policy_operation" >/dev/null ||
  die "policy commit failed"

# 8. Fund the canonical child address and stage a native transfer. The wallet
#    holds exactly one EVM child, so the derived-child signing path resolves
#    implicitly and unambiguously.
cast send --rpc-url "$rpc_url" --private-key "$FUNDER_PRIV_KEY" \
  "$expected_addr" --value 10ether >/dev/null || die "funding the canonical child failed"
sleep 0.25
balance="$(wait_for_file "canonical child balance" "/wallets/${wallet_id}/chains/anvil/balance")"
printf '%s' "$balance" | grep -q '^10' || die "canonical child balance should start with 10: $balance"
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
printf 'bip39 transfer e2e: staged pending entry %s\n' "$pending_id"

# 9. First confirm must fail closed and persist the Sealed Approval ceremony.
confirm_path="${pending_dir}/${pending_id}/confirm"
if vwrite "$confirm_path" "y" >/dev/null 2>&1; then
  die "confirm succeeded before the approval ceremony completed"
fi
ceremony="$(wait_for_file "pending ceremony projection" "${pending_dir}/${pending_id}/ceremony.json")"
approval_ceremony_url="$(printf '%s' "$ceremony" | jq -er '.ceremony_url')"

# 10. Complete the approval ceremony and confirm on the exact retry.
"$driver_bin" complete "$approval_ceremony_url" "$AUTH_SEED" --sign-count 4 >/dev/null ||
  die "completing the Sealed Approval ceremony failed"
vwrite "$confirm_path" "y" || die "post-ceremony confirm retry failed"

# 11. The entry must reconcile into sent/ with a transaction hash.
sent_dir="/wallets/${wallet_id}/chains/anvil/outbox/sent"
tx_hash="$(wait_for_file "broadcast transaction hash" "${sent_dir}/${pending_id}/tx_hash" | tr -d '[:space:]')"
printf '%s' "$tx_hash" | grep -Eq '^0x[0-9a-f]{64}$' || die "malformed tx_hash: $tx_hash"

# 12. On-chain truth: the sender is the canonical child's address, derived
#     independently from the mnemonic by cast, and the transfer landed once.
receipt="$(cast receipt --rpc-url "$rpc_url" --json "$tx_hash")"
printf '%s' "$receipt" | jq -e --arg addr "$expected_addr" --arg to "$(printf '%s' "$RECIPIENT" | tr '[:upper:]' '[:lower:]')" '
  (.status == "0x1" or .status == "1") and
  (.from | ascii_downcase) == $addr and
  (.to | ascii_downcase) == $to
' >/dev/null || die "on-chain receipt does not match the canonical child sender: $receipt"
sender_nonce="$(cast nonce --rpc-url "$rpc_url" "$expected_addr")"
[ "$sender_nonce" = "1" ] || die "canonical child nonce should be exactly 1: $sender_nonce"
recipient_balance_after="$(cast balance --rpc-url "$rpc_url" "$RECIPIENT")"
balance_delta_ok="$(python3 -c "
before = int('$recipient_balance_before'.strip(), 0)
after = int('$recipient_balance_after'.strip(), 0)
print('ok' if after - before == 10**18 else 'bad')
")"
[ "$balance_delta_ok" = "ok" ] ||
  die "recipient balance did not advance by exactly 1 ETH: before=${recipient_balance_before} after=${recipient_balance_after}"

# 13. Secret confinement: the mnemonic phrase must never appear in anything
#     Machine wrote.
if grep -R -F -a -q -- "$MNEMONIC" "$machine_home" "$log_dir" "$launcher_log" 2>/dev/null; then
  die "mnemonic material leaked into Machine-owned artifacts"
fi

printf 'bip39 transfer e2e passed: wallet %s imported its canonical EVM child %s, allocated a Solana child through the ceremony, and spent from the child on anvil (%s) with the on-chain sender matching cast'\''s independent derivation.\n' \
  "$wallet_id" "$expected_addr" "$tx_hash"
