#!/usr/bin/env bash
# End-to-end acceptance for the BIP-39 account lifecycle through the real
# triad: a fixed throwaway mnemonic is delivered only to the Broker-hosted
# ceremony, the imported wallet's canonical EVM child (m/44'/60'/0'/0/0) is
# projected together with its canonical Solana sibling. Signer then allocates
# account 1 in both families. That account spends on local Anvil and Agave
# validator chains through the canonical stage ->
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
command -v solana-test-validator >/dev/null 2>&1 || die "solana-test-validator (Agave) is required for real Solana account-1 signing"
command -v solana >/dev/null 2>&1 || die "solana CLI is required for validator setup and on-chain verification"
command -v solana-keygen >/dev/null 2>&1 || die "solana-keygen is required for a disposable transfer recipient"
command -v curl >/dev/null 2>&1 || die "curl is required for validator transaction verification"
[ -x "$launcher" ] || die "triad developer launcher is not executable: $launcher"
[ -x "$bloom_bin" ] || die "Machine binary is not executable: $bloom_bin"
[ -x "$driver_bin" ] || die "debug driver binary is not executable: $driver_bin"
case "$startup_timeout_secs" in *[!0-9]*|'') die "startup timeout must be an integer" ;; esac

# Throwaway determinism: the canonical all-abandon test mnemonic, never funded
# outside this run. The canonical EVM child at m/44'/60'/0'/0/0 is derived
# independently with cast below, funded from anvil account #0.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
EVM_HD_PATH="m/44'/60'/0'/0/0"
SOLANA_HD_PATH="m/44'/501'/0'/0'"
EVM_ACCOUNT_ONE_PATH="m/44'/60'/0'/0/1"
SOLANA_ACCOUNT_ONE_PATH="m/44'/501'/1'/0'"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FUNDER_PRIV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTH_SEED="bip39-e2e-auth"
WALLET_NAME="bip39-e2e"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

solana_lamports() {
  curl --silent --show-error --fail "$solana_rpc" -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg address "$1" '{jsonrpc:"2.0",id:1,method:"getBalance",params:[$address]}')" |
    jq -er '.result.value'
}

work_root="${BLOOM_INTEGRATION_WORK_ROOT:-${repo_root}/target/triad-account1}"
mkdir -p "$work_root"
run_root="$(mktemp -d "${work_root}/run.XXXXXX")"
export TMPDIR="${run_root}/tmp"
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
validator_pid=""
mkdir -p "$TMPDIR" "$machine_home" "$log_dir" "$(dirname "$machine_socket")"

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
  if [ -n "$validator_pid" ] && kill -0 "$validator_pid" 2>/dev/null; then
    kill "$validator_pid" 2>/dev/null || true
    wait "$validator_pid" 2>/dev/null || true
  fi
  rm -f -- "$mnemonic_file"
  printf 'bip39 transfer e2e run retained at: %s\n' "$run_root" >&2
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

# Pin the genesis of a real local validator before Machine starts. The
# disposable recipient provides an independent on-chain balance check.
solana_port="$(free_port)"
solana_faucet_port="$(free_port)"
solana_rpc="http://127.0.0.1:${solana_port}"
validator_log="${run_root}/validator.log"
solana-test-validator --ledger "${run_root}/solana-ledger" --rpc-port "$solana_port" \
  --faucet-port "$solana_faucet_port" --bind-address 127.0.0.1 \
  >"$validator_log" 2>&1 &
validator_pid=$!
attempts=0
until solana_genesis="$(solana genesis-hash --url "$solana_rpc" 2>/dev/null)"; do
  kill -0 "$validator_pid" 2>/dev/null || { cat "$validator_log" >&2; die "Solana validator exited before RPC became ready"; }
  attempts=$((attempts + 1))
  [ "$attempts" -lt 150 ] || die "Solana validator RPC did not become ready"
  sleep 0.2
done
solana_recipient_keypair="${run_root}/solana-recipient.json"
solana-keygen new --no-bip39-passphrase --silent --outfile "$solana_recipient_keypair" >/dev/null
solana_recipient="$(solana-keygen pubkey "$solana_recipient_keypair")"
solana_recipient_before="$(solana_lamports "$solana_recipient")"

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
  printf 'display_name = "Anvil (local)"\n'
  printf 'native_symbol = "ETH"\n'
  printf 'native_decimals = 18\n'
  printf 'legacy_tx = false\n'
  printf 'op_stack = false\n'
  printf '\n[solana_chains.solana-local]\n'
  printf 'name = "solana-local"\n'
  printf 'expected_genesis_base58 = "%s"\n' "$solana_genesis"
  printf '[[solana_chains.solana-local.endpoints]]\n'
  printf 'url = "%s"\n' "$solana_rpc"
  printf 'weight = 100\n'
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

# 5. Import projects both canonical children without another ceremony.
accounts="$(cli wallet accounts "$wallet_id")"
printf '%s' "$accounts" | jq -e --arg wallet "$wallet_id" --arg evm_path "$EVM_HD_PATH" --arg solana_path "$SOLANA_HD_PATH" --arg addr "$expected_addr" '
  .wallet_id == $wallet and
  .seed_profile == "bip39-multicurve-v1" and
  ([.accounts[] | select(
      .derivation_profile == "bip44-evm-secp256k1-v1" and
      .path == $evm_path and .lifecycle == "ACTIVE")] | length) == 1 and
  ([.accounts[] | select(
      .derivation_profile == "bip44-solana-slip10-ed25519-v1" and
      .path == $solana_path and .lifecycle == "ACTIVE")] | length) == 1 and
  any(.accounts[]; any(.chain_projections[]?; (.address | ascii_downcase) == $addr))
' >/dev/null || die "imported wallet did not project the canonical EVM child at the derived address: $accounts"
[ "$(printf '%s' "$accounts" | jq '.accounts | length')" = "2" ] ||
  die "a fresh BIP-39 import must project exactly two accounts: $accounts"
solana_address="$(cli wallet address "$wallet_id" --profile solana)"
case "$solana_address" in
  ''|*[!123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*)
    die "wallet address did not print a Base58 Solana address: $solana_address" ;;
esac
printf 'bip39 transfer e2e: import projected EVM and Solana children (Solana: %s)\n' "$solana_address"

# 6. Signer allocates both account-1 children in one real custody ceremony.
#    The `new` projection must report Signer's number before either family
#    can be used; Machine never guesses it from list position.
vwrite "/wallets/${wallet_id}/new" '{"request_id":"account-one"}' ||
  die "account-1 allocation request failed"
creation="$(wait_for_file "account creation" "/wallets/${wallet_id}/new")"
account_ceremony_url="$(printf '%s' "$creation" | jq -er '.requests[] | select(.request_id == "account-one") | .ceremony_url')"
"$driver_bin" complete "$account_ceremony_url" "$AUTH_SEED" --sign-count 2 >/dev/null ||
  die "account-1 custody ceremony failed"
attempts=0
while [ "$attempts" -lt 100 ]; do
  creation="$(vcat "/wallets/${wallet_id}/new")"
  if printf '%s' "$creation" | jq -e 'any(.requests[]; .request_id == "account-one" and .state == "created" and .number == 1)' >/dev/null; then
    break
  fi
  attempts=$((attempts + 1))
  sleep 0.1
done
[ "$attempts" -lt 100 ] || die "Signer did not allocate account 1: $creation"
accounts="$(cli wallet accounts "$wallet_id")"
printf '%s' "$accounts" | jq -e --arg evm "$EVM_ACCOUNT_ONE_PATH" --arg sol "$SOLANA_ACCOUNT_ONE_PATH" '
  ([.accounts[] | select(.number == 1 and .path == $evm and .lifecycle == "ACTIVE")] | length) == 1 and
  ([.accounts[] | select(.number == 1 and .path == $sol and .lifecycle == "ACTIVE")] | length) == 1
' >/dev/null || die "account-1 projection lacks paired EVM/Solana children: $accounts"
expected_addr="$(cast wallet address --mnemonic "$MNEMONIC" --hd-path "$EVM_ACCOUNT_ONE_PATH" | tr '[:upper:]' '[:lower:]')"
projected_addr="$(vcat "/wallets/${wallet_id}/1/address.evm" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
[ "$projected_addr" = "$expected_addr" ] || die "account-1 EVM address disagrees with cast derivation: ${projected_addr} != ${expected_addr}"
solana_address="$(vcat "/wallets/${wallet_id}/1/address.sol" | tr -d '[:space:]')"
case "$solana_address" in
  ''|*[!123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*)
    die "account-1 Solana address is not Base58: $solana_address" ;;
esac
solana airdrop 2 "$solana_address" --url "$solana_rpc" >/dev/null ||
  die "funding the account-1 Solana child failed"
printf 'bip39 transfer e2e: Signer allocated account 1 (EVM %s, Solana %s)\n' "$expected_addr" "$solana_address"

# 7. Allowlist both recipients through the canonical policy-update
#    ceremony (a fresh wallet denies every destination).
current_policy="$(vcat "/wallets/${wallet_id}/policy.json")"
policy_file="${run_root}/proposed-policy.json"
printf '%s' "$current_policy" | jq -cS \
  --arg chain "anvil" --arg dest "$RECIPIENT" \
  --arg sol_chain "solana" --arg sol_dest "$solana_recipient" \
  '.allowed_destinations = ((.allowed_destinations // []) + [{chain:$chain, destination:$dest}, {chain:$sol_chain, destination:$sol_dest}] | unique | sort)' \
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

# 8. Fund account 1 and stage a native EVM transfer. The wallet now holds two
#    EVM children; the numbered path pins the one that may sign this intent.
cast send --rpc-url "$rpc_url" --private-key "$FUNDER_PRIV_KEY" \
  "$expected_addr" --value 10ether >/dev/null || die "funding the canonical child failed"
sleep 0.25
balance="$(wait_for_file "account-1 child balance" "/wallets/${wallet_id}/1/chains/anvil/balance")"
printf '%s' "$balance" | grep -q '^10' || die "canonical child balance should start with 10: $balance"
intent="$(jq -nc --arg to "$RECIPIENT" \
  '{kind:"send", to:$to, value:"1 eth", chain:"anvil", usd_value_hint:"1"}')"
vwrite "/wallets/${wallet_id}/1/chains/anvil/outbox/new.tx" "$intent" ||
  die "staging the send intent failed"
pending_dir="/wallets/${wallet_id}/1/chains/anvil/outbox/pending"
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

# 8. First confirm must fail closed and persist the Sealed Approval ceremony.
confirm_path="${pending_dir}/${pending_id}/confirm"
if vwrite "$confirm_path" "y" >/dev/null 2>&1; then
  die "confirm succeeded before the approval ceremony completed"
fi
ceremony="$(wait_for_file "pending ceremony projection" "${pending_dir}/${pending_id}/ceremony.json")"
approval_ceremony_url="$(printf '%s' "$ceremony" | jq -er '.ceremony_url')"

# 9. Complete the approval ceremony and confirm on the exact retry.
"$driver_bin" complete "$approval_ceremony_url" "$AUTH_SEED" --sign-count 4 >/dev/null ||
  die "completing the Sealed Approval ceremony failed"
vwrite "$confirm_path" "y" || die "post-ceremony confirm retry failed"

# 10. The entry must reconcile into sent/ with a transaction hash.
sent_dir="/wallets/${wallet_id}/1/chains/anvil/outbox/sent"
tx_hash="$(wait_for_file "broadcast transaction hash" "${sent_dir}/${pending_id}/tx_hash" | tr -d '[:space:]')"
printf '%s' "$tx_hash" | grep -Eq '^0x[0-9a-f]{64}$' || die "malformed tx_hash: $tx_hash"

# 11. On-chain truth: the sender is the canonical child's address, derived
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

# 12. Account 1 signs a native Solana transfer through Broker approval and
# Signer custody. The validator supplies independent transaction evidence.
solana_intent="$(jq -nc --arg destination "$solana_recipient" '{destination:$destination,lamports:1000000}')"
vwrite "/wallets/${wallet_id}/1/chains/solana-local/outbox/new.tx" "$solana_intent" ||
  die "staging the account-1 Solana transfer failed"
solana_pending="/wallets/${wallet_id}/1/chains/solana-local/outbox/pending"
solana_id=""
attempts=0
while [ "$attempts" -lt 100 ]; do
  listing="$(cli vfs ls "$solana_pending" 2>/dev/null || true)"
  solana_id="$(printf '%s\n' "$listing" | awk -F '\t' '$2 == "Dir" { print $1; exit }')"
  [ -n "$solana_id" ] && break
  attempts=$((attempts + 1))
  sleep 0.1
done
[ -n "$solana_id" ] || die "account-1 Solana intent never reached pending outbox"
solana_confirm="${solana_pending}/${solana_id}/confirm"
if vwrite "$solana_confirm" "y" >/dev/null 2>&1; then
  die "Solana confirm succeeded before Broker approval"
fi
challenge="$(wait_for_file "Solana approval challenge" "${solana_pending}/${solana_id}/approval_challenge.json")"
solana_ceremony_url="$(printf '%s' "$challenge" | jq -er '.ceremony_url')"
printf '%s' "$challenge" | jq -e --arg payer "$solana_address" '.fee_payer == $payer and .lamports == 1000000' >/dev/null ||
  die "Solana approval challenge did not bind the account-1 sender: $challenge"
"$driver_bin" complete "$solana_ceremony_url" "$AUTH_SEED" --sign-count 5 >/dev/null ||
  die "completing the Solana approval ceremony failed"
vwrite "$solana_confirm" "y" || die "post-ceremony Solana confirm failed"
solana_sent="/wallets/${wallet_id}/1/chains/solana-local/outbox/sent"
solana_receipt="$(wait_for_file "Solana reconciled receipt" "${solana_sent}/${solana_id}/receipt.json")"
solana_signature="$(printf '%s' "$solana_receipt" | jq -er 'select(.outcome == "success" and .err == null) | .signature')"
transaction="$(curl --silent --show-error --fail "$solana_rpc" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg signature "$solana_signature" '{jsonrpc:"2.0",id:1,method:"getTransaction",params:[$signature,{encoding:"json",maxSupportedTransactionVersion:0}]}')")"
printf '%s' "$transaction" | jq -e --arg payer "$solana_address" \
  '.result != null and .result.meta.err == null and .result.transaction.message.accountKeys[0] == $payer' >/dev/null ||
  die "validator transaction does not show account 1 as fee payer: $transaction"
solana_recipient_after="$(solana_lamports "$solana_recipient")"
[ "$((solana_recipient_after - solana_recipient_before))" -eq 1000000 ] ||
  die "Solana recipient did not receive exactly 1000000 lamports: before=${solana_recipient_before} after=${solana_recipient_after}"

# 13. Secret confinement: the mnemonic phrase must never appear in anything
#     Machine wrote.
if grep -R -F -a -q -- "$MNEMONIC" "$machine_home" "$log_dir" "$launcher_log" 2>/dev/null; then
  die "mnemonic material leaked into Machine-owned artifacts"
fi

printf 'bip39 transfer e2e passed: wallet %s spent from account 1 on Anvil (%s, EVM %s) and Solana validator (%s, Solana %s), with on-chain senders bound to the authenticated account.\n' \
  "$wallet_id" "$tx_hash" "$expected_addr" "$solana_signature" "$solana_address"
