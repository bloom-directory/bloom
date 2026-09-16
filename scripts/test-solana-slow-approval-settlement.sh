#!/usr/bin/env bash
# The slow-approval settlement acceptance: a native SOL transfer whose staged
# blockhash genuinely expires before its owner approves still settles, once,
# through the real Machine, Broker and Signer processes against a real Solana
# validator.
#
# A Solana message commits to a recent blockhash the cluster honours for about
# a minute, while a passkey ceremony can easily take longer. A blockhash-
# normalized Exact approval covers the transfer's terms with those 32 bytes
# excluded, so the Machine may restamp the message once before signing. This
# script is the end-to-end proof of that: it waits for the cluster to pass the
# staged lastValidBlockHeight and refuse the staged blockhash outright, and
# only then completes the ceremony.
#
# Everything runs in a private network namespace. The ceremony listener is
# fixed at 127.0.0.1:18734 by design, one host has one owner of that port, and
# this run must not disturb whoever already holds it.
#
# Binaries are selected with the standard launcher environment:
#   BLOOM_INTEGRATION_MACHINE_BIN / BLOOM_INTEGRATION_BROKER_BIN /
#   BLOOM_INTEGRATION_SIGNER_BIN / BLOOM_INTEGRATION_DEBUG_DRIVER_BIN
# so the exact Machine/Broker/Signer revisions under test stay explicit.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
die() { printf 'solana slow-approval e2e: %s\n' "$*" >&2; exit 1; }
say() { printf 'solana slow-approval e2e: %s\n' "$*"; }

[ "$(uname -s)" = Linux ] || die "this acceptance is Linux-only; it needs a private network namespace"

# Re-enter in a private network namespace with a working loopback, keeping the
# invoking uid. Everything below then owns its own 127.0.0.1.
if [ "${BLOOM_SOLANA_E2E_ISOLATED:-0}" != 1 ]; then
  command -v unshare >/dev/null 2>&1 || die "unshare is required"
  command -v ip >/dev/null 2>&1 || die "iproute2 is required"
  exec env BLOOM_SOLANA_E2E_ISOLATED=1 \
    unshare --user --net --map-current-user --keep-caps -- \
    bash -c 'ip link set lo up && exec "$0" "$@"' "${BASH_SOURCE[0]}" "$@"
fi
[ "$(id -u)" -ne 0 ] || die "run this as the developer user, not root"

# The Broker's ceremony listeners cannot come from systemd user units here:
# those start in the user manager's network namespace, not this one.
export BLOOM_TRIAD_DEV_LINUX_SERVICE_MANAGER=direct
export BLOOM_TRIAD_DEV_BUILD_PETALS=0

launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
broker_repo="${BLOOM_TRIAD_DEV_BROKER_REPO:-$(cd "${repo_root}/../bloom-broker" 2>/dev/null && pwd -P || true)}"
signer_repo="${BLOOM_TRIAD_DEV_SIGNER_REPO:-$(cd "${repo_root}/../bloom-signer" 2>/dev/null && pwd -P || true)}"
[ -n "$broker_repo" ] || die "set BLOOM_TRIAD_DEV_BROKER_REPO to the Broker checkout under test"
[ -n "$signer_repo" ] || die "set BLOOM_TRIAD_DEV_SIGNER_REPO to the Signer checkout under test"
export BLOOM_TRIAD_DEV_BROKER_REPO="$broker_repo"
export BLOOM_TRIAD_DEV_SIGNER_REPO="$signer_repo"
bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-${repo_root}/target/debug/bloom}"
broker_bin="${BLOOM_INTEGRATION_BROKER_BIN:-${broker_repo}/target/debug/bloom-broker}"
signer_bin="${BLOOM_INTEGRATION_SIGNER_BIN:-${signer_repo}/target/debug/bloom-signer}"
driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:-${broker_repo}/target/debug/bloom-broker-debug-driver}"
export BLOOM_INTEGRATION_MACHINE_BIN="$bloom_bin"
export BLOOM_INTEGRATION_BROKER_BIN="$broker_bin"
export BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin"
validator_bin="${BLOOM_SOLANA_TEST_VALIDATOR_BIN:-solana-test-validator}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-300}"
# Generous: the whole point is that the ceremony is allowed to be slow. The
# approval itself is what bounds this, at five minutes.
expiry_timeout_secs="${BLOOM_SOLANA_E2E_EXPIRY_TIMEOUT_SECS:-240}"

for tool in jq curl python3 "$validator_bin" systemd-socket-activate; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
[ -x "$launcher" ] || die "triad developer launcher is not executable: $launcher"
for binary in "$bloom_bin" "$broker_bin" "$signer_bin" "$driver_bin"; do
  [ -x "$binary" ] || die "required binary is not executable: $binary"
done

# The canonical all-abandon test mnemonic; never funded outside a local
# validator. The recipient is a fixed off-curve-free 32-byte key that holds
# nothing anywhere else: base58 of 0xcc repeated.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
SOLANA_HD_PATH="m/44'/501'/0'/0'"
RECIPIENT="EnTJCS15dqbDTU2XywYSMaScoPv4Py4GzExrtY9DQxoD"
TRANSFER_LAMPORTS=125000000
AIRDROP_LAMPORTS=2000000000
AUTH_SEED="solana-slow-approval-auth"
WALLET_NAME="solana-slow-approval"
CHAIN="solana-local"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

run_root="${BLOOM_SOLANA_E2E_RUN_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/bloom-solana-slow.XXXXXX")}"
mkdir -p "$run_root"
run_root="$(cd "$run_root" && pwd -P)"
# The triad's Unix sockets live under the run root and sockaddr_un is 108
# bytes; the deepest of them adds a little under fifty. Fail here with a
# readable message rather than inside a service's bind().
[ "${#run_root}" -le 55 ] ||
  die "run root is too long for the triad's Unix sockets (${#run_root} chars, 55 max): $run_root"
developer_root="${run_root}/developer"
machine_home="${developer_root}/machine-home"
log_dir="${run_root}/logs"
machine_socket="${run_root}/run/machine.sock"
ready_file="${run_root}/run/ready"
launcher_log="${run_root}/launcher.log"
machine_config="${run_root}/machine-config.toml"
mnemonic_file="${run_root}/mnemonic.txt"
validator_log="${run_root}/validator.log"
ledger_dir="${run_root}/test-ledger"
launcher_pid=""
validator_pid=""
mkdir -p "$machine_home" "$log_dir" "$(dirname "$machine_socket")"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  if [ -n "$validator_pid" ] && kill -0 "$validator_pid" 2>/dev/null; then
    kill "$validator_pid" 2>/dev/null || true
    wait "$validator_pid" 2>/dev/null || true
  fi
  # The run directory is evidence; it is never removed here.
  printf 'solana slow-approval e2e artifacts: %s\n' "$run_root" >&2
  exit "$status"
}
trap cleanup EXIT INT TERM

# The launcher serves the Machine on $machine_socket (run root), not the
# --home-derived default: every CLI call must use the launcher endpoint.
export BLOOM_RPC_ENDPOINT="unix:${machine_socket}"
# A missing audit-history file means "no predecessors" (clean); pointing at
# the run root keeps a packaging-installed /etc/bloom history - which a
# developer UID cannot satisfy - from degrading this throwaway run.
export BLOOM_MACHINE_AUDIT_HISTORY="${run_root}/machine-audit-history.json"
cli() { "$bloom_bin" --home "$machine_home" "$@"; }
vcat() { cli vfs cat "$1"; }
vwrite() { cli vfs write "$1" --data "$2"; }

rpc() {
  curl -sS --max-time 20 -X POST -H 'content-type: application/json' \
    -d "$(jq -nc --arg method "$1" --argjson params "$2" \
      '{jsonrpc:"2.0", id:1, method:$method, params:$params}')" \
    "$solana_rpc"
}

wait_for_file() {
  label="$1"; path="$2"; attempts=0; body=""
  while [ "$attempts" -lt 600 ]; do
    if body="$(vcat "$path" 2>/dev/null)" && [ -n "$body" ]; then
      printf '%s' "$body"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.1
  done
  die "timed out waiting for ${label}: ${path}"
}

say "revisions under test"
for pair in "machine:${repo_root}" "broker:${broker_repo}" "signer:${signer_repo}"; do
  label="${pair%%:*}"; path="${pair#*:}"
  printf '  %-8s %s %s\n' "$label" "$(git -C "$path" rev-parse HEAD 2>/dev/null || echo unknown)" "$path"
done
printf '  %-8s %s\n' binaries "$bloom_bin"
printf '  %-8s %s\n' '' "$broker_bin"
printf '  %-8s %s\n' '' "$signer_bin"

# 1. A local validator with a fresh ledger. A reused ledger replays old state
#    and makes balance deltas meaningless.
rpc_port="$(free_port)"; faucet_port="$(free_port)"
gossip_port="$(free_port)"; dynamic_base="$(free_port)"
solana_rpc="http://127.0.0.1:${rpc_port}"
say "starting a validator on ${solana_rpc} with a fresh ledger"
"$validator_bin" \
  --ledger "$ledger_dir" --reset --quiet \
  --rpc-port "$rpc_port" --faucet-port "$faucet_port" \
  --gossip-port "$gossip_port" \
  --dynamic-port-range "${dynamic_base}-$((dynamic_base + 40))" \
  >"$validator_log" 2>&1 &
validator_pid=$!
attempts=0
until [ "$(rpc getHealth '[]' 2>/dev/null | jq -r '.result // empty')" = ok ]; do
  kill -0 "$validator_pid" 2>/dev/null || { tail -n 40 "$validator_log" >&2; die "validator exited during startup"; }
  attempts=$((attempts + 1))
  [ "$attempts" -lt 600 ] || die "validator RPC did not become healthy"
  sleep 0.2
done
genesis="$(rpc getGenesisHash '[]' | jq -er '.result')"
say "validator healthy; genesis ${genesis}"

# 2. Machine config: canonical base (keeps the required EVM `chains` table
# and its default) plus this cluster only, broadcast enabled, genesis pinned.
nfs_port="$(free_port)"
canonical_machine_config="${HOME}/.bloom/config.toml"
[ -f "$canonical_machine_config" ] && [ ! -L "$canonical_machine_config" ] ||
  die "canonical Machine config is not a regular file: $canonical_machine_config"
cp "$canonical_machine_config" "$machine_config"
{
  printf 'nfs_listen_addr = "127.0.0.1:%s"\n' "$nfs_port"
  printf '\n[solana_chains.%s]\n' "$CHAIN"
  printf 'name = "%s"\n' "$CHAIN"
  printf 'expected_genesis_base58 = "%s"\n' "$genesis"
  printf 'allow_broadcast = true\n'
  printf '\n[[solana_chains.%s.endpoints]]\n' "$CHAIN"
  printf 'url = "%s"\n' "$solana_rpc"
  printf 'weight = 100\n'
  printf 'http_only = false\n'
} >> "$machine_config"
chmod 0600 "$machine_config"

# 3. The real triad: real Signer, real Broker, real Machine, no kernel mount.
: > "$launcher_log"
BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
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
say "triad ready"

# 4. Import the mnemonic through the real Broker-hosted ceremony. The import
#    projects the canonical Solana child without a second ceremony.
printf '%s\n' "$MNEMONIC" > "$mnemonic_file"
chmod 0600 "$mnemonic_file"
import_launch="$(cli wallet import "$WALLET_NAME")"
import_ceremony_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$import_ceremony_url" ] || die "wallet import launch omitted ceremony_url: $import_launch"
import_result="$("$driver_bin" complete "$import_ceremony_url" "$AUTH_SEED" \
  --sign-count 1 --mnemonic-file "$mnemonic_file")"
wallet_id="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
accounts="$(cli wallet accounts "$wallet_id")"
printf '%s' "$accounts" | jq -e --arg path "$SOLANA_HD_PATH" '
  ([.accounts[] | select(
      .derivation_profile == "bip44-solana-slip10-ed25519-v1" and
      .path == $path and .lifecycle == "ACTIVE")] | length) == 1
' >/dev/null || die "imported wallet did not project the canonical Solana child: $accounts"
sender="$(cli wallet address "$wallet_id" --profile solana)"
say "wallet ${wallet_id}; Solana child ${sender} at ${SOLANA_HD_PATH}"

# 5. Allowlist the recipient through the canonical policy-update ceremony. A
#    fresh wallet denies every destination. The claim names the chain family,
#    not the operator's local cluster name.
current_policy="$(vcat "/wallets/${wallet_id}/policy.json")"
policy_file="${run_root}/proposed-policy.json"
printf '%s' "$current_policy" | jq -cS --arg dest "$RECIPIENT" \
  '.allowed_destinations = ((.allowed_destinations // []) + [{chain:"solana", destination:$dest}] | unique | sort)' \
  > "$policy_file"
policy_launch="$(cli wallet update-policy "$wallet_id" --file "$policy_file" 2>&1)" ||
  die "policy update launch failed: ${policy_launch:-<no diagnostic>}"
policy_ceremony_url="$(printf '%s\n' "$policy_launch" | sed -n 's/^ceremony_url: //p')"
[ -n "$policy_ceremony_url" ] || die "policy update launch omitted ceremony_url: $policy_launch"
"$driver_bin" complete "$policy_ceremony_url" "$AUTH_SEED" --sign-count 3 >/dev/null ||
  die "completing the policy-update ceremony failed"
policy_operation="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
cli wallet commit-policy "$policy_operation" >/dev/null || die "policy commit failed"
say "recipient ${RECIPIENT} allowlisted"

# 6. Fund the Solana child.
rpc requestAirdrop "$(jq -nc --arg a "$sender" --argjson l "$AIRDROP_LAMPORTS" '[$a,$l]')" >/dev/null
attempts=0
until [ "$(rpc getBalance "$(jq -nc --arg a "$sender" '[$a]')" | jq -r '.result.value // 0')" -ge "$AIRDROP_LAMPORTS" ]; do
  attempts=$((attempts + 1))
  [ "$attempts" -lt 120 ] || die "airdrop never credited ${sender}"
  sleep 0.5
done
recipient_before="$(rpc getBalance "$(jq -nc --arg a "$RECIPIENT" '[$a]')" | jq -r '.result.value // 0')"
say "funded ${sender}; recipient starts at ${recipient_before} lamports"

# 7. Stage the transfer.
intent="$(jq -nc --arg to "$RECIPIENT" --argjson l "$TRANSFER_LAMPORTS" \
  '{destination:$to, lamports:$l}')"
vwrite "/wallets/${wallet_id}/chains/${CHAIN}/outbox/new.tx" "$intent" ||
  die "staging the transfer failed"
pending_dir="/wallets/${wallet_id}/chains/${CHAIN}/outbox/pending"
pending_id=""
attempts=0
while [ "$attempts" -lt 200 ]; do
  pending_id="$(cli vfs ls "$pending_dir" 2>/dev/null | awk -F '\t' '$2 == "Dir" { print $1; exit }')"
  [ -n "$pending_id" ] && break
  attempts=$((attempts + 1))
  sleep 0.1
done
[ -n "$pending_id" ] || die "staged intent never reached ${pending_dir}"
staged_intent="$(wait_for_file "staged intent" "${pending_dir}/${pending_id}/intent.json")"
staged_blockhash="$(printf '%s' "$staged_intent" | jq -er '.blockhash')"
staged_last_valid="$(printf '%s' "$staged_intent" | jq -er '.last_valid_block_height')"
staged_message="$(printf '%s' "$staged_intent" | jq -er '.message_b64')"
printf '%s' "$staged_intent" | jq -e '.message_normalization == "solana_native_transfer_blockhash_v1"' >/dev/null ||
  die "a newly staged native transfer must be blockhash-normalized: $staged_intent"
say "staged ${pending_id}; blockhash ${staged_blockhash} valid through height ${staged_last_valid}"

# 8. The first confirm must fail closed and open the approval ceremony.
confirm_path="${pending_dir}/${pending_id}/confirm"
if vwrite "$confirm_path" "y" >/dev/null 2>&1; then
  die "confirm succeeded before the approval ceremony completed"
fi
ceremony="$(wait_for_file "pending ceremony projection" "${pending_dir}/${pending_id}/ceremony.json")"
approval_ceremony_url="$(printf '%s' "$ceremony" | jq -er '.ceremony_url')"
say "approval ceremony opened"

# 9. The point of the whole exercise: let the staged blockhash actually die on
#    the cluster before the owner approves.
started="$(date +%s)"
observed_height=0
deadline=$(( started + expiry_timeout_secs ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  observed_height="$(rpc getBlockHeight '[]' | jq -r '.result // 0')"
  [ "$observed_height" -gt "$staged_last_valid" ] && break
  sleep 0.5
done
[ "$observed_height" -gt "$staged_last_valid" ] ||
  die "cluster never passed the staged window: ${observed_height} <= ${staged_last_valid}"
still_valid="$(rpc isBlockhashValid "$(jq -nc --arg h "$staged_blockhash" '[$h, {commitment:"processed"}]')" |
  jq -r '.result.value')"
[ "$still_valid" = false ] ||
  die "the staged blockhash is still valid; this run proves nothing: isBlockhashValid=${still_valid}"
say "blockhash expired: height ${observed_height} > ${staged_last_valid} after $(( $(date +%s) - started ))s; isBlockhashValid=false"

# 10. Only now does the owner approve, and the same entry confirms.
"$driver_bin" complete "$approval_ceremony_url" "$AUTH_SEED" --sign-count 4 >/dev/null ||
  die "completing the Sealed Approval ceremony failed"
vwrite "$confirm_path" "y" || die "post-ceremony confirm retry failed"

sent_dir="/wallets/${wallet_id}/chains/${CHAIN}/outbox/sent"
signature="$(wait_for_file "broadcast signature" "${sent_dir}/${pending_id}/tx_hash" | tr -d '[:space:]')"
say "settled as ${signature}"

# 11. On-chain truth.
tx=""
attempts=0
while [ "$attempts" -lt 120 ]; do
  tx="$(rpc getTransaction "$(jq -nc --arg s "$signature" \
    '[$s, {encoding:"json", commitment:"confirmed", maxSupportedTransactionVersion:0}]')")"
  [ "$(printf '%s' "$tx" | jq -r '.result // "null"')" != null ] && break
  attempts=$((attempts + 1))
  sleep 0.5
done
[ "$(printf '%s' "$tx" | jq -r '.result // "null"')" != null ] || die "validator never returned ${signature}"
printf '%s' "$tx" | jq -e '.result.meta.err == null' >/dev/null || die "transaction failed on chain: $tx"
signed_blockhash="$(printf '%s' "$tx" | jq -er '.result.transaction.message.recentBlockhash')"
[ "$signed_blockhash" != "$staged_blockhash" ] ||
  die "the settled transaction carried the expired staged blockhash"
printf '%s' "$tx" | jq -e --arg sender "$sender" --arg to "$RECIPIENT" '
  .result.transaction.message.accountKeys[0] == $sender and
  (.result.transaction.message.accountKeys | index($to)) != null and
  (.result.transaction.message.instructions | length) == 1
' >/dev/null || die "settled transaction is not the single reviewed transfer: $tx"

recipient_after="$(rpc getBalance "$(jq -nc --arg a "$RECIPIENT" '[$a]')" | jq -r '.result.value // 0')"
[ "$((recipient_after - recipient_before))" -eq "$TRANSFER_LAMPORTS" ] ||
  die "recipient moved by $((recipient_after - recipient_before)), expected ${TRANSFER_LAMPORTS}"
say "recipient ${recipient_before} -> ${recipient_after} lamports; signed under ${signed_blockhash}"

# 12. Retrying the settled operation must not pay twice. The same approval is
#     spent and the entry has already reconciled.
retry_output="$(vwrite "$confirm_path" "y" 2>&1)" && retry_status=0 || retry_status=$?
if [ "$retry_status" -eq 0 ]; then
  say "retry was accepted as a no-op: ${retry_output:-<no output>}"
else
  say "retry refused: ${retry_output}"
fi
sleep 2
recipient_final="$(rpc getBalance "$(jq -nc --arg a "$RECIPIENT" '[$a]')" | jq -r '.result.value // 0')"
[ "$recipient_final" -eq "$recipient_after" ] ||
  die "retry produced a second payment: ${recipient_after} -> ${recipient_final}"
sender_signatures="$(rpc getSignaturesForAddress "$(jq -nc --arg a "$sender" '[$a, {limit:25}]')" |
  jq -r '[.result[] | select(.err == null)] | length')"
# One airdrop credit does not appear under the sender's own signatures; the
# only signature this account authored is the transfer itself.
[ "$sender_signatures" -eq 1 ] ||
  die "expected exactly one settled signature from ${sender}, found ${sender_signatures}"

say "PASSED"
printf '  wallet            %s\n' "$wallet_id"
printf '  sender            %s\n' "$sender"
printf '  recipient         %s (+%s lamports)\n' "$RECIPIENT" "$TRANSFER_LAMPORTS"
printf '  staged blockhash  %s (expired, isBlockhashValid=false)\n' "$staged_blockhash"
printf '  signed blockhash  %s\n' "$signed_blockhash"
printf '  signature         %s\n' "$signature"
printf '  staged message    %s\n' "$staged_message"
