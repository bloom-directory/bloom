#!/usr/bin/env bash
# Concurrency acceptance for independent ceremony ports: two complete
# development Triads (A on one port, B on another) run side by side while
# the installed custody Triad keeps 18734. Each candidate enrolls a
# disposable wallet through the real Broker-hosted ceremony and completes
# assertion ceremonies (policy updates) with the software authenticator. A
# fresh-root launch on A's occupied port must fail on the occupied
# listener; stopping A through its own launcher handle must leave B able
# to complete a fresh ceremony; restarting A on its stopped root must
# restore an enrollment that can complete a fresh ceremony.
#
# This needs no funded wallet, mainnet transaction, or RPC-provider
# acceptance test: the local anvil chain exists only so the Machine config
# mirrors the proven import-transfer setup; nothing is funded or broadcast.
#
# Linux-only: the collision assertion reads the contender's socket-unit
# bind-conflict evidence from the user journal.
#
# Binaries are selected explicitly so the exact files under test stay in
# the record (no sibling discovery):
#   BLOOM_INTEGRATION_MACHINE_BIN / BLOOM_INTEGRATION_BROKER_BIN /
#   BLOOM_INTEGRATION_SIGNER_BIN / BLOOM_INTEGRATION_DEBUG_DRIVER_BIN
# The launcher under test defaults to this checkout's script (override with
# BLOOM_TRIAD_DEV_LAUNCHER). Candidate ports default to 28735/28736 and
# must be distinct and never 18734. A sanitized transcript (ceremony URLs
# redacted) is written when BLOOM_TRIAD_CONCURRENCY_TRANSCRIPT names a
# file outside the disposable run directory.
#
# Evidence hygiene: ceremony URLs and driver output carry session tokens.
# Progress lines never contain them; every other output passes through the
# redactor before reaching the console transcript or the retained log.
set -euo pipefail

[ "$(uname -s)" = "Linux" ] || { printf 'ceremony-port concurrency: Linux with a systemd user manager is required\n' >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
broker_repo="${BLOOM_INTEGRATION_BROKER_REPO:-${repo_root}/../bloom-broker}"
signer_repo="${BLOOM_INTEGRATION_SIGNER_REPO:-${repo_root}/../bloom-signer}"
launcher="${BLOOM_TRIAD_DEV_LAUNCHER:-${repo_root}/scripts/triad-dev-launch.sh}"
bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-${repo_root}/target/debug/bloom}"
broker_bin="${BLOOM_INTEGRATION_BROKER_BIN:-${broker_repo}/target/debug/bloom-broker}"
signer_bin="${BLOOM_INTEGRATION_SIGNER_BIN:-${signer_repo}/target/debug/bloom-signer}"
driver_bin="${BLOOM_INTEGRATION_DEBUG_DRIVER_BIN:-${broker_repo}/target/debug/bloom-broker-debug-driver}"
port_a="${BLOOM_TRIAD_CONCURRENCY_PORT_A:-28735}"
port_b="${BLOOM_TRIAD_CONCURRENCY_PORT_B:-28736}"
startup_timeout_secs="${BLOOM_INTEGRATION_STARTUP_TIMEOUT_SECS:-300}"
transcript="${BLOOM_TRIAD_CONCURRENCY_TRANSCRIPT:-}"

[ "$port_a" != "$port_b" ] || { printf 'ceremony-port concurrency: candidate ports must differ\n' >&2; exit 1; }
[ "$port_a" != "18734" ] && [ "$port_b" != "18734" ] || {
  printf 'ceremony-port concurrency: this acceptance script never takes the custody port 18734\n' >&2
  exit 1
}

redact() {
  sed -e 's|http://localhost:[0-9][0-9]*/ceremony/[^[:space:]"'"'"']*|http://localhost:PORT/ceremony/<token-redacted>|g' "$@"
}

say() {
  # Progress goes to stderr: several callers run inside command
  # substitution where stdout is reserved for captured values.
  printf 'ceremony-port concurrency: %s\n' "$*" >&2
  if [ -n "$transcript" ]; then
    printf 'ceremony-port concurrency: %s\n' "$*" | redact >> "$transcript"
  fi
}

die() {
  printf 'ceremony-port concurrency: %s\n' "$*" >&2
  if [ -n "$transcript" ]; then
    printf 'ceremony-port concurrency: %s\n' "$*" | redact >> "$transcript"
  fi
  exit 1
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v anvil >/dev/null 2>&1 || die "anvil (foundry) is required"
command -v cast >/dev/null 2>&1 || die "cast (foundry) is required"
command -v journalctl >/dev/null 2>&1 || die "journalctl (systemd user journal) is required"
[ -x "$launcher" ] || die "launcher is not executable: $launcher"
[ -x "$bloom_bin" ] || die "Machine binary is not executable: $bloom_bin"
[ -x "$broker_bin" ] || die "Broker binary is not executable: $broker_bin"
[ -x "$signer_bin" ] || die "Signer binary is not executable: $signer_bin"
[ -x "$driver_bin" ] || die "debug driver binary is not executable: $driver_bin"
if [ -n "$transcript" ]; then
  : > "$transcript" || die "transcript file is not writable: $transcript"
fi

# Throwaway determinism: the canonical all-abandon test mnemonic, never
# funded. Distinct authenticator seeds per candidate.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
RECIPIENT2="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

# Provenance: hashes identify the exact files under test; commits identify
# the sources to rebuild them from (plus the build commands). A checkout
# HEAD alone cannot prove which binary ran.
say "binaries under test (sha256 of each executable)"
for entry in "machine:$bloom_bin" "broker:$broker_bin" "signer:$signer_bin" "driver:$driver_bin"; do
  name="${entry%%:*}"; path="${entry#*:}"
  say "  $name $path sha256:$(sha256sum "$path" | awk '{print $1}')"
done
rev_of_bin() { git -C "$(dirname "$1")" rev-parse HEAD 2>/dev/null || printf 'unknown'; }
say "source checkout containing each binary (rebuild from these before running)"
say "  bloom $(rev_of_bin "$bloom_bin"): cargo build -p bloom --no-default-features --features mount,triad-dev-harness"
say "  broker $(rev_of_bin "$broker_bin"): cargo build -p bloom-broker --features triad-dev-harness; cargo build -p bloom-broker-debug-driver"
say "  signer $(rev_of_bin "$signer_bin"): cargo build -p bloom-signer --features triad-dev-harness"
say "ports A=$port_a B=$port_b (custody 18734 untouched)"

# Unix socket paths must stay under SUN_LEN (108 bytes), so the run root
# stays short under /tmp regardless of the caller's TMPDIR; unit paths must
# additionally use only ASCII letters, digits, and `_./:@+-`.
run_root="$(mktemp -d /tmp/bcp.XXXXXX)"

# Launchers are real children of this shell (never started inside command
# substitution), so wait(1) reaps them and cleanup can prove they stopped.
launcher_a_pid=""; launcher_b_pid=""; contender_pid=""
anvil_pid=""

cleanup() {
  status=$?
  trap - EXIT INT TERM
  unreaped=""
  for pid in $launcher_a_pid $launcher_b_pid $contender_pid; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      deadline=$(( $(date +%s) + 60 ))
      while kill -0 "$pid" 2>/dev/null; do
        [ "$(date +%s)" -lt "$deadline" ] || break
        sleep 0.5
      done
    fi
    wait "$pid" 2>/dev/null || true
    kill -0 "$pid" 2>/dev/null && unreaped="$unreaped $pid"
  done
  if [ -n "$anvil_pid" ] && kill -0 "$anvil_pid" 2>/dev/null; then
    kill "$anvil_pid" 2>/dev/null || true
    wait "$anvil_pid" 2>/dev/null || true
  fi
  if [ -n "$unreaped" ]; then
    status=1
    printf 'ceremony-port concurrency: cleanup FAILED, owned launchers still running:%s; diagnostics retained at: %s\n' "$unreaped" "$run_root" >&2
  fi
  if [ "$status" -eq 0 ] && [ -z "$unreaped" ]; then
    rm -rf -- "$run_root" 2>/dev/null || true
  else
    printf 'ceremony-port concurrency diagnostics retained at: %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

fail_with_log() {
  redact "$2" >&2
  if [ -n "$transcript" ]; then
    redact "$2" >> "$transcript"
  fi
  die "candidate $1 exited during startup"
}

# Launch in the parent shell and assign the child PID to the named variable.
launch_candidate() {
  outvar="$1"; label="$2"; port="$3"; root="$4"; socket="$5"; ready="$6"; log="$7"
  mkdir -p "$root/developer/machine-home" "$root/logs" "$(dirname "$socket")"
  # shellcheck disable=SC2086
  BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
  BLOOM_INTEGRATION_MACHINE_BIN="$bloom_bin" \
  BLOOM_INTEGRATION_BROKER_BIN="$broker_bin" \
  BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin" \
    "$launcher" \
      --developer-root "$root/developer" \
      --machine-home "$root/developer/machine-home" \
      --machine-socket "$socket" \
      --log-dir "$root/logs" \
      --ready-file "$ready" \
      --ceremony-port "$port" >"$log" 2>&1 &
  pid=$!
  deadline=$(( $(date +%s) + startup_timeout_secs ))
  while [ ! -f "$ready" ]; do
    kill -0 "$pid" 2>/dev/null || fail_with_log "$label" "$log"
    [ "$(date +%s)" -lt "$deadline" ] || { fail_with_log "$label" "$log"; }
    sleep 0.5
  done
  printf -v "$outvar" '%s' "$pid"
}

# Launchers are real children here, so wait reaps and the stop is provable:
# SIGTERM, bounded patience for process exit and socket release, then reap.
stop_candidate() {
  pid="$1"; socket="$2"; label="$3"
  kill "$pid" 2>/dev/null || true
  deadline=$(( $(date +%s) + 60 ))
  while kill -0 "$pid" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || die "$label launcher did not exit after SIGTERM"
    sleep 0.2
  done
  deadline=$(( $(date +%s) + 60 ))
  while [ -e "$socket" ] || [ -L "$socket" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || die "$label socket still present after launcher exit: $socket"
    sleep 0.2
  done
  wait "$pid" 2>/dev/null || true
}

cli_for() {
  socket="$1"; home="$2"; shift 2
  BLOOM_RPC_ENDPOINT="unix:${socket}" BLOOM_HOME="$home" "$bloom_bin" --home "$home" "$@"
}

# Enroll a disposable wallet through the real ceremony. Prints only the
# wallet ID on stdout; progress goes through say().
enroll_wallet() {
  label="$1"; socket="$2"; home="$3"; wallet="$4"; seed="$5"; expect_port="$6"
  mnemonic_file="$run_root/$label-mnemonic.txt"
  printf '%s\n' "$MNEMONIC" > "$mnemonic_file"
  chmod 0600 "$mnemonic_file"
  import_launch="$(cli_for "$socket" "$home" wallet import "$wallet")"
  import_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$import_url" ] || die "$label: wallet import omitted its ceremony URL"
  case "$import_url" in
    "http://localhost:${expect_port}/ceremony/"*)
      say "$label enrollment ceremony on :$expect_port" ;;
    *) die "$label: enrollment ceremony not on :$expect_port" ;;
  esac
  import_result="$("$driver_bin" complete "$import_url" "$seed" --sign-count 1 --mnemonic-file "$mnemonic_file")"
  wallet_id="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
  accounts="$(cli_for "$socket" "$home" wallet accounts "$wallet_id")"
  [ "$(printf '%s' "$accounts" | jq '.accounts | length')" = "2" ] ||
    die "$label: fresh import must project exactly two accounts"
  printf '%s' "$wallet_id"
}

# Complete one policy-update assertion ceremony with an actual policy
# change (allow or remove a destination) at an advancing sign count, then
# commit and verify the projection. Prints nothing on stdout.
policy_change() {
  label="$1"; socket="$2"; home="$3"; wallet_id="$4"; seed="$5"
  sign_count="$6"; operation="$7"; address="$8"; expect_port="$9"
  current_policy="$(cli_for "$socket" "$home" vfs cat "/wallets/${wallet_id}/policy.json")"
  policy_file="$run_root/$label-policy-$sign_count.json"
  if [ "$operation" = "allow" ]; then
    printf '%s' "$current_policy" | jq -cS \
      --arg chain "anvil" --arg dest "$address" \
      '.allowed_destinations = ((.allowed_destinations // []) + [{chain:$chain, destination:$dest}] | unique | sort)' \
      > "$policy_file"
  else
    printf '%s' "$current_policy" | jq -cS \
      --arg dest "$address" \
      '.allowed_destinations = ((.allowed_destinations // []) | map(select(.destination != $dest)))' \
      > "$policy_file"
  fi
  policy_launch="$(cli_for "$socket" "$home" wallet update-policy "$wallet_id" --file "$policy_file" 2>&1)" ||
    die "$label: policy update launch failed"
  policy_url="$(printf '%s\n' "$policy_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$policy_url" ] || die "$label: policy update omitted its ceremony URL"
  case "$policy_url" in
    "http://localhost:${expect_port}/ceremony/"*) ;;
    *) die "$label: assertion ceremony not on :$expect_port" ;;
  esac
  "$driver_bin" complete "$policy_url" "$seed" --sign-count "$sign_count" >/dev/null ||
    die "$label: completing the policy-update ceremony failed"
  operation_id="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
  cli_for "$socket" "$home" wallet commit-policy "$operation_id" >/dev/null ||
    die "$label: policy commit failed"
  updated="$(cli_for "$socket" "$home" vfs cat "/wallets/${wallet_id}/policy.json")"
  if [ "$operation" = "allow" ]; then
    printf '%s' "$updated" | jq -e --arg dest "$address" \
      'any(.allowed_destinations[]; .destination == $dest)' >/dev/null ||
      die "$label: committed policy lacks the allowlisted destination"
  else
    printf '%s' "$updated" | jq -e --arg dest "$address" \
      'all(.allowed_destinations[]; .destination != $dest)' >/dev/null ||
      die "$label: committed policy still lists the removed destination"
  fi
  say "$label assertion ceremony (sign-count $sign_count, $operation destination) committed on :$expect_port"
}

usable() {
  cli_for "$2" "$3" wallet accounts "$4" >/dev/null ||
    die "$1: enrolled wallet not readable"
}

# Local chain only so the Machine config mirrors the proven setup.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
anvil_port="$(free_port)"
anvil --port "$anvil_port" --host 127.0.0.1 --chain-id 31337 >"$run_root/anvil.log" 2>&1 &
anvil_pid=$!
attempts=0
while ! cast block-number --rpc-url "http://127.0.0.1:${anvil_port}" >/dev/null 2>&1; do
  kill -0 "$anvil_pid" 2>/dev/null || die "anvil exited before RPC became ready"
  attempts=$((attempts + 1))
  [ "$attempts" -lt 100 ] || die "anvil RPC did not become ready"
  sleep 0.1
done
nfs_port="$(free_port)"
machine_config="$run_root/machine-config.toml"
{
  printf 'default_chain = "anvil"\n'
  printf 'nfs_listen_addr = "127.0.0.1:%s"\n' "$nfs_port"
  printf '\n[chains.anvil]\n'
  printf 'name = "anvil"\n'
  printf 'chain_id = 31337\n'
  printf 'rpc_urls = ["http://127.0.0.1:%s"]\n' "$anvil_port"
  printf 'rpc_endpoints = []\n'
  printf 'display_name = "Anvil (local)"\n'
  printf 'native_symbol = "ETH"\n'
  printf 'native_decimals = 18\n'
  printf 'legacy_tx = false\n'
  printf 'op_stack = false\n'
} > "$machine_config"
chmod 0600 "$machine_config"

# A and B up together as real children of this shell.
a_root="$run_root/a"; a_socket="$run_root/a/run/machine.sock"; a_ready="$run_root/a/run/ready"
b_root="$run_root/b"; b_socket="$run_root/b/run/machine.sock"; b_ready="$run_root/b/run/ready"
launch_candidate launcher_a_pid A "$port_a" "$a_root" "$a_socket" "$a_ready" "$run_root/a-launcher.log"
launch_candidate launcher_b_pid B "$port_b" "$b_root" "$b_socket" "$b_ready" "$run_root/b-launcher.log"
say "A (:$port_a) and B (:$port_b) ready"

wallet_a="$(enroll_wallet A "$a_socket" "$a_root/developer/machine-home" concurrency-a concurrency-a-auth "$port_a")"
policy_change A "$a_socket" "$a_root/developer/machine-home" "$wallet_a" concurrency-a-auth 3 allow "$RECIPIENT" "$port_a"
wallet_b="$(enroll_wallet B "$b_socket" "$b_root/developer/machine-home" concurrency-b concurrency-b-auth "$port_b")"
policy_change B "$b_socket" "$b_root/developer/machine-home" "$wallet_b" concurrency-b-auth 3 allow "$RECIPIENT" "$port_b"
say "A wallet $wallet_a and B wallet $wallet_b enrolled with assertion ceremonies"

# A fresh root on A's occupied port must fail on the occupied listener: run
# the contender as a tracked child with the same Machine config, fail at
# once if it ever becomes ready, and require its own socket units to report
# the address-in-use conflict on A's port.
collide_root="$run_root/collide"
mkdir -p "$collide_root/developer/machine-home" "$collide_root/logs" "$collide_root/run"
contender_start="$(date '+%Y-%m-%d %H:%M:%S')"
BLOOM_TRIAD_DEV_MACHINE_CONFIG="$machine_config" \
BLOOM_INTEGRATION_MACHINE_BIN="$bloom_bin" \
BLOOM_INTEGRATION_BROKER_BIN="$broker_bin" \
BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin" \
  "$launcher" \
    --developer-root "$collide_root/developer" \
    --machine-home "$collide_root/developer/machine-home" \
    --machine-socket "$collide_root/run/machine.sock" \
    --log-dir "$collide_root/logs" \
    --ready-file "$collide_root/run/ready" \
    --ceremony-port "$port_a" >"$run_root/collide.log" 2>&1 &
contender_pid=$!
deadline=$(( $(date +%s) + 120 ))
while kill -0 "$contender_pid" 2>/dev/null; do
  [ ! -f "$collide_root/run/ready" ] ||
    { kill "$contender_pid" 2>/dev/null || true; wait "$contender_pid" 2>/dev/null || true; contender_pid=""; die "colliding launch on :$port_a unexpectedly became ready"; }
  [ "$(date +%s)" -lt "$deadline" ] || {
    kill "$contender_pid" 2>/dev/null || true
    wait "$contender_pid" 2>/dev/null || true; contender_pid=""
    die "colliding launch on :$port_a still running after the deadline"
  }
  sleep 0.5
done
contender_status=0
wait "$contender_pid" 2>/dev/null || contender_status=$?
contender_pid=""
[ "$contender_status" -ne 0 ] || die "fresh-root launch on occupied port :$port_a unexpectedly succeeded"
# The contender's own cleanup removes its runtime directory, so attribute
# by journal instead: our UID-scoped unit names reporting address-in-use on
# A's port since the contender started, excluding A/B's own live runtimes.
set -- "$a_root"/developer/runtime.* "$b_root"/developer/runtime.*
known_tokens=""
for candidate_runtime in "$@"; do
  [ -d "$candidate_runtime" ] || die "live candidate runtime missing: $candidate_runtime"
  known_tokens="$known_tokens $(basename "$candidate_runtime")"
done
conflict="$(journalctl --user --since "$contender_start" 2>/dev/null)"
for token in $known_tokens; do
  conflict="$(printf '%s\n' "$conflict" | grep -vF "$token")"
done
printf '%s\n' "$conflict" | grep -F "bloom-triad-dev-$(id -u)-" | grep -F "Address already in use" | grep -F ":$port_a" >/dev/null ||
  die "colliding launch failed without the expected bind conflict on :$port_a"
say "colliding launch on :$port_a failed on the occupied listener as required"
usable A "$a_socket" "$a_root/developer/machine-home" "$wallet_a"
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
policy_change A "$a_socket" "$a_root/developer/machine-home" "$wallet_a" concurrency-a-auth 5 allow "$RECIPIENT2" "$port_a"
say "A and B usable after the collision, with a fresh A ceremony"

# Stop A through its own launcher handle; B must complete a fresh ceremony
# while A is down.
stop_candidate "$launcher_a_pid" "$a_socket" A
launcher_a_pid=""
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
policy_change B "$b_socket" "$b_root/developer/machine-home" "$wallet_b" concurrency-b-auth 5 allow "$RECIPIENT2" "$port_b"
say "B completed a fresh ceremony while A was stopped"

# Restart A on its stopped root and port; its enrollment must persist and
# complete a fresh ceremony, and B must stay usable.
launch_candidate launcher_a_pid A "$port_a" "$a_root" "$a_socket" "$a_ready" "$run_root/a2-launcher.log"
usable A "$a_socket" "$a_root/developer/machine-home" "$wallet_a"
policy_change A "$a_socket" "$a_root/developer/machine-home" "$wallet_a" concurrency-a-auth 7 remove "$RECIPIENT2" "$port_a"
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
say "A restarted on :$port_a with enrollment intact and a fresh ceremony; B still usable"

say "PASS ports A=$port_a B=$port_b custody=18734"
