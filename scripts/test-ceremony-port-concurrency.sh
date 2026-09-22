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
# BLOOM_TRIAD_DEV_LAUNCHER). Candidate ports default to 28735/28736; they
# are normalized to canonical decimal, then required to differ and to avoid
# 18734. Shutdown patience is BLOOM_TRIAD_CONCURRENCY_STOP_TIMEOUT_SECS
# (default 60). A sanitized transcript (ceremony URLs redacted) is written
# when BLOOM_TRIAD_CONCURRENCY_TRANSCRIPT names a file outside the
# disposable run directory.
#
# Evidence hygiene: ceremony URLs and driver output carry session tokens.
# Progress lines never contain them; every other output passes through the
# redactor before reaching the console transcript or the retained log.
#
# Failure-mode coverage for this script's own process handling and port
# validation lives in scripts/test-ceremony-port-concurrency-cases.sh,
# which sources this file (set BLOOM_CONCURRENCY_SOURCED=1 to skip main).
set -euo pipefail

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
stop_timeout_secs="${BLOOM_TRIAD_CONCURRENCY_STOP_TIMEOUT_SECS:-60}"
contender_deadline_secs="${BLOOM_TRIAD_CONCURRENCY_CONTENDER_DEADLINE_SECS:-120}"
transcript="${BLOOM_TRIAD_CONCURRENCY_TRANSCRIPT:-}"

# Throwaway determinism: the canonical all-abandon test mnemonic, never
# funded. Distinct authenticator seeds per candidate.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
RECIPIENT2="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

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

# Print the canonical decimal for digit input, rejecting anything else.
# Callers compare and select on the canonical form, so spellings like
# 018734 or 028735 cannot slip past the custody and distinctness guards
# the way raw-string comparison would allow.
normalize_port() {
  raw=$1
  case "$raw" in ''|*[!0-9]*) return 1 ;; esac
  stripped=$raw
  while [ -n "$stripped" ] && [ "${stripped#0}" != "$stripped" ]; do
    stripped=${stripped#0}
  done
  [ -n "$stripped" ] || stripped=0
  [ "${#stripped}" -le 5 ] || return 1
  value=$((10#$stripped))
  [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || return 1
  printf '%s' "$value"
}

check_ports() {
  # Explicit returns after die keep in-process callers (see the cases
  # script) honest; with the real die they are unreachable.
  norm_a="$(normalize_port "$port_a")" || { die "candidate A port must be an integer 1 through 65535"; return $?; }
  norm_b="$(normalize_port "$port_b")" || { die "candidate B port must be an integer 1 through 65535"; return $?; }
  port_a=$norm_a; port_b=$norm_b
  [ "$port_a" != "$port_b" ] || { die "candidate ports must differ (after normalization)"; return $?; }
  [ "$port_a" != "18734" ] && [ "$port_b" != "18734" ] ||
    { die "this acceptance script never takes the custody port 18734"; return $?; }
}

# Wait up to secs for pid to exit, then reap it. Returns 0 when the exit
# was established and reaped, 1 when the child is still alive: callers
# must report failure instead of blocking on a live child.
wait_pid() {
  pid="$1"; secs="$2"
  deadline=$(( $(date +%s) + secs ))
  while kill -0 "$pid" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 0.2
  done
  wait "$pid" 2>/dev/null || true
  return 0
}

# Launchers are real children of this shell (never started inside command
# substitution), so wait(1) reaps them and cleanup can prove they stopped.
# Initialized in main; the EXIT trap owns whatever is still set.
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
      wait_pid "$pid" "$stop_timeout_secs" || unreaped="$unreaped $pid"
    else
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ -n "$anvil_pid" ]; then
    if kill -0 "$anvil_pid" 2>/dev/null; then
      kill "$anvil_pid" 2>/dev/null || true
      wait_pid "$anvil_pid" "$stop_timeout_secs" || unreaped="$unreaped anvil($anvil_pid)"
    else
      wait "$anvil_pid" 2>/dev/null || true
    fi
  fi
  if [ -n "$unreaped" ]; then
    status=1
    printf 'ceremony-port concurrency: cleanup FAILED, owned processes still running:%s; diagnostics retained at: %s\n' "$unreaped" "$run_root" >&2
  fi
  if [ "$status" -eq 0 ] && [ -z "$unreaped" ]; then
    rm -rf -- "$run_root" 2>/dev/null || true
  else
    printf 'ceremony-port concurrency diagnostics retained at: %s\n' "$run_root" >&2
  fi
  exit "$status"
}

fail_with_log() {
  redact "$2" >&2
  if [ -n "$transcript" ]; then
    redact "$2" >> "$transcript"
  fi
  die "candidate $1 exited during startup"
}

# Launch in the parent shell and assign the child PID to the named variable
# immediately, before the readiness loop: a startup failure must still
# leave the live child discoverable for cleanup.
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
  printf -v "$outvar" '%s' "$pid"
  deadline=$(( $(date +%s) + startup_timeout_secs ))
  while [ ! -f "$ready" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      fail_with_log "$label" "$log"; return $?
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail_with_log "$label" "$log"; return $?
    fi
    sleep 0.5
  done
}

# SIGTERM, bounded patience for process exit and socket release, then reap.
# Fails (retaining diagnostics) instead of blocking on a live child.
stop_candidate() {
  pid="$1"; socket="$2"; label="$3"
  kill "$pid" 2>/dev/null || true
  wait_pid "$pid" "$stop_timeout_secs" || { die "$label launcher still alive after SIGTERM"; return $?; }
  deadline=$(( $(date +%s) + stop_timeout_secs ))
  while [ -e "$socket" ] || [ -L "$socket" ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      die "$label socket still present after launcher exit: $socket"; return $?
    fi
    sleep 0.2
  done
  say "$label launcher stopped"
}

stop_anvil() {
  [ -n "$anvil_pid" ] || return 0
  kill "$anvil_pid" 2>/dev/null || true
  wait_pid "$anvil_pid" "$stop_timeout_secs" || { die "anvil still alive after SIGTERM"; return $?; }
  anvil_pid=""
}

# True when one exact socket unit journals the bind conflict on the port.
unit_shows_conflict() {
  journalctl --user -u "$1" --since "$3" 2>/dev/null |
    grep -F "Address already in use" | grep -F ":$2" >/dev/null
}

# Require the contender's exact socket units (one runtime token, both
# families) to journal the bind conflict on the expected port. Both units
# must show it: the retry loop only stops early when the pair is complete.
require_contender_conflict() {
  token=$1; port=$2; since=$3
  prefix="bloom-triad-dev-$(id -u)-$token"
  v4=$prefix-broker-ceremony-ipv4.socket
  v6=$prefix-broker-ceremony-ipv6.socket
  attempt=0
  while [ "$attempt" -lt 3 ]; do
    if unit_shows_conflict "$v4" "$port" "$since"; then v4ok=1; else v4ok=0; fi
    if unit_shows_conflict "$v6" "$port" "$since"; then v6ok=1; else v6ok=0; fi
    if [ "$v4ok" -eq 1 ] && [ "$v6ok" -eq 1 ]; then
      say "colliding launch on :$port failed on its own units $v4 $v6 (address in use) as required"
      return 0
    fi
    sleep 2; attempt=$((attempt + 1))
  done
  die "contender units $v4 $v6 lack journaled bind conflicts on :$port"; return $?
}

# Launch the colliding contender, supervise it with a deadline, and prove
# the failure is the occupied listener on A's port. The contender PID is
# cleared only after reaping the expected failure; abnormal paths keep it
# set so EXIT cleanup retries it bounded and reports leftovers.
run_contender() {
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
  contender_token=""
  deadline=$(( $(date +%s) + contender_deadline_secs ))
  while kill -0 "$contender_pid" 2>/dev/null; do
    # Capture the runtime token while the contender is alive: its own
    # cleanup deletes the directory on exit, so this observation is the
    # ownership record the journal queries below are checked against.
    if [ -z "$contender_token" ]; then
      for runtime_dir in "$collide_root"/developer/runtime.*; do
        [ -d "$runtime_dir" ] || continue
        contender_token=$(basename "$runtime_dir")
        break
      done
    fi
    if [ -f "$collide_root/run/ready" ]; then
      kill "$contender_pid" 2>/dev/null || true
      if wait_pid "$contender_pid" "$stop_timeout_secs"; then contender_pid=""; fi
      die "colliding launch on :$port_a unexpectedly became ready"; return $?
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      kill "$contender_pid" 2>/dev/null || true
      if wait_pid "$contender_pid" "$stop_timeout_secs"; then contender_pid=""; fi
      die "colliding launch on :$port_a still running after the deadline"; return $?
    fi
    sleep 0.5
  done
  contender_status=0
  wait "$contender_pid" 2>/dev/null || contender_status=$?
  contender_pid=""
  [ "$contender_status" -ne 0 ] || { die "fresh-root launch on occupied port :$port_a unexpectedly succeeded"; return $?; }
  [ -n "$contender_token" ] || die "never observed the contender runtime directory; cannot attribute units"
  require_contender_conflict "$contender_token" "$port_a" "$contender_start" || return $?
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

rev_of_bin() { git -C "$(dirname "$1")" rev-parse HEAD 2>/dev/null || printf 'unknown'; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

main() {
  [ "$(uname -s)" = "Linux" ] || die "Linux with a systemd user manager is required"
  check_ports

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

  # Provenance: hashes identify the exact files under test; commits identify
  # the sources to rebuild them from (plus the build commands). A checkout
  # HEAD alone cannot prove which binary ran.
  say "binaries under test (sha256 of each executable)"
  for entry in "machine:$bloom_bin" "broker:$broker_bin" "signer:$signer_bin" "driver:$driver_bin"; do
    name="${entry%%:*}"; path="${entry#*:}"
    say "  $name $path sha256:$(sha256sum "$path" | awk '{print $1}')"
  done
  say "source checkout containing each binary (rebuild from these before running)"
  say "  bloom $(rev_of_bin "$bloom_bin"): cargo build -p bloom --no-default-features --features mount,triad-dev-harness"
  say "  broker $(rev_of_bin "$broker_bin"): cargo build -p bloom-broker --features triad-dev-harness; cargo build -p bloom-broker-debug-driver"
  say "  signer $(rev_of_bin "$signer_bin"): cargo build -p bloom-signer --features triad-dev-harness"
  say "ports A=$port_a B=$port_b (custody 18734 untouched)"

  # Unix socket paths must stay under SUN_LEN (108 bytes), so the run root
  # stays short under /tmp regardless of the caller's TMPDIR; unit paths
  # must additionally use only ASCII letters, digits, and `_./:@+-`.
  run_root="$(mktemp -d /tmp/bcp.XXXXXX)"
  trap cleanup EXIT INT TERM

  # Local chain only so the Machine config mirrors the proven setup.
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

  # A fresh root on A's occupied port must fail on the occupied listener.
  run_contender
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

  # Shut everything down provably before claiming success: each stop fails
  # instead of blocking, so PASS is only printed after cleanup succeeded.
  stop_candidate "$launcher_a_pid" "$a_socket" "A (restarted)"
  launcher_a_pid=""
  stop_candidate "$launcher_b_pid" "$b_socket" B
  launcher_b_pid=""
  stop_anvil
  rm -rf -- "$run_root" || die "run directory removal failed: $run_root"
  say "PASS ports A=$port_a B=$port_b custody=18734"
}

if [ "${BLOOM_CONCURRENCY_SOURCED:-0}" != "1" ]; then
  main "$@"
fi
