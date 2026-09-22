#!/usr/bin/env bash
# Concurrency acceptance for independent ceremony ports: two complete
# development Triads (A on one port, B on another) run side by side while
# the installed custody Triad keeps 18734. Each candidate enrolls a
# disposable wallet through the real Broker-hosted ceremony and completes a
# subsequent assertion ceremony (policy update) with the software
# authenticator. A fresh-root launch on A's occupied port must fail without
# disturbing either Triad; stopping A through its own launcher handle must
# leave B usable; restarting A on its stopped root must restore its
# enrolled wallet.
#
# Binaries are selected explicitly so the exact revisions under test stay
# in the record (no sibling discovery):
#   BLOOM_INTEGRATION_MACHINE_BIN / BLOOM_INTEGRATION_BROKER_BIN /
#   BLOOM_INTEGRATION_SIGNER_BIN / BLOOM_INTEGRATION_DEBUG_DRIVER_BIN
# The launcher under test defaults to this checkout's script (override with
# BLOOM_TRIAD_DEV_LAUNCHER). Candidate ports default to 28735/28736.
# This needs no funded wallet, mainnet transaction, or RPC-provider
# acceptance test: the local anvil chain exists only so the Machine config
# mirrors the proven import-transfer setup; nothing is funded or broadcast.
#
# Evidence hygiene: ceremony URLs and driver output carry session tokens and
# are never printed; only wallet IDs, ports, revisions, and exit statuses
# reach the log.
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

die() { printf 'ceremony-port concurrency: %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v anvil >/dev/null 2>&1 || die "anvil (foundry) is required"
command -v cast >/dev/null 2>&1 || die "cast (foundry) is required"
[ -x "$launcher" ] || die "launcher is not executable: $launcher"
[ -x "$bloom_bin" ] || die "Machine binary is not executable: $bloom_bin"
[ -x "$broker_bin" ] || die "Broker binary is not executable: $broker_bin"
[ -x "$signer_bin" ] || die "Signer binary is not executable: $signer_bin"
[ -x "$driver_bin" ] || die "debug driver binary is not executable: $driver_bin"

# Throwaway determinism: the canonical all-abandon test mnemonic, never
# funded. Distinct authenticator seeds per candidate.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
RECIPIENT="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Unix socket paths must stay under SUN_LEN (108 bytes), so the run root
# stays short under /tmp regardless of the caller's TMPDIR; unit paths must
# additionally use only ASCII letters, digits, and `_./:@+-`.
run_root="$(mktemp -d /tmp/bcp.XXXXXX)"
launcher_a_pid=""; launcher_b_pid=""; launcher_a2_pid=""; anvil_pid=""
mkdir -p "$run_root/a" "$run_root/b" "$run_root/collide"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  # Kill by variable and by pidfile: a launch that dies inside command
  # substitution never assigns its variable, so the pidfile is the record
  # that prevents leaking a live launcher.
  for pid in $launcher_a_pid $launcher_b_pid $launcher_a2_pid \
      $(cat "$run_root/a/launcher.pid" "$run_root/b/launcher.pid" 2>/dev/null); do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ -n "$anvil_pid" ] && kill -0 "$anvil_pid" 2>/dev/null; then
    kill "$anvil_pid" 2>/dev/null || true
    wait "$anvil_pid" 2>/dev/null || true
  fi
  if [ "$status" -eq 0 ]; then
    rm -rf -- "$run_root" 2>/dev/null || true
  else
    printf 'ceremony-port concurrency diagnostics retained at: %s\n' "$run_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

rev_of_bin() { git -C "$(dirname "$1")" rev-parse HEAD 2>/dev/null || printf 'unknown'; }
printf 'ceremony-port concurrency: revisions (source of each binary under test)\n  bloom:  %s\n  broker: %s\n  signer: %s\n' \
  "$(rev_of_bin "$bloom_bin")" "$(rev_of_bin "$broker_bin")" "$(rev_of_bin "$signer_bin")"
printf 'ceremony-port concurrency: ports A=%s B=%s (custody 18734 untouched)\n' "$port_a" "$port_b"

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

# Each launcher runs in the background and signals its ready file. Client
# commands address a candidate by its own home and Machine socket, never by
# sourcing another candidate's triad.env.
launch_candidate() {
  name="$1"; port="$2"; root="$3"; socket="$4"; ready="$5"; log="$6"
  mkdir -p "$root/developer/machine-home" "$root/logs" "$(dirname "$socket")"
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
  launcher_pid=$!
  printf '%s' "$launcher_pid" > "$root/launcher.pid"
  deadline=$(( $(date +%s) + startup_timeout_secs ))
  while [ ! -f "$ready" ]; do
    kill -0 "$launcher_pid" 2>/dev/null || { cat "$log" >&2; die "candidate $name exited during startup"; }
    [ "$(date +%s)" -lt "$deadline" ] || { cat "$log" >&2; die "candidate $name did not become ready"; }
    sleep 0.5
  done
  printf '%s' "$launcher_pid"
}

cli_for() {
  socket="$1"; home="$2"; shift 2
  BLOOM_RPC_ENDPOINT="unix:${socket}" BLOOM_HOME="$home" "$bloom_bin" --home "$home" "$@"
}

enroll_and_assert() {
  label="$1"; socket="$2"; home="$3"; wallet="$4"; seed="$5"; expect_port="$6"
  mnemonic_file="$run_root/$label-mnemonic.txt"
  printf '%s\n' "$MNEMONIC" > "$mnemonic_file"
  chmod 0600 "$mnemonic_file"
  import_launch="$(cli_for "$socket" "$home" wallet import "$wallet")"
  import_url="$(printf '%s\n' "$import_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$import_url" ] || die "$label: wallet import omitted ceremony_url"
  case "$import_url" in
    "http://localhost:${expect_port}/ceremony/"*)
      printf 'ceremony-port concurrency: %s enrollment ceremony on :%s\n' "$label" "$expect_port" >&2 ;;
    *) die "$label: enrollment ceremony not on :$expect_port" ;;
  esac
  import_result="$("$driver_bin" complete "$import_url" "$seed" --sign-count 1 --mnemonic-file "$mnemonic_file")"
  wallet_id="$(printf '%s' "$import_result" | jq -er '.wallet_id')"
  accounts="$(cli_for "$socket" "$home" wallet accounts "$wallet_id")"
  [ "$(printf '%s' "$accounts" | jq '.accounts | length')" = "2" ] ||
    die "$label: fresh import must project exactly two accounts"
  current_policy="$(cli_for "$socket" "$home" vfs cat "/wallets/${wallet_id}/policy.json")"
  policy_file="$run_root/$label-policy.json"
  printf '%s' "$current_policy" | jq -cS \
    --arg chain "anvil" --arg dest "$RECIPIENT" \
    '.allowed_destinations = ((.allowed_destinations // []) + [{chain:$chain, destination:$dest}] | unique | sort)' \
    > "$policy_file"
  policy_launch="$(cli_for "$socket" "$home" wallet update-policy "$wallet_id" --file "$policy_file" 2>&1)" ||
    die "$label: policy update launch failed"
  policy_url="$(printf '%s\n' "$policy_launch" | sed -n 's/^ceremony_url: //p')"
  [ -n "$policy_url" ] || die "$label: policy update omitted ceremony_url"
  case "$policy_url" in
    "http://localhost:${expect_port}/ceremony/"*) ;;
    *) die "$label: assertion ceremony not on :$expect_port" ;;
  esac
  "$driver_bin" complete "$policy_url" "$seed" --sign-count 3 >/dev/null ||
    die "$label: completing the policy-update ceremony failed"
  operation="$(printf '%s\n' "$policy_launch" | sed -n 's/^operation_id: //p')"
  cli_for "$socket" "$home" wallet commit-policy "$operation" >/dev/null ||
    die "$label: policy commit failed"
  updated="$(cli_for "$socket" "$home" vfs cat "/wallets/${wallet_id}/policy.json")"
  printf '%s' "$updated" | jq -e --arg dest "$RECIPIENT" \
    'any(.allowed_destinations[]; .destination == $dest)' >/dev/null ||
    die "$label: committed policy lacks the allowlisted destination"
  printf 'ceremony-port concurrency: %s wallet %s enrolled + assertion ceremony committed\n' "$label" "$wallet_id" >&2
  printf '%s' "$wallet_id"
}

usable() {
  label="$1"; socket="$2"; home="$3"; wallet_id="$4"
  cli_for "$socket" "$home" wallet accounts "$wallet_id" >/dev/null ||
    die "$label: enrolled wallet not usable"
}

# A and B up together.
a_root="$run_root/a"; a_socket="$run_root/a/run/machine.sock"; a_ready="$run_root/a/run/ready"
b_root="$run_root/b"; b_socket="$run_root/b/run/machine.sock"; b_ready="$run_root/b/run/ready"
launcher_a_pid="$(launch_candidate A "$port_a" "$a_root" "$a_socket" "$a_ready" "$run_root/a-launcher.log")"
launcher_b_pid="$(launch_candidate B "$port_b" "$b_root" "$b_socket" "$b_ready" "$run_root/b-launcher.log")"
printf 'ceremony-port concurrency: A (:%s) and B (:%s) ready\n' "$port_a" "$port_b"

wallet_a="$(enroll_and_assert A "$a_socket" "$a_root/developer/machine-home" concurrency-a concurrency-a-auth "$port_a")"
wallet_b="$(enroll_and_assert B "$b_socket" "$b_root/developer/machine-home" concurrency-b concurrency-b-auth "$port_b")"

# A fresh root on A's occupied port must fail; both Triads stay usable.
collide_root="$run_root/collide"
mkdir -p "$collide_root/developer/machine-home" "$collide_root/logs" "$collide_root/run"
if BLOOM_INTEGRATION_MACHINE_BIN="$bloom_bin" \
   BLOOM_INTEGRATION_BROKER_BIN="$broker_bin" \
   BLOOM_INTEGRATION_SIGNER_BIN="$signer_bin" \
     "$launcher" \
       --developer-root "$collide_root/developer" \
       --machine-home "$collide_root/developer/machine-home" \
       --machine-socket "$collide_root/run/machine.sock" \
       --log-dir "$collide_root/logs" \
       --ready-file "$collide_root/run/ready" \
       --ceremony-port "$port_a" >"$run_root/collide.log" 2>&1; then
  die "fresh-root launch on occupied port :$port_a unexpectedly succeeded"
fi
printf 'ceremony-port concurrency: colliding launch on :%s failed as required\n' "$port_a"
usable A "$a_socket" "$a_root/developer/machine-home" "$wallet_a"
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
printf 'ceremony-port concurrency: A and B usable after the collision\n'

# Launchers start inside command substitution, so they are not children of
# this shell and `wait` cannot reap them: stop by PID and poll for process
# exit plus socket release before relaunching on the same root.
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
}

# Stop A through its own launcher handle; B must stay usable.
stop_candidate "$launcher_a_pid" "$a_socket" A
launcher_a_pid=""
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
printf 'ceremony-port concurrency: B usable after A stopped\n'

# Restart A on its stopped root and port; its enrollment must persist.
launcher_a2_pid="$(launch_candidate A "$port_a" "$a_root" "$a_socket" "$a_ready" "$run_root/a2-launcher.log")"
usable A "$a_socket" "$a_root/developer/machine-home" "$wallet_a"
usable B "$b_socket" "$b_root/developer/machine-home" "$wallet_b"
launcher_a_pid="$launcher_a2_pid"; launcher_a2_pid=""
printf 'ceremony-port concurrency: A restarted on :%s with enrollment intact; B still usable\n' "$port_a"

printf 'ceremony-port concurrency: PASS ports A=%s B=%s custody=18734\n' "$port_a" "$port_b"
