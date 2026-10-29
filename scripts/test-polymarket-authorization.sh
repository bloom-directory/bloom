#!/usr/bin/env bash
# Real installed-component authorization with a disposable software owner.
# Retain temporary files for diagnosis without recursive cleanup.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
run_root="${1:?usage: test-polymarket-authorization.sh FRESH_EMPTY_RUN_ROOT}"
case "${2:-login}" in
  login) test_name=installed_account_one_auth_and_exact_continuation_use_real_authority ;;
  prepared-buy) test_name=prepared_buy_uses_real_bounded_permission ;;
  *) echo "Expected login or prepared-buy" >&2; exit 1 ;;
esac
[[ "$run_root" == /tmp/pm80-auth.* ]] || { echo 'Expected a fresh /tmp/pm80-auth.* root' >&2; exit 1; }
[ -d "$run_root" ] && [ ! -L "$run_root" ] || exit 1
[ -z "$(find "$run_root" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo 'Run root must be empty' >&2; exit 1; }
for variable in BLOOM_INTEGRATION_MACHINE_BIN BLOOM_INTEGRATION_BROKER_BIN BLOOM_INTEGRATION_SIGNER_BIN BLOOM_INTEGRATION_DEBUG_DRIVER_BIN; do
  [ -x "${!variable:?set exact candidate binaries}" ] || exit 1
done
[ -d "${BLOOM_PM80_POLYMARKET_ROOT:?set the built source package}" ] || exit 1
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
cat > "$run_root/machine.toml" <<'EOF'
default_chain = "polygon"
[chains.polygon]
name = "polygon"
chain_id = 137
rpc_urls = ["http://127.0.0.1:1"]
allow_broadcast = false
EOF
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > "$run_root/disposable-mnemonic.txt"
export BLOOM_PM80_MNEMONIC_FILE="$run_root/disposable-mnemonic.txt"
export BLOOM_PM80_AUTHORIZATION_RESULT="$run_root/authorization-result.json"
export BLOOM_TRIAD_DEV_MACHINE_CONFIG="$run_root/machine.toml"
export BLOOM_TRIAD_DEV_BUILD_PETALS=0 BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=0
# Reuse the launcher's existing source-package installer enrollment hook. Its
# historical variable name does not constrain the generated package's name.
export BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE="$BLOOM_PM80_POLYMARKET_ROOT"
launcher_pid=""
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid"
    wait "$launcher_pid" || true
  fi
  printf 'Disposable authorization evidence retained at %s\n' "$run_root"
  exit "$status"
}
trap cleanup EXIT INT TERM
ceremony_port="$(free_port)"
remote_upstream_port="$(free_port)"
start_services() {
  bash "$repo_root/scripts/triad-dev-launch.sh" --services-only --retain-temporary-files \
    --developer-root "$run_root" --machine-socket "$run_root/m.sock" \
    --log-dir "$run_root/logs" --ready-file "$run_root/ready" \
    --ceremony-port "$ceremony_port" --remote-upstream-port "$remote_upstream_port" \
    >> "$run_root/launcher.log" 2>&1 &
  launcher_pid=$!
  for attempt in $(seq 1 900); do
    [ ! -f "$run_root/ready" ] || break
    kill -0 "$launcher_pid" 2>/dev/null || { echo "Launcher failed; inspect $run_root/launcher.log" >&2; exit 1; }
    sleep 0.1
  done
  [ -f "$run_root/ready" ] || { echo 'Launcher readiness timed out' >&2; exit 1; }
  source "$run_root/logs/triad.env"
}
run_test() {
  cargo test --locked -p bloom-daemon --features triad-dev-harness --lib \
    "polymarket_authorization::$test_name" -- --ignored --exact
}
cd "$repo_root"
start_services
if [ "$test_name" = prepared_buy_uses_real_bounded_permission ]; then
  export BLOOM_PM80_BUY_PHASE=first
  run_test
  kill "$launcher_pid"
  wait "$launcher_pid" || true
  launcher_pid=""
  start_services
  export BLOOM_PM80_BUY_PHASE=restart
  run_test
else
  run_test
fi
