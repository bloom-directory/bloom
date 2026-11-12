#!/usr/bin/env bash
# Broker's fee verdict for the catalogued builder-order class, against real
# installed components and a disposable software owner.
#
# No funded wallet, no mainnet transaction and no RPC node: the chain entry is
# dormant with broadcast disabled. The two refusals land when Broker evaluates
# the claim, before a signature exists; the accepted case signs a four-byte
# payload that is not an order. Nothing is submitted anywhere.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
run_root="${1:?usage: test-hyperliquid-builder-fee.sh FRESH_EMPTY_RUN_ROOT}"
test_name=broker_judges_a_builder_order_fee_against_the_catalogued_asset
[ -d "$run_root" ] && [ ! -L "$run_root" ] || exit 1
[ -z "$(find "$run_root" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo 'Run root must be empty' >&2; exit 1; }
for variable in BLOOM_INTEGRATION_MACHINE_BIN BLOOM_INTEGRATION_BROKER_BIN \
                BLOOM_INTEGRATION_SIGNER_BIN BLOOM_INTEGRATION_DEBUG_DRIVER_BIN; do
  [ -x "${!variable:?set exact candidate binaries}" ] || exit 1
done
[ -d "${BLOOM_HLFEE_PETAL_ROOT:?set the built Hyperliquid package}" ] || exit 1
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
cat > "$run_root/machine.toml" <<'EOF'
default_chain = "hyperliquid"
[chains.hyperliquid]
name = "hyperliquid"
chain_id = 999
rpc_urls = ["http://127.0.0.1:1"]
allow_broadcast = false
EOF
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > "$run_root/disposable-mnemonic.txt"
export BLOOM_HLFEE_MNEMONIC_FILE="$run_root/disposable-mnemonic.txt"
export BLOOM_TRIAD_DEV_MACHINE_CONFIG="$run_root/machine.toml"
export BLOOM_TRIAD_DEV_BUILD_PETALS=0 BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE=0
export BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE="$BLOOM_HLFEE_PETAL_ROOT"
launcher_pid=""
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$launcher_pid" ] && kill -0 "$launcher_pid" 2>/dev/null; then
    kill "$launcher_pid"; wait "$launcher_pid" || true
  fi
  printf 'Disposable evidence retained at %s\n' "$run_root"
  exit "$status"
}
trap cleanup EXIT INT TERM
bash "$repo_root/scripts/triad-dev-launch.sh" --services-only --retain-temporary-files \
  --developer-root "$run_root" --machine-socket "$run_root/m.sock" \
  --log-dir "$run_root/logs" --ready-file "$run_root/ready" \
  --ceremony-port "$(free_port)" --remote-upstream-port "$(free_port)" \
  > "$run_root/launcher.log" 2>&1 &
launcher_pid=$!
for attempt in $(seq 1 1800); do
  [ ! -f "$run_root/ready" ] || break
  kill -0 "$launcher_pid" 2>/dev/null || { echo "Launcher failed; inspect $run_root/launcher.log" >&2; exit 1; }
  sleep 0.1
done
[ -f "$run_root/ready" ] || { echo 'Launcher readiness timed out' >&2; exit 1; }
source "$run_root/logs/triad.env"
cd "$repo_root"
cargo test -p bloom-daemon --features triad-dev-harness --lib \
  "hyperliquid_builder_fee::$test_name" -- --ignored --exact --nocapture
