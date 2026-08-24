#!/usr/bin/env bash
set -uo pipefail

mkdir -p /logs/verifier
reward=0
cleanup_status=0

cleanup() {
  local base="/bloom/petals/hyperliquid/mainnet/agent_sessions/${BLOOM_EVAL_WALLET_ID}/${BLOOM_EVAL_SESSION_ID}"
  local open_orders="/bloom/petals/hyperliquid/mainnet/users/${BLOOM_EVAL_WALLET}/open_orders.json"
  if [ -e "${base}/cancel_all" ] && ! { [ -s "${base}/status.json" ] && jq -e '.stopped == true' "${base}/status.json" >/dev/null 2>&1; }; then
    timeout 30 bash -c 'printf %s cleanup > "$1"' _ "${base}/cancel_all" >/dev/null 2>&1 || cleanup_status=1
  fi
  if ! timeout 30 bash -c '
    until jq -e '\''type == "array" and length == 0'\'' "$1" >/dev/null 2>&1; do
      sleep 1
    done
  ' _ "$open_orders"; then
    cleanup_status=1
  fi
}
trap cleanup EXIT

# The Python verifier queries Hyperliquid's public orderStatus endpoint by the
# host-generated CLOID and again by the returned venue order id. The report is
# only a claimed transcript; it is not evidence that an order rested or was
# canceled.
if python3 /tests/verify_result.py /logs/artifacts/result.json; then
  reward=1
fi

cleanup
trap - EXIT
if [ "$cleanup_status" -ne 0 ]; then
  printf '%s\n' 'Verifier cleanup failed; forcing reward to zero.' >&2
  reward=0
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
if [ "$reward" -eq 1 ]; then
  printf '%s\n' 'Bloom Hyperliquid result and venue order evidence passed.'
  exit 0
fi
exit 1
