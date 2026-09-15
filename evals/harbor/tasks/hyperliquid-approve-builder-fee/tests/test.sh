#!/usr/bin/env bash
set -uo pipefail

mkdir -p /logs/verifier
reward=0

# The Python verifier queries Hyperliquid's public maxBuilderFee endpoint
# independently of the agent's report. Unlike hyperliquid-order-cancel, this
# action leaves no open order or position for the verifier to unwind — the
# one-time approval it grants is revoked by the host-side harness's own
# cleanup() after the Harbor job completes, using the same ceremony-driving
# path that granted it. Nothing here needs to tear down venue state.
if python3 /tests/verify_result.py /logs/artifacts/result.json; then
  reward=1
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
if [ "$reward" -eq 1 ]; then
  printf '%s\n' 'Bloom Hyperliquid builder-fee approval and venue evidence passed.'
  exit 0
fi
exit 1
