#!/usr/bin/env bash
set -uo pipefail

# Grade independent VFS and finalized chain state before host teardown.

mkdir -p /logs/verifier
reward=0

# Chain views live under the numbered account directory the harness resolved.
outbox="/bloom/wallets/${BLOOM_EVAL_SOLANA_WALLET_ID}/${BLOOM_EVAL_SOLANA_ACCOUNT}/chains/${BLOOM_EVAL_SOLANA_CHAIN}/outbox"

# A failed listing is not evidence that pending is empty.
if pending="$(timeout 30 ls -A "${outbox}/pending" 2>/dev/null)"; then
  if [ -z "$pending" ] && python3 /tests/verify_result.py; then
    reward=1
  fi
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
if [ "$reward" -eq 1 ]; then
  printf '%s\n' 'Bloom Solana on-chain transfer evidence passed.'
  exit 0
fi
exit 1
