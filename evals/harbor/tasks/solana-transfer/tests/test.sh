#!/usr/bin/env bash
set -uo pipefail

# Grades the trial from independent VFS and chain state. The container never
# cleans up: the mount refuses `cancel` on outbox entries, a settled transfer
# can only be reversed by another transfer, and the host harness drains the
# outbox after grading.

mkdir -p /logs/verifier
reward=0

# Chain views live under the numbered account directory the harness resolved.
outbox="/bloom/wallets/${BLOOM_EVAL_SOLANA_WALLET_ID}/${BLOOM_EVAL_SOLANA_ACCOUNT}/chains/${BLOOM_EVAL_SOLANA_CHAIN}/outbox"

# The agent is not told about evaluation artifacts. No staged action may remain
# (it could still be broadcast later), a missing pending directory is a broken
# mount rather than a drained outbox, and the fresh destination must have
# received the exact finalized transfer.
if [ -d "${outbox}/pending" ] && \
    [ -z "$(timeout 30 ls -A "${outbox}/pending" 2>/dev/null)" ] && \
    python3 /tests/verify_result.py; then
  reward=1
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
if [ "$reward" -eq 1 ]; then
  printf '%s\n' 'Bloom Solana on-chain transfer evidence passed.'
  exit 0
fi
exit 1
