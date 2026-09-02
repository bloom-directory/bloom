#!/usr/bin/env bash
set -uo pipefail

# Container-side cleanup for this task cancels staged-but-unbroadcast entries
# and nothing else. Unlike the Hyperliquid task there is no post-broadcast undo
# to delegate here: a settled transfer can only be reversed by another transfer,
# and only the host holds the destination key. Giving the container a path that
# moves funds would defeat the bound this eval rests on.

mkdir -p /logs/verifier
reward=0
cleanup_status=0

outbox="/bloom/wallets/${BLOOM_EVAL_SOLANA_WALLET_ID}/chains/${BLOOM_EVAL_SOLANA_CHAIN}/outbox"

cleanup() {
  # Cancel every entry still pending. `cancel` is a control write on a staged
  # entry; it cannot move funds and is safe to repeat.
  local id
  for id in $(timeout 30 ls -1 "${outbox}/pending" 2>/dev/null); do
    timeout 30 bash -c 'printf %s cleanup > "$1"' _ "${outbox}/pending/${id}/cancel" \
      >/dev/null 2>&1 || cleanup_status=1
  done
  # Require the pending directory to drain. A residual staged entry holds a
  # blockhash that could still be broadcast later, so it is not an acceptable
  # end state even when the trial otherwise passed.
  if ! timeout 60 bash -c '
    until [ -z "$(ls -A "$1" 2>/dev/null)" ]; do
      sleep 2
    done
  ' _ "${outbox}/pending"; then
    cleanup_status=1
  fi
}
trap cleanup EXIT

# The agent is not told about evaluation artifacts. Grade only independent VFS
# and chain state: no pending action may remain, and the fresh destination must
# have received the exact finalized transfer.
if [ -z "$(timeout 30 ls -A "${outbox}/pending" 2>/dev/null)" ] && \
    python3 /tests/verify_result.py; then
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
  printf '%s\n' 'Bloom Solana on-chain transfer evidence passed.'
  exit 0
fi
exit 1
