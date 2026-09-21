#!/usr/bin/env bash
set -uo pipefail

mkdir -p /logs/verifier
reward=0

# The report is a claimed transcript. The Python verifier reads the fork
# directly: the outer receipt, the Safe's own ExecutionSuccess event, the
# decoded execTransaction arguments, the recipient's balance delta and the Safe
# nonce. Nothing the agent writes is accepted as evidence of settlement.
if python3 /tests/verify_result.py /logs/artifacts/result.json; then
  reward=1
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
if [ "$reward" -eq 1 ]; then
  printf '%s\n' 'Bloom Safe transfer report and on-chain evidence passed.'
  exit 0
fi
exit 1
