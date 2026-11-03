#!/usr/bin/env bash
set -uo pipefail
mkdir -p /logs/verifier
reward=0
if python3 /tests/verify_result.py; then reward=1; fi
printf '%s\n' "$reward" > /logs/verifier/reward.txt
[ "$reward" -eq 1 ]
