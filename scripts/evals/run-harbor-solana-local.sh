#!/usr/bin/env bash
set -euo pipefail

# Developer wrapper for the local-lane native SOL transfer evaluation.
#
# It drives the prepared, dedicated evaluation triad from the task README:
# one triad on the canonical ceremony port 18734, one trial at a time, plus a
# disposable local validator. This wrapper never launches, restarts, or stops
# services; lifecycle belongs to scripts/triad-dev-launch.sh and to whoever
# started the validator.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

usage() {
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor-solana-local.sh [claude|codex|glm|deepseek|opencode]' \
    '       scripts/evals/run-harbor-solana-local.sh smoke' \
    'Prepare the evaluation triad and local validator first; see' \
    'evals/harbor/tasks/solana-transfer/README.md.' >&2
  exit 2
}

mode="${1:-glm}"
[ "$#" -le 1 ] || usage
case "$mode" in
  smoke) harness_args=(--smoke-only) ;;
  claude|codex|glm|deepseek|opencode) harness_args=("$mode") ;;
  *) usage ;;
esac

# Pull the prepared triad's connection settings when they are not already
# exported. triad.env holds public settings only; sourcing it here supplies
# defaults, and explicit environment always wins.
if [ -z "${BLOOM_HOME:-}" ] || [ -z "${BLOOM_EVAL_BLOOM_MOUNT:-}" ]; then
  triad_env="${BLOOM_TRIAD_ENV:-${BLOOM_EVAL_TRIAD_ROOT:-/tmp/bloom-triad-logs}/logs/triad.env}"
  if [ -f "$triad_env" ]; then
    # shellcheck disable=SC1090
    source "$triad_env"
  fi
fi

if [ -z "${BLOOM_EVAL_BLOOM_MOUNT:-}" ]; then
  printf '%s\n' \
    'error: BLOOM_EVAL_BLOOM_MOUNT is not set; export it or point BLOOM_TRIAD_ENV' \
    'at the prepared triad env file.' >&2
  exit 1
fi
if ! mount | grep -F " on ${BLOOM_EVAL_BLOOM_MOUNT} " >/dev/null 2>&1; then
  printf '%s\n' \
    "error: no mount is live at ${BLOOM_EVAL_BLOOM_MOUNT}; start the prepared" \
    'evaluation triad with scripts/triad-dev-launch.sh --mount ... (README).' >&2
  exit 1
fi

# The canonical ceremony port must be serving. An occupied port is expected
# here only when it is the dedicated evaluation triad; when another service
# owns the port, launching the triad fails upstream and this wrapper never
# kills or stops the owner.
if ! (exec 3<>"/dev/tcp/127.0.0.1/18734") 2>/dev/null; then
  printf '%s\n' \
    'error: nothing is listening on the canonical ceremony port 18734; start' \
    'the dedicated evaluation triad with scripts/triad-dev-launch.sh (README).' >&2
  exit 1
fi

export BLOOM_EVAL_SOLANA_LANE="${BLOOM_EVAL_SOLANA_LANE:-local}"
export BLOOM_EVAL_SOLANA_CHAIN="${BLOOM_EVAL_SOLANA_CHAIN:-solana-local}"
export BLOOM_EVAL_SOLANA_WALLET_ID="${BLOOM_EVAL_SOLANA_WALLET_ID:-solana-eval}"
export BLOOM_EVAL_SOLANA_RPC_URL="${BLOOM_EVAL_SOLANA_RPC_URL:-http://127.0.0.1:8899}"
export BLOOM_EVAL_SOLANA_NETWORK="${BLOOM_EVAL_SOLANA_NETWORK:-localnet}"
export BLOOM_EVAL_SOLANA_HOME_ROOT="${BLOOM_EVAL_SOLANA_HOME_ROOT:-${BLOOM_HOME:-}}"

exec "$repo_root/scripts/evals/run-harbor.sh" solana-transfer "${harness_args[@]}"
