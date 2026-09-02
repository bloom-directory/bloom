#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
harbor_version="${HARBOR_VERSION:-0.21.0}"

usage() {
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor.sh <eval> claude|codex|deepseek|glm|opencode' \
    '       scripts/evals/run-harbor.sh <eval> --preauthorization-only' \
    '' \
    'Evals:' \
    '  hyperliquid-order-cancel   bounded BTC order/cancel on Hyperliquid mainnet' \
    '  solana-transfer            bounded native SOL transfer' >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

export BLOOM_EVAL_REPO_ROOT="$repo_root"
export PYTHONPATH="${repo_root}/evals/harbor${PYTHONPATH:+:${PYTHONPATH}}"
exec uv run --isolated --no-project --with "harbor==${harbor_version}" \
  python -m harness "$1" "$2"
