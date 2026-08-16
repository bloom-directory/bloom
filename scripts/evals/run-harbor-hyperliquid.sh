#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
harbor_version="${HARBOR_VERSION:-0.21.0}"

if [ "$#" -ne 1 ]; then
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor-hyperliquid.sh claude|codex|--preauthorization-only' >&2
  exit 2
fi

export BLOOM_EVAL_REPO_ROOT="$repo_root"
export PYTHONPATH="${repo_root}/evals/harbor${PYTHONPATH:+:${PYTHONPATH}}"
exec uv run --isolated --no-project --with "harbor==${harbor_version}" \
  python -m harness hyperliquid-order-cancel "$1"
