#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
harbor_version="${HARBOR_VERSION:-0.21.0}"

if [ "$#" -lt 1 ]; then
  printf '%s\n' \
    'Usage: scripts/evals/operate-harbor-hyperliquid.sh init|status|run|recover [options]' >&2
  exit 2
fi

command="$1"
export BLOOM_EVAL_REPO_ROOT="$repo_root"
export PYTHONPATH="${repo_root}/evals/harbor${PYTHONPATH:+:${PYTHONPATH}}"

case "$command" in
  init|status|recover)
    exec uv run --isolated --no-project --python 3.12 \
      python -m harness.operator "$@"
    ;;
  run)
    exec uv run --isolated --no-project --python 3.12 \
      --with "harbor==${harbor_version}" \
      python -m harness.operator "$@"
    ;;
  *)
    printf 'Unknown operator command: %s\n' "$command" >&2
    exit 2
    ;;
esac
