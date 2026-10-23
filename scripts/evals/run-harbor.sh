#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if [ "$#" -lt 2 ]; then
  printf '%s\n' 'Usage: scripts/evals/run-harbor.sh <task> claude|codex|opencode' >&2
  exit 2
fi
export BLOOM_EVAL_REPO_ROOT="$repo_root"
export PYTHONPATH="${repo_root}/evals/harbor${PYTHONPATH:+:${PYTHONPATH}}"
exec uv run --isolated --no-project --python 3.12 --with harbor==0.21.0 python -m harness "$@"
