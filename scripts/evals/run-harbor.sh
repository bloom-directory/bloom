#!/usr/bin/env bash
set -euo pipefail

# Generic Harbor evaluation launcher. Each evaluation exposes its own
# preflight and lane model; this wrapper only pins the repository root and the
# reviewed Harbor version and starts the shared harness CLI.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
harbor_version="${HARBOR_VERSION:-0.21.0}"

if [ "$#" -lt 1 ]; then
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor.sh EVAL claude|codex|glm|deepseek|opencode|--smoke-only|--preauthorization-only' >&2
  exit 2
fi

eval_name="$1"
shift

export BLOOM_EVAL_REPO_ROOT="$repo_root"
export PYTHONPATH="${repo_root}/evals/harbor${PYTHONPATH:+:${PYTHONPATH}}"
exec uv run --isolated --no-project --with "harbor==${harbor_version}" \
  python -m harness "$eval_name" "$@"
