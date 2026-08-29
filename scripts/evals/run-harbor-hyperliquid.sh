#!/usr/bin/env bash
# Deprecated: superseded by `scripts/evals/run-harbor.sh <eval> <agent>`, which
# dispatches every registered eval instead of one per integration. Kept so
# existing runbooks and muscle memory keep working.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

if [ "$#" -ne 1 ]; then
  printf '%s\n' \
    'Usage: scripts/evals/run-harbor-hyperliquid.sh claude|codex|--preauthorization-only' >&2
  exit 2
fi

printf '%s\n' \
  'note: run-harbor-hyperliquid.sh is deprecated; use' \
  "      scripts/evals/run-harbor.sh hyperliquid-order-cancel $1" >&2

exec "${repo_root}/scripts/evals/run-harbor.sh" hyperliquid-order-cancel "$1"
