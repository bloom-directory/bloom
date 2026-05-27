#!/usr/bin/env bash
# Compatibility wrapper for the old Docker DEX acceptance entrypoint.
#
# The legacy script targeted removed `bloom-dex-cli` / `bloom-dex-it`
# packages. The maintained live 4-validator DEX gate is the petal DEX
# harness.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$REPO_ROOT/scripts/test-docker-petal-dex.sh" "$@"
