#!/usr/bin/env bash
# Dockerized petal VFS acceptance gate.
#
# Provisions the same 4-validator devnet as the petal DEX test, deploys a
# view petal under /bloom/petals/, mounts the real VFS, invokes the endpoint
# shim via argv and stdin, and compares both with direct `chain_view_call`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

export BLOOM_DOCKER_PETAL_VFS_ONLY=1
exec "$REPO_ROOT/scripts/test-docker-petal-dex.sh" "$@"
