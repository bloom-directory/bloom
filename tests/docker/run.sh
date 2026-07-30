#!/usr/bin/env bash
# Host-side driver: build the test image and run an in-container
# integration suite.
#
# Usage:
#   ./tests/docker/run.sh [--rebuild] [--workspace|--mount|--fork|--mempool]
#
# Modes:
#   default       — runs tests/docker/test.sh (NFS mount integration test).
#                   Container runs with SYS_ADMIN + apparmor=unconfined +
#                   /dev/fuse so mount.nfs4 can do its thing.
#   --workspace   — runs tests/docker/test_workspace.sh (cargo test
#                   --workspace --lib). Skips the privileged flags
#                   because the workspace unit tests don't mount.
#   --fork        — runs tests/docker/test_fork_mount.sh inside the same
#                   docker-compose stack via the `fork` profile. Stages and
#                   broadcasts a native-ETH send via the wallet outbox, then exercises
#                   the chain read paths (head/tx/blocks/gas) against the
#                   resulting hash. No Enso key required.
#   --mempool     — runs tests/docker/test_mempool_mock.sh inside the same
#                   docker-compose stack via the `mempool` profile. Spins
#                   up an in-container WS mock server that emulates
#                   alchemy_pendingTransactions and asserts the daemon's
#                   chains/base/mempool/{status.json,recent.jsonl} surface
#                   populates within ~30 seconds. No Enso key required.
#
# `--rebuild` forces `docker build --no-cache`. The default reuses the
# cached image so iterative loops stay fast. The named docker volume
# `bloom-cargo-cache` (mounted at /tmp/cargo-target inside the
# container) persists incremental compile artifacts across runs — wipe
# it with `docker volume rm bloom-cargo-cache` if you ever need a
# truly cold rebuild.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE_TAG=bloom-mount-test:latest
COMPOSE_FILE="$REPO_ROOT/tests/docker/docker-compose.yml"
CARGO_CACHE_VOLUME=bloom-cargo-cache

usage() {
    cat <<EOF
Usage: $0 [--rebuild] [--workspace|--mount|--fork|--mempool]

Default mode runs the NFS mount integration test.
--workspace runs \`cargo test --workspace --lib\` inside the same image.
--fork runs the wallet outbox + chain reads test against an anvil fork.
--mempool runs the mempool mock WS + daemon ingestion test.
--rebuild forces \`docker build --no-cache\`.
EOF
}

docker_build_image() {
    echo "::group::docker build"
    local build_args=(-t "$IMAGE_TAG" -f "$REPO_ROOT/tests/docker/Dockerfile" "$REPO_ROOT")
    if [ "$REBUILD" -eq 1 ]; then
        docker build --no-cache "${build_args[@]}"
    else
        docker build "${build_args[@]}"
    fi
    echo "::endgroup::"
}

compose_cmd() {
    if command -v docker-compose >/dev/null 2>&1; then
        COMPOSE=(docker-compose)
    else
        COMPOSE=(docker compose)
    fi
}

# Run a profile under the consolidated compose stack. The driver service
# the profile exposes is always named bloom-test-<profile> so we can pin
# `--exit-code-from` to the right thing without another arg.
run_compose_profile() {
    local profile=$1
    local service="bloom-test-$profile"

    compose_cmd
    echo "::group::docker compose up ($profile)"
    export REPO_ROOT
    export BLOOM_TEST_IMAGE="$IMAGE_TAG"
    export BASE_FORK_RPC_URL="${BASE_FORK_RPC_URL:-https://base-rpc.publicnode.com}"

    "${COMPOSE[@]}" -f "$COMPOSE_FILE" --profile "$profile" \
        down --remove-orphans >/dev/null 2>&1 || true
    rc=0
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" --profile "$profile" up \
        --abort-on-container-exit --exit-code-from "$service" \
        || rc=$?
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" --profile "$profile" \
        down --remove-orphans >/dev/null 2>&1 || true
    echo "::endgroup::"
    exit "$rc"
}

mount_privileges=(
    --cap-add SYS_ADMIN
    --device /dev/fuse
    --security-opt apparmor=unconfined
)

REBUILD=0
MODE=mount
for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=1 ;;
        --workspace) MODE=workspace ;;
        --mount) MODE=mount ;;
        --fork) MODE=fork ;;
        --mempool) MODE=mempool ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

docker_build_image

run_args=(
    --rm
    -v "$REPO_ROOT":/workspace
    # Persist cargo's incremental cache across runs. The image's
    # CARGO_TARGET_DIR points here, so anything compiled in one run is
    # reused by the next.
    -v "$CARGO_CACHE_VOLUME":/tmp/cargo-target
    -w /workspace
)

case "$MODE" in
    mount)
        # --cap-add SYS_ADMIN          — allows mount() inside the container
        # --device /dev/fuse           — only needed if we ever switch to FUSE,
        #                                 but harmless and matches bloom's run
        # --security-opt apparmor=unconfined
        #                              — Debian/Ubuntu hosts ship an apparmor
        #                                 profile that blocks mount() even with
        #                                 SYS_ADMIN; unconfined gets us past it
        run_args+=("${mount_privileges[@]}")
        cmd=(bash tests/docker/test.sh)
        ;;
    workspace)
        # Workspace unit tests don't need any of the mount privileges.
        cmd=(bash tests/docker/test_workspace.sh)
        ;;
    fork)
        run_compose_profile fork
        ;;
    mempool)
        run_compose_profile mempool
        ;;
    *)
        echo "internal error: unknown mode $MODE" >&2
        exit 2
        ;;
esac

echo "::group::docker run ($MODE)"
docker run "${run_args[@]}" "$IMAGE_TAG" "${cmd[@]}"
echo "::endgroup::"
