#!/usr/bin/env bash
# Host-side driver: build the test image and run an in-container
# integration suite.
#
# Usage:
#   ./tests/docker/run.sh [--rebuild] [--workspace|--mount|--enso|--enso-live|--fork]
#
# Modes:
#   default       — runs tests/docker/test.sh (NFS mount integration test).
#                   Container runs with SYS_ADMIN + apparmor=unconfined +
#                   /dev/fuse so mount.nfs4 can do its thing.
#   --workspace   — runs tests/docker/test_workspace.sh (cargo test
#                   --workspace --lib). Skips the privileged flags
#                   because the workspace unit tests don't mount.
#   --enso        — runs tests/docker/test_enso_aave.sh inside the
#                   shared docker-compose stack (anvil-fork sidecar +
#                   bloom-test-enso driver, selected via the `enso`
#                   profile). Drives the Enso -> Aave intent flow end
#                   to end through the NFS mount at /bloom/. Requires
#                   BLOOM_ENSO_KEY in the environment.
#   --enso-live   — same Enso -> Aave flow but against Base mainnet,
#                   broadcasting from the live keystore at $BLOOM_LIVE_HOME
#                   under the wallet $BLOOM_LIVE_DEST1. SPENDS REAL ETH on
#                   every run (default 0.001 ETH; override with
#                   BLOOM_SWAP_AMOUNT_ETH). The live keystore is mounted
#                   read-only and copied into a throwaway home inside
#                   the container — the canonical keystore is never
#                   written to from this script.
#   --fork        — runs tests/docker/test_fork_mount.sh inside the same
#                   docker-compose stack via the `fork` profile. Like
#                   --enso but skips DeFi: stages and broadcasts a plain
#                   native-ETH send via the wallet outbox, then exercises
#                   the chain read paths (head/tx/blocks/gas) against the
#                   resulting hash. No Enso key required.
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
Usage: $0 [--rebuild] [--workspace|--mount|--enso|--enso-live|--fork]

Default mode runs the NFS mount integration test.
--workspace runs \`cargo test --workspace --lib\` inside the same image.
--enso runs the Enso -> Aave integration test against an anvil fork.
--enso-live runs the same flow against Base mainnet (spends real ETH).
--fork runs the wallet outbox + chain reads test against an anvil fork.
--rebuild forces \`docker build --no-cache\`.
EOF
}

require_env() {
    local name
    for name in "$@"; do
        if [[ -z "${!name:-}" ]]; then
            echo "$name not set; required for --$MODE." >&2
            echo "  hint: source test.env or pass it inline." >&2
            exit 2
        fi
    done
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
        --enso) MODE=enso ;;
        --enso-live) MODE=enso-live ;;
        --fork) MODE=fork ;;
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
    enso)
        require_env BLOOM_ENSO_KEY
        export BLOOM_ENSO_KEY
        run_compose_profile enso
        ;;
    fork)
        run_compose_profile fork
        ;;
    enso-live)
        # No anvil sidecar: the daemon points at a real Base RPC and
        # the broadcast lands on Base mainnet. Single privileged
        # `docker run` so the in-container kernel can mount NFS.
        require_env BLOOM_ENSO_KEY BLOOM_LIVE_HOME BLOOM_LIVE_DEST1 BLOOM_PASSPHRASE
        if [[ ! -d "$BLOOM_LIVE_HOME/keystore" ]]; then
            echo "BLOOM_LIVE_HOME=$BLOOM_LIVE_HOME has no keystore/ subdir." >&2
            echo "  the live wallet must already exist before this test runs." >&2
            exit 2
        fi
        SWAP_AMOUNT_ETH="${BLOOM_SWAP_AMOUNT_ETH:-0.001}"
        BASE_RPC_URL="${BLOOM_BASE_RPC_URL:-https://base-rpc.publicnode.com}"
        echo "::group::docker run (enso-live)"
        echo "  wallet: $BLOOM_LIVE_DEST1" >&2
        echo "  swap:   $SWAP_AMOUNT_ETH ETH (override via BLOOM_SWAP_AMOUNT_ETH)" >&2
        echo "  rpc:    $BASE_RPC_URL" >&2
        echo "  NOTE:   this broadcasts to Base mainnet and spends real ETH." >&2
        # The live keystore is mounted read-only; the test script
        # copies it into a throwaway home inside the container so an
        # in-container daemon write can't corrupt the canonical copy.
        docker run --rm \
            "${mount_privileges[@]}" \
            --security-opt seccomp=unconfined \
            -v "$REPO_ROOT":/workspace \
            -v "$CARGO_CACHE_VOLUME":/tmp/cargo-target \
            -v "$BLOOM_LIVE_HOME":/bloom-live-home:ro \
            -e BLOOM_TEST_MODE=live \
            -e BLOOM_ENSO_KEY \
            -e BLOOM_PASSPHRASE \
            -e BLOOM_LIVE_DEST1 \
            -e BLOOM_BASE_RPC_URL="$BASE_RPC_URL" \
            -e BLOOM_SWAP_AMOUNT_ETH="$SWAP_AMOUNT_ETH" \
            -e RUST_LOG="${RUST_LOG:-info}" \
            -w /workspace \
            "$IMAGE_TAG" \
            bash tests/docker/test_enso_aave.sh
        rc=$?
        echo "::endgroup::"
        exit "$rc"
        ;;
    *)
        echo "internal error: unknown mode $MODE" >&2
        exit 2
        ;;
esac

echo "::group::docker run ($MODE)"
docker run "${run_args[@]}" "$IMAGE_TAG" "${cmd[@]}"
echo "::endgroup::"
