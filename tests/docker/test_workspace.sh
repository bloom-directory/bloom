#!/usr/bin/env bash
# In-container driver: build and run the bloom workspace unit tests.
#
# This is the dockerized equivalent of `cargo test --workspace --lib`,
# pinned to the same rust:bookworm image used by the NFS mount test so
# CI-style results match what the host runs locally.
#
# Steps:
#   1. Show the toolchain so failures are easy to bisect.
#   2. Run the workspace unit-test suite with --no-fail-fast so we see
#      every failure in one pass instead of stopping at the first.
#   3. Surface a short summary line so the host `run.sh` log is grep-able.
set -euo pipefail

echo "::group::toolchain"
rustc --version
cargo --version
echo "::endgroup::"

# /workspace/target is a host-side macOS build dir mounted in via -v.
# Reusing it from a Linux toolchain causes E0460 "possibly newer version
# of crate" errors. Redirect to a container-local path so the two
# toolchains never share rmeta files.
export CARGO_TARGET_DIR=/tmp/cargo-target

CARGO_FLAGS=(
    --workspace
    --lib
    --no-fail-fast
)

# Allow the caller to inject extra cargo args via $EXTRA_CARGO_ARGS for
# ad-hoc filtering ("--package bloom-tx", etc.) without editing the script.
if [ -n "${EXTRA_CARGO_ARGS:-}" ]; then
    # word-splitting is intentional here
    # shellcheck disable=SC2206
    EXTRA=( ${EXTRA_CARGO_ARGS} )
    CARGO_FLAGS+=("${EXTRA[@]}")
fi

echo "::group::cargo test ${CARGO_FLAGS[*]}"
cargo test "${CARGO_FLAGS[@]}"
status=$?
echo "::endgroup::"

if [ "$status" -ne 0 ]; then
    echo "FAIL: cargo test exited $status" >&2
    exit "$status"
fi

echo "all workspace unit tests passed"
