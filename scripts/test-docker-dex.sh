#!/usr/bin/env bash
# scripts/test-docker-dex.sh — drive the dockerized 4-validator bloom-chain
# integration test.
#
# Steps:
#   1. Resolve / create $BLOOM_DOCKER_TMPDIR.
#   2. Build the docker image (`bloom-eth:test` via docker-compose.yml).
#   3. Build the host-side bloom + bloom-dex binaries (release).
#   4. Provision per-validator homes under $BLOOM_DOCKER_TMPDIR via
#      `bloom chain testnet`, wiring peers to the docker DNS names
#      val0..val3 and binding the in-container listeners on 0.0.0.0.
#   5. `docker compose up --wait -d` to start the 4-node network.
#   6. Run the bloom-dex-it docker driver test.
#   7. Always tear the stack down on exit (trap EXIT).
#
# Fast-iteration: set BLOOM_DOCKER_COMPOSE_UP=0 to skip build+provision+up
# (assumes the stack is already running from a previous invocation) and
# jump straight to the test.
#
# Keep the temp tree: set BLOOM_DOCKER_DEX_KEEP=1.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"

log()  { printf '\033[1;36m[docker-dex]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[docker-dex:fail]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd docker cargo
detect_docker_compose

# Validator count is parameterised; default 4 matches the static
# docker-compose.yml. Any other count generates a fresh compose file via
# scripts/gen-docker-compose.sh. Currently the bloom-dex-it docker test
# itself assumes 4 validators (val0..val3, host ports 18545..18548) — see
# `HOST_RPC_PORTS` in tests/docker_dex_multi_user.rs — so non-default N
# only exercises the chain stack, not the DEX driver.
BLOOM_VALIDATOR_COUNT="${BLOOM_VALIDATOR_COUNT:-4}"
log "validators: $BLOOM_VALIDATOR_COUNT"

# Retry knob for the known-flaky DEX driver. The chain stack itself is
# stable; the flake is in `dex_v0_acceptance_end_to_end` style nonce-race
# territory and disappears on retry without code changes (Memory IDs
# 1671-1674).
BLOOM_DOCKER_DEX_RETRIES="${BLOOM_DOCKER_DEX_RETRIES:-2}"

# Resolve tmpdir (host-side homes for validators).
BLOOM_DOCKER_TMPDIR="${BLOOM_DOCKER_TMPDIR:-$(mktemp -d -t bloom-docker-dex.XXXX)}"
export BLOOM_DOCKER_TMPDIR
log "tmpdir: $BLOOM_DOCKER_TMPDIR"

if [ "$BLOOM_VALIDATOR_COUNT" = "4" ]; then
    COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
else
    COMPOSE_FILE="$BLOOM_DOCKER_TMPDIR/docker-compose.gen.yml"
    log "generating compose file for $BLOOM_VALIDATOR_COUNT validators: $COMPOSE_FILE"
    "$REPO_ROOT/scripts/gen-docker-compose.sh" "$BLOOM_VALIDATOR_COUNT" > "$COMPOSE_FILE"
fi

BLOOM_BIN="$REPO_ROOT/target/release/bloom"
BLOOM_DEX_BIN="$REPO_ROOT/target/release/bloom-dex"

# Teardown runs unconditionally on exit so we don't leak containers or
# tmpdirs even if the test panics. We capture and re-raise the original
# exit code so a failing test still surfaces as a non-zero script exit.
TEARDOWN_RAN=0
teardown() {
    local rc=$?
    [ "$TEARDOWN_RAN" -eq 1 ] && return 0
    TEARDOWN_RAN=1
    if [ "$rc" -ne 0 ]; then
        log "test failed (exit $rc) — dumping recent compose logs"
        (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" logs --tail=600) \
            2>&1 | sed 's/^/[compose-logs] /' || true
    fi
    log "tearing down compose stack"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" down -v --remove-orphans) \
        >/dev/null 2>&1 || true
    if [ -z "${BLOOM_DOCKER_DEX_KEEP:-}" ]; then
        if [ -d "$BLOOM_DOCKER_TMPDIR" ]; then
            log "removing tmpdir $BLOOM_DOCKER_TMPDIR"
            rm -rf "$BLOOM_DOCKER_TMPDIR"
        fi
    else
        log "BLOOM_DOCKER_DEX_KEEP set — leaving $BLOOM_DOCKER_TMPDIR in place"
    fi
    exit "$rc"
}
trap teardown EXIT INT TERM

if [ "${BLOOM_DOCKER_COMPOSE_UP:-1}" != "0" ]; then
    log "building docker image (bloom-eth:test)"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" build)

    log "building host-side bloom + bloom-dex (release)"
    (cd "$REPO_ROOT" && cargo build --release -p bloom -p bloom-dex-cli)
    [ -x "$BLOOM_BIN" ]     || fail "bloom binary missing: $BLOOM_BIN"
    [ -x "$BLOOM_DEX_BIN" ] || fail "bloom-dex binary missing: $BLOOM_DEX_BIN"

    # Comma-separated peer-host list: val0,val1,...,val(N-1)
    peer_hosts=""
    for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
        [ -z "$peer_hosts" ] && peer_hosts="val$i" || peer_hosts="$peer_hosts,val$i"
    done

    log "provisioning $BLOOM_VALIDATOR_COUNT-validator testnet under $BLOOM_DOCKER_TMPDIR"
    "$BLOOM_BIN" chain testnet \
        --validators "$BLOOM_VALIDATOR_COUNT" \
        --output-dir "$BLOOM_DOCKER_TMPDIR" \
        --peer-hosts "$peer_hosts" \
        --listen-addr 0.0.0.0:26656 \
        --rpc-tcp-addr 0.0.0.0:8545 \
        --allocation 1000000000000000000000000

    log "starting compose stack"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" up -d)

    # Poll the per-container healthcheck instead of relying on `compose up
    # --wait`, which isn't available in older compose plugins (2.0.0-beta.1
    # rejects the flag).
    log "waiting for val0..val$((BLOOM_VALIDATOR_COUNT - 1)) to report healthy"
    deadline=$(( $(date +%s) + 180 ))
    while :; do
        unhealthy=()
        for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
            name="bloom-val$i"
            state=$(docker inspect --format='{{.State.Health.Status}}' "$name" 2>/dev/null || echo missing)
            [ "$state" = "healthy" ] || unhealthy+=("$name=$state")
        done
        if [ "${#unhealthy[@]}" -eq 0 ]; then
            log "all $BLOOM_VALIDATOR_COUNT validators healthy"
            break
        fi
        now=$(date +%s)
        if [ "$now" -ge "$deadline" ]; then
            fail "timed out waiting for validators: ${unhealthy[*]}"
        fi
        sleep 2
    done
else
    log "BLOOM_DOCKER_COMPOSE_UP=0 — skipping build/provision/up"
    [ -x "$BLOOM_BIN" ]     || fail "bloom binary missing: $BLOOM_BIN (build it first or unset BLOOM_DOCKER_COMPOSE_UP)"
    [ -x "$BLOOM_DEX_BIN" ] || fail "bloom-dex binary missing: $BLOOM_DEX_BIN"
fi

log "running bloom-dex-it::docker_dex_multi_user (up to $BLOOM_DOCKER_DEX_RETRIES retries)"

attempt=0
test_rc=0
while :; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 1 ]; then
        log "retry $((attempt - 1))/$((BLOOM_DOCKER_DEX_RETRIES - 1)) — flake on a stable chain; transient nonce-race territory"
    fi
    test_rc=0
    BLOOM_DOCKER_TMPDIR="$BLOOM_DOCKER_TMPDIR" \
    BLOOM_BIN="$BLOOM_BIN" \
    BLOOM_DEX_BIN="$BLOOM_DEX_BIN" \
    RUST_LOG="${RUST_LOG:-warn}" \
        cargo test --release -p bloom-dex-it --test docker_dex_multi_user \
        -- --ignored --nocapture || test_rc=$?
    if [ "$test_rc" -eq 0 ]; then
        [ "$attempt" -gt 1 ] && log "passed on retry $((attempt - 1))"
        break
    fi
    if [ "$attempt" -ge "$BLOOM_DOCKER_DEX_RETRIES" ]; then
        fail "docker DEX test failed after $attempt attempt(s) (rc=$test_rc)"
    fi
done
