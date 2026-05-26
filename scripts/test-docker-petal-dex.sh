#!/usr/bin/env bash
# scripts/test-docker-petal-dex.sh — drive the dockerized 4-validator
# bloom-chain LIVE acceptance test for the petal-based DEX
# (/bloom/dex/{pool,wallet,faucet}).
#
# Proves, on a real 4-validator network over RPC, the two PTB flows that
# `examples/petal-dex/tests/.../faucet_provision.rs` proves in-process:
#   1. faucet.mint ×2 -> create_pool          (shared Pool, reserves 1000/1000)
#   2. faucet.mint -> swap_exact_in -> wallet.receive  (carol gets Coin worth 90;
#                                                       pool reserves -> 1100/910)
#
# Steps:
#   1. Resolve / create $BLOOM_DOCKER_TMPDIR.
#   2. Build the docker image (`bloom-eth:test` via docker-compose.yml). REQUIRED
#      so the in-container validator binary matches the current tree (the
#      driver pins petal hashes computed from the host-built wasm).
#   3. Build the host-side `bloom` binary (release).
#   4. Provision per-validator homes via `bloom chain testnet`, wiring peers to
#      the docker DNS names val0..val3.
#   5. APPEND a genesis allocation for the inner-PTB Ed25519 signer (the inner
#      gas-payer) to ALL FOUR home*/chain/genesis.toml files — byte-identical,
#      or the genesis hash diverges and consensus breaks.
#   6. `docker compose up -d` + wait for all four healthy.
#   7. Run the petal-dex docker driver test.
#   8. Always tear the stack down on exit (trap EXIT), capturing per-validator
#      logs first.
#
# Fast-iteration: set BLOOM_DOCKER_COMPOSE_UP=0 to skip build+provision+up
# (assumes the stack is already running) and jump straight to the test.
# Keep the temp tree: set BLOOM_DOCKER_PETAL_KEEP=1.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"

log()  { printf '\033[1;35m[docker-petal-dex]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[docker-petal-dex:fail]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd docker cargo
detect_docker_compose

# This driver is hard-wired to 4 validators (val0..val3, host ports
# 18545..18548) — see HOST_RPC_PORTS in tests/docker_petal_dex.rs.
BLOOM_VALIDATOR_COUNT=4
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

# Inner-PTB Ed25519 signer pubkey hex. MUST equal
# `bloom_petal_dex_it::dex_harness::ptb_signer_pubkey_hex()` — derived from the
# fixed `PTB_SIGNER_SEED` constant in that harness. Regenerate with:
#   cargo test -p bloom-petal-dex-it ptb_signer_pubkey -- --nocapture
PTB_SIGNER_PK_HEX="f10eaa1bc9f9470c53cab56dfc5c1cad0b106964a9e92b37ba068d17950fc346"

# Inner gas-payer LOOM allocation (gas_price=0 means it's never debited, but the
# coin must EXIST and be owned by the signer). 1M LOOM in bloomweis.
PTB_SIGNER_ALLOCATION="1000000000000000000000000"

# Resolve tmpdir (host-side homes for validators).
BLOOM_DOCKER_TMPDIR="${BLOOM_DOCKER_TMPDIR:-$(mktemp -d -t bloom-docker-petal-dex.XXXX)}"
export BLOOM_DOCKER_TMPDIR
log "tmpdir: $BLOOM_DOCKER_TMPDIR"

BLOOM_BIN="$REPO_ROOT/target/release/bloom"

# Teardown runs unconditionally on exit so we don't leak containers or tmpdirs
# even if the test panics. Capture and re-raise the original exit code.
TEARDOWN_RAN=0
teardown() {
    local rc=$?
    [ "$TEARDOWN_RAN" -eq 1 ] && return 0
    TEARDOWN_RAN=1
    local log_dir="${BLOOM_DOCKER_LOG_DIR:-/tmp/bloom-petal-dex-run}"
    mkdir -p "$log_dir" || true
    for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
        name="bloom-val$i"
        docker logs "$name" >"$log_dir/val$i.log" 2>&1 || true
    done
    log "captured per-validator logs to $log_dir/val{0..$((BLOOM_VALIDATOR_COUNT - 1))}.log"
    if [ "$rc" -ne 0 ]; then
        log "test failed (exit $rc) — dumping recent compose logs"
        (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" logs --tail=600) \
            2>&1 | sed 's/^/[compose-logs] /' || true
    fi
    log "tearing down compose stack"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" down -v --remove-orphans) \
        >/dev/null 2>&1 || true
    if [ -z "${BLOOM_DOCKER_PETAL_KEEP:-}" ]; then
        if [ -d "$BLOOM_DOCKER_TMPDIR" ]; then
            log "removing tmpdir $BLOOM_DOCKER_TMPDIR"
            # The in-container validator writes receipts/mempool files into the
            # bind-mounted home dirs as the container uid (root), which the host
            # user cannot delete. Remove them from inside a throwaway container
            # (runs as root) first, then drop the now-empty tree on the host.
            # Both steps are best-effort: a cleanup failure must NEVER mask the
            # acceptance test's own exit code ($rc).
            docker run --rm -v "$BLOOM_DOCKER_TMPDIR:/cleanup" \
                --entrypoint /bin/sh bloom-eth:test \
                -c 'rm -rf /cleanup/* /cleanup/.[!.]* 2>/dev/null || true' \
                >/dev/null 2>&1 || true
            rm -rf "$BLOOM_DOCKER_TMPDIR" 2>/dev/null \
                || log "could not fully remove $BLOOM_DOCKER_TMPDIR (container-owned files may remain)"
        fi
    else
        log "BLOOM_DOCKER_PETAL_KEEP set — leaving $BLOOM_DOCKER_TMPDIR in place"
    fi
    exit "$rc"
}
trap teardown EXIT INT TERM

if [ "${BLOOM_DOCKER_COMPOSE_UP:-1}" != "0" ]; then
    log "building docker image (bloom-eth:test) — must match current tree"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" build)

    log "building host-side bloom (release)"
    (cd "$REPO_ROOT" && cargo build --release -p bloom)
    [ -x "$BLOOM_BIN" ] || fail "bloom binary missing: $BLOOM_BIN"

    peer_hosts="val0,val1,val2,val3"

    log "provisioning $BLOOM_VALIDATOR_COUNT-validator testnet under $BLOOM_DOCKER_TMPDIR"
    "$BLOOM_BIN" chain testnet \
        --validators "$BLOOM_VALIDATOR_COUNT" \
        --output-dir "$BLOOM_DOCKER_TMPDIR" \
        --peer-hosts "$peer_hosts" \
        --listen-addr 0.0.0.0:26656 \
        --rpc-tcp-addr 0.0.0.0:8545 \
        --unsafe-rpc-public-bind \
        --allocation 1000000000000000000000000

    # Append the inner-PTB Ed25519 gas allocation to ALL FOUR genesis.toml
    # files. They MUST stay byte-identical (same genesis hash) or consensus
    # breaks, so we append the exact same lines to each.
    #
    # `parse_b1_address` accepts a raw 64-hex string as a 32-byte Address, so
    # the genesis `address` is the signer pubkey hex; genesis then emits a
    # Coin<LOOM> owned by Owner::Address(ed25519_pk).
    log "appending ed25519 gas allocation ($PTB_SIGNER_PK_HEX) to all 4 genesis.toml"
    alloc_block=$(printf '\n[[allocations]]\naddress = "%s"\namount = "%s"\n' \
        "$PTB_SIGNER_PK_HEX" "$PTB_SIGNER_ALLOCATION")
    for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
        g="$BLOOM_DOCKER_TMPDIR/home$i/chain/genesis.toml"
        [ -f "$g" ] || fail "missing genesis.toml: $g"
        printf '%s' "$alloc_block" >>"$g"
    done
    # Sanity: all four genesis files identical (same hash) post-edit.
    h0=$(sha256sum "$BLOOM_DOCKER_TMPDIR/home0/chain/genesis.toml" | awk '{print $1}')
    for i in 1 2 3; do
        hi=$(sha256sum "$BLOOM_DOCKER_TMPDIR/home$i/chain/genesis.toml" | awk '{print $1}')
        [ "$h0" = "$hi" ] || fail "genesis.toml mismatch home0 vs home$i ($h0 != $hi)"
    done
    log "genesis.toml byte-identical across all 4 homes (sha256=$h0)"

    log "starting compose stack"
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" up -d)

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
    [ -x "$BLOOM_BIN" ] || fail "bloom binary missing: $BLOOM_BIN (build it first or unset BLOOM_DOCKER_COMPOSE_UP)"
fi

log "running bloom-petal-dex-it::docker_petal_dex"
BLOOM_DOCKER_TMPDIR="$BLOOM_DOCKER_TMPDIR" \
BLOOM_BIN="$BLOOM_BIN" \
RUST_LOG="${RUST_LOG:-warn}" \
    cargo test -p bloom-petal-dex-it --test docker_petal_dex \
    -- --ignored --nocapture
