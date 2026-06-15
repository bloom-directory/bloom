#!/usr/bin/env bash
# scripts/test-docker-petal-dex.sh — drive the dockerized 4-validator
# bloom-chain LIVE acceptance test for the petal-based DEX
# (/bloom/petals/dex/{pool,wallet,faucet}).
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
#   3. Extract the already-built `bloom` binary from the docker image for
#      host-side provisioning and CLI shellouts.
#   4. Provision per-validator homes via `bloom chain testnet`, wiring peers to
#      the docker DNS names val0..val3.
#   5. APPEND the canonical core fungible petal binding plus a genesis
#      allocation and key-registry entry for the inner-PTB xDSA signer (the
#      inner gas-payer) to ALL FOUR home*/chain/genesis.toml files —
#      byte-identical, or the genesis hash diverges and consensus breaks.
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

require_cmd docker
detect_docker_compose

# This driver is hard-wired to 4 validators (val0..val3, host ports
# 18545..18548) — see HOST_RPC_PORTS in tests/docker_petal_dex.rs.
BLOOM_VALIDATOR_COUNT=4
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

# Inner-PTB xDSA signer registry values are derived from the fixed test-only
# secret in `bloom_petal_dex_it::dex_harness`.
PTB_SIGNER_PK_HEX=""
PTB_SIGNER_PUBKEY_B64=""

# Inner gas-payer LOOM allocation. Live PTBs use non-zero gas_price, and the
# coin must exist and be owned by the signer. 1M LOOM in bloomweis.
PTB_SIGNER_ALLOCATION="1000000000000000000000000"
CORE_FUNGIBLE_PATH="/bloom/petals/core/fungible"

# Resolve tmpdir (host-side homes for validators).
BLOOM_DOCKER_TMPDIR="${BLOOM_DOCKER_TMPDIR:-$(mktemp -d -t bloom-docker-petal-dex.XXXX)}"
export BLOOM_DOCKER_TMPDIR
log "tmpdir: $BLOOM_DOCKER_TMPDIR"

# Prefer an existing host-native release binary for local iteration. CI starts
# from a clean checkout, so Linux still extracts the image-built binary below.
BLOOM_BIN="${BLOOM_BIN:-$REPO_ROOT/target/release/bloom}"
BLOOM_DOCKER_TEST_BIN="${BLOOM_DOCKER_TEST_BIN:-$BLOOM_DOCKER_TMPDIR/host-bin/docker_petal_dex}"
BLOOM_DOCKER_PREBUILT_WASM_DIR="${BLOOM_DOCKER_PREBUILT_WASM_DIR:-$BLOOM_DOCKER_TMPDIR/wasm}"

# Teardown runs unconditionally on exit so we don't leak containers or tmpdirs
# even if the test panics. Capture and re-raise the original exit code.
TEARDOWN_RAN=0
teardown() {
    local rc=$?
    [ "$TEARDOWN_RAN" -eq 1 ] && return 0
    TEARDOWN_RAN=1
    local log_dir="${BLOOM_DOCKER_LOG_DIR:-/tmp/bloom-petal-dex-run}"
    mkdir -p "$log_dir" || true
    {
        printf 'exit_code=%s\n' "$rc"
        printf 'tmpdir=%s\n' "$BLOOM_DOCKER_TMPDIR"
        printf 'repo=%s\n' "$REPO_ROOT"
        printf 'compose_file=%s\n' "$COMPOSE_FILE"
        printf 'petal_vfs_only=%s\n' "${BLOOM_DOCKER_PETAL_VFS_ONLY:-0}"
    } >"$log_dir/run.env" 2>&1 || true
    (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" ps --all) \
        >"$log_dir/docker-compose-ps.txt" 2>&1 || true
    for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
        name="bloom-val$i"
        docker logs "$name" >"$log_dir/val$i.log" 2>&1 || true
        docker inspect "$name" >"$log_dir/$name.inspect.json" 2>&1 || true
        {
            printf '=== docker health status ===\n'
            docker inspect --format='{{.State.Health.Status}}' "$name" 2>&1 || true
            printf '\n=== chain health ===\n'
            docker exec "$name" /bin/sh -lc \
                'BLOOM_RPC_TCP=127.0.0.1:8545 /usr/local/bin/bloom --home /home/bloom chain health' \
                2>&1 || true
            printf '\n=== chain validators ===\n'
            docker exec "$name" /bin/sh -lc \
                'BLOOM_RPC_TCP=127.0.0.1:8545 /usr/local/bin/bloom --home /home/bloom chain ls-validators' \
                2>&1 || true
        } >"$log_dir/$name.health.txt" 2>&1 || true
        chain_dir="$BLOOM_DOCKER_TMPDIR/home$i/chain"
        if [ -d "$chain_dir" ]; then
            mkdir -p "$log_dir/home$i" || true
            cp "$chain_dir/genesis.toml" "$log_dir/home$i/genesis.toml" 2>/dev/null || true
            cp "$chain_dir/config.toml" "$log_dir/home$i/config.toml" 2>/dev/null || true
        fi
    done
    log "captured per-validator logs to $log_dir/val{0..$((BLOOM_VALIDATOR_COUNT - 1))}.log"
    if [ "$rc" -ne 0 ]; then
        {
            printf '=== docker compose ps ===\n'
            cat "$log_dir/docker-compose-ps.txt" 2>/dev/null || true
            printf '\n=== host home/run ownership ===\n'
            for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
                printf -- '-- home%s --\n' "$i"
                ls -ldn "$BLOOM_DOCKER_TMPDIR/home$i" \
                    "$BLOOM_DOCKER_TMPDIR/home$i/run" \
                    "$BLOOM_DOCKER_TMPDIR/home$i/run/.daemon.lock" 2>&1 || true
            done
            for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
                printf '\n=== bloom-val%s health ===\n' "$i"
                cat "$log_dir/bloom-val$i.health.txt" 2>/dev/null || true
                printf '\n=== bloom-val%s recent consensus warnings/errors ===\n' "$i"
                grep -E 'ERROR|WARN|fatal|rejected|invalid|block\.committed|sync\.block_applied|consensus\.timeout|frame\.(proposal|vote)' \
                    "$log_dir/val$i.log" 2>/dev/null | tail -n 160 || true
            done
        } >"$log_dir/failure-summary.txt" 2>&1 || true
        log "test failed (exit $rc) — dumping failure summary"
        sed 's/^/[docker-debug] /' "$log_dir/failure-summary.txt" || true
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

prepare_bloom_cli() {
    if [ -x "$BLOOM_BIN" ] && ! grep -a -q 'mount support is not enabled' "$BLOOM_BIN"; then
        log "using host-side bloom CLI: $BLOOM_BIN"
        return 0
    fi
    if [ -x "$BLOOM_BIN" ]; then
        log "rebuilding host-side bloom with all features because existing CLI lacks mount support: $BLOOM_BIN"
        require_cmd cargo
        (cd "$REPO_ROOT" && cargo build --release -p bloom --all-features)
        BLOOM_BIN="$REPO_ROOT/target/release/bloom"
        [ -x "$BLOOM_BIN" ] || fail "bloom binary missing: $BLOOM_BIN"
        return 0
    fi

    if [ "$(uname -s)" = "Linux" ] && docker image inspect bloom-eth:test >/dev/null 2>&1; then
        log "extracting host-side bloom CLI from bloom-eth:test"
        mkdir -p "$(dirname "$BLOOM_BIN")"
        local cid=""
        cid=$(docker create bloom-eth:test)
        if ! docker cp "$cid:/usr/local/bin/bloom" "$BLOOM_BIN"; then
            docker rm "$cid" >/dev/null 2>&1 || true
            fail "failed to extract /usr/local/bin/bloom from bloom-eth:test"
        fi
        docker rm "$cid" >/dev/null
        chmod +x "$BLOOM_BIN"
        [ -x "$BLOOM_BIN" ] || fail "extracted bloom binary is not executable: $BLOOM_BIN"
        return 0
    fi

    log "building host-side bloom (release) because no compatible docker image binary is available"
    require_cmd cargo
    (cd "$REPO_ROOT" && cargo build --release -p bloom --all-features)
    BLOOM_BIN="$REPO_ROOT/target/release/bloom"
    [ -x "$BLOOM_BIN" ] || fail "bloom binary missing: $BLOOM_BIN"
}

extract_prebuilt_acceptance_artifacts() {
    docker image inspect bloom-eth:test >/dev/null \
        || fail "BLOOM_DOCKER_IMAGE_PREBUILT=1 but bloom-eth:test is missing"

    local can_run_image_bins=0
    [ "$(uname -s)" = "Linux" ] && can_run_image_bins=1

    if { [ "$can_run_image_bins" -eq 0 ] || [ -x "$BLOOM_DOCKER_TEST_BIN" ]; } \
        && [ -f "$BLOOM_DOCKER_PREBUILT_WASM_DIR/bloom_petal_dex_pool.wasm" ] \
        && [ -f "$BLOOM_DOCKER_PREBUILT_WASM_DIR/bloom_petal_fungible.wasm" ]; then
        log "using extracted docker acceptance artifacts"
        return 0
    fi

    if [ "$can_run_image_bins" -eq 1 ]; then
        log "extracting docker acceptance test binary and wasm artifacts from bloom-eth:test"
    else
        log "extracting docker wasm artifacts from bloom-eth:test"
    fi
    mkdir -p "$(dirname "$BLOOM_DOCKER_TEST_BIN")" "$BLOOM_DOCKER_PREBUILT_WASM_DIR"
    local cid=""
    cid=$(docker create bloom-eth:test)
    if [ "$can_run_image_bins" -eq 1 ]; then
        if ! docker cp "$cid:/tests/docker_petal_dex" "$BLOOM_DOCKER_TEST_BIN"; then
            docker rm "$cid" >/dev/null 2>&1 || true
            fail "failed to extract /tests/docker_petal_dex from bloom-eth:test"
        fi
    fi
    if ! docker cp "$cid:/wasm/." "$BLOOM_DOCKER_PREBUILT_WASM_DIR/"; then
        docker rm "$cid" >/dev/null 2>&1 || true
        fail "failed to extract /wasm from bloom-eth:test"
    fi
    docker rm "$cid" >/dev/null
    if [ "$can_run_image_bins" -eq 1 ]; then
        chmod +x "$BLOOM_DOCKER_TEST_BIN"
        [ -x "$BLOOM_DOCKER_TEST_BIN" ] || fail "extracted test binary is not executable: $BLOOM_DOCKER_TEST_BIN"
    fi
    [ -f "$BLOOM_DOCKER_PREBUILT_WASM_DIR/bloom_petal_dex_faucet.wasm" ] \
        || fail "extracted faucet wasm missing from $BLOOM_DOCKER_PREBUILT_WASM_DIR"
    [ -f "$BLOOM_DOCKER_PREBUILT_WASM_DIR/bloom_petal_fungible.wasm" ] \
        || fail "extracted core fungible wasm missing from $BLOOM_DOCKER_PREBUILT_WASM_DIR"
}

derive_ptb_signer_registry() {
    local signer_vars=""
    if [ -x "$BLOOM_DOCKER_TEST_BIN" ]; then
        signer_vars=$("$BLOOM_DOCKER_TEST_BIN" \
            prints_ptb_signer_registry_entry_for_docker_script \
            --exact --nocapture)
    else
        require_cmd cargo
        signer_vars=$(cargo test -q -p bloom-petal-dex-it --lib \
            prints_ptb_signer_registry_entry -- --nocapture)
    fi
    PTB_SIGNER_PK_HEX=$(printf '%s\n' "$signer_vars" | sed -n 's/^PTB_SIGNER_PK_HEX=//p' | tail -n1)
    PTB_SIGNER_PUBKEY_B64=$(printf '%s\n' "$signer_vars" | sed -n 's/^PTB_SIGNER_PUBKEY_B64=//p' | tail -n1)
    [ -n "$PTB_SIGNER_PK_HEX" ] || fail "failed to derive PTB signer address"
    [ -n "$PTB_SIGNER_PUBKEY_B64" ] || fail "failed to derive PTB signer pubkey"
}

prepare_host_acceptance_driver() {
    if [ -x "$BLOOM_DOCKER_TEST_BIN" ]; then
        return 0
    fi
    require_cmd cargo
    log "precompiling host-side docker acceptance test"
    (cd "$REPO_ROOT" && \
        BLOOM_DEX_FAUCET_ADMIN_HEX="$PTB_SIGNER_PK_HEX" \
        cargo test -p bloom-petal-dex-it --test docker_petal_dex --no-run)
}

upsert_core_fungible_petal() {
    local genesis_file="$1"
    local wasm_file="$BLOOM_DOCKER_PREBUILT_WASM_DIR/bloom_petal_fungible.wasm"
    [ -f "$wasm_file" ] || fail "missing core fungible wasm: $wasm_file"
    local wasm_hex_file="$BLOOM_DOCKER_TMPDIR/core_fungible_wasm.hex"
    od -An -tx1 -v "$wasm_file" | tr -d ' \n' >"$wasm_hex_file"
    CORE_FUNGIBLE_PATH="$CORE_FUNGIBLE_PATH" \
        CORE_FUNGIBLE_WASM_HEX_FILE="$wasm_hex_file" \
        perl -0pi -e '
            my $path = quotemeta($ENV{CORE_FUNGIBLE_PATH});
            open my $fh, "<", $ENV{CORE_FUNGIBLE_WASM_HEX_FILE}
                or die "open wasm hex file: $!";
            my $wasm_hex = do { local $/; <$fh> };
            chomp $wasm_hex;
            my $block = "\n[[petals]]\npath = \"$ENV{CORE_FUNGIBLE_PATH}\"\nwasm_hex = \"$wasm_hex\"\n";
            if (!s/\n\[\[petals\]\]\npath = "$path"\nwasm_hex = "[^"]*"\n/$block/s) {
                $_ .= $block;
            }
        ' "$genesis_file"
}

if [ "${BLOOM_DOCKER_COMPOSE_UP:-1}" != "0" ]; then
    if [ "${BLOOM_DOCKER_IMAGE_PREBUILT:-0}" = "1" ]; then
        log "using prebuilt docker image (bloom-eth:test)"
        docker image inspect bloom-eth:test >/dev/null \
            || fail "BLOOM_DOCKER_IMAGE_PREBUILT=1 but bloom-eth:test is missing"
        extract_prebuilt_acceptance_artifacts
    else
        require_cmd cargo
        log "running petal DEX package preflight tests"
        (cd "$REPO_ROOT" && cargo test \
            -p bloom-dex-math \
            -p bloom-petal-dex-pool \
            -p bloom-petal-dex-router)

        log "building docker image (bloom-eth:test) — must match current tree"
        (cd "$REPO_ROOT" && "${DC[@]}" -f "$COMPOSE_FILE" build)
        extract_prebuilt_acceptance_artifacts
    fi

    prepare_bloom_cli

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

    derive_ptb_signer_registry
    prepare_host_acceptance_driver

    # Upsert the canonical fungible petal plus the inner-PTB xDSA gas allocation
    # and key-registry entry to ALL FOUR genesis.toml files. They MUST stay
    # byte-identical (same genesis hash) or consensus breaks.
    log "upserting core fungible petal and xDSA gas/custody allocations ($PTB_SIGNER_PK_HEX) to all 4 genesis.toml"
    alloc_block=""
    alloc_block+=$(printf '\n[[key_registry]]\naddress = "%s"\npubkey = "%s"\n' \
        "$PTB_SIGNER_PK_HEX" "$PTB_SIGNER_PUBKEY_B64")
    for _ in gas merge-a merge-b split-src; do
        alloc_block+=$(printf '\n[[allocations]]\naddress = "%s"\namount = "%s"\n' \
            "$PTB_SIGNER_PK_HEX" "$PTB_SIGNER_ALLOCATION")
    done
    for i in $(seq 0 $((BLOOM_VALIDATOR_COUNT - 1))); do
        g="$BLOOM_DOCKER_TMPDIR/home$i/chain/genesis.toml"
        [ -f "$g" ] || fail "missing genesis.toml: $g"
        upsert_core_fungible_petal "$g"
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
    if [ "${BLOOM_DOCKER_IMAGE_PREBUILT:-0}" = "1" ]; then
        extract_prebuilt_acceptance_artifacts
    fi
    prepare_bloom_cli
fi

if [ -z "$PTB_SIGNER_PK_HEX" ]; then
    derive_ptb_signer_registry
fi

if [ -n "${BLOOM_DOCKER_PETAL_VFS_ONLY:-}" ]; then
    DOCKER_PETAL_TEST_NAME="docker_petal_vfs_acceptance"
else
    DOCKER_PETAL_TEST_NAME="docker_petal_dex_acceptance"
fi

log "running bloom-petal-dex-it::docker_petal_dex::$DOCKER_PETAL_TEST_NAME"
if [ -x "$BLOOM_DOCKER_TEST_BIN" ]; then
    BLOOM_DOCKER_TMPDIR="$BLOOM_DOCKER_TMPDIR" \
    BLOOM_BIN="$BLOOM_BIN" \
    BLOOM_DOCKER_PREBUILT_WASM_DIR="$BLOOM_DOCKER_PREBUILT_WASM_DIR" \
    BLOOM_DEX_FAUCET_ADMIN_HEX="$PTB_SIGNER_PK_HEX" \
    RUST_LOG="${RUST_LOG:-warn}" \
    RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}" \
        "$BLOOM_DOCKER_TEST_BIN" "$DOCKER_PETAL_TEST_NAME" \
        --exact --ignored --nocapture
else
    require_cmd cargo
    BLOOM_DOCKER_TMPDIR="$BLOOM_DOCKER_TMPDIR" \
    BLOOM_BIN="$BLOOM_BIN" \
    BLOOM_DOCKER_PREBUILT_WASM_DIR="$BLOOM_DOCKER_PREBUILT_WASM_DIR" \
    BLOOM_DEX_FAUCET_ADMIN_HEX="$PTB_SIGNER_PK_HEX" \
    RUST_LOG="${RUST_LOG:-warn}" \
    RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}" \
        cargo test -p bloom-petal-dex-it --test docker_petal_dex \
        "$DOCKER_PETAL_TEST_NAME" -- --exact --ignored --nocapture
fi
