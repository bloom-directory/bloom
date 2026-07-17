#!/usr/bin/env bash
# tests/docker/test_enso_aave.sh — dockerized Enso -> Aave integration
# test driver. Runs *inside* the bloom-test-enso container brought up by
# tests/docker/docker-compose.yml under the `enso` profile (fork mode)
# or by tests/docker/run.sh --enso-live (live mainnet mode).
#
# What this proves
#   The agent-facing surface (NFS mount at /bloom/) end-to-ends a real
#   DeFi intent: ETH -> aBaseUSDC via Enso shortcut -> Aave V3 supply.
#   Every step except the wallet unlock (in-process by design) is
#   driven through plain filesystem ops on /bloom/ — no `bloom vfs write`
#   short-circuits, no `bloom ipc call`. If this test passes, an agent
#   with shell access to /bloom/ can place real DeFi trades.
#
# Modes (selected by BLOOM_TEST_MODE; default "fork")
#   fork  — broadcasts land on an anvil --fork-url=Base sidecar.
#           Throwaway state, no real funds.
#   live  — broadcasts land on Base mainnet via $BLOOM_BASE_RPC_URL.
#           Spends real ETH from $BLOOM_LIVE_DEST1. The keystore is
#           expected at /bloom-live-home/keystore (mounted read-only by
#           run.sh --enso-live) and is COPIED into a throwaway home
#           before the daemon starts so the canonical keystore is
#           never written to.
#
# How to run (host side)
#   set -a && source test.env && set +a
#   bash tests/docker/run.sh --enso         # fork
#   bash tests/docker/run.sh --enso-live    # mainnet, spends real ETH
#
# Required env (fork mode — set by docker-compose.yml's enso profile)
#   BLOOM_ENSO_KEY              Enso v1 API key
#   BLOOM_TEST_WALLET_PASSPHRASE   passphrase for the imported test wallet
#   BASE_FORK_INTERNAL_URL     RPC URL the daemon hits (anvil-fork:8545)
#
# Required env (live mode — set by run.sh --enso-live)
#   BLOOM_TEST_MODE=live        selects this branch
#   BLOOM_ENSO_KEY              Enso v1 API key
#   BLOOM_PASSPHRASE            passphrase for the live keystore
#   BLOOM_LIVE_DEST1            sender address (must exist as `dest1`
#                              under /bloom-live-home/keystore)
#   BLOOM_BASE_RPC_URL          real Base RPC the daemon broadcasts to
#   BLOOM_SWAP_AMOUNT_ETH       optional, defaults to 0.001
#
# Idempotency
#   Fork mode wipes the home dir per run and the anvil fork is fresh
#   each `docker compose up`. Live mode wipes only the throwaway
#   /tmp/bloom-enso-home; the canonical $BLOOM_LIVE_HOME on the host is
#   read-only-mounted and never modified.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_PREFIX=enso-test
source "$SCRIPT_DIR/lib.sh"

MODE="${BLOOM_TEST_MODE:-fork}"

# MNT/PIDFILE/LOGFILE/SENTINEL come from lib.sh defaults.
# DEST1/ANVIL_KEY/USDC/AUSDC come from lib.sh fixtures (fork mode keeps
# DEST1 as Anvil account[0]; live mode overrides below).
HOME_DIR=/tmp/bloom-enso-home
WALLET=dest1
CHAIN=base

# ---------- mode-specific config ----------
case "$MODE" in
    fork)
        SWAP_AMOUNT_ETH=0.05
        WALLET_PASSPHRASE="${BLOOM_TEST_WALLET_PASSPHRASE:-}"
        IMPORT_KEY="$ANVIL_KEY"
        [[ -n "${BLOOM_ENSO_KEY:-}" ]] || fail "BLOOM_ENSO_KEY not set"
        [[ -n "$WALLET_PASSPHRASE" ]] || fail "BLOOM_TEST_WALLET_PASSPHRASE not set"
        [[ -n "${BASE_FORK_INTERNAL_URL:-}" ]] \
            || fail "BASE_FORK_INTERNAL_URL not set"
        RPC_URL="$BASE_FORK_INTERNAL_URL"
        CHAIN_DISPLAY="Base (forked)"
        ;;
    live)
        DEST1="${BLOOM_LIVE_DEST1:-}"
        SWAP_AMOUNT_ETH="${BLOOM_SWAP_AMOUNT_ETH:-0.001}"
        WALLET_PASSPHRASE="${BLOOM_PASSPHRASE:-}"
        # No key import in live mode — the keystore is the source of
        # truth and was created by `bloom wallet create` long ago.
        IMPORT_KEY=
        [[ -n "${BLOOM_ENSO_KEY:-}" ]] || fail "BLOOM_ENSO_KEY not set"
        [[ -n "$DEST1" ]]             || fail "BLOOM_LIVE_DEST1 not set"
        [[ -n "$WALLET_PASSPHRASE" ]] || fail "BLOOM_PASSPHRASE not set"
        [[ -n "${BLOOM_BASE_RPC_URL:-}" ]] \
            || fail "BLOOM_BASE_RPC_URL not set"
        RPC_URL="$BLOOM_BASE_RPC_URL"
        CHAIN_DISPLAY="Base (mainnet)"
        warn "LIVE MODE: broadcasting to Base mainnet from $DEST1"
        warn "           swap = $SWAP_AMOUNT_ETH ETH (real funds)"
        ;;
    *)
        fail "unknown BLOOM_TEST_MODE='$MODE' (expected fork|live)"
        ;;
esac

prepare_home_dir "$HOME_DIR"
[[ "$MODE" == "live" ]] && prepare_live_home "$HOME_DIR" "$WALLET"

write_base_config "$HOME_DIR" "$RPC_URL" "$CHAIN_DISPLAY" "$BLOOM_ENSO_KEY"
build_mount_demo

# ---------- top up the test wallet on the fork ----------
# Anvil's account[0] starts with 10k ETH on a brand-new anvil, but a
# *fork* respects upstream state — the address may have nothing on
# real Base. Use anvil_setBalance to guarantee 10 ETH for the run.
# Live mode skips this — there is no anvil and the wallet is expected
# to already hold enough ETH for the swap plus gas.
if [[ "$MODE" == "fork" ]]; then
    top_up_anvil_balance "$BASE_FORK_INTERNAL_URL" "$DEST1"
fi

# BLOOM_TEST_WALLET_KEY is only set in fork mode where mount_demo
# imports an Anvil-derived key under the name "dest1". In live mode the
# keystore was copied in above, so we leave the import key empty —
# mount_demo will skip the import branch and just unlock the existing
# entry with BLOOM_TEST_WALLET_PASSPHRASE.
start_mount_demo "$MNT" "$HOME_DIR" "$PIDFILE" "$LOGFILE" "$WALLET" "$IMPORT_KEY" "$WALLET_PASSPHRASE"
trap 'cleanup_mount_demo "$MNT" "$PIDFILE" "$LOGFILE"' EXIT
wait_for_mount "$SENTINEL" "$DAEMON_PID" "$LOGFILE" 90

# ---------- breadcrumbs ----------
read_chain_head_breadcrumb "$MNT" "$CHAIN"
read_wallet_balance_breadcrumb "$MNT" "$CHAIN" "$WALLET" "$DEST1"

# Sanity: the test only makes sense if dest1 has ETH to spend. In fork
# mode anvil_setBalance guarantees 10 ETH; in live mode the wallet
# must already hold > swap+gas. We use awk for the comparison because
# `[[ ... -lt ... ]]` is integer-only and the balance is decimal.
[[ -n "$BAL_NATIVE" && "$BAL_NATIVE" != "0" ]] || fail "$WALLET native balance is 0"
if ! awk -v b="$BAL_NATIVE" -v s="$SWAP_AMOUNT_ETH" 'BEGIN { exit !(b+0 > s+0) }'; then
    fail "$WALLET native balance ($BAL_NATIVE) is not greater than swap amount ($SWAP_AMOUNT_ETH); top up before retrying"
fi

# ---------- post the intent through the mount ----------
# slippage_bps=500 (5%) is generous on purpose. The default of 50bps
# trips on both the fork (Anvil lazy-fetches storage from public RPC
# replicas that may serve a different block than the fork's frozen base)
# and on live mainnet (Enso quotes against latest-mainnet, our broadcast
# lands a few blocks later). Both surfaced as `ShortcutExecutionFailed`
# with inner "Insufficient output" / "T12" Uniswap reverts at step 0
# of the route.
INTENT_BODY=$(printf '{"intent":"swap %s ETH to %s on base","chain":"%s","slippage_bps":500}' \
    "$SWAP_AMOUNT_ETH" "$AUSDC" "$CHAIN")
log "POST intent (via /bloom write): $INTENT_BODY"

# Snapshot the pending set so we can diff it after confirmation and
# learn the staged id. This used to be impossible — `BloomFs::getattr`
# returned a stable `change` attribute, so once the kernel cached the
# empty listing it never refreshed. Now `dir_change` hashes the actual
# listing, so a daemon-side write moves the change attribute and the
# kernel re-issues READDIR.
OUTBOX="$MNT/wallets/$WALLET/chains/$CHAIN/outbox"
PENDING_BEFORE=$(pending_set "$OUTBOX")

printf '%s' "$INTENT_BODY" > "$MNT/defi/intents/$WALLET/new"

# Pull the new session id (the only entry under defi/intents/<w> that
# isn't `new`).
SESS=$(latest_session "$WALLET")
[[ -n "$SESS" ]] || fail "no defi session created under $MNT/defi/intents/$WALLET"
log "session: $SESS"

echo '::group::session plan.md' >&2
cat "$MNT/defi/intents/$WALLET/$SESS/plan.md" >&2 || true
echo '::endgroup::' >&2

# Confirm the session — that stages a tx into the wallet outbox.
# The confirm write returns once the daemon has accepted it, but the
# tx engine still has to estimate gas (which can take tens of seconds
# against an upstream RPC) before the stage appears under outbox/pending.
# Poll instead of snapshotting once.
log "confirm defi session"
echo y > "$MNT/defi/intents/$WALLET/$SESS/confirm"

STAGE=
# Budget is generous because gas estimation walks the Enso route
# through Aave/USDC/Uniswap, all of which lazy-fetch state from the
# fork's upstream RPC. A cold fork against a slow public endpoint can
# easily push this past 90s.
STAGE=$(wait_for_new_pending_stages "$OUTBOX" "$PENDING_BEFORE" 300)
STAGE=${STAGE%%$'\n'*}
[[ -n "$STAGE" ]] || fail "no new outbox stage produced within 300s"
log "stage: $STAGE"

echo '::group::stage plan.md' >&2
cat "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/pending/$STAGE/plan.md" >&2 || true
echo '::endgroup::' >&2

# Broadcast through the mount. The keystore was unlocked at startup
# inside the daemon process, so the write is allowed.
log "broadcast via outbox confirm"
echo y > "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/pending/$STAGE/confirm"

# After the write returns, the stage moves to sent/<id>/tx_hash. The
# NFS write is synchronous wrt our in-process VFS, so we can read
# immediately.
HASH=$(cat "$MNT/wallets/$WALLET/chains/$CHAIN/outbox/sent/$STAGE/tx_hash" \
    | tr -d '\n' || true)
[[ -n "$HASH" ]] || fail "tx_hash missing after broadcast"
log "tx hash: $HASH"

# ---------- poll for receipt ----------
wait_tx_success "$MNT" "$CHAIN" "$HASH" 60 tx

# ---------- verify all receipt VFS paths are populated ----------
# `status` already proved the receipt is fetched. Now exercise every
# path the chains handler exposes under chains/<c>/tx/<hash>/ so we
# know an agent can pull the full receipt picture from the mount, not
# just the tx_hash + status.
TX_DIR="$MNT/chains/$CHAIN/tx/$HASH"
assert_tx_receipt_paths "$TX_DIR"

# ---------- assert aBaseUSDC balance ----------
AUSDC_RAW=$(cat "$MNT/chains/$CHAIN/addresses/$DEST1/tokens/$AUSDC/balance.raw" \
    | tr -d '\n' || true)
log "aBaseUSDC raw balance after supply: $AUSDC_RAW"
[[ -n "$AUSDC_RAW" && "$AUSDC_RAW" != "0" ]] \
    || fail "aBaseUSDC balance is 0 after a successful Enso route"

# ---------- live-mode unwind: keep dest1 balance-neutral ----------
# Without this, every --enso-live run permanently leaves the supplied
# aBaseUSDC at dest1, so balances drift up forever. Fork mode skips —
# anvil throws state away on container shutdown.
if [[ "$MODE" == "live" ]]; then
    log "===== unwind: redeem aBaseUSDC -> ETH via Enso ====="

    OUTBOX="$MNT/wallets/$WALLET/chains/$CHAIN/outbox"

    # Confirm a single staged tx and await its receipt. The auto-approve
    # flow may produce N stages from one DeFi session, so we wrap the
    # confirm + wait for receipt pair here. Heavy lifting (`confirm_stage_and_get_hash`,
    # `wait_receipt_status`) lives in lib.sh.
    unwind_confirm_stage() {
        local stage=$1 label=$2
        log "  $label: $stage"
        local hash
        hash=$(confirm_stage_and_get_hash "$OUTBOX" "$stage")
        [[ -n "$hash" ]] || { warn "$label: tx_hash missing after broadcast"; return 1; }
        log "  $label tx: $hash"
        wait_receipt_status "$CHAIN" "$hash" 90 || return 1
        log "  $label ✓"
    }

    # Single DeFi intent: aBaseUSDC -> ETH. Enso bundles the Aave
    # redemption (aBaseUSDC -> USDC) and the USDC -> ETH swap into one
    # routed transaction; the DeFi handler auto-prepends an `approve`
    # stage when the wallet's allowance to the router is below the
    # input amount, so a single user-facing intent produces 1-2 staged
    # txs (`approve` + `swap`, or just `swap` when allowance is already
    # set).
    AUSDC_BEFORE=$(cat "$MNT/chains/$CHAIN/addresses/$DEST1/tokens/$AUSDC/balance.raw" \
        2>/dev/null | tr -d '\n' || echo 0)
    log "  aBaseUSDC raw to redeem: $AUSDC_BEFORE"
    if [[ -z "$AUSDC_BEFORE" || "$AUSDC_BEFORE" == "0" ]]; then
        warn "aBaseUSDC balance is 0 — nothing to unwind"
    else
        unwind_pending_before=$(ls "$OUTBOX/pending" 2>/dev/null \
            | sort -u | tr '\n' '|' || true)

        intent_body=$(printf '{"intent":"swap %s %s to ETH","chain":"%s","slippage_bps":500}' \
            "$AUSDC_BEFORE" "$AUSDC" "$CHAIN")
        log "  POST defi intent: $intent_body"
        printf '%s' "$intent_body" > "$MNT/defi/intents/$WALLET/new"

        unwind_sess=$(latest_session "$WALLET")
        [[ -n "$unwind_sess" ]] || fail "unwind: no defi session created"
        log "  unwind session: $unwind_sess"

        echo '::group::unwind plan.md' >&2
        cat "$MNT/defi/intents/$WALLET/$unwind_sess/plan.md" >&2 || true
        echo '::endgroup::' >&2

        # Confirm the session. Auto-approve may produce up to 2 stages
        # (approve, swap). Budget bumps to 300s — Enso route quoting +
        # gas estimation across both stages can be slow.
        echo y > "$MNT/defi/intents/$WALLET/$unwind_sess/confirm"

        log "  waiting for staged txs (300s budget)"
        unwind_stages=
        for _ in $(seq 1 300); do
            ua=$(ls "$OUTBOX/pending" 2>/dev/null | sort -u | tr '\n' '|' || true)
            unwind_stages=$(comm -13 \
                <(printf '%s' "$unwind_pending_before" | tr '|' '\n' | sort -u) \
                <(printf '%s' "$ua"                    | tr '|' '\n' | sort -u) \
                | grep -v '^$' | sort)
            # Wait for both stages to materialise when auto-approve is
            # in play. If only the swap is staged (allowance already
            # max) one is fine.
            if [[ -n "$unwind_stages" ]]; then
                # Give the second stage one extra second to appear so
                # we don't broadcast approve before swap is queued.
                sleep 1
                ua=$(ls "$OUTBOX/pending" 2>/dev/null | sort -u | tr '\n' '|' || true)
                unwind_stages=$(comm -13 \
                    <(printf '%s' "$unwind_pending_before" | tr '|' '\n' | sort -u) \
                    <(printf '%s' "$ua"                    | tr '|' '\n' | sort -u) \
                    | grep -v '^$' | sort)
                break
            fi
            sleep 1
        done
        [[ -n "$unwind_stages" ]] || fail "unwind: no stage produced within 300s"

        # Broadcast in id order — outbox ids are monotonic so `sort`
        # gives the staged sequence.
        n_stages=$(printf '%s\n' "$unwind_stages" | wc -l | tr -d ' ')
        log "  unwind staged $n_stages tx(s)"
        i=0
        while IFS= read -r stage; do
            [[ -z "$stage" ]] && continue
            i=$((i + 1))
            label="unwind step $i/$n_stages"
            unwind_confirm_stage "$stage" "$label" \
                || fail "unwind: $label failed; aborting cleanup"
        done <<< "$unwind_stages"
    fi

    # Final assertions: balance-neutral except for gas + interest dust.
    # Public RPC providers (incl. base-rpc.publicnode.com) load-balance
    # across replicas that can be a block out of sync — the receipt is
    # served from a leading node while the next eth_call hits a lagging
    # one and returns pre-swap state. Poll until both balances converge
    # to the expected window or the budget elapses.
    log "  polling final balances (60s budget)"
    AUSDC_FINAL= USDC_FINAL=
    for _ in $(seq 1 60); do
        AUSDC_FINAL=$(cat "$MNT/chains/$CHAIN/addresses/$DEST1/tokens/$AUSDC/balance.raw" \
            2>/dev/null | tr -d '\n' || echo "")
        USDC_FINAL=$(cat "$MNT/chains/$CHAIN/addresses/$DEST1/tokens/$USDC/balance.raw" \
            2>/dev/null | tr -d '\n' || echo "")
        # aBaseUSDC accrues interest continuously, so a few raw of post-
        # withdraw dust is normal.
        if [[ -n "$AUSDC_FINAL" && -n "$USDC_FINAL" ]] \
            && (( AUSDC_FINAL <= 5 )) \
            && [[ "$USDC_FINAL" == "0" ]]; then
            break
        fi
        sleep 1
    done
    log "  final aBaseUSDC raw: $AUSDC_FINAL"
    log "  final USDC raw:     $USDC_FINAL"

    unwind_fail=0
    if [[ -z "$AUSDC_FINAL" ]] || (( AUSDC_FINAL > 5 )); then
        warn "aBaseUSDC residue '$AUSDC_FINAL' > 5 raw — cleanup incomplete"
        unwind_fail=1
    fi
    if [[ -z "$USDC_FINAL" || "$USDC_FINAL" != "0" ]]; then
        warn "USDC residue '$USDC_FINAL' != 0 — cleanup incomplete"
        unwind_fail=1
    fi
    [[ "$unwind_fail" -eq 0 ]] || fail "unwind did not return dest1 to balance-neutral"
    log "===== unwind PASSED — dest1 balance-neutral ====="
fi

log "===== Enso -> Aave integration test PASSED ====="
exit 0
