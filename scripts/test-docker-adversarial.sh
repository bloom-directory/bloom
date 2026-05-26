#!/usr/bin/env bash
# Dockerized adversarial private-testnet readiness gate.
#
# This is the acceptance suite for docs/reviews/2026-05-26-branch-vs-master-private-testnet-review.md.
# It combines fast adversarial cargo tests for malformed consensus/execution/RPC
# inputs with the live 4-validator docker DeX stack. The docker leg provisions a
# clean network, exercises DeX adversarial PTBs over RPC, restarts a validator,
# and proves catch-up convergence before tearing the stack down.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"

log() { printf '\033[1;31m[docker-adversarial]\033[0m %s\n' "$*"; }

require_cmd cargo docker
detect_docker_compose

cd "$REPO_ROOT"

log "consensus/block validity: malformed sync blocks, proposer, commit votes"
cargo test -p bloom-chain-node --test block_sync_validation

log "execution commitments: state_root, receipts_root, fuel_used, block fuel limit"
cargo test -p bloom-chain-node --test execution_commitment_validation

log "restart/snapshot recovery: checkpoint restore, suffix replay, missing blocks"
cargo test -p bloom-chain-node --test restart_replay
cargo test -p bloom-chain-state --test blob

log "bounded RPC/decode and PTB gas/signature/admission checks"
cargo test -p bloom-chain-node rpc -- --nocapture
cargo test -p bloom-chain-node submit_tx_params -- --nocapture
cargo test -p bloom-chain-node --test ptb_gas_reservation
cargo test -p bloom-chain-node --test ptb_signature_rejection
cargo test -p bloom-chain-node --test petal_admission
cargo test -p bloom-script --lib

log "DeX adversarial in-process coverage: cross-pool LP, stale versions, slippage, exact-out"
cargo test -p bloom-dex-math
cargo test -p bloom-petal-dex-pool
cargo test -p bloom-petal-dex-it --test real_wasm_pool \
  real_pool_cross_pool_lp_remove_reverts_without_state_change -- --ignored --nocapture
cargo test -p bloom-petal-dex-it --test real_wasm_pool \
  real_pool_stale_shared_pool_version_and_sandwich_slippage_revert -- --ignored --nocapture
cargo test -p bloom-petal-dex-it --test real_wasm_pool \
  real_pool_add_remove_and_exact_out_execute -- --ignored --nocapture
cargo test -p bloom-petal-dex-it --test real_wasm_pool \
  real_pool_high_fee_exact_out_executes -- --ignored --nocapture

log "live docker network: clean 4-validator DeX adversarial acceptance + restart/catch-up"
BLOOM_DOCKER_COMPOSE_UP=1 "$REPO_ROOT/scripts/test-docker-petal-dex.sh"

log "adversarial readiness suite passed"
