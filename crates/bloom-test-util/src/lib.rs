//! Shared scaffolding for bloom-eth integration tests.
//!
//! Centralises validator/block/tx builders, multi-validator orchestration,
//! RPC polling helpers, and mock handlers so each test crate no longer
//! reinvents its own variants. See `docs/reviews/2026-05-19-testing-unification.md`
//! for the binding contract.
//!
//! This crate is a dev-dependency only. It deliberately does NOT depend on
//! `bloom-chain-node` (which would cycle when chain-node tests import this
//! crate). The `compute_txs_root` / block-validation logic from chain-node
//! is mirrored in [`blocks::txs_root`] with a parity test in
//! `crates/bloom-chain-node/tests/test_util_parity.rs` (added in Phase 1).

pub mod blocks;
pub mod mocks;
pub mod multi_sm;
pub mod provision;
pub mod rpc;
pub mod txs;
pub mod validators;

// Re-exports for convenience: a test file can `use bloom_test_util::{...}`
// instead of reaching into module paths for the common helpers.
pub use blocks::{BlockBuilder, txs_root};
pub use mocks::TestSigner;
pub use multi_sm::MultiValidatorMailbox;
pub use provision::{
    ChainNodeConfig, ChainNodeGuard, bloom_bin, pick_free_port, provision_network, spawn_validator,
};
pub use rpc::wait_for_socket;
pub use txs::{make_mempool_tx, make_signed_deploy_tx};
pub use validators::{
    TestValidator, make_addr, make_addr_derived, make_validator_set_fake,
    make_validator_set_signed, make_validator_with_keypair,
};
