//! Multi-validator bloom-chain harness for integration tests.
//!
//! This module is now a thin re-export of [`bloom_test_util::provision`],
//! which is the single source of truth for testnet provisioning and
//! validator-process management. Kept as a stable import path for
//! `bloom-it` tests (`chain_smoke`, `chain_testnet_provision`, etc).

pub use bloom_test_util::provision::{
    ChainNodeConfig, ChainNodeGuard, bloom_bin, pick_free_port, provision_network, spawn_validator,
};
