//! `bloom-petal-dex-it` — integration tests for the bloom DEX petal suite.
//!
//! This crate exercises the pool + cpmm + router petals through the in-process
//! PTB harness, using inline WAT proxy petals (no wasm32 compilation required).
//!
//! # Test strategy
//!
//! All tests use the in-process `ChainPetalExecutorWithManifests` harness,
//! WAT-based inline petals, and a freshly built `State` seeded via
//! `dex_harness::build_state`. Real wasm petal loading is marked `#[ignore]`
//! with a TODO referencing a follow-up task to wire real wasm.
//!
//! [`dex_harness`]: crate::dex_harness

#![forbid(unsafe_code)]

pub mod dex_harness;
