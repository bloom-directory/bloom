//! `bloom-petal-it` — integration test harness for the bloom-native
//! contracts framework.
//!
//! This crate is **not** published and contains no production code;
//! everything lives in `src/harness.rs` (a shared test helper module)
//! and the integration test files under `tests/`.
//!
//! # Test strategy
//!
//! All tests use the in-process `ChainPetalExecutor` / `ChainPetalExecutorWithManifests`
//! harness, WAT-based inline petals (no wasm32 compilation at test
//! time), and a freshly built `State` seeded via `build_state`.  The
//! full fungible petal wasm is NOT required; we exercise the §16.2
//! host-import surface directly through small WAT fixtures.
//!
//! [`harness`]: crate::harness

#![forbid(unsafe_code)]

pub mod harness;
