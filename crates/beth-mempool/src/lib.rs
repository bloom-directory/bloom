//! Mempool observability + private orderflow + MEV heuristic.
//!
//! See `docs/specs/2026-05-12-mempool-and-private-orderflow-design.md`.

pub mod bump;
pub mod heuristic;
pub mod index;
pub mod private;
pub mod provider;
pub mod stream;

// pub use re-exports added as types land in later tasks (Tasks 1.2–1.7).
