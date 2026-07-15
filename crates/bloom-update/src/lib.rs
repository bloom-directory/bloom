//! Background checker for newer `bloom` releases on GitHub.
//!
//! Public surface:
//! - [`UpdateSnapshot`] / [`UpdateStatus`] / [`UpdateAvailable`]: the
//!   immutable view of "what do we know about the latest release".
//! - [`UpdateChecker`]: a clone-cheap, Arc-shareable object that holds
//!   the snapshot, owns the `reqwest::Client`, and can spawn a
//!   background tokio task that refreshes every 5 minutes.
//! - [`parse_semver`] / [`compare_semver`]: tiny semver helpers that
//!   avoid pulling in the `semver` crate.
//!
//! The crate is intentionally network- and cache-only; it knows nothing
//! about the daemon, the VFS, or the CLI. Wiring it into the rest of
//! the workspace is the consumer's job (see `crates/bloom-daemon` and
//! `crates/bloom/src/main.rs`).

#![forbid(unsafe_code)]

pub mod cache;
pub mod checker;
pub mod semver;
pub mod snapshot;

pub use checker::UpdateChecker;
pub use checker::read_cache_only;
pub use semver::{compare_semver, parse_semver};
pub use snapshot::{UpdateAvailable, UpdateSnapshot, UpdateStatus};
