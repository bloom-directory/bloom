//! Content-addressed wasm petals for bloom.
//!
//! Petals are wasm modules stored under `~/.bloom/petals/objects/<hash>`
//! with metadata in `~/.bloom/petals/meta/<hash>.json` and a
//! petname → hash registry in `~/.bloom/petals/names.toml`. The
//! [`PetalsHandler`] exposes them as a subtree of the bloom VFS at
//! `public/`; the [`PetalVm`] runs them with WASI stdio and an
//! optional `bloom` host module (`vfs_read` / `vfs_write`) gated by
//! per-petal capabilities.
//!
//! The `chain_vm` module provides `PetalMode::Chain` for deterministic
//! smart-contract execution under bloom-chain BFT consensus (chain spec
//! §7.5–§7.9).

#![forbid(unsafe_code)]

pub mod chain_vm;
pub mod error;
pub mod handler;
pub mod host;
pub mod meta;
pub mod registry;
pub mod runner;
pub mod store;
pub mod vm;

pub use chain_vm::{BlockCtx, ChainCallInput, ChainCallOutput, ChainCtx, ChainEntry, LogEntry};
pub use error::PetalError;
pub use handler::PetalsHandler;
pub use host::{HostError, PetalHost};
pub use meta::{Capability, PetalMeta, PetalMode};
pub use registry::{NameRegistry, validate_name};
pub use runner::{PetalRunner, VfsHost};
pub use store::{InstallResult, PetalStore};
pub use vm::{PetalVm, RunOptions, RunOutput};
