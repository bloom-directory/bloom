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

pub mod abi;
pub mod chain_vm;
pub mod error;
pub mod handler;
pub mod host;
pub mod meta;
pub mod policy;
pub mod private_store;
pub mod registry;
pub mod router;
pub mod runner;
pub mod store;
pub mod vm;

pub use abi::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse, HttpRequest,
    HttpResponse, SignRequest, decode_dispatch_request, decode_dispatch_response,
    decode_http_request, decode_http_response, decode_sign_request, decode_string_list,
    encode_dispatch_request, encode_dispatch_response, encode_http_request, encode_http_response,
    encode_sign_request, encode_string_list,
};
pub use chain_vm::{BlockCtx, ChainCallInput, ChainCallOutput, ChainCtx, ChainEntry, LogEntry};
pub use error::PetalError;
pub use handler::PetalsHandler;
pub use host::{DenyHost, HostError, PetalHost};
pub use meta::{Capability, PetalMeta, PetalMode};
pub use policy::NetPolicy;
pub use private_store::PrivateStore;
pub use registry::{NameRegistry, validate_name};
pub use router::PetalRouter;
pub use runner::{LateVfsHost, PetalRunner, VfsHost};
pub use store::{InstallResult, PetalStore};
pub use vm::{PetalVm, RunOptions, RunOutput};
