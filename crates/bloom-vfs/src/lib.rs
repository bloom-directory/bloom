//! VFS path router for bloom.
//!
//! This crate translates POSIX-ish path operations (lookup, read, write,
//! list) into calls against the underlying engines (chain, keystore, tx,
//! tools). It is transport-agnostic — the NFS mount adapter
//! (`bloom-mount`) and the CLI (`bloom`) both call into [`Vfs`] directly.
//!
//! Path semantics follow §3 of the bloom spec. Top-level segments:
//!
//! - `chains/<chain>/...` — read-only chain views
//! - `wallets/<wallet>/...` — managed wallets, including the outbox
//! - `petals/...` — installed application surfaces such as the Enso Petal
//! - `watch/...` — subscriptions (stub)
//! - `tools/...` — pure helpers (keccak, checksum, units)
//! - `status/...` — daemon health
//! - `docs/...` — vendored docs

#![forbid(unsafe_code)]

pub mod cache;
pub mod exact_signing;
pub mod handler;
pub mod handlers;
pub mod operation_index;
pub mod paginate;
pub mod path;
pub mod planning;
pub mod router;
#[cfg(test)]
pub(crate) mod test_support;

pub use cache::PathCache;
pub use exact_signing::{BrokerExactPayloadSigner, ExactPayloadBatchOutcome, ExactPayloadOutcome};
pub use handler::{
    Entry, EntryKind, Handler, HandlerError, entry_for_fs_path, entry_from_fs_dir_entry,
    entry_from_fs_metadata, fs_path_modified,
};
pub use handlers::status::{UpdateAvailable, UpdateSnapshot};
pub use operation_index::{FileOperationIndex, OperationIndex};
pub use paginate::{PAGE_SIZE, Projection, page_indices, page_name, page_slice, parse_page_name};
pub use path::{PercentDecodeError, VfsPath, percent_decode_segment};
pub use planning::{advisory_evm_policy, advisory_paid_http_policy};
pub use router::Vfs;
