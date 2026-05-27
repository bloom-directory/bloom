//! # bloom-chain-state
//!
//! Accounts, per-contract storage, code store, object ownership, VFS,
//! xDSA key registry, and state-blob store for bloom-chain v0.
//!
//! ## Architecture
//!
//! ```text
//! State
//! |-- AccountsTrie  (BTreeMap-backed commitment, domain: accounts_root)
//! |-- BTreeMap<Address, StorageTrie>  (per-contract, domain: storage_key)
//! |-- CodeStore  (content-addressed wasm, domain: code_root)
//! |-- Object map and OwnershipIndex  (PTB/object commitments)
//! |-- VFS bindings  (path -> petal hash commitments)
//! `-- xDSA key registry  (address -> composite public key commitments)
//! ```
//!
//! `State::state_root()` commits to:
//!
//! ```text
//! blake3_tagged(
//!     "state_root:",
//!     accounts_root || code_root || object_root || ownership_index_root ||
//!     vfs_root || key_registry_root
//! )
//! ```
//!
//! See [`state`] for the snapshot/commit API and [`blob`] for serialisation.

#![forbid(unsafe_code)]

pub mod account;
pub mod accounts;
pub mod blob;
pub mod code_store;
pub mod error;
pub mod state;
pub mod storage;
pub mod trie;

// Convenience re-exports
pub use account::Account;
pub use accounts::AccountsTrie;
pub use blob::BlobStore;
pub use code_store::CodeStore;
pub use error::StateError;
pub use state::{State, StateSnapshot, WriteSet};
pub use storage::StorageTrie;
pub use trie::{Trie, TrieKind};
