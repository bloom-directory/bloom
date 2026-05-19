//! # bloom-chain-state
//!
//! Accounts trie, per-contract storage tries, code store, and state-blob
//! store for bloom-chain v0.
//!
//! ## Architecture
//!
//! ```text
//! State
//! ├── AccountsTrie  (BTreeMap-backed sparse Merkle, domain: accounts_root)
//! ├── BTreeMap<Address, StorageTrie>  (per-contract, domain: storage_key)
//! └── CodeStore  (content-addressed wasm, domain: code_root)
//! ```
//!
//! `State::state_root()` = `blake3_tagged("state_root:", accounts_root || code_root)`
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
