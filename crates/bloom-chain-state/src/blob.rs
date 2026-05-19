//! Content-addressed state-blob storage (spec §6.3).
//!
//! # Blob format
//!
//! A state blob is a hand-rolled binary encoding (not full SSZ) of:
//!
//! ```text
//! blob = header || accounts_section || storage_section || code_section
//!
//! header:
//!   magic:       [u8; 8]  = b"BLMSTATE"
//!   version:     u8       = 0
//!   height:      u64 LE
//!   state_root:  [u8; 32]
//!   parent_hash: [u8; 32]
//!
//! accounts_section:
//!   count: u32 LE
//!   for each:
//!     key:   [u8; 32]
//!     value: [u8; Account::SSZ_LEN]   (89 bytes)
//!
//! storage_section:
//!   addr_count: u32 LE
//!   for each address:
//!     addr:       [u8; 32]
//!     slot_count: u32 LE
//!     for each slot:
//!       key:   [u8; 32]
//!       value: [u8; 32]
//!
//! code_section:
//!   count: u32 LE
//!   for each:
//!     hash:      [u8; 32]
//!     wasm_len:  u32 LE
//!     wasm:      [u8; wasm_len]
//! ```
//!
//! The blob hash is `blake3_tagged(tags::PETAL, &blob_bytes)` — we reuse the
//! PETAL domain for content-addressed opaque bytes (the blob itself is not wasm,
//! but the hash is content-addressed by the same scheme).
//!
//! # `BlobStore`
//!
//! The `BlobStore` uses a `sled` database (or an in-memory `BTreeMap` via
//! `BlobStore::in_memory()`) keyed by blob hash, retaining only the last 256
//! entries (FIFO pruning, spec §6.3).

use std::collections::VecDeque;

use bloom_chain_types::{
    Address, Hash32,
    digest::{blake3_tagged, tags},
};
use ssz::Encode;

use crate::{
    account::Account,
    error::StateError,
    state::State,
};

const MAGIC: &[u8; 8] = b"BLMSTATE";
const VERSION: u8 = 0;

/// Maximum number of blobs retained in the store (spec §6.3).
pub const MAX_RETAINED_BLOBS: usize = 256;

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u32_le(buf: &[u8], off: &mut usize) -> Result<u32, StateError> {
    if buf.len() < *off + 4 {
        return Err(StateError::BlobDecode("unexpected EOF reading u32".into()));
    }
    let v = u32::from_le_bytes(buf[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64_le(buf: &[u8], off: &mut usize) -> Result<u64, StateError> {
    if buf.len() < *off + 8 {
        return Err(StateError::BlobDecode("unexpected EOF reading u64".into()));
    }
    let v = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn read_bytes32(buf: &[u8], off: &mut usize) -> Result<[u8; 32], StateError> {
    if buf.len() < *off + 32 {
        return Err(StateError::BlobDecode("unexpected EOF reading [u8;32]".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&buf[*off..*off + 32]);
    *off += 32;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// State serialization
// ---------------------------------------------------------------------------

impl State {
    /// Serialize the full state to a content-addressed blob.
    ///
    /// Returns `(blob_bytes, blob_hash)`.
    pub fn to_blob(&self, height: u64, parent_block_hash: Hash32) -> (Vec<u8>, Hash32) {
        let state_root = self.state_root();
        let mut buf = Vec::new();

        // --- Header ---
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        push_u64_le(&mut buf, height);
        buf.extend_from_slice(&state_root.0);
        buf.extend_from_slice(&parent_block_hash.0);

        // --- Accounts section ---
        let accounts: Vec<_> = self.accounts.iter().collect();
        push_u32_le(&mut buf, accounts.len() as u32);
        for (addr, account) in &accounts {
            buf.extend_from_slice(&addr.0);
            buf.extend_from_slice(&account.as_ssz_bytes());
        }

        // --- Storage section ---
        let storage_entries: Vec<_> = self.storage.iter().collect();
        push_u32_le(&mut buf, storage_entries.len() as u32);
        for (addr, trie) in &storage_entries {
            buf.extend_from_slice(&addr.0);
            let slots: Vec<_> = trie.iter().collect();
            push_u32_le(&mut buf, slots.len() as u32);
            for (key, val_slice) in &slots {
                buf.extend_from_slice(*key);
                // val_slice is 32 bytes (storage trie stores [u8;32])
                if val_slice.len() == 32 {
                    buf.extend_from_slice(val_slice);
                } else {
                    // Should never happen; pad/truncate defensively
                    let mut padded = [0u8; 32];
                    let n = val_slice.len().min(32);
                    padded[..n].copy_from_slice(&val_slice[..n]);
                    buf.extend_from_slice(&padded);
                }
            }
        }

        // --- Code section ---
        let code_entries: Vec<_> = self.code.iter().collect();
        push_u32_le(&mut buf, code_entries.len() as u32);
        for (hash, wasm) in &code_entries {
            buf.extend_from_slice(*hash);
            push_u32_le(&mut buf, wasm.len() as u32);
            buf.extend_from_slice(wasm);
        }

        let hash = blake3_tagged(tags::PETAL, &buf);
        (buf, hash)
    }

    /// Deserialize a state blob and verify its state root.
    pub fn from_blob(bytes: &[u8], expected_state_root: Hash32) -> Result<State, StateError> {
        // --- Header ---
        if bytes.len() < 8 {
            return Err(StateError::BlobDecode("blob too short for magic".into()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(StateError::BlobDecode("invalid magic bytes".into()));
        }
        let mut off = 8;

        if bytes.len() <= off {
            return Err(StateError::BlobDecode("blob too short for version".into()));
        }
        let version = bytes[off];
        off += 1;
        if version != VERSION {
            return Err(StateError::BlobDecode(format!("unsupported version: {version}")));
        }

        let _height = read_u64_le(bytes, &mut off)?;
        let state_root_bytes = read_bytes32(bytes, &mut off)?;
        let _parent_hash = read_bytes32(bytes, &mut off)?;

        let stored_root = Hash32(state_root_bytes);
        if stored_root != expected_state_root {
            return Err(StateError::RootMismatch {
                expected: format!("{expected_state_root}"),
                actual: format!("{stored_root}"),
            });
        }

        let mut state = State::new();

        // --- Accounts section ---
        let account_count = read_u32_le(bytes, &mut off)? as usize;
        for _ in 0..account_count {
            let addr_bytes = read_bytes32(bytes, &mut off)?;
            if bytes.len() < off + Account::SSZ_LEN {
                return Err(StateError::BlobDecode("unexpected EOF reading account".into()));
            }
            let account = Account::from_ssz_bytes_impl(&bytes[off..off + Account::SSZ_LEN])
                .map_err(|e| StateError::Ssz(format!("{e:?}")))?;
            off += Account::SSZ_LEN;
            state.set_account(Address(addr_bytes), account);
        }

        // --- Storage section ---
        let addr_count = read_u32_le(bytes, &mut off)? as usize;
        for _ in 0..addr_count {
            let addr_bytes = read_bytes32(bytes, &mut off)?;
            let addr = Address(addr_bytes);
            let slot_count = read_u32_le(bytes, &mut off)? as usize;
            for _ in 0..slot_count {
                let key = read_bytes32(bytes, &mut off)?;
                let val = read_bytes32(bytes, &mut off)?;
                state.storage_write(addr, key, val);
            }
        }

        // --- Code section ---
        let code_count = read_u32_le(bytes, &mut off)? as usize;
        for _ in 0..code_count {
            let _hash = read_bytes32(bytes, &mut off)?;
            let wasm_len = read_u32_le(bytes, &mut off)? as usize;
            if bytes.len() < off + wasm_len {
                return Err(StateError::BlobDecode("unexpected EOF reading wasm".into()));
            }
            state.insert_code(&bytes[off..off + wasm_len]);
            off += wasm_len;
        }

        // Verify that reconstructed root matches
        let actual_root = state.state_root();
        if actual_root != expected_state_root {
            return Err(StateError::RootMismatch {
                expected: format!("{expected_state_root}"),
                actual: format!("{actual_root}"),
            });
        }

        Ok(state)
    }
}

// Provide a helper to call Account's SSZ decode from here without importing ssz::Decode trait
// publicly (we already import it via Account's impl).
trait FromSszBytesHelper: Sized {
    fn from_ssz_bytes_impl(bytes: &[u8]) -> Result<Self, ssz::DecodeError>;
}

impl FromSszBytesHelper for Account {
    fn from_ssz_bytes_impl(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        use ssz::Decode;
        Account::from_ssz_bytes(bytes)
    }
}

// ---------------------------------------------------------------------------
// BlobStore
// ---------------------------------------------------------------------------

/// Backend selector for `BlobStore`.
enum BlobStoreBackend {
    InMemory(std::collections::BTreeMap<[u8; 32], Vec<u8>>),
    Sled(sled::Db),
}

/// Content-addressed blob store with 256-entry FIFO retention (spec §6.3).
pub struct BlobStore {
    backend: BlobStoreBackend,
    /// Ordered insertion log (oldest first) — used for FIFO pruning.
    insertion_order: VecDeque<[u8; 32]>,
}

impl BlobStore {
    /// Create an in-memory blob store (for tests and ephemeral nodes).
    pub fn in_memory() -> Self {
        Self {
            backend: BlobStoreBackend::InMemory(std::collections::BTreeMap::new()),
            insertion_order: VecDeque::new(),
        }
    }

    /// Open a sled-backed blob store at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, StateError> {
        let db = sled::open(path)
            .map_err(|e| StateError::BlobStore(format!("sled open: {e}")))?;

        // Rebuild insertion order from sled (alphabetic key order ≠ insertion order,
        // so we cannot fully recover order after restart — we start fresh).
        // In practice the node tracks blob retention via the state_index; this is
        // sufficient for v0.
        let store = Self {
            backend: BlobStoreBackend::Sled(db),
            insertion_order: VecDeque::new(),
        };
        Ok(store)
    }

    /// Insert a blob (raw bytes + its hash).  Prunes oldest entries beyond 256.
    pub fn insert(&mut self, hash: Hash32, blob: Vec<u8>) -> Result<(), StateError> {
        match &mut self.backend {
            BlobStoreBackend::InMemory(map) => {
                map.insert(hash.0, blob);
            }
            BlobStoreBackend::Sled(db) => {
                db.insert(hash.0, blob)
                    .map_err(|e| StateError::BlobStore(format!("sled insert: {e}")))?;
            }
        }

        // Track insertion order for pruning
        if !self.insertion_order.contains(&hash.0) {
            self.insertion_order.push_back(hash.0);
        }

        // Prune if over limit
        while self.insertion_order.len() > MAX_RETAINED_BLOBS {
            if let Some(oldest) = self.insertion_order.pop_front() {
                match &mut self.backend {
                    BlobStoreBackend::InMemory(map) => {
                        map.remove(&oldest);
                    }
                    BlobStoreBackend::Sled(db) => {
                        let _ = db.remove(oldest);
                    }
                }
            }
        }

        Ok(())
    }

    /// Retrieve a blob by hash.
    pub fn get(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, StateError> {
        match &self.backend {
            BlobStoreBackend::InMemory(map) => Ok(map.get(&hash.0).cloned()),
            BlobStoreBackend::Sled(db) => {
                let ivec = db
                    .get(hash.0)
                    .map_err(|e| StateError::BlobStore(format!("sled get: {e}")))?;
                Ok(ivec.map(|v| v.to_vec()))
            }
        }
    }

    /// Number of blobs currently stored.
    pub fn len(&self) -> usize {
        self.insertion_order.len()
    }

    /// True iff the store is empty.
    pub fn is_empty(&self) -> bool {
        self.insertion_order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use bloom_chain_types::Address;

    fn make_state() -> State {
        let mut s = State::new();
        s.set_account(
            Address([1u8; 32]),
            Account {
                nonce: 1,
                loom: 1000,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
            },
        );
        s.insert_code(b"fake wasm bytes");
        s.storage_write(Address([2u8; 32]), [3u8; 32], [4u8; 32]);
        s
    }

    #[test]
    fn blob_roundtrip() {
        let state = make_state();
        let expected_root = state.state_root();
        let (blob, _hash) = state.to_blob(10, Hash32([0xAB; 32]));
        let recovered = State::from_blob(&blob, expected_root).expect("roundtrip failed");
        assert_eq!(recovered.state_root(), expected_root);
    }

    #[test]
    fn blob_rejects_root_mismatch() {
        let state = make_state();
        let (blob, _hash) = state.to_blob(10, Hash32([0xAB; 32]));
        let wrong_root = Hash32([0xFF; 32]);
        assert!(State::from_blob(&blob, wrong_root).is_err());
    }

    #[test]
    fn blob_store_retention() {
        let mut store = BlobStore::in_memory();
        for i in 0u32..300 {
            let hash = Hash32(blake3::hash(&i.to_le_bytes()).into());
            store.insert(hash, vec![i as u8]).unwrap();
        }
        assert_eq!(store.len(), MAX_RETAINED_BLOBS);
    }
}
