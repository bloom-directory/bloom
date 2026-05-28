//! Content-addressed state-blob storage (spec §6.3).
//!
//! # Blob format
//!
//! A state blob is a hand-rolled binary encoding (not full SSZ) of:
//!
//! ```text
//! blob = header || accounts_section || storage_section || code_section
//!      || objects_section || ownership_section || vfs_section || key_registry_section
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
//!
//! objects_section:
//!   count: u32 LE
//!   for each:
//!     id:      [u8; 32]
//!     obj_len: u32 LE
//!     object:  canonical Object bytes
//!
//! ownership_section:
//!   count: u32 LE
//!   for each:
//!     key:       [u8; 33]   (owner_kind || owner_id)
//!     id_count:  u32 LE
//!     ids:       id_count * [u8; 32]
//!
//! vfs_section:
//!   count: u32 LE
//!   for each:
//!     path_len: u32 LE
//!     path:     UTF-8 bytes
//!     hash:     [u8; 32]
//!
//! key_registry_section:
//!   count: u32 LE
//!   for each:
//!     address:    [u8; 32]
//!     pubkey_len: u32 LE
//!     pubkey:     pubkey_len bytes
//! ```
//!
//! The blob hash is `blake3_tagged(STATE_BLOB_HASH_TAG, &blob_bytes)`.
//!
//! # `BlobStore`
//!
//! The `BlobStore` uses a `sled` database (or an in-memory `BTreeMap` via
//! `BlobStore::in_memory()`) keyed by blob hash, retaining only the last 256
//! entries (FIFO pruning, spec §6.3).

use std::collections::VecDeque;

use bloom_chain_types::{Address, Hash32, digest::blake3_tagged, types::PubKeyBytes};
use bloom_objects::{Object, ObjectId, OwnershipIndexKey};
use ssz::Encode;

use crate::{account::Account, error::StateError, state::State};

const MAGIC: &[u8; 8] = b"BLMSTATE";
const VERSION: u8 = 1;
pub const STATE_BLOB_HASH_TAG: &str = "bloom-chain.v0.state_blob:";

/// Maximum number of blobs retained in the store (spec §6.3).
pub const MAX_RETAINED_BLOBS: usize = 256;
/// Maximum accepted state blob size. Matches the transport frame payload cap.
pub const MAX_STATE_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 1_000_000;
const MAX_STORAGE_ADDRS: usize = 1_000_000;
const MAX_STORAGE_SLOTS_PER_ADDR: usize = 1_000_000;
const MAX_CODE_ENTRIES: usize = 100_000;
const MAX_CODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_OWNERSHIP_ROWS: usize = 1_000_000;
const MAX_OWNERSHIP_IDS_PER_ROW: usize = 1_000_000;
const MAX_VFS_ENTRIES: usize = 100_000;
const MAX_VFS_PATH_BYTES: usize = 4096;
const MAX_KEY_REGISTRY_ENTRIES: usize = 1_000_000;
const MAX_PUBKEY_BYTES: usize = 4096;

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
        return Err(StateError::BlobDecode(
            "unexpected EOF reading [u8;32]".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&buf[*off..*off + 32]);
    *off += 32;
    Ok(arr)
}

fn read_exact<'a>(buf: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], StateError> {
    if buf.len() < *off + len {
        return Err(StateError::BlobDecode(format!(
            "unexpected EOF reading {len} bytes"
        )));
    }
    let out = &buf[*off..*off + len];
    *off += len;
    Ok(out)
}

fn remaining(buf: &[u8], off: usize) -> usize {
    buf.len().saturating_sub(off)
}

fn read_count_le(
    buf: &[u8],
    off: &mut usize,
    section: &str,
    max_count: usize,
    min_bytes_per_item: usize,
) -> Result<usize, StateError> {
    let count = read_u32_le(buf, off)? as usize;
    if count > max_count {
        return Err(StateError::BlobDecode(format!(
            "{section} count {count} exceeds cap {max_count}"
        )));
    }
    if let Some(max_possible) = remaining(buf, *off).checked_div(min_bytes_per_item)
        && count > max_possible
    {
        return Err(StateError::BlobDecode(format!(
            "{section} count {count} exceeds remaining bytes"
        )));
    }
    Ok(count)
}

fn read_len_le(
    buf: &[u8],
    off: &mut usize,
    section: &str,
    max_len: usize,
) -> Result<usize, StateError> {
    let len = read_u32_le(buf, off)? as usize;
    if len > max_len {
        return Err(StateError::BlobDecode(format!(
            "{section} length {len} exceeds cap {max_len}"
        )));
    }
    if len > remaining(buf, *off) {
        return Err(StateError::BlobDecode(format!(
            "{section} length {len} exceeds remaining bytes"
        )));
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// State serialization
// ---------------------------------------------------------------------------

impl State {
    /// Compute the content-addressed hash of canonical state-blob bytes.
    pub fn blob_hash(bytes: &[u8]) -> Hash32 {
        blake3_tagged(STATE_BLOB_HASH_TAG, bytes)
    }

    /// Read the canonical state-blob header without materializing the full state.
    ///
    /// Returns `(height, state_root, parent_block_hash)`.
    pub fn blob_header(bytes: &[u8]) -> Result<(u64, Hash32, Hash32), StateError> {
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
            return Err(StateError::BlobDecode(format!(
                "unsupported version: {version}"
            )));
        }

        let height = read_u64_le(bytes, &mut off)?;
        let state_root = Hash32(read_bytes32(bytes, &mut off)?);
        let parent_block_hash = Hash32(read_bytes32(bytes, &mut off)?);
        Ok((height, state_root, parent_block_hash))
    }

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

        // --- Objects section ---
        let object_entries: Vec<_> = self.objects.iter().collect();
        push_u32_le(&mut buf, object_entries.len() as u32);
        for (id, obj) in &object_entries {
            buf.extend_from_slice(&id.0);
            let encoded = obj
                .encode_canonical()
                .expect("Object canonical encoding is infallible for in-state records");
            push_u32_le(&mut buf, encoded.len() as u32);
            buf.extend_from_slice(&encoded);
        }

        // --- Ownership section ---
        let ownership_entries: Vec<_> = self.ownership.iter().collect();
        push_u32_le(&mut buf, ownership_entries.len() as u32);
        for (key, ids) in &ownership_entries {
            buf.extend_from_slice(&key.encode());
            let mut sorted = (*ids).clone();
            sorted.sort_unstable();
            sorted.dedup();
            push_u32_le(&mut buf, sorted.len() as u32);
            for id in sorted {
                buf.extend_from_slice(&id.0);
            }
        }

        // --- VFS section ---
        let vfs_entries: Vec<_> = self.vfs.iter().collect();
        push_u32_le(&mut buf, vfs_entries.len() as u32);
        for (path, hash) in &vfs_entries {
            let path_bytes = path.as_bytes();
            push_u32_le(&mut buf, path_bytes.len() as u32);
            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(&hash.0);
        }

        // --- Key registry section ---
        let key_entries: Vec<_> = self.key_registry.iter().collect();
        push_u32_le(&mut buf, key_entries.len() as u32);
        for (addr, pubkey) in &key_entries {
            buf.extend_from_slice(&addr.0);
            push_u32_le(&mut buf, pubkey.0.len() as u32);
            buf.extend_from_slice(&pubkey.0);
        }

        let hash = Self::blob_hash(&buf);
        (buf, hash)
    }

    /// Deserialize a state blob and verify its state root.
    pub fn from_blob(bytes: &[u8], expected_state_root: Hash32) -> Result<State, StateError> {
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(StateError::BlobDecode(format!(
                "state blob is {} bytes, exceeds cap {}",
                bytes.len(),
                MAX_STATE_BLOB_BYTES
            )));
        }
        // --- Header ---
        let (_, stored_root, _) = Self::blob_header(bytes)?;
        let mut off = 8 + 1 + 8 + 32 + 32;

        if stored_root != expected_state_root {
            return Err(StateError::RootMismatch {
                expected: format!("{expected_state_root}"),
                actual: format!("{stored_root}"),
            });
        }

        let mut state = State::new();

        // --- Accounts section ---
        let account_count = read_count_le(
            bytes,
            &mut off,
            "accounts",
            MAX_ACCOUNTS,
            32 + Account::SSZ_LEN,
        )?;
        for _ in 0..account_count {
            let addr_bytes = read_bytes32(bytes, &mut off)?;
            if bytes.len() < off + Account::SSZ_LEN {
                return Err(StateError::BlobDecode(
                    "unexpected EOF reading account".into(),
                ));
            }
            let account = Account::from_ssz_bytes_impl(&bytes[off..off + Account::SSZ_LEN])
                .map_err(|e| StateError::Ssz(format!("{e:?}")))?;
            off += Account::SSZ_LEN;
            state.set_account(Address(addr_bytes), account);
        }

        // --- Storage section ---
        let addr_count =
            read_count_le(bytes, &mut off, "storage addresses", MAX_STORAGE_ADDRS, 36)?;
        for _ in 0..addr_count {
            let addr_bytes = read_bytes32(bytes, &mut off)?;
            let addr = Address(addr_bytes);
            let slot_count = read_count_le(
                bytes,
                &mut off,
                "storage slots",
                MAX_STORAGE_SLOTS_PER_ADDR,
                64,
            )?;
            for _ in 0..slot_count {
                let key = read_bytes32(bytes, &mut off)?;
                let val = read_bytes32(bytes, &mut off)?;
                state.storage_write(addr, key, val);
            }
        }

        // --- Code section ---
        let code_count = read_count_le(bytes, &mut off, "code", MAX_CODE_ENTRIES, 36)?;
        for _ in 0..code_count {
            let hash = Hash32(read_bytes32(bytes, &mut off)?);
            let wasm_len = read_len_le(bytes, &mut off, "code bytes", MAX_CODE_BYTES)?;
            let wasm = read_exact(bytes, &mut off, wasm_len)?;
            let inserted_hash = state.insert_code(wasm);
            if inserted_hash != hash {
                return Err(StateError::BlobDecode(format!(
                    "code hash mismatch: stored={} actual={}",
                    hash, inserted_hash
                )));
            }
        }

        // --- Objects section ---
        let object_count = read_count_le(bytes, &mut off, "objects", MAX_OBJECTS, 36)?;
        for _ in 0..object_count {
            let id = ObjectId(read_bytes32(bytes, &mut off)?);
            let obj_len = read_len_le(bytes, &mut off, "object bytes", MAX_OBJECT_BYTES)?;
            let obj_bytes = read_exact(bytes, &mut off, obj_len)?;
            let obj = Object::decode_canonical(obj_bytes)
                .map_err(|e| StateError::BlobDecode(format!("object decode: {e}")))?;
            if obj.id != id {
                return Err(StateError::BlobDecode("object id/key mismatch".into()));
            }
            state.set_object(obj);
        }

        // --- Ownership section ---
        let ownership_count = read_count_le(bytes, &mut off, "ownership", MAX_OWNERSHIP_ROWS, 37)?;
        for _ in 0..ownership_count {
            let key_bytes = read_exact(bytes, &mut off, 33)?;
            let key = OwnershipIndexKey::decode(key_bytes)
                .map_err(|e| StateError::BlobDecode(format!("ownership key decode: {e}")))?;
            let id_count = read_count_le(
                bytes,
                &mut off,
                "ownership ids",
                MAX_OWNERSHIP_IDS_PER_ROW,
                32,
            )?;
            let mut ids = Vec::new();
            for _ in 0..id_count {
                ids.push(ObjectId(read_bytes32(bytes, &mut off)?));
            }
            state.set_ownership(key, ids);
        }

        // --- VFS section ---
        let vfs_count = read_count_le(bytes, &mut off, "vfs", MAX_VFS_ENTRIES, 36)?;
        for _ in 0..vfs_count {
            let path_len = read_len_le(bytes, &mut off, "vfs path", MAX_VFS_PATH_BYTES)?;
            let path_bytes = read_exact(bytes, &mut off, path_len)?;
            let path = std::str::from_utf8(path_bytes)
                .map_err(|e| StateError::BlobDecode(format!("vfs path utf8: {e}")))?
                .to_owned();
            let hash = Hash32(read_bytes32(bytes, &mut off)?);
            state.set_vfs_binding(path, hash);
        }

        // --- Key registry section ---
        let key_count = read_count_le(
            bytes,
            &mut off,
            "key registry",
            MAX_KEY_REGISTRY_ENTRIES,
            36,
        )?;
        for _ in 0..key_count {
            let addr = Address(read_bytes32(bytes, &mut off)?);
            let pubkey_len = read_len_le(bytes, &mut off, "key registry pubkey", MAX_PUBKEY_BYTES)?;
            let pubkey = read_exact(bytes, &mut off, pubkey_len)?.to_vec();
            state.register_pubkey(addr, PubKeyBytes(pubkey));
        }

        if off != bytes.len() {
            return Err(StateError::BlobDecode(format!(
                "trailing bytes after state blob: {}",
                bytes.len() - off
            )));
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
        let db = sled::open(path).map_err(|e| StateError::BlobStore(format!("sled open: {e}")))?;

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
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
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
