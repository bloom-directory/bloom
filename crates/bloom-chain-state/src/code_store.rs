//! Content-addressed wasm code store.
//!
//! The `CodeStore` holds raw wasm bytes keyed by their BLAKE3 petal hash
//! (`tags::PETAL`).  It also maintains a `code_root` commitment via a
//! `Trie<TrieKind::Code>` whose entries are `(petal_hash -> wasm_bytes)`.
//!
//! Many contracts can share one code entry (same wasm, different instances).

use bloom_chain_types::{
    Hash32,
    digest::{blake3_tagged, tags},
};

use crate::trie::{Trie, TrieKind};

/// Content-addressed wasm code store.
#[derive(Clone, Debug)]
pub struct CodeStore {
    trie: Trie,
}

impl CodeStore {
    /// Create an empty code store.
    pub fn new() -> Self {
        Self {
            trie: Trie::new(TrieKind::Code),
        }
    }

    /// Insert wasm bytes, returning their petal hash (`blake3_tagged(PETAL, bytes)`).
    ///
    /// Inserting the same bytes twice is idempotent.
    pub fn insert(&mut self, wasm: &[u8]) -> Hash32 {
        let hash = blake3_tagged(tags::PETAL, wasm);
        if self.trie.get(&hash.0).is_none() {
            self.trie.insert(hash.0, wasm.to_vec());
        }
        hash
    }

    /// Retrieve wasm bytes by petal hash.
    pub fn get(&self, hash: &Hash32) -> Option<&[u8]> {
        self.trie.get(&hash.0)
    }

    /// Compute the code root.
    pub fn root(&self) -> Hash32 {
        self.trie.root()
    }

    /// Number of distinct code entries.
    pub fn len(&self) -> usize {
        self.trie.len()
    }

    /// True iff the code store contains no entries.
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }

    /// Iterate over all (hash, wasm_bytes) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.trie.iter()
    }
}

impl Default for CodeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_roundtrip() {
        let mut store = CodeStore::new();
        let wasm = b"(module)";
        let hash = store.insert(wasm);
        assert_eq!(store.get(&hash), Some(wasm.as_ref()));
    }

    #[test]
    fn double_insert_is_idempotent() {
        let mut store = CodeStore::new();
        let wasm = b"(module)";
        let h1 = store.insert(wasm);
        let h2 = store.insert(wasm);
        assert_eq!(h1, h2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn root_changes_on_insert() {
        let mut store = CodeStore::new();
        let r0 = store.root();
        store.insert(b"(module)");
        assert_ne!(store.root(), r0);
    }

    #[test]
    fn petal_hash_uses_domain_tag() {
        let wasm = b"fake wasm";
        let h1 = blake3_tagged(tags::PETAL, wasm);
        let mut store = CodeStore::new();
        let h2 = store.insert(wasm);
        assert_eq!(h1, h2);
    }
}
