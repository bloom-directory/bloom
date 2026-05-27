//! # BTreeMap-backed v0 state commitment
//!
//! ## Design choice (v0 vs v1)
//!
//! The spec calls for a 256-ary sparse Merkle tree over BLAKE3 (section 5.1,
//! section 6.2). A full SMT requires about 32 rounds of hashing per path and substantial
//! bookkeeping for partial branches. For v0 we need only:
//!
//! - A **deterministic commitment** to the set of populated (key, value) pairs.
//! - **Cheap diffs** (just BTreeMap insert/remove).
//! - **Domain separation** between the accounts, storage, and code roles.
//!
//! Therefore the v0 commitment is:
//!
//! ```text
//! root = blake3_tagged(DOMAIN_TAG,
//!            len_u64_le || for each (k, v) in sorted order:
//!                k || blake3_tagged(VALUE_TAG, v))
//! ```
//!
//! The inner `blake3_tagged(VALUE_TAG, v)` ensures value-domain separation;
//! the outer hash commits to the sorted entry list. An empty trie returns the
//! all-zeros hash.
//!
//! **v1 swap-in path:** replace the `root()` implementation with a true 256-ary
//! SMT, for example a Patricia-Merkle trie over BLAKE3. The `insert`, `get`, `remove`,
//! `iter`, `len`, `is_empty` public API is identical; only the root computation
//! changes, which is behind a single method boundary.

use std::collections::BTreeMap;

use bloom_chain_types::{
    Hash32,
    digest::{blake3_tagged, tags},
};

/// Selects domain-separation tags for a trie instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrieKind {
    /// Accounts trie — keyed by address, valued at SSZ-encoded `Account`.
    Accounts,
    /// Per-contract storage trie — keyed and valued by `bytes32` words.
    Storage,
    /// Code trie — keyed by petal hash, valued at raw wasm bytes.
    Code,
    /// Per-account Object trie (spec §16.3, Phase 1).
    ///
    /// Keyed by 32-byte object id, valued at the canonical
    /// `bloom_objects::store::object_leaf_value` encoding. Empty in
    /// Phase 1 because no PTBs execute yet, but the variant exists so
    /// the commitment scheme is stable.
    Object,
    /// Per-account OwnershipIndex trie (spec §16.3, Phase 1).
    ///
    /// Keyed by `blake3_tagged(OWNERSHIP_LEAF, owner || object_id)`,
    /// valued at the SSZ-encoded ownership record. Empty in Phase 1.
    OwnershipIndex,
}

impl TrieKind {
    /// Root-level domain tag for this trie kind.
    pub(crate) fn root_tag(self) -> &'static str {
        match self {
            TrieKind::Accounts => tags::ACCOUNTS_ROOT,
            TrieKind::Storage => tags::STORAGE_KEY,
            TrieKind::Code => tags::CODE_ROOT,
            TrieKind::Object => tags::OBJECT_ROOT,
            TrieKind::OwnershipIndex => tags::OWNERSHIP_ROOT,
        }
    }

    /// Value-level domain tag for this trie kind.
    pub(crate) fn value_tag(self) -> &'static str {
        match self {
            TrieKind::Accounts => tags::ACCOUNTS_ROOT,
            TrieKind::Storage => tags::STORAGE_VALUE,
            TrieKind::Code => tags::PETAL,
            TrieKind::Object => tags::OBJECT_LEAF,
            TrieKind::OwnershipIndex => tags::OWNERSHIP_LEAF,
        }
    }
}

/// A deterministic key-value commitment backed by a `BTreeMap`.
///
/// Keys are 32-byte arrays; values are arbitrary byte vectors.  Only non-empty
/// entries are stored.  See module-level docs for the v0 commitment scheme.
#[derive(Clone, Debug)]
pub struct Trie {
    kind: TrieKind,
    entries: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Trie {
    /// Create a new, empty trie with the given domain kind.
    pub fn new(kind: TrieKind) -> Self {
        Self {
            kind,
            entries: BTreeMap::new(),
        }
    }

    /// Insert or replace a key-value pair.
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.entries.insert(key, value);
    }

    /// Look up a key.
    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8]> {
        self.entries.get(key).map(|v| v.as_slice())
    }

    /// Remove a key, returning its old value if present.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    /// Iterate over all (key, value) pairs in sorted key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.entries.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Number of populated entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the trie contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the commitment root.
    ///
    /// Empty trie → `Hash32([0u8; 32])`.
    ///
    /// Non-empty trie → domain-separated BLAKE3 over the sorted entries.
    /// See module docs for the exact formula.
    pub fn root(&self) -> Hash32 {
        if self.entries.is_empty() {
            return Hash32([0u8; 32]);
        }

        // Build payload: len_u64_le || (key || value_hash)*
        let count = self.entries.len() as u64;
        let mut payload = Vec::with_capacity(8 + self.entries.len() * 64);
        payload.extend_from_slice(&count.to_le_bytes());

        for (key, value) in &self.entries {
            let value_hash = blake3_tagged(self.kind.value_tag(), value);
            payload.extend_from_slice(key);
            payload.extend_from_slice(&value_hash.0);
        }

        blake3_tagged(self.kind.root_tag(), &payload)
    }

    /// Return the `TrieKind` of this trie.
    pub fn kind(&self) -> TrieKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn empty_trie_root_is_zero() {
        let t = Trie::new(TrieKind::Accounts);
        assert_eq!(t.root(), Hash32([0u8; 32]));
    }

    #[test]
    fn insert_get_roundtrip() {
        let mut t = Trie::new(TrieKind::Storage);
        t.insert(key(1), b"hello".to_vec());
        assert_eq!(t.get(&key(1)), Some(b"hello".as_ref()));
        assert_eq!(t.get(&key(2)), None);
    }

    #[test]
    fn remove_restores_root() {
        let mut t = Trie::new(TrieKind::Accounts);
        let initial = t.root();
        t.insert(key(5), b"value".to_vec());
        assert_ne!(t.root(), initial);
        t.remove(&key(5));
        assert_eq!(t.root(), initial);
    }

    #[test]
    fn root_is_insertion_order_independent() {
        let mut t1 = Trie::new(TrieKind::Accounts);
        t1.insert(key(1), b"a".to_vec());
        t1.insert(key(2), b"b".to_vec());

        let mut t2 = Trie::new(TrieKind::Accounts);
        t2.insert(key(2), b"b".to_vec());
        t2.insert(key(1), b"a".to_vec());

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn domain_tag_distinguishes_tries() {
        let mut a = Trie::new(TrieKind::Accounts);
        a.insert(key(1), b"payload".to_vec());

        let mut s = Trie::new(TrieKind::Storage);
        s.insert(key(1), b"payload".to_vec());

        assert_ne!(a.root(), s.root());
    }

    #[test]
    fn object_trie_empty_root_is_zero() {
        let t = Trie::new(TrieKind::Object);
        assert_eq!(t.root(), Hash32([0u8; 32]));
    }

    #[test]
    fn ownership_index_empty_root_is_zero() {
        let t = Trie::new(TrieKind::OwnershipIndex);
        assert_eq!(t.root(), Hash32([0u8; 32]));
    }

    #[test]
    fn object_and_ownership_have_distinct_roots() {
        let mut o = Trie::new(TrieKind::Object);
        o.insert(key(1), b"payload".to_vec());

        let mut oi = Trie::new(TrieKind::OwnershipIndex);
        oi.insert(key(1), b"payload".to_vec());

        assert_ne!(o.root(), oi.root());
    }

    #[test]
    fn object_and_accounts_have_distinct_roots() {
        let mut o = Trie::new(TrieKind::Object);
        o.insert(key(7), b"shared".to_vec());

        let mut a = Trie::new(TrieKind::Accounts);
        a.insert(key(7), b"shared".to_vec());

        assert_ne!(o.root(), a.root());
    }

    #[test]
    fn new_trie_kind_tags_match_canonical_strings() {
        // Pin the wire-level strings so they cannot drift from
        // bloom_objects::store::OBJECT_ROOT_TAG / OBJECT_LEAF_TAG etc.
        assert_eq!(TrieKind::Object.root_tag(), "bloom-chain.v0.object_root:");
        assert_eq!(TrieKind::Object.value_tag(), "bloom-chain.v0.object_leaf:");
        assert_eq!(
            TrieKind::OwnershipIndex.root_tag(),
            "bloom-chain.v0.ownership_root:"
        );
        assert_eq!(
            TrieKind::OwnershipIndex.value_tag(),
            "bloom-chain.v0.ownership_leaf:"
        );
    }
}
