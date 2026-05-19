//! Per-contract storage trie.
//!
//! Each contract instance has an independent `StorageTrie` keyed by `[u8; 32]`
//! storage keys and valued at `[u8; 32]` storage words (spec §6.2).
//!
//! A missing key reads as the zero word; writing the zero word is equivalent to
//! deleting the slot to keep the trie sparse.

use bloom_chain_types::Hash32;

use crate::trie::{Trie, TrieKind};

/// Per-contract storage trie.
#[derive(Clone, Debug)]
pub struct StorageTrie {
    trie: Trie,
}

impl StorageTrie {
    /// Create an empty storage trie.
    pub fn new() -> Self {
        Self {
            trie: Trie::new(TrieKind::Storage),
        }
    }

    /// Read a storage slot.  Returns the zero word for unset slots.
    pub fn read(&self, key: &[u8; 32]) -> [u8; 32] {
        match self.trie.get(key) {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                arr
            }
            _ => [0u8; 32],
        }
    }

    /// Write a storage slot.  Writing the zero word deletes the slot.
    pub fn write(&mut self, key: [u8; 32], value: [u8; 32]) {
        if value == [0u8; 32] {
            self.trie.remove(&key);
        } else {
            self.trie.insert(key, value.to_vec());
        }
    }

    /// Delete a storage slot (equivalent to writing zero).
    pub fn delete(&mut self, key: &[u8; 32]) {
        self.trie.remove(key);
    }

    /// Compute the storage root.
    pub fn root(&self) -> Hash32 {
        self.trie.root()
    }

    /// True iff the storage trie has no populated slots.
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }

    /// Iterate over all (key, value) slot pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.trie.iter()
    }

    /// Number of populated slots.
    pub fn len(&self) -> usize {
        self.trie.len()
    }
}

impl Default for StorageTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn word(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn unset_key_returns_zero() {
        let trie = StorageTrie::new();
        assert_eq!(trie.read(&key(1)), [0u8; 32]);
    }

    #[test]
    fn write_read_roundtrip() {
        let mut trie = StorageTrie::new();
        trie.write(key(1), word(0xAB));
        assert_eq!(trie.read(&key(1)), word(0xAB));
    }

    #[test]
    fn write_zero_deletes() {
        let mut trie = StorageTrie::new();
        trie.write(key(1), word(5));
        trie.write(key(1), [0u8; 32]);
        assert_eq!(trie.read(&key(1)), [0u8; 32]);
        assert!(trie.is_empty());
    }

    #[test]
    fn delete_works() {
        let mut trie = StorageTrie::new();
        trie.write(key(1), word(7));
        trie.delete(&key(1));
        assert_eq!(trie.read(&key(1)), [0u8; 32]);
    }

    #[test]
    fn root_changes_on_write() {
        let mut trie = StorageTrie::new();
        let r0 = trie.root();
        trie.write(key(1), word(1));
        assert_ne!(trie.root(), r0);
    }
}
