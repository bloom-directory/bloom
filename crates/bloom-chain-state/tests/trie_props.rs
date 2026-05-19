//! Category: property
//!
//! Property-based tests for the `Trie` commitment scheme.

use bloom_chain_state::trie::{Trie, TrieKind};
use bloom_chain_types::Hash32;
use proptest::prelude::*;

fn arb_key() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

proptest! {
    /// Inserting then removing a key restores the original root.
    #[test]
    fn insert_remove_restores_root(key in arb_key(), value in arb_value()) {
        let mut trie = Trie::new(TrieKind::Accounts);
        let initial = trie.root();
        trie.insert(key, value);
        trie.remove(&key);
        prop_assert_eq!(trie.root(), initial);
    }

    /// Root is deterministic regardless of insertion order.
    #[test]
    fn root_deterministic_regardless_of_order(
        entries in prop::collection::vec((arb_key(), arb_value()), 2..=8)
    ) {
        // Deduplicate keys (BTreeMap semantics: last write wins per key)
        let mut map: std::collections::BTreeMap<[u8; 32], Vec<u8>> = std::collections::BTreeMap::new();
        for (k, v) in &entries {
            map.insert(*k, v.clone());
        }

        let mut t1 = Trie::new(TrieKind::Accounts);
        for (k, v) in &map {
            t1.insert(*k, v.clone());
        }

        // Insert in reverse order
        let mut t2 = Trie::new(TrieKind::Accounts);
        for (k, v) in map.iter().rev() {
            t2.insert(*k, v.clone());
        }

        prop_assert_eq!(t1.root(), t2.root());
    }

    /// Domain tags actually distinguish tries with the same data.
    #[test]
    fn domain_tag_distinguishes_tries(key in arb_key(), value in arb_value()) {
        let mut accounts = Trie::new(TrieKind::Accounts);
        accounts.insert(key, value.clone());

        let mut storage = Trie::new(TrieKind::Storage);
        storage.insert(key, value.clone());

        let mut code = Trie::new(TrieKind::Code);
        code.insert(key, value);

        prop_assert_ne!(accounts.root(), storage.root());
        prop_assert_ne!(accounts.root(), code.root());
        prop_assert_ne!(storage.root(), code.root());
    }
}

#[test]
fn empty_trie_root_is_zero_hash() {
    let trie = Trie::new(TrieKind::Accounts);
    assert_eq!(trie.root(), Hash32([0u8; 32]));
}

#[test]
fn single_entry_root_is_nonzero() {
    let mut trie = Trie::new(TrieKind::Accounts);
    trie.insert([1u8; 32], b"hello".to_vec());
    assert_ne!(trie.root(), Hash32([0u8; 32]));
}
