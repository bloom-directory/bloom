//! Category: integration
//!
//! Integration tests for the accounts trie and state root.

use bloom_chain_state::{Account, AccountsTrie, State};
use bloom_chain_types::{Address, Hash32};

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn eoa(nonce: u64) -> Account {
    Account {
        nonce,
        code_hash: None,
        storage_root: Hash32([0u8; 32]),
        manifest_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Set / get / remove cycle
// ---------------------------------------------------------------------------

#[test]
fn set_get_remove_cycle() {
    let mut trie = AccountsTrie::new();

    let a1 = eoa(100);
    let a2 = eoa(200);

    let r0 = trie.root();
    trie.set(addr(1), a1.clone());
    let r1 = trie.root();
    assert_ne!(r0, r1, "root should change after set");

    trie.set(addr(2), a2.clone());
    let r2 = trie.root();
    assert_ne!(r1, r2, "root should change again after second set");

    assert_eq!(trie.get(&addr(1)), Some(a1));
    assert_eq!(trie.get(&addr(2)), Some(a2));

    trie.remove(&addr(1));
    let r3 = trie.root();
    assert_ne!(r2, r3, "root should change after remove");
    assert_eq!(trie.get(&addr(1)), None);

    trie.remove(&addr(2));
    assert_eq!(
        trie.root(),
        r0,
        "root should return to initial after all removes"
    );
}

// ---------------------------------------------------------------------------
// Empty account is auto-removed
// ---------------------------------------------------------------------------

#[test]
fn empty_account_auto_removed() {
    let mut trie = AccountsTrie::new();
    trie.set(addr(1), Account::empty());
    assert_eq!(trie.get(&addr(1)), None);
    assert!(trie.is_empty());
}

#[test]
fn setting_account_to_empty_removes_it() {
    let mut trie = AccountsTrie::new();
    trie.set(addr(1), eoa(500));
    assert!(!trie.is_empty());

    trie.set(addr(1), Account::empty());
    assert_eq!(trie.get(&addr(1)), None);
    assert!(trie.is_empty());
}

// ---------------------------------------------------------------------------
// Two states with same accounts → same state_root
// ---------------------------------------------------------------------------

#[test]
fn same_accounts_same_state_root() {
    let mut s1 = State::new();
    s1.set_account(addr(1), eoa(1000));
    s1.set_account(addr(2), eoa(2000));

    let mut s2 = State::new();
    s2.set_account(addr(2), eoa(2000));
    s2.set_account(addr(1), eoa(1000));

    assert_eq!(s1.state_root(), s2.state_root());
}

#[test]
fn different_accounts_different_state_root() {
    let mut s1 = State::new();
    s1.set_account(addr(1), eoa(1000));

    let mut s2 = State::new();
    s2.set_account(addr(1), eoa(9999));

    assert_ne!(s1.state_root(), s2.state_root());
}

// ---------------------------------------------------------------------------
// Root changes on every mutation
// ---------------------------------------------------------------------------

#[test]
fn root_changes_on_every_mutation() {
    let mut trie = AccountsTrie::new();
    let roots: Vec<Hash32> = {
        let mut v = vec![trie.root()];
        trie.set(addr(1), eoa(10));
        v.push(trie.root());
        trie.set(addr(2), eoa(20));
        v.push(trie.root());
        trie.set(addr(1), eoa(11)); // update
        v.push(trie.root());
        trie.remove(&addr(2));
        v.push(trie.root());
        v
    };

    // All roots must be distinct
    for i in 0..roots.len() {
        for j in i + 1..roots.len() {
            assert_ne!(roots[i], roots[j], "roots[{i}] == roots[{j}]");
        }
    }
}
