//! Accounts trie — wraps the generic `Trie` with `Account`-specific semantics.
//!
//! Keys are 32-byte addresses (`Address.0`).  Values are SSZ-encoded `Account`s.
//!
//! Empty accounts (spec §5.1) are never stored in the trie: `set` with an empty
//! account is equivalent to `remove`.

use bloom_chain_types::{Address, Hash32};
use ssz::{Decode, Encode};

use crate::account::Account;
use crate::trie::{Trie, TrieKind};

/// The top-level accounts trie.
#[derive(Clone, Debug)]
pub struct AccountsTrie {
    trie: Trie,
}

impl AccountsTrie {
    /// Create an empty accounts trie.
    pub fn new() -> Self {
        Self {
            trie: Trie::new(TrieKind::Accounts),
        }
    }

    /// Retrieve an account by address.  Returns `None` for non-existent addresses.
    pub fn get(&self, addr: &Address) -> Option<Account> {
        let bytes = self.trie.get(&addr.0)?;
        Account::from_ssz_bytes(bytes).ok()
    }

    /// Store an account.  If `account.is_empty()`, the entry is removed instead
    /// (spec §5.1: empty accounts are not materialised).
    pub fn set(&mut self, addr: Address, account: Account) {
        if account.is_empty() {
            self.trie.remove(&addr.0);
        } else {
            self.trie.insert(addr.0, account.as_ssz_bytes());
        }
    }

    /// Remove an address from the trie.
    pub fn remove(&mut self, addr: &Address) {
        self.trie.remove(&addr.0);
    }

    /// Compute the accounts root.
    pub fn root(&self) -> Hash32 {
        self.trie.root()
    }

    /// Iterate over all (address, account) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (Address, Account)> + '_ {
        self.trie.iter().filter_map(|(key, value)| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(key);
            let addr = Address(arr);
            let account = Account::from_ssz_bytes(value).ok()?;
            Some((addr, account))
        })
    }

    /// Number of non-empty accounts in the trie.
    pub fn len(&self) -> usize {
        self.trie.len()
    }

    /// True iff the accounts trie is empty.
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }
}

impl Default for AccountsTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    #[test]
    fn set_get_roundtrip() {
        let mut trie = AccountsTrie::new();
        let account = Account {
            nonce: 1,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        };
        trie.set(addr(1), account.clone());
        assert_eq!(trie.get(&addr(1)), Some(account));
        assert_eq!(trie.get(&addr(2)), None);
    }

    #[test]
    fn empty_account_is_not_stored() {
        let mut trie = AccountsTrie::new();
        trie.set(addr(1), Account::empty());
        assert_eq!(trie.get(&addr(1)), None);
        assert!(trie.is_empty());
    }

    #[test]
    fn remove_works() {
        let mut trie = AccountsTrie::new();
        let account = Account {
            nonce: 5,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        };
        trie.set(addr(3), account);
        trie.remove(&addr(3));
        assert_eq!(trie.get(&addr(3)), None);
    }

    #[test]
    fn root_changes_on_mutation() {
        let mut trie = AccountsTrie::new();
        let r0 = trie.root();

        trie.set(
            addr(1),
            Account {
                nonce: 1,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );
        let r1 = trie.root();
        assert_ne!(r0, r1);

        trie.set(
            addr(2),
            Account {
                nonce: 2,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );
        let r2 = trie.root();
        assert_ne!(r1, r2);
    }
}
