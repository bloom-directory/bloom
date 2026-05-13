//! Address helpers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Parse an address from a `0x`-prefixed hex string.
///
/// Lowercase or mixed-case (EIP-55) both work; the alloy parser is strict
/// only when the input starts with `0X` (no relevance for our API).
pub fn parse_address(s: &str) -> Result<Address, alloy::hex::FromHexError> {
    s.parse::<Address>()
}

/// Render an address in EIP-55 mixed-case checksum form.
pub fn checksum_address(a: &Address) -> String {
    a.to_checksum(None)
}

/// Tiny address book (`alias -> address`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AddressBook {
    #[serde(default)]
    pub entries: BTreeMap<String, String>,
}

impl AddressBook {
    pub fn resolve(&self, name: &str) -> Option<Address> {
        self.entries.get(name).and_then(|s| parse_address(s).ok())
    }

    pub fn set(&mut self, name: impl Into<String>, addr: Address) {
        self.entries.insert(name.into(), checksum_address(&addr));
    }

    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.entries.remove(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    /// Iterate `(name, checksum_address)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.entries.iter()
    }

    /// Reverse lookup: given an address, return the first (alphabetical)
    /// alias mapped to it.
    pub fn alias_for(&self, addr: &Address) -> Option<&str> {
        let target = checksum_address(addr);
        for (k, v) in &self.entries {
            if v.eq_ignore_ascii_case(&target) {
                return Some(k.as_str());
            }
        }
        None
    }

    /// Load from a TOML file (`[entries] alias = "0x..."`).
    /// Returns an empty book if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, AddressBookError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| AddressBookError::Io(path.to_path_buf(), e))?;
        let book: AddressBook = toml::from_str(&text)
            .map_err(|e| AddressBookError::Toml(path.to_path_buf(), e.to_string()))?;
        Ok(book)
    }

    /// Persist to a TOML file. Creates parent dirs as needed.
    pub fn save(&self, path: &Path) -> Result<(), AddressBookError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AddressBookError::Io(parent.to_path_buf(), e))?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| AddressBookError::Toml(path.to_path_buf(), e.to_string()))?;
        std::fs::write(path, text).map_err(|e| AddressBookError::Io(path.to_path_buf(), e))
    }

    /// Validate alias: 1..=64 chars, ASCII alphanumeric or `_`, `-`, `.`.
    pub fn validate_alias(name: &str) -> Result<(), AddressBookError> {
        if name.is_empty() || name.len() > 64 {
            return Err(AddressBookError::InvalidAlias(name.to_string()));
        }
        for c in name.chars() {
            if !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
                return Err(AddressBookError::InvalidAlias(name.to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error("io {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("toml {0}: {1}")]
    Toml(PathBuf, String),
    #[error("invalid alias '{0}' (1-64 chars, [a-zA-Z0-9_.-] only)")]
    InvalidAlias(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Address {
        "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap()
    }

    #[test]
    fn round_trips_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("addressbook.toml");
        let mut book = AddressBook::default();
        book.set("alice", alice());
        book.save(&path).unwrap();
        let loaded = AddressBook::load(&path).unwrap();
        assert_eq!(loaded.resolve("alice"), Some(alice()));
    }

    #[test]
    fn alias_for_finds_name() {
        let mut book = AddressBook::default();
        book.set("alice", alice());
        assert_eq!(book.alias_for(&alice()), Some("alice"));
    }

    #[test]
    fn validate_alias_rejects_garbage() {
        assert!(AddressBook::validate_alias("alice").is_ok());
        assert!(AddressBook::validate_alias("a.b_c-1").is_ok());
        assert!(AddressBook::validate_alias("").is_err());
        assert!(AddressBook::validate_alias(" alice").is_err());
        assert!(AddressBook::validate_alias("a/b").is_err());
    }

    #[test]
    fn load_missing_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let book = AddressBook::load(&path).unwrap();
        assert!(book.entries.is_empty());
    }
}
