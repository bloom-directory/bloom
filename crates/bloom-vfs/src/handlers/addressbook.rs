//! `addressbook/<alias>` — local petname directory.
//!
//! Reads return the EIP-55 checksum address for an alias (with trailing
//! newline). Writes register or delete entries:
//!
//! * write `0xabc...` to `addressbook/alice` → register `alice`.
//! * write `delete` (or empty bytes) to `addressbook/alice` → remove it.
//!
//! Persistence: TOML at `<home>/addressbook.toml`.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_proto::{AddressBook, checksum_address, parse_address};
use parking_lot::RwLock;
use tracing::warn;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct AddressBookHandler {
    pub book: Arc<RwLock<AddressBook>>,
    pub path: PathBuf,
}

impl AddressBookHandler {
    /// Construct a handler from a TOML path. The file is loaded lazily;
    /// missing files yield an empty book.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HandlerError> {
        let path = path.into();
        let book = AddressBook::load(&path).map_err(|e| HandlerError::backend(e.to_string()))?;
        Ok(Self {
            book: Arc::new(RwLock::new(book)),
            path,
        })
    }

    /// Convenience for tests / in-process use without persistence.
    pub fn from_book(book: AddressBook, path: impl Into<PathBuf>) -> Self {
        Self {
            book: Arc::new(RwLock::new(book)),
            path: path.into(),
        }
    }

    fn save(&self) -> Result<(), HandlerError> {
        let snapshot = self.book.read().clone();
        snapshot
            .save(&self.path)
            .map_err(|e| HandlerError::backend(e.to_string()))
    }
}

#[async_trait]
impl Handler for AddressBookHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "addressbook.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "addressbook.read_err");
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "addressbook.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "addressbook.list_err");
        }
        r
    }
}

impl AddressBookHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        if path.is_root() {
            return Ok(Entry::dir(""));
        }
        let segs = path.segments();
        if segs.len() != 1 {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        let name = &segs[0];
        if name == "new" {
            return Ok(Entry::writable_file("new"));
        }
        let book = self.book.read();
        if book.entries.contains_key(name.as_str()) {
            Ok(Entry::writable_file(name))
        } else {
            // Allow lookup on any valid alias name so writes can create.
            AddressBook::validate_alias(name).map_err(|e| HandlerError::invalid(e.to_string()))?;
            Ok(Entry::writable_file(name))
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.len() != 1 {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        let name = &segs[0];
        if name == "new" {
            return Ok(b"# write '<alias>=0xADDRESS' to register a petname\n".to_vec());
        }
        let book = self.book.read();
        let v = book
            .entries
            .get(name.as_str())
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        Ok(format!("{v}\n").into_bytes())
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        let body = std::str::from_utf8(data)
            .map_err(|e| HandlerError::invalid(format!("utf8: {e}")))?
            .trim();

        // Two write surfaces:
        //   1. write to `addressbook/new`  with body `alias=0x..`
        //   2. write to `addressbook/<alias>` with body `0x..` or "delete"
        let (alias_owned, value) = if segs.len() == 1 && segs[0] == "new" {
            let (alias, val) = body
                .split_once('=')
                .ok_or_else(|| HandlerError::invalid("expected 'alias=0x...'"))?;
            (alias.trim().to_string(), val.trim())
        } else if segs.len() == 1 {
            (segs[0].clone(), body)
        } else {
            return Err(HandlerError::invalid(format!(
                "addressbook: unsupported write path {}",
                path.to_string_path()
            )));
        };

        AddressBook::validate_alias(&alias_owned)
            .map_err(|e| HandlerError::invalid(e.to_string()))?;

        if value.is_empty() || value.eq_ignore_ascii_case("delete") {
            self.book.write().remove(&alias_owned);
            self.save()?;
            return Ok(());
        }

        let addr = parse_address(value)
            .map_err(|e| HandlerError::invalid(format!("invalid address '{value}': {e}")))?;
        let mut guard = self.book.write();
        guard
            .entries
            .insert(alias_owned.clone(), checksum_address(&addr));
        drop(guard);
        if let Err(e) = self.save() {
            warn!("addressbook.save failed: {e}");
            return Err(e);
        }
        Ok(())
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if !path.is_root() {
            return Err(HandlerError::NotADir(path.to_string_path()));
        }
        let mut out = vec![Entry::writable_file("new")];
        let book = self.book.read();
        for k in book.entries.keys() {
            out.push(Entry::writable_file(k));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn write_and_read_round_trip() {
        let d = dir();
        let p = d.path().join("addressbook.toml");
        let h = AddressBookHandler::open(&p).unwrap();
        let alice = VfsPath::parse("/alice").unwrap();
        h.write(&alice, b"0x000000000000000000000000000000000000beef")
            .await
            .unwrap();
        let bytes = h.read(&alice).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with("0x"));
        // persisted on disk
        let reloaded = AddressBook::load(&p).unwrap();
        assert!(reloaded.resolve("alice").is_some());
    }

    #[tokio::test]
    async fn delete_removes_alias() {
        let d = dir();
        let p = d.path().join("addressbook.toml");
        let h = AddressBookHandler::open(&p).unwrap();
        let alice = VfsPath::parse("/alice").unwrap();
        h.write(&alice, b"0x000000000000000000000000000000000000beef")
            .await
            .unwrap();
        h.write(&alice, b"delete").await.unwrap();
        let r = h.read(&alice).await;
        assert!(matches!(r, Err(HandlerError::NotFound(_))));
    }

    #[tokio::test]
    async fn write_new_with_alias_equals_value() {
        let d = dir();
        let p = d.path().join("addressbook.toml");
        let h = AddressBookHandler::open(&p).unwrap();
        let new_p = VfsPath::parse("/new").unwrap();
        h.write(&new_p, b"bob=0x000000000000000000000000000000000000beef")
            .await
            .unwrap();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert!(entries.iter().any(|e| e.name == "bob"));
    }

    #[tokio::test]
    async fn invalid_alias_rejected() {
        let d = dir();
        let p = d.path().join("addressbook.toml");
        let h = AddressBookHandler::open(&p).unwrap();
        let bad = VfsPath::parse("/bad alias").unwrap();
        let r = h
            .write(&bad, b"0x000000000000000000000000000000000000beef")
            .await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))));
    }

    #[tokio::test]
    async fn root_lists_new_plus_entries() {
        let d = dir();
        let p = d.path().join("addressbook.toml");
        let h = AddressBookHandler::open(&p).unwrap();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "new");
    }
}
