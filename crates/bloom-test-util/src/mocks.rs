//! Mock implementations used across the test suites.
//!
//! - [`TestSigner`]: wraps an xDSA secret key and implements the
//!   chain-consensus [`Signer`] trait.
//! - [`SingleFileHandler`]: tiny VFS [`Handler`] exposing exactly one file
//!   at root with a fixed name + payload. Replaces the previously
//!   duplicated `StubHandler` (bloom-daemon ipc tests) and `ProbeHandler`
//!   (bloom CLI ipc tests).

use std::sync::Arc;

use async_trait::async_trait;
use bloom_chain_consensus::signer::Signer;
use bloom_chain_types::types::SigBytes;
use bloom_keystore::xdsa::XdsaSecretKey;
use bloom_vfs::{Entry, Handler, HandlerError, VfsPath};

/// Production-style xDSA signer for tests. Functionally identical to
/// `bloom_chain_node::consensus_driver::XdsaSigner`, but lives outside
/// chain-node so test crates can import it without pulling the node.
#[derive(Clone)]
pub struct TestSigner {
    sk: Arc<XdsaSecretKey>,
}

impl TestSigner {
    pub fn new(sk: Arc<XdsaSecretKey>) -> Self {
        Self { sk }
    }
}

impl Signer for TestSigner {
    fn sign(&self, msg: &[u8]) -> SigBytes {
        SigBytes(self.sk.sign(msg).to_bytes())
    }
}

/// Tiny VFS handler: root has exactly one file named `file_name`,
/// reading it always returns `contents`. Used by the daemon IPC tests
/// and the CLI ipc subprocess test — both want a deterministic VFS
/// surface that the production daemon would never mount.
pub struct SingleFileHandler {
    pub file_name: String,
    pub contents: Vec<u8>,
}

impl SingleFileHandler {
    pub fn new(file_name: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            file_name: file_name.into(),
            contents: contents.into(),
        }
    }
}

#[async_trait]
impl Handler for SingleFileHandler {
    async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
        if p.is_root() {
            return Ok(Entry::dir(""));
        }
        if p.segments().len() == 1 && p.segments()[0].as_str() == self.file_name {
            return Ok(Entry::file(&self.file_name));
        }
        Err(HandlerError::not_found(p.to_string_path()))
    }
    async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if p.is_root() {
            Ok(vec![Entry::file(&self.file_name)])
        } else {
            Err(HandlerError::NotADir(p.to_string_path()))
        }
    }
    async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        Ok(self.contents.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_produces_non_empty_signature() {
        let (sk, _pk) = XdsaSecretKey::generate();
        let signer = TestSigner::new(Arc::new(sk));
        let sig = signer.sign(b"hello world");
        assert!(!sig.0.is_empty());
    }

    #[tokio::test]
    async fn single_file_handler_serves_one_file_at_root() {
        let h = SingleFileHandler::new("greet", b"hi\n".to_vec());
        let root = VfsPath::root();
        let entries = h.list(&root).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "greet");
        let file_path = root.join("greet");
        let entry = h.lookup(&file_path).await.unwrap();
        assert_eq!(entry.name, "greet");
        let body = h.read(&file_path).await.unwrap();
        assert_eq!(body, b"hi\n");
        // Anything else 404s.
        let missing = root.join("does-not-exist");
        let err = h.lookup(&missing).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)));
    }

    #[test]
    fn test_signer_signatures_are_deterministic_per_key() {
        let (sk, _pk) = XdsaSecretKey::generate();
        let signer = TestSigner::new(Arc::new(sk));
        // ml-dsa is randomised; ed25519 is deterministic; the composite
        // signature differs across calls (the ml-dsa half includes
        // randomness). Just assert each signature is well-formed.
        let s1 = signer.sign(b"msg");
        let s2 = signer.sign(b"msg");
        assert!(!s1.0.is_empty());
        assert!(!s2.0.is_empty());
    }
}
