//! Host interface a petal can call back into.
//!
//! Implementations bridge wasm petals to the surrounding system. The
//! production impl wraps the daemon's [`bloom_vfs::Vfs`]; tests
//! typically use an in-memory mock. Capability checks happen *before*
//! the host call in `vm.rs` — the host impl does not need to enforce
//! them itself.

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("denied: {0}")]
    Denied(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("backend: {0}")]
    Backend(String),
    #[error("block not pinnable (block=0)")]
    BlockNotPinnable,
    #[error("chain unavailable: {0}")]
    ChainUnavailable(String),
    #[error("chain path unknown: {0}")]
    ChainPathUnknown(String),
}

impl HostError {
    /// Stable negative error codes returned to wasm.
    pub fn as_wasm_code(&self) -> i32 {
        match self {
            HostError::NotFound(_) => -1,
            HostError::Denied(_) => -2,
            HostError::Invalid(_) => -3,
            HostError::Backend(_) => -4,
            HostError::BlockNotPinnable => -5,
            HostError::ChainUnavailable(_) => -6,
            HostError::ChainPathUnknown(_) => -7,
        }
    }
}

#[async_trait]
pub trait PetalHost: Send + Sync {
    /// Read the file at `path` from the surrounding VFS.
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError>;

    /// Write `bytes` to the writable file at `path` in the surrounding
    /// VFS.
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError>;

    /// Read a pinned-block view of a chain VFS path. `chain` is the
    /// canonical chain id (e.g. `"ethereum"`); `path` is the
    /// chains-VFS-relative path; `block` is the block number.
    ///
    /// Onchain petals call this via `bloom.chain_read_at`. Local petals
    /// reach the live chain state via `vfs_read` instead.
    async fn chain_read_at(
        &self,
        chain: &str,
        path: &str,
        block: u64,
    ) -> Result<Vec<u8>, HostError>;
}

/// An always-denying host. Useful as a default and in tests where the
/// petal under test should not be able to touch the VFS.
pub struct DenyHost;

#[async_trait]
impl PetalHost for DenyHost {
    async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn chain_read_at(
        &self,
        _chain: &str,
        _path: &str,
        _block: u64,
    ) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_distinct() {
        let codes: Vec<i32> = vec![
            HostError::NotFound("x".into()).as_wasm_code(),
            HostError::Denied("x".into()).as_wasm_code(),
            HostError::Invalid("x".into()).as_wasm_code(),
            HostError::Backend("x".into()).as_wasm_code(),
            HostError::BlockNotPinnable.as_wasm_code(),
            HostError::ChainUnavailable("eth".into()).as_wasm_code(),
            HostError::ChainPathUnknown("p".into()).as_wasm_code(),
        ];
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "codes overlap: {codes:?}");
        for c in codes {
            assert!(c < 0, "host error codes must be negative, got {c}");
        }
    }

    #[tokio::test]
    async fn deny_host_denies_chain_read() {
        let h = DenyHost;
        assert!(matches!(
            h.chain_read_at("eth", "chains/eth/state/0x0/balance", 1).await,
            Err(HostError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn deny_host_denies_both_directions() {
        let h = DenyHost;
        assert!(matches!(h.vfs_read("any").await, Err(HostError::Denied(_))));
        assert!(matches!(
            h.vfs_write("any", b"x").await,
            Err(HostError::Denied(_))
        ));
    }
}
