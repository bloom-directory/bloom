//! Host interface a petal can call back into.
//!
//! Implementations bridge wasm petals to the surrounding system. The
//! production impl wraps the daemon's [`bloom_vfs::Vfs`]; tests
//! typically use an in-memory mock. Capability checks happen *before*
//! the host call in `vm.rs` — the host impl does not need to enforce
//! them itself.

use async_trait::async_trait;

use crate::abi::{
    ChainRequest, ChainResponse, EvmOutboxInspection, EvmOutboxOutcome, EvmTransactionRequest,
    HttpRequest, HttpResponse, PetalRouteContext, SignBatchOutcome, SignBatchRequest, SignOutcome,
    SignRequest,
};
use crate::policy::NetPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostVfsEntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostVfsEntry {
    pub name: String,
    pub kind: HostVfsEntryKind,
    pub mode: u32,
    pub size: Option<u64>,
    pub link_target: Option<String>,
}

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
}

impl HostError {
    /// Stable negative error codes returned to wasm.
    pub fn as_wasm_code(&self) -> i32 {
        match self {
            HostError::NotFound(_) => -1,
            HostError::Denied(_) => -2,
            HostError::Invalid(_) => -3,
            HostError::Backend(_) => -4,
        }
    }
}

#[async_trait]
pub trait PetalHost: Send + Sync {
    /// Look up an entry at `path` from the surrounding VFS.
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError>;

    /// Read the file at `path` from the surrounding VFS.
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError>;

    /// List child entries at `path` from the surrounding VFS.
    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError>;

    /// Write `bytes` to the writable file at `path` in the surrounding
    /// VFS.
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError>;

    /// Perform a daemon-mediated HTTP request. Default-deny; production
    /// hosts opt in explicitly.
    async fn http_fetch(
        &self,
        _req: HttpRequest,
        _policy: NetPolicy,
        _max_response_bytes: usize,
    ) -> Result<HttpResponse, HostError> {
        Err(HostError::Denied("http_fetch".into()))
    }

    /// Sign a precomputed 32-byte hash with a daemon-held wallet key.
    /// Default-deny; keys never cross into the petal.
    async fn sign_hash(&self, _req: SignRequest) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("sign_hash".into()))
    }

    /// Structured component signing result for `bloom:sign/signing@0.1.0`.
    /// Hosts that have not opted into staged approval retain the v0.1 behavior.
    async fn sign_hash_outcome(&self, req: SignRequest) -> Result<SignOutcome, HostError> {
        self.sign_hash(req).await.map(SignOutcome::Signature)
    }

    /// Sign an exact ordered set of hashes under one staged approval. Hosts
    /// must not return a partial signature vector.
    async fn sign_hashes_outcome(
        &self,
        _req: SignBatchRequest,
    ) -> Result<SignBatchOutcome, HostError> {
        Err(HostError::Denied("sign_hashes".into()))
    }

    /// Stage a generic EVM transaction in the daemon outbox. Hosts default to
    /// deny so a package cannot gain transaction authority merely by importing
    /// the WIT interface.
    async fn evm_tx_stage(
        &self,
        _req: EvmTransactionRequest,
    ) -> Result<EvmOutboxOutcome, HostError> {
        Err(HostError::Denied("evm_tx_stage".into()))
    }

    /// Confirm a previously staged generic EVM transaction. Transaction bytes
    /// are always read from the persisted outbox entry, not component input.
    async fn evm_tx_confirm(
        &self,
        _wallet: String,
        _chain: String,
        _outbox_id: String,
        _acknowledge_warnings: bool,
        _context: Option<PetalRouteContext>,
    ) -> Result<EvmOutboxOutcome, HostError> {
        Err(HostError::Denied("evm_tx_confirm".into()))
    }

    /// Inspect an outbox entry owned by the trusted route package.
    async fn evm_tx_inspect(
        &self,
        _wallet: String,
        _chain: String,
        _outbox_id: String,
        _context: Option<PetalRouteContext>,
    ) -> Result<EvmOutboxInspection, HostError> {
        Err(HostError::Denied("evm_tx_inspect".into()))
    }

    /// Perform a daemon-mediated chain read. Default-deny; production hosts
    /// opt in explicitly so chain RPC access remains policy mediated.
    async fn chain_read(&self, _req: ChainRequest) -> Result<ChainResponse, HostError> {
        Err(HostError::Denied("chain_read".into()))
    }
}

/// An always-denying host. Useful as a default and in tests where the
/// petal under test should not be able to touch the VFS.
pub struct DenyHost;

#[async_trait]
impl PetalHost for DenyHost {
    async fn vfs_lookup(&self, _path: &str) -> Result<HostVfsEntry, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn vfs_list(&self, _path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
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
        ];
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "codes overlap: {codes:?}");
        for c in codes {
            assert!(c < 0, "host error codes must be negative, got {c}");
        }
    }

    /// The wasm-facing error codes are part of the local host ABI. Pin the
    /// exact numeric assignments so a careless swap gets caught at test time.
    #[test]
    fn error_codes_are_pinned() {
        assert_eq!(HostError::NotFound("x".into()).as_wasm_code(), -1);
        assert_eq!(HostError::Denied("x".into()).as_wasm_code(), -2);
        assert_eq!(HostError::Invalid("x".into()).as_wasm_code(), -3);
        assert_eq!(HostError::Backend("x".into()).as_wasm_code(), -4);
    }

    #[tokio::test]
    async fn deny_host_denies_both_directions() {
        let h = DenyHost;
        assert!(matches!(h.vfs_read("any").await, Err(HostError::Denied(_))));
        assert!(matches!(h.vfs_list("any").await, Err(HostError::Denied(_))));
        assert!(matches!(
            h.vfs_write("any", b"x").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            h.http_fetch(
                HttpRequest {
                    method: "GET".into(),
                    url: "https://example.com/".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                NetPolicy::deny_all(),
                1024,
            )
            .await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            h.sign_hash(SignRequest {
                wallet: "0x0".into(),
                hash32: [0u8; 32],
                purpose: "test".into(),
                context: None,
            })
            .await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            h.chain_read(ChainRequest {
                chain: "polygon".into(),
                method: "eth_call".into(),
                params_json: "{}".into(),
                context: None,
            })
            .await,
            Err(HostError::Denied(_))
        ));
    }
}
