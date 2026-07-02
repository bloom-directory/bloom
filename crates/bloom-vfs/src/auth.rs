use std::sync::Arc;

use bloom_auth_api::{ApprovalVerifier, AuthStoreView, AuthStoreWriter};

use crate::handler::HandlerError;

/// Shared authorization services injected by the daemon.
///
/// VFS handlers own most signer-sensitive write surfaces, but the concrete
/// auth store/verifier belongs outside the NFS-facing crate. This handle keeps
/// the dependency direction narrow: handlers can ask for Sealed Approval
/// services while the NFS-facing crate stays out of the authorization TCB.
#[derive(Clone, Default)]
pub struct AuthServices {
    approval_verifier: Option<Arc<dyn ApprovalVerifier>>,
    store: Option<Arc<dyn AuthStoreView>>,
    writer: Option<Arc<dyn AuthStoreWriter>>,
}

impl AuthServices {
    pub fn new(
        approval_verifier: Option<Arc<dyn ApprovalVerifier>>,
        store: Option<Arc<dyn AuthStoreView>>,
        writer: Option<Arc<dyn AuthStoreWriter>>,
    ) -> Self {
        Self {
            approval_verifier,
            store,
            writer,
        }
    }

    pub fn with_approval_verifier(mut self, verifier: Arc<dyn ApprovalVerifier>) -> Self {
        self.approval_verifier = Some(verifier);
        self
    }

    pub fn with_store(mut self, store: Arc<dyn AuthStoreView>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_writer(mut self, writer: Arc<dyn AuthStoreWriter>) -> Self {
        self.writer = Some(writer);
        self
    }

    pub fn approval_verifier(&self) -> Option<&Arc<dyn ApprovalVerifier>> {
        self.approval_verifier.as_ref()
    }

    pub fn require_approval_verifier(&self) -> Result<&Arc<dyn ApprovalVerifier>, HandlerError> {
        self.approval_verifier.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval verifier is not wired".into())
        })
    }

    pub fn store(&self) -> Option<&Arc<dyn AuthStoreView>> {
        self.store.as_ref()
    }

    pub fn require_store(&self) -> Result<&Arc<dyn AuthStoreView>, HandlerError> {
        self.store.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval auth store is not wired".into())
        })
    }

    pub fn writer(&self) -> Option<&Arc<dyn AuthStoreWriter>> {
        self.writer.as_ref()
    }

    pub fn require_writer(&self) -> Result<&Arc<dyn AuthStoreWriter>, HandlerError> {
        self.writer.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval auth store writer is not wired".into())
        })
    }

    pub fn is_wired(&self) -> bool {
        self.approval_verifier.is_some() && self.store.is_some() && self.writer.is_some()
    }
}
