use std::sync::Arc;

use bloom_auth_api::{
    ApprovalVerifier, AuthStoreView, AuthStoreWriter, GrantStore, PetalHost, PolicyEvaluator,
    SigningAttestationSchemaRegistry, WalletRegistrationCoordinator,
};

use crate::handler::HandlerError;

/// Shared authorization services injected by the daemon.
///
/// VFS handlers own most signer-sensitive write surfaces, but the concrete
/// auth store/verifier belongs outside the NFS-facing crate. This handle keeps
/// the dependency direction narrow: handlers can ask for Layer-B services when
/// a surface is migrated, while tests and legacy setups default to no services.
#[derive(Clone, Default)]
pub struct AuthServices {
    approval_verifier: Option<Arc<dyn ApprovalVerifier>>,
    store: Option<Arc<dyn AuthStoreView>>,
    writer: Option<Arc<dyn AuthStoreWriter>>,
    /// WS-1: in-memory [`GrantStore`] backing [`PetalHost::sign_hash`].
    grant_store: Option<Arc<dyn GrantStore>>,
    /// WS-1: host signing API exposed to first-party Petals.
    petal_host: Option<Arc<dyn PetalHost>>,
    /// WS-1: per-`(petal_id, intent)` attestation schema registry.
    attestation_registry: Option<Arc<dyn SigningAttestationSchemaRegistry>>,
    /// WS-3: policy taxonomy evaluator (Hard / StepUp / Informational).
    policy_evaluator: Option<Arc<dyn PolicyEvaluator>>,
    /// Daemon-owned asynchronous passkey registration coordinator.
    registration_coordinator: Option<Arc<dyn WalletRegistrationCoordinator>>,
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
            grant_store: None,
            petal_host: None,
            attestation_registry: None,
            policy_evaluator: None,
            registration_coordinator: None,
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

    pub fn with_grant_store(mut self, grant_store: Arc<dyn GrantStore>) -> Self {
        self.grant_store = Some(grant_store);
        self
    }

    pub fn with_petal_host(mut self, petal_host: Arc<dyn PetalHost>) -> Self {
        self.petal_host = Some(petal_host);
        self
    }

    pub fn with_attestation_registry(
        mut self,
        registry: Arc<dyn SigningAttestationSchemaRegistry>,
    ) -> Self {
        self.attestation_registry = Some(registry);
        self
    }

    pub fn with_policy_evaluator(mut self, policy_evaluator: Arc<dyn PolicyEvaluator>) -> Self {
        self.policy_evaluator = Some(policy_evaluator);
        self
    }

    pub fn with_registration_coordinator(
        mut self,
        coordinator: Arc<dyn WalletRegistrationCoordinator>,
    ) -> Self {
        self.registration_coordinator = Some(coordinator);
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

    pub fn grant_store(&self) -> Option<&Arc<dyn GrantStore>> {
        self.grant_store.as_ref()
    }

    pub fn require_grant_store(&self) -> Result<&Arc<dyn GrantStore>, HandlerError> {
        self.grant_store.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval grant store is not wired".into())
        })
    }

    pub fn petal_host(&self) -> Option<&Arc<dyn PetalHost>> {
        self.petal_host.as_ref()
    }

    pub fn require_petal_host(&self) -> Result<&Arc<dyn PetalHost>, HandlerError> {
        self.petal_host.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval Petal host is not wired".into())
        })
    }

    pub fn attestation_registry(&self) -> Option<&Arc<dyn SigningAttestationSchemaRegistry>> {
        self.attestation_registry.as_ref()
    }

    pub fn require_attestation_registry(
        &self,
    ) -> Result<&Arc<dyn SigningAttestationSchemaRegistry>, HandlerError> {
        self.attestation_registry.as_ref().ok_or_else(|| {
            HandlerError::Unsupported("Sealed Approval attestation registry is not wired".into())
        })
    }

    pub fn policy_evaluator(&self) -> Option<&Arc<dyn PolicyEvaluator>> {
        self.policy_evaluator.as_ref()
    }

    pub fn require_policy_evaluator(&self) -> Result<&Arc<dyn PolicyEvaluator>, HandlerError> {
        self.policy_evaluator
            .as_ref()
            .ok_or_else(|| HandlerError::Unsupported("Policy evaluator is not wired".into()))
    }

    pub fn registration_coordinator(&self) -> Option<&Arc<dyn WalletRegistrationCoordinator>> {
        self.registration_coordinator.as_ref()
    }

    pub fn require_registration_coordinator(
        &self,
    ) -> Result<&Arc<dyn WalletRegistrationCoordinator>, HandlerError> {
        self.registration_coordinator.as_ref().ok_or_else(|| {
            HandlerError::Unsupported(
                "wallet registration requires a running `bloom serve` daemon; start it and \
                 retry"
                    .into(),
            )
        })
    }

    pub fn is_wired(&self) -> bool {
        self.approval_verifier.is_some()
            || self.store.is_some()
            || self.writer.is_some()
            || self.grant_store.is_some()
            || self.petal_host.is_some()
            || self.attestation_registry.is_some()
            || self.policy_evaluator.is_some()
            || self.registration_coordinator.is_some()
    }
}
