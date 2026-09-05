//! Exact-package eligibility values shared by the existing wallet policy coordinator.
//!
//! These values grant no signing authority and persist no separate Petal journal.

use bloom_broker_api::{
    CanonicalWalletPolicy, CeremonyState, Digest32, OperationId, PolicyUpdatePrepareResponse,
    SignedPolicySnapshot,
};

/// Preserve every existing restriction and append only the requested exact package hash.
pub fn policy_with_package(
    current: &CanonicalWalletPolicy,
    package_hash: &Digest32,
) -> CanonicalWalletPolicy {
    let mut proposed = current.clone();
    if !proposed.allowed_petal_packages.contains(package_hash) {
        proposed.allowed_petal_packages.push(package_hash.clone());
    }
    proposed
}

#[derive(Clone, Debug)]
pub enum PetalEligibility {
    Allowed(SignedPolicySnapshot),
    AwaitingPolicyApproval(PendingPolicyUpdate),
}

/// A view of the existing wallet-scoped policy operation, including unrelated consent.
#[derive(Clone, Debug)]
pub struct PendingPolicyUpdate {
    pub operation_id: OperationId,
    pub ceremony_state: CeremonyState,
    /// Present only while the Broker currently offers an actionable owner ceremony.
    pub prepare: Option<PolicyUpdatePrepareResponse>,
    pub status_path: String,
    pub challenge_path: String,
    pub includes_requested_package: bool,
}
