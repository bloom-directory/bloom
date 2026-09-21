//! Exact-package eligibility values shared by the existing wallet policy coordinator.
//!
//! These values grant no signing authority and persist no separate Petal journal.

use bloom_broker_api::{
    CanonicalWalletPolicy, CeremonyState, Digest32, OperationId, PolicyDestination,
    PolicyUpdatePrepareResponse, SignedPolicySnapshot,
};

/// Preserve every existing restriction and append only the requested exact package hash.
pub fn policy_with_package(
    current: &CanonicalWalletPolicy,
    package_hash: &Digest32,
) -> CanonicalWalletPolicy {
    policy_with_packages(current, std::slice::from_ref(package_hash))
}

/// Preserve every existing restriction and append each requested exact package
/// hash once, in order.
pub fn policy_with_packages(
    current: &CanonicalWalletPolicy,
    package_hashes: &[Digest32],
) -> CanonicalWalletPolicy {
    let mut proposed = current.clone();
    for package_hash in package_hashes {
        if !proposed.allowed_petal_packages.contains(package_hash) {
            proposed.allowed_petal_packages.push(package_hash.clone());
        }
    }
    proposed
}

/// Preserve every existing restriction and append each requested destination
/// once, in order. Destinations are never removed or rewritten.
pub fn policy_with_destinations(
    current: &CanonicalWalletPolicy,
    destinations: &[PolicyDestination],
) -> CanonicalWalletPolicy {
    let mut proposed = current.clone();
    for destination in destinations {
        if !proposed.allowed_destinations.contains(destination) {
            proposed.allowed_destinations.push(destination.clone());
        }
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
    /// Whether this change carries every package and every destination the
    /// caller asked for. False means it is somebody else's change.
    pub includes_requested: bool,
}
