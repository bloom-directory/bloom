//! Key-free advisory planning views derived from authenticated Broker policy.

use bloom_broker_api::CanonicalWalletPolicy;
use bloom_machine_client::WalletProjection;
use bloom_proto::Policy;

/// Translate the canonical Broker policy fields understood by the legacy EVM
/// planner into a conservative, non-authorizing view. Broker independently
/// enforces the canonical snapshot again before any final signature.
pub fn advisory_evm_policy(projection: &WalletProjection, chain: &str) -> Result<Policy, String> {
    let canonical: CanonicalWalletPolicy =
        serde_json::from_slice(&projection.policy.canonical_policy.decode())
            .map_err(|error| format!("parse canonical Broker policy projection: {error}"))?;
    if canonical.wallet_id != projection.wallet.wallet_id {
        return Err("canonical Broker policy projection names a different wallet".into());
    }

    let mut policy = Policy::default();
    for destination in canonical
        .allowed_destinations
        .iter()
        .filter(|destination| destination.chain.as_str() == chain)
    {
        policy
            .allowlists
            .recipients
            .insert(destination.destination.clone());
    }
    if policy.allowlists.recipients.is_empty() {
        // An empty canonical allow-set denies every declared destination in
        // Broker. Preserve that fail-closed meaning in advisory planning.
        policy
            .allowlists
            .recipients
            .insert("__broker_policy_denies_all_destinations__".into());
    }
    Ok(policy)
}

/// Produce a non-authorizing paid-request planning view. Canonical policy has
/// no legacy HTTP cap fields; Broker evaluates the exact payload and canonical
/// policy before signing, so Machine must not invent persistent local limits.
pub fn advisory_paid_http_policy(projection: &WalletProjection) -> Result<Policy, String> {
    let mut policy = advisory_evm_policy(projection, "paid-http")?;
    policy.payments.enabled = true;
    policy.payments.sessions.enabled = true;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use bloom_broker_api::{
        Base64UrlBytes, CryptoSuite, DecimalU64, Digest32, KeyPublic, KeyRef, KeyRole, KeySpec,
        PolicyDestination, SignedPolicySnapshot, Token, WalletPublic,
    };
    use bloom_machine_client::{ProjectionFreshness, ProjectionVerification};
    use sha2::Digest as _;

    use super::*;

    fn projection(destinations: Vec<PolicyDestination>) -> WalletProjection {
        let wallet_id = Token::new("alice").unwrap();
        let root_key_ref = KeyRef {
            backend: Token::new("test").unwrap(),
            backend_instance: Token::new("projection").unwrap(),
            locator: "alice/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::from_bytes([1; 32]),
            derivation: None,
        };
        let canonical = serde_jcs::to_vec(&CanonicalWalletPolicy {
            wallet_id: wallet_id.clone(),
            maximum_approval_lifetime_ms: 60_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: destinations,
            required_verifiers: Vec::new(),
        })
        .unwrap();
        WalletProjection {
            wallet: WalletPublic {
                wallet_id: wallet_id.clone(),
                wallet_kind: Token::new("passkey").unwrap(),
                root_key_ref: Some(root_key_ref.clone()),
                key_refs: vec![root_key_ref.clone()],
                policy_version: DecimalU64::new(1),
                policy_digest: Digest32::from_bytes(sha2::Sha256::digest(&canonical).into()),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            keys: vec![KeyPublic {
                key_ref: root_key_ref,
                role: KeyRole::WalletRoot,
                canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            }],
            credentials: Vec::new(),
            policy: SignedPolicySnapshot {
                wallet_id,
                version: DecimalU64::new(1),
                canonical_policy: Base64UrlBytes::from_bytes(&canonical),
                policy_digest: Digest32::from_bytes(sha2::Sha256::digest(&canonical).into()),
                policy_signing_key_id: Token::new("policy-key").unwrap(),
                policy_verifying_key: Base64UrlBytes::from_bytes(&[1; 32]),
                signer_signature: Base64UrlBytes::from_bytes(&[2; 64]),
            },
            source_protocol: "bloom.machine-broker.v1".into(),
            response_digest: Digest32::from_bytes([3; 32]),
            observed_at_ms: 1,
            freshness: ProjectionFreshness::Fresh,
            verification: ProjectionVerification::AuthenticatedBroker,
        }
    }

    #[test]
    fn canonical_destinations_become_chain_scoped_advisory_allowlist() {
        let allowed = "0x0000000000000000000000000000000000000001";
        let policy = advisory_evm_policy(
            &projection(vec![PolicyDestination {
                chain: Token::new("ethereum").unwrap(),
                destination: allowed.into(),
            }]),
            "ethereum",
        )
        .unwrap();
        assert!(policy.allowlists.recipients.contains(allowed));
        let other_chain = advisory_evm_policy(
            &projection(vec![PolicyDestination {
                chain: Token::new("ethereum").unwrap(),
                destination: allowed.into(),
            }]),
            "base",
        )
        .unwrap();
        assert!(
            other_chain
                .allowlists
                .recipients
                .contains("__broker_policy_denies_all_destinations__")
        );
    }
}
