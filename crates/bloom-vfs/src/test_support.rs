use std::sync::Arc;

use async_trait::async_trait;
use bloom_broker_api::{
    Base64UrlBytes, CanonicalWalletPolicy, CredentialPublic, CryptoSuite, DecimalU64, Digest32,
    KeyPublic, KeyRef, KeySpec, ProtocolError, ProtocolErrorCode, SignedPolicySnapshot, Token,
    WalletPublic,
};
use bloom_machine_client::{
    ProjectionFreshness, ProjectionVerification, WalletProjection, WalletProjectionReader,
};
use sha2::Digest as _;

#[derive(Clone)]
struct StaticWalletProjection(WalletProjection);

#[async_trait]
impl WalletProjectionReader for StaticWalletProjection {
    async fn list_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        Ok(vec![self.0.clone()])
    }

    async fn get_wallet(&self, wallet_id: &Token) -> Result<WalletProjection, ProtocolError> {
        if self.0.wallet.wallet_id == *wallet_id {
            Ok(self.0.clone())
        } else {
            Err(ProtocolError::new(
                ProtocolErrorCode::BackendInvalidRequest,
                "unknown test wallet",
            ))
        }
    }

    fn cached_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        Ok(vec![self.0.clone()])
    }
}

pub(crate) fn wallet_projection_reader(
    wallet: &str,
    address: &str,
) -> Arc<dyn WalletProjectionReader> {
    let wallet_id = Token::new(wallet.to_owned()).unwrap();
    let key_ref = KeyRef {
        backend: Token::new("test").unwrap(),
        backend_instance: Token::new("projection").unwrap(),
        locator: format!("{wallet}/root"),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: Digest32::from_bytes([1; 32]),
        derivation: None,
    };
    let canonical = serde_jcs::to_vec(&CanonicalWalletPolicy {
        wallet_id: wallet_id.clone(),
        maximum_approval_lifetime_ms: 300_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
    })
    .unwrap();
    let policy_digest = Digest32::from_bytes(sha2::Sha256::digest(&canonical).into());
    Arc::new(StaticWalletProjection(WalletProjection {
        wallet: WalletPublic {
            wallet_id: wallet_id.clone(),
            wallet_kind: Token::new("passkey").unwrap(),
            root_key_ref: Some(key_ref.clone()),
            key_refs: vec![key_ref.clone()],
            policy_version: DecimalU64::new(1),
            policy_digest: policy_digest.clone(),
            wallet_revocation_epoch: DecimalU64::new(0),
        },
        keys: vec![KeyPublic {
            key_ref,
            role: bloom_broker_api::KeyRole::WalletRoot,
            canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
            addresses: vec![address.to_owned()],
            supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        }],
        credentials: Vec::<CredentialPublic>::new(),
        policy: SignedPolicySnapshot {
            wallet_id,
            version: DecimalU64::new(1),
            canonical_policy: Base64UrlBytes::from_bytes(&canonical),
            policy_digest,
            policy_signing_key_id: Token::new("policy-key").unwrap(),
            policy_verifying_key: Base64UrlBytes::from_bytes(&[3; 32]),
            signer_signature: Base64UrlBytes::from_bytes(&[4; 64]),
        },
        source_protocol: "bloom.machine-broker.v1".into(),
        response_digest: Digest32::from_bytes([5; 32]),
        observed_at_ms: 1,
        freshness: ProjectionFreshness::Fresh,
        verification: ProjectionVerification::AuthenticatedBroker,
    }))
}
