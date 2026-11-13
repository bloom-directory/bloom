//! Broker fixture and provenance catalog shared by the Solana engine tests.
#![allow(dead_code)]

use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalPrepareState, Base64UrlBytes, CryptoSuite, DecimalU64,
    Digest32, KeyPublic, KeyRef, KeyRequest, KeyRole, KeySpec, MachineBrokerRequest,
    MachineBrokerResponse, MachineBrokerService, NormalizedSignature, ProtocolError,
    ProtocolErrorCode, ProvenanceCatalog, ProvenanceOperationClass, ProvenanceRecord,
    ProvenanceSubject, SealedApprovalPrepareResponse, ServiceFuture, SigningPayloads,
    SigningResult, Token, WalletPublic, WalletRequest,
};
use sha2::{Digest as _, Sha256};

pub fn token(s: &str) -> Token {
    Token::new(s).unwrap()
}
pub fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

pub struct BrokerFixture {
    pub child_signing_key: ed25519_dalek::SigningKey,
    pub child_key_ref: KeyRef,
}

impl BrokerFixture {
    pub fn new() -> Self {
        let child_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xaa; 32]);
        let pubkey = child_signing_key.verifying_key().to_bytes();
        Self {
            child_signing_key,
            child_key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("primary"),
                locator: "wallet/derived/solana-0".into(),
                key_spec: KeySpec::Ed25519,
                public_key_fingerprint: Digest32::from_bytes(Sha256::digest(pubkey).into()),
                derivation: None,
            },
        }
    }
    pub fn child_pubkey(&self) -> [u8; 32] {
        self.child_signing_key.verifying_key().to_bytes()
    }
}

impl MachineBrokerService for BrokerFixture {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            match request {
                MachineBrokerRequest::WalletGetPublic(WalletRequest { wallet_id }) => {
                    Ok(MachineBrokerResponse::WalletGetPublic(WalletPublic {
                        wallet_id,
                        wallet_kind: token("local"),
                        root_key_ref: None,
                        key_refs: vec![self.child_key_ref.clone()],
                        policy_version: DecimalU64::new(1),
                        policy_digest: digest(1),
                        wallet_revocation_epoch: DecimalU64::new(1),
                    }))
                }
                // Selection resolves candidates from the fresh account
                // projection; serve the fixture's single active child.
                MachineBrokerRequest::WalletAccounts(WalletRequest { wallet_id }) => Ok(
                    MachineBrokerResponse::WalletAccounts(bloom_broker_api::WalletAccountsPublic {
                        wallet_id,
                        seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                        accounts: vec![bloom_broker_api::DerivedAccountPublic {
                            key_ref: self.child_key_ref.clone(),
                            wallet_seed_profile:
                                bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                            derivation_profile:
                                bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                            path: "m/44'/501'/0'/0'".into(),
                            canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                            public_key_encoding:
                                bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer,
                            public_key_fingerprint: self
                                .child_key_ref
                                .public_key_fingerprint
                                .clone(),
                            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                            chain_projections: vec![],
                            lifecycle: bloom_broker_api::AccountLifecycleState::Active,
                        }],
                    }),
                ),
                MachineBrokerRequest::KeyGetPublic(KeyRequest { key_ref }) => {
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        role: KeyRole::Derived,
                        key_ref,
                        canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                        addresses: vec![],
                        supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                    }))
                }
                MachineBrokerRequest::SigningSign(sign_request) => {
                    let SigningPayloads::Single { payload } = &sign_request.payloads else {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::MalformedFrame,
                            "expected single payload",
                        ));
                    };
                    use ed25519_dalek::Signer as _;
                    let signature = self.child_signing_key.sign(payload.decode().as_slice());
                    Ok(MachineBrokerResponse::SigningSign(SigningResult {
                        operation_id: sign_request.operation_id,
                        operation_digest: sign_request.operation_digest,
                        signatures: vec![NormalizedSignature {
                            crypto_suite: CryptoSuite::Ed25519Message,
                            bytes: Base64UrlBytes::from_bytes(&signature.to_bytes()),
                        }],
                        signer_receipt_digest: digest(90),
                        broker_receipt_digest: digest(91),
                    }))
                }
                MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
                    surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
                    terms,
                    ..
                }) => Ok(MachineBrokerResponse::SealedApprovalPrepare(
                    SealedApprovalPrepareResponse {
                        approval_id: terms.approval_id().unwrap_or_else(|_| digest(7)),
                        state: ApprovalPrepareState::AwaitingCeremony,
                        ceremony_url: "http://localhost:18734/ceremony".into(),
                        ceremony_expires_at_ms: terms.expires_at_ms,
                        review_manifest_digest: digest(92),
                    },
                )),
                other => Err(ProtocolError::new(
                    ProtocolErrorCode::UnknownMethod,
                    format!("unhandled {other:?}"),
                )),
            }
        })
    }
}

pub fn catalog() -> ProvenanceCatalog {
    ProvenanceCatalog {
        schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
        records: vec![ProvenanceRecord {
            subject: ProvenanceSubject::System {
                component_id: token("bloom-machine"),
                operation_class: token("solana.transfer.confirm"),
            },
            publisher: token("bloom-installer"),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: token("solana.native-transfer"),
                fee_asset: Some(bloom_broker_api::ProvenanceFeeAsset {
                    chain: token("solana"),
                    asset: "native".into(),
                }),
            }],
            installer_key_id: token("installer-key"),
            installer_signature: Base64UrlBytes::from_bytes(&[11; 64]),
        }],
    }
}
