//! Shared fixtures for the Solana E2E tests against a real local Agave
//! validator. The Broker is an in-process fixture; the Daemon, VFS, wallet
//! handler, Solana engine, reconciler, and validator are real.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use bloom_broker_api::*;
use bloom_daemon::Daemon;
use bloom_machine_client::MachineBrokerClient;
use bloom_proto::{Config, EndpointSpec, HomeDir, HomeWritePermit, SolanaSpec};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use sha2::{Digest as _, Sha256};

pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon art";

/// Overridable so the suite can run against a validator on a non-default
/// port (several developer harnesses keep one on 8899).
pub fn rpc_url() -> String {
    std::env::var("BLOOM_IT_SOLANA_RPC").unwrap_or_else(|_| "http://127.0.0.1:8899".into())
}

pub fn tok(s: &str) -> Token {
    Token::new(s.to_owned()).unwrap()
}
pub fn dig(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

/// Canonical Ed25519 SubjectPublicKeyInfo DER: the fixed 12-byte prefix
/// followed by the raw 32-byte key, as the real Signer publishes it.
pub fn spki(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    out.extend_from_slice(pubkey);
    out
}

pub fn fingerprint_of(pubkey: &[u8; 32]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(spki(pubkey)).into())
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64 message")
}

pub fn step(n: &str, msg: &str) {
    println!("\n=== {n} :: {msg}");
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_daemon=debug")),
        )
        .try_init();
}

/// `reqwest::blocking` builds and drops its own runtime, which panics inside
/// an async context, so it runs on a tokio-naive OS thread.
pub fn rpc(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let url = rpc_url();
    let method = method.to_string();
    std::thread::spawn(move || -> Result<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = reqwest::blocking::Client::new()
            .post(url)
            .json(&body)
            .send()?
            .json()?;
        Ok(resp)
    })
    .join()
    .map_err(|_| anyhow!("rpc thread panicked"))?
}

pub fn balance(address: &str) -> Result<u64> {
    Ok(
        rpc("getBalance", serde_json::json!([address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0),
    )
}

/// Airdrops `lamports` and waits up to 40s for the balance to reach it.
pub async fn airdrop(address: &str, lamports: u64) -> Result<()> {
    rpc("requestAirdrop", serde_json::json!([address, lamports]))?;
    for _ in 0..40 {
        let bal = balance(address)?;
        if bal >= lamports {
            println!("    funded {address}: {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(())
}

pub async fn read_json(daemon: &Daemon, path: &str) -> Result<serde_json::Value> {
    let bytes = daemon
        .vfs
        .read(&VfsPath::parse(path).unwrap())
        .await
        .map_err(|e| anyhow!("read {path}: {e}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn seed() -> Result<[u8; 64]> {
    let seed =
        bloom_signer_derive::seed_from_mnemonic(MNEMONIC).map_err(|e| anyhow!("seed: {e}"))?;
    Ok((*seed).as_slice().try_into().unwrap())
}

/// A temp Bloom home whose config pins `solana-local` to the validator's
/// genesis hash. Broadcasting requires that pin: it is the transaction-level
/// half of the mainnet guard.
pub fn solana_home() -> Result<tempfile::TempDir> {
    let genesis = rpc("getGenesisHash", serde_json::json!([]))?["result"]
        .as_str()
        .ok_or_else(|| anyhow!("validator did not answer getGenesisHash"))?
        .to_string();
    println!("    local validator genesis = {genesis}");
    let tmp = tempfile::tempdir()?;
    let mut cfg = Config::local_default();
    cfg.solana_chains.insert(
        "solana-local".to_string(),
        SolanaSpec {
            name: "solana-local".into(),
            endpoints: vec![EndpointSpec {
                url: rpc_url(),
                weight: 100,
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            }],
            expected_genesis_base58: Some(genesis),
        },
    );
    cfg.save(&tmp.path().join("config.toml"))
        .map_err(|e| anyhow!("save config: {e}"))?;
    Ok(tmp)
}

/// A provenance catalog with the base system records plus `extra`
/// `(action, operation_class, fee_chain)` records.
pub fn catalog(extra: &[(&str, &str, &str)]) -> ProvenanceCatalog {
    let record = |&(action, op, chain): &(&str, &str, &str)| ProvenanceRecord {
        subject: ProvenanceSubject::System {
            component_id: tok("bloom-machine"),
            operation_class: tok(action),
        },
        publisher: tok("bloom-installer"),
        petal_lineage: None,
        operation_classes: vec![ProvenanceOperationClass {
            operation_class: tok(op),
            fee_asset: Some(ProvenanceFeeAsset {
                chain: tok(chain),
                asset: "native".into(),
            }),
        }],
        installer_key_id: tok("installer-key"),
        installer_signature: Base64UrlBytes::from_bytes(&[11; 64]),
    };
    let base = [
        ("system.readiness", "system.readiness", "ethereum"),
        ("transaction.confirm", "transaction.confirm", "ethereum"),
    ];
    let solana = [(
        "solana.transfer.confirm",
        "solana.native-transfer",
        "solana",
    )];
    ProvenanceCatalog {
        schema: PROVENANCE_CATALOG_SCHEMA.into(),
        records: base
            .iter()
            .chain(extra)
            .chain(&solana)
            .map(record)
            .collect(),
    }
}

pub fn daemon_at(
    home: &Path,
    broker: Arc<SolanaBroker>,
    catalog: ProvenanceCatalog,
) -> Result<Daemon> {
    let home = HomeDir::at(home);
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let service: Arc<dyn MachineBrokerService> = broker;
    Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        MachineBrokerClient::new(service),
        catalog,
    )
    .map_err(|e| anyhow!("daemon: {e}"))
}

// ---------------------------------------------------------------- broker ---

/// One derived Solana child, with the private key the fixture signs with.
pub struct Child {
    pub account: u32,
    pub path: String,
    pub pubkey: [u8; 32],
    pub address: String,
    pub signing_key: ed25519_dalek::SigningKey,
    pub key_ref: KeyRef,
}

impl Child {
    /// Derives through the production derivation crate rather than fixture
    /// constants.
    pub fn derive(seed: &[u8; 64], account: u32) -> Result<Self> {
        let derived = bloom_signer_derive::derive_solana_account(seed, account)
            .map_err(|e| anyhow!("derive account {account}: {e}"))?;
        let pubkey = derived.public_key;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived.private_key);
        // The published key must be the one that actually signs.
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            pubkey,
            "account {account}: derived public key does not match its private key"
        );
        Ok(Self {
            account,
            path: derived.path.clone(),
            pubkey,
            address: bs58::encode(pubkey).into_string(),
            signing_key,
            key_ref: KeyRef {
                backend: tok("local"),
                backend_instance: tok("e2e"),
                locator: format!("wallet/derived/solana-{account}"),
                key_spec: KeySpec::Ed25519,
                public_key_fingerprint: fingerprint_of(&pubkey),
                derivation: Some(DerivationRef::Bip39Multicurve {
                    wallet_seed_ref: tok("alice-seed"),
                    profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                    path: derived.path,
                }),
            },
        })
    }

    pub fn fingerprint_hex(&self) -> &str {
        self.key_ref.public_key_fingerprint.as_str()
    }

    fn account_public(&self) -> DerivedAccountPublic {
        DerivedAccountPublic {
            key_ref: self.key_ref.clone(),
            wallet_seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            path: self.path.clone(),
            canonical_public_key: Base64UrlBytes::from_bytes(&spki(&self.pubkey)),
            public_key_encoding: PublicKeyEncoding::Ed25519SpkiDer,
            public_key_fingerprint: fingerprint_of(&self.pubkey),
            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
            chain_projections: vec![ChainAccountProjection {
                chain_family: tok("solana"),
                caip2: "solana:local".into(),
                caip10: format!("solana:local:{}", self.address),
                address: self.address.clone(),
                address_encoding: AddressEncoding::Base58,
            }],
            lifecycle: AccountLifecycleState::Active,
        }
    }

    fn key_public(&self) -> KeyPublic {
        KeyPublic {
            key_ref: self.key_ref.clone(),
            role: KeyRole::Derived,
            canonical_public_key: Base64UrlBytes::from_bytes(&spki(&self.pubkey)),
            addresses: vec![self.address.clone()],
            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
        }
    }
}

/// Broker fixture for wallet `alice` with every child active at once. It
/// answers and signs for the exact key a request names, never a default, so
/// a wrong account selection is observable.
pub struct SolanaBroker {
    pub children: Vec<Child>,
    pub approval_active: AtomicBool,
    /// Every signing call, as (key_ref locator, signed bytes).
    pub sign_calls: parking_lot::Mutex<Vec<(String, Vec<u8>)>>,
}

impl SolanaBroker {
    pub fn new(children: Vec<Child>) -> Arc<Self> {
        Arc::new(Self {
            children,
            approval_active: AtomicBool::new(false),
            sign_calls: parking_lot::Mutex::new(Vec::new()),
        })
    }

    fn child_for(&self, key_ref: &KeyRef, what: &str) -> Result<&Child, ProtocolError> {
        self.children
            .iter()
            .find(|child| &child.key_ref == key_ref)
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    format!("{what} is not a child of this wallet"),
                )
            })
    }

    fn policy(&self, wallet_id: Token) -> SignedPolicySnapshot {
        let canonical = serde_json::to_vec(&CanonicalWalletPolicy {
            clear_signing: None,
            wallet_id: wallet_id.clone(),
            maximum_approval_lifetime_ms: 3_600_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
        })
        .unwrap();
        SignedPolicySnapshot {
            wallet_id,
            version: DecimalU64::new(1),
            canonical_policy: Base64UrlBytes::from_bytes(&canonical),
            policy_digest: Digest32::from_bytes(Sha256::digest(&canonical).into()),
            policy_signing_key_id: tok("e2e-policy-key"),
            policy_verifying_key: Base64UrlBytes::from_bytes(&[12; 32]),
            signer_signature: Base64UrlBytes::from_bytes(&[13; 64]),
        }
    }

    fn wallet_public(&self, wallet_id: Token) -> WalletPublic {
        let p = self.policy(wallet_id.clone());
        WalletPublic {
            wallet_id,
            wallet_kind: tok("local"),
            // A BIP-39 seed root is not signable; the children are the keys.
            root_key_ref: None,
            key_refs: self.children.iter().map(|c| c.key_ref.clone()).collect(),
            policy_version: DecimalU64::new(1),
            policy_digest: p.policy_digest,
            wallet_revocation_epoch: DecimalU64::new(0),
        }
    }
}

impl MachineBrokerService for SolanaBroker {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            match request {
                MachineBrokerRequest::WalletListPublic(_) => {
                    Ok(MachineBrokerResponse::WalletListPublic(vec![
                        self.wallet_public(tok("alice")),
                    ]))
                }
                MachineBrokerRequest::WalletGetPublic(r) => Ok(
                    MachineBrokerResponse::WalletGetPublic(self.wallet_public(r.wallet_id)),
                ),
                MachineBrokerRequest::WalletAccounts(WalletRequest { wallet_id }) => Ok(
                    MachineBrokerResponse::WalletAccounts(WalletAccountsPublic {
                        wallet_id,
                        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
                        accounts: self.children.iter().map(Child::account_public).collect(),
                    }),
                ),
                MachineBrokerRequest::KeyListPublic(_) => Ok(MachineBrokerResponse::KeyListPublic(
                    self.children.iter().map(Child::key_public).collect(),
                )),
                MachineBrokerRequest::KeyGetPublic(r) => Ok(MachineBrokerResponse::KeyGetPublic(
                    self.child_for(&r.key_ref, "key")?.key_public(),
                )),
                MachineBrokerRequest::CredentialListPublic(_) => {
                    Ok(MachineBrokerResponse::CredentialListPublic(Vec::<
                        CredentialPublic,
                    >::new(
                    )))
                }
                MachineBrokerRequest::PolicyRead(WalletRequest { wallet_id }) => {
                    Ok(MachineBrokerResponse::PolicyRead(self.policy(wallet_id)))
                }
                MachineBrokerRequest::SealedApprovalPrepare(r) => Ok(
                    MachineBrokerResponse::SealedApprovalPrepare(SealedApprovalPrepareResponse {
                        approval_id: r.terms.approval_id()?,
                        state: ApprovalPrepareState::AwaitingCeremony,
                        ceremony_url: "http://localhost:18734/ceremony/e2e".into(),
                        ceremony_expires_at_ms: r.terms.expires_at_ms,
                        review_manifest_digest: dig(8),
                    }),
                ),
                MachineBrokerRequest::SealedApprovalStatus(r) => {
                    let active = self.approval_active.load(Ordering::SeqCst);
                    Ok(MachineBrokerResponse::SealedApprovalStatus(
                        ApprovalPublicStatus {
                            approval_id: r.id,
                            wallet_id: tok("alice"),
                            state: if active {
                                ApprovalLifecycleState::Active
                            } else {
                                ApprovalLifecycleState::AwaitingCeremony
                            },
                            effective_claim_assurance: None,
                            ceremony_url: (!active)
                                .then(|| "http://localhost:18734/ceremony/e2e".into()),
                            ceremony_expires_at_ms: (!active).then(|| DecimalU64::new(u64::MAX)),
                        },
                    ))
                }
                MachineBrokerRequest::SigningSign(r) => {
                    let SigningPayloads::Single { payload } = &r.payloads else {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::MalformedFrame,
                            "expected a single payload",
                        ));
                    };
                    let child = self.child_for(&r.key_ref, "signing key")?;
                    let bytes = payload.decode();
                    self.sign_calls
                        .lock()
                        .push((child.key_ref.locator.clone(), bytes.clone()));
                    use ed25519_dalek::Signer as _;
                    let sig = child.signing_key.sign(&bytes);
                    Ok(MachineBrokerResponse::SigningSign(SigningResult {
                        operation_id: r.operation_id,
                        operation_digest: r.operation_digest,
                        signatures: vec![NormalizedSignature {
                            crypto_suite: CryptoSuite::Ed25519Message,
                            bytes: Base64UrlBytes::from_bytes(&sig.to_bytes()),
                        }],
                        signer_receipt_digest: dig(9),
                        broker_receipt_digest: dig(10),
                    }))
                }
                other => Err(ProtocolError::new(
                    ProtocolErrorCode::UnknownMethod,
                    format!("unhandled {other:?}"),
                )),
            }
        })
    }
}
