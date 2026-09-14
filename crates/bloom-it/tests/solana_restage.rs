//! The blockhash-expiry → restage recovery E2E, the companion to
//! `solana_workflow` for the failure path that workflow test never reaches.
//!
//! It proves two coupled properties of Bloom's Solana engine against a REAL
//! local Agave validator:
//!
//!   1. Fail-closed on expiry. Once the validator's block height passes a
//!      staged transfer's `last_valid_block_height`, `confirm` MUST refuse to
//!      sign or broadcast — even with owner approval already active, so the
//!      only possible reason to refuse is the expired blockhash.
//!   2. Recovery via restage. Writing `restage` rebuilds the SAME economic
//!      intent (same account pin, destination, lamports) with a FRESH blockhash
//!      as a new replacement entry, marks the old one `failed`/`Expired`, and
//!      links the two through `restage_advice.json`. Confirming the replacement
//!      then signs, broadcasts, and finalizes exactly once.
//!
//! Boundary, as in `solana_workflow` and the EVM `anvil_e2e`: the Broker is an
//! in-process fixture. The Daemon, VFS, wallet handler, Solana engine,
//! reconciler, and validator are real.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use bloom_broker_api::*;
use bloom_daemon::Daemon;
use bloom_machine_client::MachineBrokerClient;
use bloom_proto::{Config, EndpointSpec, HomeDir, HomeWritePermit, SolanaSpec};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use sha2::{Digest as _, Sha256};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon art";
const RPC: &str = "http://127.0.0.1:8899";
const LAMPORTS: u64 = 250_000_000;

fn tok(s: &str) -> Token {
    Token::new(s.to_owned()).unwrap()
}
fn dig(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}
/// Canonical Ed25519 SubjectPublicKeyInfo DER: the fixed 12-byte prefix
/// followed by the raw 32-byte key. Matches what the real Signer publishes.
fn spki(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    out.extend_from_slice(pubkey);
    out
}

// ---------------------------------------------------------------- broker ---

struct SolanaBroker {
    signing_key: ed25519_dalek::SigningKey,
    pubkey: [u8; 32],
    key_ref: KeyRef,
    approval_active: AtomicBool,
    sign_calls: parking_lot::Mutex<Vec<Vec<u8>>>,
}

impl SolanaBroker {
    fn policy(&self, wallet_id: Token) -> SignedPolicySnapshot {
        let canonical = serde_json::to_vec(&CanonicalWalletPolicy {
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
            root_key_ref: None,
            key_refs: vec![self.key_ref.clone()],
            policy_version: DecimalU64::new(1),
            policy_digest: p.policy_digest,
            wallet_revocation_epoch: DecimalU64::new(0),
        }
    }

    fn key_public(&self) -> KeyPublic {
        KeyPublic {
            key_ref: self.key_ref.clone(),
            role: KeyRole::Derived,
            canonical_public_key: Base64UrlBytes::from_bytes(&spki(&self.pubkey)),
            addresses: vec![bs58::encode(self.pubkey).into_string()],
            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
        }
    }

    fn accounts(&self, wallet_id: Token) -> WalletAccountsPublic {
        WalletAccountsPublic {
            wallet_id,
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            accounts: vec![DerivedAccountPublic {
                key_ref: self.key_ref.clone(),
                wallet_seed_profile: WalletSeedProfile::Bip39MulticurveV1,
                derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                path: "m/44'/501'/0'/0'".into(),
                canonical_public_key: Base64UrlBytes::from_bytes(&spki(&self.pubkey)),
                public_key_encoding: PublicKeyEncoding::Ed25519SpkiDer,
                public_key_fingerprint: Digest32::from_bytes(
                    Sha256::digest(spki(&self.pubkey)).into(),
                ),
                supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                chain_projections: vec![],
                lifecycle: AccountLifecycleState::Active,
            }],
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
                    MachineBrokerResponse::WalletAccounts(self.accounts(wallet_id)),
                ),
                MachineBrokerRequest::KeyListPublic(_) => {
                    Ok(MachineBrokerResponse::KeyListPublic(vec![
                        self.key_public(),
                    ]))
                }
                MachineBrokerRequest::KeyGetPublic(_) => {
                    Ok(MachineBrokerResponse::KeyGetPublic(self.key_public()))
                }
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
                    let bytes = payload.decode();
                    self.sign_calls.lock().push(bytes.clone());
                    use ed25519_dalek::Signer as _;
                    let sig = self.signing_key.sign(&bytes);
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

// ------------------------------------------------------------------- rpc ---

/// `reqwest::blocking` builds and drops its own runtime, which panics if that
/// happens inside an async context — so run it on a tokio-naive OS thread.
fn rpc(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let method = method.to_string();
    std::thread::spawn(move || -> Result<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = reqwest::blocking::Client::new()
            .post(RPC)
            .json(&body)
            .send()?
            .json()?;
        Ok(resp)
    })
    .join()
    .map_err(|_| anyhow!("rpc thread panicked"))?
}

fn step(n: &str, msg: &str) {
    println!("\n=== {n} :: {msg}");
}

async fn read_json(daemon: &Daemon, path: &str) -> Result<serde_json::Value> {
    let bytes = daemon
        .vfs
        .read(&VfsPath::parse(path).unwrap())
        .await
        .map_err(|e| anyhow!("read {path}: {e}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn block_height() -> Result<u64> {
    rpc("getBlockHeight", serde_json::json!([]))?["result"]
        .as_u64()
        .ok_or_else(|| anyhow!("validator did not answer getBlockHeight"))
}

/// A unique, non-fixed 32-byte destination so the test is idempotent even on a
/// reused ledger: a fresh address starts at zero balance and cannot collide
/// with a prior run. Derived from a monotonic nonce rather than a fixed byte
/// pattern.
fn unique_destination() -> [u8; 32] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-restage-e2e-destination/v1");
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.finalize().into()
}

// ------------------------------------------------------------------ main ---

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn solana_expired_blockhash_fails_closed_then_restages() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_daemon=debug")),
        )
        .try_init();

    // 1. Derive the Solana child from the mnemonic through the production
    //    derivation crate — not a hardcoded fixture key.
    step("1", "derive the Solana account from the BIP-39 mnemonic");
    let seed =
        bloom_signer_derive::seed_from_mnemonic(MNEMONIC).map_err(|e| anyhow!("seed: {e}"))?;
    let seed64: [u8; 64] = (*seed).as_slice().try_into().unwrap();
    let derived = bloom_signer_derive::derive_solana_account(&seed64, 0)
        .map_err(|e| anyhow!("derive: {e}"))?;
    let pubkey = derived.public_key;
    let address = bs58::encode(pubkey).into_string();
    println!("    path        {}", derived.path);
    println!("    address     {address}");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived.private_key);
    assert_eq!(signing_key.verifying_key().to_bytes(), pubkey);

    // 2. Real daemon over a temp home, wired to the local validator.
    step("2", "build a real Daemon with the Solana chain configured");
    let broker = Arc::new(SolanaBroker {
        signing_key,
        pubkey,
        key_ref: KeyRef {
            backend: tok("local"),
            backend_instance: tok("e2e"),
            locator: "wallet/derived/solana-0".into(),
            key_spec: KeySpec::Ed25519,
            public_key_fingerprint: Digest32::from_bytes(Sha256::digest(spki(&pubkey)).into()),
            derivation: Some(DerivationRef::Bip39Multicurve {
                wallet_seed_ref: tok("wallet-seed"),
                profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                path: derived.path.clone(),
            }),
        },
        approval_active: AtomicBool::new(false),
        sign_calls: parking_lot::Mutex::new(Vec::new()),
    });

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
                url: RPC.into(),
                weight: 100,
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            }],
            expected_genesis_base58: Some(genesis.clone()),
            allow_broadcast: true,
        },
    );
    cfg.save(&tmp.path().join("config.toml"))
        .map_err(|e| anyhow!("save config: {e}"))?;

    let home = HomeDir::at(tmp.path());
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let record = |action: &str, op: &str, chain: &str| ProvenanceRecord {
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
    let catalog = ProvenanceCatalog {
        schema: PROVENANCE_CATALOG_SCHEMA.into(),
        records: vec![
            record("system.readiness", "system.readiness", "ethereum"),
            record("transaction.confirm", "transaction.confirm", "ethereum"),
            record(
                "solana.transfer.confirm",
                "solana.native-transfer",
                "solana",
            ),
        ],
    };
    let service: Arc<dyn MachineBrokerService> = broker.clone();
    let daemon = Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        MachineBrokerClient::new(service),
        catalog,
    )
    .map_err(|e| anyhow!("daemon: {e}"))?;
    println!("    daemon constructed; solana-local admitted by the genesis guard");

    // 3. Fund the derived child and record its starting balance.
    step("3", "airdrop to the mnemonic-derived fee payer");
    rpc(
        "requestAirdrop",
        serde_json::json!([address, 2_000_000_000u64]),
    )?;
    for _ in 0..40 {
        let bal = rpc("getBalance", serde_json::json!([address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
        if bal >= 2_000_000_000 {
            println!("    funded: {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let payer_before = rpc("getBalance", serde_json::json!([address]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    println!("    fee payer balance before = {payer_before} lamports");

    // 4. A unique, non-fixed destination — idempotent on a reused ledger.
    let destination_bytes = unique_destination();
    let destination = bs58::encode(destination_bytes).into_string();
    let dest_before = rpc("getBalance", serde_json::json!([destination]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    println!("    unique destination {destination} balance before = {dest_before} lamports");
    assert_eq!(
        dest_before, 0,
        "a freshly derived destination must start empty"
    );

    // 5. Stage transfer T1.
    step("5", "stage transfer T1");
    let new_tx = VfsPath::parse("/wallets/alice/chains/solana-local/outbox/new.tx").unwrap();
    let intent = serde_json::json!({"destination": destination, "lamports": LAMPORTS});
    daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&intent)?.as_slice())
        .await
        .map_err(|e| anyhow!("stage write: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let t1_id = pending
        .first()
        .ok_or_else(|| anyhow!("no pending entry staged"))?
        .name
        .clone();
    let t1 = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/pending/{t1_id}/intent.json"),
    )
    .await?;
    let t1_lvbh = t1["last_valid_block_height"]
        .as_u64()
        .ok_or_else(|| anyhow!("T1 intent missing last_valid_block_height"))?;
    let t1_blockhash = t1["blockhash"].as_str().unwrap().to_string();
    assert_eq!(t1["fee_payer"].as_str().unwrap(), address);
    assert_eq!(t1["lamports"].as_u64(), Some(LAMPORTS));
    println!("    staged T1 id={t1_id} last_valid_block_height={t1_lvbh} blockhash={t1_blockhash}");

    // 6. Age the blockhash: wait until block height passes T1's window.
    step(
        "6",
        "wait until block height passes T1's last_valid_block_height",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut current = block_height()?;
    while current <= t1_lvbh {
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "block height {current} never passed {t1_lvbh} within 120s"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        current = block_height()?;
    }
    println!("    block height {current} now exceeds T1's window {t1_lvbh}");

    // 7. Confirm T1 with owner approval ALREADY active, so the only possible
    //    reason to refuse is the expired blockhash. It must fail closed.
    step(
        "7",
        "confirm expired T1 must fail closed (no sign, no broadcast)",
    );
    broker.approval_active.store(true, Ordering::SeqCst);
    let confirm_t1 = VfsPath::parse(&format!(
        "/wallets/alice/chains/solana-local/outbox/pending/{t1_id}/confirm"
    ))
    .unwrap();
    let refusal = daemon.vfs.write(&confirm_t1, b"y\n").await;
    let refusal_msg = match &refusal {
        Err(e) => e.to_string(),
        Ok(()) => {
            return Err(anyhow!(
                "SECURITY: confirm of an expired blockhash succeeded"
            ));
        }
    };
    println!("    confirm correctly refused: {refusal_msg}");
    assert!(
        refusal_msg.contains("expired") || refusal_msg.contains("restage"),
        "the refusal must be about blockhash expiry, got: {refusal_msg}"
    );
    // The signer was never asked to sign the expired message.
    assert!(
        broker.sign_calls.lock().is_empty(),
        "fail-closed means the Broker was never asked to sign"
    );
    // Nothing moved to `sent`, and the destination is untouched.
    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert!(
        !sent.iter().any(|e| e.name == t1_id),
        "an expired T1 must never appear in sent/"
    );
    let dest_mid = rpc("getBalance", serde_json::json!([destination]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        dest_mid, 0,
        "no broadcast means the destination stays empty"
    );
    println!("    no signing call, T1 not in sent/, destination still 0");

    // 8. Restage T1 → a fresh replacement, T1 marked failed/Expired.
    step("8", "restage T1 into a fresh replacement T2");
    let restage_t1 = VfsPath::parse(&format!(
        "/wallets/alice/chains/solana-local/outbox/pending/{t1_id}/restage"
    ))
    .unwrap();
    daemon
        .vfs
        .write(&restage_t1, b"y\n")
        .await
        .map_err(|e| anyhow!("restage write: {e}"))?;
    let advice = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/failed/{t1_id}/restage_advice.json"),
    )
    .await?;
    println!(
        "    restage_advice.json = {}",
        serde_json::to_string(&advice)?
    );
    assert_eq!(
        advice["schema"].as_str(),
        Some("bloom.solana-restage-advice/1")
    );
    assert_eq!(advice["reason"].as_str(), Some("blockhash_expired"));
    let t2_id = advice["replacement_id"]
        .as_str()
        .ok_or_else(|| anyhow!("restage advice missing replacement_id"))?
        .to_string();
    assert_ne!(t2_id, t1_id, "the replacement must be a new entry");
    println!("    replacement id = {t2_id}");

    // T1 is now terminal: failed/, status Expired, and gone from pending/.
    let t1_failed = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/failed/{t1_id}/intent.json"),
    )
    .await?;
    assert_eq!(
        t1_failed["status"].as_str(),
        Some("expired"),
        "the old entry's status must be Expired"
    );
    let pending_after = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    assert!(
        !pending_after.iter().any(|e| e.name == t1_id),
        "the expired entry must no longer be pending"
    );
    assert!(
        pending_after.iter().any(|e| e.name == t2_id),
        "the replacement must be pending"
    );

    // 9. The replacement carries the same economic intent with a fresh hash.
    step(
        "9",
        "the replacement T2 has a fresh blockhash and same intent",
    );
    let t2 = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/pending/{t2_id}/intent.json"),
    )
    .await?;
    let t2_blockhash = t2["blockhash"].as_str().unwrap().to_string();
    let t2_fee = t2["fee_lamports"]
        .as_u64()
        .ok_or_else(|| anyhow!("T2 intent missing fee_lamports"))?;
    assert_ne!(
        t2_blockhash, t1_blockhash,
        "the replacement must not reuse the expired blockhash"
    );
    assert_eq!(t2["lamports"].as_u64(), Some(LAMPORTS), "same amount");
    assert_eq!(
        t2["destination"].as_str(),
        Some(destination.as_str()),
        "same destination"
    );
    assert_eq!(
        t2["fee_payer"].as_str(),
        Some(address.as_str()),
        "same payer"
    );
    println!("    T2 blockhash={t2_blockhash} fee={t2_fee} (T1 blockhash was {t1_blockhash})");

    // 10. Confirm T2. Approval is already active, so the first confirm still
    //     prepares the sealed approval (no approval_id sidecar yet) and refuses;
    //     the retry reuses the recorded approval and signs + broadcasts.
    step("10", "confirm T2: approve, sign, broadcast");
    let confirm_t2 = VfsPath::parse(&format!(
        "/wallets/alice/chains/solana-local/outbox/pending/{t2_id}/confirm"
    ))
    .unwrap();
    let first = daemon.vfs.write(&confirm_t2, b"y\n").await;
    assert!(
        first.is_err(),
        "the first confirm must prepare the approval and refuse"
    );
    println!(
        "    first confirm prepared the approval: {}",
        first.unwrap_err()
    );
    daemon
        .vfs
        .write(&confirm_t2, b"y\n")
        .await
        .map_err(|e| anyhow!("second confirm of T2: {e}"))?;
    println!("    second confirm accepted");

    // Exactly one signing call happened across the whole test — for T2 only.
    let calls = broker.sign_calls.lock().len();
    assert_eq!(
        calls, 1,
        "exactly one signing call (T2); expired T1 must never have signed"
    );
    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert!(
        sent.iter().any(|e| e.name == t2_id),
        "T2 must be in sent/ after broadcast"
    );
    assert!(
        !sent.iter().any(|e| e.name == t1_id),
        "T1 must never reach sent/"
    );

    // 11. Reconcile T2 to a durable finalized receipt.
    step("11", "reconcile T2 to a finalized receipt");
    let mut receipt = None;
    for _ in 0..60 {
        if let Ok(value) = read_json(
            &daemon,
            &format!("/wallets/alice/chains/solana-local/outbox/sent/{t2_id}/receipt.json"),
        )
        .await
            && value["confirmation_status"].as_str() == Some("finalized")
        {
            receipt = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = receipt.ok_or_else(|| anyhow!("T2 did not reach a finalized receipt"))?;
    println!("    receipt.json = {}", serde_json::to_string(&receipt)?);
    assert_eq!(receipt["outcome"].as_str(), Some("success"));
    assert_eq!(receipt["confirmation_status"].as_str(), Some("finalized"));

    // 12. Exactly one on-chain transfer landed: destination credited once,
    //     fee payer debited once (amount + T2 fee).
    step("12", "verify exactly one on-chain transfer");
    let dest_after = rpc("getBalance", serde_json::json!([destination]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        dest_after, LAMPORTS,
        "the destination must receive exactly the transfer amount, once"
    );
    let payer_after = rpc("getBalance", serde_json::json!([address]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    let debit = payer_before - payer_after;
    println!(
        "    destination {dest_after} lamports; fee payer debited {debit} (= {LAMPORTS} + fee {t2_fee})"
    );
    assert_eq!(
        debit,
        LAMPORTS + t2_fee,
        "the payer must be debited exactly once: amount + the single T2 fee"
    );

    println!("\n=== RESTAGE RECOVERY COMPLETE ===");
    Ok(())
}
