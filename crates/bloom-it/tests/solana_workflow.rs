//! The missing full-workflow E2E: the Solana analogue of `bloom-it`'s
//! `anvil_full_stage_confirm_flow`.
//!
//! Drives a REAL `bloom_daemon::Daemon` (real VFS, real wallets handler, real
//! Solana engine wiring, real reconciler) against a REAL local Agave
//! validator, using a fee payer that is genuinely derived from a BIP-39
//! mnemonic through `bloom-signer-derive`.
//!
//! Boundary: the Broker is an in-process fixture, exactly as the EVM
//! `anvil_e2e` test does. This does not exercise the real bloom-broker /
//! bloom-signer processes or a kernel mount.

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

// ------------------------------------------------------------------ main ---

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn solana_full_stage_confirm_flow() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_daemon=debug")),
        )
        .try_init();

    // 1. Derive the Solana child from the mnemonic, through the production
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
    println!("    public key  {}", hex::encode(pubkey));
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

    // `allow_broadcast` requires a pinned genesis hash — the config-level
    // half of the mainnet guard. Discover the local cluster's identity.
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
    // Mirror the shipped installer catalog
    // (packaging/triad/macos/config/provenance-catalog.unsigned.json).
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
            record("transaction.replace", "transaction.replace", "ethereum"),
            record("transaction.cancel", "transaction.cancel", "ethereum"),
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

    // 3. The chain must be enumerable through the VFS.
    step(
        "3",
        "the Solana chain appears in the wallet's chain listing",
    );
    let chains = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains").unwrap())
        .await
        .map_err(|e| anyhow!("list chains: {e}"))?;
    let names: Vec<&str> = chains.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"solana-local"),
        "solana-local missing from {names:?}"
    );
    println!("    chains listing includes solana-local");

    // 4. Fund the derived child on the validator.
    step("4", "airdrop to the mnemonic-derived address");
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

    // 5. The write surface must be reachable the way a filesystem client
    //    reaches it: lookup first, then write.
    step(
        "5",
        "lookup the outbox write sinks (the mount-reachability path)",
    );
    let new_tx = VfsPath::parse("/wallets/alice/chains/solana-local/outbox/new.tx").unwrap();
    match daemon.vfs.lookup(&new_tx).await {
        Ok(entry) => {
            println!("    lookup new.tx -> mode {:o}", entry.mode);
            assert!(entry.mode & 0o200 != 0, "new.tx lookup must be writable");
        }
        Err(e) => return Err(anyhow!("lookup new.tx failed: {e}")),
    }
    let outbox_listing = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox").unwrap())
        .await
        .map_err(|e| anyhow!("list outbox: {e}"))?;
    println!(
        "    outbox listing: {:?}",
        outbox_listing
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>()
    );

    // 6. Stage.
    step("6", "stage a transfer by writing outbox/new.tx");
    let destination = bs58::encode([0xbbu8; 32]).into_string();
    let intent = serde_json::json!({"destination": destination, "lamports": 250_000_000u64});
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
    let id = pending
        .first()
        .ok_or_else(|| anyhow!("no pending entry staged"))?
        .name
        .clone();
    println!("    staged pending id = {id}");
    let intent_json = daemon
        .vfs
        .read(
            &VfsPath::parse(&format!(
                "/wallets/alice/chains/solana-local/outbox/pending/{id}/intent.json"
            ))
            .unwrap(),
        )
        .await
        .map_err(|e| anyhow!("read intent: {e}"))?;
    let staged: serde_json::Value = serde_json::from_slice(&intent_json)?;
    println!(
        "    fee_payer={} lamports={} fee={} blockhash={}",
        staged["fee_payer"], staged["lamports"], staged["fee_lamports"], staged["blockhash"]
    );
    assert_eq!(staged["fee_payer"].as_str().unwrap(), address);

    // 7. Confirm must fail closed before owner approval.
    step(
        "7",
        "first confirm must fail closed (no Sealed Approval yet)",
    );
    let confirm = VfsPath::parse(&format!(
        "/wallets/alice/chains/solana-local/outbox/pending/{id}/confirm"
    ))
    .unwrap();
    match daemon.vfs.lookup(&confirm).await {
        Ok(e) => println!("    lookup confirm -> mode {:o}", e.mode),
        Err(e) => return Err(anyhow!("lookup confirm failed: {e}")),
    }
    let first = daemon.vfs.write(&confirm, b"y\n").await;
    match &first {
        Err(e) => println!("    first confirm correctly refused: {e}"),
        Ok(()) => {
            return Err(anyhow!(
                "SECURITY: confirm succeeded without owner approval"
            ));
        }
    }

    // 8. Owner completes the ceremony; retry confirms, signs, broadcasts.
    step("8", "owner approves; confirm again -> sign + broadcast");
    broker.approval_active.store(true, Ordering::SeqCst);
    daemon
        .vfs
        .write(&confirm, b"y\n")
        .await
        .map_err(|e| anyhow!("second confirm: {e}"))?;
    println!("    confirm accepted");

    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    println!(
        "    sent entries: {:?}",
        sent.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()
    );

    // 9. What did the Broker actually get asked to sign?
    step("9", "the Broker signed exactly the staged message bytes");
    let calls = broker.sign_calls.lock().clone();
    println!("    SigningSign calls: {}", calls.len());
    let signed_payload = calls.last().ok_or_else(|| anyhow!("no signing call"))?;
    let staged_msg = {
        use std::io::Read as _;
        let _ = &mut std::io::empty().read(&mut []);
        staged["message_b64"].as_str().unwrap().to_string()
    };
    let expected = {
        // decode the staged base64 message without pulling a base64 dep
        fn b64(s: &str) -> Vec<u8> {
            let t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut acc = 0u32;
            let mut bits = 0;
            let mut out = Vec::new();
            for c in s.chars().filter(|c| *c != '=') {
                let v = t.find(c).unwrap() as u32;
                acc = (acc << 6) | v;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
            out
        }
        b64(&staged_msg)
    };
    println!("    staged message  {} bytes", expected.len());
    println!("    signed payload  {} bytes", signed_payload.len());
    assert_eq!(
        signed_payload, &expected,
        "Broker was asked to sign bytes other than the staged message"
    );
    println!("    signed payload == staged message bytes");

    // 10. On-chain verification.
    step("10", "verify the transfer on the validator");
    let receipt_path =
        format!("/wallets/alice/chains/solana-local/outbox/sent/{id}/broadcast_attempted.json");
    if let Ok(b) = daemon
        .vfs
        .read(&VfsPath::parse(&receipt_path).unwrap())
        .await
    {
        println!(
            "    broadcast_attempted.json = {}",
            String::from_utf8_lossy(&b)
        );
    }
    for _ in 0..45 {
        let bal = rpc("getBalance", serde_json::json!([destination]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
        if bal > 0 {
            println!("    destination {destination} balance = {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let payer_bal = rpc("getBalance", serde_json::json!([address]))?["result"]["value"]
        .as_u64()
        .unwrap_or(0);
    println!("    fee payer balance = {payer_bal} lamports");

    // 11. Reconciliation writes the receipt.
    step("11", "reconcile to a durable receipt");
    for _ in 0..45 {
        let r = daemon
            .vfs
            .read(
                &VfsPath::parse(&format!(
                    "/wallets/alice/chains/solana-local/outbox/sent/{id}/receipt.json"
                ))
                .unwrap(),
            )
            .await;
        if let Ok(b) = r {
            println!("    receipt.json = {}", String::from_utf8_lossy(&b));
            let receipt: serde_json::Value = serde_json::from_slice(&b)?;
            assert_eq!(receipt["outcome"], "success");
            assert_eq!(receipt["confirmation_status"], "finalized");
            println!("\n=== WORKFLOW COMPLETE ===");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    println!("    NO RECEIPT after 45s — reconciler did not finalize");
    Err(anyhow!("reconciliation did not produce a receipt"))
}
