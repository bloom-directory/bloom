//! Multi-account Solana selection against a real local Agave validator.
//!
//! The companion to `solana_workflow`, for the case that one could not cover:
//! a BIP-39 wallet with **two simultaneously active** Solana children. That is
//! the state Finding R1 is about — with one child every path is unambiguous,
//! and retiring a child to reach the second proves the account lifecycle
//! rather than multi-account usability.
//!
//! Both children are derived from the mnemonic through the production
//! derivation crate, and the Broker fixture signs with whichever key the
//! request's `key_ref` names. A selection bug therefore cannot pass this test
//! by accident: choosing the wrong child produces a signature that fails to
//! verify against the staged fee payer, and the validator rejects it.
//!
//! Boundary, stated plainly: the Broker here is an in-process fixture, exactly
//! as in `solana_workflow` and the EVM `anvil_e2e`. The Daemon, VFS, wallet
//! handler, Solana engine, reconciler, and validator are real. This is not the
//! separate-process bloom-broker/bloom-signer triad.

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
/// followed by the raw 32-byte key, as the real Signer publishes it.
fn spki(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    out.extend_from_slice(pubkey);
    out
}

fn fingerprint_of(pubkey: &[u8; 32]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(spki(pubkey)).into())
}

/// One derived Solana child, with the private key the fixture signs with.
struct Child {
    account: u32,
    path: String,
    pubkey: [u8; 32],
    address: String,
    signing_key: ed25519_dalek::SigningKey,
    key_ref: KeyRef,
}

impl Child {
    fn derive(seed: &[u8; 64], account: u32) -> Result<Self> {
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

    fn fingerprint_hex(&self) -> &str {
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
            chain_projections: vec![],
            // Both children stay active for the whole test. That is the point.
            lifecycle: AccountLifecycleState::Active,
        }
    }
}

// ---------------------------------------------------------------- broker ---

struct MultiAccountBroker {
    children: Vec<Child>,
    approval_active: AtomicBool,
    /// Every signing call, as (key_ref locator, signed bytes).
    sign_calls: parking_lot::Mutex<Vec<(String, Vec<u8>)>>,
}

impl MultiAccountBroker {
    fn child_for(&self, key_ref: &KeyRef) -> Option<&Child> {
        self.children.iter().find(|child| &child.key_ref == key_ref)
    }

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
            // A BIP-39 seed root is not signable; the children are the keys.
            root_key_ref: None,
            key_refs: self.children.iter().map(|c| c.key_ref.clone()).collect(),
            policy_version: DecimalU64::new(1),
            policy_digest: p.policy_digest,
            wallet_revocation_epoch: DecimalU64::new(0),
        }
    }

    fn key_public(&self, child: &Child) -> KeyPublic {
        KeyPublic {
            key_ref: child.key_ref.clone(),
            role: KeyRole::Derived,
            canonical_public_key: Base64UrlBytes::from_bytes(&spki(&child.pubkey)),
            addresses: vec![child.address.clone()],
            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
        }
    }

    fn accounts(&self, wallet_id: Token) -> WalletAccountsPublic {
        WalletAccountsPublic {
            wallet_id,
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            accounts: self.children.iter().map(|c| c.account_public()).collect(),
        }
    }
}

impl MachineBrokerService for MultiAccountBroker {
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
                MachineBrokerRequest::KeyListPublic(_) => Ok(MachineBrokerResponse::KeyListPublic(
                    self.children.iter().map(|c| self.key_public(c)).collect(),
                )),
                // Answer for the exact key asked about. Returning a fixed key
                // here would mask a selection bug entirely.
                MachineBrokerRequest::KeyGetPublic(r) => {
                    let child = self.child_for(&r.key_ref).ok_or_else(|| {
                        ProtocolError::new(
                            ProtocolErrorCode::KeyrefMismatch,
                            "key is not a child of this wallet",
                        )
                    })?;
                    Ok(MachineBrokerResponse::KeyGetPublic(self.key_public(child)))
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
                        ceremony_url: "http://localhost:18734/ceremony/multi".into(),
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
                                .then(|| "http://localhost:18734/ceremony/multi".into()),
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
                    // Sign with the key the request names, never a default.
                    // This is what makes a wrong selection observable.
                    let child = self.child_for(&r.key_ref).ok_or_else(|| {
                        ProtocolError::new(
                            ProtocolErrorCode::KeyrefMismatch,
                            "signing key is not a child of this wallet",
                        )
                    })?;
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

// ------------------------------------------------------------------- rpc ---

/// `reqwest::blocking` builds and drops its own runtime, which panics inside
/// an async context, so it runs on a tokio-naive OS thread.
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

fn b64_decode(s: &str) -> Vec<u8> {
    let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| *c != '=') {
        let v = table.find(c).expect("base64 alphabet") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

async fn read_json(daemon: &Daemon, path: &str) -> Result<serde_json::Value> {
    let bytes = daemon
        .vfs
        .read(&VfsPath::parse(path).unwrap())
        .await
        .map_err(|e| anyhow!("read {path}: {e}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ------------------------------------------------------------------ main ---

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn two_active_solana_children_select_sign_and_reconcile_independently() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_daemon=debug")),
        )
        .try_init();

    // 1. Two children from one mnemonic, through the production derivation
    //    crate rather than fixture constants.
    step(
        "1",
        "derive Solana accounts 0 and 1 from the BIP-39 mnemonic",
    );
    let seed =
        bloom_signer_derive::seed_from_mnemonic(MNEMONIC, "").map_err(|e| anyhow!("seed: {e}"))?;
    let seed64: [u8; 64] = (*seed).as_slice().try_into().unwrap();
    let account0 = Child::derive(&seed64, 0)?;
    let account1 = Child::derive(&seed64, 1)?;
    for child in [&account0, &account1] {
        println!(
            "    account {} path {} address {} fingerprint {}",
            child.account,
            child.path,
            child.address,
            child.fingerprint_hex()
        );
    }

    // 2. Independent checks on the two identities, so a later assertion about
    //    "account 1" cannot be satisfied by account 0 under another name.
    step("2", "verify the two accounts are distinct and canonical");
    assert_eq!(account0.path, "m/44'/501'/0'/0'");
    assert_eq!(account1.path, "m/44'/501'/1'/0'");
    assert_ne!(account0.pubkey, account1.pubkey, "children must differ");
    assert_ne!(account0.address, account1.address);
    assert_ne!(account0.fingerprint_hex(), account1.fingerprint_hex());
    // A Solana address is the base58 of the raw 32-byte key, and the
    // fingerprint commits to the canonical SPKI encoding of that same key.
    for child in [&account0, &account1] {
        let decoded = bs58::decode(&child.address)
            .into_vec()
            .map_err(|e| anyhow!("address base58: {e}"))?;
        assert_eq!(
            decoded,
            child.pubkey.to_vec(),
            "address must be the raw key"
        );
        let spki_bytes = spki(&child.pubkey);
        assert_eq!(spki_bytes.len(), 44);
        assert_eq!(&spki_bytes[12..], &child.pubkey[..]);
        assert_eq!(
            child.fingerprint_hex(),
            Digest32::from_bytes(Sha256::digest(&spki_bytes).into()).as_str()
        );
    }
    println!("    both accounts verified independently of the projection");

    // 3. Real daemon, both children active at once.
    step("3", "build a real Daemon with BOTH children active");
    let broker = Arc::new(MultiAccountBroker {
        children: vec![account0, account1],
        approval_active: AtomicBool::new(false),
        sign_calls: parking_lot::Mutex::new(Vec::new()),
    });
    let account0 = &broker.children[0];
    let account1 = &broker.children[1];

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
            expected_genesis_hex: Some(genesis.clone()),
            allow_broadcast: true,
        },
    );
    let config_path = tmp.path().join("config.toml");
    cfg.save(&config_path).map_err(|e| anyhow!("save: {e}"))?;

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

    let build_daemon = || -> Result<Daemon> {
        let home = HomeDir::at(tmp.path());
        let permit = Arc::new(HomeWritePermit::acquire(&home)?);
        let service: Arc<dyn MachineBrokerService> = broker.clone();
        Daemon::from_home_with_permit_and_broker(
            home,
            permit,
            MachineBrokerClient::new(service),
            catalog.clone(),
        )
        .map_err(|e| anyhow!("daemon: {e}"))
    };
    let daemon = build_daemon()?;
    println!("    daemon constructed with 2 active Solana children");

    // 4. Fund ONLY account 1, so a transfer signed by account 0 could not
    //    succeed on-chain even if selection silently fell back to it.
    step("4", "airdrop to account 1 only");
    rpc(
        "requestAirdrop",
        serde_json::json!([account1.address, 2_000_000_000u64]),
    )?;
    for _ in 0..40 {
        let bal = rpc("getBalance", serde_json::json!([account1.address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
        if bal >= 2_000_000_000 {
            println!("    account 1 funded: {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    // Account 0's balance is recorded, not assumed to be zero: the same
    // mnemonic's account 0 may already hold funds from another suite on this
    // validator. What matters is that this transfer leaves it untouched.
    let account0_balance =
        rpc("getBalance", serde_json::json!([account0.address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
    println!("    account 0 balance before: {account0_balance} lamports");

    let new_tx = VfsPath::parse("/wallets/alice/chains/solana-local/outbox/new.tx").unwrap();
    let destination = bs58::encode([0xccu8; 32]).into_string();

    // 5. With two active children, staging without a selector must fail and
    //    name both, rather than quietly picking whichever is listed first.
    step(
        "5",
        "staging without a selector fails closed and names both",
    );
    let ambiguous = serde_json::json!({
        "destination": destination,
        "lamports": 250_000_000u64,
    });
    let err = daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&ambiguous)?.as_slice())
        .await
        .expect_err("two active children must not resolve implicitly");
    let message = err.to_string();
    println!("    refused: {message}");
    assert!(
        message.contains(account0.fingerprint_hex())
            && message.contains(account1.fingerprint_hex()),
        "the error must name both candidates: {message}"
    );
    assert!(
        message.contains(&account0.path) && message.contains(&account1.path),
        "the error must name both derivation paths: {message}"
    );

    // 6. A fingerprint that belongs to no active child is refused too.
    step("6", "a foreign fingerprint is refused");
    let foreign = "f".repeat(64);
    let err = daemon
        .vfs
        .write(
            &new_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": destination,
                "lamports": 250_000_000u64,
                "account_fingerprint": foreign,
            }))?
            .as_slice(),
        )
        .await
        .expect_err("a fingerprint outside the wallet must never select");
    println!("    refused: {err}");

    // 7. Select account 1 explicitly, with account 0 still active.
    step(
        "7",
        "stage from account 1 by fingerprint, account 0 still active",
    );
    let intent = serde_json::json!({
        "destination": destination,
        "lamports": 250_000_000u64,
        "account_fingerprint": account1.fingerprint_hex(),
    });
    daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&intent)?.as_slice())
        .await
        .map_err(|e| anyhow!("stage: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let id = pending
        .first()
        .ok_or_else(|| anyhow!("nothing staged"))?
        .name
        .clone();
    let staged = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/pending/{id}/intent.json"),
    )
    .await?;
    println!("    staged id {id} fee_payer {}", staged["fee_payer"]);
    assert_eq!(
        staged["fee_payer"].as_str().unwrap(),
        account1.address,
        "the staged fee payer must be the selected account, not the first listed"
    );
    assert_eq!(
        staged["account_fingerprint"].as_str().unwrap(),
        account1.fingerprint_hex(),
        "the selected account must be pinned into the staged record"
    );

    // 8. Approve, confirm, broadcast.
    step("8", "owner approves; confirm signs and broadcasts");
    let confirm = VfsPath::parse(&format!(
        "/wallets/alice/chains/solana-local/outbox/pending/{id}/confirm"
    ))
    .unwrap();
    let refused = daemon.vfs.write(&confirm, b"y\n").await;
    assert!(
        refused.is_err(),
        "confirm must fail closed before owner approval"
    );
    println!("    pre-approval confirm correctly refused");

    broker.approval_active.store(true, Ordering::SeqCst);
    daemon
        .vfs
        .write(&confirm, b"y\n")
        .await
        .map_err(|e| anyhow!("confirm: {e}"))?;
    println!("    confirm accepted");

    // 9. The Broker was asked to sign with account 1's key, and with exactly
    //    the staged bytes.
    step("9", "the signing call named account 1 and the staged bytes");
    let calls = broker.sign_calls.lock().clone();
    assert_eq!(calls.len(), 1, "exactly one signing call: {calls:?}");
    let (locator, signed_bytes) = &calls[0];
    println!("    signed with key locator {locator}");
    assert_eq!(
        locator, &account1.key_ref.locator,
        "the wrong child was asked to sign"
    );
    let staged_message = b64_decode(staged["message_b64"].as_str().unwrap());
    assert_eq!(
        signed_bytes, &staged_message,
        "the Broker must sign the staged message bytes verbatim"
    );

    // 10. Independent signature verification over the RAW message, and the
    //     negative that Solana does not sign SHA-256(message).
    step(
        "10",
        "verify the signature independently over the raw message",
    );
    let broadcast = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/sent/{id}/broadcast_attempted.json"),
    )
    .await?;
    let signature_b58 = broadcast["signature"]
        .as_str()
        .ok_or_else(|| anyhow!("no broadcast signature"))?
        .to_string();
    let signature_bytes: [u8; 64] = bs58::decode(&signature_b58)
        .into_vec()
        .map_err(|e| anyhow!("signature base58: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    use ed25519_dalek::Verifier as _;
    let account1_key = ed25519_dalek::VerifyingKey::from_bytes(&account1.pubkey)?;
    account1_key
        .verify(&staged_message, &signature)
        .map_err(|e| anyhow!("signature must verify over the raw message: {e}"))?;
    println!("    verifies against account 1 over the raw message");

    // The other active child must NOT verify it. This is the assertion a
    // selection bug fails.
    let account0_key = ed25519_dalek::VerifyingKey::from_bytes(&account0.pubkey)?;
    assert!(
        account0_key.verify(&staged_message, &signature).is_err(),
        "SECURITY: the signature verifies against the account that was not selected"
    );
    println!("    does not verify against account 0");

    // Solana signs the serialized message with Ed25519, not SHA-256 of it.
    let hashed = Sha256::digest(&staged_message);
    assert!(
        account1_key.verify(&hashed, &signature).is_err(),
        "signature must not verify over SHA-256(message)"
    );
    println!("    does not verify over SHA-256(message)");

    // 11. Reconcile to a durable finalized receipt, and check the money moved
    //     from the selected account.
    step("11", "reconcile to a finalized receipt and verify balances");
    let mut receipt = None;
    for _ in 0..60 {
        if let Ok(value) = read_json(
            &daemon,
            &format!("/wallets/alice/chains/solana-local/outbox/sent/{id}/receipt.json"),
        )
        .await
            && value["confirmation_status"].as_str() == Some("finalized")
        {
            receipt = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = receipt.ok_or_else(|| anyhow!("transfer did not reach a finalized receipt"))?;
    println!("    receipt = {}", serde_json::to_string_pretty(&receipt)?);
    assert_eq!(receipt["outcome"].as_str(), Some("success"));
    assert_eq!(receipt["signature"].as_str(), Some(signature_b58.as_str()));

    let destination_balance =
        rpc("getBalance", serde_json::json!([destination]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
    assert_eq!(destination_balance, 250_000_000, "destination debit");
    let account0_after =
        rpc("getBalance", serde_json::json!([account0.address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
    assert_eq!(
        account0_after, account0_balance,
        "the unselected account's balance must be untouched"
    );
    println!("    destination credited; account 0 untouched at {account0_after} lamports");

    // 12. Replay: confirming the same entry again must not produce a second
    //     transaction.
    step("12", "replaying confirm does not double-send");
    let replay = daemon.vfs.write(&confirm, b"y\n").await;
    println!("    replay result: {replay:?}");
    let calls_after = broker.sign_calls.lock().len();
    assert_eq!(
        calls_after, 1,
        "a replayed confirm must not sign again (calls={calls_after})"
    );
    let sent_after = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert_eq!(sent_after.len(), 1, "exactly one sent entry must exist");

    // 13. Restart: the durable receipt and the pinned account survive, and a
    //     post-restart confirm still does not resend.
    step(
        "13",
        "re-read the durable state the way a restarted process would",
    );
    // A Daemon holds the home write permit for the life of the process, by
    // design — one daemon per home. So an in-process "restart" cannot mean a
    // second Daemon over the same home; it means reading the state a fresh
    // process would read on start. That is what a restart actually recovers
    // from, so it is read straight off disk through a fresh outbox rather
    // than through the still-running daemon's caches.
    let reopened =
        bloom_solana_tx::outbox::SolanaOutbox::new(HomeDir::at(tmp.path()).solana_outbox_dir())
            .map_err(|e| anyhow!("reopen outbox: {e}"))?;

    // Still terminal, and still in `sent` — a restarted process therefore has
    // nothing pending to confirm, so it cannot resend.
    let reopened_entry = reopened
        .read_in_state(
            "alice",
            "solana-local",
            &id,
            bloom_solana_tx::outbox::SolanaOutboxState::Sent,
        )
        .map_err(|e| anyhow!("reopened entry must still be sent: {e}"))?;
    assert_eq!(
        reopened_entry.staged.account_fingerprint.as_deref(),
        Some(account1.fingerprint_hex()),
        "the pinned account must survive a restart"
    );
    assert_eq!(
        reopened_entry.staged.fee_payer, account1.address,
        "the staged fee payer must survive a restart"
    );
    assert!(
        reopened
            .read_in_state(
                "alice",
                "solana-local",
                &id,
                bloom_solana_tx::outbox::SolanaOutboxState::Pending,
            )
            .is_err(),
        "a completed transfer must not reappear as pending after a restart"
    );
    let receipt_after = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/sent/{id}/receipt.json"),
    )
    .await?;
    assert_eq!(
        receipt_after["signature"].as_str(),
        Some(signature_b58.as_str()),
        "the receipt must be durable"
    );
    assert_eq!(
        receipt_after["confirmation_status"].as_str(),
        Some("finalized")
    );
    println!("    durable receipt and pinned account survive a fresh read");

    // Confirming again must still refuse, and must not sign again.
    let replay_again = daemon.vfs.write(&confirm, b"y\n").await;
    println!("    second replay result: {replay_again:?}");
    assert_eq!(
        broker.sign_calls.lock().len(),
        1,
        "no replay may produce a second signing call"
    );

    // 14. The other child stays independently selectable while account 1
    //     is also active.
    step("14", "account 0 is still selectable in its own right");
    rpc(
        "requestAirdrop",
        serde_json::json!([account0.address, 1_000_000_000u64]),
    )?;
    for _ in 0..40 {
        let bal = rpc("getBalance", serde_json::json!([account0.address]))?["result"]["value"]
            .as_u64()
            .unwrap_or(0);
        if bal >= 1_000_000_000 {
            println!("    account 0 funded: {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    daemon
        .vfs
        .write(
            &new_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": destination,
                "lamports": 100_000_000u64,
                "account_fingerprint": account0.fingerprint_hex(),
            }))?
            .as_slice(),
        )
        .await
        .map_err(|e| anyhow!("stage from account 0: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let second_id = pending
        .first()
        .ok_or_else(|| anyhow!("nothing staged from account 0"))?
        .name
        .clone();
    let staged0 = read_json(
        &daemon,
        &format!("/wallets/alice/chains/solana-local/outbox/pending/{second_id}/intent.json"),
    )
    .await?;
    assert_eq!(
        staged0["fee_payer"].as_str(),
        Some(account0.address.as_str()),
        "account 0 must be selectable while account 1 is also active"
    );
    assert_eq!(
        staged0["account_fingerprint"].as_str(),
        Some(account0.fingerprint_hex())
    );
    println!("    account 0 staged independently: {second_id}");

    println!("\n=== MULTI-ACCOUNT SELECTION COMPLETE ===");
    Ok(())
}
