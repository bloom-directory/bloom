use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use bloom_broker_api::{
    Base64UrlBytes, CanonicalWalletPolicy, CeremonyKind, CeremonyPublicStatus, CeremonyState,
    CredentialPublic, CryptoSuite, CustodyResult, DecimalU64, Digest32, KeyPublic, KeyRef, KeySpec,
    MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, OperationId,
    PolicyCommitReceipt, PolicyUpdatePrepareResponse, ProtocolError, ProtocolErrorCode,
    ServiceFuture, SignedPolicySnapshot, Token, WalletAccountsPublic, WalletPublic, WalletRequest,
    WalletSeedProfile,
};
use bloom_machine_client::{
    CachedWalletProjectionReader, FileProjectionStore, MachineBrokerClient, PetalEligibility,
    WalletProjectionReader, policy_with_package,
};
use bloom_proto::{AddressBook, HomeDir, HomeWritePermit};
use bloom_tx::{outbox::Outbox, tx_engine::TxEngine};
use bloom_vfs::{Handler, HandlerError, VfsPath, handlers::wallets::WalletsHandler};
use sha2::{Digest as _, Sha256};

#[path = "support/m2_exact_production_routes.rs"]
mod m2_exact_production_routes;

fn projection_reader(
    path: impl Into<std::path::PathBuf>,
    broker: Option<MachineBrokerClient>,
) -> Arc<dyn WalletProjectionReader> {
    Arc::new(CachedWalletProjectionReader::new(broker, FileProjectionStore::new(path)).unwrap())
}

struct FixtureState {
    operation_id: Option<OperationId>,
    proposed_policy: Option<Vec<u8>>,
    proposed_digest: Option<Digest32>,
    authority_diff_digest: Option<Digest32>,
}

struct BrokerFixture {
    available: AtomicBool,
    complete: AtomicBool,
    lose_prepare_response_once: AtomicBool,
    ceremony_state_override: parking_lot::Mutex<Option<CeremonyState>>,
    ceremony_expires_at_ms: AtomicU64,
    requests: parking_lot::Mutex<Vec<MachineBrokerRequest>>,
    state: parking_lot::Mutex<FixtureState>,
    baseline: SignedPolicySnapshot,
}

impl BrokerFixture {
    fn committed_snapshot(&self) -> SignedPolicySnapshot {
        let state = self.state.lock();
        SignedPolicySnapshot {
            wallet_id: Token::new("alice").unwrap(),
            version: DecimalU64::new(2),
            canonical_policy: Base64UrlBytes::from_bytes(state.proposed_policy.as_ref().unwrap()),
            policy_digest: state.proposed_digest.clone().unwrap(),
            policy_signing_key_id: Token::new("policy-key").unwrap(),
            policy_verifying_key: Base64UrlBytes::from_bytes(&[4; 32]),
            signer_signature: Base64UrlBytes::from_bytes(&[5; 64]),
        }
    }

    fn key_ref(&self) -> KeyRef {
        KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("primary").unwrap(),
            locator: "alice/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::from_bytes([12; 32]),
            derivation: None,
        }
    }

    fn wallet_public(&self) -> WalletPublic {
        let policy = if self.complete.load(Ordering::SeqCst)
            && self.state.lock().proposed_policy.is_some()
        {
            self.committed_snapshot()
        } else {
            self.baseline.clone()
        };
        WalletPublic {
            wallet_id: Token::new("alice").unwrap(),
            wallet_kind: Token::new("passkey").unwrap(),
            root_key_ref: Some(self.key_ref()),
            key_refs: vec![self.key_ref()],
            policy_version: policy.version,
            policy_digest: policy.policy_digest,
            wallet_revocation_epoch: DecimalU64::new(0),
        }
    }

    fn key_public(&self) -> KeyPublic {
        KeyPublic {
            key_ref: self.key_ref(),
            role: bloom_broker_api::KeyRole::WalletRoot,
            canonical_public_key: Base64UrlBytes::from_bytes(&[13; 33]),
            addresses: vec!["0x0000000000000000000000000000000000000001".into()],
            supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        }
    }
}

impl MachineBrokerService for BrokerFixture {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            if !self.available.load(Ordering::SeqCst) {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    "projection test Broker unavailable",
                ));
            }
            self.requests.lock().push(request.clone());
            match request {
                MachineBrokerRequest::WalletListPublic(_) => {
                    Ok(MachineBrokerResponse::WalletListPublic(vec![
                        self.wallet_public(),
                    ]))
                }
                MachineBrokerRequest::KeyListPublic(WalletRequest { wallet_id })
                    if wallet_id.as_str() == "alice" =>
                {
                    Ok(MachineBrokerResponse::KeyListPublic(vec![
                        self.key_public(),
                    ]))
                }
                MachineBrokerRequest::CredentialListPublic(WalletRequest { wallet_id })
                    if wallet_id.as_str() == "alice" =>
                {
                    Ok(MachineBrokerResponse::CredentialListPublic(Vec::<
                        CredentialPublic,
                    >::new(
                    )))
                }
                MachineBrokerRequest::WalletAccounts(WalletRequest { wallet_id })
                    if wallet_id.as_str() == "alice" =>
                {
                    Ok(MachineBrokerResponse::WalletAccounts(
                        WalletAccountsPublic {
                            wallet_id,
                            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
                            accounts: Vec::new(),
                        },
                    ))
                }
                MachineBrokerRequest::PolicyRead(_) => {
                    let snapshot = if self.complete.load(Ordering::SeqCst)
                        && self.state.lock().proposed_policy.is_some()
                    {
                        self.committed_snapshot()
                    } else {
                        self.baseline.clone()
                    };
                    Ok(MachineBrokerResponse::PolicyRead(snapshot))
                }
                MachineBrokerRequest::PolicyValidateUpdate(request) => {
                    self.state.lock().operation_id = Some(request.operation_id.clone());
                    self.state.lock().proposed_policy =
                        Some(request.proposed_canonical_policy.decode());
                    self.state.lock().proposed_digest = Some(request.proposed_policy_digest);
                    self.state.lock().authority_diff_digest = Some(request.authority_diff_digest);
                    let prepared = PolicyUpdatePrepareResponse {
                        operation_id: request.operation_id,
                        ceremony_kind: CeremonyKind::PolicyUpdate,
                        ceremony_url: "http://localhost:18734/ceremony/policy-test-secret".into(),
                        ceremony_expires_at_ms: DecimalU64::new(u64::MAX),
                        review_manifest_digest: Digest32::from_bytes([6; 32]),
                    };
                    if self
                        .lose_prepare_response_once
                        .swap(false, Ordering::SeqCst)
                    {
                        return Err(bloom_broker_api::ProtocolError::new(
                            bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
                            "simulated response loss after durable policy prepare",
                        ));
                    }
                    Ok(MachineBrokerResponse::PolicyValidateUpdate(prepared))
                }
                MachineBrokerRequest::CeremonyStatus(request) => {
                    let complete = self.complete.load(Ordering::SeqCst);
                    let state = (*self.ceremony_state_override.lock()).unwrap_or(if complete {
                        CeremonyState::Succeeded
                    } else {
                        CeremonyState::AwaitingUser
                    });
                    Ok(MachineBrokerResponse::CeremonyStatus(
                        CeremonyPublicStatus {
                            ceremony_id: Digest32::from_bytes([7; 32]),
                            ceremony_kind: CeremonyKind::PolicyUpdate,
                            operation_id: OperationId::new(request.id.as_str().to_owned()).unwrap(),
                            state,
                            expires_at_ms: DecimalU64::new(
                                self.ceremony_expires_at_ms.load(Ordering::SeqCst),
                            ),
                            ceremony_url: (state == CeremonyState::AwaitingUser).then(|| {
                                "http://localhost:18734/ceremony/policy-test-secret".into()
                            }),
                            receipt_digest: (state == CeremonyState::Succeeded)
                                .then(|| Digest32::from_bytes([8; 32])),
                        },
                    ))
                }
                MachineBrokerRequest::CeremonyCancel(request) => {
                    *self.ceremony_state_override.lock() = Some(CeremonyState::Cancelled);
                    Ok(MachineBrokerResponse::CeremonyCancel(
                        CeremonyPublicStatus {
                            ceremony_id: Digest32::from_bytes([7; 32]),
                            ceremony_kind: CeremonyKind::PolicyUpdate,
                            operation_id: OperationId::new(request.id.as_str().to_owned()).unwrap(),
                            state: CeremonyState::Cancelled,
                            expires_at_ms: DecimalU64::new(u64::MAX),
                            ceremony_url: None,
                            receipt_digest: None,
                        },
                    ))
                }
                MachineBrokerRequest::CustodyResult(request) => {
                    Ok(MachineBrokerResponse::CustodyResult(CustodyResult {
                        ceremony_kind: CeremonyKind::PolicyUpdate,
                        custody_operation_id: request.operation_id,
                        public_status: CeremonyState::Succeeded,
                        wallet_id: Some(Token::new("alice").unwrap()),
                        public_key_refs: Vec::new(),
                        credential_summaries: Vec::new(),
                        initial_policy: None,
                        receipt_digest: Digest32::from_bytes([8; 32]),
                        encrypted_browser_result: None,
                        signer_key_id: Token::new("signer-key").unwrap(),
                        signer_signature: Base64UrlBytes::from_bytes(&[9; 64]),
                    }))
                }
                MachineBrokerRequest::PolicyCommitUpdate(request) => {
                    let committed = self.committed_snapshot();
                    let authority_diff_digest =
                        self.state.lock().authority_diff_digest.clone().unwrap();
                    Ok(MachineBrokerResponse::PolicyCommitUpdate(
                        PolicyCommitReceipt {
                            operation_id: request.operation_id,
                            wallet_id: Token::new("alice").unwrap(),
                            previous_version: DecimalU64::new(1),
                            committed,
                            authority_diff_digest,
                            signer_key_id: Token::new("signer-key").unwrap(),
                            signer_signature: Base64UrlBytes::from_bytes(&[11; 64]),
                        },
                    ))
                }
                other => panic!("unexpected Broker request: {other:?}"),
            }
        })
    }
}

fn policy(maximum_approval_lifetime_ms: u64) -> CanonicalWalletPolicy {
    CanonicalWalletPolicy {
        wallet_id: Token::new("alice").unwrap(),
        maximum_approval_lifetime_ms,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: vec![bloom_broker_api::PolicyDestination {
            chain: Token::new("ethereum").unwrap(),
            destination: "0x0000000000000000000000000000000000000001".into(),
        }],
        required_verifiers: vec![bloom_broker_api::RequiredVerifier {
            verifier_id: Token::new("human").unwrap(),
            verifier_digest: Digest32::from_bytes([4; 32]),
        }],
    }
}

fn broker_fixture(lose_prepare_response_once: bool) -> Arc<BrokerFixture> {
    broker_fixture_with_policy(lose_prepare_response_once, policy(60_000))
}

fn broker_fixture_with_policy(
    lose_prepare_response_once: bool,
    baseline_policy: CanonicalWalletPolicy,
) -> Arc<BrokerFixture> {
    let baseline_bytes = serde_jcs::to_vec(&baseline_policy).unwrap();
    Arc::new(BrokerFixture {
        available: AtomicBool::new(true),
        complete: AtomicBool::new(false),
        lose_prepare_response_once: AtomicBool::new(lose_prepare_response_once),
        ceremony_state_override: parking_lot::Mutex::new(None),
        ceremony_expires_at_ms: AtomicU64::new(u64::MAX),
        requests: parking_lot::Mutex::new(Vec::new()),
        state: parking_lot::Mutex::new(FixtureState {
            operation_id: None,
            proposed_policy: None,
            proposed_digest: None,
            authority_diff_digest: None,
        }),
        baseline: SignedPolicySnapshot {
            wallet_id: Token::new("alice").unwrap(),
            version: DecimalU64::new(1),
            canonical_policy: Base64UrlBytes::from_bytes(&baseline_bytes),
            policy_digest: Digest32::from_bytes(Sha256::digest(&baseline_bytes).into()),
            policy_signing_key_id: Token::new("policy-key").unwrap(),
            policy_verifying_key: Base64UrlBytes::from_bytes(&[2; 32]),
            signer_signature: Base64UrlBytes::from_bytes(&[3; 64]),
        },
    })
}

#[tokio::test]
async fn signer_wallet_is_visible_in_vfs_without_a_legacy_keystore_record() {
    let temp = tempfile::tempdir().unwrap();
    assert!(!temp.path().join("keystore").exists());
    let fixture = broker_fixture(false);
    let expected_policy = fixture.baseline.canonical_policy.decode();
    let expected_policy_digest = fixture.baseline.policy_digest.clone();
    let cache = temp.path().join("cache/wallets.json");
    let projections = Arc::new(
        CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(fixture.clone())),
            FileProjectionStore::new(&cache),
        )
        .unwrap(),
    );
    let handler = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
        AddressBook::default(),
        projections,
        temp.path().join("machine-policy-projections"),
    );

    let root = handler.list(&VfsPath::parse("/").unwrap()).await.unwrap();
    assert!(root.iter().any(|entry| entry.name == "alice"));
    assert_eq!(
        handler
            .read(&VfsPath::parse("/alice/0/address.evm").unwrap())
            .await
            .unwrap(),
        b"0x0000000000000000000000000000000000000001\n"
    );
    assert_eq!(
        handler
            .read(&VfsPath::parse("/alice/kind").unwrap())
            .await
            .unwrap(),
        b"passkey\n"
    );
    let wallet_entries = handler
        .list(&VfsPath::parse("/alice").unwrap())
        .await
        .unwrap();
    assert!(
        wallet_entries
            .iter()
            .any(|entry| entry.name == "policy.json")
    );
    assert!(
        !wallet_entries
            .iter()
            .any(|entry| entry.name == "policy.toml"),
        "removed compatibility policy surface must not be discoverable"
    );
    assert!(matches!(
        handler
            .lookup(&VfsPath::parse("/alice/policy.toml").unwrap())
            .await,
        Err(HandlerError::NotFound(_))
    ));

    fixture.available.store(false, Ordering::SeqCst);
    let stale_projections = Arc::new(
        CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(fixture)),
            FileProjectionStore::new(cache),
        )
        .unwrap(),
    );
    let stale_handler = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(
            Outbox::new(temp.path().join("stale-outbox")).unwrap(),
            60_000,
        ),
        AddressBook::default(),
        stale_projections,
        temp.path().join("stale-machine-policy-projections"),
    );
    let account: serde_json::Value = serde_json::from_slice(
        &stale_handler
            .read(&VfsPath::parse("/alice/0/account.json").unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(account["number"], 0);
    assert_eq!(account["freshness"], "stale");
    let projection: serde_json::Value = serde_json::from_slice(
        &stale_handler
            .read(&VfsPath::parse("/alice/projection.json").unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(projection["freshness"], "stale");
    assert_eq!(projection["wallet"]["policy_version"], "1");
    assert_eq!(
        projection["wallet"]["policy_digest"],
        expected_policy_digest.as_str()
    );
    assert_eq!(projection["wallet"]["wallet_revocation_epoch"], "0");
    assert_eq!(
        stale_handler
            .read(&VfsPath::parse("/alice/policy.json").unwrap())
            .await
            .unwrap(),
        expected_policy,
        "canonical policy must remain readable from the authenticated stale projection"
    );
}

#[tokio::test]
async fn vfs_policy_prepare_response_loss_reconciles_the_persisted_operation_id() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(true);
    let service: Arc<dyn MachineBrokerService> = fixture.clone();
    let home = HomeDir::at(temp.path().join("home"));
    let handler = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
        AddressBook::default(),
        projection_reader(
            temp.path().join("cache/prepare-loss-wallets.json"),
            Some(MachineBrokerClient::new(service.clone())),
        ),
        temp.path().join("machine-policy-projections"),
    )
    .with_broker(Some(MachineBrokerClient::new(service)))
    .with_home_write_permit(Arc::new(HomeWritePermit::acquire(&home).unwrap()));
    let write_path = VfsPath::parse("alice/policy.json").unwrap();
    let proposed = serde_json::to_vec_pretty(&policy(120_000)).unwrap();

    let lost = handler.write(&write_path, &proposed).await.unwrap_err();
    assert!(
        matches!(lost, HandlerError::Backend(ref message) if message.contains("SERVICE_UNAVAILABLE"))
    );
    let operation_id = fixture.state.lock().operation_id.clone().unwrap();
    let projection = temp
        .path()
        .join("machine-policy-projections/alice/policy-updates/pending")
        .join(operation_id.as_str())
        .join("approval_challenge.json");
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(projection).unwrap()).unwrap();
    assert_eq!(journal["operation_id"], operation_id.as_str());
    assert!(journal["review_manifest_digest"].is_null());
    assert!(journal["ceremony_url"].is_null());

    assert!(matches!(
        handler.write(&write_path, &proposed).await,
        Err(HandlerError::PermissionDenied)
    ));
    assert_eq!(
        fixture.state.lock().operation_id.as_ref(),
        Some(&operation_id)
    );
    let requests = fixture.requests.lock();
    assert!(matches!(
        requests.as_slice(),
        [
            MachineBrokerRequest::PolicyRead(_),
            MachineBrokerRequest::PolicyValidateUpdate(_),
            MachineBrokerRequest::PolicyValidateUpdate(_)
        ]
    ));
}

#[tokio::test]
async fn vfs_policy_write_prepares_then_commits_only_with_completed_custody_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let outbox = Outbox::new(temp.path().join("outbox")).unwrap();
    let fixture = broker_fixture(false);
    let service: Arc<dyn MachineBrokerService> = fixture.clone();
    let broker = MachineBrokerClient::new(service);
    let home = HomeDir::at(temp.path().join("home"));
    let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
    let projection_root = temp.path().join("machine-policy-projections");
    let handler = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(outbox, 60_000),
        AddressBook::default(),
        projection_reader(
            temp.path().join("cache/policy-wallets.json"),
            Some(broker.clone()),
        ),
        &projection_root,
    )
    .with_broker(Some(broker.clone()))
    .with_home_write_permit(permit);
    let write_path = VfsPath::parse("alice/policy.json").unwrap();
    let proposed = serde_json::to_vec_pretty(&policy(120_000)).unwrap();

    assert!(matches!(
        handler.write(&write_path, &proposed).await,
        Err(HandlerError::PermissionDenied)
    ));
    let operation_id = fixture.state.lock().operation_id.clone().unwrap();
    let pending_status = handler
        .read(
            &VfsPath::parse(&format!(
                "alice/policy-updates/pending/{operation_id}/status.json"
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending_status).unwrap();
    assert_eq!(pending["ceremony_kind"], "policy_update");
    assert_eq!(pending["write_path"], "/wallets/alice/policy.json");
    assert_eq!(
        pending["ceremony_url"],
        "http://localhost:18734/ceremony/policy-test-secret"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let projection = projection_root
            .join("alice/policy-updates/pending")
            .join(operation_id.as_str())
            .join("approval_challenge.json");
        assert_eq!(
            std::fs::metadata(projection).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fixture.complete.store(true, Ordering::SeqCst);
    drop(handler);
    let restarted = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
        AddressBook::default(),
        projection_reader(
            temp.path().join("cache/restarted-wallets.json"),
            Some(broker.clone()),
        ),
        &projection_root,
    )
    .with_broker(Some(broker.clone()))
    .with_home_write_permit(Arc::new(HomeWritePermit::acquire(&home).unwrap()));
    let ready_status = restarted
        .read(&VfsPath::parse("alice/policy-updates/latest/status.json").unwrap())
        .await
        .unwrap();
    let ready: serde_json::Value = serde_json::from_slice(&ready_status).unwrap();
    assert_eq!(ready["status"], "ready_to_commit");
    assert!(ready["ceremony_url"].is_null());

    restarted.write(&write_path, &proposed).await.unwrap();
    let confirmed_status = restarted
        .read(
            &VfsPath::parse(&format!(
                "alice/policy-updates/confirmed/{operation_id}/status.json"
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let confirmed: serde_json::Value = serde_json::from_slice(&confirmed_status).unwrap();
    assert_eq!(confirmed["status"], "confirmed");
    assert!(confirmed["ceremony_url"].is_null());
    let current = restarted
        .read(&VfsPath::parse("alice/policy.json").unwrap())
        .await
        .unwrap();
    assert_eq!(current, serde_jcs::to_vec(&policy(120_000)).unwrap());

    let requests = fixture.requests.lock();
    assert!(matches!(
        requests.as_slice(),
        [
            MachineBrokerRequest::PolicyRead(_),
            MachineBrokerRequest::PolicyValidateUpdate(_),
            MachineBrokerRequest::CeremonyStatus(_),
            MachineBrokerRequest::CeremonyStatus(_),
            MachineBrokerRequest::CeremonyStatus(_),
            MachineBrokerRequest::CustodyResult(_),
            MachineBrokerRequest::PolicyCommitUpdate(_),
            MachineBrokerRequest::WalletListPublic(_),
            MachineBrokerRequest::KeyListPublic(_),
            MachineBrokerRequest::CredentialListPublic(_),
            MachineBrokerRequest::PolicyRead(_),
            MachineBrokerRequest::WalletAccounts(_)
        ]
    ));
}

#[tokio::test]
async fn vfs_policy_cancel_terminates_staged_ceremony_before_recovery_clears_it() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(false);
    let service: Arc<dyn MachineBrokerService> = fixture.clone();
    let home = HomeDir::at(temp.path().join("home"));
    let handler = WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
        AddressBook::default(),
        projection_reader(
            temp.path().join("cache/cancel-wallets.json"),
            Some(MachineBrokerClient::new(service.clone())),
        ),
        temp.path().join("machine-policy-projections"),
    )
    .with_broker(Some(MachineBrokerClient::new(service)))
    .with_home_write_permit(Arc::new(HomeWritePermit::acquire(&home).unwrap()));
    let proposed = serde_json::to_vec_pretty(&policy(120_000)).unwrap();

    assert!(matches!(
        handler
            .write(&VfsPath::parse("alice/policy.json").unwrap(), &proposed)
            .await,
        Err(HandlerError::PermissionDenied)
    ));
    let operation_id = fixture.state.lock().operation_id.clone().unwrap();
    let action_path = format!("alice/policy-updates/pending/{operation_id}");
    let entries = handler
        .list(&VfsPath::parse(&action_path).unwrap())
        .await
        .unwrap();
    assert!(entries.iter().any(|entry| entry.name == "cancel"));
    handler
        .write(
            &VfsPath::parse(&format!("{action_path}/cancel")).unwrap(),
            b"cancel\n",
        )
        .await
        .unwrap();

    assert!(matches!(
        handler.lookup(&VfsPath::parse(&action_path).unwrap()).await,
        Err(HandlerError::NotFound(_))
    ));
    let failed: serde_json::Value = serde_json::from_slice(
        &handler
            .read(
                &VfsPath::parse(&format!(
                    "alice/policy-updates/failed/{operation_id}/status.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["ceremony_state"], "CANCELLED");
    assert_eq!(
        handler
            .read(&VfsPath::parse("alice/policy.json").unwrap())
            .await
            .unwrap(),
        fixture.baseline.canonical_policy.decode()
    );
    assert!(
        fixture
            .requests
            .lock()
            .iter()
            .any(|request| matches!(request, MachineBrokerRequest::CeremonyCancel(_)))
    );
}

#[tokio::test]
async fn vfs_policy_terminal_ceremony_states_clear_urls_and_fail_the_projection() {
    for terminal_state in [
        CeremonyState::Cancelled,
        CeremonyState::Expired,
        CeremonyState::Failed,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let fixture = broker_fixture(false);
        let service: Arc<dyn MachineBrokerService> = fixture.clone();
        let home = HomeDir::at(temp.path().join("home"));
        let projection_root = temp.path().join("machine-policy-projections");
        let handler = WalletsHandler::new(
            bloom_evm::ChainRegistry::default(),
            TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
            AddressBook::default(),
            projection_reader(
                temp.path().join("cache/terminal-wallets.json"),
                Some(MachineBrokerClient::new(service.clone())),
            ),
            &projection_root,
        )
        .with_broker(Some(MachineBrokerClient::new(service)))
        .with_home_write_permit(Arc::new(HomeWritePermit::acquire(&home).unwrap()));
        let proposed = serde_json::to_vec_pretty(&policy(120_000)).unwrap();

        assert!(matches!(
            handler
                .write(&VfsPath::parse("alice/policy.json").unwrap(), &proposed)
                .await,
            Err(HandlerError::PermissionDenied)
        ));
        let operation_id = fixture.state.lock().operation_id.clone().unwrap();
        *fixture.ceremony_state_override.lock() = Some(terminal_state);

        let status = handler
            .read(&VfsPath::parse("alice/policy-updates/latest/status.json").unwrap())
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["status"], "failed");
        assert!(status["ceremony_url"].is_null());

        let failed_projection = projection_root
            .join("alice/policy-updates/failed")
            .join(operation_id.as_str())
            .join("approval_challenge.json");
        let projection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(failed_projection).unwrap()).unwrap();
        assert!(projection["ceremony_url"].is_null());
        assert!(projection["ceremony_expires_at_ms"].is_null());
    }
}

#[tokio::test]
async fn vfs_policy_non_actionable_ceremony_states_never_expose_launch_data() {
    for state in [
        CeremonyState::Prepared,
        CeremonyState::Verifying,
        CeremonyState::WalletCommitted,
        CeremonyState::AwaitingRecoveryAck,
        CeremonyState::ApprovingRootChange,
        CeremonyState::CreatingCredential,
        CeremonyState::Committing,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let fixture = broker_fixture(false);
        let service: Arc<dyn MachineBrokerService> = fixture.clone();
        let home = HomeDir::at(temp.path().join("home"));
        let projection_root = temp.path().join("machine-policy-projections");
        let handler = WalletsHandler::new(
            bloom_evm::ChainRegistry::default(),
            TxEngine::new(Outbox::new(temp.path().join("outbox")).unwrap(), 60_000),
            AddressBook::default(),
            projection_reader(
                temp.path().join("cache/non-actionable-wallets.json"),
                Some(MachineBrokerClient::new(service.clone())),
            ),
            &projection_root,
        )
        .with_broker(Some(MachineBrokerClient::new(service)))
        .with_home_write_permit(Arc::new(HomeWritePermit::acquire(&home).unwrap()));
        let proposed = serde_json::to_vec_pretty(&policy(120_000)).unwrap();

        assert!(matches!(
            handler
                .write(&VfsPath::parse("alice/policy.json").unwrap(), &proposed)
                .await,
            Err(HandlerError::PermissionDenied)
        ));
        let operation_id = fixture.state.lock().operation_id.clone().unwrap();
        *fixture.ceremony_state_override.lock() = Some(state);

        let status = handler
            .read(&VfsPath::parse("alice/policy-updates/latest/status.json").unwrap())
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert!(status["ceremony_url"].is_null(), "{state:?}");

        let projection = projection_root
            .join("alice/policy-updates/pending")
            .join(operation_id.as_str())
            .join("approval_challenge.json");
        let projection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(projection).unwrap()).unwrap();
        assert!(projection["ceremony_url"].is_null(), "{state:?}");
        assert!(projection["ceremony_expires_at_ms"].is_null(), "{state:?}");
    }
}

#[test]
fn package_eligibility_preserves_all_existing_policy_restrictions() {
    let before = policy(60_000);
    let hash = Digest32::from_bytes([7; 32]);
    let after = policy_with_package(&before, &hash);
    let mut expected = before.clone();
    expected.allowed_petal_packages.push(hash.clone());
    assert_eq!(after, expected);
    assert_eq!(policy_with_package(&after, &hash), after);
}

#[test]
fn default_policy_packages_are_appended_once_in_order() {
    let before = policy(60_000);
    let first = Digest32::from_bytes([7; 32]);
    let second = Digest32::from_bytes([8; 32]);
    let after = bloom_machine_client::policy_with_packages(
        &before,
        &[first.clone(), second.clone(), first.clone()],
    );
    let mut expected = before.clone();
    expected.allowed_petal_packages.extend([first, second]);
    assert_eq!(after, expected);
}

#[tokio::test]
async fn default_wallet_first_proposal_allows_setup_packages_together() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(true);
    let requested = Digest32::from_bytes([7; 32]);
    let chosen = Digest32::from_bytes([8; 32]);
    let defaults: bloom_vfs::handlers::DefaultPolicyPackages = {
        let chosen = chosen.clone();
        Arc::new(move |wallet: &str| {
            if wallet == "alice" {
                bloom_vfs::handlers::DefaultPolicySetup {
                    packages: vec![chosen.clone()],
                    destinations: vec![setup_destination()],
                }
            } else {
                bloom_vfs::handlers::DefaultPolicySetup::default()
            }
        })
    };
    let handler = eligibility_handler(temp.path(), fixture.clone())
        .with_default_policy_packages(defaults.clone());
    assert!(
        matches!(handler.ensure_petal_eligibility("alice", &requested).await,
        Err(HandlerError::Backend(message)) if message.contains("SERVICE_UNAVAILABLE"))
    );
    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_eligibility("alice", &requested)
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };
    assert!(pending.includes_requested_package);
    drop(handler);
    fixture.complete.store(true, Ordering::SeqCst);
    let restarted =
        eligibility_handler(temp.path(), fixture.clone()).with_default_policy_packages(defaults);
    let PetalEligibility::Allowed(snapshot) = restarted
        .ensure_petal_packages_allowed("alice", &[requested.clone(), chosen.clone()], &[])
        .await
        .unwrap()
    else {
        panic!("one completed ceremony must allow every setup package");
    };
    // One ceremony allows every chosen Petal and the contracts they transact
    // with, so no Petal is left usable-but-blocked at the outbox.
    assert_eq!(
        snapshot.canonical_policy.decode(),
        serde_jcs::to_vec(&bloom_machine_client::policy_with_destinations(
            &bloom_machine_client::policy_with_packages(&policy(60_000), &[requested, chosen]),
            &[setup_destination()],
        ))
        .unwrap()
    );
}

#[test]
fn default_policy_destinations_are_appended_once_in_order() {
    let before = policy(60_000);
    let existing = before.allowed_destinations[0].clone();
    let router = bloom_broker_api::PolicyDestination {
        chain: Token::new("arbitrum").unwrap(),
        destination: "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf".into(),
    };
    let after = bloom_machine_client::policy_with_destinations(
        &before,
        &[router.clone(), existing, router.clone()],
    );
    let mut expected = before.clone();
    expected.allowed_destinations.push(router);
    assert_eq!(after, expected);
}

#[tokio::test]
async fn default_policy_proposes_packages_and_destinations_in_one_ceremony() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(false);
    let packages = [Digest32::from_bytes([7; 32])];
    let destinations = [bloom_broker_api::PolicyDestination {
        chain: Token::new("arbitrum").unwrap(),
        destination: "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf".into(),
    }];
    let handler = eligibility_handler(temp.path(), fixture.clone());
    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_packages_allowed("alice", &packages, &destinations)
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };
    assert!(pending.includes_requested_package);

    fixture.complete.store(true, Ordering::SeqCst);
    let PetalEligibility::Allowed(snapshot) = handler
        .ensure_petal_packages_allowed("alice", &packages, &destinations)
        .await
        .unwrap()
    else {
        panic!("one completed ceremony must allow the packages and destinations");
    };
    let expected = bloom_machine_client::policy_with_destinations(
        &bloom_machine_client::policy_with_packages(&policy(60_000), &packages),
        &destinations,
    );
    assert_eq!(
        snapshot.canonical_policy.decode(),
        serde_jcs::to_vec(&expected).unwrap()
    );
}

#[tokio::test]
async fn setup_packages_join_only_a_wallets_first_policy_proposal() {
    let temp = tempfile::tempdir().unwrap();
    let existing = Digest32::from_bytes([5; 32]);
    let mut baseline = policy(60_000);
    baseline.allowed_petal_packages.push(existing.clone());
    let fixture = broker_fixture_with_policy(false, baseline.clone());
    let requested = Digest32::from_bytes([7; 32]);
    let chosen = Digest32::from_bytes([8; 32]);
    let defaults: bloom_vfs::handlers::DefaultPolicyPackages = {
        let chosen = chosen.clone();
        Arc::new(
            move |_wallet: &str| bloom_vfs::handlers::DefaultPolicySetup {
                packages: vec![chosen.clone()],
                destinations: vec![setup_destination()],
            },
        )
    };
    let handler =
        eligibility_handler(temp.path(), fixture.clone()).with_default_policy_packages(defaults);

    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_eligibility("alice", &requested)
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };
    assert!(pending.includes_requested_package);

    // The owner removed `chosen` from a policy that already allows a Petal;
    // this proposal must not put it back behind the requested package.
    let proposed: CanonicalWalletPolicy = serde_json::from_slice(
        fixture
            .state
            .lock()
            .proposed_policy
            .as_ref()
            .expect("a policy was proposed"),
    )
    .unwrap();
    assert_eq!(
        proposed.allowed_petal_packages,
        vec![existing, requested.clone()]
    );
    assert!(!proposed.allowed_petal_packages.contains(&chosen));
}

#[tokio::test]
async fn a_pending_change_without_every_required_package_is_reported_as_unrelated() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(false);
    let first = Digest32::from_bytes([7; 32]);
    let second = Digest32::from_bytes([8; 32]);
    let handler = eligibility_handler(temp.path(), fixture.clone());

    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_eligibility("alice", &first)
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };
    assert!(pending.includes_requested_package);

    // The pending change allows `first` only. A caller asking for both must be
    // told this change is not theirs, so nothing announces it as such.
    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_packages_allowed("alice", &[first, second], &[])
        .await
        .unwrap()
    else {
        panic!("owner approval must still be required");
    };
    assert!(!pending.includes_requested_package);
}

#[tokio::test]
async fn expired_default_policy_proposal_is_replaced_by_a_new_ceremony() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(false);
    let packages = [Digest32::from_bytes([7; 32]), Digest32::from_bytes([8; 32])];
    let handler = eligibility_handler(temp.path(), fixture.clone());
    let PetalEligibility::AwaitingPolicyApproval(first) = handler
        .ensure_petal_packages_allowed("alice", &packages, &[])
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };

    *fixture.ceremony_state_override.lock() = Some(CeremonyState::Expired);
    let PetalEligibility::AwaitingPolicyApproval(replacement) = handler
        .ensure_petal_packages_allowed("alice", &packages, &[])
        .await
        .unwrap()
    else {
        panic!("an expired proposal must be replaced, not reported as terminal");
    };
    assert_ne!(replacement.operation_id, first.operation_id);
    assert!(replacement.prepare.is_some());
    let updates = temp
        .path()
        .join("machine-policy-projections/alice/policy-updates");
    assert!(
        updates
            .join("failed")
            .join(first.operation_id.as_str())
            .exists()
    );
    assert!(
        updates
            .join("pending")
            .join(replacement.operation_id.as_str())
            .exists()
    );
}

#[tokio::test]
async fn policy_ceremony_past_expiry_is_cancelled_and_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(false);
    let packages = [Digest32::from_bytes([7; 32]), Digest32::from_bytes([8; 32])];
    let handler = eligibility_handler(temp.path(), fixture.clone());
    let PetalEligibility::AwaitingPolicyApproval(first) = handler
        .ensure_petal_packages_allowed("alice", &packages, &[])
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };

    // The Broker still reports the ceremony as awaiting the owner after expiry.
    fixture.ceremony_expires_at_ms.store(1, Ordering::SeqCst);
    let PetalEligibility::AwaitingPolicyApproval(replacement) = handler
        .ensure_petal_packages_allowed("alice", &packages, &[])
        .await
        .unwrap()
    else {
        panic!("a ceremony past its expiry must be replaced");
    };
    assert_ne!(replacement.operation_id, first.operation_id);
    assert!(fixture.requests.lock().iter().any(|request| matches!(
        request,
        MachineBrokerRequest::CeremonyCancel(cancel)
            if cancel.id.as_str() == first.operation_id.as_str()
    )));
    assert!(
        temp.path()
            .join("machine-policy-projections/alice/policy-updates/failed")
            .join(first.operation_id.as_str())
            .exists()
    );
}

/// A destination the setup Petals contribute, as the catalog does.
fn setup_destination() -> bloom_broker_api::PolicyDestination {
    bloom_broker_api::PolicyDestination {
        chain: Token::new("polygon").unwrap(),
        destination: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
    }
}

fn eligibility_handler(temp: &std::path::Path, fixture: Arc<BrokerFixture>) -> WalletsHandler {
    let broker = MachineBrokerClient::new(fixture);
    WalletsHandler::new(
        bloom_evm::ChainRegistry::default(),
        TxEngine::new(Outbox::new(temp.join("outbox")).unwrap(), 60_000),
        AddressBook::default(),
        projection_reader(temp.join("wallets.json"), Some(broker.clone())),
        temp.join("machine-policy-projections"),
    )
    .with_broker(Some(broker))
    .with_home_write_permit(Arc::new(
        HomeWritePermit::acquire(&HomeDir::at(temp.join("home"))).unwrap(),
    ))
}

#[tokio::test]
async fn petal_eligibility_recovers_lost_prepare_and_commits_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = broker_fixture(true);
    let hash = Digest32::from_bytes([7; 32]);
    let handler = eligibility_handler(temp.path(), fixture.clone());
    assert!(
        matches!(handler.ensure_petal_eligibility("alice", &hash).await,
        Err(HandlerError::Backend(message)) if message.contains("SERVICE_UNAVAILABLE"))
    );
    let operation = fixture.state.lock().operation_id.clone().unwrap();
    let PetalEligibility::AwaitingPolicyApproval(pending) = handler
        .ensure_petal_eligibility("alice", &hash)
        .await
        .unwrap()
    else {
        panic!("owner approval must be required");
    };
    assert_eq!(pending.operation_id, operation);
    assert!(pending.includes_requested_package);
    assert!(pending.prepare.is_some());
    drop(handler);
    fixture.complete.store(true, Ordering::SeqCst);
    let restarted = eligibility_handler(temp.path(), fixture.clone());
    let PetalEligibility::Allowed(snapshot) = restarted
        .ensure_petal_eligibility("alice", &hash)
        .await
        .unwrap()
    else {
        panic!("completed ceremony must commit automatically");
    };
    assert_eq!(
        snapshot.canonical_policy.decode(),
        serde_jcs::to_vec(&policy_with_package(&policy(60_000), &hash)).unwrap()
    );
    assert!(
        temp.path()
            .join("machine-policy-projections/alice/policy-updates/confirmed")
            .join(operation.as_str())
            .exists()
    );
    let requests = fixture.requests.lock();
    let prepares: Vec<_> = requests
        .iter()
        .filter_map(|r| match r {
            MachineBrokerRequest::PolicyValidateUpdate(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(prepares.len(), 2);
    assert_eq!(prepares[0], prepares[1]);
    assert_eq!(
        requests
            .iter()
            .filter(|r| matches!(r, MachineBrokerRequest::PolicyCommitUpdate(_)))
            .count(),
        1
    );
}
