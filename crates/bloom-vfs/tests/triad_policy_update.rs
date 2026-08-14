use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use bloom_broker_api::{
    Base64UrlBytes, CanonicalWalletPolicy, CeremonyKind, CeremonyPublicStatus, CeremonyState,
    CredentialPublic, CryptoSuite, CustodyResult, DecimalU64, Digest32, KeyPublic, KeyRef, KeySpec,
    MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, OperationId,
    PolicyCommitReceipt, PolicyUpdatePrepareResponse, ProtocolError, ProtocolErrorCode,
    ServiceFuture, SignedPolicySnapshot, Token, WalletPublic, WalletRequest,
};
use bloom_machine_client::{
    CachedWalletProjectionReader, FileProjectionStore, MachineBrokerClient, WalletProjectionReader,
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
            root_key_ref: self.key_ref(),
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
                            expires_at_ms: DecimalU64::new(u64::MAX),
                            ceremony_url: (state == CeremonyState::AwaitingUser).then(|| {
                                "http://localhost:18734/ceremony/policy-test-secret".into()
                            }),
                            receipt_digest: (state == CeremonyState::Succeeded)
                                .then(|| Digest32::from_bytes([8; 32])),
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
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
    }
}

fn broker_fixture(lose_prepare_response_once: bool) -> Arc<BrokerFixture> {
    let baseline_bytes = serde_jcs::to_vec(&policy(60_000)).unwrap();
    Arc::new(BrokerFixture {
        available: AtomicBool::new(true),
        complete: AtomicBool::new(false),
        lose_prepare_response_once: AtomicBool::new(lose_prepare_response_once),
        ceremony_state_override: parking_lot::Mutex::new(None),
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
            .read(&VfsPath::parse("/alice/address").unwrap())
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
    let addresses: serde_json::Value = serde_json::from_slice(
        &stale_handler
            .read(&VfsPath::parse("/alice/addresses.json").unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(addresses["freshness"], "stale");
    assert_eq!(addresses["policy_version"], "1");
    assert_eq!(addresses["policy_digest"], expected_policy_digest.as_str());
    assert_eq!(addresses["wallet_revocation_epoch"], "0");
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
            MachineBrokerRequest::PolicyRead(_)
        ]
    ));
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
