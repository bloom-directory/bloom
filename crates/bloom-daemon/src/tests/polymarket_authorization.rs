//! Real installer/Daemon host/Broker/Signer acceptance. Only venue and chain
//! observations are controlled; signing always delegates to DaemonPetalHost.
use super::*;
use bloom_broker_api::{CustodyPrepareRequest, Digest32, OperationId, Token};
use bloom_vfs::{Handler, VfsPath};
use std::sync::{Mutex, atomic::AtomicU64};

struct VenueFixture {
    machine: Arc<DaemonPetalHost>,
    trading_ready: bool,
    timestamp: AtomicU64,
    requests: Mutex<Vec<PayloadBatchSignRequest>>,
    signed: Mutex<Vec<(PayloadBatchSignRequest, Vec<Vec<u8>>)>>,
    auth_posts: AtomicU64,
    prepared_requests: Mutex<Vec<(bloom_petal_contract::prepared::Request, PetalRouteContext)>>,
    prepared_signed: Mutex<Vec<(bloom_petal_contract::prepared::Request, Vec<u8>)>>,
    prepared_outcomes: Mutex<
        Vec<(
            String,
            Result<
                bloom_petal_contract::prepared::SigningOutcome,
                bloom_petal_contract::prepared::SigningError,
            >,
        )>,
    >,
    single_requests: Mutex<Vec<PayloadSignRequest>>,
    single_signed: Mutex<Vec<(PayloadSignRequest, Vec<u8>)>>,
}

impl VenueFixture {
    fn new(machine: Arc<DaemonPetalHost>, trading_ready: bool) -> Self {
        Self {
            machine,
            trading_ready,
            timestamp: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            requests: Mutex::new(vec![]),
            signed: Mutex::new(vec![]),
            auth_posts: AtomicU64::new(0),
            prepared_requests: Mutex::new(vec![]),
            prepared_signed: Mutex::new(vec![]),
            prepared_outcomes: Mutex::new(vec![]),
            single_requests: Mutex::new(vec![]),
            single_signed: Mutex::new(vec![]),
        }
    }
}

#[async_trait::async_trait]
impl PetalHost for VenueFixture {
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        self.machine.vfs_lookup(path).await
    }
    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        self.machine.vfs_list(path).await
    }
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        if path == "chains/polygon/chain_id" {
            return Ok(b"137".to_vec());
        }
        self.machine.vfs_read(path).await
    }
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.machine.vfs_write(path, bytes).await
    }
    async fn http_fetch(
        &self,
        request: HttpRequest,
        policy: NetPolicy,
        _max: usize,
    ) -> Result<HttpResponse, HostError> {
        policy.check(&request.method, &request.url)?;
        let body = if request.url == "https://clob.polymarket.com/time" && request.method == "GET" {
            self.timestamp
                .load(Ordering::SeqCst)
                .to_string()
                .into_bytes()
        } else if request.url == "https://clob.polymarket.com/auth/api-key"
            && request.method == "POST"
        {
            let signed = self.prepared_signed.lock().unwrap();
            assert_eq!(
                signed.len(),
                1,
                "credentials require one completed signature"
            );
            let (authorization, signature_bytes) = &signed[0];
            let signature = alloy::primitives::Signature::from_raw(signature_bytes).unwrap();
            let owner = signature
                .recover_address_from_prehash(&alloy::primitives::B256::from(
                    authorization.action.payload.hash,
                ))
                .unwrap();
            let prepared: serde_json::Value =
                serde_json::from_slice(&authorization.action.review.bytes).unwrap();
            let prepared = &prepared[0];
            assert_eq!(
                prepared["preimage"]["timestamp"].as_u64(),
                Some(self.timestamp.load(Ordering::SeqCst))
            );
            assert_eq!(prepared["preimage"]["nonce"].as_u64(), Some(0));
            assert_eq!(
                prepared["owner"]
                    .as_str()
                    .unwrap()
                    .parse::<alloy::primitives::Address>()
                    .unwrap(),
                owner
            );
            assert_eq!(
                prepared["signing_preimage_hex"].as_str().unwrap(),
                hex::encode(&authorization.action.payload.preimage)
            );
            let header = |name: &str| {
                let values = request
                    .headers
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(values.len(), 1, "one {name} authentication header required");
                values[0]
            };
            // Compare without including authentication values in assertion output.
            assert!(header("POLY_ADDRESS") == format!("{owner:#x}"));
            assert!(header("POLY_NONCE") == "0");
            assert!(header("POLY_TIMESTAMP") == self.timestamp.load(Ordering::SeqCst).to_string());
            assert!(header("POLY_SIGNATURE") == format!("0x{}", hex::encode(signature_bytes)));
            self.auth_posts.fetch_add(1, Ordering::SeqCst);
            include_bytes!("../../tests/fixtures/polymarket-credentials.json").to_vec()
        } else if request.url == "https://gamma-api.polymarket.com/markets/slug/test"
            && request.method == "GET"
        {
            br#"{"slug":"test","question":"test","conditionId":"condition","clobTokenIds":["42","43"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true,"negRisk":false}"#.to_vec()
        } else if request.url.starts_with("https://clob.polymarket.com/book?")
            && request.method == "GET"
        {
            br#"{"market":"condition","asset_id":"42","tick_size":"0.01","min_order_size":"1","neg_risk":false,"asks":[{"price":"0.50","size":"100"}],"bids":[{"price":"0.49","size":"100"}]}"#.to_vec()
        } else if request
            .url
            .starts_with("https://clob.polymarket.com/balance-allowance?")
            && request.method == "GET"
        {
            br#"{"balance":"100000000","allowance":"100000000"}"#.to_vec()
        } else if request
            .url
            .starts_with("https://relayer-v2.polymarket.com/nonce?")
        {
            br#"{"nonce":"0"}"#.to_vec()
        } else {
            // Deliberately stop before any venue submission. The test inspects
            // the actual completed batch signature, not a simulated settlement.
            return Err(HostError::Denied(
                "venue submission excluded from signing fixture".into(),
            ));
        };
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body,
        })
    }
    async fn chain_read(&self, request: ChainRequest) -> Result<ChainResponse, HostError> {
        assert_eq!(request.chain, "polygon");
        let params: serde_json::Value = serde_json::from_str(&request.params_json).unwrap();
        let value = match request.method.as_str() {
            "eth_getCode" => "0x6000".into(),
            "eth_call" => {
                let data = params[0]["data"].as_str().unwrap();
                match &data[..10] {
                    // The live readiness gate requires at least 2^160, not
                    // merely a positive ERC20 allowance.
                    "0xdd62ed3e" if self.trading_ready => format!("0x{}", "f".repeat(64)),
                    "0xdd62ed3e" => format!("0x{:064x}", 0),
                    selector => {
                        let word = match selector {
                            "0x5c60da1b" | "0x1f264778" => 3u64,
                            "0x70a08231" | "0x00fdd58e" => 100_000_000,
                            "0xe985e9c5" => u64::from(self.trading_ready),
                            _ => {
                                return Err(HostError::Denied(
                                    "unexpected fixture chain selector".into(),
                                ));
                            }
                        };
                        format!("0x{word:064x}")
                    }
                }
            }
            _ => return Err(HostError::Denied("unexpected fixture chain method".into())),
        };
        Ok(ChainResponse {
            result_json: serde_json::to_string(&value).unwrap(),
        })
    }
    async fn prepared_sign(
        &self,
        request: bloom_petal_contract::prepared::Request,
        context: PetalRouteContext,
    ) -> Result<
        bloom_petal_contract::prepared::SigningOutcome,
        bloom_petal_contract::prepared::SigningError,
    > {
        self.prepared_requests
            .lock()
            .unwrap()
            .push((request.clone(), context.clone()));
        let result = self.machine.prepared_sign(request.clone(), context).await;
        self.prepared_outcomes
            .lock()
            .unwrap()
            .push((request.operation_key.clone(), result.clone()));
        if let Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { signature }) = &result {
            self.prepared_signed
                .lock()
                .unwrap()
                .push((request, signature.clone()));
        }
        result
    }
    async fn prepared_sign_status(
        &self,
        request: bloom_petal_contract::prepared::StatusRequest,
        context: PetalRouteContext,
    ) -> Result<
        bloom_petal_contract::prepared::SigningOutcome,
        bloom_petal_contract::prepared::SigningError,
    > {
        self.machine.prepared_sign_status(request, context).await
    }
    async fn sign_payload_batch_outcome(
        &self,
        request: PayloadBatchSignRequest,
    ) -> Result<PayloadBatchSignOutcome, HostError> {
        self.requests.lock().unwrap().push(request.clone());
        // Keep the component's original request for producer assertions, but
        // exercise a caller preferring reusable authority at the real boundary.
        // Machine must still obtain exact approval with the complete witness.
        let mut forwarded = request.clone();
        if bloom_broker_api::POLYMARKET_REVIEW_OPERATION_CLASSES
            .contains(&forwarded.operation_class.as_str())
        {
            forwarded.selector = bloom_broker_api::PetalSignSelector::Reusable;
        }
        let result = self.machine.sign_payload_batch_outcome(forwarded).await;
        if let Ok(PayloadBatchSignOutcome::Signatures(signatures)) = &result {
            self.signed
                .lock()
                .unwrap()
                .push((request, signatures.clone()));
        }
        result
    }
    async fn sign_payload_outcome(
        &self,
        request: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        self.single_requests.lock().unwrap().push(request.clone());
        let result = self.machine.sign_payload_outcome(request.clone()).await;
        if let Ok(SignOutcome::Signature(signature)) = &result {
            self.single_signed
                .lock()
                .unwrap()
                .push((request, signature.clone()));
        }
        result
    }
}

fn setting(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("set {name} through scripts/test-polymarket-authorization.sh"))
        .into()
}

fn complete(url: &str, count: u64, mnemonic: Option<&Path>) {
    let mut command = std::process::Command::new(setting("BLOOM_INTEGRATION_DEBUG_DRIVER_BIN"));
    command.args([
        "complete",
        url,
        "pm80-authorization-disposable-owner",
        "--sign-count",
        &count.to_string(),
    ]);
    if let Some(path) = mnemonic {
        command.arg("--mnemonic-file").arg(path);
    }
    let result = command.output().unwrap();
    // Do not expose the capability URL, signatures, recovery data or driver
    // output. The retained service logs and public test result identify failures.
    assert!(
        result.status.success(),
        "software-owner ceremony failed (exit {:?})",
        result.status.code()
    );
}

async fn read_json(vfs: &Vfs, path: &str) -> serde_json::Value {
    serde_json::from_slice(&vfs.read(&VfsPath::parse(path).unwrap()).await.unwrap()).unwrap()
}

fn pending(root: &Path, class: &str) -> serde_json::Value {
    let matches: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                return None;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            (value["operation_class"] == class && value["status"] == "awaiting_owner_approval")
                .then_some(value)
        })
        .collect();
    assert_eq!(matches.len(), 1, "one pending owner ceremony for {class}");
    matches.into_iter().next().unwrap()
}

struct AuthorizationFixture {
    home: HomeDir,
    client: MachineBrokerClient,
    catalog: bloom_broker_api::ProvenanceCatalog,
    daemon: Daemon,
    wallet: Token,
}

async fn account_one_fixture() -> AuthorizationFixture {
    use sha2::Digest as _;
    let root = setting("BLOOM_TRIAD_DEVELOPER_ROOT");
    let home = HomeDir::at(setting("BLOOM_HOME"));
    let client = MachineBrokerClient::connect_unix_from_developer_files(
        &root,
        setting("BLOOM_BROKER_SOCKET"),
        setting("BLOOM_MACHINE_IDENTITY"),
        setting("BLOOM_EDGE_MANIFEST"),
    )
    .unwrap();
    let catalog: bloom_broker_api::ProvenanceCatalog =
        serde_json::from_slice(&std::fs::read(setting("BLOOM_PROVENANCE_CATALOG")).unwrap())
            .unwrap();
    let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
    let daemon = Daemon::from_home_with_permit_and_broker(
        home.clone(),
        permit,
        client.clone(),
        catalog.clone(),
    )
    .unwrap();
    let wallet = Token::new("pm80-authorization").unwrap();
    let operation = OperationId::from_bytes([0x81; 32]);
    let imported = client
        .prepare_custody(
            bloom_machine_client::CustodyPrepareMethod::WalletImport,
            CustodyPrepareRequest {
                ceremony_kind: bloom_broker_api::CeremonyKind::WalletImport,
                surface_selection: bloom_broker_api::CeremonySurfaceSelection::Local,
                custody_operation_id: operation.clone(),
                wallet_id: Some(wallet.clone()),
                key_ref: None,
                exact_terms_digest: Digest32::from_bytes(
                    sha2::Sha256::digest(b"pm80 disposable import").into(),
                ),
                expected_input_class: Token::new("bip39-mnemonic").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1),
                derivation_requests: vec![],
                account_terms: None,
            },
        )
        .await
        .unwrap();
    complete(
        &imported.ceremony_url,
        1,
        Some(&setting("BLOOM_PM80_MNEMONIC_FILE")),
    );
    client
        .custody_result(bloom_broker_api::OperationRequest {
            operation_id: operation,
        })
        .await
        .unwrap();
    let allocate = VfsPath::parse("wallets/pm80-authorization/new").unwrap();
    daemon
        .vfs
        .write(&allocate, br#"{"request_id":"account-one"}"#)
        .await
        .unwrap();
    let allocation = read_json(&daemon.vfs, "wallets/pm80-authorization/new").await;
    complete(
        allocation["requests"][0]["ceremony_url"].as_str().unwrap(),
        2,
        None,
    );
    let allocated = read_json(&daemon.vfs, "wallets/pm80-authorization/new").await;
    assert_eq!(allocated["requests"][0]["number"], 1);
    AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet,
    }
}

async fn existing_authorization_fixture() -> AuthorizationFixture {
    let root = setting("BLOOM_TRIAD_DEVELOPER_ROOT");
    let home = HomeDir::at(setting("BLOOM_HOME"));
    let client = MachineBrokerClient::connect_unix_from_developer_files(
        &root,
        setting("BLOOM_BROKER_SOCKET"),
        setting("BLOOM_MACHINE_IDENTITY"),
        setting("BLOOM_EDGE_MANIFEST"),
    )
    .unwrap();
    let catalog: bloom_broker_api::ProvenanceCatalog =
        serde_json::from_slice(&std::fs::read(setting("BLOOM_PROVENANCE_CATALOG")).unwrap())
            .unwrap();
    let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
    let daemon = Daemon::from_home_with_permit_and_broker(
        home.clone(),
        permit,
        client.clone(),
        catalog.clone(),
    )
    .unwrap();
    AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet: Token::new("pm80-authorization").unwrap(),
    }
}

async fn approve_package(
    daemon: &Daemon,
    client: &MachineBrokerClient,
    wallet: &Token,
    hash: &str,
    counter: u64,
    standing: bool,
) {
    let baseline = client.policy(wallet.clone()).await.unwrap();
    let mut policy: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(&baseline.canonical_policy.decode()).unwrap();
    if standing {
        policy.maximum_approval_lifetime_ms =
            bloom_broker_api::STANDING_APPROVAL_POLICY_LIFETIME_MS;
    }
    policy
        .allowed_petal_packages
        .push(Digest32::new(hash.to_owned()).unwrap());
    let policy_bytes = serde_jcs::to_vec(&policy).unwrap();
    let policy_path = VfsPath::parse("wallets/pm80-authorization/policy.json").unwrap();
    assert!(daemon.vfs.write(&policy_path, &policy_bytes).await.is_err());
    let review = read_json(
        &daemon.vfs,
        "wallets/pm80-authorization/policy-updates/latest/approval_challenge.json",
    )
    .await;
    complete(review["ceremony_url"].as_str().unwrap(), counter, None);
    daemon.vfs.write(&policy_path, &policy_bytes).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable real services and installer enrollment; run scripts/test-polymarket-authorization.sh"]
async fn installed_account_one_auth_and_exact_continuation_use_real_authority() {
    let AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet,
    } = account_one_fixture().await;
    let capabilities = client
        .request(bloom_broker_api::MachineBrokerRequest::BrokerCapabilities(
            bloom_broker_api::Empty {},
        ))
        .await
        .unwrap();
    let bloom_broker_api::MachineBrokerResponse::BrokerCapabilities(capabilities) = capabilities
    else {
        panic!("Broker capability response mismatch");
    };
    assert!(
        bloom_broker_api::reusable_signing_profiles()
            .iter()
            .all(|profile| profile.is_advertised(&capabilities.schemas))
    );
    let accounts = client.wallet_accounts(wallet.clone()).await.unwrap();
    let account_one = accounts
        .accounts
        .iter()
        .find(|a| a.path == "m/44'/60'/0'/0/1")
        .unwrap();
    // Navigation reads use the authenticated cache; explicitly refresh after
    // allocating the new account before reading its address in this fixture.
    daemon
        .wallet_projections
        .get_wallet_authority(&wallet)
        .await
        .unwrap();
    let owner: Address = String::from_utf8(
        daemon
            .vfs
            .read(&VfsPath::parse("wallets/pm80-authorization/1/address.evm").unwrap())
            .await
            .unwrap(),
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap();

    let package =
        bloom_petals::package::build_petal_package_dir(setting("BLOOM_PM80_POLYMARKET_ROOT"))
            .unwrap();
    let hash = package.hash.clone();
    let auth_route = package
        .route_index
        .routes
        .iter()
        .find(|r| r.pattern == "onboard/[wallet]/[index]/begin")
        .unwrap()
        .route_id
        .clone();
    let exact_route = package
        .route_index
        .routes
        .iter()
        .find(|r| r.pattern == "onboard/[wallet]/[index]/continue")
        .unwrap()
        .route_id
        .clone();
    for (route, class) in [
        (&auth_route, "polymarket.clob_auth.v1"),
        (&exact_route, "polymarket.onboard"),
    ] {
        let record = catalog
            .record(&bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: Digest32::new(hash.clone()).unwrap(),
                route: route.clone(),
            })
            .unwrap();
        assert!(
            record
                .operation_classes
                .iter()
                .any(|c| c.operation_class.as_str() == class)
        );
        assert!(!record.installer_signature.decode().is_empty());
        assert!(record.petal_lineage.as_ref().unwrap().active);
    }
    let staged = daemon.petals.store().stage_petal_package(package).unwrap();
    daemon
        .petals
        .install_staged_petal_package(staged, None, || Ok(()))
        .unwrap();
    approve_package(&daemon, &client, &wallet, &hash, 3, false).await;

    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(daemon.vfs.clone()));
    let state = home.cache_dir().join("pm80-signing-requests");
    let machine = Arc::new(
        DaemonPetalHost::new(late, daemon.audit.clone())
            .with_broker(daemon.broker_client())
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(Some(catalog))
            .with_petal_signing_state_root(state.clone()),
    );
    let host = Arc::new(VenueFixture::new(machine.clone(), false));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host.clone())),
        )
        .build();
    let begin = VfsPath::parse("petals/polymarket/onboard/pm80-authorization/1/begin").unwrap();
    let begin_error = vfs.write(&begin, b"begin").await.unwrap_err();
    assert!(
        !host.prepared_requests.lock().unwrap().is_empty(),
        "begin failed before prepared signing: {begin_error}"
    );
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 0);
    let first_outcome = host.prepared_outcomes.lock().unwrap()[0].1.clone();
    assert!(
        matches!(
            first_outcome,
            Ok(bloom_petal_contract::prepared::SigningOutcome::ApprovalPending { .. })
        ),
        "login should request review, outcome: {first_outcome:?}; route error: {begin_error}"
    );
    let auth = pending(&state, "polymarket.clob_auth.v1");
    let (first, first_context) = host.prepared_requests.lock().unwrap()[0].clone();
    assert_eq!(first_context.route_id, auth_route);
    assert_eq!(first_context.trusted_account().unwrap().number, 1);
    complete(auth["ceremony_url"].as_str().unwrap(), 4, None);
    host.timestamp.fetch_add(2, Ordering::SeqCst);
    vfs.write(&begin, b"begin").await.unwrap();
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 1);
    {
        let signed = host.prepared_signed.lock().unwrap();
        assert_eq!(signed.len(), 1);
        assert_ne!(
            signed[0].0.action.payload.preimage, first.action.payload.preimage,
            "server timestamp refreshed under one-use auth profile"
        );
        assert_eq!(signed[0].1.len(), 65);
    }
    let continuation =
        VfsPath::parse("petals/polymarket/onboard/pm80-authorization/1/continue").unwrap();
    let continuation_error = vfs
        .write(&continuation, b"continue")
        .await
        .expect_err("continuation must await exact review");
    let continuation_outcome = host.prepared_outcomes.lock().unwrap().last().cloned();
    let continuation_state = match &continuation_outcome {
        Some((_, Ok(bloom_petal_contract::prepared::SigningOutcome::ApprovalPending { .. }))) => {
            "approval_pending".to_owned()
        }
        Some((_, Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { .. }))) => {
            "signed".to_owned()
        }
        Some((_, Ok(bloom_petal_contract::prepared::SigningOutcome::RecoveryRequired { .. }))) => {
            "recovery_required".to_owned()
        }
        Some((_, Err(error))) => format!("error: {error}"),
        None => "not called".to_owned(),
    };
    assert_eq!(
        continuation_state, "approval_pending",
        "continuation should reach exact review; route error: {continuation_error}"
    );
    let exact = pending(&state, "polymarket.onboard");
    assert_ne!(auth["approval_id"], exact["approval_id"]);
    let (exact_request, exact_context) = host
        .prepared_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(exact_context.route_id, exact_route);
    let approval_count = client.list_approvals(wallet.clone()).await.unwrap().len();
    for _ in 0..2 {
        vfs.write(&begin, b"begin").await.unwrap();
    }
    assert_eq!(
        client.list_approvals(wallet.clone()).await.unwrap().len(),
        approval_count
    );
    assert_eq!(
        pending(&state, "polymarket.onboard")["approval_id"],
        exact["approval_id"]
    );
    let mut changed = exact_request.clone();
    changed.action.payload.preimage.push(0);
    changed.action.payload.hash = bloom_petal_contract::prepared::SigningPayload::hash_for(
        changed.action.payload.suite,
        &changed.action.payload.preimage,
    );
    let conflict = machine
        .prepared_sign(changed, exact_context.clone())
        .await
        .unwrap_err();
    assert_eq!(
        conflict.code,
        bloom_petal_contract::prepared::ErrorCode::Conflict
    );
    for mutation in ["account", "route"] {
        let mut context = exact_context.clone();
        match mutation {
            "account" => {
                for (key, value) in &mut context.params {
                    if key == "bloom.account" {
                        *value = "0".into();
                    }
                }
            }
            "route" => context.route_id = "unenrolled-route".into(),
            _ => unreachable!(),
        }
        assert!(
            !matches!(
                machine.prepared_sign(exact_request.clone(), context).await,
                Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { .. })
            ),
            "{mutation} substitution must not sign"
        );
    }
    complete(exact["ceremony_url"].as_str().unwrap(), 5, None);
    // The fixture refuses venue submission after the real signature.
    let continuation_retry = vfs.write(&continuation, b"continue").await;
    {
        let signed = host.prepared_signed.lock().unwrap();
        assert_eq!(
            signed.len(),
            2,
            "approved continuation did not sign; route result: {continuation_retry:?}"
        );
        assert_eq!(signed[1].0.action.operation_class, "polymarket.onboard");
        assert_eq!(
            signed[1].0.action.payload.preimage,
            exact_request.action.payload.preimage
        );
        for (request, signature) in signed.iter() {
            let signature = alloy::primitives::Signature::from_raw(signature).unwrap();
            assert_eq!(
                signature
                    .recover_address_from_prehash(&alloy::primitives::B256::from(
                        request.action.payload.hash
                    ))
                    .unwrap(),
                owner
            );
        }
    }
    let cancelled_root = home.cache_dir().join("pm80-cancelled-prepared");
    let cancelled_host = DaemonPetalHost::new(machine.vfs.clone(), daemon.audit.clone())
        .with_broker(daemon.broker_client())
        .with_wallets(daemon.wallets.clone())
        .with_petal_runner(daemon.petals.clone())
        .with_provenance_catalog(machine.provenance_catalog.clone())
        .with_petal_signing_state_root(cancelled_root.clone());
    let mut cancelled_request = exact_request.clone();
    cancelled_request.operation_key.push_str(":cancel-test");
    let bloom_petal_contract::prepared::SigningOutcome::ApprovalPending { action_id, .. } =
        cancelled_host
            .prepared_sign(cancelled_request.clone(), exact_context.clone())
            .await
            .unwrap()
    else {
        panic!("fresh exact request must require owner approval");
    };
    let cancelled_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            cancelled_root
                .join(".state")
                .join(format!("{action_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let cancelled_operation: OperationId =
        serde_json::from_value(cancelled_state["approval_operation_id"].clone()).unwrap();
    client
        .cancel_ceremony(cancelled_operation.clone())
        .await
        .unwrap();
    assert_eq!(
        client
            .ceremony_status(cancelled_operation)
            .await
            .unwrap()
            .state,
        bloom_broker_api::CeremonyState::Cancelled
    );
    assert!(!matches!(
        cancelled_host
            .prepared_sign(cancelled_request, exact_context.clone())
            .await,
        Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { .. })
    ));
    // Unknown package can initiate a separate retained policy review; do this
    // last so it cannot interfere with exact continuation or cancellation.
    let mut wrong_context = exact_context.clone();
    wrong_context.package_hash = "99".repeat(32);
    assert!(!matches!(
        machine
            .prepared_sign(exact_request.clone(), wrong_context)
            .await,
        Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { .. })
    ));
    let result = serde_json::json!({"schema":"bloom.pm80.authorization-boundary.v1", "package_hash":hash,
        "auth_route":auth_route,"continuation_route":exact_route,"account":1,
        "owner_key_fingerprint":account_one.public_key_fingerprint,
        "verified_profiles_advertised":true,"auth_timestamp_refreshed":true,"auth_headers_validated":true,"auth_posts":1,"separate_exact_approval":true,
        "signed_operations":2,"changed_exact_payload_conflict":true,"cancelled_approval_cannot_sign":true,
        "limits":"disposable software owner; controlled venue/chain observations; no venue submission, funds or settlement"});
    std::fs::write(
        setting("BLOOM_PM80_AUTHORIZATION_RESULT"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

/// Compile the same single-member token budget used by persona onboarding.
/// This fixture deliberately scopes it to the installed route and account.
async fn activate_buy_permission(
    daemon: &Daemon,
    wallet: &Token,
    key_ref: bloom_broker_api::KeyRef,
    package_hash: &str,
    route: &str,
    provenance_digest: Digest32,
    counter: u64,
) -> bloom_machine_client::PersonaSessionStatus {
    use bloom_broker_api::*;
    use sha2::Digest as _;
    let client = daemon.broker_client().unwrap();
    let descriptor = client.wallet(wallet.clone()).await.unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let package = Digest32::new(package_hash.to_owned()).unwrap();
    let class = Token::new("polymarket.order.poly1271").unwrap();
    let asset = AssetId {
        chain: Token::new("evm-137").unwrap(),
        asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
    };
    let limits = ApprovalLimits {
        max_operations: DecimalU64::new(20),
        max_signatures: DecimalU64::new(20),
        operation_rate_limits: vec![SlidingWindow {
            duration_ms: DecimalU64::new(60_000),
            maximum: DecimalU64::new(20),
        }],
        signature_rate_limits: vec![SlidingWindow {
            duration_ms: DecimalU64::new(60_000),
            maximum: DecimalU64::new(20),
        }],
        value_limits: vec![],
    };
    let mut terms = SealedApprovalTerms {
        session_budget: None,
        subject: ApprovalSubject::Petal {
            package_hash: package.clone(),
            route: route.into(),
            agent_id: None,
        },
        wallet_id: wallet.clone(),
        key_ref: key_ref.clone(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        selector: ApprovalSelector::Petal {
            package_hash: package,
            route: route.into(),
            allowed_operation_classes: vec![class],
            route_grants: vec![],
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        },
        limits: limits.clone(),
        activation_mode: ActivationMode::DurableLocal {
            provider_tier: Token::new("local-passkey").unwrap(),
            maximum_rearm_until_ms: DecimalU64::new(u64::MAX),
        },
        wallet_revocation_epoch: descriptor.wallet_revocation_epoch.clone(),
        policy_version: descriptor.policy_version.clone(),
        policy_digest: descriptor.policy_digest.clone(),
        provenance_digest,
        request_nonce: RequestNonce::from_bytes([0x91; 16]),
        issued_at_ms: DecimalU64::new(now),
        not_before_ms: DecimalU64::new(now),
        expires_at_ms: DecimalU64::new(u64::MAX),
        renewal_of: None,
    };
    let scope = session_member_scope_digest(&terms).unwrap();
    let mut pool_limits = limits.clone();
    pool_limits.value_limits = vec![ValueLimit {
        asset: asset.clone(),
        lifetime: DecimalU256::parse("10000000").unwrap(),
        rolling_windows: vec![ValueWindow {
            maximum: DecimalU256::parse("10000000").unwrap(),
            duration_ms: DecimalU64::new(86_400_000),
        }],
    }];
    terms.session_budget = Some(SessionBudget {
        token_policy: Some(SessionTokenPolicy {
            schema_version: 3,
            budget_nonce: RequestNonce::from_bytes([0x92; 16]),
            member_scope_digests: vec![scope.clone()],
            member_templates: vec![terms.clone()],
            member_backstop_allocations: vec![SessionMemberAllocation {
                scope_digest: scope,
                limits,
            }],
            assets: vec![approved_session_asset(&asset).unwrap()],
        }),
        wallet_id: wallet.clone(),
        policy_version: descriptor.policy_version,
        policy_digest: descriptor.policy_digest,
        wallet_revocation_epoch: descriptor.wallet_revocation_epoch,
        member_keys: vec![key_ref],
        limits: pool_limits,
        per_action_value_limits: vec![SessionValueCeiling {
            asset,
            maximum: DecimalU256::parse("3000000").unwrap(),
        }],
        not_before_ms: DecimalU64::new(now),
        expires_at_ms: DecimalU64::new(u64::MAX),
    });
    terms.validate().unwrap();
    let id = terms.approval_id().unwrap();
    let op: [u8; 32] = sha2::Sha256::digest(
        [
            b"bloom.persona.prepare.v1\0".as_slice(),
            id.as_str().as_bytes(),
        ]
        .concat(),
    )
    .into();
    let facts = serde_json::json!({ "schema":"bloom.machine.persona-session-facts.v1", "persona":"trader", "account":1, "terms":&terms });
    let proposal = bloom_machine_client::PersonaSessionProposal {
        schema_version: 1,
        persona: "trader".into(),
        account: 1,
        prepare_operation_id: OperationId::from_bytes(op),
        terms,
        canonical_plan_facts_digest: Digest32::from_bytes(
            sha2::Sha256::digest(serde_jcs::to_vec(&facts).unwrap()).into(),
        ),
    };
    client
        .stage_persona_sessions(std::slice::from_ref(&proposal))
        .await
        .unwrap();
    let pending = client
        .prepare_persona_session(proposal.clone())
        .await
        .unwrap();
    complete(
        pending
            .authority
            .ceremony_url
            .as_deref()
            .expect("activation ceremony"),
        counter,
        None,
    );
    let active = client.prepare_persona_session(proposal).await.unwrap();
    assert_eq!(active.authority.state, ApprovalLifecycleState::Active);
    active
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable real services; run scripts/test-polymarket-authorization.sh with prepared-buy"]
async fn prepared_buy_uses_real_bounded_permission() {
    let phase = std::env::var("BLOOM_PM80_BUY_PHASE").unwrap_or_else(|_| "first".into());
    assert!(phase == "first" || phase == "restart");
    let AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet,
    } = if phase == "first" {
        account_one_fixture().await
    } else {
        existing_authorization_fixture().await
    };
    let account = client
        .wallet_accounts(wallet.clone())
        .await
        .unwrap()
        .accounts
        .into_iter()
        .find(|a| a.path == "m/44'/60'/0'/0/1")
        .unwrap();
    daemon
        .wallet_projections
        .get_wallet_authority(&wallet)
        .await
        .unwrap();
    let owner: Address = String::from_utf8(
        daemon
            .vfs
            .read(&VfsPath::parse("wallets/pm80-authorization/1/address.evm").unwrap())
            .await
            .unwrap(),
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap();
    let package =
        bloom_petals::package::build_petal_package_dir(setting("BLOOM_PM80_POLYMARKET_ROOT"))
            .unwrap();
    let hash = package.hash.clone();
    let route = package
        .route_index
        .routes
        .iter()
        .find(|r| r.pattern == "trade/[wallet]/[index]/drafts/[id]/post")
        .unwrap()
        .route_id
        .clone();
    let provenance = catalog
        .record(&bloom_broker_api::ProvenanceSubject::Petal {
            package_hash: Digest32::new(hash.clone()).unwrap(),
            route: route.clone(),
        })
        .unwrap()
        .digest()
        .unwrap();
    let grant_id = if phase == "first" {
        let staged = daemon.petals.store().stage_petal_package(package).unwrap();
        daemon
            .petals
            .install_staged_petal_package(staged, None, || Ok(()))
            .unwrap();
        approve_package(&daemon, &client, &wallet, &hash, 3, true).await;
        let grant = activate_buy_permission(
            &daemon,
            &wallet,
            account.key_ref,
            &hash,
            &route,
            provenance,
            4,
        )
        .await;
        let grant_id = grant.approval_id.clone();
        let store = bloom_petals::PrivateStore::open_account(
            daemon.petals.store().private_account_data_root(),
            wallet.as_str(),
            1,
        )
        .unwrap();
        store
            .put(
                &hash,
                "state/settings/pm80-authorization/venue.toml",
                b"enabled = true\n",
                false,
            )
            .unwrap();
        store
            .put(
                &hash,
                "secrets/creds/pm80-authorization/clob.json",
                include_bytes!("../../tests/fixtures/polymarket-credentials.json"),
                true,
            )
            .unwrap();
        let status = serde_json::json!({"wallet":wallet.as_str(), "owner":format!("{owner:#x}"), "stage":"complete", "tradeable":true, "creds_present":true, "deposit_wallet":{"address":"0x1111111111111111111111111111111111111111","source":"live_factory_resolved","fundable":true}});
        store
            .put(
                &hash,
                "state/onboard/pm80-authorization/status.json",
                &serde_json::to_vec(&status).unwrap(),
                false,
            )
            .unwrap();
        grant_id
    } else {
        let statuses = daemon.persona_sessions(wallet.as_str()).await.unwrap();
        assert_eq!(
            statuses.len(),
            1,
            "restart retains exactly the existing grant"
        );
        statuses[0].approval_id.clone()
    };
    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(daemon.vfs.clone()));
    let state = home.cache_dir().join("pm80-prepared-buy-signing");
    let machine = Arc::new(
        DaemonPetalHost::new(late, daemon.audit.clone())
            .with_broker(daemon.broker_client())
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(Some(catalog))
            .with_petal_signing_state_root(state),
    );
    let host = Arc::new(VenueFixture::new(machine, true));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host.clone())),
        )
        .build();
    if phase == "first" {
        let readiness = read_json(
            &vfs,
            "petals/polymarket/onboard/pm80-authorization/1/status.json",
        )
        .await;
        assert_eq!(
            readiness["stage"], "complete",
            "controlled observations must satisfy the normal onboarding gate"
        );
        assert_eq!(readiness["tradeable"], true);
        assert_eq!(readiness["probes"]["approvals_in_place"], true);
        assert_eq!(readiness["probes"]["clob_collateral_synced"], true);
        let approvals = client.list_approvals(wallet.clone()).await.unwrap().len();
        for id in ["0001", "0002"] {
            let new = VfsPath::parse("petals/polymarket/trade/pm80-authorization/1/new").unwrap();
            vfs.write(
            &new,
            br#"{"slug":"test","outcome":"YES","amount":"1","side":"buy","limit_price":"0.50"}"#,
        )
        .await
        .unwrap();
            let base = format!("petals/polymarket/trade/pm80-authorization/1/drafts/{id}");
            vfs.write(
                &VfsPath::parse(&format!("{base}/revalidate")).unwrap(),
                br#"{"revalidate":true}"#,
            )
            .await
            .unwrap();
            let post = VfsPath::parse(&format!("{base}/post")).unwrap();
            let _ = vfs
                .write(&post, br#"{"post":true,"acknowledge_warnings":true}"#)
                .await;
            let _ = vfs
                .write(&post, br#"{"post":true,"acknowledge_warnings":true}"#)
                .await;
        }
        let signatures = {
            let signed = host.prepared_signed.lock().unwrap();
            assert_eq!(
                signed.len(),
                2,
                "two distinct orders signed once each before blocked venue submission"
            );
            for (request, sig) in signed.iter() {
                assert_eq!(request.action.operation_class, "polymarket.order.poly1271");
                let recovered = alloy::primitives::Signature::from_raw(sig)
                    .unwrap()
                    .recover_address_from_prehash(&alloy::primitives::B256::from(
                        request.action.payload.hash,
                    ))
                    .unwrap();
                assert_eq!(recovered, owner);
            }
            assert_ne!(signed[0].0.operation_key, signed[1].0.operation_key);
            signed
                .iter()
                .map(|(_, signature)| signature.clone())
                .collect::<Vec<_>>()
        };
        let requests = host.prepared_requests.lock().unwrap().clone();
        let mut unique = Vec::new();
        for (request, context) in requests {
            if !unique.iter().any(
                |(existing, _): &(bloom_petal_contract::prepared::Request, PetalRouteContext)| {
                    existing.operation_key == request.operation_key
                },
            ) {
                unique.push((request, context));
            }
        }
        assert_eq!(unique.len(), 2);
        for ((request, context), signature) in
            unique.iter().cloned().zip(signatures.iter().cloned())
        {
            let result = host.machine.prepared_sign(request, context).await.unwrap();
            assert_eq!(
                result,
                bloom_petal_contract::prepared::SigningOutcome::Signed { signature }
            );
        }
        // Simulate a crash after Broker persisted the signature but before
        // Machine persisted its outer result. Preserve the frozen action and
        // all lower-level records and retry the identical operation.
        let (crash_request, crash_context) = &unique[0];
        let prepared_root = home
            .cache_dir()
            .join("pm80-prepared-buy-signing")
            .join(".prepared");
        let mut matching = Vec::new();
        for entry in std::fs::read_dir(prepared_root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if record["operation_key"] == crash_request.operation_key {
                matching.push((path, record));
            }
        }
        assert_eq!(matching.len(), 1, "one frozen prepared operation");
        let (path, mut record) = matching.pop().unwrap();
        assert_eq!(record["outcome"]["state"], "signed");
        record["outcome"] = serde_json::Value::Null;
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        let recovered = host
            .machine
            .prepared_sign(crash_request.clone(), crash_context.clone())
            .await
            .unwrap();
        assert_eq!(
            recovered,
            bloom_petal_contract::prepared::SigningOutcome::Signed {
                signature: signatures[0].clone()
            },
            "crash recovery must return the original signature"
        );
        assert_eq!(
            client.list_approvals(wallet.clone()).await.unwrap().len(),
            approvals,
            "covered orders must not create ceremonies"
        );
    }
    let statuses = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let status = statuses.iter().find(|s| s.approval_id == grant_id).unwrap();
    let usage = status
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    assert_eq!(usage.operations.get(), 2);
    assert_eq!(usage.signatures.get(), 2);
    assert_eq!(usage.asset_usage.len(), 1);
    assert_eq!(usage.asset_usage[0].amount.as_str(), "2000000");
    if phase == "first" {
        use bloom_petal_contract::prepared::{SigningOutcome, Spend};
        let (original, context) = host.prepared_requests.lock().unwrap()[0].clone();
        for kind in [
            "sell_declaration",
            "wrong_asset",
            "amount_mismatch",
            "witness_mismatch",
            "wrong_account",
            "wrong_route",
            "credential_class",
            "onboarding_class",
        ] {
            let mut request = original.clone();
            request.operation_key = format!("acceptance-negative-{kind}");
            let mut trusted = context.clone();
            match kind {
                "sell_declaration" => {
                    request.action.spend = Spend::erc1155(
                        "evm-137",
                        "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
                        "42",
                        "1000000",
                    )
                    .unwrap()
                }
                "wrong_asset" => {
                    request.action.spend = Spend::erc20(
                        "evm-137",
                        "0x1111111111111111111111111111111111111111",
                        "1000000",
                    )
                    .unwrap()
                }
                "amount_mismatch" => {
                    request.action.spend =
                        Spend::erc20("evm-137", "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb", "1")
                            .unwrap()
                }
                "witness_mismatch" => request.action.review.bytes = b"[]".to_vec(),
                "wrong_account" => {
                    for (key, value) in &mut trusted.params {
                        if key == "bloom.account" {
                            *value = "0".into();
                        }
                    }
                }
                "wrong_route" => trusted.route_id = "unenrolled-route".into(),
                "credential_class" => {
                    request.action.operation_class = "polymarket.clob_auth.v1".into()
                }
                "onboarding_class" => request.action.operation_class = "polymarket.onboard".into(),
                _ => unreachable!(),
            }
            let negative_host =
                DaemonPetalHost::new(host.machine.vfs.clone(), daemon.audit.clone())
                    .with_broker(daemon.broker_client())
                    .with_wallets(daemon.wallets.clone())
                    .with_petal_runner(daemon.petals.clone())
                    .with_provenance_catalog(host.machine.provenance_catalog.clone())
                    .with_petal_signing_state_root(
                        home.cache_dir().join(format!("pm80-negative-{kind}")),
                    );
            let outcome = negative_host.prepared_sign(request, trusted).await;
            assert!(
                !matches!(&outcome, Ok(SigningOutcome::Signed { .. })),
                "negative case {kind} cannot sign using BUY permission"
            );
            if matches!(kind, "amount_mismatch" | "witness_mismatch") {
                assert!(
                    outcome.is_err(),
                    "{kind} must be refused, not offered as a valid operation"
                );
            }
        }
        let statuses = daemon.persona_sessions(wallet.as_str()).await.unwrap();
        let after_negatives = statuses
            .iter()
            .find(|s| s.approval_id == grant_id)
            .unwrap()
            .usage
            .as_ref()
            .unwrap()
            .session_budget_state
            .as_ref()
            .unwrap();
        assert_eq!(after_negatives.operations.get(), 2);
        assert_eq!(after_negatives.asset_usage[0].amount.as_str(), "2000000");
        std::fs::write(setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension("first.json"), serde_json::to_vec_pretty(&serde_json::json!({"schema":"bloom.prepared-buy.acceptance.v1", "phase":"before_restart", "package_hash":hash, "approval_id":grant_id, "account":1, "recovered_owner":format!("{owner:#x}"), "covered_operations":2, "usage_raw_pusd":"2000000", "stable_retries":true, "crash_recovered_same_signature_and_no_charge":true, "negative_cases_no_sign":true})).unwrap()).unwrap();
        return;
    }

    let rearmed = daemon
        .broker_client()
        .unwrap()
        .rearm_persona_session(
            &wallet,
            Some(&grant_id),
            OperationId::from_bytes([0x93; 32]),
        )
        .await
        .unwrap();
    complete(
        rearmed
            .authority
            .ceremony_url
            .as_deref()
            .expect("rearm ceremony"),
        5,
        None,
    );
    let before = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let before = before
        .iter()
        .find(|s| s.approval_id == grant_id)
        .unwrap()
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    assert_eq!(
        before.operations.get(),
        2,
        "rearm must preserve prior usage"
    );
    let restarted = Arc::new(
        DaemonPetalHost::new(host.machine.vfs.clone(), daemon.audit.clone())
            .with_broker(daemon.broker_client())
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(host.machine.provenance_catalog.clone())
            .with_petal_signing_state_root(home.cache_dir().join("pm80-prepared-buy-signing")),
    );
    let host2 = Arc::new(VenueFixture::new(restarted, true));
    let vfs2 = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host2.clone())),
        )
        .build();
    let new = VfsPath::parse("petals/polymarket/trade/pm80-authorization/1/new").unwrap();
    vfs2.write(
        &new,
        br#"{"slug":"test","outcome":"YES","amount":"1","side":"buy","limit_price":"0.50"}"#,
    )
    .await
    .unwrap();
    let base = "petals/polymarket/trade/pm80-authorization/1/drafts/0003";
    vfs2.write(
        &VfsPath::parse(&format!("{base}/revalidate")).unwrap(),
        br#"{"revalidate":true}"#,
    )
    .await
    .unwrap();
    let _ = vfs2
        .write(
            &VfsPath::parse(&format!("{base}/post")).unwrap(),
            br#"{"post":true,"acknowledge_warnings":true}"#,
        )
        .await;
    {
        let signed = host2.prepared_signed.lock().unwrap();
        assert_eq!(signed.len(), 1, "rearmed host must sign covered order");
        let (request, signature) = &signed[0];
        let recovered = alloy::primitives::Signature::from_raw(signature)
            .unwrap()
            .recover_address_from_prehash(&alloy::primitives::B256::from(
                request.action.payload.hash,
            ))
            .unwrap();
        assert_eq!(recovered, owner);
    }
    let after = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let after = after
        .iter()
        .find(|s| s.approval_id == grant_id)
        .unwrap()
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    assert_eq!(after.operations.get(), 3);
    assert_eq!(after.asset_usage[0].amount.as_str(), "3000000");

    // This is a real SELL produced by the built Polymarket component. CTF
    // balance and approvals are controlled observations, not live funds.
    vfs2.write(
        &new,
        br#"{"slug":"test","outcome":"YES","amount":"1","side":"sell","limit_price":"0.50"}"#,
    )
    .await
    .unwrap();
    let sell = "petals/polymarket/trade/pm80-authorization/1/drafts/0004";
    vfs2.write(
        &VfsPath::parse(&format!("{sell}/revalidate")).unwrap(),
        br#"{"revalidate":true}"#,
    )
    .await
    .unwrap();
    let sell_post_error = vfs2
        .write(
            &VfsPath::parse(&format!("{sell}/post")).unwrap(),
            br#"{"post":true,"acknowledge_warnings":true}"#,
        )
        .await
        .expect_err("SELL must await review, not submit");
    let sell_request = host2
        .prepared_requests
        .lock()
        .unwrap()
        .iter()
        .find(|(request, _)| request.operation_key.contains("drafts/0004/"))
        .map(|(request, _)| request.clone())
        .unwrap_or_else(|| {
            panic!("SELL must reach prepared signing; post error: {sell_post_error}")
        });
    match &sell_request.action.spend {
        bloom_petal_contract::prepared::Spend::Bounded { debits } => {
            assert_eq!(debits.len(), 1);
            assert_eq!(debits[0].network, "evm-137");
            assert_eq!(debits[0].amount, "1000000");
            assert!(
                matches!(&debits[0].asset, bloom_petal_contract::prepared::Asset::Erc1155 { token_id, .. } if token_id == "42")
            );
        }
        _ => panic!("SELL must declare its share debit"),
    }
    let sell_outcome = host2
        .prepared_outcomes
        .lock()
        .unwrap()
        .iter()
        .find(|(key, _)| *key == sell_request.operation_key)
        .map(|(_, outcome)| outcome.clone())
        .expect("SELL host outcome");
    let sell_action_id = match sell_outcome {
        Ok(bloom_petal_contract::prepared::SigningOutcome::ApprovalPending {
            action_id, ..
        }) => action_id,
        Err(error) => panic!("SELL requires separate exact review: {error}"),
        Ok(_) => panic!("SELL requires separate exact review"),
    };
    assert_eq!(
        host2.prepared_signed.lock().unwrap().len(),
        1,
        "SELL must not sign using BUY permission"
    );
    let statuses = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let after_sell = statuses
        .iter()
        .find(|s| s.approval_id == grant_id)
        .unwrap()
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    assert_eq!(after_sell.operations.get(), 3);
    assert_eq!(after_sell.asset_usage[0].amount.as_str(), "3000000");
    // The Broker permits one live ceremony per wallet. Cancel this separate
    // SELL review before exercising the over-limit BUY review below.
    let sell_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            home.cache_dir()
                .join("pm80-prepared-buy-signing")
                .join(".state")
                .join(format!("{sell_action_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let sell_operation: OperationId =
        serde_json::from_value(sell_state["approval_operation_id"].clone()).unwrap();
    client
        .cancel_ceremony(sell_operation.clone())
        .await
        .unwrap();
    assert_eq!(
        client.ceremony_status(sell_operation).await.unwrap().state,
        bloom_broker_api::CeremonyState::Cancelled
    );
    // Broker applies a short cancellation backoff before another ceremony.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    vfs2.write(
        &new,
        br#"{"slug":"test","outcome":"YES","amount":"4","side":"buy","limit_price":"0.50"}"#,
    )
    .await
    .unwrap();
    let over = "petals/polymarket/trade/pm80-authorization/1/drafts/0005";
    vfs2.write(
        &VfsPath::parse(&format!("{over}/revalidate")).unwrap(),
        br#"{"revalidate":true}"#,
    )
    .await
    .unwrap();
    assert!(
        vfs2.write(
            &VfsPath::parse(&format!("{over}/post")).unwrap(),
            br#"{"post":true,"acknowledge_warnings":true}"#
        )
        .await
        .is_err()
    );
    assert_eq!(
        host2.prepared_signed.lock().unwrap().len(),
        1,
        "over-limit order must not sign"
    );
    let over_outcome = host2
        .prepared_outcomes
        .lock()
        .unwrap()
        .iter()
        .find(|(key, _)| key.contains("drafts/0005/"))
        .map(|(_, outcome)| outcome.clone())
        .expect("over-limit BUY must reach signing");
    let action_id = match over_outcome {
        Ok(bloom_petal_contract::prepared::SigningOutcome::ApprovalPending {
            action_id, ..
        }) => action_id,
        other => panic!("over-limit BUY requires separate exact review; got {other:?}"),
    };
    let (over_request, over_context) = host2
        .prepared_requests
        .lock()
        .unwrap()
        .iter()
        .find(|(request, _)| request.operation_key.contains("drafts/0005/"))
        .cloned()
        .expect("over-limit prepared request");
    let exact_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            home.cache_dir()
                .join("pm80-prepared-buy-signing")
                .join(".state")
                .join(format!("{action_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let cancel_operation: OperationId =
        serde_json::from_value(exact_state["approval_operation_id"].clone()).unwrap();
    client
        .cancel_ceremony(cancel_operation.clone())
        .await
        .unwrap();
    assert_eq!(
        client
            .ceremony_status(cancel_operation)
            .await
            .unwrap()
            .state,
        bloom_broker_api::CeremonyState::Cancelled
    );
    let status_request = bloom_petal_contract::prepared::StatusRequest {
        version: bloom_petal_contract::prepared::VERSION,
        wallet: over_request.wallet.clone(),
        operation_key: over_request.operation_key.clone(),
    };
    let status_error = host2
        .machine
        .prepared_sign_status(status_request, over_context.clone())
        .await
        .unwrap_err();
    assert_eq!(
        status_error.code,
        bloom_petal_contract::prepared::ErrorCode::Cancelled,
        "status must expose terminal cancellation"
    );
    let retry_error = host2
        .machine
        .prepared_sign(over_request, over_context)
        .await
        .unwrap_err();
    assert_eq!(
        retry_error.code,
        bloom_petal_contract::prepared::ErrorCode::Cancelled,
        "retry cannot renew or replace cancelled approval"
    );
    assert_eq!(host2.prepared_signed.lock().unwrap().len(), 1);
    let statuses = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let after_cancel = statuses
        .iter()
        .find(|s| s.approval_id == grant_id)
        .unwrap()
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    assert_eq!(after_cancel.operations.get(), 3);
    assert_eq!(after_cancel.asset_usage[0].amount.as_str(), "3000000");
    // Unknown package can create a separate policy proposal, so perform this
    // last to avoid influencing subsequent signing attempts in the fixture.
    let (mut wrong_package, mut context) = host2.prepared_requests.lock().unwrap()[0].clone();
    wrong_package.operation_key = "acceptance-negative-wrong-package".into();
    context.package_hash = "99".repeat(32);
    assert!(!matches!(
        host2.machine.prepared_sign(wrong_package, context).await,
        Ok(bloom_petal_contract::prepared::SigningOutcome::Signed { .. })
    ));
    std::fs::write(setting("BLOOM_PM80_AUTHORIZATION_RESULT"), serde_json::to_vec_pretty(&serde_json::json!({"schema":"bloom.prepared-buy.acceptance.v1", "phase":"after_restart", "package_hash":hash, "approval_id":grant_id, "account":1, "recovered_owner":format!("{owner:#x}"), "covered_operations":3, "usage_raw_pusd":"3000000", "prior_usage_retained_after_restart_and_rearm":true, "sell_separate_review":true, "over_limit_separate_review":true, "cancelled_over_limit_retry_and_status_refused":true, "scope":"disposable owner; controlled venue and chain observations; no venue submission or funds"})).unwrap()).unwrap();
}
