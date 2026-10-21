//! Real installer/Daemon host/Broker/Signer acceptance. Only venue and chain
//! observations are controlled; signing always delegates to DaemonPetalHost.
use super::*;
use bloom_broker_api::{CustodyPrepareRequest, Digest32, OperationId, Token};
use bloom_vfs::{Handler, VfsPath};
use std::sync::{Mutex, atomic::AtomicU64};

struct VenueFixture {
    machine: Arc<DaemonPetalHost>,
    timestamp: AtomicU64,
    requests: Mutex<Vec<PayloadBatchSignRequest>>,
    signed: Mutex<Vec<(PayloadBatchSignRequest, Vec<Vec<u8>>)>>,
    auth_posts: AtomicU64,
    single_requests: Mutex<Vec<PayloadSignRequest>>,
    single_signed: Mutex<Vec<(PayloadSignRequest, Vec<u8>)>>,
}

impl VenueFixture {
    fn new(machine: Arc<DaemonPetalHost>) -> Self {
        Self {
            machine,
            timestamp: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            requests: Mutex::new(vec![]),
            signed: Mutex::new(vec![]),
            auth_posts: AtomicU64::new(0),
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
            let signed = self.signed.lock().unwrap();
            assert_eq!(
                signed.len(),
                1,
                "credentials require a real completed signature"
            );
            let (authorization, signatures) = &signed[0];
            assert_eq!(authorization.payloads.len(), 1);
            assert_eq!(signatures.len(), 1);
            let signature = alloy::primitives::Signature::from_raw(&signatures[0]).unwrap();
            let owner = signature
                .recover_address_from_prehash(&alloy::primitives::B256::from(
                    authorization.payloads[0].claimed_hash,
                ))
                .unwrap();
            let prepared: serde_json::Value = serde_json::from_slice(
                authorization
                    .action
                    .as_ref()
                    .expect("auth keeps its prepared record"),
            )
            .unwrap();
            let prepared = &prepared[0];
            assert_eq!(
                prepared["preimage"]["timestamp"].as_u64(),
                Some(self.timestamp.load(Ordering::SeqCst))
            );
            assert_eq!(prepared["preimage"]["nonce"].as_u64(), Some(0));
            assert!(
                prepared["owner"]
                    .as_str()
                    .unwrap()
                    .parse::<alloy::primitives::Address>()
                    .unwrap()
                    == owner
            );
            assert!(
                prepared["signing_preimage_hex"].as_str().unwrap()
                    == hex::encode(&authorization.payloads[0].preimage)
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
            assert!(header("POLY_SIGNATURE") == format!("0x{}", hex::encode(&signatures[0])));
            self.auth_posts.fetch_add(1, Ordering::SeqCst);
            include_bytes!("../../tests/fixtures/polymarket-credentials.json").to_vec()
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
                let word = match &data[..10] {
                    "0x5c60da1b" | "0x1f264778" => 3u64,
                    "0x70a08231" => 100,
                    "0xdd62ed3e" | "0xe985e9c5" => 0,
                    _ => {
                        return Err(HostError::Denied(
                            "unexpected fixture chain selector".into(),
                        ));
                    }
                };
                format!("0x{word:064x}")
            }
            _ => return Err(HostError::Denied("unexpected fixture chain method".into())),
        };
        Ok(ChainResponse {
            result_json: serde_json::to_string(&value).unwrap(),
        })
    }
    async fn sign_payload_batch_outcome(
        &self,
        request: PayloadBatchSignRequest,
    ) -> Result<PayloadBatchSignOutcome, HostError> {
        self.requests.lock().unwrap().push(request.clone());
        let result = self
            .machine
            .sign_payload_batch_outcome(request.clone())
            .await;
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

async fn approve_package(
    daemon: &Daemon,
    client: &MachineBrokerClient,
    wallet: &Token,
    hash: &str,
    counter: u64,
) {
    let baseline = client.policy(wallet.clone()).await.unwrap();
    let mut policy: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(&baseline.canonical_policy.decode()).unwrap();
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
#[ignore = "requires built SDK conformance package and disposable services; use sdk-message runner case"]
async fn installed_supported_messages_use_real_installer_and_selected_account() {
    let AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet,
    } = account_one_fixture().await;
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
    for format in ["personal", "typed"] {
        let route = package
            .route_index
            .routes
            .iter()
            .find(|r| r.pattern == format!("{format}/[wallet]/[index]/sign"))
            .unwrap();
        let record = catalog
            .record(&bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: Digest32::new(hash.clone()).unwrap(),
                route: route.route_id.clone(),
            })
            .unwrap();
        assert!(
            record
                .operation_classes
                .iter()
                .any(|c| c.operation_class.as_str() == format!("conformance.{format}"))
        );
        assert!(!record.installer_signature.decode().is_empty());
        assert!(record.petal_lineage.as_ref().unwrap().active);
    }
    let staged = daemon.petals.store().stage_petal_package(package).unwrap();
    daemon
        .petals
        .install_staged_petal_package(staged, None, || Ok(()))
        .unwrap();
    approve_package(&daemon, &client, &wallet, &hash, 3).await;
    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(daemon.vfs.clone()));
    let state = home.cache_dir().join("petal-signing-requests");
    let machine = Arc::new(
        DaemonPetalHost::new(late, daemon.audit.clone())
            .with_broker(Some(client.clone()))
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(Some(catalog))
            .with_petal_signing_state_root(state.clone()),
    );
    let host = Arc::new(VenueFixture::new(machine.clone()));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host.clone())),
        )
        .build();
    for (position, format) in ["personal", "typed"].into_iter().enumerate() {
        let class = format!("conformance.{format}");
        let path = VfsPath::parse(&format!(
            "petals/conformance/{format}/pm80-authorization/1/sign"
        ))
        .unwrap();
        let calls = host.single_requests.lock().unwrap().len();
        assert!(vfs.write(&path, b"arbitrary message").await.is_err());
        assert_eq!(host.single_requests.lock().unwrap().len(), calls);
        vfs.write(&path, b"sign").await.unwrap();
        assert_eq!(host.single_signed.lock().unwrap().len(), position);
        let awaiting = pending(&state, &class);
        let projection_path = format!(
            "petal-signing-requests/{}.json",
            awaiting["request_id"].as_str().unwrap()
        );
        let projected = read_json(&daemon.vfs, &projection_path).await;
        assert_eq!(projected["status"], "awaiting_owner_approval");
        vfs.write(&path, b"sign").await.unwrap();
        let repeated = pending(&state, &class);
        assert!(awaiting["approval_id"] == repeated["approval_id"]);
        assert_eq!(host.single_signed.lock().unwrap().len(), position);
        complete(
            projected["ceremony_url"].as_str().unwrap(),
            4 + position as u64,
            None,
        );
        let mut changed = host.single_requests.lock().unwrap().last().unwrap().clone();
        changed.approval_hint = None;
        changed.operation_class = "conformance.forbidden".into();
        let mut claim: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&changed.petal_use_claim_jcs).unwrap();
        claim.operation_class = Token::new(&changed.operation_class).unwrap();
        changed.petal_use_claim_jcs = serde_jcs::to_vec(&claim).unwrap();
        match machine.sign_payload_outcome(changed).await {
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("installer provenance does not authorize conformance.forbidden"),
                "class substitution must reach installer authorization: {error}"
            ),
            Ok(_) => panic!("installer must reject a class absent from its signed catalog"),
        }
        vfs.write(&path, b"sign").await.unwrap();
        assert_eq!(host.single_signed.lock().unwrap().len(), position + 1);
        let signed = host.single_signed.lock().unwrap();
        let (request, bytes) = signed.last().unwrap();
        assert_eq!(
            request
                .context
                .as_ref()
                .unwrap()
                .trusted_account()
                .unwrap()
                .number,
            1
        );
        assert_eq!(request.operation_class, class);
        assert_eq!(
            request.signature_algorithm,
            "secp256k1-keccak256-recoverable"
        );
        assert_eq!(bytes.len(), 65);
        assert_eq!(
            alloy::primitives::Signature::from_raw(bytes)
                .unwrap()
                .recover_address_from_prehash(&alloy::primitives::B256::from(request.claimed_hash))
                .unwrap(),
            owner
        );
        drop(signed);
        assert_eq!(
            read_json(&daemon.vfs, &projection_path).await["status"],
            "signed"
        );
    }
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 0);
    let result = serde_json::json!({"schema":"bloom.sdk.authorization-boundary.v1",
        "package_hash":hash,"account":1,"formats":["personal","typed"],
        "authorized_in_test":true,"signed_operations":2,"installer_class_denials_without_hint":2,
        "normal_owner_projection":true,"retry_identity_preserved":true,
        "limits":"disposable software owner; no chain submission, funds, settlement or physical ceremony"});
    std::fs::write(
        setting("BLOOM_PM80_AUTHORIZATION_RESULT"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
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
    let accounts = client.wallet_accounts(wallet.clone()).await.unwrap();
    let account_one = accounts
        .accounts
        .iter()
        .find(|a| a.path == "m/44'/60'/0'/0/1")
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
    approve_package(&daemon, &client, &wallet, &hash, 3).await;

    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(daemon.vfs.clone()));
    let state = home.cache_dir().join("pm80-signing-requests");
    let machine = Arc::new(
        DaemonPetalHost::new(late, daemon.audit.clone())
            .with_broker(Some(client.clone()))
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(Some(catalog))
            .with_petal_signing_state_root(state.clone()),
    );
    let host = Arc::new(VenueFixture::new(machine.clone()));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host.clone())),
        )
        .build();
    let begin = VfsPath::parse("petals/polymarket/onboard/pm80-authorization/1/begin").unwrap();
    let begin_error = vfs.write(&begin, b"begin").await.unwrap_err();
    assert!(
        !host.requests.lock().unwrap().is_empty(),
        "begin failed before calling the signing host: {begin_error}"
    );
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 0);
    let auth = pending(&state, "polymarket.clob_auth.v1");
    let first = host.requests.lock().unwrap()[0].clone();
    assert_eq!(first.context.as_ref().unwrap().route_id, auth_route);
    assert_eq!(
        first
            .context
            .as_ref()
            .unwrap()
            .trusted_account()
            .unwrap()
            .number,
        1
    );
    complete(auth["ceremony_url"].as_str().unwrap(), 4, None);
    host.timestamp.fetch_add(2, Ordering::SeqCst);
    vfs.write(&begin, b"begin").await.unwrap();
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 1);
    {
        let signed = host.signed.lock().unwrap();
        assert_eq!(signed.len(), 1);
        assert_ne!(
            signed[0].0.payloads[0].preimage, first.payloads[0].preimage,
            "server timestamp refreshed under one-use auth profile"
        );
        assert_eq!(signed[0].1[0].len(), 65);
    }
    let continuation =
        VfsPath::parse("petals/polymarket/onboard/pm80-authorization/1/continue").unwrap();
    assert!(vfs.write(&continuation, b"continue").await.is_err());
    let exact = pending(&state, "polymarket.onboard");
    assert_ne!(auth["approval_id"], exact["approval_id"]);
    let exact_request = host.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        exact_request.context.as_ref().unwrap().route_id,
        exact_route
    );
    assert_eq!(
        exact_request.selector,
        bloom_broker_api::PetalSignSelector::Exact
    );
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

    // These hinted substitutions test pending-request identity, not installer
    // authorization or an upgrade from a real predecessor package.
    for mutation in ["account", "class", "route", "batch"] {
        let mut changed = exact_request.clone();
        changed.approval_hint = Some(exact["request_id"].as_str().unwrap().to_owned());
        let mut claim: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&changed.petal_use_claim_jcs).unwrap();
        let context = changed.context.as_mut().unwrap();
        match mutation {
            "account" => {
                for (key, value) in &mut context.params {
                    if key == "bloom.account" {
                        *value = "0".into();
                    }
                }
            }
            "class" => {
                changed.operation_class = "polymarket.clob_auth.v1".into();
                claim.operation_class = Token::new(&changed.operation_class).unwrap();
            }
            "route" => {
                context.route_id = "old-route".into();
                claim.route = context.route_id.clone();
            }
            "batch" => {
                changed.payloads[0].preimage[0] ^= 1;
                changed.payloads[0].claimed_hash =
                    alloy::primitives::keccak256(&changed.payloads[0].preimage).into();
                claim.ordered_hashes = changed
                    .payloads
                    .iter()
                    .map(|p| Digest32::from_bytes(p.claimed_hash))
                    .collect();
                let mut digest = sha2::Sha256::new();
                digest.update(b"bloom.petal.payload-batch.v1\0");
                digest.update((changed.payloads.len() as u64).to_be_bytes());
                for payload in &changed.payloads {
                    digest.update((payload.preimage.len() as u64).to_be_bytes());
                    digest.update(&payload.preimage);
                }
                claim.payload_digest = Digest32::from_bytes(digest.finalize().into());
            }
            _ => unreachable!(),
        }
        changed.petal_use_claim_jcs = serde_jcs::to_vec(&claim).unwrap();
        assert!(
            machine.sign_payload_batch_outcome(changed).await.is_err(),
            "{mutation} substitution must fail"
        );
    }
    complete(exact["ceremony_url"].as_str().unwrap(), 5, None);
    // With the exact grant approved and unconsumed, bypass the hint guard and
    // require the installer-specific denial. A generic error is insufficient.
    for mutation in ["class", "route"] {
        let mut changed = exact_request.clone();
        changed.approval_hint = None;
        let mut claim: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&changed.petal_use_claim_jcs).unwrap();
        if mutation == "class" {
            changed.operation_class = "polymarket.unauthorized.v1".into();
            claim.operation_class = Token::new(&changed.operation_class).unwrap();
        } else {
            changed.context.as_mut().unwrap().route_id = "unenrolled-route".into();
            claim.route = "unenrolled-route".into();
        }
        changed.petal_use_claim_jcs = serde_jcs::to_vec(&claim).unwrap();
        let expected = format!(
            "installer provenance does not authorize {}",
            changed.operation_class
        );
        let error = machine
            .sign_payload_batch_outcome(changed)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(&expected),
            "{mutation} must reach installer authorization: {error}"
        );
    }
    // The fixture refuses the subsequent venue submission, after the actual
    // exact batch signature has traversed Broker and Signer successfully.
    let _ = vfs.write(&continuation, b"continue").await;
    let cancelled_root = home.cache_dir().join("pm80-cancelled-signing");
    let cancelled_host = DaemonPetalHost::new(machine.vfs.clone(), daemon.audit.clone())
        .with_broker(Some(client.clone()))
        .with_wallets(daemon.wallets.clone())
        .with_petal_runner(daemon.petals.clone())
        .with_provenance_catalog(machine.provenance_catalog.clone())
        .with_petal_signing_state_root(cancelled_root.clone());
    let cancelled_request = exact_request.clone();
    let PayloadBatchSignOutcome::ApprovalPending(cancelled) = cancelled_host
        .sign_payload_batch_outcome(cancelled_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh exact request must require its own owner approval");
    };
    let cancelled_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            cancelled_root
                .join(".state")
                .join(format!("{}.json", cancelled.action_id)),
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
    assert!(
        !matches!(
            cancelled_host
                .sign_payload_batch_outcome(cancelled_request)
                .await,
            Ok(PayloadBatchSignOutcome::Signatures(_))
        ),
        "cancelled owner approval cannot sign"
    );
    // Unknown packages can initiate separate policy consent before installer
    // authorization. Do this last: a retained policy proposal intentionally
    // takes precedence over unrelated signing attempts on the same wallet.
    let mut unknown_package = exact_request.clone();
    unknown_package.approval_hint = None;
    unknown_package.context.as_mut().unwrap().package_hash = "99".repeat(32);
    let mut claim: bloom_broker_api::PetalUseClaim =
        serde_json::from_slice(&unknown_package.petal_use_claim_jcs).unwrap();
    claim.package_hash = Digest32::new("99".repeat(32)).unwrap();
    unknown_package.petal_use_claim_jcs = serde_jcs::to_vec(&claim).unwrap();
    assert!(
        !matches!(
            machine.sign_payload_batch_outcome(unknown_package).await,
            Ok(PayloadBatchSignOutcome::Signatures(_))
        ),
        "an unknown package cannot use the approved grant"
    );
    let signed = host.signed.lock().unwrap();
    assert_eq!(signed.len(), 2);
    assert_eq!(signed[1].0.operation_class, "polymarket.onboard");
    assert_eq!(
        signed[1].0.payloads[0].preimage,
        exact_request.payloads[0].preimage
    );
    assert_eq!(signed[1].1[0].len(), 65);
    for (request, signatures) in signed.iter() {
        assert_eq!(
            request.payloads.len(),
            signatures.len(),
            "every requested payload must have exactly one signature"
        );
        assert_eq!(
            request.signature_algorithm,
            "secp256k1-keccak256-recoverable"
        );
        for (payload, signature) in request.payloads.iter().zip(signatures) {
            let signature = alloy::primitives::Signature::from_raw(signature).unwrap();
            assert_eq!(
                signature
                    .recover_address_from_prehash(&alloy::primitives::B256::from(
                        payload.claimed_hash
                    ))
                    .unwrap(),
                owner,
                "real signatures must recover the selected account-1 owner"
            );
        }
    }
    let result = serde_json::json!({"schema":"bloom.pm80.authorization-boundary.v1", "package_hash":hash,
        "auth_route":auth_route,"continuation_route":exact_route,"account":1,
        "owner_key_fingerprint":account_one.public_key_fingerprint,
        "auth_timestamp_refreshed":true,"auth_headers_validated":true,"auth_posts":1,"separate_exact_approval":true,
        "signed_operations":2,"hint_substitutions":["account","class","route","batch"],
        "installer_denials_without_hint":["class","route"],"unknown_package_cannot_sign":true,
        "cancelled_approval_cannot_sign":true,
        "limits":"disposable software owner; controlled venue/chain observations; no venue submission, funds or settlement"});
    std::fs::write(
        setting("BLOOM_PM80_AUTHORIZATION_RESULT"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}
