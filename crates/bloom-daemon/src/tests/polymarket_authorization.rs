//! Real installer/Daemon host/Broker/Signer acceptance. Only venue and chain
//! observations are controlled; signing always delegates to DaemonPetalHost.
use super::*;
use bloom_broker_api::{CustodyPrepareRequest, Digest32, OperationId, Token};
use bloom_vfs::{Handler, VfsPath};
use std::sync::{Mutex, atomic::AtomicU64};

#[path = "gasless_authorization.rs"]
mod gasless_authorization;

struct VenueFixture {
    machine: Arc<DaemonPetalHost>,
    trading_ready: bool,
    timestamp: AtomicU64,
    requests: Mutex<Vec<PayloadBatchSignRequest>>,
    signed: Mutex<Vec<(PayloadBatchSignRequest, Vec<Vec<u8>>)>>,
    auth_posts: AtomicU64,
    relay_submissions: AtomicU64,
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
            relay_submissions: AtomicU64::new(0),
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
        let body = if request.url == "https://api.relay.link/quote/v2" && request.method == "POST" {
            gasless_authorization::quote_response(
                &request,
                self.auth_posts.fetch_add(1, Ordering::SeqCst),
            )
        } else if let Some(signature) = request
            .url
            .strip_prefix("https://api.relay.link/execute/permits?signature=")
        {
            assert_eq!(request.method, "POST");
            let signed = self.prepared_signed.lock().unwrap();
            let (_, bytes) = signed
                .last()
                .expect("submission requires a completed real signature");
            // Relay receives Ethereum's 27/28 recovery byte; Broker returns
            // the same recoverable signature with a 0/1 recovery ID.
            assert_eq!(bytes.len(), 65);
            let mut relay_signature = bytes.clone();
            relay_signature[64] = match bytes[64] {
                0 | 1 => bytes[64] + 27,
                27 | 28 => bytes[64],
                other => panic!("invalid real signature recovery ID: {other}"),
            };
            assert_eq!(signature, format!("0x{}", hex::encode(relay_signature)));
            let submitted: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(submitted["kind"], "eip3009");
            self.relay_submissions.fetch_add(1, Ordering::SeqCst);
            br#"{"accepted":true}"#.to_vec()
        } else if request
            .url
            .starts_with("https://api.relay.link/intents/status/v3?")
        {
            assert_eq!(request.method, "GET");
            br#"{"status":"success","originChainId":8453,"destinationChainId":10}"#.to_vec()
        } else if request.url == "https://clob.polymarket.com/time" && request.method == "GET" {
            self.timestamp
                .load(Ordering::SeqCst)
                .to_string()
                .into_bytes()
        } else if request.url == "https://clob.polymarket.com/auth/api-key"
            && request.method == "POST"
        {
            let signed = self.prepared_signed.lock().unwrap();
            let (authorization, signature_bytes) = signed
                .last()
                .expect("credentials require a completed signature");
            let signature = alloy::primitives::Signature::from_raw(signature_bytes).unwrap();
            let owner = signature
                .recover_address_from_prehash(&alloy::primitives::B256::from(
                    authorization.action.payload.hash,
                ))
                .unwrap();
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
            let review: serde_json::Value =
                serde_json::from_slice(&authorization.action.review.bytes).unwrap();
            let timestamp = &review["typed_data"]["message"]["timestamp"];
            let timestamp = timestamp
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| timestamp.to_string());
            assert!(header("POLY_TIMESTAMP") == timestamp);

            assert!(header("POLY_SIGNATURE") == signature.to_string());
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

fn integration_package(name: &str) -> bloom_petals::package::PreparedPetalPackage {
    let input = setting(name);
    if input.is_file() {
        bloom_petals::package::PreparedPetalPackage::from_petal_tar(input).unwrap()
    } else {
        bloom_petals::package::build_petal_package_dir(input).unwrap()
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

#[path = "phase1_acceptance.rs"]
mod phase1_acceptance;
