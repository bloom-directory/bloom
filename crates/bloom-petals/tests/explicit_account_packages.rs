//! Installed, independently compiled package coverage with synthetic account projections.
//! This is a VM/host fixture test: it performs no daemon, Broker, Signer, or live-network work.
//! Build sibling packages first, then run with BLOOM_HD_PACKAGE_ROOT pointing at their parent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use bloom_petals::abi::{ChainRequest, ChainResponse};
use bloom_petals::policy::NetPolicy;
use bloom_petals::{
    EvmOutboxOutcome, EvmTransactionRequest, HostError, HostVfsEntry, HostVfsEntryKind,
    HttpRequest, HttpResponse, NameRegistry, PayloadSignRequest, PetalHost, PetalKeyOutcome,
    PetalKeyRequest, PetalRouter, PetalRunner, PetalStore, PetalVm, PrivateStore, SignOutcome,
};
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};

#[derive(Default)]
struct AccountFixture {
    account_one_missing: AtomicBool,
    external_calls: AtomicUsize,
    capture_signing: AtomicBool,
    sign_requests: std::sync::Mutex<Vec<PayloadSignRequest>>,
    batch_sign_requests: std::sync::Mutex<Vec<bloom_petals::PayloadBatchSignRequest>>,
}

fn directory(name: &str) -> HostVfsEntry {
    HostVfsEntry {
        name: name.into(),
        kind: HostVfsEntryKind::Dir,
        mode: 0o755,
        size: None,
        link_target: None,
    }
}

#[async_trait]
impl PetalHost for AccountFixture {
    async fn sign_payload_batch_outcome(
        &self,
        request: bloom_petals::PayloadBatchSignRequest,
    ) -> Result<bloom_petals::PayloadBatchSignOutcome, HostError> {
        if !self.capture_signing.load(Ordering::SeqCst) {
            return Err(HostError::Denied("fixture batch signing".into()));
        }
        self.batch_sign_requests.lock().unwrap().push(request);
        Ok(bloom_petals::PayloadBatchSignOutcome::ApprovalPending(
            bloom_petals::abi::ApprovalPending {
                action_id: "55".repeat(32),
                expires_ms: u64::MAX,
            },
        ))
    }
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        if matches!(path, "wallets" | "wallets/alice") {
            return Ok(directory(path.rsplit('/').next().unwrap()));
        }
        Err(HostError::NotFound(path.into()))
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        match path {
            "wallets" => Ok(vec![directory("alice"), directory("registrations")]),
            "wallets/alice" => Ok(vec![directory("0"), directory("1")]),
            _ => Err(HostError::NotFound(path.into())),
        }
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        if self.capture_signing.load(Ordering::SeqCst) && path == "chains/polygon/chain_id" {
            return Ok(b"137".to_vec());
        }
        for index in [0, 1] {
            if path == format!("wallets/alice/{index}/account.json") {
                if index == 1 && self.account_one_missing.load(Ordering::SeqCst) {
                    return Err(HostError::NotFound(path.into()));
                }
                return Ok(serde_json::to_vec(&serde_json::json!({
                    "schema":"bloom.account.v1", "wallet":"alice", "number":index,
                    "freshness":"fresh", "evm":{"state":"active","public_key_fingerprint":format!("{:064x}",index+1)},
                    "solana":{"state":"missing"}
                })).unwrap());
            }
            if path == format!("wallets/alice/{index}/address.evm") {
                return Ok(format!("0x{:040x}\n", index + 1).into_bytes());
            }
        }
        Err(HostError::NotFound(path.into()))
    }

    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        Err(HostError::Denied("fixture VFS writes".into()))
    }

    async fn http_fetch(
        &self,
        request: HttpRequest,
        _policy: NetPolicy,
        _max: usize,
    ) -> Result<HttpResponse, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        if self.capture_signing.load(Ordering::SeqCst) && request.url.ends_with("/time") {
            return Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: b"1700000000".to_vec(),
            });
        }
        if self.capture_signing.load(Ordering::SeqCst) && request.url.contains("/nonce?") {
            return Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: br#"{"nonce":"0"}"#.to_vec(),
            });
        }
        Err(HostError::Denied("fixture HTTP".into()))
    }

    async fn chain_read(&self, request: ChainRequest) -> Result<ChainResponse, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        if self.capture_signing.load(Ordering::SeqCst) {
            let params: serde_json::Value = serde_json::from_str(&request.params_json).unwrap();
            let value = match request.method.as_str() {
                "eth_getCode" => "0x6000".to_owned(),
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap();
                    let word = match &data[..10] {
                        "0x5c60da1b" | "0x1f264778" => 3u64,
                        "0x70a08231" => 100,
                        "0xdd62ed3e" | "0xe985e9c5" => 0,
                        _ => return Err(HostError::Denied("unexpected fixture selector".into())),
                    };
                    format!("0x{word:064x}")
                }
                _ => return Err(HostError::Denied("unexpected fixture RPC".into())),
            };
            return Ok(ChainResponse {
                result_json: serde_json::to_string(&value).unwrap(),
            });
        }
        Err(HostError::Denied("fixture chain RPC".into()))
    }

    async fn evm_tx_stage(
        &self,
        _request: EvmTransactionRequest,
    ) -> Result<EvmOutboxOutcome, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        Err(HostError::Denied("fixture transaction staging".into()))
    }

    async fn petal_key_request(
        &self,
        _request: PetalKeyRequest,
    ) -> Result<PetalKeyOutcome, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        Err(HostError::Denied("fixture key creation".into()))
    }

    async fn sign_payload_outcome(
        &self,
        request: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        if self.capture_signing.load(Ordering::SeqCst) {
            self.sign_requests.lock().unwrap().push(request);
            return Ok(SignOutcome::ApprovalPending(
                bloom_petals::abi::ApprovalPending {
                    action_id: "55".repeat(32),
                    expires_ms: u64::MAX,
                },
            ));
        }
        Err(HostError::Denied("fixture signing".into()))
    }
}

struct Package {
    name: &'static str,
    repository: &'static str,
    public: &'static str,
    parent: &'static str,
    listing: &'static str,
    marker_key: &'static str,
}

const PACKAGES: &[Package] = &[
    Package {
        name: "enso",
        repository: "bloom-petal-enso",
        public: "meta/route-contract.json",
        parent: "intents/alice",
        listing: "intents/alice/{index}",
        marker_key: "state/intents/alice/{marker}/session.json",
    },
    Package {
        name: "near-intents",
        repository: "bloom-petal-near",
        public: "meta/route-contract.json",
        parent: "swaps/alice",
        listing: "swaps/alice/{index}",
        marker_key: "state/swaps/alice/{marker}/session.json",
    },
    Package {
        name: "polymarket",
        repository: "bloom-petal-polymarket",
        public: "meta/route-contract.json",
        parent: "settings/alice",
        listing: "trade/alice/{index}/drafts",
        marker_key: "state/trade/alice/drafts/{marker}/order.json",
    },
    Package {
        name: "hyperliquid",
        repository: "bloom-petal-hyperliquid",
        public: "asset_ids.md",
        parent: "testnet/agent_sessions/alice",
        listing: "testnet/agent_sessions/alice/{index}",
        marker_key: "state/state/sessions/testnet/alice/{marker}/session.json",
    },
    Package {
        name: "tolly",
        repository: "bloom-petal-tolly",
        public: "README.md",
        parent: "wallets/alice",
        listing: "wallets/alice/{index}/operations",
        marker_key: "state/tolly/ops/alice/{marker}",
    },
];

fn mounted(name: &str, relative: &str) -> VfsPath {
    VfsPath::parse(&format!("/petals/{name}/{relative}")).unwrap()
}

fn fixture_vfs(home: &Path, host: Arc<AccountFixture>) -> Vfs {
    let store = PetalStore::open(home.join("petals/store")).unwrap();
    let registry = Arc::new(NameRegistry::open(home.join("registry")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    Vfs::builder()
        .mount("petals", Arc::new(PetalRouter::new(runner, host)))
        .build()
}

async fn names(vfs: &Vfs, name: &str, path: &str) -> Vec<String> {
    vfs.list(&mounted(name, path))
        .await
        .unwrap_or_else(|error| panic!("{name}/{path} list failed: {error}"))
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

async fn credential_status(vfs: &Vfs, name: &str) -> serde_json::Value {
    let bytes = vfs
        .read(&mounted(name, "settings/status.json"))
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let credential = match name {
        "enso" => document,
        "near-intents" => document
            .get("credential")
            .expect("Near status.json credential object")
            .clone(),
        _ => panic!("no credential status contract for {name}"),
    };
    assert!(
        credential["configured"].is_boolean(),
        "{name}: configured field missing"
    );
    assert!(
        credential["source"].is_string(),
        "{name}: source field missing"
    );
    assert!(
        credential["storage"].is_string(),
        "{name}: storage field missing"
    );
    credential
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(files_under(&path));
            } else {
                files.push(path);
            }
        }
    }
    files
}

#[tokio::test]
#[ignore = "requires built sibling packages and explicit BLOOM_HD_PACKAGE_ROOT"]
async fn installed_packages_keep_explicit_account_routes_and_private_state() {
    let root = PathBuf::from(
        std::env::var_os("BLOOM_HD_PACKAGE_ROOT")
            .expect("set BLOOM_HD_PACKAGE_ROOT to built sibling package parent"),
    );
    let selected = std::env::var("BLOOM_HD_PACKAGE_NAMES").ok();
    let packages: Vec<_> = PACKAGES
        .iter()
        .filter(|package| {
            selected
                .as_ref()
                .is_none_or(|names| names.split(',').any(|name| name == package.name))
        })
        .collect();
    assert!(!packages.is_empty(), "no known packages selected");
    let temporary = tempfile::Builder::new().prefix("vm-").tempdir().unwrap();
    let home = temporary.path();
    let store = PetalStore::open(home.join("petals/store")).unwrap();
    let mut hashes = BTreeMap::new();
    for package in &packages {
        let source = root.join(package.repository);
        let prepared = bloom_petals::package::build_petal_package_dir(&source)
            .unwrap_or_else(|error| panic!("{} package validation: {error}", package.name));
        assert!(
            prepared
                .route_index
                .routes
                .iter()
                .any(|route| route.pattern.contains("[wallet]/[index]")),
            "{} has no explicit wallet/index route",
            package.name
        );
        let (installed, _, _) = store.install_prepared_petal_package(prepared).unwrap();
        hashes.insert(package.name, installed.hash);
    }
    let host = Arc::new(AccountFixture::default());
    let vfs = fixture_vfs(home, host.clone());
    for package in &packages {
        assert!(
            !vfs.read(&mounted(package.name, package.public))
                .await
                .unwrap()
                .is_empty()
        );
        let indexes = names(&vfs, package.name, package.parent).await;
        assert!(
            indexes.contains(&"0".into()) && indexes.contains(&"1".into()),
            "{} account enumeration: {indexes:?}",
            package.name
        );
        let hash = &hashes[package.name];
        for index in [0, 1] {
            let marker = format!("marker-{index}");
            let private =
                PrivateStore::open_account(store.private_account_data_root(), "alice", index)
                    .unwrap();
            let key = package.marker_key.replace("{marker}", &marker);
            private.put(hash, &key, b"{}", false).unwrap();
            let listing = package.listing.replace("{index}", &index.to_string());
            let listed = names(&vfs, package.name, &listing).await;
            assert!(
                listed
                    .iter()
                    .any(|name| name == &marker || name == &format!("{marker}.json")),
                "{} index {index} missing marker in {listed:?}",
                package.name
            );
            assert!(
                !listed
                    .iter()
                    .any(|name| name.contains(&format!("marker-{}", 1 - index))),
                "{} account state leaked",
                package.name
            );
        }
        for bad in ["01", "4294967296", "missing"] {
            let path = package.listing.replace("{index}", bad);
            assert!(
                vfs.list(&mounted(package.name, &path)).await.is_err(),
                "{} accepted invalid index {bad}",
                package.name
            );
        }
        let missing_wallet = package
            .listing
            .replace("alice", "absent")
            .replace("{index}", "0");
        assert!(
            vfs.list(&mounted(package.name, &missing_wallet))
                .await
                .is_err()
        );
        host.account_one_missing.store(true, Ordering::SeqCst);
        let missing_account = package.listing.replace("{index}", "1");
        assert!(
            vfs.list(&mounted(package.name, &missing_account))
                .await
                .is_err(),
            "{} ignored missing live account",
            package.name
        );
        assert!(
            !vfs.read(&mounted(package.name, package.public))
                .await
                .unwrap()
                .is_empty(),
            "public metadata should not depend on account selection"
        );
        host.account_one_missing.store(false, Ordering::SeqCst);
        assert!(
            vfs.read(&mounted(
                package.name,
                &format!("wallets/alice/0/{}", package.public)
            ))
            .await
            .is_err(),
            "{} accepted global-root rewriting",
            package.name
        );
        eprintln!(
            "{}: installed built WASM, public read, indexes, private listing isolation and negative paths passed",
            package.name
        );
    }

    for package in packages
        .iter()
        .filter(|package| matches!(package.name, "enso" | "near-intents"))
    {
        let name = package.name;
        let hash = &hashes[name];
        let logical_key = if name == "enso" {
            "secrets/credentials/enso-api-key"
        } else {
            "secrets/credentials/partner-jwt"
        };
        let token = format!("synthetic.{name}.petal-wide");
        vfs.write(&mounted(name, "settings/api-key"), token.as_bytes())
            .await
            .unwrap();
        let status = credential_status(&vfs, name).await;
        assert_eq!(status["configured"], true);
        assert_eq!(status["source"], "private_store");
        assert!(!status.to_string().contains(&token));
        let api_read = vfs.read(&mounted(name, "settings/api-key")).await.unwrap();
        assert!(!String::from_utf8_lossy(&api_read).contains(&token));
        let shared = PrivateStore::open(store.private_data_root()).unwrap();
        assert_eq!(shared.get(hash, logical_key).unwrap(), token.as_bytes());
        for index in [0, 1] {
            let private =
                PrivateStore::open_account(store.private_account_data_root(), "alice", index)
                    .unwrap();
            assert!(
                private.get(hash, logical_key).is_err(),
                "credential copied into account store"
            );
            assert!(
                vfs.read(&mounted(name, &format!("settings/alice/{index}/api-key")))
                    .await
                    .is_err()
            );
        }
    }

    if hashes.contains_key("polymarket") {
        let key = b"synthetic-polymarket-service-key";
        let router = "0x1111111111111111111111111111111111111111";
        let body = serde_json::to_vec(&serde_json::json!({
            "api_key": std::str::from_utf8(key).unwrap(), "router": router
        }))
        .unwrap();
        vfs.write(&mounted("polymarket", "settings/enso-api-key"), &body)
            .await
            .unwrap();
        let global = PrivateStore::open(store.private_data_root()).unwrap();
        let hash = &hashes["polymarket"];
        assert_eq!(global.get(hash, "secrets/creds/enso-api-key").unwrap(), key);
        assert_eq!(
            global.get(hash, "state/settings/enso-router").unwrap(),
            router.as_bytes()
        );
        assert!(
            !String::from_utf8_lossy(
                &vfs.read(&mounted("polymarket", "settings/enso-api-key"))
                    .await
                    .unwrap()
            )
            .contains(std::str::from_utf8(key).unwrap())
        );
        for (index, body) in [
            (0, b"enabled = false\n".as_slice()),
            (1, b"enabled = true\n".as_slice()),
        ] {
            let path = mounted("polymarket", &format!("settings/alice/{index}/venue.toml"));
            vfs.write(&path, body).await.unwrap();
            assert_eq!(vfs.read(&path).await.unwrap(), body);
        }
    }
    if hashes.contains_key("hyperliquid") {
        for index in [0, 1] {
            assert!(
                vfs.write(
                    &mounted(
                        "hyperliquid",
                        &format!("testnet/agent_sessions/alice/{index}/new.json")
                    ),
                    b"{broken"
                )
                .await
                .is_err()
            );
        }
    }
    drop(vfs);
    let restarted = fixture_vfs(home, host.clone());
    for package in &packages {
        for index in [0, 1] {
            let listed = names(
                &restarted,
                package.name,
                &package.listing.replace("{index}", &index.to_string()),
            )
            .await;
            assert!(
                listed
                    .iter()
                    .any(|name| name.contains(&format!("marker-{index}")))
            );
        }
        if matches!(package.name, "enso" | "near-intents") {
            assert_eq!(
                credential_status(&restarted, package.name).await["source"],
                "private_store"
            );
        }
    }
    if hashes.contains_key("polymarket") {
        for (index, body) in [
            (0, b"enabled = false\n".as_slice()),
            (1, b"enabled = true\n".as_slice()),
        ] {
            assert_eq!(
                restarted
                    .read(&mounted(
                        "polymarket",
                        &format!("settings/alice/{index}/venue.toml")
                    ))
                    .await
                    .unwrap(),
                body
            );
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in files_under(&store.private_account_data_root())
            .into_iter()
            .chain(files_under(&store.private_data_root()))
            .filter(|path| path.components().any(|part| part.as_os_str() == "secrets"))
        {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{} secret mode",
                path.display()
            );
        }
    }
    assert_eq!(
        host.external_calls.load(Ordering::SeqCst),
        0,
        "fixture attempted network, key creation, signing, staging, or VFS write"
    );
    eprintln!(
        "installed WASM fixture: private settings, restart, secret permissions and no external side effects passed"
    );
}

#[tokio::test]
#[ignore = "requires rebuilt packages via BLOOM_PM80_POLYMARKET_ROOT and BLOOM_PM80_HYPERLIQUID_ROOT"]
async fn real_signing_producers_reach_the_host_with_selected_account_and_full_witness() {
    let temporary = tempfile::Builder::new().prefix("cs-vm-").tempdir().unwrap();
    let home = temporary.path();
    let store = PetalStore::open(home.join("petals/store")).unwrap();
    let mut hashes = BTreeMap::new();
    let mut package_records = Vec::new();
    for (name, variable) in [
        ("polymarket", "BLOOM_PM80_POLYMARKET_ROOT"),
        ("hyperliquid", "BLOOM_PM80_HYPERLIQUID_ROOT"),
    ] {
        let root = PathBuf::from(std::env::var_os(variable).expect(variable));
        let prepared = bloom_petals::package::build_petal_package_dir(&root).unwrap();
        let authority: Vec<_> = prepared
            .route_index
            .routes
            .iter()
            .filter_map(|route| {
                let mut classes = route.key_derive_operation_classes.clone();
                if let Some(intent) = &route.install_metadata.sign_intent {
                    classes.push(intent.clone());
                }
                classes.sort();
                classes.dedup();
                (!classes.is_empty()).then(|| serde_json::json!({
                "route_id":route.route_id, "pattern":route.pattern, "operation_classes":classes,
            }))
            })
            .collect();
        let (installed, _, _) = store.install_prepared_petal_package(prepared).unwrap();
        package_records.push(serde_json::json!({"name":name,"package_hash":installed.hash,"authority_routes":authority}));
        hashes.insert(name, installed.hash);
    }
    let host = Arc::new(AccountFixture::default());
    host.capture_signing.store(true, Ordering::SeqCst);
    let vfs = fixture_vfs(home, host.clone());
    let begin = mounted("polymarket", "onboard/alice/1/begin");
    let status_path = mounted("polymarket", "onboard/alice/1/status.json");
    let fresh: serde_json::Value =
        serde_json::from_slice(&vfs.read(&status_path).await.unwrap()).unwrap();
    assert_eq!(fresh["next_action"], "onboard/alice/1/begin");
    let begin_result = vfs.write(&begin, b"begin").await;
    {
        let requests = host.batch_sign_requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "fresh begin must emit CLOB auth: {begin_result:?}"
        );
        let request = &requests[0];
        assert_eq!(request.operation_class, "polymarket.clob_auth.v1");
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
        assert_eq!(
            request.context.as_ref().unwrap().package_hash,
            hashes["polymarket"]
        );
        assert!(request.action.is_some());
    }
    let private =
        PrivateStore::open_account(store.private_account_data_root(), "alice", 1).unwrap();
    private
        .put(
            &hashes["polymarket"],
            "secrets/creds/alice/clob.json",
            br#"{"apiKey":"fixture","secret":"fixture","passphrase":"fixture"}"#,
            true,
        )
        .unwrap();
    vfs.write(&begin, b"begin").await.unwrap();
    let credentials_ready: serde_json::Value =
        serde_json::from_slice(&vfs.read(&status_path).await.unwrap()).unwrap();
    assert_eq!(credentials_ready["next_action"], "onboard/alice/1/continue");
    assert_eq!(
        host.batch_sign_requests.lock().unwrap().len(),
        1,
        "stored credentials must not sign under begin"
    );
    let continuation = mounted("polymarket", "onboard/alice/1/continue");
    let continuation_result = vfs.write(&continuation, b"continue").await;
    {
        let requests = host.batch_sign_requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "continuation must prepare the separate exact batch: {continuation_result:?}"
        );
        assert_eq!(requests[1].operation_class, "polymarket.onboard");
        assert_eq!(
            requests[1].selector,
            bloom_broker_api::PetalSignSelector::Exact
        );
        assert_eq!(requests[1].context.as_ref().unwrap().route_id, "r000043");
        assert_eq!(requests[0].context.as_ref().unwrap().route_id, "r000042");
    }
    let pending_keys = [
        "state/onboard/alice/approval.json",
        "state/onboard/alice/prepared_relayer_batch.json",
    ];
    let pending = pending_keys.map(|key| private.get(&hashes["polymarket"], key).unwrap());
    for _ in 0..2 {
        vfs.write(&begin, b"begin").await.unwrap();
        for (key, expected) in pending_keys.iter().zip(&pending) {
            assert_eq!(
                &private.get(&hashes["polymarket"], key).unwrap(),
                expected,
                "begin must preserve the pending exact batch and approval"
            );
        }
    }
    assert_eq!(host.batch_sign_requests.lock().unwrap().len(), 2);
    let awaiting: serde_json::Value =
        serde_json::from_slice(&vfs.read(&status_path).await.unwrap()).unwrap();
    assert_eq!(awaiting["next_action"], "onboard/alice/1/continue");
    assert!(
        awaiting["message"]
            .as_str()
            .unwrap()
            .contains("existing owner approval")
    );
    // Old hint files cannot keep completed/read-only accounts actionable.
    private
        .put(
            &hashes["polymarket"],
            "state/onboard/alice/next_action.json",
            br#"{"next_action":"stale continuation"}"#,
            false,
        )
        .unwrap();
    private.del(&hashes["polymarket"], pending_keys[0]).unwrap();
    for stage in ["fund", "complete"] {
        let status = serde_json::json!({"owner":"0x0000000000000000000000000000000000000002", "stage":stage});
        private
            .put(
                &hashes["polymarket"],
                "state/onboard/alice/status.json",
                &serde_json::to_vec(&status).unwrap(),
                false,
            )
            .unwrap();
        let projected: serde_json::Value =
            serde_json::from_slice(&vfs.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(
            projected["next_action"],
            if stage == "fund" {
                serde_json::json!("fund/alice/1/new")
            } else {
                serde_json::Value::Null
            }
        );
    }
    private
        .put(
            &hashes["polymarket"],
            "secrets/creds/relayer.json",
            br#"{"legacy_eoa_mode":true}"#,
            true,
        )
        .unwrap();
    let read_only: serde_json::Value =
        serde_json::from_slice(&vfs.read(&status_path).await.unwrap()).unwrap();
    assert_eq!(read_only["stage"], "legacy_eoa");
    assert!(read_only["next_action"].is_null());
    // A real persisted delegated session drives the actual compiled workflow.
    let key = bloom_broker_api::KeyRef {
        backend: bloom_broker_api::Token::new("local").unwrap(),
        backend_instance: bloom_broker_api::Token::new("fixture").unwrap(),
        locator: "wallet/alice/petals/fixture-child".into(),
        key_spec: bloom_broker_api::KeySpec::Secp256k1,
        public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([0x44; 32]),
        derivation: None,
    };
    let session = serde_json::json!({
        "schema":"bloom.hyperliquid_agent_session.v1", "network":"testnet", "wallet":"alice",
        "owner_address":"0x0000000000000000000000000000000000000002", "id":"test",
        "agent_address":"0x0000000000000000000000000000000000000003",
        "key_ref_jcs":serde_jcs::to_vec(&key).unwrap(), "agent_name":"test",
        "created_ms":1, "expires_ms":u64::MAX, "max_notional_usd":null, "max_leverage":3,
        "assets":["0"], "stopped":false, "last_response":null, "last_error":null
    });
    private
        .put(
            &hashes["hyperliquid"],
            "state/state/sessions/testnet/alice/test/session.json",
            &serde_json::to_vec(&session).unwrap(),
            false,
        )
        .unwrap();
    let cancel = mounted(
        "hyperliquid",
        "testnet/agent_sessions/alice/1/test/cancel.json",
    );
    let mut cancellation_results = Vec::new();
    for (nonce, action) in [
        (
            123,
            serde_json::json!({"type":"cancel","cancels":[{"a":0,"o":42}]}),
        ),
        (
            124,
            serde_json::json!({"type":"cancel","cancels":[{"a":0,"o":42}],"f":true}),
        ),
        (
            125,
            serde_json::json!({"type":"cancelByCloid","cancels":[{"asset":0,"cloid":"0x00112233445566778899aabbccddeeff"}]}),
        ),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({
            "action":action, "nonce":nonce
        }))
        .unwrap();
        cancellation_results.push(vfs.write(&cancel, &body).await);
    }
    let requests = host.sign_requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        3,
        "normal, fast and client-ID cancellations must reach the host: {cancellation_results:?}"
    );
    for request in requests.iter() {
        assert_eq!(request.operation_class, "hyperliquid.agent_action");
        assert_eq!(request.key_ref.as_ref(), Some(&key));
        assert_eq!(request.claim_assurance_evidence, request.action);
        assert!(
            request
                .claim_assurance_evidence
                .as_ref()
                .is_some_and(|bytes| !bytes.is_empty())
        );
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
    }
    let produced: Vec<_> = requests.iter().map(|request| serde_json::json!({
            "preimage_hex":hex::encode(&request.preimage), "hash_hex":hex::encode(request.claimed_hash),
            "witness":serde_json::from_slice::<serde_json::Value>(request.claim_assurance_evidence.as_ref().unwrap()).unwrap()
        })).collect();
    let broker_fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hyperliquid-producer-cancel.json")).unwrap();
    assert_eq!(
        serde_json::json!(produced),
        broker_fixture,
        "actual compiled producer witness/hash/preimage differs from the Broker reconstruction fixture"
    );
    if let Some(path) = std::env::var_os("BLOOM_PM80_PRODUCER_WITNESS") {
        std::fs::write(path, serde_json::to_vec_pretty(&produced).unwrap()).unwrap();
    }
    if let Some(path) = std::env::var_os("BLOOM_PM80_PACKAGE_RECORDS") {
        std::fs::write(path, serde_json::to_vec_pretty(&package_records).unwrap()).unwrap();
    }
}
