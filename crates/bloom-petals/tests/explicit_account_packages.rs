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
        for index in [0, 1] {
            if path == format!("wallets/alice/{index}/account.json") {
                if index == 1 && self.account_one_missing.load(Ordering::SeqCst) {
                    return Err(HostError::NotFound(path.into()));
                }
                return Ok(serde_json::to_vec(&serde_json::json!({
                    "schema":"bloom.account.v1", "wallet":"alice", "number":index,
                    "freshness":"fresh", "evm":{"public_key_fingerprint":format!("{:064x}",index+1)},
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
        _request: HttpRequest,
        _policy: NetPolicy,
        _max: usize,
    ) -> Result<HttpResponse, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
        Err(HostError::Denied("fixture HTTP".into()))
    }

    async fn chain_read(&self, _request: ChainRequest) -> Result<ChainResponse, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
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
        _request: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
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
