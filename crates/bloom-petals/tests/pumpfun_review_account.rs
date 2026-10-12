//! Category: integration
//! The built Pump.fun package, installed into Bloom's own Petal router with a
//! synthetic two-account wallet. Run by `scripts/check-bloom-contract.sh`,
//! which copies this file into a Bloom checkout at the pinned contract rev.
//! No daemon, Broker, Signer or network: every HTTP request and signing
//! attempt is recorded and refused by the fixture host.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bloom_petals::policy::NetPolicy;
use bloom_petals::{
    HostError, HostVfsEntry, HostVfsEntryKind, HttpRequest, HttpResponse, NameRegistry,
    PayloadSignRequest, PetalHost, PetalRouter, PetalRunner, PetalStore, PetalVm, PrivateStore,
    SignOutcome,
};
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};

const WALLET: &str = "alice";
/// Account 0 and account 1 hold different Solana addresses, so a route that
/// read the wrong account would name the wrong one.
const ADDRESSES: [&str; 2] = [
    "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF",
    "C8CMvu8FXZruHrNjFaixaDJjiveG6gKmUvT5BrK5pump",
];

#[derive(Default)]
struct Fixture {
    vfs_reads: Mutex<Vec<String>>,
    http: Mutex<Vec<String>>,
    signing_attempts: Mutex<usize>,
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
impl PetalHost for Fixture {
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        match path {
            "wallets" => Ok(directory("wallets")),
            "wallets/alice" => Ok(directory(WALLET)),
            _ => Err(HostError::NotFound(path.into())),
        }
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        match path {
            "wallets" => Ok(vec![directory(WALLET), directory("registrations")]),
            "wallets/alice" => Ok(vec![directory("0"), directory("1")]),
            _ => Err(HostError::NotFound(path.into())),
        }
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.vfs_reads.lock().unwrap().push(path.to_owned());
        for (index, address) in ADDRESSES.iter().enumerate() {
            if path == format!("wallets/{WALLET}/{index}/account.json") {
                return Ok(serde_json::to_vec(&serde_json::json!({
                    "schema": "bloom.account.v1", "wallet": WALLET, "number": index,
                    "freshness": "fresh", "evm": {"state": "missing"},
                    "solana": {"state": "active", "public_key_fingerprint": format!("{:064x}", index + 1)}
                }))
                .unwrap());
            }
            if path == format!("wallets/{WALLET}/{index}/address.sol") {
                return Ok(format!("{address}\n").into_bytes());
            }
        }
        Err(HostError::NotFound(path.into()))
    }

    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("fixture VFS writes".into()))
    }

    async fn http_fetch(
        &self,
        request: HttpRequest,
        _policy: NetPolicy,
        _max: usize,
    ) -> Result<HttpResponse, HostError> {
        let body = String::from_utf8_lossy(&request.body);
        self.http
            .lock()
            .unwrap()
            .push(format!("{} {body}", request.url));
        Err(HostError::Denied("fixture HTTP".into()))
    }

    async fn sign_payload_outcome(
        &self,
        _request: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        *self.signing_attempts.lock().unwrap() += 1;
        Err(HostError::Denied("fixture signing".into()))
    }
}

fn mounted(relative: &str) -> VfsPath {
    VfsPath::parse(&format!("/petals/pumpfun/{relative}")).unwrap()
}

async fn names(vfs: &Vfs, relative: &str) -> Vec<String> {
    vfs.list(&mounted(relative))
        .await
        .unwrap_or_else(|error| panic!("list {relative}: {error}"))
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

fn buy(operation: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "operationId": operation,
        "mint": ADDRESSES[1],
        "amount": "1000000",
    }))
    .unwrap()
}

#[tokio::test]
#[ignore = "requires the built package; run through scripts/check-bloom-contract.sh"]
async fn trades_run_only_under_the_wallet_and_account_bloom_selected() {
    let root = PathBuf::from(
        std::env::var_os("PUMPFUN_PACKAGE_ROOT")
            .expect("set PUMPFUN_PACKAGE_ROOT to the built bloom-petal-pumpfun checkout"),
    );
    let home = tempfile::tempdir().unwrap();
    let store = PetalStore::open(home.path().join("petals/store")).unwrap();
    let prepared = bloom_petals::package::build_petal_package_dir(&root)
        .unwrap_or_else(|error| panic!("package validation: {error}"));
    let patterns: Vec<_> = prepared
        .route_index
        .routes
        .iter()
        .map(|route| route.pattern.clone())
        .collect();
    for pattern in patterns.iter().filter(|p| p.starts_with("trade/")) {
        assert!(
            matches!(pattern.as_str(), "trade" | "trade/[wallet]")
                || pattern.starts_with("trade/[wallet]/[index]"),
            "trade route outside an explicit account: {pattern}"
        );
    }
    let (installed, _, _) = store.install_prepared_petal_package(prepared).unwrap();
    let hash = installed.hash;

    let host = Arc::new(Fixture::default());
    let registry = Arc::new(NameRegistry::open(home.path().join("registry")).unwrap());
    let runner = PetalRunner::new(store.clone(), registry, PetalVm::new().unwrap());
    let vfs = Vfs::builder()
        .mount("petals", Arc::new(PetalRouter::new(runner, host.clone())))
        .build();

    // Bloom, not the Petal, lists the wallets and accounts that can trade.
    assert_eq!(names(&vfs, "trade").await, [WALLET]);
    assert_eq!(names(&vfs, "trade/alice").await, ["0", "1"]);
    let leaves = names(&vfs, "trade/alice/1").await;
    for leaf in [
        "buy.json",
        "sell.json",
        "launch.json",
        "holdings.html",
        "preflight.json",
        "operations",
    ] {
        assert!(leaves.iter().any(|name| name == leaf), "{leaves:?}");
    }

    // The old unscoped paths no longer exist, and touching them runs nothing.
    assert!(vfs.read(&mounted("trade/alice/preflight.json")).await.is_err());
    assert!(
        vfs.write(&mounted("trade/alice/buy.json"), &buy("op-old"))
            .await
            .is_err()
    );
    for bad in ["01", "2", "4294967296", "x"] {
        assert!(
            vfs.read(&mounted(&format!("trade/alice/{bad}/preflight.json")))
                .await
                .is_err(),
            "accepted account {bad}"
        );
    }
    assert!(
        vfs.read(&mounted("trade/absent/0/preflight.json"))
            .await
            .is_err()
    );
    assert!(host.http.lock().unwrap().is_empty());

    // Preflight on account 1 reports account 1's own address.
    let report: serde_json::Value = serde_json::from_slice(
        &vfs.read(&mounted("trade/alice/1/preflight.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let text = report.to_string();
    assert!(text.contains(ADDRESSES[1]), "{text}");
    assert!(!text.contains(ADDRESSES[0]), "{text}");
    assert!(
        host.vfs_reads
            .lock()
            .unwrap()
            .iter()
            .all(|path| !path.starts_with("wallets/alice/0/")),
        "account 1 read account 0"
    );

    // A buy on account 1 builds for account 1's address. The fixture refuses
    // the builder, so the write fails before any signing request.
    host.http.lock().unwrap().clear();
    let refused = vfs
        .write(&mounted("trade/alice/1/buy.json"), &buy("op-1"))
        .await
        .expect_err("the fixture refuses the builder");
    eprintln!("account 1 buy refused as expected: {refused}");
    let requests = host.http.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|request| request.contains(ADDRESSES[1])),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains(ADDRESSES[0]))
    );
    assert_eq!(*host.signing_attempts.lock().unwrap(), 0);

    // A launch makes account 1 the coin's creator and payer, the same way.
    host.http.lock().unwrap().clear();
    let launch = serde_json::to_vec(&serde_json::json!({
        "operationId": "launch-1",
        "name": "Fixture Coin",
        "symbol": "FIX",
        "amount": "1000000",
        "uri": "https://example.com/coin.json",
    }))
    .unwrap();
    let refused = vfs
        .write(&mounted("trade/alice/1/launch.json"), &launch)
        .await
        .expect_err("the fixture refuses the builder");
    eprintln!("account 1 launch refused as expected: {refused}");
    let requests = host.http.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|request| request.contains(ADDRESSES[1])),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains(ADDRESSES[0]))
    );
    assert_eq!(*host.signing_attempts.lock().unwrap(), 0);

    // Each account lists only the operation records in its own store.
    for index in [0u32, 1] {
        PrivateStore::open_account(store.private_account_data_root(), WALLET, index)
            .unwrap()
            .put(
                &hash,
                &format!("state/state/trades/{index}/{WALLET}/operations/marker-{index}.json"),
                b"{}",
                false,
            )
            .unwrap();
    }
    for index in [0u32, 1] {
        let listed = names(&vfs, &format!("trade/alice/{index}/operations")).await;
        assert_eq!(listed, [format!("marker-{index}.json")]);
    }
}
