use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bloom_petal_manifest::extract_local_petal_manifest;
use bloom_petals::abi::{HttpRequest, HttpResponse, SignRequest};
use bloom_petals::{
    HostError, NameRegistry, PetalHost, PetalMode, PetalRouter, PetalRunner, PetalStore, PetalVm,
};
use bloom_petals::{NetPolicy, private_store::PrivateStore};
use bloom_vfs::Handler;
use bloom_vfs::path::VfsPath;

#[tokio::test]
async fn compiled_polymarket_petal_uses_http_and_private_store() {
    let root = workspace_root();
    if !wasm32_wasip1_installed(&root) {
        eprintln!("skipping polymarket petal smoke test: wasm32-wasip1 target is not installed");
        return;
    }
    let target_dir = root.join("target/local-petal-polymarket-test");
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "bloom-local-petal-polymarket",
            "--target",
            "wasm32-wasip1",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("cargo build must run");
    assert!(status.success(), "wasm build failed with {status}");

    let wasm_path = target_dir.join("wasm32-wasip1/debug/bloom_local_petal_polymarket.wasm");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("read wasm {}: {e}", wasm_path.display()));

    let manifest = extract_local_petal_manifest(&wasm, std::iter::empty::<&str>())
        .expect("local manifest must extract");
    assert_eq!(manifest.provides.mount, "polymarket");
    assert_eq!(
        manifest
            .provides
            .caps
            .iter()
            .map(|cap| cap.as_str())
            .collect::<Vec<_>>(),
        vec!["vfs.read", "net.fetch", "sign", "store"]
    );
    assert_eq!(manifest.net.as_ref().unwrap().allow.len(), 3);

    let tmp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(tmp.path().join("store")).unwrap();
    let registry = Arc::new(NameRegistry::open(tmp.path().join("names")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    let (install, _) = runner
        .install(&wasm, None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();

    let host = Arc::new(MockHost::fixture());
    let router = PetalRouter::new(runner.clone(), host.clone());

    let root_entries = router
        .list(&VfsPath::parse("polymarket").unwrap())
        .await
        .unwrap();
    assert!(root_entries.iter().any(|entry| entry.name == "markets"));
    assert!(root_entries.iter().any(|entry| entry.name == "trade"));

    let markets = router
        .list(&VfsPath::parse("polymarket/markets").unwrap())
        .await
        .unwrap();
    assert_eq!(markets.len(), 1);
    assert_eq!(markets[0].name, "test-market");

    let market = router
        .read(&VfsPath::parse("polymarket/markets/test-market/market.json").unwrap())
        .await
        .unwrap();
    let market: serde_json::Value = serde_json::from_slice(&market).unwrap();
    assert_eq!(market["slug"], "test-market");

    let book = router
        .read(&VfsPath::parse("polymarket/markets/test-market/book.json").unwrap())
        .await
        .unwrap();
    let book: serde_json::Value = serde_json::from_slice(&book).unwrap();
    assert_eq!(book["asset_id"], "yes-token");

    router
        .write(
            &VfsPath::parse("polymarket/onboard/alice/begin").unwrap(),
            b"go",
        )
        .await
        .unwrap();
    let status = router
        .read(&VfsPath::parse("polymarket/onboard/alice/status.json").unwrap())
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
    assert_eq!(status["creds_present"], true);

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();
    let drafts = router
        .list(&VfsPath::parse("polymarket/trade/alice/drafts").unwrap())
        .await
        .unwrap();
    assert_eq!(drafts[0].name, "0001");
    let plan = router
        .read(&VfsPath::parse("polymarket/trade/alice/drafts/0001/plan.md").unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(plan).unwrap().contains("test-market"));

    let private = PrivateStore::open(tmp.path().join("data")).unwrap();
    let draft = private
        .get(&install.hash, "trade/alice/drafts/0001/order.json")
        .unwrap();
    assert!(String::from_utf8(draft).unwrap().contains("test-market"));
    let creds = private.get(&install.hash, "creds/alice/clob.json").unwrap();
    let creds_text = String::from_utf8(creds).unwrap();
    assert!(creds_text.contains("secret-value"));
    let account = router
        .read(&VfsPath::parse("polymarket/account/alice/portfolio.json").unwrap())
        .await
        .unwrap();
    let account_text = String::from_utf8(account).unwrap();
    assert!(account_text.contains("credentials_present"));
    assert!(!account_text.contains("secret-value"));

    assert_eq!(
        host.vfs_calls.lock().unwrap().as_slice(),
        ["read wallets/alice/address"]
    );
    assert_eq!(host.sign_calls.lock().unwrap().len(), 1);
    assert!(
        router
            .write(
                &VfsPath::parse("polymarket/markets/test-market/market.json").unwrap(),
                b"nope",
            )
            .await
            .is_err()
    );
}

#[derive(Default)]
struct MockHost {
    responses: BTreeMap<String, Vec<u8>>,
    http_calls: Mutex<Vec<(String, String)>>,
    vfs_calls: Mutex<Vec<String>>,
    sign_calls: Mutex<Vec<SignRequest>>,
}

impl MockHost {
    fn fixture() -> Self {
        let mut host = Self::default();
        host.responses.insert(
            "GET https://gamma-api.polymarket.com/markets?closed=false&limit=20&order=volumeNum&ascending=false".into(),
            br#"[{"slug":"test-market","conditionId":"cond","clobTokenIds":["yes-token","no-token"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}]"#.to_vec(),
        );
        host.responses.insert(
            "GET https://gamma-api.polymarket.com/markets/slug/test-market".into(),
            br#"{"slug":"test-market","conditionId":"cond","clobTokenIds":["yes-token","no-token"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/book?token_id=yes-token".into(),
            br#"{"market":"cond","asset_id":"yes-token","tick_size":"0.01","min_order_size":"1","neg_risk":false,"last_trade_price":"0.42","bids":[],"asks":[]}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/midpoint?token_id=yes-token".into(),
            br#"{"mid":"0.42"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/spread?token_id=yes-token".into(),
            br#"{"spread":"0.01"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/price?token_id=yes-token&side=BUY".into(),
            br#"{"price":"0.43"}"#.to_vec(),
        );
        host.responses.insert(
            "POST https://clob.polymarket.com/auth/api-key".into(),
            br#"{"apiKey":"api-key","secret":"secret-value","passphrase":"pass-value"}"#.to_vec(),
        );
        host
    }
}

#[async_trait]
impl PetalHost for MockHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.vfs_calls.lock().unwrap().push(format!("read {path}"));
        if path == "wallets/alice/address" {
            Ok(b"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\n".to_vec())
        } else {
            Err(HostError::NotFound(path.into()))
        }
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
        self.vfs_calls.lock().unwrap().push(format!("list {path}"));
        Err(HostError::Denied("vfs not expected".into()))
    }

    async fn vfs_write(&self, path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        self.vfs_calls.lock().unwrap().push(format!("write {path}"));
        Err(HostError::Denied("vfs not expected".into()))
    }

    async fn http_fetch(
        &self,
        req: HttpRequest,
        policy: NetPolicy,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, HostError> {
        policy.check(&req.method, &req.url)?;
        self.http_calls
            .lock()
            .unwrap()
            .push((req.method.clone(), req.url.clone()));
        let key = format!("{} {}", req.method, req.url);
        let body = self
            .responses
            .get(&key)
            .cloned()
            .ok_or_else(|| HostError::NotFound(key.clone()))?;
        assert!(body.len() <= max_response_bytes);
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body,
        })
    }

    async fn sign_hash(&self, req: SignRequest) -> Result<Vec<u8>, HostError> {
        self.sign_calls.lock().unwrap().push(req);
        Ok(vec![7u8; 65])
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("example path has workspace root")
        .to_path_buf()
}

fn wasm32_wasip1_installed(root: &Path) -> bool {
    let output = Command::new("rustup")
        .current_dir(root)
        .args(["target", "list", "--installed"])
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim() == "wasm32-wasip1")
}
