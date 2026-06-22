use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bloom_petal_manifest::extract_local_petal_manifest;
use bloom_petals::abi::{
    DispatchOp, DispatchRequest, DispatchResponse, HttpRequest, HttpResponse, SignRequest,
};
use bloom_petals::{
    HostError, NameRegistry, PetalHost, PetalMode, PetalRouter, PetalRunner, PetalStore, PetalVm,
    RunOptions,
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
    assert_eq!(manifest.net.as_ref().unwrap().allow.len(), 5);

    let tmp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(tmp.path().join("store")).unwrap();
    let registry = Arc::new(NameRegistry::open(tmp.path().join("names")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    let (install, _) = runner
        .install(&wasm, None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();
    let private = PrivateStore::open(tmp.path().join("data")).unwrap();

    let blocked_host = Arc::new(MockHost::fixture_with_geoblock_body(
        br#"{"blocked":true,"country":"XX","region":"YY"}"#,
    ));
    let blocked = dispatch_onboard_begin(&runner, blocked_host.clone()).await;
    assert!(matches!(
        blocked,
        DispatchResponse::Error { code: -3, message } if message.contains("country=XX")
    ));
    assert_eq!(blocked_host.sign_calls.lock().unwrap().len(), 0);
    assert_no_onboard_private_state(&private, &install.hash);

    let invalid_geo_host = Arc::new(MockHost::fixture_with_geoblock_body(b"<html>nope</html>"));
    let invalid_geo = dispatch_onboard_begin(&runner, invalid_geo_host.clone()).await;
    assert!(matches!(
        invalid_geo,
        DispatchResponse::Error { code: -3, message } if message.contains("could not verify region availability")
    ));
    assert_eq!(invalid_geo_host.sign_calls.lock().unwrap().len(), 0);
    assert_no_onboard_private_state(&private, &install.hash);

    let denied_geo_host = Arc::new(MockHost::fixture_with_geoblock_response(
        br#"{"blocked":false}"#,
        403,
    ));
    let denied_geo = dispatch_onboard_begin(&runner, denied_geo_host.clone()).await;
    assert!(matches!(
        denied_geo,
        DispatchResponse::Error { code: -3, message } if message.contains("geoblock status 403")
    ));
    assert_eq!(denied_geo_host.sign_calls.lock().unwrap().len(), 0);
    assert_no_onboard_private_state(&private, &install.hash);

    let host = Arc::new(MockHost::fixture());
    let router = PetalRouter::new(runner.clone(), host.clone());

    let root_entries = router
        .list(&VfsPath::parse("polymarket").unwrap())
        .await
        .unwrap();
    assert!(root_entries.iter().any(|entry| entry.name == "markets"));
    assert!(root_entries.iter().any(|entry| entry.name == "trade"));

    for root in ["positions", "onboard", "account", "fund", "trade"] {
        let entries = router
            .list(&VfsPath::parse(&format!("polymarket/{root}")).unwrap())
            .await
            .unwrap();
        assert!(
            entries.iter().any(|entry| entry.name == "alice"),
            "{root} should enumerate keystore wallet alice"
        );
    }

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

    let positions = router
        .read(&VfsPath::parse("polymarket/positions/alice/positions.json").unwrap())
        .await
        .unwrap();
    let positions_text = String::from_utf8(positions).unwrap();
    assert!(positions_text.contains("Example Position"));
    let alias_positions = router
        .read(&VfsPath::parse("polymarket/positions/0xalice/positions.json").unwrap())
        .await
        .unwrap();
    let alias_positions_text = String::from_utf8(alias_positions).unwrap();
    assert!(alias_positions_text.contains("Alias Position"));

    let book = router
        .read(&VfsPath::parse("polymarket/markets/test-market/book.json").unwrap())
        .await
        .unwrap();
    let book: serde_json::Value = serde_json::from_slice(&book).unwrap();
    assert_eq!(book["asset_id"], "111");

    router
        .write(
            &VfsPath::parse("polymarket/onboard/alice/begin").unwrap(),
            b"go",
        )
        .await
        .unwrap();
    let status = wait_for_creds(&router).await;
    assert_eq!(status["creds_present"], true);
    assert_eq!(status["deposit_wallet"]["fundable"], false);
    assert_eq!(
        status["deposit_wallet"]["source"],
        "local_estimate_unverified"
    );
    let approvals = router
        .read(&VfsPath::parse("polymarket/onboard/alice/approvals.json").unwrap())
        .await
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&approvals).unwrap();
    assert_eq!(approvals["deposit_wallet_fundable"], false);
    assert_eq!(approvals["calls"].as_array().unwrap().len(), 8);
    assert_eq!(host.sign_calls.lock().unwrap().len(), 1);

    let status_key = "onboard/alice/status.json";
    let saved_status = private.get(&install.hash, status_key).unwrap();
    private
        .put(
            &install.hash,
            status_key,
            br#"{"wallet":"alice","owner":"0x0000000000000000000000000000000000000001","stage":"creds","creds_present":true,"tradeable":false,"deposit_wallet":{"address":"0x0000000000000000000000000000000000000002","source":"stale","fundable":true}}"#,
            false,
        )
        .unwrap();
    assert!(
        router
            .read(&VfsPath::parse("polymarket/account/alice/portfolio.json").unwrap())
            .await
            .is_err()
    );
    private
        .put(&install.hash, status_key, &saved_status, false)
        .unwrap();

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
    let revalidate_hint = router
        .read(&VfsPath::parse("polymarket/trade/alice/drafts/0001/revalidate").unwrap())
        .await
        .unwrap();
    assert!(
        String::from_utf8(revalidate_hint)
            .unwrap()
            .contains("revalidate")
    );
    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/drafts/0001/revalidate").unwrap(),
            br#"{"revalidate":true}"#,
        )
        .await
        .unwrap();
    let revalidated = private
        .get(&install.hash, "trade/alice/drafts/0001/order.json")
        .unwrap();
    let revalidated_text = String::from_utf8(revalidated).unwrap();
    assert!(revalidated_text.contains(r#""status": "revalidated""#));
    let final_review = router
        .read(&VfsPath::parse("polymarket/trade/alice/drafts/0001/review_intent.json").unwrap())
        .await
        .unwrap();
    let final_review_text = String::from_utf8(final_review).unwrap();
    assert!(final_review_text.contains("final_review_staged"));
    assert!(final_review_text.contains(r#""posting_enabled": false"#));
    assert_eq!(host.sign_calls.lock().unwrap().len(), 1);

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();
    let blocked_revalidate_host = Arc::new(MockHost::fixture_with_geoblock_body(
        br#"{"blocked":true,"country":"XX","region":"YY"}"#,
    ));
    let blocked_revalidate =
        dispatch_trade_revalidate(&runner, blocked_revalidate_host.clone(), "0002").await;
    assert!(matches!(
        blocked_revalidate,
        DispatchResponse::Error { code: -3, message } if message.contains("country=XX")
    ));
    assert_eq!(blocked_revalidate_host.sign_calls.lock().unwrap().len(), 0);
    assert!(matches!(
        private.get(&install.hash, "trade/alice/receipts/0002/receipt.json"),
        Err(HostError::NotFound(_))
    ));

    let drift_host = Arc::new(MockHost::fixture_with_trade_market(
        br#"{"slug":"test-market","conditionId":"changed","clobTokenIds":["333","444"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#,
        "333",
    ));
    let drift = dispatch_trade_revalidate(&runner, drift_host.clone(), "0002").await;
    assert!(matches!(
        drift,
        DispatchResponse::Error { code: -3, message } if message.contains("token id changed")
    ));
    assert_eq!(drift_host.sign_calls.lock().unwrap().len(), 0);
    assert!(matches!(
        private.get(&install.hash, "trade/alice/receipts/0002/receipt.json"),
        Err(HostError::NotFound(_))
    ));
    let condition_drift_host = Arc::new(MockHost::fixture_with_trade_market(
        br#"{"slug":"test-market","conditionId":"changed","clobTokenIds":["111","222"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#,
        "111",
    ));
    let condition_drift =
        dispatch_trade_revalidate(&runner, condition_drift_host.clone(), "0002").await;
    assert!(matches!(
        condition_drift,
        DispatchResponse::Error { code: -3, message } if message.contains("condition id changed")
    ));
    assert_eq!(condition_drift_host.sign_calls.lock().unwrap().len(), 0);

    let neg_risk_drift_host = Arc::new(MockHost::fixture_with_trade_market_and_book(
        br#"{"slug":"test-market","conditionId":"cond","clobTokenIds":["111","222"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true,"negRisk":true}"#,
        "111",
        br#"{"market":"cond","asset_id":"111","tick_size":"0.01","min_order_size":"1","neg_risk":true,"last_trade_price":"0.09","bids":[{"price":"0.08","size":"10"}],"asks":[{"price":"0.09","size":"10"}]}"#,
    ));
    let neg_risk_drift =
        dispatch_trade_revalidate(&runner, neg_risk_drift_host.clone(), "0002").await;
    assert!(matches!(
        neg_risk_drift,
        DispatchResponse::Error { code: -3, message } if message.contains("neg-risk changed")
    ));
    assert_eq!(neg_risk_drift_host.sign_calls.lock().unwrap().len(), 0);

    let draft = private
        .get(&install.hash, "trade/alice/drafts/0001/order.json")
        .unwrap();
    assert!(String::from_utf8(draft).unwrap().contains("test-market"));
    let creds = private.get(&install.hash, "creds/alice/clob.json").unwrap();
    let creds_text = String::from_utf8(creds).unwrap();
    assert!(creds_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let account = router
        .read(&VfsPath::parse("polymarket/account/alice/portfolio.json").unwrap())
        .await
        .unwrap();
    let account_text = String::from_utf8(account).unwrap();
    assert!(account_text.contains("credentials_present"));
    assert!(account_text.contains("clob_balance_allowance"));
    assert!(account_text.contains("deposit_wallet"));
    assert!(account_text.contains("onboarding_state"));
    assert!(!account_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let orders = router
        .read(&VfsPath::parse("polymarket/account/alice/orders.json").unwrap())
        .await
        .unwrap();
    let orders_text = String::from_utf8(orders).unwrap();
    assert!(orders_text.contains("order-1"));
    assert!(!orders_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));

    let vfs_calls = host.vfs_calls.lock().unwrap().clone();
    assert!(
        vfs_calls
            .iter()
            .filter(|call| *call == "list wallets")
            .count()
            >= 5
    );
    assert!(
        vfs_calls
            .iter()
            .filter(|call| call.starts_with("read "))
            .all(|call| matches!(
                call.as_str(),
                "read wallets/alice/address" | "read wallets/0xalice/address"
            ))
    );
    let http_calls = host.http_calls.lock().unwrap();
    assert!(
        http_calls
            .iter()
            .any(|(_, url)| url == "https://polymarket.com/api/geoblock")
    );
    assert!(
        !http_calls
            .iter()
            .any(|(method, url)| method == "POST" && url == "https://clob.polymarket.com/order")
    );
    drop(http_calls);
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

async fn dispatch_onboard_begin(runner: &PetalRunner, host: Arc<MockHost>) -> DispatchResponse {
    runner
        .dispatch_mount(
            "polymarket",
            DispatchRequest {
                op: DispatchOp::Write,
                path: "onboard/alice/begin".into(),
                body: b"go".to_vec(),
                ctx: Vec::new(),
            },
            host,
            None,
            RunOptions::default(),
        )
        .await
        .unwrap()
        .response
}

async fn dispatch_trade_revalidate(
    runner: &PetalRunner,
    host: Arc<MockHost>,
    id: &str,
) -> DispatchResponse {
    runner
        .dispatch_mount(
            "polymarket",
            DispatchRequest {
                op: DispatchOp::Write,
                path: format!("trade/alice/drafts/{id}/revalidate"),
                body: br#"{"revalidate":true}"#.to_vec(),
                ctx: Vec::new(),
            },
            host,
            None,
            RunOptions::default(),
        )
        .await
        .unwrap()
        .response
}

fn assert_no_onboard_private_state(private: &PrivateStore, hash: &str) {
    assert!(
        matches!(
            private.get(hash, "creds/alice/clob.json"),
            Err(HostError::NotFound(_))
        ),
        "blocked geoblock must not write CLOB credentials"
    );
    assert!(
        matches!(
            private.get(hash, "onboard/alice/status.json"),
            Err(HostError::NotFound(_))
        ),
        "blocked geoblock must not write onboarding status"
    );
}

#[derive(Default)]
struct MockHost {
    responses: BTreeMap<String, Vec<u8>>,
    statuses: BTreeMap<String, u16>,
    http_calls: Mutex<Vec<(String, String)>>,
    vfs_calls: Mutex<Vec<String>>,
    sign_calls: Mutex<Vec<SignRequest>>,
}

impl MockHost {
    fn fixture() -> Self {
        Self::fixture_with_geoblock_body(
            br#"{"blocked":false,"ip":"1.2.3.4","country":"AR","region":"X"}"#,
        )
    }

    fn fixture_with_geoblock_body(geoblock_body: &[u8]) -> Self {
        Self::fixture_with_geoblock_response(geoblock_body, 200)
    }

    fn fixture_with_trade_market(market_body: &[u8], token_id: &str) -> Self {
        Self::fixture_with_trade_market_and_book(
            market_body,
            token_id,
            format!(
                r#"{{"market":"changed","asset_id":"{token_id}","tick_size":"0.01","min_order_size":"1","neg_risk":false,"last_trade_price":"0.09","bids":[{{"price":"0.08","size":"10"}}],"asks":[{{"price":"0.09","size":"10"}}]}}"#
            )
            .as_bytes(),
        )
    }

    fn fixture_with_trade_market_and_book(
        market_body: &[u8],
        token_id: &str,
        book_body: &[u8],
    ) -> Self {
        let mut host = Self::fixture();
        host.responses.insert(
            "GET https://gamma-api.polymarket.com/markets/slug/test-market".into(),
            market_body.to_vec(),
        );
        host.responses.insert(
            format!("GET https://clob.polymarket.com/book?token_id={token_id}"),
            book_body.to_vec(),
        );
        host
    }

    fn fixture_with_geoblock_response(geoblock_body: &[u8], geoblock_status: u16) -> Self {
        let mut host = Self::default();
        host.responses.insert(
            "GET https://gamma-api.polymarket.com/markets?closed=false&limit=20&order=volumeNum&ascending=false".into(),
            br#"[{"slug":"test-market","conditionId":"cond","clobTokenIds":["111","222"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}]"#.to_vec(),
        );
        host.responses.insert(
            "GET https://gamma-api.polymarket.com/markets/slug/test-market".into(),
            br#"{"slug":"test-market","conditionId":"cond","clobTokenIds":["111","222"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://data-api.polymarket.com/positions?user=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            br#"[{"title":"Example Position","asset":"111","conditionId":"cond","outcome":"Yes"}]"#.to_vec(),
        );
        host.responses.insert(
            "GET https://data-api.polymarket.com/positions?user=0x0000000000000000000000000000000000000001".into(),
            br#"[{"title":"Alias Position","asset":"222","conditionId":"cond","outcome":"No"}]"#.to_vec(),
        );
        host.responses.insert(
            "GET https://polymarket.com/api/geoblock".into(),
            geoblock_body.to_vec(),
        );
        host.statuses.insert(
            "GET https://polymarket.com/api/geoblock".into(),
            geoblock_status,
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/book?token_id=111".into(),
            br#"{"market":"cond","asset_id":"111","tick_size":"0.01","min_order_size":"1","neg_risk":false,"last_trade_price":"0.09","bids":[{"price":"0.08","size":"10"}],"asks":[{"price":"0.09","size":"10"}]}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/midpoint?token_id=111".into(),
            br#"{"mid":"0.42"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/spread?token_id=111".into(),
            br#"{"spread":"0.01"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/price?token_id=111&side=BUY".into(),
            br#"{"price":"0.43"}"#.to_vec(),
        );
        host.responses.insert(
            "POST https://clob.polymarket.com/auth/api-key".into(),
            br#"{"apiKey":"api-key","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","passphrase":"pass-value"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/balance-allowance?asset_type=COLLATERAL&signature_type=3".into(),
            br#"{"balance":"123","allowance":"456"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/data/orders".into(),
            br#"[{"id":"order-1","status":"LIVE"}]"#.to_vec(),
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
        } else if path == "wallets/0xalice/address" {
            Ok(b"0x0000000000000000000000000000000000000001\n".to_vec())
        } else {
            Err(HostError::NotFound(path.into()))
        }
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
        self.vfs_calls.lock().unwrap().push(format!("list {path}"));
        if path == "wallets" {
            Ok(vec!["alice".into(), "0xalice".into(), "new".into()])
        } else {
            Err(HostError::Denied("vfs not expected".into()))
        }
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
        let status = self.statuses.get(&key).copied().unwrap_or(200);
        assert!(body.len() <= max_response_bytes);
        Ok(HttpResponse {
            status,
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

async fn wait_for_creds(router: &PetalRouter) -> serde_json::Value {
    let path = VfsPath::parse("polymarket/onboard/alice/status.json").unwrap();
    for _ in 0..50 {
        let status = router.read(&path).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        if status["creds_present"] == true {
            return status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let status = router.read(&path).await.unwrap();
    serde_json::from_slice(&status).unwrap()
}
