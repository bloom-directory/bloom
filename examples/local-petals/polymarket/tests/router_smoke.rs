use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
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
use bloom_polymarket::eip712::{CTF, PUSD};
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
        vec!["vfs.read", "vfs.write", "net.fetch", "sign", "store"]
    );
    assert_eq!(manifest.net.as_ref().unwrap().allow.len(), 7);

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

    let clob_auth_error_host = Arc::new(MockHost::fixture_with_clob_auth_error());
    let clob_auth_error = dispatch_onboard_begin(&runner, clob_auth_error_host.clone()).await;
    assert!(matches!(
        clob_auth_error,
        DispatchResponse::Error { code: -4, message }
            if message.contains("CLOB auth error (status 500)")
                && !message.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                && !message.contains("pass-value")
    ));
    assert_eq!(clob_auth_error_host.sign_calls.lock().unwrap().len(), 1);
    assert_no_onboard_private_state(&private, &install.hash);

    let host = Arc::new(MockHost::fixture());
    let router = PetalRouter::new(runner.clone(), host.clone());

    let root_entries = router
        .list(&VfsPath::parse("polymarket").unwrap())
        .await
        .unwrap();
    assert!(root_entries.iter().any(|entry| entry.name == "markets"));
    assert!(root_entries.iter().any(|entry| entry.name == "trade"));
    assert!(root_entries.iter().any(|entry| entry.name == "meta"));
    let parity = router
        .read(&VfsPath::parse("polymarket/meta/parity.json").unwrap())
        .await
        .unwrap();
    let parity_text = String::from_utf8(parity).unwrap();
    let parity_json: serde_json::Value = serde_json::from_str(&parity_text).unwrap();
    assert_eq!(parity_json["kind"], "polymarket_local_petal_parity");
    assert_eq!(parity_json["graduation_ready"], false);
    assert!(parity_json["implemented"].as_array().unwrap().len() >= 7);
    assert!(
        parity_json["implemented"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "authoritative_sell_posting")
    );
    assert!(
        parity_json["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "graduation_signoff")
    );
    assert!(
        parity_json["native_unsupported_or_deferred"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "gtd_orders")
    );
    assert!(!parity_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(!parity_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));
    assert!(!parity_text.contains("builder-pass"));
    assert!(
        router
            .write(
                &VfsPath::parse("polymarket/meta/parity.json").unwrap(),
                b"{}"
            )
            .await
            .is_err()
    );

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
    assert_eq!(status["stage"], "complete");
    assert_eq!(status["tradeable"], true);
    assert_eq!(status["deposit_wallet"]["fundable"], true);
    assert_eq!(status["deposit_wallet"]["source"], "live_factory_resolved");
    assert_eq!(status["probes"]["deposit_wallet_deployed"], true);
    assert_eq!(status["probes"]["approvals_in_place"], true);
    assert_eq!(status["probes"]["clob_collateral_synced"], true);
    let approvals = router
        .read(&VfsPath::parse("polymarket/onboard/alice/approvals.json").unwrap())
        .await
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&approvals).unwrap();
    assert_eq!(approvals["deposit_wallet_fundable"], true);
    assert_eq!(approvals["deposit_wallet_source"], "live_factory_resolved");
    assert_eq!(approvals["calls"].as_array().unwrap().len(), 8);
    assert_eq!(host.sign_calls.lock().unwrap().len(), 1);

    let status_key = "onboard/alice/status.json";
    let approval_host = Arc::new(MockHost::fixture_with_pusd_allowance(false));
    let approval_run = dispatch_onboard_begin(&runner, approval_host.clone()).await;
    assert!(matches!(approval_run, DispatchResponse::Write));
    assert!(
        approval_host
            .http_bodies
            .lock()
            .unwrap()
            .iter()
            .any(|(method, url, body)| method == "POST"
                && url == "https://relayer-v2.polymarket.com/submit"
                && String::from_utf8_lossy(body).contains(r#""type":"WALLET""#))
    );
    assert!(
        approval_host
            .vfs_writes
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path.contains("/methods/allowance@"))
    );
    assert_eq!(approval_host.sign_calls.lock().unwrap().len(), 2);
    let approved_status = private.get(&install.hash, status_key).unwrap();
    let approved_status: serde_json::Value = serde_json::from_slice(&approved_status).unwrap();
    assert_eq!(approved_status["stage"], "complete");
    assert_eq!(approved_status["approve_tx_id"], "tx-approve");
    assert_eq!(approved_status["relayer_auth"], "builder_key_auto");
    assert_eq!(approved_status["last_error"], serde_json::Value::Null);
    let builder_creds = private
        .get(&install.hash, "creds/alice/builder.json")
        .unwrap();
    let builder_creds_text = String::from_utf8(builder_creds).unwrap();
    assert!(builder_creds_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));
    assert!(builder_creds_text.contains("builder-pass"));
    let approved_status_text = String::from_utf8(
        private
            .get(&install.hash, "onboard/alice/status.json")
            .unwrap(),
    )
    .unwrap();
    assert!(!approved_status_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));
    assert!(!approved_status_text.contains("builder-pass"));

    let relayer_error_host = Arc::new(MockHost::fixture_with_relayer_submit_error(
        500,
        br#"{"error":"echo YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ= builder-pass"}"#,
    ));
    let relayer_error = dispatch_onboard_begin(&runner, relayer_error_host.clone()).await;
    assert!(matches!(
        relayer_error,
        DispatchResponse::Error { code: -4, message }
            if message.contains("relayer error (status 500)")
                && message.contains("redacted")
                && !message.contains("builder-pass")
                && !message.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ=")
    ));
    let relayer_error_status = private.get(&install.hash, status_key).unwrap();
    let relayer_error_status_text = String::from_utf8(relayer_error_status).unwrap();
    assert!(relayer_error_status_text.contains("relayer error (status 500)"));
    assert!(relayer_error_status_text.contains("redacted"));
    assert!(relayer_error_status_text.contains(r#""in_flight_deadline_ms": null"#));
    assert!(!relayer_error_status_text.contains("builder-pass"));
    assert!(!relayer_error_status_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));

    let sync_error_host = Arc::new(MockHost::fixture_with_sync_error());
    let sync_error = dispatch_onboard_begin(&runner, sync_error_host.clone()).await;
    assert!(matches!(
        sync_error,
        DispatchResponse::Error { code: -4, message } if message.contains("CLOB account error (status 500)")
    ));
    let sync_error_status = private.get(&install.hash, status_key).unwrap();
    let sync_error_status_text = String::from_utf8(sync_error_status).unwrap();
    assert!(
        sync_error_status_text.contains("CLOB account error (status 500): response body redacted")
    );
    assert!(!sync_error_status_text.contains("sync failed"));
    assert!(sync_error_status_text.contains(r#""in_flight_deadline_ms": null"#));

    let saved_status = private.get(&install.hash, status_key).unwrap();
    private
        .put(
            &install.hash,
            status_key,
            br#"{"wallet":"alice","owner":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","stage":"creds","creds_present":true,"tradeable":true,"deposit_wallet":{"address":"0x0000000000000000000000000000000000000002","source":"stale","fundable":true}}"#,
            false,
        )
        .unwrap();
    let stale_approvals = router
        .read(&VfsPath::parse("polymarket/onboard/alice/approvals.json").unwrap())
        .await
        .unwrap();
    let stale_approvals: serde_json::Value = serde_json::from_slice(&stale_approvals).unwrap();
    assert_eq!(stale_approvals["deposit_wallet_fundable"], false);
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
    let not_ready = dispatch_trade_revalidate(
        &runner,
        Arc::new(MockHost::fixture_with_deposit_deployed(false)),
        "0001",
    )
    .await;
    assert!(matches!(
        not_ready,
        DispatchResponse::Error { code: -3, message } if message.contains("wallet onboarding is not complete")
    ));
    let created_review = private
        .get(&install.hash, "trade/alice/drafts/0001/review_intent.json")
        .unwrap();
    let created_review: serde_json::Value = serde_json::from_slice(&created_review).unwrap();
    assert_eq!(created_review["status"], "created");
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
    assert!(final_review_text.contains(r#""posting_enabled": true"#));
    assert_eq!(host.sign_calls.lock().unwrap().len(), 1);

    let stale_denied_host = Arc::new(MockHost::fixture_with_policy(b""));
    let stale_denied = dispatch_trade_revalidate(&runner, stale_denied_host.clone(), "0001").await;
    assert!(matches!(
        stale_denied,
        DispatchResponse::Error { code: -3, message } if message.contains("policy denied")
    ));
    assert_eq!(stale_denied_host.sign_calls.lock().unwrap().len(), 0);
    assert!(matches!(
        private.get(&install.hash, "trade/alice/drafts/0001/review_intent.json"),
        Err(HostError::NotFound(_))
    ));
    let denied_order = private
        .get(&install.hash, "trade/alice/drafts/0001/order.json")
        .unwrap();
    assert!(
        String::from_utf8(denied_order)
            .unwrap()
            .contains(r#""status": "policy_denied""#)
    );

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

    let denied_policy_host = Arc::new(MockHost::fixture_with_policy(b""));
    let denied_policy =
        dispatch_trade_revalidate(&runner, denied_policy_host.clone(), "0002").await;
    assert!(matches!(
        denied_policy,
        DispatchResponse::Error { code: -3, message } if message.contains("policy denied")
    ));
    assert_eq!(denied_policy_host.sign_calls.lock().unwrap().len(), 0);
    let policy_check = private
        .get(&install.hash, "trade/alice/drafts/0002/policy_check.json")
        .unwrap();
    let policy_check_text = String::from_utf8(policy_check).unwrap();
    assert!(policy_check_text.contains(r#""policy_status": "denied""#));
    assert!(policy_check_text.contains(r#""outcome": "deny""#));
    assert!(policy_check_text.contains("polymarket.enabled"));

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();
    let audit_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let audit_line = format!(
        r#"{{"ts_ms":{audit_ms},"event":"receipt_written","details":{{"draft_id":"0099","clob_status":"matched","amount_microusd":1000000}}}}
"#
    );
    private
        .put(
            &install.hash,
            "trade/alice/audit.jsonl",
            audit_line.as_bytes(),
            false,
        )
        .unwrap();
    let truncated_receipts =
        dispatch_trade_revalidate(&runner, Arc::new(MockHost::fixture()), "0003").await;
    assert!(matches!(
        truncated_receipts,
        DispatchResponse::Error { code: -3, message } if message.contains("policy denied")
    ));
    let policy_check = private
        .get(&install.hash, "trade/alice/drafts/0003/policy_check.json")
        .unwrap();
    let policy_check_text = String::from_utf8(policy_check).unwrap();
    assert!(policy_check_text.contains(r#""receipt_audit_parity": true"#));
    assert!(policy_check_text.contains(r#""receipt_store_readable": false"#));
    assert!(policy_check_text.contains("polymarket.max_daily_usd"));

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();

    let drift_host = Arc::new(MockHost::fixture_with_trade_market(
        br#"{"slug":"test-market","conditionId":"changed","clobTokenIds":["333","444"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#,
        "333",
    ));
    let drift = dispatch_trade_revalidate(&runner, drift_host.clone(), "0004").await;
    assert!(matches!(
        drift,
        DispatchResponse::Error { code: -3, message } if message.contains("token id changed")
    ));
    assert_eq!(drift_host.sign_calls.lock().unwrap().len(), 0);
    assert!(matches!(
        private.get(&install.hash, "trade/alice/receipts/0004/receipt.json"),
        Err(HostError::NotFound(_))
    ));
    let condition_drift_host = Arc::new(MockHost::fixture_with_trade_market(
        br#"{"slug":"test-market","conditionId":"changed","clobTokenIds":["111","222"],"outcomes":["Yes","No"],"active":true,"closed":false,"enableOrderBook":true}"#,
        "111",
    ));
    let condition_drift =
        dispatch_trade_revalidate(&runner, condition_drift_host.clone(), "0004").await;
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
        dispatch_trade_revalidate(&runner, neg_risk_drift_host.clone(), "0004").await;
    assert!(matches!(
        neg_risk_drift,
        DispatchResponse::Error { code: -3, message } if message.contains("neg-risk changed")
    ));
    assert_eq!(neg_risk_drift_host.sign_calls.lock().unwrap().len(), 0);

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","side":"sell","amount":"1","min_price":"0.05"}"#,
        )
        .await
        .unwrap();
    let sell_revalidated =
        dispatch_trade_revalidate(&runner, Arc::new(MockHost::fixture()), "0005").await;
    assert!(matches!(sell_revalidated, DispatchResponse::Write));
    let sell_review = private
        .get(&install.hash, "trade/alice/drafts/0005/review_intent.json")
        .unwrap();
    let sell_review_text = String::from_utf8(sell_review).unwrap();
    assert!(sell_review_text.contains("final_review_staged"));
    assert!(sell_review_text.contains("sell_preflight"));
    assert!(sell_review_text.contains(r#""status": "pass""#));
    assert!(sell_review_text.contains(r#""preflight_complete_for_posting": true"#));
    assert!(sell_review_text.contains("clob_conditional_balance_and_chain_ctf"));
    assert!(sell_review_text.contains(r#""chain_ctf_balance_checked": true"#));
    assert!(sell_review_text.contains(r#""ctf_approval_checked": true"#));
    assert!(sell_review_text.contains(r#""posting_enabled": true"#));

    let sell_denied = dispatch_trade_revalidate(
        &runner,
        Arc::new(MockHost::fixture_with_chain_ctf_balance_micro(500_000)),
        "0005",
    )
    .await;
    assert!(matches!(
        sell_denied,
        DispatchResponse::Error { code: -3, message } if message.contains("cannot sell")
    ));
    assert!(matches!(
        private.get(&install.hash, "trade/alice/drafts/0005/review_intent.json"),
        Err(HostError::NotFound(_))
    ));
    let sell_order = private
        .get(&install.hash, "trade/alice/drafts/0005/order.json")
        .unwrap();
    assert!(
        String::from_utf8(sell_order)
            .unwrap()
            .contains(r#""status": "preflight_denied""#)
    );

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","side":"sell","amount":"1","min_price":"0.05"}"#,
        )
        .await
        .unwrap();
    let lock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    private
        .put(
            &install.hash,
            "trade/alice/.lock",
            format!(r#"{{"wallet":"alice","acquired_ms":{lock_ms}}}"#).as_bytes(),
            false,
        )
        .unwrap();
    let locked = dispatch_trade_revalidate(&runner, Arc::new(MockHost::fixture()), "0006").await;
    assert!(matches!(
        locked,
        DispatchResponse::Error { code: -3, message } if message.contains("holds the lock")
    ));
    let locked_review = private
        .get(&install.hash, "trade/alice/drafts/0006/review_intent.json")
        .unwrap();
    let locked_review_text = String::from_utf8(locked_review).unwrap();
    assert!(locked_review_text.contains(r#""status": "created""#));
    assert!(!locked_review_text.contains("final_review_staged"));
    private
        .put(
            &install.hash,
            "trade/alice/.lock",
            br#"{"wallet":"alice","acquired_ms":0}"#,
            false,
        )
        .unwrap();
    let stale_lock_revalidated =
        dispatch_trade_revalidate(&runner, Arc::new(MockHost::fixture()), "0006").await;
    assert!(matches!(stale_lock_revalidated, DispatchResponse::Write));
    assert!(matches!(
        private.get(&install.hash, "trade/alice/.lock"),
        Err(HostError::NotFound(_))
    ));

    private
        .del(&install.hash, "trade/alice/audit.jsonl")
        .unwrap();
    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();
    let post_revalidated =
        dispatch_trade_revalidate(&runner, Arc::new(MockHost::fixture()), "0007").await;
    assert!(matches!(post_revalidated, DispatchResponse::Write));
    let post_hint = router
        .read(&VfsPath::parse("polymarket/trade/alice/drafts/0007/post").unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(post_hint).unwrap().contains("post"));
    let posted = dispatch_trade_post(&runner, host.clone(), "0007").await;
    assert!(matches!(posted, DispatchResponse::Write));
    let posted_order = private
        .get(&install.hash, "trade/alice/drafts/0007/order.json")
        .unwrap();
    let posted_order_text = String::from_utf8(posted_order).unwrap();
    assert!(posted_order_text.contains(r#""status": "posted""#));
    assert!(posted_order_text.contains(r#""clob_order_id": "order-post-1""#));
    let post_attempt = private
        .get(&install.hash, "trade/alice/drafts/0007/post_attempt.json")
        .unwrap();
    let post_attempt_text = String::from_utf8(post_attempt).unwrap();
    assert!(post_attempt_text.contains("order_body_blake3"));
    assert!(!post_attempt_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let receipt = private
        .get(&install.hash, "trade/alice/receipts/0007/receipt.json")
        .unwrap();
    let receipt_text = String::from_utf8(receipt).unwrap();
    assert!(receipt_text.contains(r#""clob_status": "matched""#));
    assert!(receipt_text.contains(r#""clob_order_id": "order-post-1""#));
    assert!(receipt_text.contains("response_redacted"));
    assert!(!receipt_text.contains("0xechoed-signature"));
    assert!(!receipt_text.contains("requestBody"));
    assert!(!receipt_text.contains("accepted signature"));
    assert!(!receipt_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let audit = private
        .get(&install.hash, "trade/alice/audit.jsonl")
        .unwrap();
    let audit_text = String::from_utf8(audit).unwrap();
    assert!(audit_text.contains("receipt_written"));
    assert!(audit_text.contains("0007"));
    assert_eq!(host.sign_calls.lock().unwrap().len(), 2);
    let cancel_hint = router
        .read(&VfsPath::parse("polymarket/trade/alice/receipts/0007/cancel").unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(cancel_hint).unwrap().contains("cancel"));
    let cancelled = dispatch_trade_cancel(&runner, host.clone(), "0007").await;
    assert!(matches!(cancelled, DispatchResponse::Write));
    let cancelled_receipt = private
        .get(&install.hash, "trade/alice/receipts/0007/receipt.json")
        .unwrap();
    let cancelled_receipt_text = String::from_utf8(cancelled_receipt).unwrap();
    assert!(cancelled_receipt_text.contains(r#""clob_status": "cancelled""#));
    assert!(cancelled_receipt_text.contains("response_redacted"));
    assert!(!cancelled_receipt_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let cancelled_order = private
        .get(&install.hash, "trade/alice/drafts/0007/order.json")
        .unwrap();
    assert!(
        String::from_utf8(cancelled_order)
            .unwrap()
            .contains(r#""status": "cancelled""#)
    );
    let cancel_audit = private
        .get(&install.hash, "trade/alice/audit.jsonl")
        .unwrap();
    assert!(
        String::from_utf8(cancel_audit)
            .unwrap()
            .contains("order_cancelled")
    );
    assert_eq!(host.sign_calls.lock().unwrap().len(), 2);
    assert!(
        host.http_bodies
            .lock()
            .unwrap()
            .iter()
            .any(|(method, url, body)| method == "DELETE"
                && url == "https://clob.polymarket.com/order"
                && body == br#"{"orderID":"order-post-1"}"#)
    );
    let delete_count_after_cancel = host
        .http_bodies
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, url, _)| method == "DELETE" && url == "https://clob.polymarket.com/order")
        .count();
    let mut stale_cancelled_order: serde_json::Value = serde_json::from_slice(
        &private
            .get(&install.hash, "trade/alice/drafts/0007/order.json")
            .unwrap(),
    )
    .unwrap();
    stale_cancelled_order["status"] = "posted".into();
    stale_cancelled_order["clob_status"] = "matched".into();
    private
        .put(
            &install.hash,
            "trade/alice/drafts/0007/order.json",
            &serde_json::to_vec_pretty(&stale_cancelled_order).unwrap(),
            false,
        )
        .unwrap();
    let idempotent_cancel = dispatch_trade_cancel(&runner, host.clone(), "0007").await;
    assert!(matches!(idempotent_cancel, DispatchResponse::Write));
    let delete_count_after_retry = host
        .http_bodies
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, url, _)| method == "DELETE" && url == "https://clob.polymarket.com/order")
        .count();
    assert_eq!(delete_count_after_retry, delete_count_after_cancel);
    let repaired_order = private
        .get(&install.hash, "trade/alice/drafts/0007/order.json")
        .unwrap();
    assert!(
        String::from_utf8(repaired_order)
            .unwrap()
            .contains(r#""status": "cancelled""#)
    );

    let gtc_host = Arc::new(MockHost::fixture_with_order_id("order-post-gtc"));
    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10","limit_price":"0.10","order_type":"GTC"}"#,
        )
        .await
        .unwrap();
    let gtc_revalidated = dispatch_trade_revalidate(&runner, gtc_host.clone(), "0008").await;
    assert!(matches!(gtc_revalidated, DispatchResponse::Write));
    let gtc_posted = dispatch_trade_post(&runner, gtc_host.clone(), "0008").await;
    assert!(matches!(gtc_posted, DispatchResponse::Write));
    let gtc_receipt = private
        .get(&install.hash, "trade/alice/receipts/0008/receipt.json")
        .unwrap();
    let gtc_receipt_text = String::from_utf8(gtc_receipt).unwrap();
    assert!(gtc_receipt_text.contains(r#""order_type": "GTC""#));
    assert!(gtc_receipt_text.contains(r#""clob_order_id": "order-post-gtc""#));
    assert!(gtc_receipt_text.contains(r#""clob_status": "unmatched""#));
    let gtc_posted_order = private
        .get(&install.hash, "trade/alice/drafts/0008/order.json")
        .unwrap();
    let gtc_posted_order_text = String::from_utf8(gtc_posted_order).unwrap();
    assert!(gtc_posted_order_text.contains(r#""status": "posted""#));
    assert!(gtc_posted_order_text.contains(r#""clob_status": "unmatched""#));
    let gtc_cancelled = dispatch_trade_cancel(&runner, gtc_host.clone(), "0008").await;
    assert!(matches!(gtc_cancelled, DispatchResponse::Write));
    let gtc_cancelled_receipt = private
        .get(&install.hash, "trade/alice/receipts/0008/receipt.json")
        .unwrap();
    assert!(
        String::from_utf8(gtc_cancelled_receipt)
            .unwrap()
            .contains(r#""clob_status": "cancelled""#)
    );
    assert!(
        gtc_host
            .http_bodies
            .lock()
            .unwrap()
            .iter()
            .any(|(method, url, body)| method == "DELETE"
                && url == "https://clob.polymarket.com/order"
                && body == br#"{"orderID":"order-post-gtc"}"#)
    );
    assert_eq!(gtc_host.sign_calls.lock().unwrap().len(), 1);

    let reconcile_host = Arc::new(MockHost::fixture_with_reconciled_open_order(
        "order-reconciled-1",
    ));
    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","amount":"1","max_price":"0.10"}"#,
        )
        .await
        .unwrap();
    let reconcile_revalidated =
        dispatch_trade_revalidate(&runner, reconcile_host.clone(), "0009").await;
    assert!(matches!(reconcile_revalidated, DispatchResponse::Write));
    let reconciled_post = dispatch_trade_post(&runner, reconcile_host.clone(), "0009").await;
    assert!(matches!(reconciled_post, DispatchResponse::Write));
    let reconciled_receipt = private
        .get(&install.hash, "trade/alice/receipts/0009/receipt.json")
        .unwrap();
    let reconciled_receipt_text = String::from_utf8(reconciled_receipt).unwrap();
    assert!(reconciled_receipt_text.contains(r#""clob_status": "live""#));
    assert!(reconciled_receipt_text.contains(r#""clob_order_id": "order-reconciled-1""#));
    assert!(reconciled_receipt_text.contains(r#""reconciled_from": "open_orders""#));
    assert!(reconciled_receipt_text.contains("response_redacted"));
    assert!(!reconciled_receipt_text.contains("gateway timeout"));
    let reconciled_order = private
        .get(&install.hash, "trade/alice/drafts/0009/order.json")
        .unwrap();
    let reconciled_order_text = String::from_utf8(reconciled_order).unwrap();
    assert!(reconciled_order_text.contains(r#""status": "posted""#));
    assert!(reconciled_order_text.contains(r#""clob_order_id": "order-reconciled-1""#));
    let reconciled_attempt = private
        .get(&install.hash, "trade/alice/drafts/0009/post_attempt.json")
        .unwrap();
    let reconciled_attempt_text = String::from_utf8(reconciled_attempt).unwrap();
    assert!(reconciled_attempt_text.contains("reconciled_open_order"));
    assert!(reconciled_attempt_text.contains("order_body_blake3"));
    assert!(!reconciled_attempt_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    let reconcile_calls = reconcile_host.http_calls.lock().unwrap();
    assert!(
        reconcile_calls.iter().any(|(method, url)| {
            method == "POST" && url == "https://clob.polymarket.com/order"
        })
    );
    assert!(reconcile_calls.iter().any(|(method, url)| {
        method == "GET" && url == "https://clob.polymarket.com/data/orders"
    }));
    drop(reconcile_calls);
    assert_eq!(reconcile_host.sign_calls.lock().unwrap().len(), 1);

    let sell_post_host = Arc::new(MockHost::fixture_with_order_id("order-sell-1"));
    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market","outcome":"yes","side":"sell","amount":"1","min_price":"0.05"}"#,
        )
        .await
        .unwrap();
    let sell_post_revalidated =
        dispatch_trade_revalidate(&runner, sell_post_host.clone(), "0010").await;
    assert!(matches!(sell_post_revalidated, DispatchResponse::Write));
    let sell_posted = dispatch_trade_post(&runner, sell_post_host.clone(), "0010").await;
    assert!(matches!(sell_posted, DispatchResponse::Write));
    let sell_receipt = private
        .get(&install.hash, "trade/alice/receipts/0010/receipt.json")
        .unwrap();
    let sell_receipt_text = String::from_utf8(sell_receipt).unwrap();
    assert!(sell_receipt_text.contains(r#""side": "SELL""#));
    assert!(sell_receipt_text.contains(r#""clob_order_id": "order-sell-1""#));
    assert!(
        sell_post_host
            .http_bodies
            .lock()
            .unwrap()
            .iter()
            .any(|(method, url, body)| method == "POST"
                && url == "https://clob.polymarket.com/order"
                && String::from_utf8_lossy(body).contains(r#""side":"SELL""#))
    );
    let sell_vfs_writes = sell_post_host.vfs_writes.lock().unwrap();
    assert!(
        sell_vfs_writes
            .iter()
            .any(|(path, body)| path.contains("/methods/balanceOf@")
                && path.ends_with(".read")
                && String::from_utf8_lossy(body).contains(r#""111""#))
    );
    assert!(sell_vfs_writes.iter().any(|(path, body)| {
        path.contains("/methods/isApprovedForAll@")
            && path.ends_with(".read")
            && String::from_utf8_lossy(body).contains("0xE111180000d2663C0091e4f400237545B87B996B")
    }));
    drop(sell_vfs_writes);
    assert_eq!(sell_post_host.sign_calls.lock().unwrap().len(), 1);

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
    assert!(!account_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));
    assert!(!account_text.contains("builder-pass"));
    let orders = router
        .read(&VfsPath::parse("polymarket/account/alice/orders.json").unwrap())
        .await
        .unwrap();
    let orders_text = String::from_utf8(orders).unwrap();
    assert!(orders_text.contains("order-1"));
    assert!(!orders_text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(!orders_text.contains("YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ="));
    assert!(!orders_text.contains("builder-pass"));

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
                "read wallets/alice/address"
                    | "read wallets/alice/policy.toml"
                    | "read wallets/0xalice/address"
            ) || (call.starts_with("read chains/polygon/contracts/")
                && call.ends_with("/proxy/implementation"))
                || (call.starts_with("read chains/polygon/contracts/")
                    && (call.contains("/methods/implementation@")
                        || call.contains("/methods/predictWalletAddress@")
                        || call.contains("/methods/balanceOf@")
                        || call.contains("/methods/allowance@")
                        || call.contains("/methods/isApprovedForAll@"))
                    && call.ends_with(".read")))
    );
    let http_calls = host.http_calls.lock().unwrap();
    assert!(
        http_calls
            .iter()
            .any(|(_, url)| url == "https://polymarket.com/api/geoblock")
    );
    assert!(
        http_calls
            .iter()
            .any(|(method, url)| method == "POST" && url == "https://clob.polymarket.com/order")
    );
    assert!(
        http_calls
            .iter()
            .any(|(method, url)| method == "DELETE" && url == "https://clob.polymarket.com/order")
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

async fn dispatch_trade_post(
    runner: &PetalRunner,
    host: Arc<MockHost>,
    id: &str,
) -> DispatchResponse {
    runner
        .dispatch_mount(
            "polymarket",
            DispatchRequest {
                op: DispatchOp::Write,
                path: format!("trade/alice/drafts/{id}/post"),
                body: br#"{"post":true}"#.to_vec(),
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

async fn dispatch_trade_cancel(
    runner: &PetalRunner,
    host: Arc<MockHost>,
    id: &str,
) -> DispatchResponse {
    runner
        .dispatch_mount(
            "polymarket",
            DispatchRequest {
                op: DispatchOp::Write,
                path: format!("trade/alice/receipts/{id}/cancel"),
                body: br#"{"cancel":true}"#.to_vec(),
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
    policy_body: Vec<u8>,
    dynamic_open_order_id: Option<String>,
    deposit_wallet_deployed: bool,
    chain_pusd_balance_micro: u64,
    chain_pusd_allowance_ok: bool,
    chain_ctf_balance_micro: u64,
    chain_ctf_approved: bool,
    relayer_submit_response: Option<(u16, Vec<u8>)>,
    http_calls: Mutex<Vec<(String, String)>>,
    http_bodies: Mutex<Vec<(String, String, Vec<u8>)>>,
    vfs_calls: Mutex<Vec<String>>,
    vfs_writes: Mutex<Vec<(String, Vec<u8>)>>,
    sign_calls: Mutex<Vec<SignRequest>>,
}

impl MockHost {
    fn fixture() -> Self {
        Self::fixture_with_geoblock_body(
            br#"{"blocked":false,"ip":"1.2.3.4","country":"AR","region":"X"}"#,
        )
    }

    fn fixture_with_policy(policy_body: &[u8]) -> Self {
        let mut host = Self::fixture();
        host.policy_body = policy_body.to_vec();
        host
    }

    fn fixture_with_order_id(order_id: &str) -> Self {
        let mut host = Self::fixture();
        host.responses.insert(
            "POST https://clob.polymarket.com/order".into(),
            format!(
                r#"{{"status":"unmatched","orderID":"{order_id}","requestBody":{{"signature":"0xechoed-signature"}}}}"#
            )
            .into_bytes(),
        );
        host.responses.insert(
            "DELETE https://clob.polymarket.com/order".into(),
            format!(r#"{{"canceled":["{order_id}"],"not_canceled":{{}}}}"#).into_bytes(),
        );
        host
    }

    fn fixture_with_reconciled_open_order(order_id: &str) -> Self {
        let mut host = Self::fixture();
        host.statuses
            .insert("POST https://clob.polymarket.com/order".into(), 502);
        host.responses.insert(
            "POST https://clob.polymarket.com/order".into(),
            br#"{"error":"gateway timeout after order submit"}"#.to_vec(),
        );
        host.dynamic_open_order_id = Some(order_id.to_string());
        host
    }

    fn fixture_with_chain_ctf_balance_micro(balance_micro: u64) -> Self {
        let mut host = Self::fixture();
        host.chain_ctf_balance_micro = balance_micro;
        host
    }

    fn fixture_with_pusd_allowance(allowance_ok: bool) -> Self {
        let mut host = Self::fixture();
        host.chain_pusd_allowance_ok = allowance_ok;
        host
    }

    fn fixture_with_deposit_deployed(deployed: bool) -> Self {
        let mut host = Self::fixture();
        host.deposit_wallet_deployed = deployed;
        host
    }

    fn fixture_with_relayer_submit_error(status: u16, body: &[u8]) -> Self {
        let mut host = Self::fixture_with_pusd_allowance(false);
        host.relayer_submit_response = Some((status, body.to_vec()));
        host
    }

    fn fixture_with_sync_error() -> Self {
        let mut host = Self::fixture();
        let key = "GET https://clob.polymarket.com/balance-allowance/update?asset_type=COLLATERAL&signature_type=3";
        host.statuses.insert(key.into(), 500);
        host.responses.insert(key.into(), b"sync failed".to_vec());
        host
    }

    fn fixture_with_clob_auth_error() -> Self {
        let mut host = Self::fixture();
        for key in [
            "POST https://clob.polymarket.com/auth/api-key",
            "GET https://clob.polymarket.com/auth/derive-api-key",
        ] {
            host.statuses.insert(key.into(), 500);
            host.responses.insert(
                key.into(),
                br#"{"error":"echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= pass-value"}"#
                    .to_vec(),
            );
        }
        host
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
        host.deposit_wallet_deployed = true;
        host.chain_pusd_balance_micro = 2_000_000;
        host.chain_pusd_allowance_ok = true;
        host.chain_ctf_balance_micro = 2_000_000;
        host.chain_ctf_approved = true;
        host.policy_body = br#"[polymarket]
enabled = true
max_order_usd = "5"
max_daily_usd = "100"
max_price = "0.20"
"#
        .to_vec();
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
        let deposit = "0x3000000000000000000000000000000000000003";
        host.responses.insert(
            format!("GET https://data-api.polymarket.com/positions?user={deposit}"),
            br#"[{"title":"Sell Position","asset":"111","size":2.0}]"#.to_vec(),
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
            "POST https://clob.polymarket.com/auth/builder-api-key".into(),
            br#"{"apiKey":"builder-key","secret":"YnVpbGRlci1zZWNyZXQtYnVpbGRlci1zZWNyZXQ=","passphrase":"builder-pass"}"#.to_vec(),
        );
        host.responses.insert(
            "POST https://clob.polymarket.com/order".into(),
            br#"{"status":"matched","orderID":"order-post-1","size_matched":"11.11","requestBody":{"signature":"0xechoed-signature"},"payload":"accepted signature 0xechoed-signature"}"#.to_vec(),
        );
        host.responses.insert(
            "DELETE https://clob.polymarket.com/order".into(),
            br#"{"canceled":["order-post-1"],"not_canceled":{}}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/balance-allowance?asset_type=COLLATERAL&signature_type=3".into(),
            br#"{"balance":"2000000","allowance":"2000000"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/balance-allowance/update?asset_type=COLLATERAL&signature_type=3".into(),
            br#"{"balance":"2000000","allowance":"2000000","updated":true}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/balance-allowance?asset_type=CONDITIONAL&token_id=111&signature_type=3".into(),
            br#"{"balance":"2000000","allowance":"2000000"}"#.to_vec(),
        );
        host.responses.insert(
            "GET https://clob.polymarket.com/data/orders".into(),
            br#"[{"id":"order-1","status":"LIVE"}]"#.to_vec(),
        );
        host
    }

    fn relayer_submit_seen(&self, needle: &str) -> bool {
        self.http_bodies
            .lock()
            .unwrap()
            .iter()
            .any(|(method, url, body)| {
                method == "POST"
                    && url == "https://relayer-v2.polymarket.com/submit"
                    && String::from_utf8_lossy(body).contains(needle)
            })
    }
}

#[async_trait]
impl PetalHost for MockHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.vfs_calls.lock().unwrap().push(format!("read {path}"));
        if path == "wallets/alice/address" {
            Ok(b"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\n".to_vec())
        } else if path == "wallets/alice/policy.toml" {
            Ok(self.policy_body.clone())
        } else if path == "wallets/0xalice/address" {
            Ok(b"0x0000000000000000000000000000000000000001\n".to_vec())
        } else if path.starts_with("chains/polygon/contracts/")
            && path.ends_with("/proxy/implementation")
        {
            if self.deposit_wallet_deployed || self.relayer_submit_seen("WALLET-CREATE") {
                Ok(b"0x2000000000000000000000000000000000000002\n".to_vec())
            } else {
                Ok(b"not a proxy\n".to_vec())
            }
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/implementation@")
            && path.ends_with(".read")
        {
            Ok(
                br#"{"decoded":["0x2000000000000000000000000000000000000002"],"raw":"0x"}"#
                    .to_vec(),
            )
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/predictWalletAddress@")
            && path.ends_with(".read")
        {
            Ok(
                br#"{"decoded":["0x3000000000000000000000000000000000000003"],"raw":"0x"}"#
                    .to_vec(),
            )
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/balanceOf@")
            && path.ends_with(".read")
            && path.starts_with(&format!(
                "chains/polygon/contracts/{}/",
                PUSD.to_checksum(None)
            ))
        {
            Ok(format!(
                r#"{{"decoded":["{}"],"raw":"0x"}}"#,
                self.chain_pusd_balance_micro
            )
            .into_bytes())
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/balanceOf@")
            && path.ends_with(".read")
            && path.starts_with(&format!(
                "chains/polygon/contracts/{}/",
                CTF.to_checksum(None)
            ))
        {
            Ok(format!(
                r#"{{"decoded":["{}"],"raw":"0x"}}"#,
                self.chain_ctf_balance_micro
            )
            .into_bytes())
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/allowance@")
            && path.ends_with(".read")
        {
            let allowance =
                if self.chain_pusd_allowance_ok || self.relayer_submit_seen(r#""WALLET""#) {
                    U256::MAX
                } else {
                    U256::ZERO
                };
            Ok(format!(r#"{{"decoded":["{allowance}"],"raw":"0x"}}"#).into_bytes())
        } else if path.starts_with("chains/polygon/contracts/")
            && path.contains("/methods/isApprovedForAll@")
            && path.ends_with(".read")
        {
            Ok(format!(r#"{{"decoded":[{}],"raw":"0x"}}"#, self.chain_ctf_approved).into_bytes())
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

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.vfs_calls.lock().unwrap().push(format!("write {path}"));
        if path.starts_with("chains/polygon/contracts/")
            && ((path.contains("/methods/balanceOf@") && path.ends_with(".read"))
                || (path.contains("/methods/allowance@") && path.ends_with(".read"))
                || (path.contains("/methods/isApprovedForAll@") && path.ends_with(".read"))
                || (path.contains("/methods/implementation@") && path.ends_with(".read"))
                || (path.contains("/methods/predictWalletAddress@") && path.ends_with(".read")))
        {
            self.vfs_writes
                .lock()
                .unwrap()
                .push((path.to_string(), bytes.to_vec()));
            Ok(())
        } else {
            Err(HostError::Denied("vfs not expected".into()))
        }
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
        self.http_bodies.lock().unwrap().push((
            req.method.clone(),
            req.url.clone(),
            req.body.clone(),
        ));
        if req.method == "GET"
            && req
                .url
                .starts_with("https://relayer-v2.polymarket.com/nonce?")
        {
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"nonce":7}"#.to_vec(),
            });
        }
        if req.method == "POST" && req.url == "https://relayer-v2.polymarket.com/submit" {
            if let Some((status, body)) = &self.relayer_submit_response {
                return Ok(HttpResponse {
                    status: *status,
                    headers: Vec::new(),
                    body: body.clone(),
                });
            }
            let body = String::from_utf8_lossy(&req.body);
            let id = if body.contains("WALLET-CREATE") {
                "tx-deploy"
            } else {
                "tx-approve"
            };
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: format!(r#"{{"transactionID":"{id}","state":"STATE_NEW"}}"#).into_bytes(),
            });
        }
        if req.method == "GET"
            && req
                .url
                .starts_with("https://relayer-v2.polymarket.com/transaction?")
        {
            let id = if req.url.contains("tx-deploy") {
                "tx-deploy"
            } else {
                "tx-approve"
            };
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: format!(
                    r#"{{"transactionID":"{id}","state":"STATE_CONFIRMED","transactionHash":"0xabc"}}"#
                )
                .into_bytes(),
            });
        }
        let key = format!("{} {}", req.method, req.url);
        if req.method == "GET"
            && req.url == "https://clob.polymarket.com/data/orders"
            && let Some(order_id) = &self.dynamic_open_order_id
        {
            let post_body = self
                .http_bodies
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(method, url, _)| {
                    method == "POST" && url == "https://clob.polymarket.com/order"
                })
                .map(|(_, _, body)| body.clone())
                .expect("post body should exist before reconciliation");
            let posted: serde_json::Value = serde_json::from_slice(&post_body).unwrap();
            let order = posted.get("order").unwrap();
            let body = serde_json::json!([{
                "id": order_id,
                "status": "live",
                "salt": order["salt"].clone(),
                "maker": order["maker"].clone(),
                "asset_id": order["tokenId"].clone(),
                "side": order["side"].clone(),
                "orderType": posted["orderType"].clone(),
                "makerAmount": order["makerAmount"].clone(),
                "takerAmount": order["takerAmount"].clone()
            }]);
            let body = serde_json::to_vec(&body).unwrap();
            assert!(body.len() <= max_response_bytes);
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body,
            });
        }
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
