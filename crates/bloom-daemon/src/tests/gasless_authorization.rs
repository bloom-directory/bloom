//! Built gasless component through the existing disposable real-triad fixture.
use super::*;
use bloom_broker_api::{ApprovalLifecycleState, AssetId};
use bloom_petal_contract::prepared::{SigningOutcome, Spend};

const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

pub(super) fn quote_response(request: &HttpRequest, serial: u64) -> Vec<u8> {
    let serial = serial
        + if std::env::var("BLOOM_PM80_BUY_PHASE").as_deref() == Ok("restart") {
            1000
        } else {
            0
        };
    let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(input["originChainId"], 8453);
    assert_eq!(input["originCurrency"], USDC);
    let owner = input["user"].as_str().unwrap();
    let amount = input["amount"].as_str().unwrap().parse::<u64>().unwrap();
    let mut quote: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/gasless-relay-quote.json"
    ))
    .unwrap();
    let old_owner = quote["details"]["sender"].as_str().unwrap().to_owned();
    fn replace(value: &mut serde_json::Value, replacements: &[(&str, String)]) {
        match value {
            serde_json::Value::String(text) => {
                if let Some((_, replacement)) =
                    replacements.iter().find(|(old, _)| text.as_str() == *old)
                {
                    *text = replacement.clone();
                }
            }
            serde_json::Value::Object(map) => {
                map.values_mut().for_each(|v| replace(v, replacements))
            }
            serde_json::Value::Array(values) => {
                values.iter_mut().for_each(|v| replace(v, replacements))
            }
            _ => {}
        }
    }
    replace(
        &mut quote,
        &[
            (&old_owner, owner.into()),
            ("100000000", amount.to_string()),
            ("98000000", (amount * 98 / 100).to_string()),
            ("97500000", (amount * 975 / 1000).to_string()),
            (
                &format!("0x{}", "aa".repeat(32)),
                format!("0x{:064x}", serial + 1),
            ),
            (
                &format!("0x{}", "bb".repeat(32)),
                format!("0x{:064x}", serial + 101),
            ),
        ],
    );
    let request_id = quote["steps"][0]["requestId"].as_str().unwrap().to_owned();
    quote["steps"][0]["items"][0]["check"]["endpoint"] =
        serde_json::json!(format!("/intents/status/v3?requestId={request_id}"));
    quote["steps"][0]["items"][0]["data"]["sign"]["value"]["validBefore"] = serde_json::json!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300
    );
    serde_json::to_vec(&quote).unwrap()
}

#[test]
fn mock_quote_keeps_the_status_endpoint_bound_to_the_distinct_request() {
    let request = HttpRequest {
        method: "POST".into(),
        url: "https://api.relay.link/quote/v2".into(),
        headers: vec![],
        body: serde_json::to_vec(&serde_json::json!({
            "originChainId":8453, "originCurrency":USDC, "amount":"1000000",
            "user":"0x1111111111111111111111111111111111111111"
        }))
        .unwrap(),
    };
    let first: serde_json::Value = serde_json::from_slice(&quote_response(&request, 0)).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&quote_response(&request, 1)).unwrap();
    assert_ne!(
        first["steps"][0]["requestId"],
        second["steps"][0]["requestId"]
    );
    assert_ne!(
        first["steps"][0]["items"][0]["data"]["sign"]["value"]["nonce"],
        second["steps"][0]["items"][0]["data"]["sign"]["value"]["nonce"]
    );
    for quote in [first, second] {
        let id = quote["steps"][0]["requestId"].as_str().unwrap();
        let item = &quote["steps"][0]["items"][0];
        assert_eq!(item["data"]["post"]["body"]["requestId"], id);
        assert_eq!(
            item["check"]["endpoint"],
            format!("/intents/status/v3?requestId={id}")
        );
        assert_eq!(item["data"]["sign"]["value"]["value"], "1000000");
    }
}

fn body(amount: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "origin":{"chain":"base","chain_id":8453,"currency":USDC,"decimals":6,
            "permit_domain":{"name":"USD Coin","version":"2"}},
        "destination":{"chain":"optimism","chain_id":10,
            "currency":"0x0b2c639c533813f4aa9d7837caf62653d097ff85","decimals":6},
        "amount":amount,"minimum_output":"0.9"
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires built gasless WASM and real services; run scripts/test-polymarket-authorization.sh with prepared-gasless"]
async fn prepared_gasless_uses_real_bounded_permission() {
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
    let package = integration_package("BLOOM_PM80_GASLESS_ROOT");
    let hash = package.hash.clone();
    let route = package
        .route_index
        .routes
        .iter()
        .find(|r| {
            r.pattern == "transactions/[wallet]/[index]/[id].json"
                && r.install_metadata.sign_intent.as_deref() == Some("gasless.relay")
        })
        .unwrap();
    assert_eq!(route.economic_effects_schema, Some(1));
    let provenance = catalog
        .record(&bloom_broker_api::ProvenanceSubject::Petal {
            package_hash: Digest32::new(hash.clone()).unwrap(),
            route: route.route_id.clone(),
        })
        .unwrap()
        .digest()
        .unwrap();
    let route = route.route_id.clone();
    let grant_id = if phase == "first" {
        let staged = daemon.petals.store().stage_petal_package(package).unwrap();
        daemon
            .petals
            .install_staged_petal_package(staged, None, || Ok(()))
            .unwrap();
        approve_package(&daemon, &client, &wallet, &hash, 3, true).await;
        activate_token_permission(
            &daemon,
            &wallet,
            account.key_ref.clone(),
            &hash,
            &route,
            provenance,
            4,
            "gasless.relay",
            AssetId {
                chain: Token::new("evm-8453").unwrap(),
                asset: USDC.into(),
            },
        )
        .await
        .approval_id
    } else {
        let sessions = daemon.persona_sessions(wallet.as_str()).await.unwrap();
        assert_eq!(sessions.len(), 1);
        let grant = &sessions[0];
        let first: serde_json::Value = serde_json::from_slice(
            &std::fs::read(setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension("first.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["approval_id"], serde_json::json!(grant.approval_id));
        assert_eq!(
            first["budget_id"],
            serde_json::json!(
                grant
                    .terms
                    .session_budget
                    .as_ref()
                    .unwrap()
                    .budget_id()
                    .unwrap()
            )
        );
        let before = grant
            .usage
            .as_ref()
            .unwrap()
            .session_budget_state
            .as_ref()
            .unwrap();
        assert_eq!(before.operations.get(), 2);
        assert_eq!(before.asset_usage[0].amount.as_str(), "2000000");
        let rearm = daemon
            .broker_client()
            .unwrap()
            .rearm_persona_session(
                &wallet,
                Some(&grant.approval_id),
                OperationId::from_bytes([0x94; 32]),
            )
            .await
            .unwrap();
        complete(
            rearm
                .authority
                .ceremony_url
                .as_deref()
                .expect("rearm ceremony"),
            5,
            None,
        );
        grant.approval_id.clone()
    };
    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(daemon.vfs.clone()));
    let state_root = home.cache_dir().join("gasless-prepared-signing");
    let machine = Arc::new(
        DaemonPetalHost::new(late, daemon.audit.clone())
            .with_broker(daemon.broker_client())
            .with_wallets(daemon.wallets.clone())
            .with_petal_runner(daemon.petals.clone())
            .with_provenance_catalog(Some(catalog))
            .with_petal_signing_state_root(state_root),
    );
    let host = Arc::new(VenueFixture::new(machine, true));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(daemon.petals.clone(), host.clone())),
        )
        .build();
    let approvals = client.list_approvals(wallet.clone()).await.unwrap().len();
    let ids: &[&str] = if phase == "first" {
        &["one", "two"]
    } else {
        &["three"]
    };
    for id in ids {
        let path =
            VfsPath::parse(&format!("petals/gasless/transactions/{wallet}/1/{id}.json")).unwrap();
        vfs.write(&path, &body("1"))
            .await
            .expect("covered payment must finish its mocked submission");
        vfs.write(&path, &body("1"))
            .await
            .expect("submitted retry must succeed without signing again");
        let status = read_json(&vfs, &path.to_string_path()).await;
        assert_eq!(status["status"], "success");
        assert_eq!(status["submission"], "accepted");
        assert_eq!(status["next"]["action"], "complete");
    }
    assert_eq!(
        host.relay_submissions.load(Ordering::SeqCst),
        ids.len() as u64,
        "repeated writes cannot submit twice"
    );
    let signed = host.prepared_signed.lock().unwrap().clone();
    assert_eq!(
        signed.len(),
        ids.len(),
        "covered distinct actions sign once each"
    );
    assert_eq!(
        client.list_approvals(wallet.clone()).await.unwrap().len(),
        approvals
    );
    let requests = host.prepared_requests.lock().unwrap().clone();
    for ((request, context), (_, signature)) in requests.iter().take(ids.len()).zip(&signed) {
        assert_eq!(request.action.operation_class, "gasless.relay");
        assert_eq!(
            host.machine
                .prepared_sign(request.clone(), context.clone())
                .await
                .unwrap(),
            SigningOutcome::Signed {
                signature: signature.clone()
            },
            "retry retains the exact signature"
        );
    }
    let sessions = daemon.persona_sessions(wallet.as_str()).await.unwrap();
    let grant = sessions.iter().find(|s| s.approval_id == grant_id).unwrap();
    assert_eq!(grant.authority.state, ApprovalLifecycleState::Active);
    let usage = grant
        .usage
        .as_ref()
        .unwrap()
        .session_budget_state
        .as_ref()
        .unwrap();
    let expected = if phase == "first" { 2 } else { 3 };
    assert_eq!(usage.operations.get(), expected);
    assert_eq!(usage.signatures.get(), expected);
    assert_eq!(
        usage.asset_usage[0].amount.as_str(),
        format!("{}000000", expected)
    );
    // Mismatched claim, malformed envelope and unreviewed class cannot sign.
    let (original, context) = requests[0].clone();
    let mut changed = original.clone();
    changed.action.spend = Spend::erc20("evm-8453", USDC, "2").unwrap();
    assert!(
        host.machine
            .prepared_sign(changed, context.clone())
            .await
            .is_err(),
        "a durable operation key cannot be rebound to a changed action"
    );
    for kind in ["claim", "envelope", "class"] {
        let mut request = original.clone();
        request.operation_key = format!("gasless-negative-{phase}-{kind}");
        match kind {
            "claim" => request.action.spend = Spend::erc20("evm-8453", USDC, "1").unwrap(),
            "envelope" => request.action.review.bytes = b"{}".to_vec(),
            "class" => request.action.operation_class = "gasless.unknown".into(),
            _ => unreachable!(),
        }
        assert!(
            host.machine
                .prepared_sign(request, context.clone())
                .await
                .is_err(),
            "{kind} must fail closed"
        );
    }
    if phase == "restart" {
        let path =
            VfsPath::parse(&format!("petals/gasless/transactions/{wallet}/1/over.json")).unwrap();
        vfs.write(&path, &body("4"))
            .await
            .expect_err("over-limit payment must wait for exact approval");
        assert_eq!(host.prepared_signed.lock().unwrap().len(), 1);
        let action_id = match host
            .prepared_outcomes
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .clone()
        {
            Ok(SigningOutcome::ApprovalPending { action_id, .. }) => action_id,
            other => panic!("over-limit payment needs exact review: {other:?}"),
        };
        let exact_state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                home.cache_dir()
                    .join("gasless-prepared-signing")
                    .join(".state")
                    .join(format!("{action_id}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        let operation: OperationId =
            serde_json::from_value(exact_state["approval_operation_id"].clone()).unwrap();
        let ceremony = client.ceremony_status(operation).await.unwrap();
        complete(
            ceremony
                .ceremony_url
                .as_deref()
                .expect("exact step-up ceremony"),
            6,
            None,
        );
        vfs.write(&path, &body("4"))
            .await
            .expect("exact-approved payment must continue through mocked submission");
        let exact_status = read_json(&vfs, &path.to_string_path()).await;
        assert_eq!(exact_status["status"], "success");
        assert_eq!(host.prepared_signed.lock().unwrap().len(), 2);
        let unchanged = daemon.persona_sessions(wallet.as_str()).await.unwrap();
        let usage = unchanged
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
            usage.operations.get(),
            3,
            "exact step-up does not refill or consume the retained allowance"
        );
        assert_eq!(usage.asset_usage[0].amount.as_str(), "3000000");
    }
    std::fs::write(setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension(format!("{phase}.json")),
        serde_json::to_vec_pretty(&serde_json::json!({"schema":"bloom.prepared-gasless.acceptance.v1",
            "phase":phase,"package_hash":hash,"approval_id":grant_id,
            "budget_id":grant.terms.session_budget.as_ref().unwrap().budget_id().unwrap(),"account":1,
            "covered_operations":expected,"exact_stepup_operations":if phase=="restart" {1} else {0},
            "usage_raw_usdc":format!("{}000000",expected),
            "covered_without_additional_ceremony":true,"duplicate_signature_recovered":true,
            "negative_cases_rejected":true,"restart_rearm_preserves_usage":phase=="restart",
            "over_limit_exact_review":phase=="restart",
            "limits":"disposable software owner; controlled Relay quote and mocked submission; no live funds or settlement"})).unwrap()).unwrap();
}
