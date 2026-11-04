//! Real binaries, software passkey and installed WASM. Venue reads are controlled.
use super::*;
use bloom_broker_api::*;
use bloom_machine_client::PersonaSessionStatus;
use bloom_petal_contract::prepared::{Request, SigningOutcome, Spend};
use std::process::Stdio;

const WALLET: &str = "pm80-authorization";
const PUSD: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";

async fn cli(home: &HomeDir, endpoint: &str, arguments: &[&str]) -> serde_json::Value {
    let output = tokio::process::Command::new(setting("BLOOM_INTEGRATION_MACHINE_BIN"))
        .arg("--home")
        .arg(home.root())
        .arg("--connect")
        .arg(endpoint)
        .args(arguments)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "candidate Machine CLI failed: {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let value = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok());
    if arguments.contains(&"activate") {
        value.expect("activation CLI must emit its JSON status payload")
    } else {
        value.unwrap_or(serde_json::Value::Null)
    }
}

/// This starts the exact candidate executable, not an in-process compiler seam.
async fn onboard(
    fixture: AuthorizationFixture,
    name: &str,
    hash: &str,
    counter: &mut u64,
) -> AuthorizationFixture {
    let AuthorizationFixture {
        home,
        client,
        catalog,
        daemon,
        wallet,
    } = fixture;
    let mut config = bloom_proto::Config::load(&home.config_path()).unwrap();
    config.petals.setup.insert(
        name.into(),
        bloom_proto::config::PetalSetupConfig::default(),
    );
    config.save(&home.config_path()).unwrap();
    daemon.shutdown().await;
    drop(daemon);
    let mut released = false;
    for _ in 0..200 {
        if HomeWritePermit::acquire(&home).is_ok() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        released,
        "in-process fixture must release its own home before CLI ownership"
    );
    let socket = setting("BLOOM_TRIAD_DEVELOPER_ROOT").join("phase1-machine.sock");
    let endpoint = format!("unix:{}", socket.display());
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(setting("BLOOM_TRIAD_DEVELOPER_ROOT").join("phase1-machine.log"))
        .unwrap();
    let mut child = tokio::process::Command::new(setting("BLOOM_INTEGRATION_MACHINE_BIN"))
        .arg("--home")
        .arg(home.root())
        .args(["serve", "--endpoint", &endpoint])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "owned candidate Machine exited before readiness"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cli(
        &home,
        &endpoint,
        &["wallet", "persona", "set", WALLET, "degen"],
    )
    .await;
    // Exercise the actual end-user policy compiler, including Degen's signed
    // native recipient opt-in, before proposing any automatic session.
    let mut policy_command = tokio::process::Command::new(setting("BLOOM_INTEGRATION_MACHINE_BIN"))
        .arg("--home")
        .arg(home.root())
        .arg("--connect")
        .arg(&endpoint)
        .args(["wallet", "default-policy", WALLET])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    use tokio::io::AsyncBufReadExt as _;
    let mut lines = tokio::io::BufReader::new(policy_command.stdout.take().unwrap()).lines();
    while let Some(line) = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .expect("policy CLI must advance")
        .unwrap()
    {
        if let Some(url) = line.strip_prefix("default_policy_url: ") {
            *counter += 1;
            complete(url, *counter, None);
        }
    }
    let policy_output = policy_command.wait_with_output().await.unwrap();
    assert!(
        policy_output.status.success(),
        "policy CLI failed: {}",
        String::from_utf8_lossy(&policy_output.stderr)
    );
    let snapshot = client.policy(wallet.clone()).await.unwrap();
    let policy: CanonicalWalletPolicy =
        serde_json::from_slice(&snapshot.canonical_policy.decode()).unwrap();
    assert!(
        policy
            .allowed_destinations
            .iter()
            .any(|d| d.chain.as_str() == "evm-137" && d.destination == ERC20_ANY_RECIPIENT)
    );
    let mut finished = false;
    for _ in 0..16 {
        let value = cli(
            &home,
            &endpoint,
            &["wallet", "persona", "activate", WALLET, "--account", "1"],
        )
        .await;
        let statuses: Vec<PersonaSessionStatus> = serde_json::from_value(value).unwrap();
        if let Some(url) = statuses
            .iter()
            .find_map(|status| status.authority.ceremony_url.as_deref())
        {
            *counter += 1;
            complete(url, *counter, None);
        } else if statuses
            .iter()
            .all(|status| status.authority.state == ApprovalLifecycleState::Active)
        {
            assert!(statuses.iter().any(|status|matches!(&status.terms.subject,ApprovalSubject::Petal {package_hash,..} if package_hash.as_str()==hash)));
            assert!(statuses.iter().any(|status| matches!(
                &status.terms.selector,
                ApprovalSelector::NativeSession { .. }
            )));
            finished = true;
            break;
        }
    }
    assert!(
        finished,
        "CLI activation must reconcile all compiler-created scopes"
    );
    child.start_kill().unwrap();
    child.wait().await.unwrap();
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
        wallet,
    }
}

fn host(f: &AuthorizationFixture) -> (Arc<VenueFixture>, Vfs) {
    let late = Arc::new(LateVfsHost::new());
    late.set(Arc::new(f.daemon.vfs.clone()));
    let machine = Arc::new(
        DaemonPetalHost::new(late, f.daemon.audit.clone())
            .with_broker(f.daemon.broker_client())
            .with_wallets(f.daemon.wallets.clone())
            .with_petal_runner(f.daemon.petals.clone())
            .with_provenance_catalog(Some(f.catalog.clone()))
            .with_petal_signing_state_root(f.home.cache_dir().join("phase1-prepared")),
    );
    let host = Arc::new(VenueFixture::new(machine, true));
    let vfs = Vfs::builder()
        .mount(
            "petals",
            Arc::new(PetalRouter::new(f.daemon.petals.clone(), host.clone())),
        )
        .build();
    (host, vfs)
}

fn grant_for(statuses: &[PersonaSessionStatus], hash: &str) -> PersonaSessionStatus {
    statuses.iter().find(|status|status.terms.key_ref.key_spec==KeySpec::Secp256k1 && matches!(&status.terms.subject,ApprovalSubject::Petal {package_hash,..} if package_hash.as_str()==hash)).unwrap().clone()
}
fn usage_amount(usage: &ApprovalLimitState, chain: &str, asset: &str) -> String {
    usage
        .session_budget_state
        .as_ref()
        .unwrap()
        .asset_usage
        .iter()
        .find(|entry| entry.asset.chain.as_str() == chain && entry.asset.asset == asset)
        .map(|entry| entry.amount.as_str().to_owned())
        .unwrap_or_else(|| "0".into())
}
async fn usage(f: &AuthorizationFixture, id: &Digest32) -> ApprovalLimitState {
    f.client.approval_limit_state(id.clone()).await.unwrap()
}

fn assert_accounting_unchanged(before: &ApprovalLimitState, after: &ApprovalLimitState) {
    let a = before.session_budget_state.as_ref().unwrap();
    let b = after.session_budget_state.as_ref().unwrap();
    assert_eq!(a.budget_id, b.budget_id);
    assert_eq!(a.operations, b.operations);
    assert_eq!(a.signatures, b.signatures);
    assert_eq!(a.asset_usage, b.asset_usage);
    assert_eq!(
        a.includes_reserved_and_quarantined,
        b.includes_reserved_and_quarantined
    );
    assert_eq!(before.committed_operations, after.committed_operations);
    assert_eq!(before.committed_signatures, after.committed_signatures);
}

async fn setup(name: &str, variable: &str) -> (AuthorizationFixture, String, u64) {
    let mut counter = 2;
    let first = std::env::var("BLOOM_PM80_BUY_PHASE").as_deref() != Ok("restart");
    let f = if first {
        account_one_fixture().await
    } else {
        existing_authorization_fixture().await
    };
    let package = integration_package(variable);
    let hash = package.hash.clone();
    if first {
        let staged = f
            .daemon
            .petals
            .store()
            .stage_petal_package(package)
            .unwrap();
        f.daemon
            .petals
            .install_staged_petal_package(staged, None, || Ok(()))
            .unwrap();
        if name == "polymarket" {
            let store = bloom_petals::PrivateStore::open_account(
                f.daemon.petals.store().private_account_data_root(),
                WALLET,
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
        }

        let f = onboard(f, name, &hash, &mut counter).await;
        (f, hash, counter)
    } else {
        let prior: serde_json::Value = serde_json::from_slice(
            &std::fs::read(setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension("first.json"))
                .unwrap(),
        )
        .unwrap();
        counter = prior["owner_sign_count"].as_u64().unwrap();
        (f, hash, counter)
    }
}

async fn exact_url(f: &AuthorizationFixture, action: &str) -> String {
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            f.home
                .cache_dir()
                .join("phase1-prepared/.state")
                .join(format!("{action}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let operation: OperationId =
        serde_json::from_value(state["approval_operation_id"].clone()).unwrap();
    f.client
        .ceremony_status(operation)
        .await
        .unwrap()
        .ceremony_url
        .unwrap()
}
async fn expect_exact(
    f: &AuthorizationFixture,
    host: &VenueFixture,
    request: Request,
    context: PetalRouteContext,
    counter: &mut u64,
    finish: bool,
) {
    let outcome = host
        .machine
        .prepared_sign(request.clone(), context.clone())
        .await
        .unwrap();
    let SigningOutcome::ApprovalPending { action_id, .. } = outcome else {
        panic!("action must require exact review, got {outcome:?}");
    };
    if finish {
        *counter += 1;
        complete(&exact_url(f, &action_id).await, *counter, None);
        assert!(matches!(
            host.machine.prepared_sign(request, context).await.unwrap(),
            SigningOutcome::Signed { .. }
        ));
    }
}

async fn pm_login(vfs: &Vfs, host: &VenueFixture, refresh: bool) {
    let path = VfsPath::parse(&format!("petals/polymarket/onboard/{WALLET}/1/begin")).unwrap();
    if refresh {
        host.timestamp.fetch_add(1, Ordering::SeqCst);
    }
    vfs.write(
        &path,
        if refresh {
            br#"{"refresh":true}"#
        } else {
            b"{}"
        },
    )
    .await
    .unwrap();
}
async fn pm_buy(vfs: &Vfs, id: &str) {
    vfs.write(
        &VfsPath::parse(&format!("petals/polymarket/trade/{WALLET}/1/new")).unwrap(),
        br#"{"slug":"test","outcome":"YES","amount":"1","side":"buy","limit_price":"0.50"}"#,
    )
    .await
    .unwrap();
    let base = format!("petals/polymarket/trade/{WALLET}/1/drafts/{id}");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated real triad and built PM archive; use reviewed script prepared-buy"]
async fn prepared_buy_uses_real_bounded_permission() {
    let (f, hash, mut counter) = setup("polymarket", "BLOOM_PM80_POLYMARKET_ROOT").await;
    let first = std::env::var("BLOOM_PM80_BUY_PHASE").as_deref() != Ok("restart");
    let statuses = f.daemon.persona_sessions(WALLET).await.unwrap();
    let grant = grant_for(&statuses, &hash);
    let policy = grant
        .terms
        .session_budget
        .as_ref()
        .unwrap()
        .petal_policy
        .as_ref()
        .unwrap();
    assert_eq!(policy.persona, PetalSessionPersona::Degen);
    assert_eq!(
        policy.zero_spend_rate_limit.as_ref().unwrap().maximum.get(),
        300
    );
    let (host, vfs) = host(&f);
    let account = f
        .client
        .wallet_accounts(f.wallet.clone())
        .await
        .unwrap()
        .accounts
        .into_iter()
        .find(|a| a.path == "m/44'/60'/0'/0/1")
        .unwrap();
    let mut native = serde_json::Value::Null;
    if first {
        let native_grant = statuses
            .iter()
            .find(|s| matches!(s.terms.selector, ApprovalSelector::NativeSession { .. }))
            .unwrap();
        native = crate::phase1_native_acceptance::assert_compiler_native_transfer(
            &f.daemon.broker_client().unwrap(),
            &f.wallet,
            &account.key_ref,
            native_grant,
        )
        .await;
        let before = f
            .client
            .list_approvals(f.wallet.clone())
            .await
            .unwrap()
            .len();
        pm_login(&vfs, &host, false).await;
        pm_login(&vfs, &host, true).await;
        assert_eq!(host.auth_posts.load(Ordering::SeqCst), 2);
        let login = host
            .prepared_requests
            .lock()
            .unwrap()
            .iter()
            .find(|(r, _)| matches!(r.action.spend, Spend::None))
            .unwrap()
            .clone();
        assert_eq!(
            host.machine
                .prepared_sign(login.0.clone(), login.1.clone())
                .await
                .unwrap(),
            SigningOutcome::Signed {
                signature: host.prepared_signed.lock().unwrap()[0].1.clone()
            }
        );
        let owner = String::from_utf8(
            f.daemon
                .vfs
                .read(&VfsPath::parse("wallets/pm80-authorization/1/address.evm").unwrap())
                .await
                .unwrap(),
        )
        .unwrap()
        .trim()
        .to_owned();
        let store = bloom_petals::PrivateStore::open_account(
            f.daemon.petals.store().private_account_data_root(),
            WALLET,
            1,
        )
        .unwrap();
        store.put(&hash,"state/onboard/pm80-authorization/status.json",&serde_json::to_vec(&serde_json::json!({"wallet":WALLET,"owner":owner,"stage":"complete","tradeable":true,"creds_present":true,"deposit_wallet":{"address":"0x1111111111111111111111111111111111111111","source":"live_factory_resolved","fundable":true}})).unwrap(),false).unwrap();
        for id in ["0001", "0002"] {
            pm_buy(&vfs, id).await;
        }
        assert_eq!(
            host.prepared_signed
                .lock()
                .unwrap()
                .iter()
                .filter(|(r, _)| matches!(r.action.spend, Spend::Bounded { .. }))
                .count(),
            2
        );
        assert_eq!(
            f.client
                .list_approvals(f.wallet.clone())
                .await
                .unwrap()
                .len(),
            before,
            "covered installed WASM actions must not open ceremonies"
        );
        let (order, context) = host
            .prepared_requests
            .lock()
            .unwrap()
            .iter()
            .find(|(r, _)| matches!(r.action.spend, Spend::Bounded { .. }))
            .unwrap()
            .clone();
        // R2 deliberately trusts a reviewed package's declaration; no byte/debit verifier.
        let mut understated = order.clone();
        understated.operation_key = "r2-declared-one-raw".into();
        understated.action.spend = Spend::erc20("evm-137", PUSD, "1").unwrap();
        assert!(matches!(
            host.machine
                .prepared_sign(understated.clone(), context.clone())
                .await
                .unwrap(),
            SigningOutcome::Signed { .. }
        ));
        assert!(matches!(
            host.machine
                .prepared_sign(understated, context.clone())
                .await
                .unwrap(),
            SigningOutcome::Signed { .. }
        ));
        assert_eq!(
            usage_amount(&usage(&f, &grant.approval_id).await, "evm-137", PUSD),
            "2000001"
        );
        let before_rejections = usage(&f, &grant.approval_id).await;
        for kind in ["hash", "review", "provenance", "empty", "zero"] {
            let mut bad = order.clone();
            bad.operation_key = format!("reject-{kind}");
            let mut trusted = context.clone();
            match kind {
                "hash" => bad.action.payload.hash[0] ^= 1,
                "review" => bad.action.review.bytes = b"{}".to_vec(),
                "empty" => bad.action.spend = Spend::Bounded { debits: vec![] },
                "zero" => {
                    if let Spend::Bounded { debits } = &mut bad.action.spend {
                        debits[0].amount = "0".into();
                    }
                }
                _ => trusted.route_id = "uncertified-route".into(),
            }
            assert!(
                host.machine.prepared_sign(bad, trusted).await.is_err(),
                "malformed or unauthenticated action must be rejected"
            );
        }
        assert_accounting_unchanged(&before_rejections, &usage(&f, &grant.approval_id).await);
        // Actual Degen cap, never a reduced test cap or journal edit. Batches
        // respect the independent structural 120/minute signing backstop.
        for serial in 2..300 {
            if serial == 100 || serial == 200 {
                tokio::time::sleep(Duration::from_secs(61)).await;
            }
            let mut next = login.0.clone();
            next.operation_key = format!("zero-rate-{serial}");
            assert!(matches!(
                host.machine
                    .prepared_sign(next, login.1.clone())
                    .await
                    .unwrap(),
                SigningOutcome::Signed { .. }
            ));
        }
        let mut over = login.0;
        over.operation_key = "zero-rate-over-cap".into();
        expect_exact(&f, &host, over, login.1, &mut counter, true).await;
        let mut unspecified = order.clone();
        unspecified.operation_key = "undeclared-exact".into();
        unspecified.action.spend = Spend::Unspecified;
        expect_exact(&f, &host, unspecified, context.clone(), &mut counter, true).await;
        let mut outside = order.clone();
        outside.operation_key = "outside-grant-asset".into();
        outside.action.spend = Spend::erc20(
            "evm-10",
            "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
            "1000000",
        )
        .unwrap();
        expect_exact(&f, &host, outside, context.clone(), &mut counter, true).await;
        let mut over = order;
        over.operation_key = "token-over-limit".into();
        over.action.spend = Spend::erc20("evm-137", PUSD, "1001000000").unwrap();
        expect_exact(&f, &host, over, context, &mut counter, true).await;
        let charged = usage(&f, &grant.approval_id).await;
        assert_eq!(
            charged
                .session_budget_state
                .as_ref()
                .unwrap()
                .operations
                .get(),
            303
        );
        assert_eq!(
            charged
                .session_budget_state
                .as_ref()
                .unwrap()
                .signatures
                .get(),
            303
        );
        assert_eq!(usage_amount(&charged, "evm-137", PUSD), "2000001");
    } else {
        let before = usage(&f, &grant.approval_id).await;
        assert_eq!(usage_amount(&before, "evm-137", PUSD), "2000001");
        let rearm = f
            .daemon
            .broker_client()
            .unwrap()
            .rearm_persona_session(
                &f.wallet,
                Some(&grant.approval_id),
                OperationId::from_bytes([0x96; 32]),
            )
            .await
            .unwrap();
        counter += 1;
        complete(
            rearm.authority.ceremony_url.as_deref().unwrap(),
            counter,
            None,
        );
        let after = usage(&f, &grant.approval_id).await;
        assert_accounting_unchanged(&before, &after);
        let store = bloom_petals::PrivateStore::open_account(
            f.daemon.petals.store().private_account_data_root(),
            WALLET,
            1,
        )
        .unwrap();
        // Existing Petal setup belongs to the retained package, not new authority.
        assert!(
            store
                .get(&hash, "state/settings/pm80-authorization/venue.toml")
                .is_ok()
        );
        pm_buy(&vfs, "0003").await;
        assert_eq!(
            usage_amount(&usage(&f, &grant.approval_id).await, "evm-137", PUSD),
            "3000001"
        );
        let begin = VfsPath::parse(&format!("petals/polymarket/onboard/{WALLET}/1/begin")).unwrap();
        host.timestamp.fetch_add(1, Ordering::SeqCst);
        assert!(
            vfs.write(&begin, br#"{"refresh":true}"#).await.is_err(),
            "restart/rearm must not refill zero-spend capacity"
        );
        let (request, context) = host
            .prepared_requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert!(matches!(request.action.spend, Spend::None));
        expect_exact(&f, &host, request, context, &mut counter, true).await;
    }
    let result = serde_json::json!({"schema":"bloom.phase1.acceptance.v1","phase":if first {"first"} else {"restart"},"package_hash":hash,"approval_id":grant.approval_id,"budget_id":grant.terms.session_budget.as_ref().unwrap().budget_id().unwrap(),"owner_sign_count":counter,"actual_cli_compiler_onboarding":true,"zero_spend_preset_cap":300,"native":native,"r2_declared_amount_trusted":true,"rearm_retains_usage":!first});
    std::fs::write(
        setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension(if first {
            "first.json"
        } else {
            "restart.json"
        }),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated real triad and built gasless archive; use reviewed script prepared-gasless"]
async fn prepared_gasless_uses_real_bounded_permission() {
    let (f, hash, mut counter) = setup("gasless", "BLOOM_PM80_GASLESS_ROOT").await;
    let first = std::env::var("BLOOM_PM80_BUY_PHASE").as_deref() != Ok("restart");
    let grant = grant_for(&f.daemon.persona_sessions(WALLET).await.unwrap(), &hash);
    let (_host, vfs) = host(&f);
    if !first {
        let before = usage(&f, &grant.approval_id).await;
        let rearm = f
            .daemon
            .broker_client()
            .unwrap()
            .rearm_persona_session(
                &f.wallet,
                Some(&grant.approval_id),
                OperationId::from_bytes([0x97; 32]),
            )
            .await
            .unwrap();
        counter += 1;
        complete(
            rearm.authority.ceremony_url.as_deref().unwrap(),
            counter,
            None,
        );
        assert_accounting_unchanged(&before, &usage(&f, &grant.approval_id).await);
    }
    let before = f
        .client
        .list_approvals(f.wallet.clone())
        .await
        .unwrap()
        .len();
    for id in if first {
        vec!["one", "two"]
    } else {
        vec!["three"]
    } {
        let path =
            VfsPath::parse(&format!("petals/gasless/transactions/{WALLET}/1/{id}.json")).unwrap();
        vfs.write(&path, &gasless_authorization::body("1"))
            .await
            .unwrap();
        vfs.write(&path, &gasless_authorization::body("1"))
            .await
            .unwrap();
        assert_eq!(
            read_json(&vfs, &path.to_string_path()).await["status"],
            "success"
        );
    }
    assert_eq!(
        f.client
            .list_approvals(f.wallet.clone())
            .await
            .unwrap()
            .len(),
        before
    );
    assert_eq!(
        usage_amount(
            &usage(&f, &grant.approval_id).await,
            "evm-8453",
            gasless_authorization::USDC
        ),
        if first { "2000000" } else { "3000000" }
    );
    let result = serde_json::json!({"schema":"bloom.phase1.gasless.v1","actual_cli_compiler_onboarding":true,"owner_sign_count":counter,"approval_id":grant.approval_id,"phase":if first {"first"} else {"restart"},"retry_no_double_charge":true,"rearm_retains_usage":!first});
    std::fs::write(
        setting("BLOOM_PM80_AUTHORIZATION_RESULT").with_extension(if first {
            "first.json"
        } else {
            "restart.json"
        }),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated real triad and built PM archive; use reviewed script login"]
async fn installed_account_one_auth_and_exact_continuation_use_real_authority() {
    let f = account_one_fixture().await;
    let mut config = bloom_proto::Config::load(&f.home.config_path()).unwrap();
    config.persona = Some(bloom_proto::persona::PersonaConfig::suggested(
        bloom_proto::persona::PersonaPreset::Custodian,
    ));
    config.save(&f.home.config_path()).unwrap();
    let package = integration_package("BLOOM_PM80_POLYMARKET_ROOT");
    let hash = package.hash.clone();
    let staged = f
        .daemon
        .petals
        .store()
        .stage_petal_package(package)
        .unwrap();
    f.daemon
        .petals
        .install_staged_petal_package(staged, None, || Ok(()))
        .unwrap();
    approve_package(&f.daemon, &f.client, &f.wallet, &hash, 3, false).await;
    let (host, vfs) = host(&f);
    let begin = VfsPath::parse(&format!("petals/polymarket/onboard/{WALLET}/1/begin")).unwrap();
    let pending_error = vfs.write(&begin, b"{}").await.unwrap_err();
    assert!(
        !host.prepared_requests.lock().unwrap().is_empty(),
        "login must reach prepared signing: {pending_error}"
    );
    let request = host.prepared_requests.lock().unwrap()[0].0.clone();
    assert!(matches!(request.action.spend, Spend::None));
    let pending = host.prepared_outcomes.lock().unwrap()[0].1.clone().unwrap();
    let SigningOutcome::ApprovalPending { action_id, .. } = pending else {
        panic!("Institutional login must require exact review");
    };
    complete(&exact_url(&f, &action_id).await, 4, None);
    host.timestamp.fetch_add(2, Ordering::SeqCst);
    vfs.write(&begin, b"{}").await.unwrap();
    assert_eq!(host.auth_posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        host.prepared_signed.lock().unwrap()[0].0.action.payload,
        request.action.payload,
        "exact continuation must sign the frozen pre-ceremony payload"
    );

    assert!(f.daemon.persona_sessions(WALLET).await.unwrap().is_empty());
}
