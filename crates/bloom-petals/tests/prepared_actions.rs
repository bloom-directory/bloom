//! SDK component / Machine VM wire integration without a Broker or venue.
//! Build `petal/fixtures/petal-build.toml`, then set BLOOM_PREPARED_FIXTURES
//! to its output directory. Dedicated CI builds and requires those fixtures.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use bloom_petal_contract::prepared::{
    CryptoSuite, ErrorCode, Request, SigningError, SigningOutcome, Spend, StatusRequest,
};
use bloom_petals::{
    Capability, DispatchOp, DispatchRequest, DispatchResponse, HostError, HostVfsEntry,
    NameRegistry, PetalHost, PetalRunner, PetalStore, PetalVm, RunOptions, abi::PetalRouteContext,
};

type AttemptRecords = BTreeMap<String, (Request, Result<SigningOutcome, SigningError>)>;

#[derive(Default)]
struct FixtureHost {
    requests: Mutex<Vec<(Request, PetalRouteContext)>>,
    statuses: Mutex<Vec<(StatusRequest, PetalRouteContext)>>,
    deny: AtomicBool,
    attempts: Mutex<Option<AttemptRecords>>,
    automatic: AtomicBool,
    signed_operations: AtomicUsize,
}

#[async_trait]
impl PetalHost for FixtureHost {
    async fn vfs_lookup(&self, _: &str) -> Result<HostVfsEntry, HostError> {
        Err(HostError::Denied("fixture".into()))
    }
    async fn vfs_read(&self, _: &str) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("fixture".into()))
    }
    async fn vfs_list(&self, _: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        Err(HostError::Denied("fixture".into()))
    }
    async fn vfs_write(&self, _: &str, _: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("fixture".into()))
    }

    async fn prepared_sign(
        &self,
        request: Request,
        context: PetalRouteContext,
    ) -> Result<SigningOutcome, SigningError> {
        self.requests
            .lock()
            .unwrap()
            .push((request.clone(), context.clone()));
        if let Some(attempts) = &mut *self.attempts.lock().unwrap() {
            let key = format!(
                "{}:{}:{}",
                context.package_hash, request.wallet, request.operation_key
            );
            let entry = attempts.entry(key).or_insert_with(|| {
                (
                    request.clone(),
                    Ok(SigningOutcome::ApprovalPending {
                        action_id: "fixture-action".into(),
                        expires_ms: u64::MAX,
                    }),
                )
            });
            if entry.0.action != request.action {
                return Err(SigningError {
                    code: ErrorCode::Conflict,
                    message: "frozen action changed".into(),
                });
            }
            if matches!(&entry.1, Ok(SigningOutcome::RecoveryRequired { status }) if status == "approved_retry")
                || self.automatic.load(Ordering::SeqCst)
                    && matches!(entry.1, Ok(SigningOutcome::ApprovalPending { .. }))
            {
                entry.1 = Ok(SigningOutcome::Signed {
                    signature: vec![0x42; 65],
                });
                self.signed_operations.fetch_add(1, Ordering::SeqCst);
            }
            return entry.1.clone();
        }
        if self.deny.load(Ordering::SeqCst) {
            Err(SigningError {
                code: ErrorCode::Denied,
                message: "fixture refusal".into(),
            })
        } else {
            Ok(SigningOutcome::Signed {
                signature: vec![0x42; 64],
            })
        }
    }
    async fn prepared_sign_status(
        &self,
        request: StatusRequest,
        context: PetalRouteContext,
    ) -> Result<SigningOutcome, SigningError> {
        self.statuses
            .lock()
            .unwrap()
            .push((request.clone(), context.clone()));
        if let Some(attempts) = &*self.attempts.lock().unwrap() {
            let key = format!(
                "{}:{}:{}",
                context.package_hash, request.wallet, request.operation_key
            );
            return attempts
                .get(&key)
                .map(|entry| entry.1.clone())
                .unwrap_or_else(|| {
                    Err(SigningError {
                        code: ErrorCode::NotFound,
                        message: "operation not found".into(),
                    })
                });
        }
        Ok(SigningOutcome::ApprovalPending {
            action_id: "fixture-action".into(),
            expires_ms: 1234,
        })
    }
}

fn component(name: &str) -> Vec<u8> {
    let root = PathBuf::from(
        std::env::var_os("BLOOM_PREPARED_FIXTURES")
            .expect("set BLOOM_PREPARED_FIXTURES to the rebuilt SDK fixtures/components directory"),
    );
    std::fs::read(root.join(name))
        .expect("SDK fixture component missing; rebuild fixtures/petal-build.toml")
}

fn runner() -> (tempfile::TempDir, PetalRunner, String) {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package");
    let routes = package.join("petal/conformance");
    std::fs::create_dir_all(&routes).unwrap();
    std::fs::write(
        package.join("petal.toml"),
        r#"schema = "bloom.petal.package.v1"
name = "conformance"
[consent]
summary = "Prepared signing host integration fixture."
[caps]
allowed = ["bloom:sign", "bloom:sign.status", "bloom:store"]
[sign]
allowed_intents = ["conformance.message"]
[store]
namespaces = ["state"]
"#,
    )
    .unwrap();
    std::fs::write(package.join("README.md"), "# Prepared signing fixture\n").unwrap();
    std::fs::write(package.join("AGENTS.md"), "# Test fixture\n").unwrap();
    std::fs::write(routes.join("prepared.wasm"), component("prepared.wasm")).unwrap();
    std::fs::write(
        routes.join("prepared-status.wasm"),
        component("prepared-status.wasm"),
    )
    .unwrap();
    for name in ["prepared-attempt.wasm", "prepared-attempt-status.wasm"] {
        std::fs::write(routes.join(name), component(name)).unwrap();
    }
    let store = PetalStore::open(temp.path().join("petals")).unwrap();
    let (installed, _, _) = store.install_petal_package_dir(&package).unwrap();
    let registry = Arc::new(NameRegistry::open(temp.path().join("registry")).unwrap());
    (
        temp,
        PetalRunner::new(store, registry, PetalVm::new().unwrap()),
        installed.hash,
    )
}

async fn dispatch(
    runner: &PetalRunner,
    host: Arc<FixtureHost>,
    path: &str,
    op: DispatchOp,
    caps: &[Capability],
    wallet: &str,
) -> DispatchResponse {
    let trusted = vec![
        ("bloom.wallet".into(), wallet.into()),
        ("bloom.account".into(), "2".into()),
        ("bloom.owner_key_fingerprint".into(), "cd".repeat(32)),
    ];
    runner
        .dispatch_petal_route_with_trusted_params(
            "conformance",
            DispatchRequest {
                op,
                path: path.into(),
                body: b"second-format message".to_vec(),
                ctx: vec![],
            },
            host,
            Some(caps.iter().copied().collect::<BTreeSet<_>>()),
            RunOptions::default(),
            &trusted,
            None,
        )
        .await
        .unwrap()
        .response
}

#[tokio::test]
async fn sdk_prepared_and_status_imports_enforce_capabilities_and_trusted_context() {
    if std::env::var_os("BLOOM_PREPARED_FIXTURES").is_none() {
        eprintln!(
            "not exercised; use the dedicated prepared signing fixture job or set BLOOM_PREPARED_FIXTURES"
        );
        return;
    }
    let (_temp, runner, package_hash) = runner();
    let host = Arc::new(FixtureHost::default());
    let sign = "prepared";
    let status = "prepared-status";
    let sign_route = runner
        .petal_route("conformance", DispatchOp::Write, sign)
        .unwrap()
        .route
        .route_id;
    let status_route = runner
        .petal_route("conformance", DispatchOp::Read, status)
        .unwrap()
        .route
        .route_id;

    assert_eq!(
        dispatch(
            &runner,
            host.clone(),
            sign,
            DispatchOp::Write,
            &[Capability::Sign],
            "fixture"
        )
        .await,
        DispatchResponse::Write
    );
    {
        let calls = host.requests.lock().unwrap();
        let (request, context) = &calls[0];
        assert_eq!(calls.len(), 1);
        assert_eq!(request.wallet, "fixture");
        assert_eq!(request.operation_key, "message-1");
        assert_eq!(request.action.operation_class, "conformance.message");
        assert_eq!(request.action.payload.suite, CryptoSuite::Ed25519Message);
        assert_eq!(request.action.payload.preimage, b"second-format message");
        assert_eq!(request.action.review.format, "conformance.message");
        assert_eq!(request.action.review.version, 1);
        assert_eq!(request.action.review.bytes, b"second-format message");
        assert_eq!(request.action.spend, Spend::Unspecified);
        request.validate().unwrap();
        assert_eq!(context.package_hash, package_hash);
        assert_eq!(context.route_id, sign_route);
        assert_eq!(context.path, "prepared");
        let account = context.trusted_account().unwrap();
        assert_eq!((account.wallet.as_str(), account.number), ("fixture", 2));
        assert_eq!(
            account.owner_key_fingerprint.as_deref(),
            Some("cd".repeat(32).as_str())
        );
    }

    let forged = runner
        .dispatch_petal_route_with_trusted_params(
            "conformance",
            DispatchRequest {
                op: DispatchOp::Write,
                path: sign.into(),
                body: b"message".to_vec(),
                ctx: vec![("bloom.wallet".into(), "forged".into())],
            },
            host.clone(),
            None,
            RunOptions::default(),
            &[],
            None,
        )
        .await
        .unwrap_err();
    assert!(forged.to_string().contains("reserved bloom."));
    assert_eq!(host.requests.lock().unwrap().len(), 1);

    host.deny.store(true, Ordering::SeqCst);
    let denied = dispatch(
        &runner,
        host.clone(),
        sign,
        DispatchOp::Write,
        &[Capability::Sign],
        "fixture",
    )
    .await;
    assert!(
        matches!(denied, DispatchResponse::Error { message, .. } if message.contains("Denied") && message.contains("fixture refusal"))
    );
    let wrong_wallet = dispatch(
        &runner,
        host.clone(),
        sign,
        DispatchOp::Write,
        &[Capability::Sign],
        "other",
    )
    .await;
    assert!(matches!(wrong_wallet, DispatchResponse::Error { .. }));
    let status_only_sign = dispatch(
        &runner,
        host.clone(),
        sign,
        DispatchOp::Write,
        &[Capability::SignStatus],
        "fixture",
    )
    .await;
    assert!(matches!(status_only_sign, DispatchResponse::Error { .. }));
    assert_eq!(
        host.requests.lock().unwrap().len(),
        2,
        "denied VM calls must not reach host"
    );

    let status_result = dispatch(
        &runner,
        host.clone(),
        status,
        DispatchOp::Read,
        &[Capability::SignStatus],
        "fixture",
    )
    .await;
    assert!(
        matches!(status_result, DispatchResponse::Read(bytes) if String::from_utf8_lossy(&bytes).contains("fixture-action"))
    );
    let calls = host.statuses.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.wallet, "fixture");
    assert_eq!(calls[0].0.operation_key, "message-1");
    assert_eq!(calls[0].1.package_hash, package_hash);
    assert_eq!(calls[0].1.route_id, status_route);
    assert_eq!(calls[0].1.trusted_account().unwrap().number, 2);
}

// These tests exercise real SDK WASM + the Machine VM/store. The host models
// outcome persistence; real Broker signatures/charges are covered by triad acceptance.
fn attempt_host() -> Arc<FixtureHost> {
    let host = Arc::new(FixtureHost::default());
    *host.attempts.lock().unwrap() = Some(BTreeMap::new());
    host
}
async fn attempt_dispatch(
    runner: &PetalRunner,
    host: Arc<FixtureHost>,
    body: Option<serde_json::Value>,
) -> DispatchResponse {
    runner
        .dispatch_petal_route_with_trusted_params(
            "conformance",
            DispatchRequest {
                op: if body.is_some() {
                    DispatchOp::Write
                } else {
                    DispatchOp::Read
                },
                path: if body.is_some() {
                    "prepared-attempt"
                } else {
                    "prepared-attempt-status"
                }
                .into(),
                body: body
                    .map(|v| serde_json::to_vec(&v).unwrap())
                    .unwrap_or_default(),
                ctx: vec![],
            },
            host,
            Some(
                [Capability::Sign, Capability::SignStatus, Capability::Store]
                    .into_iter()
                    .collect(),
            ),
            RunOptions::default(),
            &[
                ("bloom.wallet".into(), "fixture".into()),
                ("bloom.account".into(), "2".into()),
            ],
            None,
        )
        .await
        .unwrap()
        .response
}
fn change_outcome(host: &FixtureHost, outcome: Result<SigningOutcome, SigningError>) {
    let mut records = host.attempts.lock().unwrap();
    assert_eq!(records.as_ref().unwrap().len(), 1);
    records.as_mut().unwrap().values_mut().next().unwrap().1 = outcome;
}
fn retry_state(response: DispatchResponse) -> String {
    let DispatchResponse::Read(bytes) = response else {
        panic!("expected status JSON: {response:?}")
    };
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["retry_state"]
        .as_str()
        .unwrap()
        .to_owned()
}
#[tokio::test]
async fn sdk_attempt_helpers_resume_and_project_status() {
    if std::env::var_os("BLOOM_PREPARED_FIXTURES").is_none() {
        return;
    }
    let (_temp, runner, _) = runner();
    let host = attempt_host();
    let first = attempt_dispatch(
        &runner,
        host.clone(),
        Some(serde_json::json!({"message":"first"})),
    )
    .await;
    assert!(
        matches!(first, DispatchResponse::Error { code: -3, message } if message.contains("fixture-action"))
    );
    assert_eq!(
        retry_state(attempt_dispatch(&runner, host.clone(), None).await),
        "pending"
    );
    change_outcome(
        &host,
        Ok(SigningOutcome::RecoveryRequired {
            status: "approved_retry".into(),
        }),
    );
    assert_eq!(
        retry_state(attempt_dispatch(&runner, host.clone(), None).await),
        "approved"
    );
    assert_eq!(
        attempt_dispatch(
            &runner,
            host.clone(),
            Some(serde_json::json!({"message":"changed"}))
        )
        .await,
        DispatchResponse::Write
    );
    assert_eq!(
        attempt_dispatch(&runner, host.clone(), Some(serde_json::json!({}))).await,
        DispatchResponse::Write
    );
    {
        let requests = host.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            requests
                .iter()
                .all(|(request, _)| request == &requests[0].0)
        );
        assert_eq!(host.signed_operations.load(Ordering::SeqCst), 1);
    }

    assert!(matches!(
        attempt_dispatch(&runner, host, None).await,
        DispatchResponse::Error { code: -3, .. }
    ));
}
#[tokio::test]
async fn sdk_attempt_concurrent_renewal_signs_once() {
    if std::env::var_os("BLOOM_PREPARED_FIXTURES").is_none() {
        return;
    }
    let (_temp, runner, _) = runner();
    let host = attempt_host();
    attempt_dispatch(&runner, host.clone(), Some(serde_json::json!({}))).await;
    change_outcome(
        &host,
        Err(SigningError {
            code: ErrorCode::Expired,
            message: "expired".into(),
        }),
    );
    host.automatic.store(true, Ordering::SeqCst);
    let (a, b) = tokio::join!(
        attempt_dispatch(
            &runner,
            host.clone(),
            Some(serde_json::json!({"renew":true,"message":"a"}))
        ),
        attempt_dispatch(
            &runner,
            host.clone(),
            Some(serde_json::json!({"renew":true,"message":"b"}))
        ),
    );
    // A caller that starts after #1 is already signed sees a refused renewal;
    // overlapping renewals may both replay the winning #1. Neither creates #2.
    assert!(
        a == DispatchResponse::Write || b == DispatchResponse::Write,
        "{a:?}, {b:?}"
    );
    for result in [a, b] {
        assert!(
            result == DispatchResponse::Write
                || matches!(result, DispatchResponse::Error { code: -3, .. })
        );
    }
    let requests = host.requests.lock().unwrap();
    let renewed: Vec<_> = requests
        .iter()
        .filter(|(r, _)| r.operation_key.ends_with("#1"))
        .collect();
    assert!(!renewed.is_empty());
    assert!(renewed.iter().all(|(r, _)| r == &renewed[0].0));
    assert!(
        requests
            .iter()
            .all(|(r, _)| !r.operation_key.ends_with("#2"))
    );
    assert_eq!(host.signed_operations.load(Ordering::SeqCst), 1);
    assert_eq!(host.attempts.lock().unwrap().as_ref().unwrap().len(), 2);
}
#[tokio::test]
async fn sdk_attempt_upgrade_fails_closed() {
    if std::env::var_os("BLOOM_PREPARED_FIXTURES").is_none() {
        return;
    }
    let (temp, runner, original_hash) = runner();
    let host = attempt_host();
    attempt_dispatch(&runner, host.clone(), Some(serde_json::json!({}))).await;
    let store = bloom_petals::PrivateStore::open(runner.store().private_data_root()).unwrap();
    let key = "state/state/fixture/attempt.0.json";
    let attempt = store.get(&original_hash, key).unwrap();
    std::fs::write(
        temp.path().join("package/README.md"),
        "# New fixture package revision\n",
    )
    .unwrap();
    let (installed, _, _) = runner
        .store()
        .install_petal_package_dir(temp.path().join("package"))
        .unwrap();
    assert_ne!(installed.hash, original_hash);
    // Explicitly model an upgrade retaining the private attempt. This test
    // does not claim installer lineage migration or recovery of an empty store.
    store.put(&installed.hash, key, &attempt, false).unwrap();
    assert!(matches!(
        attempt_dispatch(&runner, host.clone(), Some(serde_json::json!({}))).await,
        DispatchResponse::Error { code: -3, .. }
    ));
    assert_eq!(
        retry_state(attempt_dispatch(&runner, host.clone(), None).await),
        "package_changed"
    );
    assert_eq!(host.requests.lock().unwrap().len(), 1);
    assert!(host.statuses.lock().unwrap().is_empty());
}
