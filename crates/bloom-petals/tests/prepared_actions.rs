//! SDK component / Machine VM wire integration without a Broker or venue.
//! Build `petal/fixtures/petal-build.toml`, then set BLOOM_PREPARED_FIXTURES
//! to its output directory and run this test with `--ignored`.
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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

#[derive(Default)]
struct FixtureHost {
    requests: Mutex<Vec<(Request, PetalRouteContext)>>,
    statuses: Mutex<Vec<(StatusRequest, PetalRouteContext)>>,
    deny: AtomicBool,
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
        self.requests.lock().unwrap().push((request, context));
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
        self.statuses.lock().unwrap().push((request, context));
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
allowed = ["bloom:sign", "bloom:sign.status"]
[sign]
allowed_intents = ["conformance.message"]
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
#[ignore = "requires separately built canonical SDK WASM fixtures; see module documentation"]
async fn sdk_prepared_and_status_imports_enforce_capabilities_and_trusted_context() {
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
