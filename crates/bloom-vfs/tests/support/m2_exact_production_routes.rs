use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bloom_broker_api::{
    ApprovalPrepareState, ApprovalSubject, Base64UrlBytes, CanonicalWalletPolicy, CredentialPublic,
    CryptoSuite, DecimalU64, Digest32, KeyPublic, KeyRef, KeySpec, MachineBrokerRequest,
    MachineBrokerResponse, MachineBrokerService, NormalizedSignature, PROVENANCE_CATALOG_SCHEMA,
    ProtocolError, ProtocolErrorCode, ProvenanceCatalog, ProvenanceOperationClass,
    ProvenanceRecord, ProvenanceSubject, SealedApprovalPrepareResponse, ServiceFuture,
    SignedPolicySnapshot, SigningResult, Token, WalletPublic,
};
use bloom_machine_client::empty_wallet_accounts;
use bloom_machine_client::{
    MachineBrokerClient, ProjectionFreshness, ProjectionVerification, WalletProjection,
    WalletProjectionReader,
};
use bloom_paid_http::PaidHttpChainRpcResolver;
use bloom_vfs::handlers::RequestsHandler;
use bloom_vfs::{BrokerExactPayloadSigner, Handler, HandlerError, VfsPath};
use mpp::protocol::core::Base64UrlJson;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

const X402_REQUIRED: &str = "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkubmFuc2VuLmFpL2FwaS92MS90b2tlbi1zY3JlZW5lciIsImRlc2NyaXB0aW9uIjoiUmV0cmlldmUgdG9rZW4gc2NyZW5lciBkYXRhIiwibWltZVR5cGUiOiIifSwiYWNjZXB0cyI6W3sic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoiZWlwMTU1Ojg0NTMiLCJhc3NldCI6IjB4ODMzNTg5ZkNENmVEYjZFMThmNGM3QzMyRDRmNzFiNTRiZEEwMjkxMyIsImFtb3VudCI6IjEwMDAwIiwicGF5VG8iOiIweDkzMDUzZjFlN0E1ZUZFRGE1MzJGZTY5Q2JiRTQzY0JFYzNBMEYxM2YiLCJtYXhUaW1lb3V0U2Vjb25kcyI6MzAwLCJleHRyYSI6eyJuYW1lIjoiVVNEIENvaW4iLCJ2ZXJzaW9uIjoiMiJ9fV19";

fn token(value: &str) -> Token {
    Token::new(value.to_owned()).unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

struct ExactBroker {
    wallet: WalletPublic,
    requests: Mutex<Vec<MachineBrokerRequest>>,
    signing_results: Mutex<Vec<SigningResult>>,
}

impl MachineBrokerService for ExactBroker {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request.clone());
            match request {
                MachineBrokerRequest::WalletGetPublic(_) => {
                    Ok(MachineBrokerResponse::WalletGetPublic(self.wallet.clone()))
                }
                MachineBrokerRequest::KeyGetPublic(request)
                    if Some(request.key_ref.clone()) == self.wallet.root_key_ref =>
                {
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        key_ref: request.key_ref,
                        role: bloom_broker_api::KeyRole::WalletRoot,
                        canonical_public_key: Base64UrlBytes::from_bytes(&[3; 33]),
                        addresses: Vec::new(),
                        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
                        petal_scope_expires_at_ms: None,
                    }))
                }
                MachineBrokerRequest::SealedApprovalPrepare(request) => Ok(
                    MachineBrokerResponse::SealedApprovalPrepare(SealedApprovalPrepareResponse {
                        approval_id: request.terms.approval_id()?,
                        state: ApprovalPrepareState::AwaitingCeremony,
                        ceremony_url: "http://localhost:18734/ceremony/m2-test".into(),
                        ceremony_expires_at_ms: request.terms.expires_at_ms,
                        review_manifest_digest: request.canonical_plan_facts_digest,
                    }),
                ),
                MachineBrokerRequest::SigningSign(request) => {
                    let mut signature = [2_u8; 65];
                    signature[64] = 1;
                    let result = SigningResult {
                        operation_id: request.operation_id,
                        operation_digest: request.operation_digest,
                        signatures: vec![NormalizedSignature {
                            crypto_suite: request.crypto_suite,
                            bytes: Base64UrlBytes::from_bytes(&signature),
                        }],
                        signer_receipt_digest: digest(90),
                        broker_receipt_digest: digest(91),
                    };
                    self.signing_results.lock().unwrap().push(result.clone());
                    Ok(MachineBrokerResponse::SigningSign(result))
                }
                other => Err(ProtocolError::new(
                    ProtocolErrorCode::UnknownMethod,
                    format!("unexpected M2 test Broker request: {other:?}"),
                )),
            }
        })
    }
}

#[derive(Clone)]
struct StaticProjection(WalletProjection);

#[async_trait]
impl WalletProjectionReader for StaticProjection {
    async fn list_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        Ok(vec![self.0.clone()])
    }

    async fn get_wallet(&self, wallet_id: &Token) -> Result<WalletProjection, ProtocolError> {
        if self.0.wallet.wallet_id == *wallet_id {
            Ok(self.0.clone())
        } else {
            Err(ProtocolError::new(
                ProtocolErrorCode::BackendInvalidRequest,
                "unknown M2 test wallet",
            ))
        }
    }

    fn cached_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        Ok(vec![self.0.clone()])
    }
}

fn projection(address: String) -> (WalletPublic, Arc<dyn WalletProjectionReader>) {
    let key_ref = KeyRef {
        backend: token("local"),
        backend_instance: token("primary"),
        locator: "alice/root".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest(1),
        derivation: None,
    };
    let policy = CanonicalWalletPolicy {
        wallet_id: token("alice"),
        maximum_approval_lifetime_ms: 300_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
    };
    let policy_bytes = serde_jcs::to_vec(&policy).unwrap();
    let policy_digest = Digest32::from_bytes(Sha256::digest(&policy_bytes).into());
    let wallet = WalletPublic {
        wallet_id: token("alice"),
        wallet_kind: token("local"),
        root_key_ref: Some(key_ref.clone()),
        key_refs: vec![key_ref.clone()],
        policy_version: DecimalU64::new(1),
        policy_digest: policy_digest.clone(),
        wallet_revocation_epoch: DecimalU64::new(0),
    };
    let projection = WalletProjection {
        wallet: wallet.clone(),
        keys: vec![KeyPublic {
            key_ref,
            role: bloom_broker_api::KeyRole::WalletRoot,
            canonical_public_key: Base64UrlBytes::from_bytes(&[3; 33]),
            addresses: vec![address],
            supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            petal_scope_expires_at_ms: None,
        }],
        credentials: Vec::<CredentialPublic>::new(),
        policy: SignedPolicySnapshot {
            wallet_id: token("alice"),
            version: DecimalU64::new(1),
            canonical_policy: Base64UrlBytes::from_bytes(&policy_bytes),
            policy_digest,
            policy_signing_key_id: token("policy-key"),
            policy_verifying_key: Base64UrlBytes::from_bytes(&[4; 32]),
            signer_signature: Base64UrlBytes::from_bytes(&[5; 64]),
        },
        accounts: empty_wallet_accounts(bloom_broker_api::Token::new("m2").unwrap()),
        accounts_unavailable: None,
        source_protocol: "bloom.machine-broker.v1".into(),
        response_digest: digest(6),
        observed_at_ms: 1,
        freshness: ProjectionFreshness::Fresh,
        verification: ProjectionVerification::AuthenticatedBroker,
    };
    (wallet, Arc::new(StaticProjection(projection)))
}

fn exact_signer(wallet: WalletPublic) -> (BrokerExactPayloadSigner, Arc<ExactBroker>) {
    let broker = Arc::new(ExactBroker {
        wallet,
        requests: Mutex::new(Vec::new()),
        signing_results: Mutex::new(Vec::new()),
    });
    let classes = ["paid-http.x402", "paid-http.mpp"];
    let records = classes
        .into_iter()
        .map(|class| ProvenanceRecord {
            subject: ProvenanceSubject::System {
                component_id: token("bloom-machine"),
                operation_class: token(class),
            },
            publisher: token("bloom-installer"),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: token(class),
                fee_asset: None,
            }],
            installer_key_id: token("test-key"),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        })
        .collect();
    (
        BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records,
            },
        ),
        broker,
    )
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(bytes).unwrap()
}

async fn spawn_http_fixture(kind: &'static str) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let request = read_request(&mut stream).await;
            let (status, headers, body) = if kind == "x402" {
                if request.to_ascii_lowercase().contains("payment-signature:") {
                    ("200 OK", String::new(), "paid")
                } else {
                    (
                        "402 Payment Required",
                        format!("Payment-Required: {X402_REQUIRED}\r\n"),
                        "payment required",
                    )
                }
            } else if kind == "mpp" {
                if request
                    .to_ascii_lowercase()
                    .contains("authorization: payment ")
                {
                    ("200 OK", String::new(), "paid")
                } else {
                    let challenge = mpp::PaymentChallenge::new(
                        "m2-mpp-charge",
                        "merchant.example",
                        "tempo",
                        "charge",
                        Base64UrlJson::from_value(&serde_json::json!({
                            "amount": "10000",
                            "currency": "0x20c0000000000000000000000000000000000000",
                            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                            "methodDetails": {
                                "chainId": 42431,
                                "feePayer": true
                            }
                        }))
                        .unwrap(),
                    );
                    (
                        "402 Payment Required",
                        format!("WWW-Authenticate: {}\r\n", challenge.to_header().unwrap()),
                        "payment required",
                    )
                }
            } else if request.starts_with("POST /info") {
                (
                    "200 OK",
                    String::new(),
                    r#"{"marginSummary":{"accountValue":"10"},"assetPositions":[]}"#,
                )
            } else {
                (
                    "200 OK",
                    String::new(),
                    r#"{"status":"ok","response":{"type":"default"}}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    Url::parse(&format!("http://{address}/")).unwrap()
}

struct StaticTempoRpc;

impl PaidHttpChainRpcResolver for StaticTempoRpc {
    fn http_rpc_urls_for_chain_id(&self, chain_id: u64) -> Vec<String> {
        assert_eq!(chain_id, 42431);
        // Fee-payer MPP charges do not call the RPC, but the production backend
        // still requires packaging to have selected a syntactically valid URL.
        vec!["http://127.0.0.1:1".into()]
    }
}

fn operation_classes(requests: &[MachineBrokerRequest]) -> Vec<String> {
    requests
        .iter()
        .filter_map(|request| match request {
            MachineBrokerRequest::SealedApprovalPrepare(request) => match &request.terms.subject {
                ApprovalSubject::System {
                    operation_class, ..
                } => Some(operation_class.as_str().to_owned()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn production_x402_route_prepares_then_signs_through_broker() {
    let temporary = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, broker) = exact_signer(wallet);
    let merchant = spawn_http_fixture("x402").await;
    let handler =
        RequestsHandler::new_projected(temporary.path(), Some("alice".into()), projections)
            .with_exact_signer(Some(signer));
    let request = format!(
        "GET {} wallet=alice max_amount_usd=20000",
        merchant.join("paid").unwrap()
    );
    handler
        .write(&VfsPath::parse("/new").unwrap(), request.as_bytes())
        .await
        .unwrap();
    let id = std::fs::read_dir(temporary.path().join("requests/pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    let confirm = VfsPath::parse(&format!("/pending/{id}/confirm")).unwrap();
    let staged_checks = std::fs::read_to_string(
        temporary
            .path()
            .join("requests/pending")
            .join(&id)
            .join("policy_check.json"),
    )
    .unwrap();
    let first = handler.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        matches!(&first, HandlerError::Backend(message) if message == "paid-http Broker approval required"),
        "expected Broker ceremony, got {first:?}; staged checks: {staged_checks}"
    );
    handler.write(&confirm, b"confirm").await.unwrap();
    assert!(temporary.path().join("requests/sent").join(&id).exists());
    let requests = broker.requests.lock().unwrap();
    assert!(operation_classes(&requests).contains(&"paid-http.x402".into()));
    assert!(
        requests
            .iter()
            .any(|request| matches!(request, MachineBrokerRequest::SigningSign(_)))
    );
    assert!(
        temporary
            .path()
            .join("requests/sent")
            .join(id)
            .join("private/exact-signing/credential.json")
            .exists()
    );
}

#[tokio::test]
async fn production_mpp_route_prepares_then_signs_through_broker() {
    let temporary = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, broker) = exact_signer(wallet);
    let merchant = spawn_http_fixture("mpp").await;
    let handler =
        RequestsHandler::new_projected(temporary.path(), Some("alice".into()), projections)
            .with_paid_http_rpc_resolver(Arc::new(StaticTempoRpc))
            .with_exact_signer(Some(signer));
    let request = format!(
        "GET {} wallet=alice max_amount_usd=20000",
        merchant.join("paid").unwrap()
    );
    handler
        .write(&VfsPath::parse("/new").unwrap(), request.as_bytes())
        .await
        .unwrap();
    let id = std::fs::read_dir(temporary.path().join("requests/pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    let confirm = VfsPath::parse(&format!("/pending/{id}/confirm")).unwrap();
    let staged_checks = std::fs::read_to_string(
        temporary
            .path()
            .join("requests/pending")
            .join(&id)
            .join("policy_check.json"),
    )
    .unwrap();

    let first = handler.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        matches!(&first, HandlerError::Backend(message) if message == "paid-http Broker approval required"),
        "expected Broker ceremony, got {first:?}; staged checks: {staged_checks}"
    );
    assert!(
        temporary
            .path()
            .join("requests/pending")
            .join(&id)
            .join("approval_challenge.json")
            .exists()
    );

    handler.write(&confirm, b"confirm").await.unwrap();
    assert!(temporary.path().join("requests/sent").join(&id).exists());
    let requests = broker.requests.lock().unwrap();
    let prepare = requests.iter().find_map(|request| match request {
        MachineBrokerRequest::SealedApprovalPrepare(request) => Some(request),
        _ => None,
    });
    let prepare = prepare.expect("MPP must prepare an exact sealed approval");
    assert!(matches!(
        &prepare.terms.subject,
        ApprovalSubject::System { operation_class, .. }
            if operation_class.as_str() == "paid-http.mpp"
    ));
    let sign = requests.iter().find_map(|request| match request {
        MachineBrokerRequest::SigningSign(request) => Some(request),
        _ => None,
    });
    let sign = sign.expect("MPP retry must submit the exact payload for signing");
    assert_eq!(sign.approval_id, prepare.terms.approval_id().unwrap());
    let signing_results = broker.signing_results.lock().unwrap();
    let result = signing_results
        .first()
        .expect("MPP signing must return a Signer receipt");
    assert_eq!(result.operation_id, sign.operation_id);
    assert_eq!(result.signer_receipt_digest, digest(90));
    assert!(
        temporary
            .path()
            .join("requests/sent")
            .join(id)
            .join("private/exact-signing/charge-transaction.json")
            .exists()
    );
}

struct PausedMerchant {
    url: Url,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PausedMerchant {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn paused_merchant() -> PausedMerchant {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let signal = entered.clone();
    let gate = release.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let signal = signal.clone();
            let gate = gate.clone();
            connections.spawn(async move {
                let request = read_request(&mut stream).await;
                let paid = request.to_ascii_lowercase().contains("payment-signature:");
                let response = if paid {
                    signal.notify_one();
                    gate.acquire().await.unwrap().forget();
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npaid".to_owned()
                } else {
                    format!("HTTP/1.1 402 Payment Required\r\nPayment-Required: {X402_REQUIRED}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    PausedMerchant {
        url,
        entered,
        release,
        task,
    }
}

async fn stage_paid(handler: &RequestsHandler, root: &std::path::Path, url: &Url) -> String {
    handler
        .write(
            &VfsPath::parse("/new").unwrap(),
            format!("GET {url} wallet=alice max_amount_usd=20000").as_bytes(),
        )
        .await
        .unwrap();
    let latest = std::fs::read_to_string(root.join("requests/latest")).unwrap();
    let id = latest.trim().strip_prefix("pending/").unwrap().to_owned();
    let confirm = VfsPath::parse(&format!("/pending/{id}/confirm")).unwrap();
    let error = handler.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        matches!(error, HandlerError::Backend(message) if message == "paid-http Broker approval required")
    );
    id
}

#[tokio::test]
async fn paid_confirm_excludes_cancel_and_same_wallet_execution() {
    let root = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, _) = exact_signer(wallet);
    let merchant = paused_merchant().await;
    let handler = RequestsHandler::new_projected(root.path(), Some("alice".into()), projections)
        .with_exact_signer(Some(signer));
    let first = stage_paid(&handler, root.path(), &merchant.url.join("first").unwrap()).await;
    let second = stage_paid(&handler, root.path(), &merchant.url.join("second").unwrap()).await;
    let first_path = VfsPath::parse(&format!("/pending/{first}/confirm")).unwrap();
    let first_confirm = handler.write(&first_path, b"confirm");
    tokio::pin!(first_confirm);
    tokio::select! {
        _ = merchant.entered.notified() => {},
        result = &mut first_confirm => panic!("confirmation should await merchant: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => panic!("merchant not reached"),
    }
    let cancel_path = VfsPath::parse(&format!("/pending/{first}/cancel")).unwrap();
    let cancel = handler.write(&cancel_path, b"cancel");
    tokio::pin!(cancel);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(cancel.as_mut().poll(cx)))
            .await
            .is_pending(),
        "cancel must wait for execution"
    );
    let second_path = VfsPath::parse(&format!("/pending/{second}/confirm")).unwrap();
    let clone = handler.clone();
    let second_confirm = clone.write(&second_path, b"confirm");
    tokio::pin!(second_confirm);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(second_confirm.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    // No second execution may mint a credential while the first holds the wallet.
    assert!(
        !root
            .path()
            .join(format!("requests/pending/{second}/receipt.json"))
            .exists()
    );
    // An unrelated request can still be staged while payment is parked.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handler.write(
            &VfsPath::parse("/new").unwrap(),
            format!(
                "GET {} wallet=alice max_amount_usd=20000",
                merchant.url.join("unrelated").unwrap()
            )
            .as_bytes(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    merchant.release.add_permits(1);
    first_confirm.await.unwrap();
    assert!(
        cancel.await.is_err(),
        "completed payment cannot be cancelled"
    );
    assert!(
        root.path()
            .join(format!("requests/sent/{first}/receipt.json"))
            .exists()
    );
    assert!(
        !root
            .path()
            .join(format!("requests/failed/{first}"))
            .exists()
    );
    merchant.release.add_permits(1);
    second_confirm.await.unwrap();
}

#[tokio::test]
async fn interrupted_payment_cannot_be_cancelled_or_free_wallet_budget() {
    let root = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, _) = exact_signer(wallet);
    let merchant = paused_merchant().await;
    let handler =
        RequestsHandler::new_projected(root.path(), Some("alice".into()), projections.clone())
            .with_exact_signer(Some(signer.clone()));
    let first = stage_paid(&handler, root.path(), &merchant.url.join("first").unwrap()).await;
    let second = stage_paid(&handler, root.path(), &merchant.url.join("second").unwrap()).await;
    let first_path = VfsPath::parse(&format!("/pending/{first}/confirm")).unwrap();
    let mut confirmation = Box::pin(handler.write(&first_path, b"confirm"));
    tokio::select! {
        _ = merchant.entered.notified() => {},
        result = &mut confirmation => panic!("expected merchant wait: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => panic!("merchant not reached"),
    }
    drop(confirmation);
    // A fresh handler models restart: protection must not depend on a live lock.
    let restarted = RequestsHandler::new_projected(root.path(), Some("alice".into()), projections)
        .with_exact_signer(Some(signer));
    let cancel = VfsPath::parse(&format!("/pending/{first}/cancel")).unwrap();
    let error = restarted.write(&cancel, b"cancel").await.unwrap_err();
    assert!(
        error.to_string().contains("execution has started"),
        "{error}"
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            root.path()
                .join(format!("requests/pending/{first}/receipt.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["outcome"], "unresolved");
    assert_eq!(receipt["wallet"], "alice");
    assert!(receipt["amount_usd"].as_f64().unwrap() > 0.0);
    assert!(
        !root
            .path()
            .join(format!(
                "requests/pending/{first}/private/execution_started"
            ))
            .exists()
    );
    assert!(restarted.write(&first_path, b"confirm").await.is_err());
    // The uncertain first payment stays charged, but is not a blanket wallet lock.
    merchant.release.add_permits(2);
    let confirm = VfsPath::parse(&format!("/pending/{second}/confirm")).unwrap();
    restarted.write(&confirm, b"confirm").await.unwrap();
    assert!(
        root.path()
            .join(format!("requests/sent/{second}/receipt.json"))
            .exists()
    );
    assert!(
        root.path()
            .join(format!("requests/pending/{first}/receipt.json"))
            .exists()
    );
}

#[tokio::test]
async fn paid_preflight_failure_remains_retryable_and_cancellable() {
    let root = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, _) = exact_signer(wallet);
    let merchant = spawn_http_fixture("mpp").await;
    let handler = RequestsHandler::new_projected(root.path(), Some("alice".into()), projections)
        .with_exact_signer(Some(signer));
    // Without an RPC resolver, MPP refuses before signing or payment submission.
    handler
        .write(
            &VfsPath::parse("/new").unwrap(),
            format!(
                "GET {} wallet=alice max_amount_usd=20000",
                merchant.join("paid").unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let latest = std::fs::read_to_string(root.path().join("requests/latest")).unwrap();
    let id = latest.trim().strip_prefix("pending/").unwrap();
    let confirm = VfsPath::parse(&format!("/pending/{id}/confirm")).unwrap();
    let error = handler.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        error.to_string().contains("no configured HTTP RPC URL"),
        "{error}"
    );
    assert!(
        !root
            .path()
            .join(format!("requests/pending/{id}/receipt.json"))
            .exists()
    );
    let repaired = handler
        .clone()
        .with_paid_http_rpc_resolver(Arc::new(StaticTempoRpc));
    let error = repaired.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("paid-http Broker approval required"),
        "{error}"
    );
    // No credential has been sent during either error, so cancellation is safe.
    repaired
        .write(
            &VfsPath::parse(&format!("/pending/{id}/cancel")).unwrap(),
            b"cancel",
        )
        .await
        .unwrap();
    assert!(root.path().join(format!("requests/failed/{id}")).exists());
    assert!(repaired.write(&confirm, b"confirm").await.is_err());
}

/// Exercises a multi-step preparer's failure after signing but before returning
/// a complete credential. No signed material has been sent to a merchant yet.
struct IncompletePreparation;

#[async_trait]
impl bloom_paid_x402::X402PaymentSigner for IncompletePreparation {
    async fn sign_x402_payment(
        &self,
        ctx: &bloom_paid_x402::X402SignContext<'_>,
    ) -> Result<bloom_paid_x402::X402PaymentCredential, String> {
        bloom_paid_x402::HostX402PaymentSigner::new()
            .sign_x402_payment(ctx)
            .await?;
        Err("credential preparation incomplete".into())
    }
}

#[tokio::test]
async fn locally_signed_but_unsubmitted_preparation_does_not_block_retry() {
    let root = tempfile::tempdir().unwrap();
    let (wallet, projections) = projection("0x1111111111111111111111111111111111111111".into());
    let (signer, broker) = exact_signer(wallet);
    let merchant = spawn_http_fixture("x402").await;
    let handler = RequestsHandler::new_projected(root.path(), Some("alice".into()), projections)
        .with_exact_signer(Some(signer))
        .with_x402_signer(Arc::new(IncompletePreparation));
    let id = stage_paid(&handler, root.path(), &merchant.join("paid").unwrap()).await;
    let confirm = VfsPath::parse(&format!("/pending/{id}/confirm")).unwrap();
    let error = handler.write(&confirm, b"confirm").await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("credential preparation incomplete"),
        "{error}"
    );
    assert!(!broker.signing_results.lock().unwrap().is_empty());
    assert!(
        !root
            .path()
            .join(format!("requests/pending/{id}/receipt.json"))
            .exists()
    );
    let handler = handler.with_x402_signer(Arc::new(bloom_paid_x402::HostX402PaymentSigner::new()));
    handler.write(&confirm, b"confirm").await.unwrap();
    assert!(
        root.path()
            .join(format!("requests/sent/{id}/receipt.json"))
            .exists()
    );
}
