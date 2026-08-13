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
                    if request.key_ref == self.wallet.root_key_ref =>
                {
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        key_ref: request.key_ref,
                        role: bloom_broker_api::KeyRole::WalletRoot,
                        canonical_public_key: Base64UrlBytes::from_bytes(&[3; 33]),
                        addresses: Vec::new(),
                        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
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
        root_key_ref: key_ref.clone(),
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
