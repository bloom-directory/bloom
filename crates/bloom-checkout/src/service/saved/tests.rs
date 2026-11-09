use super::*;
use bloom_signer_api::{
    Base64UrlBytes, CeremonyKind, Digest32, HpkeEnvelope, legacy_local_surface,
};
use hpke::{
    Deserializable, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use std::sync::atomic::{AtomicU8, Ordering};

const FORM: &str = r#"<p>Order total USD <span id="price">3.99</span></p>
<form onsubmit="event.preventDefault();window.attempts=(window.attempts||0)+1;document.body.innerHTML='<h1>Order confirmed</h1><p>Order ID: FIXTURE-ONE</p>'">
<input autocomplete="given-name"><input autocomplete="family-name">
<input autocomplete="cc-name"><input autocomplete="cc-number">
<input autocomplete="cc-exp"><input autocomplete="cc-csc"><button>Pay USD 3.99</button></form>"#;

fn sealed_result(request: &Value) -> Value {
    let operation = OperationId::new(request["operation_id"].as_str().unwrap()).unwrap();
    let aad = CustodyOutputHpkeAad {
        surface: legacy_local_surface(),
        ceremony_id: Digest32::from_bytes([1; 32]),
        ceremony_kind: CeremonyKind::CardCheckout,
        custody_operation_id: operation.clone(),
        signer_contribution_digest: Digest32::from_bytes([2; 32]),
        public_binding_digest: Digest32::from_bytes([3; 32]),
    };
    let public: Base64UrlBytes = serde_json::from_value(request["recipient_key"].clone()).unwrap();
    let key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&public.decode()).unwrap();
    let (encap, mut sender) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &hpke::OpModeS::Base,
        &key,
        b"bloom-custody-output/v1",
    )
    .unwrap();
    let values = if request["method"] == "traveler" {
        json!({"given_name":"PrivateAlice","family_name":"PrivateTraveler"})
    } else {
        json!({"number":"4242424242424242","expiry_month":12,"expiry_year":2030,"cvc":"123","name":"PrivateAlice"})
    };
    let ciphertext = sender
        .seal(
            &serde_json::to_vec(&values).unwrap(),
            &aad.canonical_bytes().unwrap(),
        )
        .unwrap();
    let receipt = CustodyResult {
        surface: Some(aad.surface.clone()),
        credential_authority_generation: None,
        ceremony_kind: CeremonyKind::CardCheckout,
        custody_operation_id: operation.clone(),
        public_status: bloom_signer_api::CeremonyState::Succeeded,
        wallet_id: None,
        public_key_refs: vec![],
        credential_summaries: vec![],
        initial_policy: None,
        receipt_digest: Digest32::from_bytes([4; 32]),
        encrypted_browser_result: Some(HpkeEnvelope {
            kem_output: Base64UrlBytes::from_bytes(&encap.to_bytes()),
            ciphertext: Base64UrlBytes::from_bytes(&ciphertext),
        }),
        signer_key_id: Token::new("fixture").unwrap(),
        signer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
    };
    json!({"kind":"result","status":{"operation_id":operation,"state":"succeeded","receipt":null,"output_aad":null},
        "receipt":receipt,"output_aad":aad})
}

async fn fixture() -> (
    Arc<CheckoutService>,
    String,
    String,
    Arc<AtomicU8>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let (service, parent, token, server) =
        super::super::tests::watched_checkout(FORM, "human_control", false, false).await;
    service.private.lock().await.as_mut().unwrap().mode = Mode::TakeOver;
    let tab = service.private.lock().await.as_ref().unwrap().tab.clone();
    tab.cdp.evaluate(&tab.session, "sessionStorage.itinerary='FLIGHT-ONE';document.cookie='seller=fixture;SameSite=Strict'".into()).await.unwrap();
    let listener = tokio::net::UnixListener::bind(&service.broker_socket).unwrap();
    let decision = Arc::new(AtomicU8::new(0));
    let signal = decision.clone();
    let broker = tokio::spawn(async move {
        let mut prepared = Value::Null;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            BufReader::new(reader).read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let response = match request["method"].as_str().unwrap() {
                "traveler_info" => {
                    json!({"kind":"traveler","traveler":{"traveler_id":"self","label":"Me","fields":["given_name","family_name"]}})
                }
                "traveler" | "prepare" => {
                    prepared = request;
                    json!({"kind":"prepared","ceremony_url":"http://localhost:28735/private-review-secret"})
                }
                "result" => match signal.load(Ordering::SeqCst) {
                    1 => sealed_result(&prepared),
                    2 => {
                        json!({"kind":"result","status":{"operation_id":request["operation_id"],"state":"cancelled","receipt":null,"output_aad":null},"receipt":null,"output_aad":null})
                    }
                    _ => {
                        json!({"kind":"result","status":{"operation_id":request["operation_id"],"state":"prepared","receipt":null,"output_aad":null},"receipt":null,"output_aad":null})
                    }
                },
                _ => json!({"kind":"error"}),
            };
            let mut encoded = serde_json::to_vec(&response).unwrap();
            encoded.push(b'\n');
            writer.write_all(&encoded).await.unwrap();
        }
    });
    (service, parent, token, decision, vec![server, broker])
}

async fn idle(service: &CheckoutService) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while service.require_saved_idle().is_err() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}

async fn session_intact(service: &CheckoutService, token: &str) {
    let tab = service.private.lock().await.as_ref().unwrap().tab.clone();
    let state = tab
        .cdp
        .evaluate(
            &tab.session,
            "({itinerary:sessionStorage.itinerary,cookie:document.cookie})".into(),
        )
        .await
        .unwrap();
    assert_eq!(state["itinerary"], "FLIGHT-ONE");
    assert!(state["cookie"].as_str().unwrap().contains("seller=fixture"));
    assert!(
        service
            .browser
            .browse(BrowseRequest::Snapshot)
            .await
            .is_err()
    );
    assert_eq!(service.private_state(token).await.unwrap()["closed"], false);
}

#[tokio::test]
async fn traveler_approval_keeps_private_session_and_never_exposes_review_url() {
    let (service, parent, token, decision, tasks) = fixture().await;
    assert!(
        service
            .private_saved(
                "wrong",
                SavedAction::Traveler {
                    traveler_id: "self".into()
                }
            )
            .await
            .is_err()
    );
    let status = service
        .private_saved(
            &token,
            SavedAction::Traveler {
                traveler_id: "self".into(),
            },
        )
        .await
        .unwrap();
    let operation = status["operation_id"].as_str().unwrap();
    assert!(service.store.get(operation).unwrap().ceremony_url.is_none());
    assert!(
        !serde_json::to_string(&service.store.history().unwrap())
            .unwrap()
            .contains("private-review-secret")
    );
    assert!(
        service
            .private_action(&token, ViewAction::Finish)
            .await
            .is_err()
    );
    assert!(
        service
            .private_action(
                &token,
                ViewAction::Type {
                    text: "unsafe".into()
                }
            )
            .await
            .is_err()
    );
    assert!(
        service
            .private_saved(
                &token,
                SavedAction::Traveler {
                    traveler_id: "self".into()
                }
            )
            .await
            .is_err()
    );
    decision.store(1, Ordering::SeqCst);
    idle(&service).await;
    assert_eq!(
        service.store.get(operation).unwrap().state,
        "traveler_filled"
    );
    let tab = service.private.lock().await.as_ref().unwrap().tab.clone();
    assert_eq!(
        tab.cdp
            .evaluate(
                &tab.session,
                "document.querySelector('[autocomplete=given-name]').value".into()
            )
            .await
            .unwrap(),
        "PrivateAlice"
    );
    assert_eq!(
        service.private.lock().await.as_ref().unwrap().operation_id,
        parent
    );
    session_intact(&service, &token).await;
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn cancelled_payment_preserves_seller_then_changed_price_requires_fresh_approval() {
    let (service, _, token, decision, tasks) = fixture().await;
    assert!(
        service
            .private_saved(
                &token,
                SavedAction::Pay {
                    card_id: "card".into(),
                    unpaid_checked: false
                }
            )
            .await
            .is_err()
    );
    let first = service
        .private_saved(
            &token,
            SavedAction::Pay {
                card_id: "card".into(),
                unpaid_checked: true,
            },
        )
        .await
        .unwrap();
    decision.store(2, Ordering::SeqCst);
    idle(&service).await;
    assert_eq!(
        service
            .store
            .get(first["operation_id"].as_str().unwrap())
            .unwrap()
            .state,
        "failed_before_release"
    );
    session_intact(&service, &token).await;
    decision.store(0, Ordering::SeqCst);
    let second = service
        .private_saved(
            &token,
            SavedAction::Pay {
                card_id: "card".into(),
                unpaid_checked: true,
            },
        )
        .await
        .unwrap();
    let tab = service.private.lock().await.as_ref().unwrap().tab.clone();
    tab.cdp
        .evaluate(
            &tab.session,
            "document.getElementById('price').textContent='4.99'".into(),
        )
        .await
        .unwrap();
    decision.store(1, Ordering::SeqCst);
    idle(&service).await;
    assert_eq!(
        service
            .store
            .get(second["operation_id"].as_str().unwrap())
            .unwrap()
            .state,
        "failed_before_release"
    );
    assert_eq!(
        tab.cdp
            .evaluate(
                &tab.session,
                "document.querySelector('[autocomplete=cc-number]').value".into()
            )
            .await
            .unwrap(),
        ""
    );
    session_intact(&service, &token).await;
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn approved_payment_submits_once_and_keeps_confirmation_private() {
    let (service, parent, token, decision, tasks) = fixture().await;
    let status = service
        .private_saved(
            &token,
            SavedAction::Pay {
                card_id: "card".into(),
                unpaid_checked: true,
            },
        )
        .await
        .unwrap();
    let id = status["operation_id"].as_str().unwrap();
    decision.store(1, Ordering::SeqCst);
    idle(&service).await;
    tokio::time::timeout(Duration::from_secs(15), async {
        while !matches!(
            service.store.get(id).unwrap().state.as_str(),
            "paid" | "booked"
        ) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(service.store.get(&parent).unwrap().state, "resolved");
    session_intact(&service, &token).await;
    let tab = service.private.lock().await.as_ref().unwrap().tab.clone();
    assert_eq!(
        tab.cdp
            .evaluate(&tab.session, "window.attempts".into())
            .await
            .unwrap(),
        1
    );
    assert!(
        service
            .private_saved(
                &token,
                SavedAction::Pay {
                    card_id: "card".into(),
                    unpaid_checked: true
                }
            )
            .await
            .is_err()
    );
    service
        .private_action(&token, ViewAction::Finish)
        .await
        .unwrap();
    assert!(matches!(
        service.store.get(id).unwrap().state.as_str(),
        "paid" | "booked"
    ));
    for task in tasks {
        task.abort();
    }
}
