use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_broker_api::{DerivationRef, Digest32, KeyRef, KeySpec, Token};
use bloom_petals::{
    HostError, HostVfsEntry, PayloadSignRequest, PetalHost, PetalKeyOutcome, PetalKeyRequest,
    PetalRouter, PetalRunner, PetalStore, PetalVm, SignOutcome,
};
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};
use parking_lot::Mutex;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/triad-authority-petal"
);

#[derive(Default)]
struct AuthorityHost {
    key_outcomes: Mutex<VecDeque<PetalKeyOutcome>>,
    key_requests: Mutex<Vec<PetalKeyRequest>>,
    sign_requests: Mutex<Vec<PayloadSignRequest>>,
}

#[async_trait]
impl PetalHost for AuthorityHost {
    async fn vfs_lookup(&self, _path: &str) -> Result<HostVfsEntry, HostError> {
        Err(HostError::Denied(
            "fixture does not import VFS authority".into(),
        ))
    }

    async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied(
            "fixture does not import VFS authority".into(),
        ))
    }

    async fn vfs_list(&self, _path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        Err(HostError::Denied(
            "fixture does not import VFS authority".into(),
        ))
    }

    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied(
            "fixture does not import VFS authority".into(),
        ))
    }

    async fn petal_key_request(
        &self,
        request: PetalKeyRequest,
    ) -> Result<PetalKeyOutcome, HostError> {
        self.key_requests.lock().push(request);
        self.key_outcomes
            .lock()
            .pop_front()
            .ok_or_else(|| HostError::Backend("missing test key outcome".into()))
    }

    async fn sign_payload_outcome(
        &self,
        request: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        self.sign_requests.lock().push(request);
        Ok(SignOutcome::Signature(vec![0x5a; 65]))
    }
}

fn delegated_key() -> KeyRef {
    KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("fixture").unwrap(),
        locator: "wallet/wallet/petals/fixture-child".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: Digest32::from_bytes([0x44; 32]),
        derivation: Some(DerivationRef::Bip32Secp256k1 {
            root_key_id: Token::new("wallet-root").unwrap(),
            path: "m/44'/60'/0'/18734/1".into(),
        }),
    }
}

#[tokio::test]
async fn mounted_fixture_reconciles_public_key_then_payload_signs_with_its_keyref() {
    let temp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(temp.path().join("petals")).unwrap();
    store.install_petal_package_dir(FIXTURE).unwrap();
    let registry =
        Arc::new(bloom_petals::NameRegistry::open(temp.path().join("registry")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    let host = Arc::new(AuthorityHost::default());
    let key_ref = delegated_key();
    let key_ref_jcs = serde_jcs::to_vec(&key_ref).unwrap();
    host.key_outcomes.lock().extend([
        PetalKeyOutcome::Pending {
            operation_id: "11".repeat(32),
            scope_digest: "22".repeat(32),
        },
        PetalKeyOutcome::Ready {
            operation_id: "11".repeat(32),
            scope_digest: "22".repeat(32),
            key_ref_jcs: key_ref_jcs.clone(),
            addresses: vec!["0x1234".into()],
        },
    ]);
    let vfs = Vfs::builder()
        .mount("petals", Arc::new(PetalRouter::new(runner, host.clone())))
        .build();
    let mounted = VfsPath::parse("/petals/triad-authority-fixture/session.json").unwrap();
    let request = serde_json::to_vec(&serde_json::json!({
        "request_id": "mounted-fixture-1",
        "wallet_id": "wallet",
        "purpose": "fixture-agent",
        "maximum_lifetime_ms": 300_000,
        "preimage_hex": hex::encode(b"full payload, never a bare hash"),
        "nonce_hex": "00112233445566778899aabbccddeeff",
        "approval_hint": "33".repeat(32)
    }))
    .unwrap();

    vfs.write(&mounted, &request).await.unwrap();
    let pending: serde_json::Value =
        serde_json::from_slice(&vfs.read(&mounted).await.unwrap()).unwrap();
    assert_eq!(pending["stage"], "key");
    assert_eq!(pending["outcome"]["state"], "pending");
    assert!(host.sign_requests.lock().is_empty());

    vfs.write(&mounted, &request).await.unwrap();
    let complete_bytes = vfs.read(&mounted).await.unwrap();
    let complete: serde_json::Value = serde_json::from_slice(&complete_bytes).unwrap();
    assert_eq!(complete["stage"], "complete");
    assert_eq!(complete["public_key"]["addresses"][0], "0x1234");
    assert_eq!(complete["signature_hex"], "5a".repeat(65));
    let rendered = String::from_utf8(complete_bytes).unwrap();
    for forbidden in ["private_key", "secret_key", "seed", "mnemonic"] {
        assert!(!rendered.contains(forbidden), "leaked {forbidden}");
    }

    let key_requests = host.key_requests.lock();
    assert_eq!(key_requests.len(), 2);
    for key_request in key_requests.iter() {
        let context = key_request.context.as_ref().expect("trusted route context");
        assert_eq!(context.petal_root, "triad-authority-fixture");
        assert_eq!(context.route_id, "r000001");
        assert_eq!(context.op, "write");
        assert_eq!(
            key_request.allowed_crypto_suites,
            ["secp256k1-sha256-recoverable"]
        );
    }

    let sign_requests = host.sign_requests.lock();
    assert_eq!(sign_requests.len(), 1);
    let signed = &sign_requests[0];
    assert_eq!(signed.preimage, b"full payload, never a bare hash");
    assert_eq!(signed.key_ref.as_ref(), Some(&key_ref));
    assert_eq!(signed.operation_class, "fixture.payload");
    let expected_approval = "33".repeat(32);
    assert_eq!(
        signed.approval_hint.as_deref(),
        Some(expected_approval.as_str())
    );
    let claim: serde_json::Value = serde_json::from_slice(&signed.petal_use_claim_jcs).unwrap();
    assert_eq!(
        claim["package_hash"],
        signed.context.as_ref().unwrap().package_hash
    );
    assert_eq!(claim["route"], "r000001");
    assert_eq!(claim["ordered_hashes"][0], hex::encode(signed.claimed_hash));
}

#[test]
fn fixture_is_an_installable_package_with_only_scoped_authority_imports() {
    let package = bloom_petals::package::PreparedPetalPackage::from_dir(FIXTURE).unwrap();
    assert_eq!(package.name, "triad-authority-fixture");
    assert_eq!(
        package.hash,
        "d1e895bb0ee3fd58a2a0d434724cb6060adb769f8604286a2906fd9b8295e9c6"
    );
    assert_eq!(package.route_index.routes.len(), 1);
    assert_eq!(package.route_index.routes[0].pattern, "session.json");
    assert_eq!(
        package.route_index.routes[0].key_derive_operation_classes,
        ["fixture.payload"]
    );
    let component = std::fs::read(format!(
        "{FIXTURE}/petal/triad-authority-fixture/session.json.wasm"
    ))
    .unwrap();
    let text = String::from_utf8_lossy(&component);
    assert!(text.contains("bloom:key/derive@0.1.0"));
    assert!(text.contains("bloom:sign/signing@0.2.0"));
    assert!(!text.contains("bloom:sign/signing@0.1.0"));
    assert!(!text.contains("sign-hash"));
}
