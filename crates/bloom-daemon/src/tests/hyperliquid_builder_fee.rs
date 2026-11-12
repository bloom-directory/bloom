//! Broker's fee verdict for the catalogued builder-order class, against real
//! services. The unit tests assert that enrollment *writes* `hyperliquid/usdc`
//! onto the class; this asserts that the pinned Broker then *judges* a claim
//! against that value.
//!
//! Nothing here reaches Hyperliquid. Both refusals land when Broker evaluates
//! the claim, before any signature exists. The accepted case does produce a
//! signature — over a four-byte payload that is not an order — and nothing is
//! submitted anywhere: the chain entry is dormant with broadcast disabled and
//! there is no RPC node.
use super::*;
use bloom_broker_api::{
    CryptoSuite, CustodyPrepareRequest, DecimalU64, DecimalU256, DeclaredFee, Digest32,
    OperationId, PetalUseClaim, ProvenanceSubject, RequestNonce, Token,
};
use bloom_machine_client::{
    ExactPayloadBatchSignRequest, ExactPayloadSignOutcome, MachineBrokerClient,
};
use bloom_vfs::VfsPath;

const WALLET: &str = "hlfee-authorization";
const BUILDER_CLASS: &str = "hyperliquid.builder_order";

fn setting(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("set {name} through scripts/test-hyperliquid-builder-fee.sh"))
        .into()
}

fn complete(url: &str, count: u64, mnemonic: Option<&Path>) {
    let mut command = std::process::Command::new(setting("BLOOM_INTEGRATION_DEBUG_DRIVER_BIN"));
    command.args([
        "complete",
        url,
        "hlfee-disposable-owner",
        "--sign-count",
        &count.to_string(),
    ]);
    if let Some(path) = mnemonic {
        command.arg("--mnemonic-file").arg(path);
    }
    // Never surface the capability URL, signatures or recovery data.
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "software-owner ceremony failed (exit {:?})",
        result.status.code()
    );
}

async fn read_json(vfs: &Vfs, path: &str) -> serde_json::Value {
    serde_json::from_slice(&vfs.read(&VfsPath::parse(path).unwrap()).await.unwrap()).unwrap()
}

/// SHA-256 over the batch domain and every preimage, as the claim commits to it.
fn batch_payload_digest(preimages: &[Vec<u8>]) -> Digest32 {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    digest.update(b"bloom.petal.payload-batch.v1\0");
    digest.update((preimages.len() as u64).to_be_bytes());
    for preimage in preimages {
        digest.update((preimage.len() as u64).to_be_bytes());
        digest.update(preimage);
    }
    Digest32::from_bytes(digest.finalize().into())
}

struct Fixture {
    client: MachineBrokerClient,
    catalog: bloom_broker_api::ProvenanceCatalog,
    daemon: Daemon,
    wallet: Token,
    package_hash: String,
}

/// A disposable owner, a disposable BIP-39 wallet and the Hyperliquid package
/// installed and approved, all through the real ceremony surface.
async fn fixture() -> Fixture {
    use sha2::Digest as _;
    let root = setting("BLOOM_TRIAD_DEVELOPER_ROOT");
    let home = HomeDir::at(setting("BLOOM_HOME"));
    let client = MachineBrokerClient::connect_unix_from_developer_files(
        &root,
        setting("BLOOM_BROKER_SOCKET"),
        setting("BLOOM_MACHINE_IDENTITY"),
        setting("BLOOM_EDGE_MANIFEST"),
    )
    .unwrap();
    let catalog: bloom_broker_api::ProvenanceCatalog =
        serde_json::from_slice(&std::fs::read(setting("BLOOM_PROVENANCE_CATALOG")).unwrap())
            .unwrap();
    let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
    let daemon = Daemon::from_home_with_permit_and_broker(
        home.clone(),
        permit,
        client.clone(),
        catalog.clone(),
    )
    .unwrap();

    let wallet = Token::new(WALLET).unwrap();
    let operation = OperationId::from_bytes([0x91; 32]);
    let imported = client
        .prepare_custody(
            bloom_machine_client::CustodyPrepareMethod::WalletImport,
            CustodyPrepareRequest {
                ceremony_kind: bloom_broker_api::CeremonyKind::WalletImport,
                surface_selection: bloom_broker_api::CeremonySurfaceSelection::Local,
                custody_operation_id: operation.clone(),
                wallet_id: Some(wallet.clone()),
                key_ref: None,
                exact_terms_digest: Digest32::from_bytes(
                    sha2::Sha256::digest(b"hlfee disposable import").into(),
                ),
                expected_input_class: Token::new("bip39-mnemonic").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1),
                derivation_requests: vec![],
                account_terms: None,
            },
        )
        .await
        .unwrap();
    complete(
        &imported.ceremony_url,
        1,
        Some(&setting("BLOOM_HLFEE_MNEMONIC_FILE")),
    );
    client
        .custody_result(bloom_broker_api::OperationRequest {
            operation_id: operation,
        })
        .await
        .unwrap();

    let allocate = VfsPath::parse(&format!("wallets/{WALLET}/new")).unwrap();
    daemon
        .vfs
        .write(&allocate, br#"{"request_id":"account-one"}"#)
        .await
        .unwrap();
    let allocation = read_json(&daemon.vfs, &format!("wallets/{WALLET}/new")).await;
    complete(
        allocation["requests"][0]["ceremony_url"].as_str().unwrap(),
        2,
        None,
    );

    let package =
        bloom_petals::package::build_petal_package_dir(setting("BLOOM_HLFEE_PETAL_ROOT")).unwrap();
    let package_hash = package.hash.clone();
    let staged = daemon.petals.store().stage_petal_package(package).unwrap();
    daemon
        .petals
        .install_staged_petal_package(staged, None, || Ok(()))
        .unwrap();

    // Broker requires the approval's package hash to be in the policy.
    let baseline = client.policy(wallet.clone()).await.unwrap();
    let mut policy: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(&baseline.canonical_policy.decode()).unwrap();
    policy
        .allowed_petal_packages
        .push(Digest32::new(package_hash.clone()).unwrap());
    let policy_bytes = serde_jcs::to_vec(&policy).unwrap();
    let policy_path = VfsPath::parse(&format!("wallets/{WALLET}/policy.json")).unwrap();
    assert!(daemon.vfs.write(&policy_path, &policy_bytes).await.is_err());
    let review = read_json(
        &daemon.vfs,
        &format!("wallets/{WALLET}/policy-updates/latest/approval_challenge.json"),
    )
    .await;
    complete(review["ceremony_url"].as_str().unwrap(), 3, None);
    daemon.vfs.write(&policy_path, &policy_bytes).await.unwrap();

    Fixture {
        client,
        catalog,
        daemon,
        wallet,
        package_hash,
    }
}

/// The live catalog's own builder-order record: the route Broker will judge
/// against, and the fee asset enrollment wrote onto it.
fn builder_record(
    catalog: &bloom_broker_api::ProvenanceCatalog,
    package_hash: &str,
) -> (String, Digest32, bloom_broker_api::ProvenanceFeeAsset) {
    let record = catalog
        .records
        .iter()
        .find(|record| match &record.subject {
            ProvenanceSubject::Petal {
                package_hash: hash, ..
            } => {
                hash.as_str() == package_hash
                    && record
                        .operation_classes
                        .iter()
                        .any(|class| class.operation_class.as_str() == BUILDER_CLASS)
            }
            _ => false,
        })
        .expect("the enrolled catalog must carry a builder-order record for this package");
    let ProvenanceSubject::Petal { route, .. } = &record.subject else {
        unreachable!()
    };
    let fee = record
        .operation_classes
        .iter()
        .find(|class| class.operation_class.as_str() == BUILDER_CLASS)
        .and_then(|class| class.fee_asset.clone())
        .expect("the builder-order class must be catalogued fee-bearing");
    (route.clone(), record.digest().unwrap(), fee)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires live services; run scripts/test-hyperliquid-builder-fee.sh"]
async fn broker_judges_a_builder_order_fee_against_the_catalogued_asset() {
    use sha2::Digest as _;
    let Fixture {
        client,
        catalog,
        daemon: _daemon,
        wallet,
        package_hash,
    } = fixture().await;
    let (route, provenance_digest, fee_asset) = builder_record(&catalog, &package_hash);
    // The disposable wallet has two active children for this suite, so Broker
    // refuses a request that does not name one -- KeyrefMismatch lands before
    // any fee logic, which is how the second run of this test failed.
    let accounts = client.wallet_accounts(wallet.clone()).await.unwrap();
    let account = accounts
        .accounts
        .iter()
        .find(|account| account.path == "m/44'/60'/0'/0/1")
        .expect("account one must exist")
        .key_ref
        .clone();
    assert_eq!(fee_asset.chain.as_str(), "hyperliquid");
    assert_eq!(fee_asset.asset, "usdc");

    // Deliberately NOT 0x19-prefixed. `is_signed_message` sends such a payload
    // down the single-payload review path, which refuses the batch form before
    // any fee logic runs — the first run of this test asserted a fee verdict it
    // never reached. The fee check is orthogonal to message review, so a plain
    // payload is what isolates it. It is never signed either way: every verdict
    // below lands before a signature exists.
    let preimages = vec![vec![0xA1u8, 0xB2, 0xC3, 0xD4]];
    let claimed_hashes: Vec<Digest32> = preimages
        .iter()
        .map(|payload| Digest32::from_bytes(alloy::primitives::keccak256(payload).into()))
        .collect();

    let mut nonce = 0u8;
    // Each prepared approval opens a ceremony, and Broker allows one live
    // ceremony per wallet: without cancelling, variants 2 and 3 come back
    // CeremonyRateLimited ("wallet already has a live ceremony") instead of a
    // fee verdict. The approval operation id is derived from the nonce so it
    // can be cancelled by id afterwards.
    let mut submit = |declared_fee: DeclaredFee, sign_count: u64| {
        nonce += 1;
        let claim = PetalUseClaim {
            package_hash: Digest32::new(package_hash.clone()).unwrap(),
            route: route.clone(),
            operation_class: Token::new(BUILDER_CLASS).unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: batch_payload_digest(&preimages),
            ordered_hashes: claimed_hashes.clone(),
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee,
            nonce: RequestNonce::from_bytes([nonce; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let request = ExactPayloadBatchSignRequest {
            message_review_payload: None,
            wallet_id: wallet.clone(),
            preimages: preimages.clone(),
            claimed_hashes: claimed_hashes.clone(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::Petal {
                package_hash: Digest32::new(package_hash.clone()).unwrap(),
                route: route.clone(),
            },
            provenance_digest: provenance_digest.clone(),
            activation_mode: None,
            approval_operation_id: OperationId::from_bytes([0xA0 + nonce; 32]),
            signing_operation_id: OperationId::from_bytes([0xB0 + nonce; 32]),
            request_nonce: RequestNonce::from_bytes([0xC0 + nonce; 16]),
            issued_at_ms: DecimalU64::new(now),
            expires_at_ms: DecimalU64::new(now + 600_000),
            canonical_plan_facts_digest: Digest32::from_bytes(
                sha2::Sha256::digest(b"hlfee plan facts").into(),
            ),
            approval_id: None,
            petal_use_claim: Some(claim),
            claim_assurance_evidence: None,
            account_key_ref: Some(account.clone()),
        };
        // The reusable path, not the exact one. service.rs chains
        // BUILDER_ORDER_CLASS in after both review tables, but only for
        // ApprovalSelector::Exact -- so an exact builder order answers
        // SelectorMismatch ("requires a review envelope") before any fee logic
        // runs. Broker's comment there says sessions sign builder orders under
        // reusable grants, so this is both the path that reaches the fee check
        // and the realistic one.
        let client = client.clone();
        async move {
            // The fee verdict is reached only at authorize. `prepare_approval`
            // never inspects `declared_fee`, and every site that raises
            // FEE_REQUIRED, FEE_ASSET_MISMATCH or FEE_NOT_ALLOWED lives in
            // `account_declared_values`, which only
            // `authorize_for_clock_profile` calls. A prepared approval is
            // therefore carried through its ceremony and submitted again; the
            // second answer is the verdict.
            //
            // Completing is also why the next variant is not refused. The
            // earlier form cancelled instead, which leaves the wallet in a
            // cancellation backoff far longer than any retry here waited out,
            // so variants 2 and 3 came back CeremonyRateLimited.
            let prepared = client
                .sign_reusable_petal_payload_batch(request.clone())
                .await;
            match prepared {
                Ok(ExactPayloadSignOutcome::ApprovalRequired(approval)) => {
                    complete(&approval.ceremony_url, sign_count, None);
                    let mut authorized = request.clone();
                    authorized.approval_id = Some(approval.approval_id.clone());
                    client.sign_reusable_petal_payload_batch(authorized).await
                }
                // A refusal that lands before any ceremony is already a verdict.
                other => other,
            }
        }
    };

    let fee = |chain: &str, asset: &str, amount: &str| DeclaredFee::Fee {
        chain: Token::new(chain).unwrap(),
        asset: asset.to_owned(),
        amount: DecimalU256::parse(amount).unwrap(),
    };

    // 1. A fee-bearing class that declares no fee.
    let none = submit(DeclaredFee::None, 4).await;
    let none = format!("{none:?}");
    println!("VERDICT declared_fee=None -> {none}");

    // 2. A fee in an asset the record does not name.
    let mismatch = submit(fee("polygon", "pusd", "7"), 5).await;
    let mismatch = format!("{mismatch:?}");
    println!("VERDICT declared_fee=polygon/pusd -> {mismatch}");

    // 3. The asset the record does name.
    let matching = submit(fee("hyperliquid", "usdc", "7"), 6).await;
    let matching = format!("{matching:?}");
    println!("VERDICT declared_fee=hyperliquid/usdc -> {matching}");

    // Earlier revisions leaned on this to prove the fee was read, which it
    // cannot do once a verdict succeeds: these are Debug strings carrying
    // unique approval ids and ceremony URLs, so on any Ok path they differ by
    // construction. It still catches the one case it was written for -- a gate
    // in front of the fee check answering every variant with the same error,
    // which happened three times getting here (0x19 routed to the review path,
    // KeyrefMismatch, CeremonyRateLimited). The three message assertions below
    // are what actually prove the declared fee was read, because the messages
    // are mutually exclusive.
    assert!(
        none != mismatch || mismatch != matching,
        "three identical verdicts means the declared fee was never read: {none}"
    );
    // FEE_REQUIRED and FEE_ASSET_MISMATCH are Broker-internal: `denied(code,
    // message)` crosses the boundary as ProtocolError { code: ClaimInvalid,
    // message }, dropping the symbolic code. The message is what arrives, so
    // it is what these match on — matching the code name asserted something
    // the client can never see.
    assert!(
        none.contains("fee-bearing operation class must declare its native fee"),
        "a catalogued fee-bearing class must refuse DeclaredFee::None: {none}"
    );
    assert!(
        mismatch.contains("declared fee does not match provenance fee asset"),
        "a fee in an uncatalogued asset must be refused: {mismatch}"
    );
    assert!(
        matching.contains("Signed"),
        "the catalogued asset must be accepted, not refused on fee grounds: {matching}"
    );
}
