//! Local-validator lifecycle E2E: stage → sign → broadcast → reconcile against
//! a real Agave validator. `#[ignore]`d — driven by
//! `.github/workflows/solana-validator.yml`, which installs the validator,
//! starts it, and runs this with `SOLANA_VALIDATOR_HTTP`.

use std::sync::Arc;

use bloom_machine_client::MachineBrokerClient;
use bloom_solana::{EndpointSpec, SolanaChainRegistry, SolanaClient, SolanaRpcError, SolanaSpec};
use bloom_solana_tx::engine::SolanaTransferEngine;
use bloom_solana_tx::outbox::SolanaOutbox;
use bloom_solana_tx::reconcile::SolanaReconciler;
use bloom_solana_tx::signing::{SolanaSignOutcome, SolanaTransferSigner};

mod common;
use common::{BrokerFixture, catalog};

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Test-only faucet: fund a base58 account over the same transport. The
/// read-only client deliberately has no airdrop method.
async fn request_airdrop(
    endpoint: &EndpointSpec,
    account: &str,
    lamports: u64,
) -> Result<String, SolanaRpcError> {
    let rpc = bloom_solana::transport::SolanaRpcClient::build(&SolanaSpec {
        name: "solana-test-airdrop".into(),
        endpoints: vec![endpoint.clone()],
        expected_genesis_base58: None,
    })?;
    rpc.call("requestAirdrop", &serde_json::json!([account, lamports]))
        .await
}

#[tokio::test]
#[ignore]
async fn local_validator_lifecycle_stage_sign_broadcast_reconcile() {
    let endpoint =
        std::env::var("SOLANA_VALIDATOR_HTTP").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    let endpoint_spec = EndpointSpec {
        url: endpoint,
        weight: 100,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    };
    let discovery_client = SolanaClient::build(&SolanaSpec {
        name: "solana-local-discovery".into(),
        endpoints: vec![endpoint_spec.clone()],
        expected_genesis_base58: None,
    })
    .unwrap();
    let genesis = discovery_client
        .verify_genesis()
        .await
        .expect("discover local validator genesis");
    let airdrop_spec = endpoint_spec.clone();
    let client = SolanaClient::build(&SolanaSpec {
        name: "solana-local".into(),
        endpoints: vec![endpoint_spec],
        expected_genesis_base58: Some(genesis),
    })
    .unwrap();
    client.get_health().await.expect("validator is healthy");

    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let engine = SolanaTransferEngine::new(outbox.clone(), client.clone(), signer, "solana-local");

    let fee_payer = broker.child_pubkey();
    let fee_payer_b58 = bs58::encode(fee_payer).into_string();
    println!("fee_payer={fee_payer_b58}");
    let airdrop_lamports = std::env::var("SOLANA_AIRDROP_LAMPORTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000_000_000);
    let transfer_lamports = std::env::var("SOLANA_TRANSFER_LAMPORTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000_000);
    assert!(transfer_lamports > 0);
    assert!(airdrop_lamports > transfer_lamports + 5_000);

    // Fund the derived child and wait for the balance to land.
    let mut airdrop_result = None;
    for attempt in 0..3 {
        match request_airdrop(&airdrop_spec, &fee_payer_b58, airdrop_lamports).await {
            Ok(signature) => {
                airdrop_result = Some(signature);
                break;
            }
            Err(error) if attempt < 2 => {
                eprintln!("airdrop attempt {} failed: {error}", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(error) => panic!("airdrop to the derived child: {error}"),
        }
    }
    assert!(airdrop_result.is_some());
    for _ in 0..30 {
        if client.get_balance(&fee_payer_b58).await.unwrap_or(0) >= airdrop_lamports {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        client.get_balance(&fee_payer_b58).await.unwrap_or(0) >= airdrop_lamports,
        "airdrop must fund the derived child"
    );

    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    let staged = engine
        .stage(
            "wallet",
            &fee_payer,
            Default::default(),
            &destination,
            transfer_lamports,
            now_ms(),
        )
        .await
        .expect("stage against the local validator");

    let first = engine
        .sign("wallet", &staged.id, &fee_payer, None, None, now_ms())
        .await
        .expect("prepare the signing ceremony");
    let approval_id = match first {
        SolanaSignOutcome::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval_id),
            now_ms(),
        )
        .await
        .expect("sign");
    assert!(matches!(signed, SolanaSignOutcome::Signed { .. }));

    let signature = engine
        .broadcast("wallet", &staged.id, now_ms())
        .await
        .expect("broadcast against the local validator");

    // Reconcile: the sent entry must reach a confirmed receipt.
    let registry = SolanaChainRegistry::new();
    registry.add(client);
    let audit = Arc::new(bloom_proto::AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit);
    for _ in 0..30 {
        if reconciler.tick().await > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = outbox
        .read_receipt("wallet", "solana-local", &staged.id)
        .unwrap()
        .expect("reconciler writes a receipt");
    assert_eq!(receipt.signature, signature);
    assert_eq!(receipt.outcome, "success");
    println!(
        "confirmed_signature={} destination={} lamports={transfer_lamports}",
        receipt.signature,
        bs58::encode(destination).into_string()
    );
}
