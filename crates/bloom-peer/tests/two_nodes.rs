use std::sync::Arc;

use anyhow::Result;
use bloom_peer::{
    DecisionVerdict, PeerIdentity, PeerNodeBuilder, ReplayStore, ReviewDecision, ReviewRequest,
    TradeIntent, now_ms, payload_digest,
};
use uuid::Uuid;

#[tokio::test]
async fn two_iroh_nodes_exchange_dummy_review() -> Result<()> {
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice = PeerNodeBuilder::new(alice_identity.clone(), ReplayStore::memory()?)
        .allow_peer(bob_identity.endpoint_id())
        .bind()
        .await?;
    let bob = PeerNodeBuilder::new(bob_identity.clone(), ReplayStore::memory()?)
        .allow_peer(alice_identity.endpoint_id())
        .bind()
        .await?;

    let server = bob.serve(Arc::new(|_peer, request: ReviewRequest| async move {
        let request_digest = payload_digest(&request)?;
        Ok(ReviewDecision {
            schema: "bloom.trade-review-decision/v1".into(),
            request_id: request.request_id,
            request_digest,
            evaluator_alias: request.evaluator_alias,
            verdict: DecisionVerdict::Approve,
            reason_codes: vec!["dummy_evaluator".into()],
            conditions: vec![],
            valid_until_ms: request.expires_at_ms,
            advisory_only: true,
        })
    }));

    let request = ReviewRequest {
        schema: "bloom.trade-review-request/v1".into(),
        request_id: Uuid::new_v4(),
        evaluator_alias: "dummy-risk".into(),
        intent: TradeIntent {
            venue: "hyperliquid".into(),
            instrument: "BTC".into(),
            side: "buy".into(),
            order_type: "limit".into(),
            quantity: "0.01".into(),
            limit_price: Some("62000".into()),
        },
        facts: serde_json::json!({"dummy": true}),
        requested_output_schema: "bloom.trade-review-decision/v1".into(),
        expires_at_ms: now_ms() + 30_000,
    };
    let decision = alice.request_review(bob.endpoint_addr(), &request).await?;
    assert_eq!(decision.verdict, DecisionVerdict::Approve);
    assert!(decision.advisory_only);
    server.shutdown().await;
    alice.close().await;
    Ok(())
}

/// Live smoke test for the N0 preset (address lookup, NAT traversal and relay
/// registration). Kept ignored in CI because it requires public infrastructure;
/// maintainers can run it before releases or transport upgrades.
#[tokio::test]
#[ignore = "requires public N0 relay and address-lookup infrastructure"]
async fn two_n0_nodes_exchange_dummy_review() -> Result<()> {
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice = PeerNodeBuilder::new(alice_identity.clone(), ReplayStore::memory()?)
        .allow_peer(bob_identity.endpoint_id())
        .use_n0(true)
        .bind()
        .await?;
    let bob = PeerNodeBuilder::new(bob_identity.clone(), ReplayStore::memory()?)
        .allow_peer(alice_identity.endpoint_id())
        .use_n0(true)
        .bind()
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(20), alice.online()).await?;
    tokio::time::timeout(std::time::Duration::from_secs(20), bob.online()).await?;

    let server = bob.serve(Arc::new(|_peer, request: ReviewRequest| async move {
        let request_digest = payload_digest(&request)?;
        Ok(ReviewDecision {
            schema: "bloom.trade-review-decision/v1".into(),
            request_id: request.request_id,
            request_digest,
            evaluator_alias: request.evaluator_alias,
            verdict: DecisionVerdict::Abstain,
            reason_codes: vec!["n0_smoke".into()],
            conditions: vec![],
            valid_until_ms: request.expires_at_ms,
            advisory_only: true,
        })
    }));
    let request = ReviewRequest {
        schema: "bloom.trade-review-request/v1".into(),
        request_id: Uuid::new_v4(),
        evaluator_alias: "dummy-risk".into(),
        intent: TradeIntent {
            venue: "hyperliquid".into(),
            instrument: "ETH".into(),
            side: "buy".into(),
            order_type: "market".into(),
            quantity: "0.01".into(),
            limit_price: None,
        },
        facts: serde_json::json!({"n0": true}),
        requested_output_schema: "bloom.trade-review-decision/v1".into(),
        expires_at_ms: now_ms() + 30_000,
    };
    let decision = alice.request_review(bob.endpoint_addr(), &request).await?;
    assert_eq!(decision.verdict, DecisionVerdict::Abstain);
    server.shutdown().await;
    alice.close().await;
    Ok(())
}
