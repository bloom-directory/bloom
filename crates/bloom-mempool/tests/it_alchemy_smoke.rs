//! Category: smoke
//!
#![cfg(feature = "live-providers")]

use bloom_mempool::provider::MempoolProvider;
use bloom_mempool::providers::alchemy::AlchemyProvider;
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn alchemy_yields_at_least_one_pending_tx_in_30s() {
    let Ok(key) = std::env::var("ALCHEMY_API_KEY") else {
        eprintln!("skip: ALCHEMY_API_KEY is not set");
        return;
    };
    let url = format!("wss://eth-mainnet.g.alchemy.com/v2/{key}");
    let provider = AlchemyProvider::new(url);
    let mut stream = provider.subscribe().await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("no pending tx within 30s")
        .expect("stream ended");
    assert_ne!(first.hash, alloy::primitives::B256::ZERO);
}
