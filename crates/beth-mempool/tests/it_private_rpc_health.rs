#![cfg(feature = "live-providers")]

use beth_mempool::private::{HealthStatus, PrivateRpcProvider};
use beth_mempool::providers::{flashbots::FlashbotsProvider, mev_blocker::MevBlockerProvider};

#[tokio::test]
async fn mev_blocker_health_returns_healthy() {
    if std::env::var("RUN_PRIVATE_RPC_HEALTH").is_err() {
        eprintln!("skipping: set RUN_PRIVATE_RPC_HEALTH=1 to run");
        return;
    }
    let p = MevBlockerProvider::default_endpoint().unwrap();
    let h = p.health().await.unwrap();
    assert!(matches!(h, HealthStatus::Healthy | HealthStatus::Degraded));
}

#[tokio::test]
async fn flashbots_health_returns_healthy() {
    if std::env::var("RUN_PRIVATE_RPC_HEALTH").is_err() {
        eprintln!("skipping: set RUN_PRIVATE_RPC_HEALTH=1 to run");
        return;
    }
    let p = FlashbotsProvider::new(beth_mempool::providers::flashbots::DEFAULT_URL).unwrap();
    let h = p.health().await.unwrap();
    assert!(matches!(h, HealthStatus::Healthy | HealthStatus::Degraded));
}
