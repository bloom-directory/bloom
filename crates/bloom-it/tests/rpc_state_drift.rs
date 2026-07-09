//! Category: integration
//!
//! Integration test for the block-pinning session introduced in WP-5
//! of the RPC robustness overhaul.
//!
//! Spawns two `anvil` instances on independent ports, mines a different
//! number of blocks on each, and exercises the session API across the
//! cross-mining gap. The two anvils never share state, so each has its
//! own block hashes — a session opened against the multi-endpoint
//! `ChainClient` pins the hash from whichever anvil "won" the open
//! call. The other anvil cannot match that hash, so any retry that
//! lands on the loser will surface a "block not found"-shaped error
//! and degrade the session via the `BlockId::Number` fallback path.
//!
//! What the test asserts:
//!
//! - `open_session()` succeeds and returns a non-zero pinned number
//!   (one of the two anvils answered, our session captured its head).
//! - 10 sequential `session.balance()` calls all return without error.
//!   The fallback layer races both anvils per call; the session
//!   tolerates the cross-anvil mismatch through its degrade-and-retry
//!   path, which is the architectural invariant WP-5 promises.
//! - After mining more blocks on the winning anvil, balance reads
//!   continue to return — the session pin is hash-based, not
//!   tag-based, so a moving head doesn't break the session.
//!
//! What the test does NOT assert:
//!
//! - `is_degraded() == false`. With two independent anvils the pinned
//!   hash is unique to one transport; the spec note in WP-5 explicitly
//!   accepts that "anvils-with-different-chains can never agree on
//!   block hashes", so the test documents whichever degrade outcome
//!   the architecture actually delivers rather than fighting it. The
//!   degraded path itself is the more important coverage — it
//!   exercises the retry logic that real-world cross-provider drift
//!   triggers.
//!
//! Like the rest of `bloom-it`, the test is gated `#[ignore]` so CI
//! runs that lack a foundry install (or just don't want to spawn
//! processes) skip cleanly. Invoke with:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored rpc_state_drift
//! ```

use anyhow::{Context, Result, anyhow};
use bloom_evm::ChainClient;
use bloom_it::spawn_anvil;
use bloom_proto::ChainSpec;
use serde_json::json;

/// Drive `evm_mine` on `rpc_url` to advance the chain by `count`
/// blocks. Anvil mines exactly one block per call, so we loop.
async fn mine(rpc_url: &str, count: u32) -> Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..count {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "evm_mine",
            "params": [],
        });
        let resp = client
            .post(rpc_url)
            .json(&req)
            .send()
            .await
            .context("evm_mine request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("evm_mine non-2xx: {}", resp.status()));
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn session_pins_across_two_anvils_with_different_heights() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_rpc=debug")),
        )
        .with_test_writer()
        .try_init();

    // Two anvils, no shared state. Mine 5 on A, 3 on B so the heads
    // diverge in both height and (more importantly) hash.
    let anvil_a = spawn_anvil().await.context("spawn anvil A")?;
    let anvil_b = spawn_anvil().await.context("spawn anvil B")?;
    let url_a = anvil_a.rpc_url();
    let url_b = anvil_b.rpc_url();

    mine(&url_a, 5).await.context("mine on A")?;
    mine(&url_b, 3).await.context("mine on B")?;

    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![url_a.clone(), url_b.clone()];
    let client = ChainClient::new(spec).map_err(|e| anyhow!("build chain client: {e}"))?;

    let session = client
        .open_session()
        .await
        .map_err(|e| anyhow!("open session: {e}"))?;
    let pinned_at_open = session.block_number();
    let degraded_at_open = session.is_degraded();
    eprintln!(
        "rpc_state_drift: opened session at block {pinned_at_open} (degraded={degraded_at_open})"
    );
    // Pinned head must be at least the lower of the two anvils (3).
    assert!(
        pinned_at_open >= 3,
        "pinned head should reflect at least the slower anvil (3), got {pinned_at_open}"
    );

    // 10 balance reads on a known prefunded anvil account. Each must
    // return without error — even when the fallback layer rotates to
    // the anvil that doesn't have the pinned hash (the session
    // degrades and retries by number).
    let prefunded = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        .parse::<alloy::primitives::Address>()
        .unwrap();
    for i in 0..10 {
        session
            .balance(prefunded)
            .await
            .with_context(|| format!("session.balance iteration {i}"))?;
    }

    // Mine 5 more on the assumed winner (whichever anvil's head we
    // pinned — we don't know without inspecting hashes, so mine on
    // both: only the winner's pinned hash needs to remain reachable).
    mine(&url_a, 5).await?;
    mine(&url_b, 5).await?;

    // The session must still answer at the pinned hash. When the
    // pinned hash is no longer the head, the historical balance read
    // should still resolve from any archive-capable upstream — anvil
    // keeps full state by default.
    let _ = session
        .balance(prefunded)
        .await
        .context("post-mine session.balance")?;

    // Document the actual degrade outcome rather than asserting one
    // shape. With two independent anvils the pinned hash is only on
    // one provider, so the session WILL flip degraded the first time
    // a parallel-fanout call lands on the loser. The fact that
    // balance reads continue to return is the substantive WP-5
    // invariant; degrade-flag observability is a bonus.
    eprintln!(
        "rpc_state_drift: session degraded={} after 11 reads at pinned block {}",
        session.is_degraded(),
        session.block_number()
    );

    drop(anvil_a);
    drop(anvil_b);
    Ok(())
}
