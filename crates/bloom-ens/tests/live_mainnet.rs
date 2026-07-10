//! Category: integration
//!
//! Live integration test against an Ethereum mainnet RPC.
//!
//! Skipped unless `BLOOM_MAINNET_RPC` is set. Also `#[ignore]`d so it
//! never runs under a plain `cargo test` — invoke with
//! `cargo test -p bloom-ens -- --ignored`.

use alloy::primitives::{Address, address};
use bloom_ens::EnsClient;
use bloom_evm::ChainClient;
use bloom_proto::ChainSpec;

const VITALIK: Address = address!("d8dA6BF26964aF9D7eED9e03E53415D37aA96045");

fn mainnet_spec(url: String) -> ChainSpec {
    ChainSpec {
        name: "ethereum".to_string(),
        chain_id: 1,
        rpc_urls: vec![url],
        rpc_endpoints: Vec::new(),
        allow_broadcast: false,
        etherscan_api_url: None,
        display_name: Some("Ethereum Mainnet".to_string()),
        native_symbol: "ETH".to_string(),
        native_decimals: 18,
        legacy_tx: false,
        op_stack: false,
    }
}

#[tokio::test]
#[ignore]
async fn vitalik_eth_round_trip() {
    let url = match std::env::var("BLOOM_MAINNET_RPC") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "skipping live ENS test: BLOOM_MAINNET_RPC not set. \
                 Set it to a mainnet HTTPS RPC URL (or a fork URL) and \
                 run with `cargo test -p bloom-ens -- --ignored`."
            );
            return;
        }
    };

    let client = ChainClient::new(mainnet_spec(url)).expect("build chain client");
    let ens = EnsClient::mainnet(client);

    // Forward.
    let resolved = ens
        .resolve("vitalik.eth")
        .await
        .expect("resolve vitalik.eth");
    assert_eq!(resolved, VITALIK, "vitalik.eth -> known address");

    // Reverse (with forward verification baked into reverse()).
    let name = ens.reverse(VITALIK).await.expect("reverse vitalik addr");
    assert_eq!(name, "vitalik.eth");

    // Optional text record. Not all names set "url" — skip if unset.
    match ens.text("vitalik.eth", "url").await {
        Ok(url) => assert!(!url.is_empty(), "text 'url' should be non-empty"),
        Err(e) => eprintln!("skipping text('url') assertion: {e}"),
    }
}
