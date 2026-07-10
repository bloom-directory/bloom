use bloom_evm::ChainClient;
use bloom_proto::config::Config;

/// Verify the `RootProvider<Optimism>` natively decodes a real
/// deposit/system transaction (type `0x7e`) on Base mainnet, and that
/// the receipt carries L1-fee fields.
#[tokio::test]
#[ignore = "hits live Base RPC"]
async fn op_stack_live_base_deposit_tx() {
    let config = Config::local_default();
    let spec = config
        .chains
        .get("base")
        .expect("base chain in config")
        .clone();
    let client = ChainClient::new(spec).unwrap();

    let tx_hash: alloy::primitives::B256 =
        "0x9e892552b72f7d974c43fb34ee40fb10f156f4afd11306501ad0f919c5a2c8cc"
            .parse()
            .unwrap();

    let tx = client.tx_json(tx_hash).await.unwrap();
    assert!(tx.is_some(), "tx_json should return Some for deposit tx");
    let tx = tx.unwrap();
    assert_eq!(
        tx.get("type").and_then(|v| v.as_str()),
        Some("0x7e"),
        "tx should be type 0x7e"
    );

    let receipt = client.receipt_json(tx_hash).await.unwrap();
    assert!(receipt.is_some(), "receipt_json should return Some");
    let receipt = receipt.unwrap();
    assert!(
        receipt.get("l1Fee").is_some(),
        "receipt should have l1Fee field"
    );

    let block = client.receipt_block_number(tx_hash).await.unwrap();
    assert!(block.is_some(), "block_number should be Some");
}
