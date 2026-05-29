//! Category: integration
//!
//! Regression coverage for the 2026-05-19 review #16 — block-query-by-hash
//! must work end-to-end through the JSON-RPC server, returning the same
//! header/body shape as the by-height variant.
//!
//! On master, `RpcServer::handle_query_block` rejected the `hash` form
//! with "hash lookup is v1+", but the CLI advertised it (spec §12) and
//! `bloom chain query block <64-char-hex>` quietly errored out. This
//! test pins the contract that a freshly put-then-fetched block survives
//! a `chain_query_block` round-trip keyed on its `block_hash()`, and that
//! the by-hash response is byte-identical to the by-height response.

use std::sync::Arc;

use bloom_chain_node::block_store::BlockStore;
use bloom_chain_node::mempool_persist::MempoolPersist;
use bloom_chain_node::receipt_store::ReceiptStore;
use bloom_chain_node::state_blob::StateBlobStore;
use bloom_chain_node::state_index::StateIndex;
use bloom_chain_node::{RpcClient, RpcServer};
use bloom_chain_state::State;
use bloom_chain_types::{
    block::{Block, BlockHeader},
    types::Hash32,
    vote::Commit,
};
use bloom_test_util::{make_addr, make_validator_set_signed, make_validator_with_keypair};
use parking_lot::Mutex;
use serde_json::json;

fn make_block(height: u64) -> Block {
    // Custom shape: zero-roots except a height-dependent state_root, so
    // every height produces a distinct block_hash without dragging in a
    // tx list or validator set. The bloom-test-util BlockBuilder uses
    // sentinel 0xAA/0xBB/0xCC/0xDD which would erase the height signal.
    Block {
        header: BlockHeader {
            chain_id: "bloomchain.test".to_string(),
            height,
            parent_hash: Hash32([(height as u8).wrapping_sub(1); 32]),
            timestamp_ms: 1_747_526_400_000 + height * 1_000,
            proposer: make_addr(0x55),
            txs_root: Hash32([0u8; 32]),
            state_root: Hash32([(height as u8); 32]),
            receipts_root: Hash32([0u8; 32]),
            validator_set_hash: Hash32([0u8; 32]),
            fuel_used: 0,
            fuel_limit: 30_000_000,
        },
        txs: vec![],
        commit: Commit {
            height,
            round: 0,
            block_hash: Hash32([0u8; 32]),
            votes: vec![],
        },
    }
}

#[tokio::test]
async fn chain_query_block_by_hash_matches_by_height() {
    let tmp = tempfile::tempdir().unwrap();
    let block_store =
        Arc::new(BlockStore::open(&tmp.path().join("blocks")).expect("open BlockStore"));
    let receipt_store =
        Arc::new(ReceiptStore::open(&tmp.path().join("receipts")).expect("open ReceiptStore"));
    let blob_store =
        Arc::new(StateBlobStore::open(&tmp.path().join("state_blobs")).expect("open blob store"));
    let state_index = Arc::new(
        StateIndex::open(&tmp.path().join("state_index.sqlite")).expect("open state index"),
    );
    let mempool_persist = Arc::new(
        MempoolPersist::open(&tmp.path().join("mempool.sled")).expect("open MempoolPersist"),
    );
    let state = Arc::new(Mutex::new(State::new()));

    // RpcServer requires a validator set — synthesise a single-validator
    // set from a real xDSA pubkey so it shape-validates.
    let v = make_validator_with_keypair();
    let validator_set = Arc::new(make_validator_set_signed(&[&v], 100));

    // We never submit anything in this test; the channel just has to exist.
    let (tx_submit, _rx) = tokio::sync::mpsc::channel(8);

    // Seed two blocks so by-hash has multiple files to walk.
    let b1 = make_block(1);
    let b2 = make_block(2);
    block_store.put(1, &b1).unwrap();
    block_store.put(2, &b2).unwrap();

    let server = RpcServer {
        state,
        block_store: Arc::clone(&block_store),
        blob_store,
        state_index,
        mempool_persist,
        receipt_store,
        validator_set,
        chain_id: "bloomchain.test".into(),
        genesis_hash: bloom_chain_types::types::Hash32([0x42; 32]),
        local_address: v.addr,
        startup_height: 0,
        tx_submit,
        max_view_fuel_limit: 1_000_000,
    };

    // Bind serve_tcp on an OS-assigned port. We resolve the port by binding
    // first via std::net::TcpListener, getting its addr, dropping it, and
    // immediately handing the same addr to RpcServer::serve_tcp.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let srv = server.clone();
    let addr_str = addr.to_string();
    let serve_handle = tokio::spawn({
        let addr_str = addr_str.clone();
        async move {
            // serve_tcp loops forever; we abort the task at end-of-test.
            let _ = srv.serve_tcp(&addr_str).await;
        }
    });

    // Give the listener a moment to bind.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&addr_str).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let client = RpcClient::tcp(addr_str.clone());

    // Query by height for both blocks.
    let by_height_2 = client
        .call("chain_query_block", json!({ "height": 2u64 }))
        .await
        .expect("by-height query");
    assert_eq!(by_height_2.get("height").and_then(|v| v.as_u64()), Some(2));
    let hash_hex_2 = by_height_2
        .get("hash")
        .and_then(|v| v.as_str())
        .expect("hash field")
        .to_string();
    assert_eq!(hash_hex_2.len(), 64);

    // Query by hash for block 2 — must return the exact same JSON.
    let by_hash_2 = client
        .call("chain_query_block", json!({ "hash": hash_hex_2 }))
        .await
        .expect("by-hash query");
    assert_eq!(
        by_height_2, by_hash_2,
        "by-hash response must equal by-height response"
    );

    // Sanity: a 32-byte zero hash points at no block and returns null.
    let missing = client
        .call("chain_query_block", json!({ "hash": "0".repeat(64) }))
        .await
        .expect("missing-hash query");
    assert!(
        missing.is_null(),
        "unknown hash must yield null, got {missing}"
    );

    // Bad-length hash → error.
    let bad = client
        .call("chain_query_block", json!({ "hash": "deadbeef" }))
        .await;
    assert!(bad.is_err(), "short hash must be rejected, got {bad:?}");

    serve_handle.abort();
}

/// review 2026-05-19 #16 — `BlockStore::get_by_hash` returns the same
/// block as `BlockStore::get(height)` for every put.
#[test]
fn block_store_get_by_hash_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BlockStore::open(tmp.path()).unwrap();
    let b1 = make_block(7);
    store.put(7, &b1).unwrap();
    let hash = b1.header.block_hash();
    let fetched = store
        .get_by_hash(&hash)
        .expect("get_by_hash ok")
        .expect("must find the block we just put");
    assert_eq!(fetched.header.block_hash(), hash);
    assert_eq!(fetched.header.height, 7);

    // A random hash returns None.
    let missing = store.get_by_hash(&Hash32([0xAA; 32])).unwrap();
    assert!(missing.is_none());
}
