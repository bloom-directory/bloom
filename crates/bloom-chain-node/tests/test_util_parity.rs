//! Category: selector-parity
//!
//! Parity test: `bloom_test_util::txs_root` must stay byte-identical to
//! `bloom_chain_node::consensus_driver::compute_txs_root`.
//!
//! The util mirrors the chain-node helper so block-builder tests can be
//! authored without dragging in the full chain-node compile graph (which
//! would create a dev-dep cycle for chain-consensus tests). This test
//! pins the mirror — any drift in the production `compute_txs_root`
//! immediately fails here and must be paired with a util update.

use bloom_chain_node::consensus_driver::compute_txs_root;
use bloom_chain_types::{
    tx::{Tx, TxKind},
    types::{Address, PubKeyBytes, SigBytes},
};

fn sample_tx(seed: u8) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender: Address([seed; 32]),
        nonce: seed as u64,
        max_fuel: 1_000,
        fee_per_unit: 1,
        kind: TxKind::DeployPetal {
            wasm_bytes: vec![seed; 4],
        },
        pubkey: PubKeyBytes(vec![seed; 4]),
        sig: SigBytes(vec![0u8; 16]),
    }
}

#[test]
fn empty_tx_list_matches() {
    assert_eq!(compute_txs_root(&[]), bloom_test_util::txs_root(&[]));
}

#[test]
fn single_tx_matches() {
    let txs = vec![sample_tx(7)];
    assert_eq!(compute_txs_root(&txs), bloom_test_util::txs_root(&txs));
}

#[test]
fn multi_tx_matches() {
    let txs: Vec<Tx> = (0u8..5).map(sample_tx).collect();
    assert_eq!(compute_txs_root(&txs), bloom_test_util::txs_root(&txs));
}
