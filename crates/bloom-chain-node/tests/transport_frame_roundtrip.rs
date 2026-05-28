//! Category: integration
//!
//! Test: encode/decode roundtrip for Proposal, Tx, and Vote frames.
//!
//! Writes a frame via `write_frame`, reads it back via `read_frame`, and
//! asserts the decoded value equals the original.

use bloom_chain_node::transport::{Frame, read_frame, write_frame};
use bloom_chain_types::{
    block::{Block, BlockHeader},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::{Commit, Proposal, Vote, VoteKind},
};
use tokio::net::{TcpListener, TcpStream};

/// Helper: create a localhost loopback pair of TcpStreams.
async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

/// Send a frame over one half, receive on the other, assert equality.
async fn roundtrip(frame: Frame) {
    let (mut tx_stream, mut rx_stream) = loopback_pair().await;
    write_frame(&mut tx_stream, &frame)
        .await
        .expect("write_frame");
    drop(tx_stream);
    let decoded = read_frame(&mut rx_stream)
        .await
        .expect("read_frame ok")
        .expect("read_frame Some");

    // Compare by re-encoding: same frame type and same SSZ bytes.
    fn frame_type_and_bytes(f: &Frame) -> (u8, Vec<u8>) {
        use bloom_chain_types::ssz::Encode;
        match f {
            Frame::Proposal(p) => (0, p.as_ssz_bytes()),
            Frame::Vote(v) => (1, v.as_ssz_bytes()),
            Frame::Tx(t) => (2, t.as_ssz_bytes()),
            Frame::BlockRequest { height } => (3, height.to_be_bytes().to_vec()),
            Frame::Ping => (7, vec![]),
            Frame::Pong => (8, vec![]),
            Frame::StateSnapshotRequest { min_height } => (9, min_height.to_be_bytes().to_vec()),
            Frame::StateSnapshotResponse {
                block,
                state_root,
                blob_hash,
                blob,
            } => {
                let mut bytes = block.as_ssz_bytes();
                bytes.extend_from_slice(&state_root.0);
                bytes.extend_from_slice(&blob_hash.0);
                bytes.extend_from_slice(blob);
                (10, bytes)
            }
            _ => (255, vec![]),
        }
    }
    assert_eq!(frame_type_and_bytes(&frame), frame_type_and_bytes(&decoded));
}

#[tokio::test]
async fn proposal_roundtrip() {
    let proposal = Proposal {
        height: 42,
        round: 1,
        block_hash: Hash32([0xAB; 32]),
        pol_round: -1,
        proposer: Address([0x02; 32]),
        sig: SigBytes(vec![0xCC; 8]),
    };
    roundtrip(Frame::Proposal(proposal)).await;
}

#[tokio::test]
async fn tx_roundtrip() {
    let tx = Tx {
        chain_id: "bloomchain.v0".into(),
        sender: Address([0x01; 32]),
        nonce: 1,
        max_fuel: 100_000,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb {
            ptb_bytes: b"frame-roundtrip-ptb".to_vec(),
        },
        pubkey: PubKeyBytes(vec![0x03; 16]),
        sig: SigBytes(vec![0x04; 16]),
    };
    roundtrip(Frame::Tx(tx)).await;
}

#[tokio::test]
async fn vote_roundtrip() {
    let vote = Vote {
        height: 10,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(Hash32([0xBB; 32])),
        validator: Address([0x05; 32]),
        sig: SigBytes(vec![0xEE; 8]),
    };
    roundtrip(Frame::Vote(vote)).await;
}

#[tokio::test]
async fn ping_pong_roundtrip() {
    roundtrip(Frame::Ping).await;
    roundtrip(Frame::Pong).await;
}

#[tokio::test]
async fn state_snapshot_request_roundtrip() {
    roundtrip(Frame::StateSnapshotRequest { min_height: 64 }).await;
}

#[tokio::test]
async fn state_snapshot_response_roundtrip() {
    let block = Block {
        header: BlockHeader {
            chain_id: "bloomchain.test".to_string(),
            height: 64,
            parent_hash: Hash32([0x01; 32]),
            timestamp_ms: 1_747_526_400_000,
            proposer: Address([0x02; 32]),
            txs_root: Hash32([0x03; 32]),
            state_root: Hash32([0x04; 32]),
            receipts_root: Hash32([0x05; 32]),
            validator_set_hash: Hash32([0x06; 32]),
            fuel_used: 7,
            fuel_limit: 30_000_000,
        },
        txs: vec![],
        commit: Commit {
            height: 64,
            round: 0,
            block_hash: Hash32([0x08; 32]),
            votes: vec![],
        },
    };

    roundtrip(Frame::StateSnapshotResponse {
        block,
        state_root: Hash32([0x04; 32]),
        blob_hash: Hash32([0x09; 32]),
        blob: vec![0x0A, 0x0B, 0x0C],
    })
    .await;
}
