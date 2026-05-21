//! Category: integration
//!
//! Tests for the state-blob serialisation and BlobStore retention.

use bloom_chain_state::blob::MAX_RETAINED_BLOBS;
use bloom_chain_state::{Account, BlobStore, State};
use bloom_chain_types::digest::blake3_tagged;
use bloom_chain_types::digest::tags;
use bloom_chain_types::{Address, Hash32};

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn build_nontrivial_state() -> State {
    let mut s = State::new();

    // Multiple accounts
    s.set_account(
        addr(1),
        Account {
            nonce: 5,
            loom: 1_000_000,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    s.set_account(
        addr(2),
        Account {
            nonce: 1,
            loom: 500,
            code_hash: Some(Hash32([0xDE; 32])),
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    // Code
    let _code_hash = s.insert_code(b"(module (func (export \"call\") ))");

    // Storage for addr(2)
    s.storage_write(addr(2), [0x11u8; 32], [0x22u8; 32]);
    s.storage_write(addr(2), [0x33u8; 32], [0x44u8; 32]);

    s
}

// ---------------------------------------------------------------------------
// Round-trip: build → blob → restore → verify state_root
// ---------------------------------------------------------------------------

#[test]
fn blob_roundtrip_state_root_matches() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();

    let (blob_bytes, blob_hash) = state.to_blob(42, Hash32([0xBE; 32]));

    // Blob hash is deterministic
    let recomputed = blake3_tagged(tags::PETAL, &blob_bytes);
    assert_eq!(blob_hash, recomputed);

    let recovered =
        State::from_blob(&blob_bytes, expected_root).expect("round-trip should succeed");

    assert_eq!(recovered.state_root(), expected_root);
}

#[test]
fn blob_accounts_preserved() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();

    let (blob_bytes, _) = state.to_blob(1, Hash32([0u8; 32]));
    let recovered = State::from_blob(&blob_bytes, expected_root).unwrap();

    assert_eq!(recovered.get_account(&addr(1)).unwrap().loom, 1_000_000);
    assert_eq!(recovered.get_account(&addr(2)).unwrap().nonce, 1);
    assert_eq!(recovered.get_account(&addr(3)), None);
}

#[test]
fn blob_storage_preserved() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();

    let (blob_bytes, _) = state.to_blob(1, Hash32([0u8; 32]));
    let recovered = State::from_blob(&blob_bytes, expected_root).unwrap();

    assert_eq!(
        recovered.storage_read(&addr(2), &[0x11u8; 32]),
        [0x22u8; 32]
    );
    assert_eq!(
        recovered.storage_read(&addr(2), &[0x33u8; 32]),
        [0x44u8; 32]
    );
}

// ---------------------------------------------------------------------------
// Verify rejection when expected_state_root mismatches
// ---------------------------------------------------------------------------

#[test]
fn blob_rejects_wrong_expected_root() {
    let state = build_nontrivial_state();
    let (blob_bytes, _) = state.to_blob(1, Hash32([0u8; 32]));

    let wrong_root = Hash32([0xFF; 32]);
    let result = State::from_blob(&blob_bytes, wrong_root);
    assert!(result.is_err(), "should reject mismatched root");
}

#[test]
fn blob_rejects_tampered_bytes() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();
    let (mut blob_bytes, _) = state.to_blob(1, Hash32([0u8; 32]));

    // Corrupt a byte in the middle
    let mid = blob_bytes.len() / 2;
    blob_bytes[mid] ^= 0xFF;

    // Either the root embedded in the blob won't match expected_root,
    // or the reconstructed state won't match — either way, an error.
    let result = State::from_blob(&blob_bytes, expected_root);
    assert!(result.is_err(), "should reject tampered blob");
}

// ---------------------------------------------------------------------------
// BlobStore retention: insert 300, assert only last 256 remain
// ---------------------------------------------------------------------------

#[test]
fn blob_store_fifo_retention() {
    let mut store = BlobStore::in_memory();

    let mut hashes = Vec::new();
    for i in 0u32..300 {
        let payload = i.to_le_bytes();
        let hash = Hash32(blake3::hash(&payload).into());
        store.insert(hash, payload.to_vec()).unwrap();
        hashes.push(hash);
    }

    // Total retained must be exactly MAX_RETAINED_BLOBS
    assert_eq!(store.len(), MAX_RETAINED_BLOBS);

    // The first 44 hashes (300 - 256) should have been pruned
    for hash in &hashes[..44] {
        assert!(
            store.get(hash).unwrap().is_none(),
            "old blobs should be pruned"
        );
    }

    // The last 256 should still be present
    for hash in &hashes[44..] {
        assert!(
            store.get(hash).unwrap().is_some(),
            "recent blobs should be retained"
        );
    }
}

#[test]
fn blob_store_empty_state() {
    let state = State::new();
    let expected_root = state.state_root();
    let (blob_bytes, _) = state.to_blob(0, Hash32([0u8; 32]));
    let recovered = State::from_blob(&blob_bytes, expected_root).unwrap();
    assert_eq!(recovered.state_root(), expected_root);
}
