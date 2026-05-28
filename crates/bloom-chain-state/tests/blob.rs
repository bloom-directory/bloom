//! Category: integration
//!
//! Tests for the state-blob serialisation and BlobStore retention.

use bloom_chain_state::blob::MAX_RETAINED_BLOBS;
use bloom_chain_state::{Account, BlobStore, State};
use bloom_chain_types::{Address, Hash32};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey, TypeTag};

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
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    s.set_account(
        addr(2),
        Account {
            nonce: 1,
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

    let obj_a = Object {
        id: ObjectId([0xA1; 32]),
        type_tag: TypeTag::Concrete {
            petal_hash: [0x10; 32],
            type_name: "Coin".to_string(),
            type_args: vec![],
        },
        owner: Owner::Address([0x01; 32]),
        version: 7,
        payload: vec![1, 2, 3],
    };
    let obj_b = Object {
        id: ObjectId([0xB2; 32]),
        type_tag: TypeTag::Concrete {
            petal_hash: [0x20; 32],
            type_name: "Cap".to_string(),
            type_args: vec![],
        },
        owner: Owner::Object(obj_a.id),
        version: 3,
        payload: vec![9, 8, 7],
    };
    s.set_object(obj_a.clone());
    s.set_object(obj_b.clone());
    s.set_ownership(
        OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: [0x01; 32],
        },
        vec![obj_a.id],
    );
    s.set_ownership(
        OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_OBJECT,
            owner_id: obj_a.id.0,
        },
        vec![obj_b.id],
    );
    s.set_vfs_binding("/bloom/test/coin".to_string(), Hash32([0xCC; 32]));

    s
}

fn empty_blob_prefix() -> Vec<u8> {
    let state_root = State::new().state_root();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BLMSTATE");
    bytes.push(1);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&state_root.0);
    bytes.extend_from_slice(&Hash32([0u8; 32]).0);
    bytes
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
    let recomputed = State::blob_hash(&blob_bytes);
    assert_eq!(blob_hash, recomputed);

    let recovered =
        State::from_blob(&blob_bytes, expected_root).expect("round-trip should succeed");

    assert_eq!(recovered.state_root(), expected_root);
}

#[test]
fn blob_header_exposes_checkpoint_metadata() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();
    let parent_hash = Hash32([0xBE; 32]);

    let (blob_bytes, _) = state.to_blob(42, parent_hash);
    let (height, state_root, stored_parent_hash) =
        State::blob_header(&blob_bytes).expect("valid blob header");

    assert_eq!(height, 42);
    assert_eq!(state_root, expected_root);
    assert_eq!(stored_parent_hash, parent_hash);
}

#[test]
fn blob_objects_ownership_and_vfs_preserved() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();
    let (blob_bytes, _) = state.to_blob(9, Hash32([0x77; 32]));

    let recovered = State::from_blob(&blob_bytes, expected_root).unwrap();

    let obj_a = recovered
        .get_object(&ObjectId([0xA1; 32]))
        .expect("address-owned object restored");
    assert_eq!(obj_a.owner, Owner::Address([0x01; 32]));
    assert_eq!(obj_a.version, 7);
    assert_eq!(obj_a.payload, vec![1, 2, 3]);

    let obj_b = recovered
        .get_object(&ObjectId([0xB2; 32]))
        .expect("object-owned child restored");
    assert_eq!(obj_b.owner, Owner::Object(ObjectId([0xA1; 32])));

    let address_key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: [0x01; 32],
    };
    assert_eq!(
        recovered.get_ownership(&address_key),
        Some(vec![ObjectId([0xA1; 32])])
    );
    assert_eq!(
        recovered.vfs_lookup("/bloom/test/coin"),
        Some(Hash32([0xCC; 32]))
    );
    assert_eq!(recovered.state_root(), expected_root);
}

#[test]
fn blob_accounts_preserved() {
    let state = build_nontrivial_state();
    let expected_root = state.state_root();

    let (blob_bytes, _) = state.to_blob(1, Hash32([0u8; 32]));
    let recovered = State::from_blob(&blob_bytes, expected_root).unwrap();

    assert_eq!(recovered.get_account(&addr(1)).unwrap().nonce, 5);
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

#[test]
fn blob_rejects_huge_ownership_id_count_without_allocating() {
    let expected_root = State::new().state_root();
    let mut blob = empty_blob_prefix();
    // accounts, storage addresses, code, objects
    for _ in 0..4 {
        blob.extend_from_slice(&0u32.to_le_bytes());
    }
    // ownership rows = 1
    blob.extend_from_slice(&1u32.to_le_bytes());
    // ownership key
    blob.push(OWNER_KIND_ADDRESS);
    blob.extend_from_slice(&[0x11u8; 32]);
    // malicious id_count with no backing bytes
    blob.extend_from_slice(&u32::MAX.to_le_bytes());

    let err = State::from_blob(&blob, expected_root).unwrap_err();
    assert!(
        format!("{err}").contains("ownership ids"),
        "unexpected error: {err}"
    );
}

#[test]
fn blob_rejects_oversized_object_length() {
    let expected_root = State::new().state_root();
    let mut blob = empty_blob_prefix();
    // accounts, storage addresses, code
    for _ in 0..3 {
        blob.extend_from_slice(&0u32.to_le_bytes());
    }
    // objects = 1, id, object length above cap
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&[0x44u8; 32]);
    blob.extend_from_slice(&(2 * 1024 * 1024u32).to_le_bytes());

    let err = State::from_blob(&blob, expected_root).unwrap_err();
    assert!(
        format!("{err}").contains("object bytes"),
        "unexpected error: {err}"
    );
}

#[test]
fn blob_rejects_oversized_vfs_path_length() {
    let expected_root = State::new().state_root();
    let mut blob = empty_blob_prefix();
    // accounts, storage addresses, code, objects, ownership
    for _ in 0..5 {
        blob.extend_from_slice(&0u32.to_le_bytes());
    }
    // vfs entries = 1, path length above cap
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&5000u32.to_le_bytes());
    blob.extend(std::iter::repeat_n(0u8, 5000));
    blob.extend_from_slice(&Hash32([0xAA; 32]).0);

    let err = State::from_blob(&blob, expected_root).unwrap_err();
    assert!(
        format!("{err}").contains("vfs path"),
        "unexpected error: {err}"
    );
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
