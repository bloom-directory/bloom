//! Key and value types for the two new `TrieKind` variants the chain
//! gains in spec §4.5 / §16.3:
//!
//! - `Object` — primary `ObjectId -> Object` index.
//! - `OwnershipIndex` — secondary `(owner_kind, owner_id) -> sorted
//!   list<ObjectId>` index.
//!
//! Both use BLAKE3-tagged-sorted-leaf commitments (the same scheme
//! `bloom-chain-state` already implements for `Accounts`/`Storage`/
//! `Code`); the chain-state crate will reference the tag constants
//! and value encoders defined here once it grows the two new
//! `TrieKind` variants.

use crate::codec::{self, CodecError, read_bytes32, read_u32_be, write_bytes32, write_u32_be};
use crate::id::ObjectId;
use crate::object::Object;

/// Domain tag for the new `Object` trie's root commitment.
pub const OBJECT_ROOT_TAG: &str = "bloom-chain.v0.object_root:";
/// Domain tag for `Object` trie leaf hashing.
pub const OBJECT_LEAF_TAG: &str = "bloom-chain.v0.object_leaf:";
/// Domain tag for the new `OwnershipIndex` trie's root commitment.
pub const OWNERSHIP_ROOT_TAG: &str = "bloom-chain.v0.ownership_root:";
/// Domain tag for `OwnershipIndex` trie leaf hashing.
pub const OWNERSHIP_LEAF_TAG: &str = "bloom-chain.v0.ownership_leaf:";

// ---------------------------------------------------------------------------
// Object trie
// ---------------------------------------------------------------------------

/// Trie key for the `Object` trie: the raw 32-byte `ObjectId`.
pub type ObjectTrieKey = [u8; 32];

/// Trie value for the `Object` trie: canonical-encoded `Object` bytes.
pub type ObjectTrieValue = Vec<u8>;

/// Build the `Object` trie key from an `ObjectId`.
pub fn object_trie_key(id: &ObjectId) -> ObjectTrieKey {
    id.0
}

/// Encode an `Object` for storage in the `Object` trie.
pub fn encode_object_trie_value(obj: &Object) -> Result<ObjectTrieValue, CodecError> {
    obj.encode_canonical()
}

/// Decode an `Object` from its trie value bytes.
pub fn decode_object_trie_value(bytes: &[u8]) -> Result<Object, CodecError> {
    Object::decode_canonical(bytes)
}

// ---------------------------------------------------------------------------
// OwnershipIndex trie
// ---------------------------------------------------------------------------

/// Composite key for the `OwnershipIndex` trie: a 1-byte owner kind
/// (matching [`crate::object::Owner::kind_byte`]) and the 32-byte
/// owner identifier (address bytes for `Address`, object-id bytes for
/// `Object`).
///
/// `Shared` and `Immutable` owners are not indexed (no `owner_id`),
/// per spec §4.5.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct OwnershipIndexKey {
    /// Owner kind discriminant (see `OWNER_KIND_*` in [`crate::object`]).
    pub owner_kind: u8,
    /// 32-byte owner identifier.
    pub owner_id: [u8; 32],
}

impl OwnershipIndexKey {
    /// Encode the key as `[owner_kind || owner_id]` (33 bytes).
    pub fn encode(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.owner_kind;
        out[1..].copy_from_slice(&self.owner_id);
        out
    }

    /// Decode the 33-byte key form.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != 33 {
            return Err(CodecError::InvalidLength(bytes.len() as u64));
        }
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(&bytes[1..]);
        Ok(Self {
            owner_kind: bytes[0],
            owner_id,
        })
    }
}

/// Trie value for the `OwnershipIndex` trie: a sorted list of
/// `ObjectId`s owned by the keyed owner.
///
/// Stored as `[u32 BE count || count * 32-byte id]`. Callers are
/// expected to keep the list sorted; the decoder checks strict
/// ascending order and rejects duplicates / unsorted entries to keep
/// the on-chain commitment canonical.
pub type OwnershipIndexValue = Vec<ObjectId>;

/// Encode a sorted list of `ObjectId`s for storage in the
/// `OwnershipIndex` trie.
pub fn encode_ownership_value(ids: &[ObjectId]) -> Result<Vec<u8>, CodecError> {
    // Reject mis-sorted input early; the trie commitment depends on canonical order.
    for w in ids.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(CodecError::InvalidLength(ids.len() as u64));
        }
    }
    let count: u32 = ids
        .len()
        .try_into()
        .map_err(|_| CodecError::LengthOverflow(ids.len() as u64))?;
    let mut buf = Vec::with_capacity(4 + ids.len() * 32);
    write_u32_be(&mut buf, count);
    for id in ids {
        write_bytes32(&mut buf, &id.0);
    }
    Ok(buf)
}

/// Decode a sorted list of `ObjectId`s from its trie value bytes.
pub fn decode_ownership_value(bytes: &[u8]) -> Result<Vec<ObjectId>, CodecError> {
    let mut rdr = bytes;
    let count = read_u32_be(&mut rdr)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(ObjectId(read_bytes32(&mut rdr)?));
    }
    codec::expect_eof(rdr)?;
    // Canonical-order invariant (defence in depth; the encoder also enforces it).
    for w in out.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(CodecError::InvalidLength(out.len() as u64));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{OWNER_KIND_ADDRESS, Owner};
    use crate::type_tag::TypeTag;

    fn sample_object(id_byte: u8) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: [0; 32],
                type_name: "Coin".to_string(),
                type_args: vec![],
            },
            owner: Owner::Address([id_byte; 32]),
            version: 1,
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn object_trie_key_is_id_bytes() {
        let id = ObjectId([0xAB; 32]);
        assert_eq!(object_trie_key(&id), id.0);
    }

    #[test]
    fn object_trie_value_roundtrip() {
        let obj = sample_object(0x42);
        let bytes = encode_object_trie_value(&obj).unwrap();
        let back = decode_object_trie_value(&bytes).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn ownership_key_roundtrip() {
        let k = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: [0x77; 32],
        };
        let enc = k.encode();
        assert_eq!(enc.len(), 33);
        let back = OwnershipIndexKey::decode(&enc).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn ownership_key_rejects_wrong_length() {
        assert!(matches!(
            OwnershipIndexKey::decode(&[0u8; 32]),
            Err(CodecError::InvalidLength(_))
        ));
    }

    #[test]
    fn ownership_value_roundtrip_empty() {
        let bytes = encode_ownership_value(&[]).unwrap();
        let back = decode_ownership_value(&bytes).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn ownership_value_roundtrip_sorted() {
        let ids = vec![ObjectId([1; 32]), ObjectId([2; 32]), ObjectId([3; 32])];
        let bytes = encode_ownership_value(&ids).unwrap();
        let back = decode_ownership_value(&bytes).unwrap();
        assert_eq!(back, ids);
    }

    #[test]
    fn ownership_value_encoder_rejects_unsorted() {
        let ids = vec![ObjectId([2; 32]), ObjectId([1; 32])];
        assert!(encode_ownership_value(&ids).is_err());
    }

    #[test]
    fn ownership_value_decoder_rejects_unsorted() {
        // Hand-craft an unsorted payload to confirm the decoder defends too.
        let mut buf = Vec::new();
        write_u32_be(&mut buf, 2);
        write_bytes32(&mut buf, &[2u8; 32]);
        write_bytes32(&mut buf, &[1u8; 32]);
        assert!(decode_ownership_value(&buf).is_err());
    }

    #[test]
    fn tag_constants_match_spec() {
        assert_eq!(OBJECT_ROOT_TAG, "bloom-chain.v0.object_root:");
        assert_eq!(OBJECT_LEAF_TAG, "bloom-chain.v0.object_leaf:");
        assert_eq!(OWNERSHIP_ROOT_TAG, "bloom-chain.v0.ownership_root:");
        assert_eq!(OWNERSHIP_LEAF_TAG, "bloom-chain.v0.ownership_leaf:");
    }
}
