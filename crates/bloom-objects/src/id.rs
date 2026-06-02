//! `ObjectId` — 32-byte identifier derived from creation context and
//! persisted object contents (spec §6).

use core::fmt;

use bloom_chain_types::Hash32;

use crate::type_tag::TypeTag;

/// Domain tag for `ObjectId` derivation.
///
/// TODO(bloom-native-contracts): hoist this constant into
/// `bloom-chain-types::digest::tags` alongside the other chain tags
/// once this crate's leaf-only status ends. For now we declare it
/// locally to keep the crate boundary clean.
pub const OBJECT_ID_TAG: &str = "bloom-chain.v0.object_id:";

/// 32-byte object identifier.
///
/// Canonical derivation:
/// `BLAKE3("bloom-chain.v0.object_id:" || creation_seed ||
/// creator_petal_hash || creation_nonce_le || canonical_encode(type_tag)
/// || canonical_payload)`.
///
/// `creation_seed` is the replay-stable transaction/genesis/event seed
/// for the creation context. `canonical_encode(type_tag)` must be the
/// persisted post-stamp tag, not a guest-supplied pre-stamp placeholder.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    /// Derive an object id from the canonical creation tuple.
    ///
    /// `type_tag_canonical` MUST be the canonical-encoded bytes of the
    /// type tag (see [`crate::type_tag::TypeTag::encode_canonical`]) —
    /// not a debug representation. The nonce is encoded little-endian.
    pub fn derive(
        creation_seed: &Hash32,
        creator_petal_hash: &Hash32,
        creation_nonce: u64,
        type_tag_canonical: &[u8],
        canonical_payload: &[u8],
    ) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(OBJECT_ID_TAG.as_bytes());
        h.update(&creation_seed.0);
        h.update(&creator_petal_hash.0);
        h.update(&creation_nonce.to_le_bytes());
        h.update(type_tag_canonical);
        h.update(canonical_payload);
        ObjectId(*h.finalize().as_bytes())
    }

    /// Derive an object id from a persisted type tag and payload.
    ///
    /// For concrete tags, the creator hash is the tag's defining petal
    /// hash. Generic/external tags are not valid persisted object
    /// identities, but this still maps them to a zero creator hash for
    /// test fixtures and defensive callers.
    pub fn derive_for_type_tag(
        creation_seed: &Hash32,
        creation_nonce: u64,
        type_tag: &TypeTag,
        canonical_payload: &[u8],
    ) -> Self {
        let creator_petal_hash = match type_tag {
            TypeTag::Concrete { petal_hash, .. } => Hash32(*petal_hash),
            TypeTag::Generic { .. } | TypeTag::External { .. } => Hash32([0u8; 32]),
        };
        let type_tag_canonical = type_tag
            .encode_canonical()
            .expect("persisted TypeTag fits canonical encoding limits");
        Self::derive(
            creation_seed,
            &creator_petal_hash,
            creation_nonce,
            &type_tag_canonical,
            canonical_payload,
        )
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_tag::TypeTag;

    #[test]
    fn derive_is_deterministic() {
        let seed = Hash32([0x11; 32]);
        let creator = Hash32([0xAA; 32]);
        let t = TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: "Coin".to_string(),
            type_args: vec![],
        };
        let bytes = t.encode_canonical().unwrap();
        let payload = 7u128.to_be_bytes();
        let a = ObjectId::derive(&seed, &creator, 42, &bytes, &payload);
        let b = ObjectId::derive(&seed, &creator, 42, &bytes, &payload);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_distinguishes_inputs() {
        let seed = Hash32([0x11; 32]);
        let creator = Hash32([0xAA; 32]);
        let t = TypeTag::Generic { idx: 0 };
        let bytes = t.encode_canonical().unwrap();
        let payload = 7u128.to_be_bytes();
        let a = ObjectId::derive(&seed, &creator, 1, &bytes, &payload);
        let b = ObjectId::derive(&seed, &creator, 2, &bytes, &payload);
        let c = ObjectId::derive(&seed, &Hash32([0xBB; 32]), 1, &bytes, &payload);
        let d = ObjectId::derive(&Hash32([0x22; 32]), &creator, 1, &bytes, &payload);
        let e = ObjectId::derive(&seed, &creator, 1, &bytes, &8u128.to_be_bytes());
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    #[test]
    fn display_is_lowercase_hex() {
        let id = ObjectId([0xAB; 32]);
        let s = id.to_string();
        assert_eq!(s.len(), 64);
        assert_eq!(s, "ab".repeat(32));
    }
}
