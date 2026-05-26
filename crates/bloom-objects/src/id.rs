//! `ObjectId` — 32-byte identifier derived from creator petal, type tag,
//! and a creation nonce (spec §4.1).

use core::fmt;

use bloom_chain_types::Hash32;

/// Domain tag for `ObjectId` derivation.
///
/// TODO(bloom-native-contracts): hoist this constant into
/// `bloom-chain-types::digest::tags` alongside the other chain tags
/// once this crate's leaf-only status ends. For now we declare it
/// locally to keep the crate boundary clean.
pub const OBJECT_ID_TAG: &str = "bloom-chain.v0.object_id:";

/// 32-byte object identifier.
///
/// Derivation (spec §4.1):
/// `ObjectId = BLAKE3("bloom-chain.v0.object_id:" || creator_petal_hash
/// || canonical_encode(type_tag) || creation_nonce_le)`.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    /// Derive an object id from the (creator, type, nonce) triple.
    ///
    /// `type_tag_canonical` MUST be the canonical-encoded bytes of the
    /// type tag (see [`crate::type_tag::TypeTag::encode_canonical`]) —
    /// not a debug representation. The nonce is encoded little-endian
    /// per spec §4.1.
    pub fn derive(
        creator_petal_hash: &Hash32,
        type_tag_canonical: &[u8],
        creation_nonce: u64,
    ) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(OBJECT_ID_TAG.as_bytes());
        h.update(&creator_petal_hash.0);
        h.update(type_tag_canonical);
        h.update(&creation_nonce.to_le_bytes());
        ObjectId(*h.finalize().as_bytes())
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
        let creator = Hash32([0xAA; 32]);
        let t = TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: "Coin".to_string(),
            type_args: vec![],
        };
        let bytes = t.encode_canonical().unwrap();
        let a = ObjectId::derive(&creator, &bytes, 42);
        let b = ObjectId::derive(&creator, &bytes, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_distinguishes_inputs() {
        let creator = Hash32([0xAA; 32]);
        let t = TypeTag::Generic { idx: 0 };
        let bytes = t.encode_canonical().unwrap();
        let a = ObjectId::derive(&creator, &bytes, 1);
        let b = ObjectId::derive(&creator, &bytes, 2);
        let c = ObjectId::derive(&Hash32([0xBB; 32]), &bytes, 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn display_is_lowercase_hex() {
        let id = ObjectId([0xAB; 32]);
        let s = id.to_string();
        assert_eq!(s.len(), 64);
        assert_eq!(s, "ab".repeat(32));
    }
}
