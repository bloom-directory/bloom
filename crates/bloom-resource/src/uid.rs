//! `UID` — the field type for the `id` field of every `#[object]`
//! struct (spec §4.1).
//!
//! Wraps `bloom_objects::ObjectId`. Today `UID` is a thin newtype; the
//! separate name exists so the macro-generated source can refer to a
//! type that is unambiguously "the field carrying an object id" — even
//! if the underlying representation gains derivation helpers later
//! (e.g. v1 deterministic-id derivation from a fresh nonce).

use bloom_objects::ObjectId;

/// Object-id field wrapper.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default, Ord, PartialOrd)]
pub struct UID(pub ObjectId);

impl UID {
    /// Construct a `UID` from a raw `ObjectId`.
    pub const fn from_object_id(id: ObjectId) -> Self {
        Self(id)
    }

    /// Construct a `UID` from a raw 32-byte array (rarely used; prefer
    /// `from_object_id` so call sites stay typed).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(ObjectId(bytes))
    }

    /// Borrow the underlying `ObjectId`.
    pub fn as_object_id(&self) -> &ObjectId {
        &self.0
    }

    /// Copy out the underlying `ObjectId`.
    pub fn to_object_id(self) -> ObjectId {
        self.0
    }

    /// Raw 32-byte bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }
}

impl From<ObjectId> for UID {
    fn from(id: ObjectId) -> Self {
        Self(id)
    }
}

impl From<UID> for ObjectId {
    fn from(uid: UID) -> Self {
        uid.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_object_id() {
        let id = ObjectId([0xAB; 32]);
        let uid = UID::from_object_id(id);
        assert_eq!(uid.as_object_id(), &id);
    }

    #[test]
    fn from_bytes() {
        let uid = UID::from_bytes([7u8; 32]);
        assert_eq!(uid.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn round_trip_via_into() {
        let id = ObjectId([0xCD; 32]);
        let uid: UID = id.into();
        let back: ObjectId = uid.into();
        assert_eq!(back, id);
    }

    #[test]
    fn default_is_zero() {
        let uid = UID::default();
        assert_eq!(*uid.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn ord_matches_object_id() {
        let a = UID::from_bytes([0; 32]);
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 1;
        let b = UID::from_bytes(b_bytes);
        assert!(a < b);
    }
}
