//! `Owner` and `Object` — the on-chain object record (spec §4.1, §4.3).

use bloom_chain_types::Address;

use crate::codec::{
    self, CodecError, read_bytes, read_bytes32, read_u8, read_u64_be, write_bytes, write_bytes32,
    write_u8, write_u64_be,
};
use crate::id::ObjectId;
use crate::type_tag::TypeTag;

/// Owner kind discriminant: `Owner::Address`.
pub const OWNER_KIND_ADDRESS: u8 = 0;
/// Owner kind discriminant: `Owner::Object`.
pub const OWNER_KIND_OBJECT: u8 = 1;
/// Owner kind discriminant: `Owner::Shared`.
pub const OWNER_KIND_SHARED: u8 = 2;
/// Owner kind discriminant: `Owner::Immutable`.
pub const OWNER_KIND_IMMUTABLE: u8 = 3;

/// Object ownership category (spec §4.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Owner {
    /// Owned by a 32-byte post-quantum address.
    Address([u8; 32]),
    /// Owned by another object (its mutation gates this one's).
    Object(ObjectId),
    /// Consensus-coordinated: any signer can take a `&mut` borrow.
    Shared,
    /// Read-only forever; any caller may take a `&` borrow.
    Immutable,
}

impl Owner {
    /// Convenience: build an `Owner::Address` from a chain `Address`.
    pub fn from_address(addr: Address) -> Self {
        Owner::Address(addr.0)
    }

    /// 1-byte discriminant for the owner category.
    pub fn kind_byte(&self) -> u8 {
        match self {
            Owner::Address(_) => OWNER_KIND_ADDRESS,
            Owner::Object(_) => OWNER_KIND_OBJECT,
            Owner::Shared => OWNER_KIND_SHARED,
            Owner::Immutable => OWNER_KIND_IMMUTABLE,
        }
    }

    /// Owner payload bytes (32 for `Address`/`Object`, empty otherwise).
    pub fn payload_bytes(&self) -> Vec<u8> {
        match self {
            Owner::Address(a) => a.to_vec(),
            Owner::Object(id) => id.0.to_vec(),
            Owner::Shared | Owner::Immutable => Vec::new(),
        }
    }

    /// Canonical-encode this owner into `buf`: kind byte then payload.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        write_u8(buf, self.kind_byte());
        match self {
            Owner::Address(a) => write_bytes32(buf, a),
            Owner::Object(id) => write_bytes32(buf, &id.0),
            Owner::Shared | Owner::Immutable => {}
        }
    }

    /// Canonical-decode an owner from a cursor (no trailing-bytes check).
    pub fn decode_from(rdr: &mut &[u8]) -> Result<Self, CodecError> {
        let kind = read_u8(rdr)?;
        match kind {
            OWNER_KIND_ADDRESS => Ok(Owner::Address(read_bytes32(rdr)?)),
            OWNER_KIND_OBJECT => Ok(Owner::Object(ObjectId(read_bytes32(rdr)?))),
            OWNER_KIND_SHARED => Ok(Owner::Shared),
            OWNER_KIND_IMMUTABLE => Ok(Owner::Immutable),
            other => Err(CodecError::InvalidDiscriminant(other)),
        }
    }

    /// Canonical-encode into a fresh buffer.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        self.encode_into(&mut buf);
        buf
    }
}

/// An on-chain object record (spec §4.1).
///
/// Canonical encoding (deterministic, no floats):
/// 1. `id` — 32 bytes.
/// 2. `type_tag` — recursive canonical encoding (see [`TypeTag`]).
/// 3. `owner` — kind byte + payload (33 or 1 bytes).
/// 4. `version` — 8-byte big-endian (chain BE convention).
/// 5. `payload` — 4-byte BE length prefix + bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Identifier (32 bytes; see [`ObjectId::derive`]).
    pub id: ObjectId,
    /// Recursive type identity.
    pub type_tag: TypeTag,
    /// Ownership category.
    pub owner: Owner,
    /// Monotonically incremented on every mutation (spec §4.4).
    pub version: u64,
    /// Type-defining petal's canonical-encoded fields.
    pub payload: Vec<u8>,
}

impl Object {
    /// Canonical-encode this object.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::with_capacity(32 + 64 + 33 + 8 + 4 + self.payload.len());
        write_bytes32(&mut buf, &self.id.0);
        self.type_tag.encode_into(&mut buf)?;
        self.owner.encode_into(&mut buf);
        write_u64_be(&mut buf, self.version);
        write_bytes(&mut buf, &self.payload);
        Ok(buf)
    }

    /// Canonical-decode an object, rejecting trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut rdr = bytes;
        let id = ObjectId(read_bytes32(&mut rdr)?);
        let type_tag = TypeTag::decode_from(&mut rdr, 0)?;
        let owner = Owner::decode_from(&mut rdr)?;
        let version = read_u64_be(&mut rdr)?;
        let payload = read_bytes(&mut rdr)?;
        codec::expect_eof(rdr)?;
        Ok(Object {
            id,
            type_tag,
            owner,
            version,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_type() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0xAB; 32],
            type_name: "Coin".to_string(),
            type_args: vec![TypeTag::Concrete {
                petal_hash: [0xCD; 32],
                type_name: "LOOM".to_string(),
                type_args: vec![],
            }],
        }
    }

    fn rt(o: Object) {
        let bytes = o.encode_canonical().unwrap();
        let back = Object::decode_canonical(&bytes).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn owner_kind_bytes() {
        assert_eq!(Owner::Address([0; 32]).kind_byte(), OWNER_KIND_ADDRESS);
        assert_eq!(
            Owner::Object(ObjectId([0; 32])).kind_byte(),
            OWNER_KIND_OBJECT
        );
        assert_eq!(Owner::Shared.kind_byte(), OWNER_KIND_SHARED);
        assert_eq!(Owner::Immutable.kind_byte(), OWNER_KIND_IMMUTABLE);
    }

    #[test]
    fn owner_payload_bytes() {
        assert_eq!(Owner::Address([7u8; 32]).payload_bytes(), vec![7u8; 32]);
        assert_eq!(
            Owner::Object(ObjectId([9u8; 32])).payload_bytes(),
            vec![9u8; 32]
        );
        assert!(Owner::Shared.payload_bytes().is_empty());
        assert!(Owner::Immutable.payload_bytes().is_empty());
    }

    #[test]
    fn owner_roundtrip_address() {
        let o = Owner::Address([1u8; 32]);
        let bytes = o.encode_canonical();
        assert_eq!(bytes.len(), 33);
        let mut rdr = bytes.as_slice();
        assert_eq!(Owner::decode_from(&mut rdr).unwrap(), o);
    }

    #[test]
    fn owner_roundtrip_object() {
        let o = Owner::Object(ObjectId([2u8; 32]));
        let bytes = o.encode_canonical();
        assert_eq!(bytes.len(), 33);
        let mut rdr = bytes.as_slice();
        assert_eq!(Owner::decode_from(&mut rdr).unwrap(), o);
    }

    #[test]
    fn owner_roundtrip_shared_immutable() {
        for o in [Owner::Shared, Owner::Immutable] {
            let bytes = o.encode_canonical();
            assert_eq!(bytes.len(), 1);
            let mut rdr = bytes.as_slice();
            assert_eq!(Owner::decode_from(&mut rdr).unwrap(), o);
        }
    }

    #[test]
    fn object_roundtrip_address_owner() {
        rt(Object {
            id: ObjectId([0xEE; 32]),
            type_tag: sample_type(),
            owner: Owner::Address([0x11; 32]),
            version: 42,
            payload: b"hello world".to_vec(),
        });
    }

    #[test]
    fn object_roundtrip_object_owner() {
        rt(Object {
            id: ObjectId([0xEE; 32]),
            type_tag: sample_type(),
            owner: Owner::Object(ObjectId([0x33; 32])),
            version: 1,
            payload: vec![1, 2, 3, 4, 5],
        });
    }

    #[test]
    fn object_roundtrip_shared() {
        rt(Object {
            id: ObjectId([0xEE; 32]),
            type_tag: sample_type(),
            owner: Owner::Shared,
            version: 0,
            payload: vec![0xFF; 1024],
        });
    }

    #[test]
    fn object_roundtrip_immutable() {
        rt(Object {
            id: ObjectId([0xEE; 32]),
            type_tag: sample_type(),
            owner: Owner::Immutable,
            version: u64::MAX,
            payload: vec![],
        });
    }

    #[test]
    fn object_roundtrip_empty_payload() {
        rt(Object {
            id: ObjectId([0x42; 32]),
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Shared,
            version: 7,
            payload: vec![],
        });
    }

    #[test]
    fn object_decode_rejects_trailing_bytes() {
        let o = Object {
            id: ObjectId([0; 32]),
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        };
        let mut bytes = o.encode_canonical().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            Object::decode_canonical(&bytes),
            Err(CodecError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn owner_decode_rejects_unknown_kind() {
        let bytes = [9u8];
        let mut rdr = bytes.as_slice();
        assert!(matches!(
            Owner::decode_from(&mut rdr),
            Err(CodecError::InvalidDiscriminant(9))
        ));
    }
}
