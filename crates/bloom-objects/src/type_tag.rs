//! `TypeTag` — the recursive, content-addressable type identity used by
//! every object payload, every PTB `Const` literal, and every petal
//! manifest entry. Spec §4.1, §7.1, §8.2.
//!
//! Encoding (1-byte variant tag + payload):
//! - `Concrete = 0` → 32-byte petal_hash + 2-byte BE utf8 name length +
//!   name bytes + 2-byte BE type-arg count + N recursive TypeTag bytes.
//! - `Generic  = 1` → 2-byte BE generic-parameter index.
//! - `External = 2` → 2-byte BE manifest external-type-ref index.

use crate::codec::{
    self, CodecError, read_bytes32, read_string, read_u8, read_u16_be, write_bytes32, write_string,
    write_u8, write_u16_be,
};

/// Variant tag byte for `TypeTag::Concrete`.
pub const TAG_CONCRETE: u8 = 0;
/// Variant tag byte for `TypeTag::Generic`.
pub const TAG_GENERIC: u8 = 1;
/// Variant tag byte for `TypeTag::External`.
pub const TAG_EXTERNAL: u8 = 2;

/// Maximum nesting depth accepted by the canonical decoder. Bounds
/// `decode_canonical`'s stack use and guards against pathological inputs.
pub const MAX_TYPE_TAG_DEPTH: usize = 16;

/// Recursive type identity.
///
/// `Concrete` resolves to a specific type defined by a specific petal
/// (named by `petal_hash`). `Generic` references a type parameter of
/// the enclosing function/type by index. `External` references a
/// pinned cross-petal type via the enclosing manifest's
/// `external_type_refs` table (spec §8.2, §13.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TypeTag {
    /// A concrete type defined by `petal_hash::type_name`, instantiated
    /// with the given (possibly empty) type-argument vector.
    Concrete {
        /// Content hash of the petal that defines the type.
        petal_hash: [u8; 32],
        /// Type name within that petal.
        type_name: String,
        /// Type-argument vector for generic instantiation (empty if monomorphic).
        type_args: Vec<TypeTag>,
    },
    /// Reference to the `idx`-th type parameter of the enclosing scope.
    Generic {
        /// Zero-based generic-parameter index.
        idx: u16,
    },
    /// Reference to the `ref_idx`-th entry in the manifest's
    /// `external_type_refs` table.
    External {
        /// Zero-based index into the manifest's `external_type_refs` table.
        ref_idx: u16,
    },
}

impl TypeTag {
    /// Canonical-encode this type tag into `buf`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                write_u8(buf, TAG_CONCRETE);
                write_bytes32(buf, petal_hash);
                write_string(buf, type_name)?;
                let count: u16 = type_args
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::LengthOverflow(type_args.len() as u64))?;
                write_u16_be(buf, count);
                for arg in type_args {
                    arg.encode_into(buf)?;
                }
                Ok(())
            }
            TypeTag::Generic { idx } => {
                write_u8(buf, TAG_GENERIC);
                write_u16_be(buf, *idx);
                Ok(())
            }
            TypeTag::External { ref_idx } => {
                write_u8(buf, TAG_EXTERNAL);
                write_u16_be(buf, *ref_idx);
                Ok(())
            }
        }
    }

    /// Canonical-encode this type tag into a new `Vec<u8>`.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Canonical-decode a single `TypeTag` from `bytes`, rejecting trailing data.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut rdr = bytes;
        let tag = Self::decode_from(&mut rdr, 0)?;
        codec::expect_eof(rdr)?;
        Ok(tag)
    }

    /// Decode from a cursor, allowing trailing data (used by `Object` decode).
    pub fn decode_from(rdr: &mut &[u8], depth: usize) -> Result<Self, CodecError> {
        if depth >= MAX_TYPE_TAG_DEPTH {
            return Err(CodecError::InvalidLength(depth as u64));
        }
        let tag = read_u8(rdr)?;
        match tag {
            TAG_CONCRETE => {
                let petal_hash = read_bytes32(rdr)?;
                let type_name = read_string(rdr)?;
                let count = read_u16_be(rdr)? as usize;
                let mut type_args = Vec::with_capacity(count);
                for _ in 0..count {
                    type_args.push(Self::decode_from(rdr, depth + 1)?);
                }
                Ok(TypeTag::Concrete {
                    petal_hash,
                    type_name,
                    type_args,
                })
            }
            TAG_GENERIC => Ok(TypeTag::Generic {
                idx: read_u16_be(rdr)?,
            }),
            TAG_EXTERNAL => Ok(TypeTag::External {
                ref_idx: read_u16_be(rdr)?,
            }),
            other => Err(CodecError::InvalidDiscriminant(other)),
        }
    }

    /// Compute `blake3(encode_canonical())`. The 32-byte digest is the
    /// canonical hash fed into [`crate::id::ObjectId::derive`].
    pub fn canonical_hash(&self) -> [u8; 32] {
        let bytes = self
            .encode_canonical()
            .expect("encoded TypeTag fits the codec's width constraints");
        *blake3::hash(&bytes).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(t: &TypeTag) {
        let bytes = t.encode_canonical().unwrap();
        let back = TypeTag::decode_canonical(&bytes).unwrap();
        assert_eq!(*t, back);
    }

    fn concrete(name: &str, args: Vec<TypeTag>) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: args,
        }
    }

    #[test]
    fn concrete_no_args_roundtrip() {
        rt(&concrete("USDC", vec![]));
    }

    #[test]
    fn generic_roundtrip() {
        rt(&TypeTag::Generic { idx: 0 });
        rt(&TypeTag::Generic { idx: u16::MAX });
    }

    #[test]
    fn external_roundtrip() {
        rt(&TypeTag::External { ref_idx: 7 });
    }

    #[test]
    fn nested_concrete_roundtrip() {
        // Pool<USDC, LOOM, ConstantProduct>
        let pool = concrete(
            "Pool",
            vec![
                concrete("USDC", vec![]),
                concrete("LOOM", vec![]),
                concrete("ConstantProduct", vec![]),
            ],
        );
        rt(&pool);

        // Coin<Pool<USDC, LOOM, ConstantProduct>> — deeper nesting.
        let coin = concrete("Coin", vec![pool]);
        rt(&coin);
    }

    #[test]
    fn invalid_discriminant_rejected() {
        let bad = [9u8];
        assert_eq!(
            TypeTag::decode_canonical(&bad),
            Err(CodecError::InvalidDiscriminant(9))
        );
    }

    #[test]
    fn canonical_hash_is_deterministic() {
        let t = concrete("Coin", vec![concrete("LOOM", vec![])]);
        let h1 = t.canonical_hash();
        let h2 = t.canonical_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_distinguishes_types() {
        let a = concrete("Coin", vec![concrete("USDC", vec![])]);
        let b = concrete("Coin", vec![concrete("LOOM", vec![])]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = TypeTag::Generic { idx: 5 }.encode_canonical().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            TypeTag::decode_canonical(&bytes),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn excessive_nesting_rejected() {
        // Build a tag nested deeper than MAX_TYPE_TAG_DEPTH manually.
        let mut bytes = Vec::new();
        for _ in 0..(MAX_TYPE_TAG_DEPTH + 1) {
            write_u8(&mut bytes, TAG_CONCRETE);
            write_bytes32(&mut bytes, &[0u8; 32]);
            write_string(&mut bytes, "X").unwrap();
            write_u16_be(&mut bytes, 1); // one nested arg follows
        }
        // Terminate with a leaf.
        write_u8(&mut bytes, TAG_GENERIC);
        write_u16_be(&mut bytes, 0);

        assert!(matches!(
            TypeTag::decode_canonical(&bytes),
            Err(CodecError::InvalidLength(_))
        ));
    }
}
