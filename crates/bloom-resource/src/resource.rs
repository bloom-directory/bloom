//! `Resource<T>` — runtime-typed wrapper for non-phantom generic state
//! (spec §11.2).
//!
//! Petals cannot have a plain `T` field where `T` is a non-phantom
//! generic parameter (the wasm ABI cannot monomorphize at PTB-execution
//! time). Instead they wrap the value in `Resource<T>`, which stores
//! the canonical-encoded bytes plus a runtime `TypeTag`, plus a
//! `PhantomData<T>` for compile-time hygiene.
//!
//! Encoding / decoding to/from a concrete `T: BloomType` is by the
//! type's own canonical codec (`BloomType::canonical_encode` /
//! `canonical_decode`). The matching `TypeTag` is also produced by
//! `BloomType::type_tag`.

use bloom_chain_types::Hash32;
use bloom_objects::{ObjectId, TypeTag};
use core::marker::PhantomData;

use crate::abi::AbiError;
use crate::error::PetalError;
use crate::handle::RuntimeHandle;

/// Synthetic petal hash used by primitive `BloomType` impls. Concrete
/// petal types use the type-defining petal's content hash; primitives
/// are intrinsic and carry an all-zero hash so the resulting `TypeTag`
/// is deterministic and globally unique among primitives.
pub const PRIMITIVE_PETAL_HASH: [u8; 32] = [0u8; 32];

/// Marker trait identifying every type that may be stored as a
/// `Resource<T>` payload. The macros impl this automatically for
/// `#[object]`-annotated structs; primitive impls live below.
///
/// All canonical-codec helpers here are **deterministic, no-float**
/// per spec §11.2 / §4.1. Encoding errors are intentionally not
/// surfaced via this trait (impls panic on encoder overflow); the
/// petal-side macros size their buffers from the type-tag width, so
/// overflow paths are unreachable for well-formed input.
pub trait BloomType: Sized {
    /// Canonical-encode `self` into a fresh `Vec<u8>`.
    fn canonical_encode(&self) -> Vec<u8>;

    /// Canonical-decode `buf`. Returns the typed value or an
    /// [`AbiError`] if the bytes do not match the expected shape.
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError>;

    /// The `TypeTag` that identifies `Self` in the on-chain object
    /// store and in inter-petal calls.
    fn type_tag() -> TypeTag;
}

/// Runtime-typed wrapper for a value of generic type `T`.
///
/// Two construction shapes coexist:
/// 1. Value-bearing: `Resource::new(type_tag, bytes)` / `Resource::from_value(&t)`
///    carry the canonical-encoded payload for a `T: BloomType`.
/// 2. Handle-bearing: `Resource::from_handle(h)` wraps a borrow-table
///    handle for an unrecognised object-like arg in a generic petal fn
///    (spec §11.2). In this mode `bytes` is empty and `type_tag` is a
///    placeholder; the petal is expected to drive host imports through
///    the carried [`RuntimeHandle`].
pub struct Resource<T> {
    type_tag: TypeTag,
    bytes: Vec<u8>,
    handle: RuntimeHandle,
    _marker: PhantomData<T>,
}

impl<T> Clone for Resource<T> {
    fn clone(&self) -> Self {
        Self {
            type_tag: self.type_tag.clone(),
            bytes: self.bytes.clone(),
            handle: self.handle,
            _marker: PhantomData,
        }
    }
}

impl<T> core::fmt::Debug for Resource<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Resource")
            .field("type_tag", &self.type_tag)
            .field("bytes_len", &self.bytes.len())
            .field("handle", &self.handle)
            .finish()
    }
}

impl<T> PartialEq for Resource<T> {
    fn eq(&self, other: &Self) -> bool {
        self.type_tag == other.type_tag && self.bytes == other.bytes && self.handle == other.handle
    }
}

impl<T> Eq for Resource<T> {}

impl<T> Resource<T> {
    /// Construct from raw `TypeTag` + canonical-encoded bytes. The
    /// runtime handle defaults to [`RuntimeHandle::INVALID`].
    pub fn new(type_tag: TypeTag, bytes: Vec<u8>) -> Self {
        Self {
            type_tag,
            bytes,
            handle: RuntimeHandle::INVALID,
            _marker: PhantomData,
        }
    }

    /// Wrap a borrow-table handle as a generic object resource.
    ///
    /// The macro-emitted `__petal_<fn>` shim calls this for any object
    /// arg whose Rust type is not specially recognised (i.e. not
    /// `Coin`, `Capability`, or `Signer`). The carried handle is the
    /// only piece of state with meaning in this mode; `type_tag` is a
    /// placeholder (`Generic { idx: 0 }`) and `bytes` is empty.
    pub fn from_handle(h: RuntimeHandle) -> Self {
        Self {
            type_tag: TypeTag::Generic { idx: 0 },
            bytes: Vec::new(),
            handle: h,
            _marker: PhantomData,
        }
    }

    /// Borrow the type tag.
    pub fn type_tag(&self) -> &TypeTag {
        &self.type_tag
    }

    /// Borrow the canonical-encoded payload.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the canonical-encoded payload.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Borrow-table handle carried by this resource (valid only for the
    /// handle-bearing construction shape; otherwise
    /// [`RuntimeHandle::INVALID`]).
    pub fn handle(&self) -> RuntimeHandle {
        self.handle
    }
}

impl<T: BloomType> Resource<T> {
    /// Wrap a `T: BloomType` value.
    pub fn from_value(value: &T) -> Self {
        Self::new(T::type_tag(), value.canonical_encode())
    }

    /// Decode into a concrete `U: BloomType`. Errors if the resource's
    /// `type_tag` does not match `U::type_tag()` or the bytes do not
    /// decode cleanly.
    pub fn into_value<U: BloomType>(self) -> Result<U, PetalError> {
        if self.type_tag != U::type_tag() {
            return Err(PetalError::TypeMismatch);
        }
        U::canonical_decode(&self.bytes).map_err(|_| PetalError::InvalidArgs)
    }
}

// ---------------------------------------------------------------------------
// Primitive BloomType impls
//
// Encoding rules match `abi::RetWriter` exactly so a primitive can be
// round-tripped between `Resource<T>` payloads and inline args without
// re-encoding through a wrapper layer.
// ---------------------------------------------------------------------------

fn primitive_tag(name: &str) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: PRIMITIVE_PETAL_HASH,
        type_name: name.to_string(),
        type_args: Vec::new(),
    }
}

macro_rules! impl_bloom_type_for_unsigned {
    ($t:ty, $name:literal, $bytes:literal) => {
        impl BloomType for $t {
            fn canonical_encode(&self) -> Vec<u8> {
                self.to_be_bytes().to_vec()
            }
            fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
                if buf.len() != $bytes {
                    return Err(AbiError::UnexpectedEof {
                        needed: $bytes,
                        available: buf.len(),
                    });
                }
                let mut a = [0u8; $bytes];
                a.copy_from_slice(buf);
                Ok(<$t>::from_be_bytes(a))
            }
            fn type_tag() -> TypeTag {
                primitive_tag($name)
            }
        }
    };
}

impl_bloom_type_for_unsigned!(u8, "u8", 1);
impl_bloom_type_for_unsigned!(u16, "u16", 2);
impl_bloom_type_for_unsigned!(u32, "u32", 4);
impl_bloom_type_for_unsigned!(u64, "u64", 8);
impl_bloom_type_for_unsigned!(u128, "u128", 16);

impl BloomType for bool {
    fn canonical_encode(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        if buf.len() != 1 {
            return Err(AbiError::UnexpectedEof {
                needed: 1,
                available: buf.len(),
            });
        }
        match buf[0] {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(AbiError::InvalidBool(other)),
        }
    }
    fn type_tag() -> TypeTag {
        primitive_tag("bool")
    }
}

impl BloomType for [u8; 32] {
    fn canonical_encode(&self) -> Vec<u8> {
        self.to_vec()
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        if buf.len() != 32 {
            return Err(AbiError::UnexpectedEof {
                needed: 32,
                available: buf.len(),
            });
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(buf);
        Ok(a)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("address")
    }
}

impl BloomType for ObjectId {
    fn canonical_encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        <[u8; 32]>::canonical_decode(buf).map(ObjectId)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("ObjectId")
    }
}

impl BloomType for Hash32 {
    fn canonical_encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        <[u8; 32]>::canonical_decode(buf).map(Hash32)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("Hash32")
    }
}

impl BloomType for String {
    fn canonical_encode(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        core::str::from_utf8(buf)
            .map(|s| s.to_owned())
            .map_err(|_| AbiError::InvalidUtf8)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("string")
    }
}

impl BloomType for Vec<u8> {
    fn canonical_encode(&self) -> Vec<u8> {
        self.clone()
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        Ok(buf.to_vec())
    }
    fn type_tag() -> TypeTag {
        primitive_tag("bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: BloomType + Eq + std::fmt::Debug>(v: T) {
        let bytes = v.canonical_encode();
        let back = T::canonical_decode(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn u8_round_trip() {
        rt(0u8);
        rt(255u8);
    }

    #[test]
    fn u16_round_trip() {
        rt(0u16);
        rt(0xFFFFu16);
    }

    #[test]
    fn u32_round_trip() {
        rt(0u32);
        rt(u32::MAX);
    }

    #[test]
    fn u64_round_trip() {
        rt(0u64);
        rt(u64::MAX);
    }

    #[test]
    fn u128_round_trip() {
        rt(0u128);
        rt(u128::MAX);
    }

    #[test]
    fn bool_round_trip() {
        rt(false);
        rt(true);
    }

    #[test]
    fn bool_rejects_garbage() {
        let err = bool::canonical_decode(&[5u8]).unwrap_err();
        assert_eq!(err, AbiError::InvalidBool(5));
    }

    #[test]
    fn bool_rejects_wrong_length() {
        let err = bool::canonical_decode(&[]).unwrap_err();
        assert!(matches!(err, AbiError::UnexpectedEof { .. }));
    }

    #[test]
    fn address_round_trip() {
        rt([0xABu8; 32]);
    }

    #[test]
    fn object_id_round_trip() {
        rt(ObjectId([0x42; 32]));
    }

    #[test]
    fn hash32_round_trip() {
        rt(Hash32([0xCD; 32]));
    }

    #[test]
    fn string_round_trip() {
        rt("Coin<USDC>".to_string());
        rt(String::new());
    }

    #[test]
    fn string_rejects_invalid_utf8() {
        let err = String::canonical_decode(&[0xFF, 0xFE]).unwrap_err();
        assert_eq!(err, AbiError::InvalidUtf8);
    }

    #[test]
    fn vec_bytes_round_trip() {
        rt(Vec::<u8>::new());
        rt(vec![1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn primitive_type_tags_are_distinct() {
        let tags: Vec<TypeTag> = vec![
            u8::type_tag(),
            u16::type_tag(),
            u32::type_tag(),
            u64::type_tag(),
            u128::type_tag(),
            bool::type_tag(),
            <[u8; 32]>::type_tag(),
            ObjectId::type_tag(),
            Hash32::type_tag(),
            String::type_tag(),
            Vec::<u8>::type_tag(),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags {} and {} collide", i, j);
            }
        }
    }

    #[test]
    fn primitive_type_tags_use_intrinsic_petal_hash() {
        match u64::type_tag() {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, PRIMITIVE_PETAL_HASH);
                assert_eq!(type_name, "u64");
                assert!(type_args.is_empty());
            }
            other => panic!("expected concrete tag, got {other:?}"),
        }
    }

    #[test]
    fn resource_round_trip_via_value() {
        let r = Resource::<u64>::from_value(&1_234_567u64);
        assert_eq!(r.type_tag(), &u64::type_tag());
        let back: u64 = r.into_value().unwrap();
        assert_eq!(back, 1_234_567);
    }

    #[test]
    fn resource_into_value_rejects_type_mismatch() {
        let r = Resource::<u64>::from_value(&1u64);
        let err = r.into_value::<u32>().unwrap_err();
        assert_eq!(err, PetalError::TypeMismatch);
    }

    #[test]
    fn resource_into_value_rejects_bad_bytes() {
        // Build a resource with the u64 tag but only 4 bytes of payload.
        let r = Resource::<u64>::new(u64::type_tag(), vec![0, 0, 0, 1]);
        let err = r.into_value::<u64>().unwrap_err();
        assert_eq!(err, PetalError::InvalidArgs);
    }

    #[test]
    fn resource_borrowed_accessors() {
        let r = Resource::<u32>::from_value(&42u32);
        assert_eq!(r.bytes(), &[0, 0, 0, 42]);
        let owned = r.clone().into_bytes();
        assert_eq!(owned, vec![0, 0, 0, 42]);
    }

    #[test]
    fn resource_from_handle_carries_handle() {
        let h = RuntimeHandle::from_raw(17);
        let r: Resource<u128> = Resource::from_handle(h);
        assert_eq!(r.handle(), h);
        assert!(r.bytes().is_empty());
    }

    #[test]
    fn resource_value_construction_handle_is_invalid() {
        let r = Resource::<u32>::from_value(&7u32);
        assert_eq!(r.handle(), RuntimeHandle::INVALID);
    }
}
