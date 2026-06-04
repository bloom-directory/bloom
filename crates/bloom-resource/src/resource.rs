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

use std::collections::{BTreeMap, BTreeSet};

use bloom_chain_types::Hash32;
use bloom_objects::{BUILTIN_TYPE_HASH, ObjectId, TypeTag};
use bloom_value::{DEFAULT_MAX_COLLECTION_LEN, read_uleb128, write_uleb128};
use core::marker::PhantomData;

use crate::abi::AbiError;
use crate::error::PetalError;
use crate::handle::RuntimeHandle;

/// Synthetic petal hash used by primitive `BloomType` impls. Concrete
/// petal types use the type-defining petal's content hash; primitives
/// are intrinsic and carry the reserved built-in hash.
pub const PRIMITIVE_PETAL_HASH: [u8; 32] = BUILTIN_TYPE_HASH;

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

    /// Canonical-decode one value from the front of `buf`, advancing
    /// the cursor by exactly the bytes consumed.
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let value = Self::canonical_decode(buf)?;
        *buf = &[];
        Ok(value)
    }

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

fn write_collection_len(len: usize, out: &mut Vec<u8>, kind: &str) {
    assert!(
        (len as u64) <= DEFAULT_MAX_COLLECTION_LEN,
        "{kind} length exceeds canonical collection limit"
    );
    write_uleb128(len as u64, out);
}

fn read_collection_len(buf: &mut &[u8], kind: &str) -> Result<usize, AbiError> {
    let count = read_uleb128(buf).map_err(|e| AbiError::ValueCodec(e.to_string()))?;
    if count > DEFAULT_MAX_COLLECTION_LEN {
        return Err(AbiError::ValueCodec(format!(
            "{kind} length exceeds canonical collection limit"
        )));
    }
    usize::try_from(count).map_err(|_| AbiError::ValueCodec(format!("{kind} length overflow")))
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
            fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
                if buf.len() < $bytes {
                    return Err(AbiError::UnexpectedEof {
                        needed: $bytes,
                        available: buf.len(),
                    });
                }
                let (head, tail) = buf.split_at($bytes);
                *buf = tail;
                let mut a = [0u8; $bytes];
                a.copy_from_slice(head);
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
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        if buf.is_empty() {
            return Err(AbiError::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        }
        let b = buf[0];
        *buf = &buf[1..];
        match b {
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
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        if buf.len() < 32 {
            return Err(AbiError::UnexpectedEof {
                needed: 32,
                available: buf.len(),
            });
        }
        let (head, tail) = buf.split_at(32);
        *buf = tail;
        let mut a = [0u8; 32];
        a.copy_from_slice(head);
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
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        <[u8; 32]>::canonical_decode_from(buf).map(ObjectId)
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
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        <[u8; 32]>::canonical_decode_from(buf).map(Hash32)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("Hash32")
    }
}

impl BloomType for String {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_collection_len(self.len(), &mut out, "string");
        out.extend_from_slice(self.as_bytes());
        out
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let len = read_collection_len(&mut cursor, "string")?;
        if cursor.len() != len {
            return Err(AbiError::UnexpectedEof {
                needed: len,
                available: cursor.len(),
            });
        }
        core::str::from_utf8(cursor)
            .map(|s| s.to_owned())
            .map_err(|_| AbiError::InvalidUtf8)
    }
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let len = read_collection_len(buf, "string")?;
        if buf.len() < len {
            return Err(AbiError::UnexpectedEof {
                needed: len,
                available: buf.len(),
            });
        }
        let (head, tail) = buf.split_at(len);
        *buf = tail;
        core::str::from_utf8(head)
            .map(|s| s.to_owned())
            .map_err(|_| AbiError::InvalidUtf8)
    }
    fn type_tag() -> TypeTag {
        primitive_tag("String")
    }
}

/// Canonical Bloom `bytes` value.
///
/// Use `Vec<T>` for the algebraic `vector<T>` collection. This wrapper
/// exists so Rust code can opt into the distinct built-in `bytes` type.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(
    /// Raw byte contents.
    pub Vec<u8>,
);

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BloomType for Bytes {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_collection_len(self.0.len(), &mut out, "bytes");
        out.extend_from_slice(&self.0);
        out
    }
    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let len = read_collection_len(&mut cursor, "bytes")?;
        if cursor.len() != len {
            return Err(AbiError::UnexpectedEof {
                needed: len,
                available: cursor.len(),
            });
        }
        Ok(Self(cursor.to_vec()))
    }
    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let len = read_collection_len(buf, "bytes")?;
        if buf.len() < len {
            return Err(AbiError::UnexpectedEof {
                needed: len,
                available: buf.len(),
            });
        }
        let (head, tail) = buf.split_at(len);
        *buf = tail;
        Ok(Self(head.to_vec()))
    }
    fn type_tag() -> TypeTag {
        primitive_tag("bytes")
    }
}

impl<T: BloomType> BloomType for Vec<T> {
    fn canonical_encode(&self) -> Vec<u8> {
        let encoded = self
            .iter()
            .map(BloomType::canonical_encode)
            .collect::<Vec<_>>();
        if encoded.first().is_some_and(Vec::is_empty) {
            panic!("non-empty vector of zero-sized values is not canonical");
        }
        let mut out = Vec::new();
        write_collection_len(encoded.len(), &mut out, "vector");
        for item in encoded {
            out.extend_from_slice(&item);
        }
        out
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let value = Self::canonical_decode_from(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(AbiError::TrailingBytes {
                remaining: cursor.len(),
            })
        }
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let count = read_collection_len(buf, "vector")?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let value = T::canonical_decode_from(buf)?;
            if value.canonical_encode().is_empty() {
                return Err(AbiError::ValueCodec(
                    "non-empty vector of zero-sized values".into(),
                ));
            }
            out.push(value);
        }
        Ok(out)
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "vector".to_string(),
            type_args: vec![T::type_tag()],
        }
    }
}

impl BloomType for TypeTag {
    fn canonical_encode(&self) -> Vec<u8> {
        self.encode_canonical()
            .expect("TypeTag canonical encoding should fit codec limits")
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        TypeTag::decode_canonical(buf).map_err(AbiError::from)
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        TypeTag::decode_from(buf, 0).map_err(AbiError::from)
    }

    fn type_tag() -> TypeTag {
        primitive_tag("TypeTag")
    }
}

impl<T: BloomType> BloomType for Option<T> {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            None => write_uleb128(0, &mut out),
            Some(value) => {
                write_uleb128(1, &mut out);
                out.extend_from_slice(&value.canonical_encode());
            }
        }
        out
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let value = Self::canonical_decode_from(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(AbiError::TrailingBytes {
                remaining: cursor.len(),
            })
        }
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        match read_uleb128(buf).map_err(|e| AbiError::ValueCodec(e.to_string()))? {
            0 => Ok(None),
            1 => T::canonical_decode_from(buf).map(Some),
            other => Err(AbiError::ValueCodec(format!(
                "Option discriminant {other} out of range"
            ))),
        }
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "Option".to_string(),
            type_args: vec![T::type_tag()],
        }
    }
}

impl<T: BloomType, E: BloomType> BloomType for Result<T, E> {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Ok(value) => {
                write_uleb128(0, &mut out);
                out.extend_from_slice(&value.canonical_encode());
            }
            Err(value) => {
                write_uleb128(1, &mut out);
                out.extend_from_slice(&value.canonical_encode());
            }
        }
        out
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let value = Self::canonical_decode_from(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(AbiError::TrailingBytes {
                remaining: cursor.len(),
            })
        }
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        match read_uleb128(buf).map_err(|e| AbiError::ValueCodec(e.to_string()))? {
            0 => T::canonical_decode_from(buf).map(Ok),
            1 => E::canonical_decode_from(buf).map(Err),
            other => Err(AbiError::ValueCodec(format!(
                "Result discriminant {other} out of range"
            ))),
        }
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "Result".to_string(),
            type_args: vec![T::type_tag(), E::type_tag()],
        }
    }
}

macro_rules! impl_tuple_bloom_type {
    ($($name:ident : $idx:tt),+ $(,)?) => {
        impl<$($name: BloomType),+> BloomType for ($($name,)+) {
            fn canonical_encode(&self) -> Vec<u8> {
                let mut out = Vec::new();
                $(
                    out.extend_from_slice(&self.$idx.canonical_encode());
                )+
                out
            }

            fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
                let mut cursor = buf;
                let value = Self::canonical_decode_from(&mut cursor)?;
                if cursor.is_empty() {
                    Ok(value)
                } else {
                    Err(AbiError::TrailingBytes {
                        remaining: cursor.len(),
                    })
                }
            }

            fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
                Ok(($(
                    $name::canonical_decode_from(buf)?,
                )+))
            }

            fn type_tag() -> TypeTag {
                TypeTag::Concrete {
                    petal_hash: PRIMITIVE_PETAL_HASH,
                    type_name: "tuple".to_string(),
                    type_args: vec![$($name::type_tag()),+],
                }
            }
        }
    };
}

impl_tuple_bloom_type!(A: 0);
impl_tuple_bloom_type!(A: 0, B: 1);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10);
impl_tuple_bloom_type!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11);

impl BloomType for () {
    fn canonical_encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        if buf.is_empty() {
            Ok(())
        } else {
            Err(AbiError::TrailingBytes {
                remaining: buf.len(),
            })
        }
    }

    fn canonical_decode_from(_buf: &mut &[u8]) -> Result<Self, AbiError> {
        Ok(())
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "tuple".to_string(),
            type_args: Vec::new(),
        }
    }
}

impl<T> BloomType for BTreeSet<T>
where
    T: BloomType + Ord,
{
    fn canonical_encode(&self) -> Vec<u8> {
        let mut encoded = self
            .iter()
            .map(BloomType::canonical_encode)
            .collect::<Vec<_>>();
        encoded.sort();
        let mut out = Vec::new();
        write_collection_len(encoded.len(), &mut out, "set");
        if encoded.first().is_some_and(Vec::is_empty) {
            panic!("non-empty set of zero-sized values is not canonical");
        }
        for item in encoded {
            out.extend_from_slice(&item);
        }
        out
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let value = Self::canonical_decode_from(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(AbiError::TrailingBytes {
                remaining: cursor.len(),
            })
        }
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let count = read_collection_len(buf, "set")?;
        let mut prev: Option<Vec<u8>> = None;
        let mut out = BTreeSet::new();
        for _ in 0..count {
            let value = T::canonical_decode_from(buf)?;
            let encoded = value.canonical_encode();
            if encoded.is_empty() {
                return Err(AbiError::ValueCodec(
                    "non-empty set of zero-sized values".into(),
                ));
            }
            if prev.as_ref().is_some_and(|p| p >= &encoded) {
                return Err(AbiError::ValueCodec(
                    "set keys are not strictly sorted".into(),
                ));
            }
            prev = Some(encoded);
            if !out.insert(value) {
                return Err(AbiError::ValueCodec("duplicate set key".into()));
            }
        }
        Ok(out)
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "set".to_string(),
            type_args: vec![T::type_tag()],
        }
    }
}

impl<K, V> BloomType for BTreeMap<K, V>
where
    K: BloomType + Ord,
    V: BloomType,
{
    fn canonical_encode(&self) -> Vec<u8> {
        let mut encoded = self
            .iter()
            .map(|(k, v)| (k.canonical_encode(), v.canonical_encode()))
            .collect::<Vec<_>>();
        encoded.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        write_collection_len(encoded.len(), &mut out, "map");
        if encoded.first().is_some_and(|(key, _)| key.is_empty()) {
            panic!("non-empty map with zero-sized keys is not canonical");
        }
        for (key, value) in encoded {
            out.extend_from_slice(&key);
            out.extend_from_slice(&value);
        }
        out
    }

    fn canonical_decode(buf: &[u8]) -> Result<Self, AbiError> {
        let mut cursor = buf;
        let value = Self::canonical_decode_from(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(AbiError::TrailingBytes {
                remaining: cursor.len(),
            })
        }
    }

    fn canonical_decode_from(buf: &mut &[u8]) -> Result<Self, AbiError> {
        let count = read_collection_len(buf, "map")?;
        let mut prev: Option<Vec<u8>> = None;
        let mut out = BTreeMap::new();
        for _ in 0..count {
            let key = K::canonical_decode_from(buf)?;
            let encoded = key.canonical_encode();
            if encoded.is_empty() {
                return Err(AbiError::ValueCodec(
                    "non-empty map with zero-sized keys".into(),
                ));
            }
            if prev.as_ref().is_some_and(|p| p >= &encoded) {
                return Err(AbiError::ValueCodec(
                    "map keys are not strictly sorted".into(),
                ));
            }
            prev = Some(encoded);
            let value = V::canonical_decode_from(buf)?;
            if out.insert(key, value).is_some() {
                return Err(AbiError::ValueCodec("duplicate map key".into()));
            }
        }
        Ok(out)
    }

    fn type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: PRIMITIVE_PETAL_HASH,
            type_name: "map".to_string(),
            type_args: vec![K::type_tag(), V::type_tag()],
        }
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
        let err = String::canonical_decode(&[2, 0xFF, 0xFE]).unwrap_err();
        assert_eq!(err, AbiError::InvalidUtf8);
    }

    #[test]
    fn bytes_round_trip() {
        rt(Bytes::from(Vec::new()));
        rt(Bytes::from(vec![1u8, 2, 3, 4, 5]));
        assert_eq!(
            Bytes::from(vec![1u8, 2, 3]).canonical_encode(),
            b"\x03\x01\x02\x03"
        );
        match Bytes::type_tag() {
            TypeTag::Concrete { type_name, .. } => assert_eq!(type_name, "bytes"),
            other => panic!("expected concrete bytes tag, got {other:?}"),
        }
    }

    #[test]
    fn vec_round_trip_and_uses_vector_type_tag() {
        rt(Vec::<u8>::new());
        rt(vec![1u8, 2, 3, 4, 5]);
        rt(vec!["a".to_string(), "bc".to_string()]);
        assert_eq!(vec![1u8, 2, 3].canonical_encode(), b"\x03\x01\x02\x03");
        match Vec::<u8>::type_tag() {
            TypeTag::Concrete {
                type_name,
                type_args,
                ..
            } => {
                assert_eq!(type_name, "vector");
                assert_eq!(type_args, vec![u8::type_tag()]);
            }
            other => panic!("expected concrete vector tag, got {other:?}"),
        }
    }

    #[test]
    fn type_tag_round_trip() {
        rt(TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: "Coin".to_string(),
            type_args: vec![String::type_tag()],
        });
    }

    #[test]
    fn option_round_trip() {
        rt(None::<u64>);
        rt(Some("hi".to_string()));
        assert_eq!(Some("hi".to_string()).canonical_encode(), b"\x01\x02hi");
    }

    #[test]
    fn result_round_trip() {
        rt(Ok::<u64, String>(7));
        rt(Err::<u64, String>("bad".to_string()));
        assert_eq!(
            Ok::<u64, String>(7).canonical_encode(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 7]
        );
    }

    #[test]
    fn tuple_round_trip() {
        rt(());
        rt((9u8,));
        rt((1u8, "x".to_string()));
        rt((1u8, 2u16, true, "z".to_string()));
        rt((1u8, 2u16, 3u32, 4u64, 5u128));
        rt((
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8,
        ));
    }

    #[test]
    fn btree_set_round_trip_and_canonical_order() {
        let mut set = BTreeSet::new();
        set.insert("aa".to_string());
        set.insert("b".to_string());

        // Canonical order is encoded-byte order, so "b" (len 1)
        // precedes "aa" (len 2), even though Rust string order differs.
        assert_eq!(set.canonical_encode(), b"\x02\x01b\x02aa");
        assert_eq!(
            BTreeSet::<String>::canonical_decode(b"\x02\x01b\x02aa").unwrap(),
            set
        );

        let err = BTreeSet::<String>::canonical_decode(b"\x02\x02aa\x01b").unwrap_err();
        assert!(matches!(err, AbiError::ValueCodec(_)));
    }

    #[test]
    fn btree_map_round_trip_and_canonical_key_order() {
        let mut map = BTreeMap::new();
        map.insert("aa".to_string(), 7u8);
        map.insert("b".to_string(), 9u8);

        assert_eq!(map.canonical_encode(), b"\x02\x01b\x09\x02aa\x07");
        assert_eq!(
            BTreeMap::<String, u8>::canonical_decode(b"\x02\x01b\x09\x02aa\x07").unwrap(),
            map
        );

        let err = BTreeMap::<String, u8>::canonical_decode(b"\x02\x02aa\x07\x01b\x09").unwrap_err();
        assert!(matches!(err, AbiError::ValueCodec(_)));
    }

    #[test]
    fn non_empty_zero_sized_collections_are_rejected() {
        let err = Vec::<()>::canonical_decode(&[1]).unwrap_err();
        assert!(matches!(err, AbiError::ValueCodec(_)));

        let err = BTreeSet::<()>::canonical_decode(&[1]).unwrap_err();
        assert!(matches!(err, AbiError::ValueCodec(_)));

        let err = BTreeMap::<(), u8>::canonical_decode(&[1, 7]).unwrap_err();
        assert!(matches!(err, AbiError::ValueCodec(_)));
    }

    #[test]
    #[should_panic(expected = "non-empty set of zero-sized values")]
    fn non_empty_zero_sized_set_encoding_panics() {
        let mut set = BTreeSet::new();
        set.insert(());
        let _ = set.canonical_encode();
    }

    #[test]
    #[should_panic(expected = "non-empty vector of zero-sized values")]
    fn non_empty_zero_sized_vector_encoding_panics() {
        let _ = vec![()].canonical_encode();
    }

    #[test]
    fn generic_type_tags_use_intrinsic_petal_hash() {
        let tags = [
            Option::<u64>::type_tag(),
            Result::<u64, String>::type_tag(),
            Vec::<String>::type_tag(),
            <(u8, String)>::type_tag(),
            BTreeSet::<String>::type_tag(),
            BTreeMap::<String, u8>::type_tag(),
        ];

        for tag in tags {
            match tag {
                TypeTag::Concrete { petal_hash, .. } => {
                    assert_eq!(petal_hash, PRIMITIVE_PETAL_HASH);
                }
                other => panic!("expected concrete tag, got {other:?}"),
            }
        }
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
