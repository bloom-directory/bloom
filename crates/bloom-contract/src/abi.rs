//! ABI traits ([`AbiEncode`], [`AbiDecode`], [`AbiType`]) + blanket impls for
//! every primitive, plus tuples up to arity 12.
//!
//! The framework's encoding model layers on top of
//! [`bloom_chain_abi::Encoder`] / [`bloom_chain_abi::Buf`]:
//!
//! - Fixed-width primitives (`u64`, `u128`, `U256`, `bool`, `Address`,
//!   `Hash32`) use the existing fixed-width `push_*` / `read_*` helpers, so
//!   bytes-on-the-wire are identical to what the legacy `contract!` macro
//!   produces.
//! - Variable-length values (`String`, `Vec<T>`, byte sequences) use the new
//!   [`dyn_codec`](bloom_chain_abi::dyn_codec) helpers with a `u16-BE` length
//!   prefix.
//! - User structs / enums are derived via the proc-macros in
//!   [`bloom_contract_macros`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use bloom_chain_abi::{AbiEncodeError, AbiError, Buf, Encoder};

use crate::types::{Address, Hash32, U256};

/// Compile-time and runtime metadata for an ABI-serializable Rust type.
///
/// Every type used in a method signature, event field, error payload, or
/// storage value must implement `AbiType`. The `ABI_TYPE` string feeds into
/// selector / topic hashing; the [`schema`](AbiType::schema) function feeds
/// the manifest emitter.
pub trait AbiType {
    /// Canonical type string, e.g. `"u256"`, `"address"`, `"string"`,
    /// `"Vec<u256>"`. Used inside `blake3` signature hashing.
    const ABI_TYPE: &'static str;

    /// Structured schema for manifest emission.
    fn schema() -> TypeSchema;
}

/// Encode `self` into the chain-ABI byte format.
pub trait AbiEncode {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError>;

    fn encode(&self) -> Result<Vec<u8>, AbiEncodeError> {
        let mut enc = Encoder::new();
        self.encode_into(&mut enc)?;
        Ok(enc.finish())
    }
}

/// Decode `Self` from a chain-ABI byte buffer.
pub trait AbiDecode: Sized {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError>;

    /// Decode + strict EOF check.
    fn decode_from(bytes: &[u8]) -> Result<Self, AbiError> {
        let mut buf = Buf::new(bytes);
        let v = Self::decode(&mut buf)?;
        buf.expect_eof()?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// TypeSchema — structured manifest emission
// ---------------------------------------------------------------------------

/// Structured schema for a Rust type emitted into the contract manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeSchema {
    Address,
    Hash32,
    U256,
    U128,
    U64,
    U32,
    U16,
    U8,
    Bool,
    /// UTF-8 string with optional max byte length.
    String { max: Option<u32> },
    /// Arbitrary byte sequence with optional max length.
    Bytes { max: Option<u32> },
    /// Fixed-length byte array.
    BytesFixed { len: u32 },
    /// Variable-length vector of homogenous elements.
    Vec(Box<TypeSchema>),
    /// Heterogeneous tuple.
    Tuple(Vec<TypeSchema>),
    /// Optional `T`, length-prefixed `0`/`1`.
    Option(Box<TypeSchema>),
    /// `Result<T, E>` (encoded as tag + payload).
    Result {
        ok: Box<TypeSchema>,
        err: Box<TypeSchema>,
    },
    /// User-defined struct with named fields, identified by canonical name.
    Struct {
        name: &'static str,
        fields: Vec<(&'static str, TypeSchema)>,
    },
    /// User-defined enum with named variants.
    Enum {
        name: &'static str,
        variants: Vec<(&'static str, Vec<TypeSchema>)>,
    },
}

// ---------------------------------------------------------------------------
// Primitive impls — fixed-width
// ---------------------------------------------------------------------------

macro_rules! abi_type_const {
    ($t:ty, $name:expr, $schema:expr) => {
        impl AbiType for $t {
            const ABI_TYPE: &'static str = $name;
            fn schema() -> TypeSchema { $schema }
        }
    };
}

abi_type_const!(bool, "bool", TypeSchema::Bool);
abi_type_const!(u8, "u8", TypeSchema::U8);
abi_type_const!(u16, "u16", TypeSchema::U16);
abi_type_const!(u32, "u32", TypeSchema::U32);
abi_type_const!(u64, "u64", TypeSchema::U64);
abi_type_const!(u128, "u128", TypeSchema::U128);
abi_type_const!(U256, "u256", TypeSchema::U256);
abi_type_const!(Address, "address", TypeSchema::Address);
abi_type_const!(Hash32, "bytes32", TypeSchema::Hash32);

impl AbiEncode for bool {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bool(*self);
        Ok(())
    }
}
impl AbiDecode for bool {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_bool()
    }
}

impl AbiEncode for u8 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes(&[*self]);
        Ok(())
    }
}
impl AbiDecode for u8 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let avail = buf.remaining();
        if avail < 1 {
            return Err(AbiError::UnexpectedEof { needed: 1, available: avail });
        }
        let pos = buf.position();
        let b = buf.data()[pos];
        buf.advance(1);
        Ok(b)
    }
}

impl AbiEncode for u16 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes(&self.to_be_bytes());
        Ok(())
    }
}
impl AbiDecode for u16 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let b = buf.read_u16_bytes()?;
        Ok(u16::from_be_bytes(b))
    }
}

impl AbiEncode for u32 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes(&self.to_be_bytes());
        Ok(())
    }
}
impl AbiDecode for u32 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let avail = buf.remaining();
        if avail < 4 {
            return Err(AbiError::UnexpectedEof { needed: 4, available: avail });
        }
        let pos = buf.position();
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&buf.data()[pos..pos + 4]);
        buf.advance(4);
        Ok(u32::from_be_bytes(arr))
    }
}

impl AbiEncode for u64 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_u64(*self);
        Ok(())
    }
}
impl AbiDecode for u64 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_u64()
    }
}

impl AbiEncode for u128 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_u128(*self);
        Ok(())
    }
}
impl AbiDecode for u128 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_u128()
    }
}

impl AbiEncode for U256 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_u256(*self);
        Ok(())
    }
}
impl AbiDecode for U256 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_u256()
    }
}

impl AbiEncode for Address {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_address(&self.0);
        Ok(())
    }
}
impl AbiDecode for Address {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_address().map(Address)
    }
}

impl AbiEncode for Hash32 {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes32(&self.0);
        Ok(())
    }
}
impl AbiDecode for Hash32 {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_bytes32().map(Hash32)
    }
}

// `()` — used by `Result<T, ()>` and zero-output methods.
impl AbiType for () {
    const ABI_TYPE: &'static str = "()";
    fn schema() -> TypeSchema {
        TypeSchema::Tuple(Vec::new())
    }
}
impl AbiEncode for () {
    fn encode_into(&self, _enc: &mut Encoder) -> Result<(), AbiEncodeError> { Ok(()) }
}
impl AbiDecode for () {
    fn decode(_buf: &mut Buf<'_>) -> Result<Self, AbiError> { Ok(()) }
}

// ---------------------------------------------------------------------------
// Dynamic primitives — string, Vec<T>, Option<T>, fixed byte arrays
// ---------------------------------------------------------------------------

impl AbiType for String {
    const ABI_TYPE: &'static str = "string";
    fn schema() -> TypeSchema {
        TypeSchema::String { max: None }
    }
}
impl AbiEncode for String {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_string(self.as_str())?;
        Ok(())
    }
}
impl AbiDecode for String {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_string()
    }
}

impl<T: AbiType> AbiType for Vec<T> {
    const ABI_TYPE: &'static str = "vec";
    fn schema() -> TypeSchema {
        TypeSchema::Vec(Box::new(T::schema()))
    }
}
impl<T: AbiEncode> AbiEncode for Vec<T> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_u16_len(self.len())?;
        for item in self {
            item.encode_into(enc)?;
        }
        Ok(())
    }
}
impl<T: AbiDecode> AbiDecode for Vec<T> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let n = buf.read_u16_len()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(T::decode(buf)?);
        }
        Ok(out)
    }
}

impl<T: AbiType> AbiType for Option<T> {
    const ABI_TYPE: &'static str = "option";
    fn schema() -> TypeSchema {
        TypeSchema::Option(Box::new(T::schema()))
    }
}
impl<T: AbiEncode> AbiEncode for Option<T> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        match self {
            None => {
                enc.push_bool(false);
                Ok(())
            }
            Some(v) => {
                enc.push_bool(true);
                v.encode_into(enc)
            }
        }
    }
}
impl<T: AbiDecode> AbiDecode for Option<T> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let tag = buf.read_bool()?;
        if tag {
            Ok(Some(T::decode(buf)?))
        } else {
            Ok(None)
        }
    }
}

// `[u8; N]` — fixed-length byte arrays. Used by event topic arrays and
// `BytesN<N>` internals.
impl<const N: usize> AbiType for [u8; N] {
    const ABI_TYPE: &'static str = "bytes_fixed";
    fn schema() -> TypeSchema {
        TypeSchema::BytesFixed { len: N as u32 }
    }
}
impl<const N: usize> AbiEncode for [u8; N] {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes(self);
        Ok(())
    }
}
impl<const N: usize> AbiDecode for [u8; N] {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let avail = buf.remaining();
        if avail < N {
            return Err(AbiError::UnexpectedEof { needed: N, available: avail });
        }
        let mut arr = [0u8; N];
        let pos = buf.position();
        arr.copy_from_slice(&buf.data()[pos..pos + N]);
        buf.advance(N);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Tuples — used by multi-return values
// ---------------------------------------------------------------------------

macro_rules! tuple_impl {
    ($abi_str:literal, ($($name:ident: $ty:ident),+)) => {
        impl<$($ty: AbiType),+> AbiType for ($($ty,)+) {
            const ABI_TYPE: &'static str = $abi_str;
            fn schema() -> TypeSchema {
                TypeSchema::Tuple(alloc::vec![$($ty::schema()),+])
            }
        }
        impl<$($ty: AbiEncode),+> AbiEncode for ($($ty,)+) {
            #[allow(non_snake_case)]
            fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
                let ($($name,)+) = self;
                $( $name.encode_into(enc)?; )+
                Ok(())
            }
        }
        impl<$($ty: AbiDecode),+> AbiDecode for ($($ty,)+) {
            #[allow(non_snake_case)]
            fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
                $( let $name = $ty::decode(buf)?; )+
                Ok(($($name,)+))
            }
        }
    };
}

tuple_impl!("tuple1", (t0: T0));
tuple_impl!("tuple2", (t0: T0, t1: T1));
tuple_impl!("tuple3", (t0: T0, t1: T1, t2: T2));
tuple_impl!("tuple4", (t0: T0, t1: T1, t2: T2, t3: T3));
tuple_impl!("tuple5", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4));
tuple_impl!("tuple6", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5));
tuple_impl!("tuple7", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6));
tuple_impl!("tuple8", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7));
tuple_impl!("tuple9", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7, t8: T8));
tuple_impl!("tuple10", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7, t8: T8, t9: T9));
tuple_impl!("tuple11", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7, t8: T8, t9: T9, t10: T10));
tuple_impl!("tuple12", (t0: T0, t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7, t8: T8, t9: T9, t10: T10, t11: T11));

// ---------------------------------------------------------------------------
// Bounded types — StringN, BytesN
// ---------------------------------------------------------------------------

/// A UTF-8 string with a static byte-length cap of `N`.
///
/// Encodes the same on the wire as `String` (length-prefixed), but the
/// manifest schema records the maximum length so off-chain validators can
/// reject oversize fields without running the contract.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StringN<const N: usize>(pub String);

impl<const N: usize> StringN<N> {
    pub fn new(s: String) -> Result<Self, AbiEncodeError> {
        if s.len() > N {
            return Err(AbiEncodeError::TooLong(s.len()));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<const N: usize> AbiType for StringN<N> {
    const ABI_TYPE: &'static str = "string";
    fn schema() -> TypeSchema {
        TypeSchema::String { max: Some(N as u32) }
    }
}
impl<const N: usize> AbiEncode for StringN<N> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        if self.0.len() > N {
            return Err(AbiEncodeError::TooLong(self.0.len()));
        }
        enc.push_string(self.0.as_str())?;
        Ok(())
    }
}
impl<const N: usize> AbiDecode for StringN<N> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let s = buf.read_string()?;
        if s.len() > N {
            return Err(AbiError::TrailingBytes { remaining: s.len() - N });
        }
        Ok(Self(s))
    }
}

/// A variable-length byte array with a static cap of `N`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BytesN<const N: usize>(pub Vec<u8>);

impl<const N: usize> BytesN<N> {
    pub fn new(b: Vec<u8>) -> Result<Self, AbiEncodeError> {
        if b.len() > N {
            return Err(AbiEncodeError::TooLong(b.len()));
        }
        Ok(Self(b))
    }
}

impl<const N: usize> AbiType for BytesN<N> {
    const ABI_TYPE: &'static str = "bytes";
    fn schema() -> TypeSchema {
        TypeSchema::Bytes { max: Some(N as u32) }
    }
}
impl<const N: usize> AbiEncode for BytesN<N> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        if self.0.len() > N {
            return Err(AbiEncodeError::TooLong(self.0.len()));
        }
        enc.push_bytes_var(self.0.as_slice())?;
        Ok(())
    }
}
impl<const N: usize> AbiDecode for BytesN<N> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let b = buf.read_bytes_var()?;
        if b.len() > N {
            return Err(AbiError::TrailingBytes { remaining: b.len() - N });
        }
        Ok(Self(b))
    }
}

// ---------------------------------------------------------------------------
// Manifest schema version constant — bumped by the metadata crate; mirrored
// here so the runtime ABI can re-export it in `prelude`.
// ---------------------------------------------------------------------------

pub const ABI_SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T: AbiEncode + AbiDecode + core::fmt::Debug + PartialEq>(v: T) {
        let bytes = v.encode().unwrap();
        let back = T::decode_from(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn primitives_roundtrip() {
        roundtrip(true);
        roundtrip(false);
        roundtrip(0u8);
        roundtrip(0xABu8);
        roundtrip(0x1234u16);
        roundtrip(0xDEAD_BEEFu32);
        roundtrip(0x0123_4567_89AB_CDEFu64);
        roundtrip((1u128 << 100) | 0xDEAD);
        roundtrip(U256::from_u128(0xCAFE));
        roundtrip(Address::from([7u8; 32]));
        roundtrip(Hash32::from([0xABu8; 32]));
        roundtrip(());
    }

    #[test]
    fn option_roundtrip() {
        roundtrip(None::<u64>);
        roundtrip(Some(42u64));
    }

    #[test]
    fn vec_roundtrip() {
        roundtrip(Vec::<u64>::new());
        roundtrip(vec![1u64, 2, 3, 4]);
    }

    #[test]
    fn string_roundtrip() {
        roundtrip(String::from(""));
        roundtrip(String::from("hello"));
    }

    #[test]
    fn tuple_roundtrip() {
        roundtrip((1u8,));
        roundtrip((1u8, true));
        roundtrip((1u128, 2u128, 3u64));
        roundtrip((Address::from([1u8; 32]), U256::from_u128(99)));
    }

    #[test]
    fn bytes_fixed_array() {
        let arr = [9u8; 16];
        let bytes = arr.encode().unwrap();
        assert_eq!(bytes.len(), 16);
        let back: [u8; 16] = AbiDecode::decode_from(&bytes).unwrap();
        assert_eq!(back, arr);
    }

    #[test]
    fn stringn_roundtrip() {
        let s = StringN::<32>::new(String::from("loom")).unwrap();
        let bytes = s.encode().unwrap();
        let back = StringN::<32>::decode_from(&bytes).unwrap();
        assert_eq!(back.as_str(), "loom");
    }

    #[test]
    fn stringn_rejects_oversize() {
        let oversize = "x".repeat(33);
        let res = StringN::<32>::new(oversize);
        assert!(matches!(res, Err(AbiEncodeError::TooLong(33))));
    }

    #[test]
    fn schema_for_primitives_matches_spec() {
        assert_eq!(u64::schema(), TypeSchema::U64);
        assert_eq!(<U256 as AbiType>::schema(), TypeSchema::U256);
        assert_eq!(<Address as AbiType>::schema(), TypeSchema::Address);
        match <Vec<u64> as AbiType>::schema() {
            TypeSchema::Vec(b) => assert_eq!(*b, TypeSchema::U64),
            other => panic!("expected Vec schema, got {other:?}"),
        }
        match <Option<bool> as AbiType>::schema() {
            TypeSchema::Option(b) => assert_eq!(*b, TypeSchema::Bool),
            other => panic!("expected Option schema, got {other:?}"),
        }
    }

    #[test]
    fn schema_version_is_v1() {
        assert_eq!(ABI_SCHEMA_VERSION, 1);
    }
}
