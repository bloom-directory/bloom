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
    String {
        max: Option<u32>,
    },
    /// Arbitrary byte sequence with optional max length.
    Bytes {
        max: Option<u32>,
    },
    /// Fixed-length byte array.
    BytesFixed {
        len: u32,
    },
    /// Variable-length vector of homogenous elements.
    Vec(Box<TypeSchema>),
    /// Variable-length vector with a static byte/element cap.
    VecN {
        elem: Box<TypeSchema>,
        max: u32,
    },
    /// Fixed-length array of homogenous elements (`[T; N]` / `ArrayN<T, N>`).
    Array {
        elem: Box<TypeSchema>,
        len: u32,
    },
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
            fn schema() -> TypeSchema {
                $schema
            }
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
abi_type_const!(crate::types::Bytes32String, "bytes32", TypeSchema::Hash32);

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
            return Err(AbiError::UnexpectedEof {
                needed: 1,
                available: avail,
            });
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
            return Err(AbiError::UnexpectedEof {
                needed: 4,
                available: avail,
            });
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

impl AbiEncode for crate::types::Bytes32String {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        enc.push_bytes32(&self.0);
        Ok(())
    }
}
impl AbiDecode for crate::types::Bytes32String {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        buf.read_bytes32().map(crate::types::Bytes32String)
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
    fn encode_into(&self, _enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        Ok(())
    }
}
impl AbiDecode for () {
    fn decode(_buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        Ok(())
    }
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

// `Result<T, E>` — encoded as `0u8 || T` for `Ok(T)`, `1u8 || E` for `Err(E)`.
//
// This is the wire form used by returning typed errors from a handler when
// the caller wants to disambiguate without re-decoding revert bytes. Most
// `#[bloom::contract]` handlers return `Result<T, ContractError>` which
// short-circuits to `petal.revert` and never round-trips through the
// `AbiEncode` impl below; this impl matters when `Result<T, E>` appears
// inside a return tuple or struct (e.g. `Result<u256, Erc20Error>` as a
// nested type).
impl<T: AbiType, E: AbiType> AbiType for core::result::Result<T, E> {
    const ABI_TYPE: &'static str = "result";
    fn schema() -> TypeSchema {
        TypeSchema::Result {
            ok: alloc::boxed::Box::new(T::schema()),
            err: alloc::boxed::Box::new(E::schema()),
        }
    }
}
impl<T: AbiEncode, E: AbiEncode> AbiEncode for core::result::Result<T, E> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        match self {
            Ok(v) => {
                enc.push_bytes(&[0u8]);
                v.encode_into(enc)
            }
            Err(e) => {
                enc.push_bytes(&[1u8]);
                e.encode_into(enc)
            }
        }
    }
}
impl<T: AbiDecode, E: AbiDecode> AbiDecode for core::result::Result<T, E> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let tag = u8::decode(buf)?;
        match tag {
            0 => Ok(Ok(T::decode(buf)?)),
            1 => Ok(Err(E::decode(buf)?)),
            other => Err(AbiError::InvalidDiscriminant(other)),
        }
    }
}

// `[u8; N]` — fixed-length byte arrays. Used by event topic arrays and
// `BytesN<N>` internals. Encodes byte-for-byte (no length prefix) because
// the length is part of the type.
//
// `[T; N]` for general `T` uses the same "no length prefix" rule but encodes
// each element through its `AbiEncode` impl. These two impls overlap on
// `[u8; N]` — we keep the byte path as a thin specialization because the
// `bytes_fixed` schema label is hard-coded into the wire format for events
// (topic arrays) and `BytesN<N>`. To avoid the impl collision Rust would
// flag on `[u8; N]`, the general path lives behind a marker trait so it
// only fires for non-`u8` element types.

/// Marker trait — element types eligible for the general `[T; N]` impl.
///
/// `u8` deliberately *does not* implement this so `[u8; N]` keeps its
/// dedicated `bytes_fixed` form. Everything else with `AbiType` does, via
/// the blanket impl below.
pub trait AbiArrayElement: AbiType {}

impl AbiArrayElement for bool {}
impl AbiArrayElement for u16 {}
impl AbiArrayElement for u32 {}
impl AbiArrayElement for u64 {}
impl AbiArrayElement for u128 {}
impl AbiArrayElement for U256 {}
impl AbiArrayElement for Address {}
impl AbiArrayElement for Hash32 {}
impl AbiArrayElement for crate::types::Bytes32String {}
impl AbiArrayElement for String {}
impl<T: AbiType> AbiArrayElement for Option<T> {}
impl<T: AbiType> AbiArrayElement for Vec<T> {}

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
            return Err(AbiError::UnexpectedEof {
                needed: N,
                available: avail,
            });
        }
        let mut arr = [0u8; N];
        let pos = buf.position();
        arr.copy_from_slice(&buf.data()[pos..pos + N]);
        buf.advance(N);
        Ok(arr)
    }
}

/// General fixed-length array `[T; N]` for any `T: AbiArrayElement`.
///
/// `T = u8` uses the byte-specialized impl above so existing `bytes_fixed`
/// encoded payloads stay byte-for-byte the same.
impl<T: AbiArrayElement, const N: usize> AbiType for ArrayN<T, N> {
    const ABI_TYPE: &'static str = "array";
    fn schema() -> TypeSchema {
        TypeSchema::Array {
            elem: alloc::boxed::Box::new(T::schema()),
            len: N as u32,
        }
    }
}
impl<T: AbiEncode + AbiArrayElement, const N: usize> AbiEncode for ArrayN<T, N> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        for elem in &self.0 {
            elem.encode_into(enc)?;
        }
        Ok(())
    }
}
impl<T: AbiDecode + AbiArrayElement + Default + Copy, const N: usize> AbiDecode for ArrayN<T, N> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let mut arr: [T; N] = [T::default(); N];
        for slot in arr.iter_mut() {
            *slot = T::decode(buf)?;
        }
        Ok(ArrayN(arr))
    }
}

/// Newtype wrapper around `[T; N]` enabling the general element-encoded
/// fixed-length array codec. `[u8; N]` keeps its `bytes_fixed` form via the
/// dedicated impl above; for any other element type, wrap in `ArrayN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArrayN<T, const N: usize>(pub [T; N]);

impl<T, const N: usize> ArrayN<T, N> {
    pub fn new(inner: [T; N]) -> Self {
        Self(inner)
    }
    pub fn into_inner(self) -> [T; N] {
        self.0
    }
    pub fn as_array(&self) -> &[T; N] {
        &self.0
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
        TypeSchema::String {
            max: Some(N as u32),
        }
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
            return Err(AbiError::TrailingBytes {
                remaining: s.len() - N,
            });
        }
        Ok(Self(s))
    }
}

/// A variable-length vector with a static element-count cap of `N`.
///
/// Wire format is identical to `Vec<T>` (u16-LE length + N encoded elements);
/// the manifest schema records the cap so off-chain validators can reject
/// over-sized calldata without instantiating the contract.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VecN<T, const N: usize>(pub Vec<T>);

impl<T, const N: usize> VecN<T, N> {
    pub fn new(items: Vec<T>) -> Result<Self, AbiEncodeError> {
        if items.len() > N {
            return Err(AbiEncodeError::TooLong(items.len()));
        }
        Ok(Self(items))
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: AbiType, const N: usize> AbiType for VecN<T, N> {
    const ABI_TYPE: &'static str = "vec";
    fn schema() -> TypeSchema {
        TypeSchema::VecN {
            elem: Box::new(T::schema()),
            max: N as u32,
        }
    }
}
impl<T: AbiEncode, const N: usize> AbiEncode for VecN<T, N> {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError> {
        if self.0.len() > N {
            return Err(AbiEncodeError::TooLong(self.0.len()));
        }
        enc.push_u16_len(self.0.len())?;
        for item in &self.0 {
            item.encode_into(enc)?;
        }
        Ok(())
    }
}
impl<T: AbiDecode, const N: usize> AbiDecode for VecN<T, N> {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError> {
        let n = buf.read_u16_len()?;
        if n > N {
            return Err(AbiError::VecOverflow {
                count: n,
                available: buf.remaining(),
            });
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(T::decode(buf)?);
        }
        Ok(Self(out))
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
        TypeSchema::Bytes {
            max: Some(N as u32),
        }
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
            return Err(AbiError::TrailingBytes {
                remaining: b.len() - N,
            });
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

    #[test]
    fn result_ok_branch_roundtrips() {
        let v: core::result::Result<u64, u32> = Ok(0xDEAD_BEEF);
        let bytes = v.encode().unwrap();
        assert_eq!(bytes[0], 0u8);
        let back: core::result::Result<u64, u32> = AbiDecode::decode_from(&bytes).unwrap();
        assert_eq!(back, Ok(0xDEAD_BEEF));
    }

    #[test]
    fn result_err_branch_roundtrips() {
        let v: core::result::Result<u64, u32> = Err(42);
        let bytes = v.encode().unwrap();
        assert_eq!(bytes[0], 1u8);
        let back: core::result::Result<u64, u32> = AbiDecode::decode_from(&bytes).unwrap();
        assert_eq!(back, Err(42));
    }

    #[test]
    fn result_rejects_invalid_discriminant() {
        let bytes = [2u8, 0, 0, 0, 0, 0, 0, 0, 0]; // tag=2 is neither Ok(0) nor Err(_)
        let res: Result<core::result::Result<u64, u32>, AbiError> =
            <core::result::Result<u64, u32> as AbiDecode>::decode_from(&bytes);
        assert!(matches!(res, Err(AbiError::InvalidDiscriminant(2))));
    }

    #[test]
    fn arrayn_roundtrip_u64() {
        let arr = ArrayN::<u64, 3>::new([0x0102_0304_0506_0708, 0x0FEDCBA987654321, 0]);
        let bytes = arr.encode().unwrap();
        // 3 u64 elements * 8 bytes — no length prefix.
        assert_eq!(bytes.len(), 24);
        let back = ArrayN::<u64, 3>::decode_from(&bytes).unwrap();
        assert_eq!(back, arr);
    }

    #[test]
    fn arrayn_schema_records_length() {
        match <ArrayN<u64, 5> as AbiType>::schema() {
            TypeSchema::Array { len, .. } => assert_eq!(len, 5),
            other => panic!("expected Array schema, got {other:?}"),
        }
    }

    #[test]
    fn vecn_roundtrip_under_cap() {
        let v = VecN::<u32, 4>::new(vec![1, 2, 3]).unwrap();
        let bytes = v.encode().unwrap();
        let back = VecN::<u32, 4>::decode_from(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn vecn_rejects_oversize_on_construction() {
        let res = VecN::<u32, 2>::new(vec![1, 2, 3]);
        assert!(matches!(res, Err(AbiEncodeError::TooLong(3))));
    }

    #[test]
    fn vecn_rejects_oversize_on_decode() {
        // Build wire bytes for a Vec of 3 elements (3 > N=2 cap).
        let raw = Vec::<u32>::from([1, 2, 3]).encode().unwrap();
        let res = <VecN<u32, 2> as AbiDecode>::decode_from(&raw);
        assert!(matches!(res, Err(AbiError::VecOverflow { count: 3, .. })));
    }

    #[test]
    fn vecn_schema_records_max() {
        match <VecN<u64, 8> as AbiType>::schema() {
            TypeSchema::VecN { max, .. } => assert_eq!(max, 8),
            other => panic!("expected VecN schema, got {other:?}"),
        }
    }
}
