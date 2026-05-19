//! ABI traits ([`AbiEncode`], [`AbiDecode`], [`AbiType`]).
//!
//! Phase 1 ships only the trait stubs and the schema enum so the rest of the
//! framework can name the types. Concrete impls land in Phase 2 alongside the
//! dynamic codec helpers.

use alloc::string::String;
use alloc::vec::Vec;

pub use bloom_chain_abi::{AbiEncodeError, AbiError, Buf, Encoder};

/// Compile-time and runtime metadata for an ABI-serializable Rust type.
///
/// Implementors return both a canonical signature string (used inside method
/// selectors and event topics) and a structured [`TypeSchema`] used by the
/// manifest emitter.
pub trait AbiType {
    /// Canonical type string, e.g. `"u256"`, `"address"`, `"(u128,u128,u64)"`,
    /// `"Vec<address>"`. Used inside selector / topic signature hashing.
    const ABI_TYPE: &'static str;

    /// Structured schema for manifest emission.
    fn schema() -> TypeSchema;
}

/// Encode a value into a chain-ABI byte buffer.
pub trait AbiEncode {
    fn encode_into(&self, enc: &mut Encoder) -> Result<(), AbiEncodeError>;

    fn encode(&self) -> Result<Vec<u8>, AbiEncodeError> {
        let mut enc = Encoder::new();
        self.encode_into(&mut enc)?;
        Ok(enc.finish())
    }
}

/// Decode a value from a chain-ABI byte buffer.
pub trait AbiDecode: Sized {
    fn decode(buf: &mut Buf<'_>) -> Result<Self, AbiError>;

    fn decode_from(bytes: &[u8]) -> Result<Self, AbiError> {
        let mut buf = Buf::new(bytes);
        let v = Self::decode(&mut buf)?;
        buf.expect_eof()?;
        Ok(v)
    }
}

/// Structured schema for a Rust type emitted into the contract manifest.
///
/// Phase 1 ships only the variant names; the manifest emitter in Phase 6 turns
/// these into JSON. Adding a variant is a backwards-compatible bump if and only
/// if the manifest `schema_version` is bumped at the same time.
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
    Vec(alloc::boxed::Box<TypeSchema>),
    /// Heterogeneous tuple.
    Tuple(Vec<TypeSchema>),
    /// Optional `T`, length-prefixed `0`/`1`.
    Option(alloc::boxed::Box<TypeSchema>),
    /// `Result<T, E>` (encoded as tag + payload).
    Result {
        ok: alloc::boxed::Box<TypeSchema>,
        err: alloc::boxed::Box<TypeSchema>,
    },
    /// User-defined struct with named fields, identified by canonical name.
    Struct {
        name: String,
        fields: Vec<(String, TypeSchema)>,
    },
    /// User-defined enum with named variants.
    Enum {
        name: String,
        variants: Vec<(String, Vec<TypeSchema>)>,
    },
}
