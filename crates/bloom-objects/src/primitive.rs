//! Canonical-bytes validation for primitive `TypeTag` payloads.
//!
//! The PTB validator pre-flights every `Arg::Const(bytes)` against the
//! declared manifest [`TypeTag`]. For the well-known primitive type
//! names (`u8`..`u128`, `i8`..`i128`, `bool`, `Address`, `ObjectId`,
//! `String`, `Hash32`) we can decide validity statically by checking
//! the byte length / shape; for anything else we return
//! [`ValidationOutcome::Unknown`] and the validator accepts the bytes
//! (the petal-side runtime is the final arbiter).
//!
//! This module deliberately does **not** know about the wider
//! `bloom-script` types — it operates purely on the raw bytes + the
//! declared [`TypeTag`]. Callers map the outcome onto their own error
//! types.

use crate::codec::{CodecError, read_u8};
use crate::type_tag::TypeTag;

const MAX_COLLECTION_LEN: u64 = 1_000_000;

/// Outcome of validating a byte string against a declared [`TypeTag`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Bytes are a valid canonical encoding of the declared type.
    Ok,
    /// We recognise the declared type as a primitive and the bytes are
    /// malformed (wrong length, invalid UTF-8, etc.).
    Invalid(&'static str),
    /// The declared type is not a primitive we know about (e.g. an
    /// object struct defined by a petal, a generic parameter, or an
    /// external-ref placeholder); the validator should accept the
    /// shape and defer detailed decoding to the runtime.
    Unknown,
}

impl ValidationOutcome {
    /// Convenience: `true` for `Ok` only.
    pub fn is_ok(&self) -> bool {
        matches!(self, ValidationOutcome::Ok)
    }
    /// Convenience: `true` for `Invalid`.
    pub fn is_invalid(&self) -> bool {
        matches!(self, ValidationOutcome::Invalid(_))
    }
    /// Convenience: the error reason if `Invalid`.
    pub fn invalid_reason(&self) -> Option<&'static str> {
        match self {
            ValidationOutcome::Invalid(r) => Some(r),
            _ => None,
        }
    }
}

/// Validate `bytes` as a canonical encoding of `tag`.
///
/// For unrecognised types (object structs, generics, externals,
/// container types other than `vector<T>`) this returns
/// [`ValidationOutcome::Unknown`] — callers should treat that as
/// "no signal, accept" so we don't reject legitimate petal-defined
/// types we have no schema for at validate time.
pub fn validate_canonical_bytes(tag: &TypeTag, bytes: &[u8]) -> ValidationOutcome {
    match tag {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => validate_concrete(type_name, type_args, bytes),
        // Generics can't be checked at validate time (the manifest
        // doesn't carry concrete bindings); externals are pinned by
        // hash but their layout is not known to this crate.
        TypeTag::Generic { .. } | TypeTag::External { .. } => ValidationOutcome::Unknown,
    }
}

fn validate_concrete(name: &str, type_args: &[TypeTag], bytes: &[u8]) -> ValidationOutcome {
    match (name, type_args.len()) {
        ("u8", 0) | ("i8", 0) | ("bool", 0) => {
            if bytes.len() == 1 {
                if name == "bool" && bytes[0] > 1 {
                    return ValidationOutcome::Invalid("bool must be 0 or 1");
                }
                ValidationOutcome::Ok
            } else {
                ValidationOutcome::Invalid("u8/i8/bool require exactly 1 byte")
            }
        }
        ("u16", 0) | ("i16", 0) => exact_len(bytes, 2, "u16/i16 require exactly 2 bytes"),
        ("u32", 0) | ("i32", 0) => exact_len(bytes, 4, "u32/i32 require exactly 4 bytes"),
        ("u64", 0) | ("i64", 0) => exact_len(bytes, 8, "u64/i64 require exactly 8 bytes"),
        ("u128", 0) | ("i128", 0) => exact_len(bytes, 16, "u128/i128 require exactly 16 bytes"),
        ("Address", 0) | ("address", 0) | ("ObjectId", 0) | ("Hash32", 0) | ("UID", 0) => {
            exact_len(
                bytes,
                32,
                "Address/ObjectId/Hash32/UID require exactly 32 bytes",
            )
        }
        ("String", 0) => {
            // Canonical String encoding: minimal ULEB128 length prefix + UTF-8.
            let mut rdr: &[u8] = bytes;
            let len = match read_uleb128(&mut rdr) {
                Ok(l) => l,
                Err(_) => {
                    return ValidationOutcome::Invalid(
                        "String missing valid ULEB128 length prefix",
                    );
                }
            };
            let Ok(len) = usize::try_from(len) else {
                return ValidationOutcome::Invalid("String length overflows usize");
            };
            if rdr.len() != len {
                return ValidationOutcome::Invalid(
                    "String length prefix does not match payload length",
                );
            }
            match core::str::from_utf8(rdr) {
                Ok(_) => ValidationOutcome::Ok,
                Err(_) => ValidationOutcome::Invalid("String payload is not valid UTF-8"),
            }
        }
        ("TypeTag", 0) => {
            // Canonical recursive encoding.
            match TypeTag::decode_canonical(bytes) {
                Ok(_) => ValidationOutcome::Ok,
                Err(_) => ValidationOutcome::Invalid("TypeTag canonical decode failed"),
            }
        }
        // `vector<T>` — ULEB128 count + N concatenated canonical encodings of
        // T. We only validate the length-walk when T is fixed-width primitive.
        ("vector", 1) => validate_vector(&type_args[0], bytes),
        _ => ValidationOutcome::Unknown,
    }
}

fn read_uleb128(input: &mut &[u8]) -> Result<u64, ()> {
    let start_len = input.len();
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10 {
        let Some((&byte, rest)) = input.split_first() else {
            return Err(());
        };
        *input = rest;
        let low = (byte & 0x7f) as u64;
        if i == 9 && (byte & 0x80 != 0 || low > 1) {
            return Err(());
        }
        value |= low << shift;
        if byte & 0x80 == 0 {
            let consumed = start_len - input.len();
            if consumed > 1 {
                let min = if value == 0 {
                    1
                } else {
                    ((value.ilog2() / 7) + 1) as usize
                };
                if consumed != min {
                    return Err(());
                }
            }
            return Ok(value);
        }
        shift += 7;
    }
    Err(())
}

fn exact_len(bytes: &[u8], n: usize, msg: &'static str) -> ValidationOutcome {
    if bytes.len() == n {
        ValidationOutcome::Ok
    } else {
        ValidationOutcome::Invalid(msg)
    }
}

fn validate_vector(elem: &TypeTag, bytes: &[u8]) -> ValidationOutcome {
    let mut rdr = bytes;
    let count = match read_uleb128(&mut rdr) {
        Ok(count) if count <= MAX_COLLECTION_LEN => count as usize,
        Ok(_) => return ValidationOutcome::Invalid("vector count exceeds limit"),
        Err(_) => return ValidationOutcome::Invalid("vector missing valid ULEB128 count prefix"),
    };
    // If the element type isn't a known primitive, we can't tell where
    // each element ends, so once we've verified the count prefix we
    // signal Unknown and let the runtime decode.
    let elem_size = primitive_size_hint(elem);
    let Some(size) = elem_size else {
        return ValidationOutcome::Unknown;
    };
    let expected = match count.checked_mul(size) {
        Some(v) => v,
        None => return ValidationOutcome::Invalid("vector count overflow"),
    };
    if rdr.len() != expected {
        return ValidationOutcome::Invalid("vector payload length mismatch");
    }
    // Validate each element bytewise where the element is also a primitive.
    for _ in 0..count {
        let chunk = &rdr[..size];
        match validate_canonical_bytes(elem, chunk) {
            ValidationOutcome::Ok | ValidationOutcome::Unknown => {}
            invalid => return invalid,
        }
        rdr = &rdr[size..];
    }
    let _ = read_u8; // silence unused-import false positive on some configs
    ValidationOutcome::Ok
}

/// Returns the fixed canonical width in bytes for primitive scalars.
/// Returns `None` for variable-length primitives (`String`, `TypeTag`,
/// `vector<...>`) and non-primitives.
fn primitive_size_hint(tag: &TypeTag) -> Option<usize> {
    let TypeTag::Concrete {
        type_name,
        type_args,
        ..
    } = tag
    else {
        return None;
    };
    if !type_args.is_empty() {
        return None;
    }
    match type_name.as_str() {
        "u8" | "i8" | "bool" => Some(1),
        "u16" | "i16" => Some(2),
        "u32" | "i32" => Some(4),
        "u64" | "i64" => Some(8),
        "u128" | "i128" => Some(16),
        "Address" | "address" | "ObjectId" | "Hash32" | "UID" => Some(32),
        _ => None,
    }
}

/// Make `CodecError` reachable via the module without a top-level
/// re-export so callers that already `use bloom_objects::CodecError`
/// don't break.
#[allow(dead_code)]
fn _codec_error_type_alias_check(_: CodecError) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn prim(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    fn vector_of(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![prim(name)],
        }
    }

    #[test]
    fn u64_exact_length_ok() {
        assert_eq!(
            validate_canonical_bytes(&prim("u64"), &[0u8; 8]),
            ValidationOutcome::Ok
        );
    }

    #[test]
    fn u64_too_short_invalid() {
        assert!(validate_canonical_bytes(&prim("u64"), &[0u8; 4]).is_invalid());
    }

    #[test]
    fn u128_exact_length_ok() {
        assert_eq!(
            validate_canonical_bytes(&prim("u128"), &[0u8; 16]),
            ValidationOutcome::Ok
        );
    }

    #[test]
    fn u128_too_long_invalid() {
        assert!(validate_canonical_bytes(&prim("u128"), &[0u8; 17]).is_invalid());
    }

    #[test]
    fn object_id_must_be_32() {
        assert!(validate_canonical_bytes(&prim("ObjectId"), &[0u8; 31]).is_invalid());
        assert!(validate_canonical_bytes(&prim("ObjectId"), &[0u8; 32]).is_ok());
        assert!(validate_canonical_bytes(&prim("ObjectId"), &[0u8; 33]).is_invalid());
    }

    #[test]
    fn bool_only_zero_or_one() {
        assert!(validate_canonical_bytes(&prim("bool"), &[0]).is_ok());
        assert!(validate_canonical_bytes(&prim("bool"), &[1]).is_ok());
        assert!(validate_canonical_bytes(&prim("bool"), &[2]).is_invalid());
    }

    #[test]
    fn string_length_prefix_match() {
        let mut buf: Vec<u8> = vec![];
        // ULEB128 length = 5
        buf.push(5);
        buf.extend_from_slice(b"hello");
        assert!(validate_canonical_bytes(&prim("String"), &buf).is_ok());
    }

    #[test]
    fn string_length_prefix_mismatch_invalid() {
        let mut buf: Vec<u8> = vec![];
        buf.push(10); // claims 10 bytes
        buf.extend_from_slice(b"hi");
        assert!(validate_canonical_bytes(&prim("String"), &buf).is_invalid());
    }

    #[test]
    fn string_invalid_utf8() {
        let mut buf: Vec<u8> = vec![];
        buf.push(2);
        buf.extend_from_slice(&[0xFF, 0xFE]);
        assert!(validate_canonical_bytes(&prim("String"), &buf).is_invalid());
    }

    #[test]
    fn type_tag_roundtrip() {
        let t = prim("u64");
        let bytes = t.encode_canonical().unwrap();
        // Wire a TypeTag-typed Const value through the validator.
        assert!(validate_canonical_bytes(&prim("TypeTag"), &bytes).is_ok());
    }

    #[test]
    fn vector_u64_count_matches() {
        let mut buf: Vec<u8> = vec![];
        buf.push(2);
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&[0u8; 8]);
        assert!(validate_canonical_bytes(&vector_of("u64"), &buf).is_ok());
    }

    #[test]
    fn vector_u64_count_mismatch_invalid() {
        let mut buf: Vec<u8> = vec![];
        buf.push(3);
        buf.extend_from_slice(&[0u8; 8]); // only one element follows
        assert!(validate_canonical_bytes(&vector_of("u64"), &buf).is_invalid());
    }

    #[test]
    fn unknown_concrete_type_returns_unknown() {
        let custom = TypeTag::Concrete {
            petal_hash: [0xAB; 32],
            type_name: "Pool".to_string(),
            type_args: vec![],
        };
        assert_eq!(
            validate_canonical_bytes(&custom, &[1, 2, 3]),
            ValidationOutcome::Unknown
        );
    }

    #[test]
    fn generic_returns_unknown() {
        assert_eq!(
            validate_canonical_bytes(&TypeTag::Generic { idx: 0 }, &[1, 2, 3]),
            ValidationOutcome::Unknown
        );
    }

    #[test]
    fn external_returns_unknown() {
        assert_eq!(
            validate_canonical_bytes(&TypeTag::External { ref_idx: 0 }, &[1, 2, 3]),
            ValidationOutcome::Unknown
        );
    }
}
