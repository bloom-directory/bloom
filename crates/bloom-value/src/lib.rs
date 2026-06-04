//! Schema-driven canonical value codec for Bloom-native payloads.
//!
//! This crate owns the value wire format described by
//! `docs/superpowers/specs/2026-06-01-canonical-codec-and-type-system-design.md`.
//! It intentionally depends only on `bloom-objects` for type identity; manifest
//! crates and host/runtime crates provide [`Resolver`] implementations.

use std::borrow::Cow;

use bloom_objects::{BUILTIN_TYPE_HASH, TypeTag};
use serde_json::{Value as JsonValue, json};
use thiserror::Error;

/// Maximum bytes in an encoded ULEB128 `u64`.
pub const MAX_ULEB128_BYTES: usize = 10;
/// Default recursive value nesting bound.
pub const DEFAULT_MAX_VALUE_DEPTH: usize = 64;
/// Default schema expansion bound.
pub const DEFAULT_MAX_SCHEMA_DEPTH: usize = 64;
/// Default collection element bound.
pub const DEFAULT_MAX_COLLECTION_LEN: u64 = 1_000_000;

/// Runtime bounds for value encoding/decoding.
#[derive(Clone, Debug)]
pub struct CodecLimits {
    /// Maximum recursive value nodes.
    pub max_value_depth: usize,
    /// Maximum type-resolution recursion.
    pub max_schema_depth: usize,
    /// Maximum vector/map/set entries.
    pub max_collection_len: u64,
    /// Maximum bytes consumed by one value slot.
    pub max_value_bytes: usize,
}

impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            max_value_depth: DEFAULT_MAX_VALUE_DEPTH,
            max_schema_depth: DEFAULT_MAX_SCHEMA_DEPTH,
            max_collection_len: DEFAULT_MAX_COLLECTION_LEN,
            max_value_bytes: usize::MAX,
        }
    }
}

/// Errors from the canonical value codec.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValueCodecError {
    /// Buffer ended before the declared value was complete.
    #[error("unexpected eof: need {needed} bytes, have {available}")]
    UnexpectedEof {
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },
    /// Bytes remained after a top-level decode.
    #[error("trailing bytes after value decode: {0}")]
    TrailingBytes(usize),
    /// ULEB128 did not use minimal form.
    #[error("non-minimal uleb128 encoding")]
    NonMinimalUleb128,
    /// ULEB128 exceeded the 10-byte `u64` limit.
    #[error("uleb128 exceeds 10 bytes")]
    Uleb128TooLong,
    /// Numeric length/count exceeds a context bound.
    #[error("length/count {value} exceeds bound {max}")]
    LimitExceeded {
        /// Actual value.
        value: u64,
        /// Bound.
        max: u64,
    },
    /// Value byte length exceeded the caller-supplied cap.
    #[error("value byte length {value} exceeds byte cap {max}")]
    ByteLimitExceeded {
        /// Actual byte length.
        value: usize,
        /// Bound.
        max: usize,
    },
    /// Value nesting exceeded the configured recursion bound.
    #[error("value nesting depth exceeded")]
    ValueDepthExceeded,
    /// Schema expansion exceeded the configured recursion bound.
    #[error("schema resolution depth exceeded")]
    SchemaDepthExceeded,
    /// A boolean byte was not 0 or 1.
    #[error("invalid bool byte: {0}")]
    InvalidBool(u8),
    /// UTF-8 validation failed.
    #[error("invalid utf-8 string")]
    InvalidUtf8,
    /// Enum discriminant was outside the variant list.
    #[error("enum discriminant {index} out of range {variants}")]
    InvalidDiscriminant {
        /// Discriminant.
        index: u64,
        /// Variant count.
        variants: usize,
    },
    /// Type/value mismatch.
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// Expected shape.
        expected: &'static str,
        /// Actual value.
        got: &'static str,
    },
    /// Type could not be resolved.
    #[error("unresolved type {0}")]
    UnresolvedType(String),
    /// Built-in type arity was wrong.
    #[error("invalid builtin arity for {name}: expected {expected}, got {got}")]
    InvalidArity {
        /// Built-in name.
        name: String,
        /// Expected type-arg count.
        expected: usize,
        /// Actual type-arg count.
        got: usize,
    },
    /// Duplicate or unsorted map/set key.
    #[error("map/set keys are not strictly sorted by canonical bytes")]
    NonCanonicalKeyOrder,
    /// Non-empty collection of zero-sized values is rejected.
    #[error("non-empty collection of zero-sized values")]
    ZeroSizedCollection,
    /// JSON value does not match the declared type.
    #[error("json mismatch for {type_tag}: {reason}")]
    JsonMismatch {
        /// Type label.
        type_tag: String,
        /// Reason.
        reason: String,
    },
}

/// Resolved structural shape of a [`TypeTag`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeShape {
    /// Built-in scalar with zero type args.
    Scalar(ScalarKind),
    /// `bytes`.
    Bytes,
    /// `String`.
    String,
    /// Declared struct fields in canonical order.
    Struct(Vec<FieldShape>),
    /// Tuple elements in canonical order.
    Tuple(Vec<TypeTag>),
    /// Declared enum variants in canonical order.
    Enum(Vec<VariantShape>),
    /// `vector<T>`.
    Vector(TypeTag),
    /// `map<K, V>`.
    Map(TypeTag, TypeTag),
    /// `set<T>`.
    Set(TypeTag),
}

/// Built-in scalar kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScalarKind {
    /// `bool`.
    Bool,
    /// `u8`.
    U8,
    /// `u16`.
    U16,
    /// `u32`.
    U32,
    /// `u64`.
    U64,
    /// `u128`.
    U128,
    /// `Address`.
    Address,
    /// `ObjectId`.
    ObjectId,
    /// `Hash32`.
    Hash32,
    /// `UID`, encoded identically to `ObjectId`.
    Uid,
    /// `TypeTag`, encoded via the canonical recursive type-tag codec.
    TypeTag,
}

/// Struct field shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldShape {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: TypeTag,
}

/// Enum variant shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantShape {
    /// Variant name.
    pub name: String,
    /// Payload layout.
    pub fields: VariantFields,
}

/// Enum payload layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantFields {
    /// Unit variant.
    Unit,
    /// Tuple-style fields.
    Tuple(Vec<TypeTag>),
    /// Struct-style named fields.
    Struct(Vec<FieldShape>),
}

/// Resolver for user-defined type declarations and external/generic refs.
pub trait Resolver {
    /// Resolve `tag` to a structural shape. Built-ins are handled by this
    /// crate before this hook is called.
    fn resolve_shape(&self, tag: &TypeTag, depth: usize) -> Result<TypeShape, ValueCodecError>;
}

/// Resolver that knows only built-in types.
#[derive(Copy, Clone, Debug, Default)]
pub struct BuiltinResolver;

impl Resolver for BuiltinResolver {
    fn resolve_shape(&self, tag: &TypeTag, _depth: usize) -> Result<TypeShape, ValueCodecError> {
        builtin_shape(tag)?.ok_or_else(|| ValueCodecError::UnresolvedType(type_tag_label(tag)))
    }
}

/// Logical value used by reflective encode/decode and JSON projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// bool.
    Bool(bool),
    /// u8.
    U8(u8),
    /// u16.
    U16(u16),
    /// u32.
    U32(u32),
    /// u64.
    U64(u64),
    /// u128.
    U128(u128),
    /// Address/ObjectId/Hash32/UID 32-byte scalar.
    Bytes32([u8; 32]),
    /// Recursive Bloom type identity.
    TypeTag(TypeTag),
    /// Raw byte vector.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    String(String),
    /// Struct fields in declaration order.
    Struct(Vec<(String, Value)>),
    /// Tuple fields.
    Tuple(Vec<Value>),
    /// Enum variant by name plus projected payload.
    Enum {
        /// Variant index.
        index: u64,
        /// Variant name.
        name: String,
        /// Payload fields.
        fields: VariantValue,
    },
    /// Vector/set values.
    Seq(Vec<Value>),
    /// Map values in canonical order.
    Map(Vec<(Value, Value)>),
}

/// Enum payload value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantValue {
    /// Unit variant.
    Unit,
    /// Tuple payload.
    Tuple(Vec<Value>),
    /// Struct payload.
    Struct(Vec<(String, Value)>),
}

impl Value {
    fn kind_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::U8(_) => "u8",
            Value::U16(_) => "u16",
            Value::U32(_) => "u32",
            Value::U64(_) => "u64",
            Value::U128(_) => "u128",
            Value::Bytes32(_) => "bytes32",
            Value::TypeTag(_) => "TypeTag",
            Value::Bytes(_) => "bytes",
            Value::String(_) => "String",
            Value::Struct(_) => "struct",
            Value::Tuple(_) => "tuple",
            Value::Enum { .. } => "enum",
            Value::Seq(_) => "seq",
            Value::Map(_) => "map",
        }
    }
}

/// Construct a built-in `TypeTag`.
pub fn builtin_type(name: &str, type_args: Vec<TypeTag>) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: BUILTIN_TYPE_HASH,
        type_name: name.to_string(),
        type_args,
    }
}

/// Return a stable human label for a type tag.
pub fn type_tag_label(tag: &TypeTag) -> String {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => {
            let mut base = if *petal_hash == BUILTIN_TYPE_HASH {
                type_name.clone()
            } else {
                format!("{}::{}", hex::encode(petal_hash), type_name)
            };
            if !type_args.is_empty() {
                base.push('<');
                base.push_str(
                    &type_args
                        .iter()
                        .map(type_tag_label)
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                base.push('>');
            }
            base
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("external#{ref_idx}"),
    }
}

/// Encode a `u64` as minimal-form ULEB128.
pub fn write_uleb128(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Decode a minimal-form ULEB128 `u64`.
pub fn read_uleb128(input: &mut &[u8]) -> Result<u64, ValueCodecError> {
    let start_len = input.len();
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..MAX_ULEB128_BYTES {
        let byte = *input.first().ok_or(ValueCodecError::UnexpectedEof {
            needed: 1,
            available: 0,
        })?;
        *input = &input[1..];
        let low = (byte & 0x7f) as u64;
        if i == MAX_ULEB128_BYTES - 1 && (byte & 0x80 != 0 || low > 1) {
            return Err(ValueCodecError::Uleb128TooLong);
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
                    return Err(ValueCodecError::NonMinimalUleb128);
                }
            }
            return Ok(value);
        }
        shift += 7;
    }
    Err(ValueCodecError::Uleb128TooLong)
}

/// Encode a typed logical value.
pub fn encode_value(
    resolver: &impl Resolver,
    tag: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
) -> Result<Vec<u8>, ValueCodecError> {
    let mut out = Vec::new();
    encode_into(resolver, tag, value, limits, 0, &mut out)?;
    if out.len() > limits.max_value_bytes {
        return Err(ValueCodecError::ByteLimitExceeded {
            value: out.len(),
            max: limits.max_value_bytes,
        });
    }
    Ok(out)
}

/// Decode a typed value and reject trailing bytes.
pub fn decode_value(
    resolver: &impl Resolver,
    tag: &TypeTag,
    bytes: &[u8],
    limits: &CodecLimits,
) -> Result<Value, ValueCodecError> {
    if bytes.len() > limits.max_value_bytes {
        return Err(ValueCodecError::ByteLimitExceeded {
            value: bytes.len(),
            max: limits.max_value_bytes,
        });
    }
    let mut cursor = bytes;
    let value = decode_from(resolver, tag, &mut cursor, limits, 0)?;
    if !cursor.is_empty() {
        return Err(ValueCodecError::TrailingBytes(cursor.len()));
    }
    Ok(value)
}

/// Decode and immediately re-encode to validate canonical bytes.
pub fn validate_value_bytes(
    resolver: &impl Resolver,
    tag: &TypeTag,
    bytes: &[u8],
    limits: &CodecLimits,
) -> Result<(), ValueCodecError> {
    let value = decode_value(resolver, tag, bytes, limits)?;
    let encoded = encode_value(resolver, tag, &value, limits)?;
    if encoded == bytes {
        Ok(())
    } else {
        Err(ValueCodecError::NonMinimalUleb128)
    }
}

/// Decode bytes and project them to JSON using the stable Bloom JSON contract.
pub fn decode_json(
    resolver: &impl Resolver,
    tag: &TypeTag,
    bytes: &[u8],
    limits: &CodecLimits,
) -> Result<JsonValue, ValueCodecError> {
    let value = decode_value(resolver, tag, bytes, limits)?;
    project_json(resolver, tag, &value, limits, 0)
}

/// Encode JSON to canonical bytes for a declared type.
pub fn encode_json(
    resolver: &impl Resolver,
    tag: &TypeTag,
    json: &JsonValue,
    limits: &CodecLimits,
) -> Result<Vec<u8>, ValueCodecError> {
    let value = value_from_json(resolver, tag, json, limits, 0)?;
    encode_value(resolver, tag, &value, limits)
}

fn encode_into(
    resolver: &impl Resolver,
    tag: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    check_depth(depth, limits)?;
    let shape = resolve_shape(resolver, tag, limits, depth)?;
    match shape {
        TypeShape::Scalar(kind) => encode_scalar(kind, value, out),
        TypeShape::Bytes => match value {
            Value::Bytes(bytes) => {
                write_len(bytes.len(), limits.max_value_bytes, out)?;
                out.extend_from_slice(bytes);
                Ok(())
            }
            other => type_mismatch("bytes", other),
        },
        TypeShape::String => match value {
            Value::String(s) => {
                write_len(s.len(), limits.max_value_bytes, out)?;
                out.extend_from_slice(s.as_bytes());
                Ok(())
            }
            other => type_mismatch("String", other),
        },
        TypeShape::Struct(fields) => {
            let Value::Struct(values) = value else {
                return type_mismatch("struct", value);
            };
            if fields.len() != values.len() {
                return Err(ValueCodecError::TypeMismatch {
                    expected: "struct field count",
                    got: "different field count",
                });
            }
            for (field, (name, v)) in fields.iter().zip(values.iter()) {
                if field.name != *name {
                    return Err(ValueCodecError::JsonMismatch {
                        type_tag: type_tag_label(tag),
                        reason: format!("expected field {}", field.name),
                    });
                }
                encode_into(resolver, &field.ty, v, limits, depth + 1, out)?;
            }
            Ok(())
        }
        TypeShape::Tuple(elems) => {
            let Value::Tuple(values) = value else {
                return type_mismatch("tuple", value);
            };
            if elems.len() != values.len() {
                return Err(ValueCodecError::TypeMismatch {
                    expected: "tuple arity",
                    got: "different tuple arity",
                });
            }
            for (elem, v) in elems.iter().zip(values) {
                encode_into(resolver, elem, v, limits, depth + 1, out)?;
            }
            Ok(())
        }
        TypeShape::Enum(variants) => {
            encode_enum(resolver, tag, &variants, value, limits, depth, out)
        }
        TypeShape::Vector(elem) => encode_seq(resolver, &elem, value, limits, depth, out),
        TypeShape::Set(elem) => encode_set(resolver, &elem, value, limits, depth, out),
        TypeShape::Map(k, v) => encode_map(resolver, &k, &v, value, limits, depth, out),
    }
}

fn decode_from(
    resolver: &impl Resolver,
    tag: &TypeTag,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    check_depth(depth, limits)?;
    let shape = resolve_shape(resolver, tag, limits, depth)?;
    match shape {
        TypeShape::Scalar(kind) => decode_scalar(kind, input),
        TypeShape::Bytes => {
            let len = read_len(input, limits)?;
            Ok(Value::Bytes(take(input, len)?.to_vec()))
        }
        TypeShape::String => {
            let len = read_len(input, limits)?;
            let bytes = take(input, len)?;
            let s = std::str::from_utf8(bytes).map_err(|_| ValueCodecError::InvalidUtf8)?;
            Ok(Value::String(s.to_string()))
        }
        TypeShape::Struct(fields) => {
            let mut values = Vec::with_capacity(fields.len());
            for field in fields {
                let v = decode_from(resolver, &field.ty, input, limits, depth + 1)?;
                values.push((field.name, v));
            }
            Ok(Value::Struct(values))
        }
        TypeShape::Tuple(elems) => {
            let mut values = Vec::with_capacity(elems.len());
            for elem in elems {
                values.push(decode_from(resolver, &elem, input, limits, depth + 1)?);
            }
            Ok(Value::Tuple(values))
        }
        TypeShape::Enum(variants) => decode_enum(resolver, variants, input, limits, depth),
        TypeShape::Vector(elem) => decode_seq(resolver, &elem, input, limits, depth),
        TypeShape::Set(elem) => decode_set(resolver, &elem, input, limits, depth),
        TypeShape::Map(k, v) => decode_map(resolver, &k, &v, input, limits, depth),
    }
}

fn resolve_shape(
    resolver: &impl Resolver,
    tag: &TypeTag,
    limits: &CodecLimits,
    depth: usize,
) -> Result<TypeShape, ValueCodecError> {
    if depth >= limits.max_schema_depth {
        return Err(ValueCodecError::SchemaDepthExceeded);
    }
    if let Some(shape) = builtin_shape(tag)? {
        Ok(shape)
    } else {
        resolver.resolve_shape(tag, depth + 1)
    }
}

fn builtin_shape(tag: &TypeTag) -> Result<Option<TypeShape>, ValueCodecError> {
    let TypeTag::Concrete {
        petal_hash,
        type_name,
        type_args,
    } = tag
    else {
        return Ok(None);
    };
    if *petal_hash != BUILTIN_TYPE_HASH {
        return Ok(None);
    }
    let expect = |expected: usize| {
        if type_args.len() == expected {
            Ok(())
        } else {
            Err(ValueCodecError::InvalidArity {
                name: type_name.clone(),
                expected,
                got: type_args.len(),
            })
        }
    };
    Ok(match type_name.as_str() {
        "bool" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::Bool))
        }
        "u8" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::U8))
        }
        "u16" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::U16))
        }
        "u32" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::U32))
        }
        "u64" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::U64))
        }
        "u128" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::U128))
        }
        "Address" | "address" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::Address))
        }
        "ObjectId" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::ObjectId))
        }
        "Hash32" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::Hash32))
        }
        "UID" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::Uid))
        }
        "TypeTag" => {
            expect(0)?;
            Some(TypeShape::Scalar(ScalarKind::TypeTag))
        }
        "bytes" => {
            expect(0)?;
            Some(TypeShape::Bytes)
        }
        "String" | "string" => {
            expect(0)?;
            Some(TypeShape::String)
        }
        "vector" => {
            expect(1)?;
            Some(TypeShape::Vector(type_args[0].clone()))
        }
        "set" => {
            expect(1)?;
            Some(TypeShape::Set(type_args[0].clone()))
        }
        "map" => {
            expect(2)?;
            Some(TypeShape::Map(type_args[0].clone(), type_args[1].clone()))
        }
        "tuple" => Some(TypeShape::Tuple(type_args.clone())),
        "Option" => {
            expect(1)?;
            Some(TypeShape::Enum(vec![
                VariantShape {
                    name: "None".to_string(),
                    fields: VariantFields::Unit,
                },
                VariantShape {
                    name: "Some".to_string(),
                    fields: VariantFields::Tuple(vec![type_args[0].clone()]),
                },
            ]))
        }
        "Result" => {
            expect(2)?;
            Some(TypeShape::Enum(vec![
                VariantShape {
                    name: "Ok".to_string(),
                    fields: VariantFields::Tuple(vec![type_args[0].clone()]),
                },
                VariantShape {
                    name: "Err".to_string(),
                    fields: VariantFields::Tuple(vec![type_args[1].clone()]),
                },
            ]))
        }
        _ => None,
    })
}

fn encode_scalar(
    kind: ScalarKind,
    value: &Value,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    match (kind, value) {
        (ScalarKind::Bool, Value::Bool(v)) => out.push(u8::from(*v)),
        (ScalarKind::U8, Value::U8(v)) => out.push(*v),
        (ScalarKind::U16, Value::U16(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ScalarKind::U32, Value::U32(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ScalarKind::U64, Value::U64(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ScalarKind::U128, Value::U128(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (
            ScalarKind::Address | ScalarKind::ObjectId | ScalarKind::Hash32 | ScalarKind::Uid,
            Value::Bytes32(v),
        ) => out.extend_from_slice(v),
        (ScalarKind::TypeTag, Value::TypeTag(v)) => v
            .encode_into(out)
            .map_err(|e| ValueCodecError::UnresolvedType(e.to_string()))?,
        (ScalarKind::Bool, other) => return type_mismatch("bool", other),
        (ScalarKind::U8, other) => return type_mismatch("u8", other),
        (ScalarKind::U16, other) => return type_mismatch("u16", other),
        (ScalarKind::U32, other) => return type_mismatch("u32", other),
        (ScalarKind::U64, other) => return type_mismatch("u64", other),
        (ScalarKind::U128, other) => return type_mismatch("u128", other),
        (ScalarKind::TypeTag, other) => return type_mismatch("TypeTag", other),
        (_, other) => return type_mismatch("bytes32", other),
    }
    Ok(())
}

fn decode_scalar(kind: ScalarKind, input: &mut &[u8]) -> Result<Value, ValueCodecError> {
    match kind {
        ScalarKind::Bool => match take(input, 1)?[0] {
            0 => Ok(Value::Bool(false)),
            1 => Ok(Value::Bool(true)),
            other => Err(ValueCodecError::InvalidBool(other)),
        },
        ScalarKind::U8 => Ok(Value::U8(take(input, 1)?[0])),
        ScalarKind::U16 => Ok(Value::U16(u16::from_be_bytes(take_array(input)?))),
        ScalarKind::U32 => Ok(Value::U32(u32::from_be_bytes(take_array(input)?))),
        ScalarKind::U64 => Ok(Value::U64(u64::from_be_bytes(take_array(input)?))),
        ScalarKind::U128 => Ok(Value::U128(u128::from_be_bytes(take_array(input)?))),
        ScalarKind::Address | ScalarKind::ObjectId | ScalarKind::Hash32 | ScalarKind::Uid => {
            Ok(Value::Bytes32(take_array(input)?))
        }
        ScalarKind::TypeTag => TypeTag::decode_from(input, 0)
            .map(Value::TypeTag)
            .map_err(|e| ValueCodecError::UnresolvedType(e.to_string())),
    }
}

fn encode_enum(
    resolver: &impl Resolver,
    tag: &TypeTag,
    variants: &[VariantShape],
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    let Value::Enum {
        index,
        name,
        fields,
    } = value
    else {
        return type_mismatch("enum", value);
    };
    let idx = usize::try_from(*index).map_err(|_| ValueCodecError::InvalidDiscriminant {
        index: *index,
        variants: variants.len(),
    })?;
    let Some(variant) = variants.get(idx) else {
        return Err(ValueCodecError::InvalidDiscriminant {
            index: *index,
            variants: variants.len(),
        });
    };
    if variant.name != *name {
        return Err(ValueCodecError::JsonMismatch {
            type_tag: type_tag_label(tag),
            reason: format!("expected variant {}", variant.name),
        });
    }
    write_uleb128(*index, out);
    encode_variant_fields(resolver, &variant.fields, fields, limits, depth, out)
}

fn decode_enum(
    resolver: &impl Resolver,
    variants: Vec<VariantShape>,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    let index = read_uleb128(input)?;
    let idx = usize::try_from(index).map_err(|_| ValueCodecError::InvalidDiscriminant {
        index,
        variants: variants.len(),
    })?;
    let Some(variant) = variants.get(idx) else {
        return Err(ValueCodecError::InvalidDiscriminant {
            index,
            variants: variants.len(),
        });
    };
    let fields = decode_variant_fields(resolver, &variant.fields, input, limits, depth)?;
    Ok(Value::Enum {
        index,
        name: variant.name.clone(),
        fields,
    })
}

fn encode_variant_fields(
    resolver: &impl Resolver,
    shape: &VariantFields,
    value: &VariantValue,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    match (shape, value) {
        (VariantFields::Unit, VariantValue::Unit) => Ok(()),
        (VariantFields::Tuple(types), VariantValue::Tuple(values)) => {
            if types.len() != values.len() {
                return Err(ValueCodecError::TypeMismatch {
                    expected: "variant tuple arity",
                    got: "different variant tuple arity",
                });
            }
            for (ty, v) in types.iter().zip(values) {
                encode_into(resolver, ty, v, limits, depth + 1, out)?;
            }
            Ok(())
        }
        (VariantFields::Struct(fields), VariantValue::Struct(values)) => {
            if fields.len() != values.len() {
                return Err(ValueCodecError::TypeMismatch {
                    expected: "variant struct field count",
                    got: "different variant struct field count",
                });
            }
            for (field, (name, v)) in fields.iter().zip(values) {
                if field.name != *name {
                    return Err(ValueCodecError::JsonMismatch {
                        type_tag: field.name.clone(),
                        reason: "variant field name mismatch".to_string(),
                    });
                }
                encode_into(resolver, &field.ty, v, limits, depth + 1, out)?;
            }
            Ok(())
        }
        (_, other) => Err(ValueCodecError::TypeMismatch {
            expected: "variant payload",
            got: match other {
                VariantValue::Unit => "unit",
                VariantValue::Tuple(_) => "tuple",
                VariantValue::Struct(_) => "struct",
            },
        }),
    }
}

fn decode_variant_fields(
    resolver: &impl Resolver,
    shape: &VariantFields,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<VariantValue, ValueCodecError> {
    match shape {
        VariantFields::Unit => Ok(VariantValue::Unit),
        VariantFields::Tuple(types) => {
            let mut out = Vec::with_capacity(types.len());
            for ty in types {
                out.push(decode_from(resolver, ty, input, limits, depth + 1)?);
            }
            Ok(VariantValue::Tuple(out))
        }
        VariantFields::Struct(fields) => {
            let mut out = Vec::with_capacity(fields.len());
            for field in fields {
                out.push((
                    field.name.clone(),
                    decode_from(resolver, &field.ty, input, limits, depth + 1)?,
                ));
            }
            Ok(VariantValue::Struct(out))
        }
    }
}

fn encode_seq(
    resolver: &impl Resolver,
    elem: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    let Value::Seq(values) = value else {
        return type_mismatch("vector", value);
    };
    write_count(values.len(), limits, out)?;
    reject_zero_sized_non_empty(resolver, elem, values.len(), limits, depth)?;
    for v in values {
        encode_into(resolver, elem, v, limits, depth + 1, out)?;
    }
    Ok(())
}

fn decode_seq(
    resolver: &impl Resolver,
    elem: &TypeTag,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    let len = read_count(input, limits)?;
    reject_zero_sized_non_empty(resolver, elem, len, limits, depth)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(decode_from(resolver, elem, input, limits, depth + 1)?);
    }
    Ok(Value::Seq(out))
}

fn encode_set(
    resolver: &impl Resolver,
    elem: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    let Value::Seq(values) = value else {
        return type_mismatch("set", value);
    };
    write_count(values.len(), limits, out)?;
    reject_zero_sized_non_empty(resolver, elem, values.len(), limits, depth)?;
    let mut prev: Option<Vec<u8>> = None;
    for v in values {
        let key = encode_value(resolver, elem, v, limits)?;
        check_key_order(&mut prev, &key)?;
        out.extend_from_slice(&key);
    }
    Ok(())
}

fn decode_set(
    resolver: &impl Resolver,
    elem: &TypeTag,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    let len = read_count(input, limits)?;
    reject_zero_sized_non_empty(resolver, elem, len, limits, depth)?;
    let mut out = Vec::with_capacity(len);
    let mut prev = None;
    for _ in 0..len {
        let v = decode_from(resolver, elem, input, limits, depth + 1)?;
        let key = encode_value(resolver, elem, &v, limits)?;
        check_key_order(&mut prev, &key)?;
        out.push(v);
    }
    Ok(Value::Seq(out))
}

fn encode_map(
    resolver: &impl Resolver,
    key_ty: &TypeTag,
    value_ty: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ValueCodecError> {
    let Value::Map(entries) = value else {
        return type_mismatch("map", value);
    };
    write_count(entries.len(), limits, out)?;
    reject_zero_sized_non_empty(resolver, key_ty, entries.len(), limits, depth)?;
    let mut prev = None;
    for (k, v) in entries {
        let key = encode_value(resolver, key_ty, k, limits)?;
        check_key_order(&mut prev, &key)?;
        out.extend_from_slice(&key);
        encode_into(resolver, value_ty, v, limits, depth + 1, out)?;
    }
    Ok(())
}

fn decode_map(
    resolver: &impl Resolver,
    key_ty: &TypeTag,
    value_ty: &TypeTag,
    input: &mut &[u8],
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    let len = read_count(input, limits)?;
    reject_zero_sized_non_empty(resolver, key_ty, len, limits, depth)?;
    let mut out = Vec::with_capacity(len);
    let mut prev = None;
    for _ in 0..len {
        let key_value = decode_from(resolver, key_ty, input, limits, depth + 1)?;
        let key = encode_value(resolver, key_ty, &key_value, limits)?;
        check_key_order(&mut prev, &key)?;
        let val = decode_from(resolver, value_ty, input, limits, depth + 1)?;
        out.push((key_value, val));
    }
    Ok(Value::Map(out))
}

fn project_json(
    resolver: &impl Resolver,
    tag: &TypeTag,
    value: &Value,
    limits: &CodecLimits,
    depth: usize,
) -> Result<JsonValue, ValueCodecError> {
    check_depth(depth, limits)?;
    let shape = resolve_shape(resolver, tag, limits, depth)?;
    match (shape, value) {
        (TypeShape::Scalar(ScalarKind::Bool), Value::Bool(v)) => Ok(json!(v)),
        (TypeShape::Scalar(ScalarKind::U8), Value::U8(v)) => Ok(json!(v)),
        (TypeShape::Scalar(ScalarKind::U16), Value::U16(v)) => Ok(json!(v)),
        (TypeShape::Scalar(ScalarKind::U32), Value::U32(v)) => Ok(json!(v)),
        (TypeShape::Scalar(ScalarKind::U64), Value::U64(v)) => Ok(json!(v.to_string())),
        (TypeShape::Scalar(ScalarKind::U128), Value::U128(v)) => Ok(json!(v.to_string())),
        (
            TypeShape::Scalar(
                ScalarKind::Address | ScalarKind::ObjectId | ScalarKind::Hash32 | ScalarKind::Uid,
            ),
            Value::Bytes32(v),
        ) => Ok(json!(hex::encode(v))),
        (TypeShape::Scalar(ScalarKind::TypeTag), Value::TypeTag(v)) => {
            Ok(json!(hex::encode(v.encode_canonical().map_err(|e| {
                ValueCodecError::UnresolvedType(e.to_string())
            })?)))
        }
        (TypeShape::Bytes, Value::Bytes(v)) => Ok(json!(hex::encode(v))),
        (TypeShape::String, Value::String(v)) => Ok(json!(v)),
        (TypeShape::Struct(fields), Value::Struct(values)) => {
            let mut obj = serde_json::Map::new();
            for (field, (_, v)) in fields.iter().zip(values) {
                obj.insert(
                    field.name.clone(),
                    project_json(resolver, &field.ty, v, limits, depth + 1)?,
                );
            }
            Ok(JsonValue::Object(obj))
        }
        (TypeShape::Tuple(elems), Value::Tuple(values)) => elems
            .iter()
            .zip(values)
            .map(|(ty, v)| project_json(resolver, ty, v, limits, depth + 1))
            .collect(),
        (
            TypeShape::Enum(variants),
            Value::Enum {
                index,
                name,
                fields,
            },
        ) => project_enum_json(resolver, &variants, *index, name, fields, limits, depth),
        (TypeShape::Vector(elem) | TypeShape::Set(elem), Value::Seq(values)) => values
            .iter()
            .map(|v| project_json(resolver, &elem, v, limits, depth + 1))
            .collect(),
        (TypeShape::Map(k, v), Value::Map(entries)) => entries
            .iter()
            .map(|(key, val)| {
                Ok(json!([
                    project_json(resolver, &k, key, limits, depth + 1)?,
                    project_json(resolver, &v, val, limits, depth + 1)?
                ]))
            })
            .collect(),
        (_, other) => type_mismatch("json projection shape", other),
    }
}

fn project_enum_json(
    resolver: &impl Resolver,
    variants: &[VariantShape],
    index: u64,
    name: &str,
    fields: &VariantValue,
    limits: &CodecLimits,
    depth: usize,
) -> Result<JsonValue, ValueCodecError> {
    let variant = variants
        .get(index as usize)
        .ok_or(ValueCodecError::InvalidDiscriminant {
            index,
            variants: variants.len(),
        })?;
    if variant.name != name {
        return Err(ValueCodecError::JsonMismatch {
            type_tag: name.to_string(),
            reason: format!("expected variant {}", variant.name),
        });
    }
    if variants.len() == 2 && variants[0].name == "None" && variants[1].name == "Some" {
        return match fields {
            VariantValue::Unit if index == 0 => Ok(JsonValue::Null),
            VariantValue::Tuple(values) if index == 1 && values.len() == 1 => {
                let VariantFields::Tuple(types) = &variant.fields else {
                    unreachable!("builtin Option Some is tuple")
                };
                let payload = project_json(resolver, &types[0], &values[0], limits, depth + 1)?;
                if option_payload_needs_explicit_some(&payload) {
                    Ok(json!({ "Some": payload }))
                } else {
                    Ok(payload)
                }
            }
            _ => Err(ValueCodecError::JsonMismatch {
                type_tag: "Option".to_string(),
                reason: "invalid Option payload".to_string(),
            }),
        };
    }
    let payload = match (&variant.fields, fields) {
        (VariantFields::Unit, VariantValue::Unit) => return Ok(json!(name)),
        (VariantFields::Tuple(types), VariantValue::Tuple(values)) => {
            if values.len() == 1 {
                project_json(resolver, &types[0], &values[0], limits, depth + 1)?
            } else {
                JsonValue::Array(
                    types
                        .iter()
                        .zip(values)
                        .map(|(ty, v)| project_json(resolver, ty, v, limits, depth + 1))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
        }
        (VariantFields::Struct(fields), VariantValue::Struct(values)) => {
            let mut obj = serde_json::Map::new();
            for (field, (_, v)) in fields.iter().zip(values) {
                obj.insert(
                    field.name.clone(),
                    project_json(resolver, &field.ty, v, limits, depth + 1)?,
                );
            }
            JsonValue::Object(obj)
        }
        _ => {
            return Err(ValueCodecError::JsonMismatch {
                type_tag: name.to_string(),
                reason: "variant payload shape mismatch".to_string(),
            });
        }
    };
    Ok(json!({ name: payload }))
}

fn option_payload_needs_explicit_some(payload: &JsonValue) -> bool {
    payload.is_null()
        || payload
            .as_object()
            .filter(|obj| obj.len() == 1)
            .and_then(|obj| obj.keys().next())
            .is_some_and(|key| key == "Some" || key == "None")
}

fn value_from_json(
    resolver: &impl Resolver,
    tag: &TypeTag,
    json: &JsonValue,
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    check_depth(depth, limits)?;
    let shape = resolve_shape(resolver, tag, limits, depth)?;
    match shape {
        TypeShape::Scalar(kind) => scalar_from_json(tag, kind, json),
        TypeShape::Bytes => Ok(Value::Bytes(hex_from_json(tag, json)?)),
        TypeShape::String => Ok(Value::String(
            json.as_str()
                .ok_or_else(|| json_mismatch(tag, "expected string"))?
                .to_string(),
        )),
        TypeShape::Struct(fields) => {
            let obj = json
                .as_object()
                .ok_or_else(|| json_mismatch(tag, "expected object"))?;
            if let Some(unknown) = obj
                .keys()
                .find(|key| !fields.iter().any(|field| field.name == **key))
            {
                return Err(json_mismatch(tag, &format!("unknown field {unknown}")));
            }
            let mut values = Vec::with_capacity(fields.len());
            for field in fields {
                let field_json = obj
                    .get(&field.name)
                    .ok_or_else(|| json_mismatch(tag, &format!("missing field {}", field.name)))?;
                values.push((
                    field.name,
                    value_from_json(resolver, &field.ty, field_json, limits, depth + 1)?,
                ));
            }
            Ok(Value::Struct(values))
        }
        TypeShape::Tuple(elems) => {
            let arr = json
                .as_array()
                .ok_or_else(|| json_mismatch(tag, "expected array"))?;
            if elems.len() != arr.len() {
                return Err(json_mismatch(tag, "tuple arity mismatch"));
            }
            Ok(Value::Tuple(
                elems
                    .iter()
                    .zip(arr)
                    .map(|(ty, v)| value_from_json(resolver, ty, v, limits, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        }
        TypeShape::Enum(variants) => enum_from_json(resolver, tag, variants, json, limits, depth),
        TypeShape::Vector(elem) | TypeShape::Set(elem) => {
            let arr = json
                .as_array()
                .ok_or_else(|| json_mismatch(tag, "expected array"))?;
            Ok(Value::Seq(
                arr.iter()
                    .map(|v| value_from_json(resolver, &elem, v, limits, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        }
        TypeShape::Map(k, v) => {
            let arr = json
                .as_array()
                .ok_or_else(|| json_mismatch(tag, "expected array of [key,value]"))?;
            let mut entries = Vec::with_capacity(arr.len());
            for entry in arr {
                let pair = entry
                    .as_array()
                    .filter(|p| p.len() == 2)
                    .ok_or_else(|| json_mismatch(tag, "expected [key,value] entry"))?;
                entries.push((
                    value_from_json(resolver, &k, &pair[0], limits, depth + 1)?,
                    value_from_json(resolver, &v, &pair[1], limits, depth + 1)?,
                ));
            }
            Ok(Value::Map(entries))
        }
    }
}

fn scalar_from_json(
    tag: &TypeTag,
    kind: ScalarKind,
    json: &JsonValue,
) -> Result<Value, ValueCodecError> {
    match kind {
        ScalarKind::Bool => json
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| json_mismatch(tag, "expected bool")),
        ScalarKind::U8 => Ok(Value::U8(u64_json(tag, json, u8::MAX as u64)? as u8)),
        ScalarKind::U16 => Ok(Value::U16(u64_json(tag, json, u16::MAX as u64)? as u16)),
        ScalarKind::U32 => Ok(Value::U32(u64_json(tag, json, u32::MAX as u64)? as u32)),
        ScalarKind::U64 => Ok(Value::U64(u64_json(tag, json, u64::MAX)?)),
        ScalarKind::U128 => Ok(Value::U128(u128_json(tag, json)?)),
        ScalarKind::Address | ScalarKind::ObjectId | ScalarKind::Hash32 | ScalarKind::Uid => {
            let bytes = hex_from_json(tag, json)?;
            if bytes.len() != 32 {
                return Err(json_mismatch(tag, "expected 32-byte hex"));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Value::Bytes32(out))
        }
        ScalarKind::TypeTag => type_tag_from_json(tag, json)
            .map(Value::TypeTag)
            .map_err(|e| json_mismatch(tag, &format!("invalid TypeTag: {e}"))),
    }
}

fn enum_from_json(
    resolver: &impl Resolver,
    tag: &TypeTag,
    variants: Vec<VariantShape>,
    json: &JsonValue,
    limits: &CodecLimits,
    depth: usize,
) -> Result<Value, ValueCodecError> {
    if variants.len() == 2 && variants[0].name == "None" && variants[1].name == "Some" {
        if json.is_null() || explicit_option_none(json)? {
            return Ok(Value::Enum {
                index: 0,
                name: "None".to_string(),
                fields: VariantValue::Unit,
            });
        }
        let VariantFields::Tuple(types) = &variants[1].fields else {
            unreachable!("builtin Option Some is tuple")
        };
        let payload = explicit_option_some(json).unwrap_or(json);
        return Ok(Value::Enum {
            index: 1,
            name: "Some".to_string(),
            fields: VariantValue::Tuple(vec![value_from_json(
                resolver,
                &types[0],
                payload,
                limits,
                depth + 1,
            )?]),
        });
    }
    if let Some(s) = json.as_str() {
        let (idx, variant) = find_variant(&variants, s, tag)?;
        if !matches!(variant.fields, VariantFields::Unit) {
            return Err(json_mismatch(tag, "variant requires payload"));
        }
        return Ok(Value::Enum {
            index: idx as u64,
            name: variant.name.clone(),
            fields: VariantValue::Unit,
        });
    }
    let obj = json
        .as_object()
        .filter(|o| o.len() == 1)
        .ok_or_else(|| json_mismatch(tag, "expected enum variant object"))?;
    let (name, payload) = obj.iter().next().expect("len checked");
    let (idx, variant) = find_variant(&variants, name, tag)?;
    let fields = match &variant.fields {
        VariantFields::Unit => {
            if !(payload.is_null() || payload.as_object().is_some_and(serde_json::Map::is_empty)) {
                return Err(json_mismatch(
                    tag,
                    "unit variant payload must be null or empty",
                ));
            }
            VariantValue::Unit
        }
        VariantFields::Tuple(types) => {
            if types.len() == 1 {
                VariantValue::Tuple(vec![value_from_json(
                    resolver,
                    &types[0],
                    payload,
                    limits,
                    depth + 1,
                )?])
            } else {
                let arr = payload
                    .as_array()
                    .ok_or_else(|| json_mismatch(tag, "expected tuple variant array"))?;
                if arr.len() != types.len() {
                    return Err(json_mismatch(tag, "tuple variant arity mismatch"));
                }
                VariantValue::Tuple(
                    types
                        .iter()
                        .zip(arr)
                        .map(|(ty, v)| value_from_json(resolver, ty, v, limits, depth + 1))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
        }
        VariantFields::Struct(fields) => {
            let obj = payload
                .as_object()
                .ok_or_else(|| json_mismatch(tag, "expected struct variant object"))?;
            if let Some(unknown) = obj
                .keys()
                .find(|key| !fields.iter().any(|field| field.name == **key))
            {
                return Err(json_mismatch(
                    tag,
                    &format!("unknown variant field {unknown}"),
                ));
            }
            VariantValue::Struct(
                fields
                    .iter()
                    .map(|field| {
                        let field_json = obj.get(&field.name).ok_or_else(|| {
                            json_mismatch(tag, &format!("missing field {}", field.name))
                        })?;
                        Ok((
                            field.name.clone(),
                            value_from_json(resolver, &field.ty, field_json, limits, depth + 1)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
    };
    Ok(Value::Enum {
        index: idx as u64,
        name: variant.name.clone(),
        fields,
    })
}

fn explicit_option_some(json: &JsonValue) -> Option<&JsonValue> {
    let obj = json.as_object().filter(|obj| obj.len() == 1)?;
    obj.get("Some")
}

fn explicit_option_none(json: &JsonValue) -> Result<bool, ValueCodecError> {
    let Some(obj) = json.as_object().filter(|obj| obj.len() == 1) else {
        return Ok(false);
    };
    let Some(payload) = obj.get("None") else {
        return Ok(false);
    };
    if payload.is_null() || payload.as_object().is_some_and(serde_json::Map::is_empty) {
        Ok(true)
    } else {
        Err(ValueCodecError::JsonMismatch {
            type_tag: "Option".to_string(),
            reason: "None payload must be null or empty".to_string(),
        })
    }
}

fn find_variant<'a>(
    variants: &'a [VariantShape],
    name: &str,
    tag: &TypeTag,
) -> Result<(usize, &'a VariantShape), ValueCodecError> {
    variants
        .iter()
        .enumerate()
        .find(|(_, variant)| variant.name == name)
        .ok_or_else(|| json_mismatch(tag, "unknown enum variant"))
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], ValueCodecError> {
    if input.len() < n {
        return Err(ValueCodecError::UnexpectedEof {
            needed: n,
            available: input.len(),
        });
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], ValueCodecError> {
    let bytes = take(input, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn write_len(len: usize, max: usize, out: &mut Vec<u8>) -> Result<(), ValueCodecError> {
    if len > max {
        return Err(ValueCodecError::ByteLimitExceeded { value: len, max });
    }
    write_uleb128(len as u64, out);
    Ok(())
}

fn read_len(input: &mut &[u8], limits: &CodecLimits) -> Result<usize, ValueCodecError> {
    let len = read_uleb128(input)?;
    if len > limits.max_value_bytes as u64 {
        return Err(ValueCodecError::ByteLimitExceeded {
            value: len as usize,
            max: limits.max_value_bytes,
        });
    }
    if len > input.len() as u64 {
        return Err(ValueCodecError::UnexpectedEof {
            needed: len as usize,
            available: input.len(),
        });
    }
    usize::try_from(len).map_err(|_| ValueCodecError::LimitExceeded {
        value: len,
        max: usize::MAX as u64,
    })
}

fn write_count(len: usize, limits: &CodecLimits, out: &mut Vec<u8>) -> Result<(), ValueCodecError> {
    let len_u64 = len as u64;
    if len_u64 > limits.max_collection_len {
        return Err(ValueCodecError::LimitExceeded {
            value: len_u64,
            max: limits.max_collection_len,
        });
    }
    write_uleb128(len_u64, out);
    Ok(())
}

fn read_count(input: &mut &[u8], limits: &CodecLimits) -> Result<usize, ValueCodecError> {
    let len = read_uleb128(input)?;
    if len > limits.max_collection_len {
        return Err(ValueCodecError::LimitExceeded {
            value: len,
            max: limits.max_collection_len,
        });
    }
    usize::try_from(len).map_err(|_| ValueCodecError::LimitExceeded {
        value: len,
        max: usize::MAX as u64,
    })
}

fn check_depth(depth: usize, limits: &CodecLimits) -> Result<(), ValueCodecError> {
    if depth >= limits.max_value_depth {
        Err(ValueCodecError::ValueDepthExceeded)
    } else {
        Ok(())
    }
}

fn check_key_order(prev: &mut Option<Vec<u8>>, current: &[u8]) -> Result<(), ValueCodecError> {
    if let Some(prev) = prev
        && prev.as_slice() >= current
    {
        return Err(ValueCodecError::NonCanonicalKeyOrder);
    }
    *prev = Some(current.to_vec());
    Ok(())
}

fn reject_zero_sized_non_empty(
    resolver: &impl Resolver,
    elem: &TypeTag,
    len: impl TryInto<u64>,
    limits: &CodecLimits,
    depth: usize,
) -> Result<(), ValueCodecError> {
    let len = len.try_into().unwrap_or(u64::MAX);
    if len != 0 && is_zero_sized(resolver, elem, limits, depth + 1)? {
        Err(ValueCodecError::ZeroSizedCollection)
    } else {
        Ok(())
    }
}

fn is_zero_sized(
    resolver: &impl Resolver,
    tag: &TypeTag,
    limits: &CodecLimits,
    depth: usize,
) -> Result<bool, ValueCodecError> {
    check_depth(depth, limits)?;
    match resolve_shape(resolver, tag, limits, depth)? {
        TypeShape::Tuple(elems) => elems
            .iter()
            .map(|t| is_zero_sized(resolver, t, limits, depth + 1))
            .try_fold(true, |acc, item| item.map(|x| acc && x)),
        TypeShape::Struct(fields) => fields
            .iter()
            .map(|f| is_zero_sized(resolver, &f.ty, limits, depth + 1))
            .try_fold(true, |acc, item| item.map(|x| acc && x)),
        TypeShape::Enum(_) => Ok(false),
        _ => Ok(false),
    }
}

fn type_mismatch<T>(expected: &'static str, got: &Value) -> Result<T, ValueCodecError> {
    Err(ValueCodecError::TypeMismatch {
        expected,
        got: got.kind_name(),
    })
}

fn json_mismatch(tag: &TypeTag, reason: &str) -> ValueCodecError {
    ValueCodecError::JsonMismatch {
        type_tag: type_tag_label(tag),
        reason: reason.to_string(),
    }
}

fn u64_json(tag: &TypeTag, value: &JsonValue, max: u64) -> Result<u64, ValueCodecError> {
    let parsed = match value {
        JsonValue::Number(n) => n.as_u64(),
        JsonValue::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| json_mismatch(tag, "expected unsigned integer"))?;
    if parsed > max {
        return Err(json_mismatch(tag, "integer out of range"));
    }
    Ok(parsed)
}

fn u128_json(tag: &TypeTag, value: &JsonValue) -> Result<u128, ValueCodecError> {
    match value {
        JsonValue::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| json_mismatch(tag, "expected unsigned integer")),
        JsonValue::String(s) => s
            .parse()
            .map_err(|_| json_mismatch(tag, "expected unsigned integer string")),
        _ => Err(json_mismatch(tag, "expected unsigned integer")),
    }
}

fn hex_from_json(tag: &TypeTag, value: &JsonValue) -> Result<Vec<u8>, ValueCodecError> {
    let s = value
        .as_str()
        .ok_or_else(|| json_mismatch(tag, "expected hex string"))?;
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|e| ValueCodecError::JsonMismatch {
        type_tag: type_tag_label(tag),
        reason: format!("invalid hex: {e}"),
    })
}

fn type_tag_from_json(tag: &TypeTag, value: &JsonValue) -> Result<TypeTag, String> {
    match value {
        JsonValue::String(s) => type_tag_from_json_string(s),
        JsonValue::Object(map) => {
            if let Some(v) = map.get("concrete") {
                let obj = v
                    .as_object()
                    .ok_or_else(|| "concrete must be an object".to_string())?;
                let type_name = obj
                    .get("type_name")
                    .or_else(|| obj.get("name"))
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| "concrete.type_name missing".to_string())?
                    .to_string();
                let petal_hash = match obj.get("petal_hash").or_else(|| obj.get("hash")) {
                    Some(JsonValue::String(s)) => parse_hex32(s)
                        .map_err(|reason| format!("invalid concrete.petal_hash: {reason}"))?,
                    None => default_type_hash(&type_name),
                    _ => return Err("concrete.petal_hash must be a hex string".to_string()),
                };
                let type_args = match obj.get("type_args") {
                    Some(JsonValue::Array(items)) => items
                        .iter()
                        .map(|item| type_tag_from_json(tag, item))
                        .collect::<Result<Vec<_>, _>>()?,
                    Some(_) => return Err("concrete.type_args must be an array".to_string()),
                    None => Vec::new(),
                };
                Ok(normalize_builtin_type_tag(&TypeTag::Concrete {
                    petal_hash,
                    type_name,
                    type_args,
                }))
            } else if let Some(v) = map.get("generic") {
                Ok(TypeTag::Generic {
                    idx: u16_from_json(v, "generic")?,
                })
            } else if let Some(v) = map.get("external") {
                Ok(TypeTag::External {
                    ref_idx: u16_from_json(v, "external")?,
                })
            } else {
                Err("expected concrete/generic/external".to_string())
            }
        }
        _ => Err("TypeTag must be a string or object".to_string()),
    }
    .map_err(|reason| format!("{reason} while parsing {}", type_tag_label(tag)))
}

fn type_tag_from_json_string(s: &str) -> Result<TypeTag, String> {
    if let Ok(bytes) = hex::decode(strip_0x(s))
        && let Ok(tag) = TypeTag::decode_canonical(&bytes)
    {
        return Ok(tag);
    }
    if let Some(inner) = s.strip_prefix("vector<").and_then(|v| v.strip_suffix('>')) {
        return Ok(TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: "vector".to_string(),
            type_args: vec![type_tag_from_json_string(inner.trim())?],
        });
    }
    if s.is_empty() {
        return Err("empty type tag".to_string());
    }
    Ok(TypeTag::Concrete {
        petal_hash: default_type_hash(s),
        type_name: s.to_string(),
        type_args: Vec::new(),
    })
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(strip_0x(s)).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn u16_from_json(value: &JsonValue, label: &str) -> Result<u16, String> {
    let n = value
        .as_u64()
        .ok_or_else(|| format!("{label} must be a u16"))?;
    n.try_into().map_err(|_| format!("{label} out of range"))
}

fn normalize_builtin_type_tag(tag: &TypeTag) -> TypeTag {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => TypeTag::Concrete {
            petal_hash: if is_builtin_type_name(type_name) {
                BUILTIN_TYPE_HASH
            } else {
                *petal_hash
            },
            type_name: type_name.clone(),
            type_args: type_args
                .iter()
                .map(normalize_builtin_type_tag)
                .collect::<Vec<_>>(),
        },
        TypeTag::Generic { .. } | TypeTag::External { .. } => tag.clone(),
    }
}

fn default_type_hash(type_name: &str) -> [u8; 32] {
    if is_builtin_type_name(type_name) {
        BUILTIN_TYPE_HASH
    } else {
        [0u8; 32]
    }
}

fn is_builtin_type_name(type_name: &str) -> bool {
    matches!(
        type_name,
        "bool"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "Address"
            | "address"
            | "ObjectId"
            | "Hash32"
            | "UID"
            | "TypeTag"
            | "bytes"
            | "String"
            | "string"
            | "vector"
            | "set"
            | "map"
            | "tuple"
            | "Option"
            | "Result"
    )
}

fn _cow_label(tag: &TypeTag) -> Cow<'_, str> {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } if *petal_hash == BUILTIN_TYPE_HASH && type_args.is_empty() => Cow::Borrowed(type_name),
        _ => Cow::Owned(type_tag_label(tag)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str) -> TypeTag {
        builtin_type(name, vec![])
    }

    fn vec_t(elem: TypeTag) -> TypeTag {
        builtin_type("vector", vec![elem])
    }

    fn map_t(k: TypeTag, v: TypeTag) -> TypeTag {
        builtin_type("map", vec![k, v])
    }

    fn set_t(elem: TypeTag) -> TypeTag {
        builtin_type("set", vec![elem])
    }

    fn custom_t(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    struct TestResolver;

    impl Resolver for TestResolver {
        fn resolve_shape(
            &self,
            tag: &TypeTag,
            _depth: usize,
        ) -> Result<TypeShape, ValueCodecError> {
            if let Some(shape) = builtin_shape(tag)? {
                return Ok(shape);
            }
            match tag {
                TypeTag::Concrete { type_name, .. } if type_name == "Pair" => {
                    Ok(TypeShape::Struct(vec![FieldShape {
                        name: "amount".to_string(),
                        ty: t("u64"),
                    }]))
                }
                TypeTag::Concrete { type_name, .. } if type_name == "Mode" => {
                    Ok(TypeShape::Enum(vec![
                        VariantShape {
                            name: "Paused".to_string(),
                            fields: VariantFields::Unit,
                        },
                        VariantShape {
                            name: "Configured".to_string(),
                            fields: VariantFields::Struct(vec![FieldShape {
                                name: "level".to_string(),
                                ty: t("u8"),
                            }]),
                        },
                    ]))
                }
                _ => Err(ValueCodecError::UnresolvedType(type_tag_label(tag))),
            }
        }
    }

    #[test]
    fn uleb128_minimal_roundtrip_and_rejects_non_minimal() {
        let cases = [0, 1, 127, 128, 16_384, u32::MAX as u64, u64::MAX];
        for case in cases {
            let mut out = Vec::new();
            write_uleb128(case, &mut out);
            let mut cursor = out.as_slice();
            assert_eq!(read_uleb128(&mut cursor).unwrap(), case);
            assert!(cursor.is_empty());
        }

        let mut non_minimal: &[u8] = &[0x80, 0x00];
        assert_eq!(
            read_uleb128(&mut non_minimal).unwrap_err(),
            ValueCodecError::NonMinimalUleb128
        );

        let mut too_long: &[u8] = &[0x80; 11];
        assert_eq!(
            read_uleb128(&mut too_long).unwrap_err(),
            ValueCodecError::Uleb128TooLong
        );
    }

    #[test]
    fn string_uses_uleb128_length() {
        let tag = t("String");
        let bytes = encode_value(
            &BuiltinResolver,
            &tag,
            &Value::String("hello".to_string()),
            &CodecLimits::default(),
        )
        .unwrap();
        assert_eq!(bytes, b"\x05hello");
        assert_eq!(
            decode_json(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            json!("hello")
        );
    }

    #[test]
    fn vector_of_variable_width_values_roundtrips() {
        let tag = vec_t(t("String"));
        let value = Value::Seq(vec![
            Value::String("a".to_string()),
            Value::String("longer".to_string()),
        ]);
        let bytes = encode_value(&BuiltinResolver, &tag, &value, &CodecLimits::default()).unwrap();
        assert_eq!(bytes, b"\x02\x01a\x06longer");
        assert_eq!(
            decode_value(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            value
        );
    }

    #[test]
    fn option_json_projection() {
        let tag = builtin_type("Option", vec![t("u64")]);
        let mut some = vec![1];
        some.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            decode_json(&BuiltinResolver, &tag, &some, &CodecLimits::default()).unwrap(),
            json!("7")
        );
        assert_eq!(
            decode_json(&BuiltinResolver, &tag, &[0], &CodecLimits::default()).unwrap(),
            JsonValue::Null
        );

        let nested = builtin_type("Option", vec![tag.clone()]);
        assert_eq!(
            decode_json(&BuiltinResolver, &nested, &[0], &CodecLimits::default()).unwrap(),
            JsonValue::Null
        );
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &nested,
                &JsonValue::Null,
                &CodecLimits::default()
            )
            .unwrap(),
            vec![0]
        );
        assert_eq!(
            decode_json(&BuiltinResolver, &nested, &[1, 0], &CodecLimits::default()).unwrap(),
            json!({ "Some": null })
        );
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &nested,
                &json!({ "Some": null }),
                &CodecLimits::default()
            )
            .unwrap(),
            vec![1, 0]
        );
        let mut nested_some_some = vec![1, 1];
        nested_some_some.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &nested,
                &json!({ "Some": { "Some": "7" } }),
                &CodecLimits::default()
            )
            .unwrap(),
            nested_some_some
        );
    }

    #[test]
    fn json_struct_rejects_unknown_fields() {
        let tag = custom_t("Pair");
        let err = encode_json(
            &TestResolver,
            &tag,
            &json!({ "amount": "7", "admin": true }),
            &CodecLimits::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field admin"));
    }

    #[test]
    fn json_unit_enum_rejects_non_empty_payload() {
        let tag = custom_t("Mode");
        encode_json(
            &TestResolver,
            &tag,
            &json!("Paused"),
            &CodecLimits::default(),
        )
        .unwrap();
        encode_json(
            &TestResolver,
            &tag,
            &json!({ "Paused": null }),
            &CodecLimits::default(),
        )
        .unwrap();
        let err = encode_json(
            &TestResolver,
            &tag,
            &json!({ "Paused": { "ignored": true } }),
            &CodecLimits::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unit variant payload"));
    }

    #[test]
    fn json_struct_variant_rejects_unknown_fields() {
        let tag = custom_t("Mode");
        let err = encode_json(
            &TestResolver,
            &tag,
            &json!({ "Configured": { "level": 1, "extra": 2 } }),
            &CodecLimits::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown variant field extra"));
    }

    #[test]
    fn map_requires_canonical_key_order() {
        let tag = map_t(t("u8"), t("String"));
        let good = Value::Map(vec![
            (Value::U8(1), Value::String("a".to_string())),
            (Value::U8(2), Value::String("b".to_string())),
        ]);
        let bytes = encode_value(&BuiltinResolver, &tag, &good, &CodecLimits::default()).unwrap();
        assert_eq!(
            decode_value(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            good
        );

        let bad = Value::Map(vec![
            (Value::U8(2), Value::String("b".to_string())),
            (Value::U8(1), Value::String("a".to_string())),
        ]);
        assert_eq!(
            encode_value(&BuiltinResolver, &tag, &bad, &CodecLimits::default()).unwrap_err(),
            ValueCodecError::NonCanonicalKeyOrder
        );
    }

    #[test]
    fn set_rejects_duplicate_keys() {
        let tag = set_t(t("u8"));
        let value = Value::Seq(vec![Value::U8(1), Value::U8(1)]);
        assert_eq!(
            encode_value(&BuiltinResolver, &tag, &value, &CodecLimits::default()).unwrap_err(),
            ValueCodecError::NonCanonicalKeyOrder
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_invalid_utf8() {
        assert_eq!(
            decode_value(&BuiltinResolver, &t("u8"), &[1, 2], &CodecLimits::default()).unwrap_err(),
            ValueCodecError::TrailingBytes(1)
        );
        assert_eq!(
            decode_value(
                &BuiltinResolver,
                &t("String"),
                &[1, 0xff],
                &CodecLimits::default()
            )
            .unwrap_err(),
            ValueCodecError::InvalidUtf8
        );
    }

    #[test]
    fn non_empty_zero_sized_collection_rejected() {
        let tag = vec_t(builtin_type("tuple", vec![]));
        assert_eq!(
            decode_value(&BuiltinResolver, &tag, &[1], &CodecLimits::default()).unwrap_err(),
            ValueCodecError::ZeroSizedCollection
        );
    }

    #[test]
    fn non_empty_unit_enum_collection_is_not_zero_sized() {
        let tag = vec_t(builtin_type("Option", vec![builtin_type("tuple", vec![])]));
        let bytes = [2, 0, 0];
        assert_eq!(
            decode_value(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            Value::Seq(vec![
                Value::Enum {
                    index: 0,
                    name: "None".to_string(),
                    fields: VariantValue::Unit,
                },
                Value::Enum {
                    index: 0,
                    name: "None".to_string(),
                    fields: VariantValue::Unit,
                },
            ])
        );
    }

    #[test]
    fn uid_is_32_byte_scalar() {
        let tag = t("UID");
        let mut bytes = [0u8; 32];
        bytes[31] = 7;
        let value = decode_value(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap();
        assert_eq!(value, Value::Bytes32(bytes));
        assert_eq!(
            decode_json(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            json!(hex::encode(bytes))
        );
    }

    #[test]
    fn type_tag_is_canonical_builtin_scalar() {
        let tag = t("TypeTag");
        let value = TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: "Coin".to_string(),
            type_args: vec![t("u128")],
        };
        let bytes = value.encode_canonical().unwrap();
        assert_eq!(
            decode_value(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            Value::TypeTag(value.clone())
        );
        assert_eq!(
            encode_value(
                &BuiltinResolver,
                &tag,
                &Value::TypeTag(value.clone()),
                &CodecLimits::default()
            )
            .unwrap(),
            bytes
        );
        assert_eq!(
            decode_json(&BuiltinResolver, &tag, &bytes, &CodecLimits::default()).unwrap(),
            json!(hex::encode(&bytes))
        );
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &tag,
                &json!(hex::encode(&bytes)),
                &CodecLimits::default()
            )
            .unwrap(),
            bytes
        );
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &tag,
                &json!("u64"),
                &CodecLimits::default()
            )
            .unwrap(),
            t("u64").encode_canonical().unwrap()
        );
        assert_eq!(
            encode_json(
                &BuiltinResolver,
                &tag,
                &json!({
                    "concrete": {
                        "petal_hash": hex::encode([0xAA; 32]),
                        "type_name": "Coin",
                        "type_args": ["u128"]
                    }
                }),
                &CodecLimits::default()
            )
            .unwrap(),
            bytes
        );
    }
}
