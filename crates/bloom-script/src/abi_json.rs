//! JSON codec for Bloom-native view-call arguments and returns.
//!
//! This module intentionally sits beside the PTB wire codec so RPC, CLI and
//! tests use one TypeTag-driven mapping between human JSON and canonical bytes.

use bloom_objects::{BUILTIN_TYPE_HASH, TypeTag};
use bloom_value::{
    BuiltinResolver, CodecLimits, ValueCodecError, decode_json as decode_value_json,
    encode_json as encode_value_json, type_tag_label,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::chain_iface::PetalManifestStub;
use crate::value_validation::{ManifestLoader, StubResolver, effective_return_slot_tag};

/// Error returned while converting typed JSON to or from canonical ABI bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JsonAbiError {
    /// The requested type is not one this JSON codec can encode.
    #[error("unsupported type tag for JSON ABI: {0}")]
    UnsupportedType(String),
    /// The JSON value does not match the declared type.
    #[error("type mismatch for {type_tag}: {reason}")]
    TypeMismatch {
        /// Human-readable TypeTag label.
        type_tag: String,
        /// Reason the value was rejected.
        reason: String,
    },
    /// A hex string was malformed.
    #[error("invalid hex for {type_tag}: {reason}")]
    InvalidHex {
        /// Human-readable TypeTag label.
        type_tag: String,
        /// Hex decoder error.
        reason: String,
    },
    /// Numeric input could not fit the declared type.
    #[error("numeric value out of range for {0}")]
    IntegerRange(String),
    /// Canonical bytes failed the low-level primitive validator.
    #[error("canonical bytes rejected for {type_tag}: {reason}")]
    InvalidCanonical {
        /// Human-readable TypeTag label.
        type_tag: String,
        /// Validator reason.
        reason: String,
    },
    /// TypeTag JSON was malformed.
    #[error("invalid TypeTag JSON: {0}")]
    InvalidTypeTag(String),
}

/// Convert typed JSON to canonical bytes for a declared TypeTag.
pub fn decode_json_const(tag: &TypeTag, value: &Value) -> Result<Vec<u8>, JsonAbiError> {
    let tag = normalize_builtin_tag(tag);
    encode_value_json(&BuiltinResolver, &tag, value, &CodecLimits::default())
        .map_err(|e| map_value_error(&tag, e))
}

/// Convert typed JSON to canonical bytes for a declared TypeTag using a petal
/// manifest to resolve custom structs/enums and generic self references.
pub fn decode_json_const_with_manifest(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    value: &Value,
) -> Result<Vec<u8>, JsonAbiError> {
    decode_json_const_with_manifest_loader(manifest, self_hash, tag, value, None)
}

/// Convert typed JSON to canonical bytes using a petal manifest plus a loader
/// for external petal manifests referenced by `external_type_refs`.
pub fn decode_json_const_with_manifest_loader(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    value: &Value,
    load_manifest: Option<&ManifestLoader<'_>>,
) -> Result<Vec<u8>, JsonAbiError> {
    let resolver =
        StubResolver::with_self_hash_and_manifest_loader(manifest, self_hash, load_manifest);
    let tag = resolver
        .resolve_declared_tag(tag)
        .map_err(|e| map_value_error(tag, e))?;
    encode_value_json(&resolver, &tag, value, &CodecLimits::default())
        .map_err(|e| map_value_error(&tag, e))
}

/// Decode one return slot. Unknown/custom types degrade to `Ok(None)` so callers
/// can still surface the raw slot.
pub fn decode_return_json(tag: &TypeTag, bytes: &[u8]) -> Result<Option<Value>, JsonAbiError> {
    let tag = normalize_builtin_tag(tag);
    decode_value_json(&BuiltinResolver, &tag, bytes, &CodecLimits::default())
        .map(Some)
        .map_err(|e| map_value_error(&tag, e))
        .or_else(|err| match err {
            JsonAbiError::UnsupportedType(_) => Ok(None),
            other => Err(other),
        })
}

/// Decode one return slot using a petal manifest to resolve custom return
/// shapes. Object-handle returns are decoded using the same effective type that
/// return-slot validation applies.
pub fn decode_return_json_with_manifest(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    bytes: &[u8],
) -> Result<Value, JsonAbiError> {
    decode_return_json_with_manifest_loader(manifest, self_hash, tag, bytes, None)
}

/// Decode one return slot using a petal manifest plus a loader for external
/// petal manifests referenced by `external_type_refs`.
pub fn decode_return_json_with_manifest_loader(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    bytes: &[u8],
    load_manifest: Option<&ManifestLoader<'_>>,
) -> Result<Value, JsonAbiError> {
    let tag = effective_return_slot_tag(manifest, tag);
    let resolver =
        StubResolver::with_self_hash_and_manifest_loader(manifest, self_hash, load_manifest);
    let tag = resolver
        .resolve_declared_tag(&tag)
        .map_err(|e| map_value_error(&tag, e))?;
    decode_value_json(&resolver, &tag, bytes, &CodecLimits::default())
        .map_err(|e| map_value_error(&tag, e))
}

/// Decode a TypeTag from JSON.
///
/// Accepted forms:
/// - canonical TypeTag hex string;
/// - primitive label string such as `"u128"` or `"vector<u64>"`;
/// - object form: `{ "concrete": { "petal_hash": "...", "type_name": "...", "type_args": [] } }`;
/// - object form: `{ "generic": 0 }` or `{ "external": 0 }`.
pub fn decode_json_type_tag(value: &Value) -> Result<TypeTag, JsonAbiError> {
    match value {
        Value::String(s) => decode_type_tag_string(s),
        Value::Object(map) => {
            if let Some(v) = map.get("concrete") {
                let obj = v.as_object().ok_or_else(|| {
                    JsonAbiError::InvalidTypeTag("concrete must be an object".to_string())
                })?;
                let type_name = obj
                    .get("type_name")
                    .or_else(|| obj.get("name"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        JsonAbiError::InvalidTypeTag("concrete.type_name missing".to_string())
                    })?
                    .to_string();
                let petal_hash = match obj.get("petal_hash").or_else(|| obj.get("hash")) {
                    Some(Value::String(s)) => parse_hex32(s).map_err(|reason| {
                        JsonAbiError::InvalidTypeTag(format!("invalid petal_hash: {reason}"))
                    })?,
                    None => default_type_hash(&type_name),
                    _ => {
                        return Err(JsonAbiError::InvalidTypeTag(
                            "concrete.petal_hash must be a hex string".to_string(),
                        ));
                    }
                };
                let type_args = match obj.get("type_args") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(decode_json_type_tag)
                        .collect::<Result<Vec<_>, _>>()?,
                    Some(_) => {
                        return Err(JsonAbiError::InvalidTypeTag(
                            "concrete.type_args must be an array".to_string(),
                        ));
                    }
                    None => Vec::new(),
                };
                Ok(normalize_builtin_tag(&TypeTag::Concrete {
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
                Err(JsonAbiError::InvalidTypeTag(
                    "expected concrete/generic/external".to_string(),
                ))
            }
        }
        _ => Err(JsonAbiError::InvalidTypeTag(
            "TypeTag must be a string or object".to_string(),
        )),
    }
}

/// Human-readable JSON projection of a TypeTag.
pub fn encode_type_tag_json(tag: &TypeTag) -> Value {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => json!({
            "concrete": {
                "petal_hash": hex::encode(petal_hash),
                "type_name": type_name,
                "type_args": type_args.iter().map(encode_type_tag_json).collect::<Vec<_>>(),
            }
        }),
        TypeTag::Generic { idx } => json!({ "generic": idx }),
        TypeTag::External { ref_idx } => json!({ "external": ref_idx }),
    }
}

fn decode_type_tag_string(s: &str) -> Result<TypeTag, JsonAbiError> {
    if let Ok(bytes) = hex::decode(strip_0x(s))
        && let Ok(tag) = TypeTag::decode_canonical(&bytes)
    {
        return Ok(tag);
    }
    if let Some(inner) = s.strip_prefix("vector<").and_then(|v| v.strip_suffix('>')) {
        return Ok(TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: "vector".to_string(),
            type_args: vec![decode_type_tag_string(inner.trim())?],
        });
    }
    if s.is_empty() {
        return Err(JsonAbiError::InvalidTypeTag("empty type tag".to_string()));
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

fn u16_from_json(value: &Value, label: &str) -> Result<u16, JsonAbiError> {
    let n = value
        .as_u64()
        .ok_or_else(|| JsonAbiError::InvalidTypeTag(format!("{label} must be a u16")))?;
    n.try_into()
        .map_err(|_| JsonAbiError::InvalidTypeTag(format!("{label} out of range")))
}

fn normalize_builtin_tag(tag: &TypeTag) -> TypeTag {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => TypeTag::Concrete {
            petal_hash: if is_builtin_name(type_name) {
                BUILTIN_TYPE_HASH
            } else {
                *petal_hash
            },
            type_name: type_name.clone(),
            type_args: type_args
                .iter()
                .map(normalize_builtin_tag)
                .collect::<Vec<_>>(),
        },
        TypeTag::Generic { .. } | TypeTag::External { .. } => tag.clone(),
    }
}

fn default_type_hash(type_name: &str) -> [u8; 32] {
    if is_builtin_name(type_name) {
        BUILTIN_TYPE_HASH
    } else {
        [0u8; 32]
    }
}

fn is_builtin_name(type_name: &str) -> bool {
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

fn map_value_error(tag: &TypeTag, err: ValueCodecError) -> JsonAbiError {
    match err {
        ValueCodecError::JsonMismatch { type_tag, reason } => {
            JsonAbiError::TypeMismatch { type_tag, reason }
        }
        ValueCodecError::UnresolvedType(_) | ValueCodecError::InvalidArity { .. } => {
            JsonAbiError::UnsupportedType(type_tag_label(tag))
        }
        ValueCodecError::TypeMismatch { expected, got } => JsonAbiError::TypeMismatch {
            type_tag: type_tag_label(tag),
            reason: format!("expected {expected}, got {got}"),
        },
        other => JsonAbiError::InvalidCanonical {
            type_tag: type_tag_label(tag),
            reason: other.to_string(),
        },
    }
}

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

    #[test]
    fn u128_uses_decimal_json_string() {
        let tag = prim("u128");
        let bytes =
            decode_json_const(&tag, &json!("340282366920938463463374607431768211455")).unwrap();
        assert_eq!(bytes, u128::MAX.to_be_bytes());
        assert_eq!(
            decode_return_json(&tag, &bytes).unwrap(),
            Some(json!(u128::MAX.to_string()))
        );
    }

    #[test]
    fn address_hex_round_trips() {
        let tag = prim("Address");
        let input = "11".repeat(32);
        let bytes = decode_json_const(&tag, &json!(input)).unwrap();
        assert_eq!(bytes, vec![0x11; 32]);
        assert_eq!(
            decode_return_json(&tag, &bytes).unwrap(),
            Some(json!(input))
        );
    }

    #[test]
    fn vector_u64_round_trips() {
        let tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![prim("u64")],
        };
        let bytes = decode_json_const(&tag, &json!([1, "2"])).unwrap();
        assert_eq!(
            decode_return_json(&tag, &bytes).unwrap(),
            Some(json!(["1", "2"]))
        );
    }

    #[test]
    fn vector_variable_width_elements_round_trip() {
        let tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![prim("string")],
        };
        let bytes = decode_json_const(&tag, &json!(["a", "bc"])).unwrap();
        assert_eq!(bytes, vec![2, 1, b'a', 2, b'b', b'c']);
        assert_eq!(
            decode_return_json(&tag, &bytes).unwrap(),
            Some(json!(["a", "bc"]))
        );
    }

    #[test]
    fn builtin_only_unknown_return_degrades_to_none() {
        let tag = prim("Custom");
        assert_eq!(decode_return_json(&tag, &[1, 2, 3]).unwrap(), None);
    }

    #[test]
    fn manifest_custom_data_round_trips() {
        let manifest = PetalManifestStub {
            data_types: vec![crate::DataTypeDeclStub {
                name: "Wrapper".to_string(),
                fields: vec![crate::FieldDeclStub {
                    name: "value".to_string(),
                    ty: prim("u64"),
                }],
                ..crate::DataTypeDeclStub::default()
            }],
            ..PetalManifestStub::default()
        };
        let tag = prim("Wrapper");

        let bytes =
            decode_json_const_with_manifest(&manifest, [0xAA; 32], &tag, &json!({"value": "42"}))
                .unwrap();

        assert_eq!(bytes, 42u64.to_be_bytes());
        assert_eq!(
            decode_return_json_with_manifest(&manifest, [0xAA; 32], &tag, &bytes).unwrap(),
            json!({"value": "42"})
        );
    }

    #[test]
    fn manifest_object_return_decodes_as_object_id() {
        let manifest = PetalManifestStub {
            object_types: vec![crate::ObjectTypeDeclStub {
                name: "Thing".to_string(),
                fields: vec![],
                ..crate::ObjectTypeDeclStub::default()
            }],
            ..PetalManifestStub::default()
        };
        let tag = prim("Thing");
        let bytes = [0x22; 32];

        assert_eq!(
            decode_return_json_with_manifest(&manifest, [0xAA; 32], &tag, &bytes).unwrap(),
            json!(hex::encode(bytes))
        );
    }
}
