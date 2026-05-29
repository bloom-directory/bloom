//! JSON codec for Bloom-native view-call arguments and returns.
//!
//! This module intentionally sits beside the PTB wire codec so RPC, CLI and
//! tests use one TypeTag-driven mapping between human JSON and canonical bytes.

use bloom_objects::{TypeTag, ValidationOutcome, validate_canonical_bytes};
use serde_json::{Value, json};
use thiserror::Error;

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
    let bytes = encode_value(tag, value)?;
    match validate_canonical_bytes(tag, &bytes) {
        ValidationOutcome::Ok | ValidationOutcome::Unknown => Ok(bytes),
        ValidationOutcome::Invalid(reason) => Err(JsonAbiError::InvalidCanonical {
            type_tag: type_tag_label(tag),
            reason: reason.to_string(),
        }),
    }
}

/// Decode one return slot. Unknown/custom types degrade to `Ok(None)` so callers
/// can still surface the raw slot.
pub fn decode_return_json(tag: &TypeTag, bytes: &[u8]) -> Result<Option<Value>, JsonAbiError> {
    decode_value(tag, bytes).map(Some).or_else(|err| match err {
        JsonAbiError::UnsupportedType(_) => Ok(None),
        other => Err(other),
    })
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
                    None => [0u8; 32],
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
                Ok(TypeTag::Concrete {
                    petal_hash,
                    type_name,
                    type_args,
                })
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

fn encode_value(tag: &TypeTag, value: &Value) -> Result<Vec<u8>, JsonAbiError> {
    let TypeTag::Concrete {
        type_name,
        type_args,
        ..
    } = tag
    else {
        return Err(JsonAbiError::UnsupportedType(type_tag_label(tag)));
    };
    match (type_name.as_str(), type_args.as_slice()) {
        ("bool", []) => Ok(vec![
            value
                .as_bool()
                .ok_or_else(|| mismatch(tag, "expected bool"))? as u8,
        ]),
        ("u8", []) => Ok(vec![u64_value(tag, value, u8::MAX as u64)? as u8]),
        ("u16", []) => Ok((u64_value(tag, value, u16::MAX as u64)? as u16)
            .to_be_bytes()
            .to_vec()),
        ("u32", []) => Ok((u64_value(tag, value, u32::MAX as u64)? as u32)
            .to_be_bytes()
            .to_vec()),
        ("u64", []) => Ok(u64_value(tag, value, u64::MAX)?.to_be_bytes().to_vec()),
        ("u128", []) => Ok(u128_value(tag, value)?.to_be_bytes().to_vec()),
        ("address" | "Address" | "ObjectId" | "Hash32", []) => {
            Ok(parse_hex32_json(tag, value)?.to_vec())
        }
        ("bytes", []) => Ok(parse_hex_json(tag, value)?),
        ("string", []) => string_value(tag, value).map(|s| s.into_bytes()),
        ("String", []) => {
            let s = string_value(tag, value)?;
            let len: u16 = s.len().try_into().map_err(|_| JsonAbiError::TypeMismatch {
                type_tag: type_tag_label(tag),
                reason: "string exceeds u16 length prefix".to_string(),
            })?;
            let mut out = Vec::with_capacity(2 + s.len());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(s.as_bytes());
            Ok(out)
        }
        ("TypeTag", []) => decode_json_type_tag(value).and_then(|t| {
            t.encode_canonical()
                .map_err(|e| JsonAbiError::InvalidTypeTag(e.to_string()))
        }),
        ("vector", [elem]) => encode_vector(tag, elem, value),
        _ => Err(JsonAbiError::UnsupportedType(type_tag_label(tag))),
    }
}

fn decode_value(tag: &TypeTag, bytes: &[u8]) -> Result<Value, JsonAbiError> {
    let TypeTag::Concrete {
        type_name,
        type_args,
        ..
    } = tag
    else {
        return Err(JsonAbiError::UnsupportedType(type_tag_label(tag)));
    };
    match (type_name.as_str(), type_args.as_slice()) {
        ("bool", []) => {
            let b = one_byte(tag, bytes)?;
            match b {
                0 => Ok(Value::Bool(false)),
                1 => Ok(Value::Bool(true)),
                _ => Err(mismatch(tag, "bool byte must be 0 or 1")),
            }
        }
        ("u8", []) => Ok(json!(one_byte(tag, bytes)?)),
        ("u16", []) => Ok(json!(u16::from_be_bytes(fixed(tag, bytes)?))),
        ("u32", []) => Ok(json!(u32::from_be_bytes(fixed(tag, bytes)?))),
        ("u64", []) => Ok(json!(u64::from_be_bytes(fixed(tag, bytes)?).to_string())),
        ("u128", []) => Ok(json!(u128::from_be_bytes(fixed(tag, bytes)?).to_string())),
        ("address" | "Address" | "ObjectId" | "Hash32", []) => {
            let a: [u8; 32] = fixed(tag, bytes)?;
            Ok(json!(hex::encode(a)))
        }
        ("bytes", []) => Ok(json!(hex::encode(bytes))),
        ("string", []) => core::str::from_utf8(bytes)
            .map(|s| json!(s))
            .map_err(|_| mismatch(tag, "invalid utf-8")),
        ("String", []) => {
            if bytes.len() < 2 {
                return Err(mismatch(tag, "missing u16 string length"));
            }
            let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if bytes.len() != 2 + len {
                return Err(mismatch(tag, "string length prefix does not match payload"));
            }
            core::str::from_utf8(&bytes[2..])
                .map(|s| json!(s))
                .map_err(|_| mismatch(tag, "invalid utf-8"))
        }
        ("TypeTag", []) => {
            let tag = TypeTag::decode_canonical(bytes)
                .map_err(|e| JsonAbiError::InvalidTypeTag(e.to_string()))?;
            Ok(encode_type_tag_json(&tag))
        }
        ("vector", [elem]) => decode_vector(tag, elem, bytes),
        _ => Err(JsonAbiError::UnsupportedType(type_tag_label(tag))),
    }
}

fn encode_vector(tag: &TypeTag, elem: &TypeTag, value: &Value) -> Result<Vec<u8>, JsonAbiError> {
    if fixed_width(elem).is_none() {
        return Err(JsonAbiError::UnsupportedType(type_tag_label(tag)));
    }
    let items = value
        .as_array()
        .ok_or_else(|| mismatch(tag, "expected array"))?;
    let count: u32 = items
        .len()
        .try_into()
        .map_err(|_| mismatch(tag, "vector too long"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for item in items {
        out.extend_from_slice(&encode_value(elem, item)?);
    }
    Ok(out)
}

fn decode_vector(tag: &TypeTag, elem: &TypeTag, bytes: &[u8]) -> Result<Value, JsonAbiError> {
    if bytes.len() < 4 {
        return Err(mismatch(tag, "vector missing u32 count"));
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let Some(width) = fixed_width(elem) else {
        return Err(JsonAbiError::UnsupportedType(type_tag_label(tag)));
    };
    let expected = 4usize
        .checked_add(
            count
                .checked_mul(width)
                .ok_or_else(|| mismatch(tag, "vector length overflow"))?,
        )
        .ok_or_else(|| mismatch(tag, "vector length overflow"))?;
    if bytes.len() != expected {
        return Err(mismatch(tag, "vector payload length mismatch"));
    }
    let mut out = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        out.push(decode_value(elem, &bytes[offset..offset + width])?);
        offset += width;
    }
    Ok(Value::Array(out))
}

fn fixed_width(tag: &TypeTag) -> Option<usize> {
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
        "bool" | "u8" => Some(1),
        "u16" => Some(2),
        "u32" => Some(4),
        "u64" => Some(8),
        "u128" => Some(16),
        "address" | "Address" | "ObjectId" | "Hash32" => Some(32),
        _ => None,
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
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![decode_type_tag_string(inner.trim())?],
        });
    }
    if s.is_empty() {
        return Err(JsonAbiError::InvalidTypeTag("empty type tag".to_string()));
    }
    Ok(TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: s.to_string(),
        type_args: Vec::new(),
    })
}

fn string_value(tag: &TypeTag, value: &Value) -> Result<String, JsonAbiError> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| mismatch(tag, "expected string"))
}

fn u64_value(tag: &TypeTag, value: &Value, max: u64) -> Result<u64, JsonAbiError> {
    let n = match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| mismatch(tag, "expected unsigned integer"))?,
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|_| mismatch(tag, "expected unsigned integer string"))?,
        _ => return Err(mismatch(tag, "expected unsigned integer")),
    };
    if n > max {
        return Err(JsonAbiError::IntegerRange(type_tag_label(tag)));
    }
    Ok(n)
}

fn u128_value(tag: &TypeTag, value: &Value) -> Result<u128, JsonAbiError> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| mismatch(tag, "expected unsigned integer")),
        Value::String(s) => s
            .parse::<u128>()
            .map_err(|_| mismatch(tag, "expected unsigned integer string")),
        _ => Err(mismatch(tag, "expected unsigned integer")),
    }
}

fn parse_hex32_json(tag: &TypeTag, value: &Value) -> Result<[u8; 32], JsonAbiError> {
    let s = value
        .as_str()
        .ok_or_else(|| mismatch(tag, "expected hex string"))?;
    parse_hex32(s).map_err(|reason| JsonAbiError::InvalidHex {
        type_tag: type_tag_label(tag),
        reason,
    })
}

fn parse_hex_json(tag: &TypeTag, value: &Value) -> Result<Vec<u8>, JsonAbiError> {
    let s = value
        .as_str()
        .ok_or_else(|| mismatch(tag, "expected hex string"))?;
    hex::decode(strip_0x(s)).map_err(|e| JsonAbiError::InvalidHex {
        type_tag: type_tag_label(tag),
        reason: e.to_string(),
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

fn one_byte(tag: &TypeTag, bytes: &[u8]) -> Result<u8, JsonAbiError> {
    if bytes.len() != 1 {
        return Err(mismatch(tag, "expected 1 byte"));
    }
    Ok(bytes[0])
}

fn fixed<const N: usize>(tag: &TypeTag, bytes: &[u8]) -> Result<[u8; N], JsonAbiError> {
    if bytes.len() != N {
        return Err(mismatch(tag, format!("expected {N} bytes")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn mismatch(tag: &TypeTag, reason: impl Into<String>) -> JsonAbiError {
    JsonAbiError::TypeMismatch {
        type_tag: type_tag_label(tag),
        reason: reason.into(),
    }
}

fn type_tag_label(tag: &TypeTag) -> String {
    match tag {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } if type_args.is_empty() => type_name.clone(),
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => {
            let args = type_args
                .iter()
                .map(type_tag_label)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{type_name}<{args}>")
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("$external_{ref_idx}"),
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
    fn vector_variable_width_elements_are_unsupported() {
        let tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![prim("string")],
        };
        assert!(matches!(
            decode_json_const(&tag, &json!(["a"])),
            Err(JsonAbiError::UnsupportedType(_))
        ));
    }

    #[test]
    fn unknown_return_degrades_to_none() {
        let tag = prim("Custom");
        assert_eq!(decode_return_json(&tag, &[1, 2, 3]).unwrap(), None);
    }
}
