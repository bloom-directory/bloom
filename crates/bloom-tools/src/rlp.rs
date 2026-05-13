//! RLP encode/decode of arbitrary JSON structures.
//!
//! Encoding rules:
//! - JSON string: if it starts with `0x` interpret as hex bytes, otherwise
//!   UTF-8 bytes.
//! - JSON number (unsigned integer): encoded as big-endian minimal-width
//!   bytes (zero is the empty byte string per RLP convention).
//! - JSON array: encoded as an RLP list, recursively.
//!
//! Decoding produces a JSON tree where every leaf is `{"hex": "0x..."}`
//! and every list is a JSON array.

use alloy::rlp::{EMPTY_LIST_CODE, EMPTY_STRING_CODE, Header};

use crate::ToolsError;

/// RLP-encode a JSON value. Returns 0x-prefixed hex.
pub fn rlp_encode(value: &serde_json::Value) -> Result<String, ToolsError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(format!("0x{}", hex::encode(out)))
}

/// RLP-decode raw bytes. Returns a JSON tree (see module docs).
pub fn rlp_decode(data: &[u8]) -> Result<serde_json::Value, ToolsError> {
    let mut buf = data;
    let v = decode_one(&mut buf)?;
    if !buf.is_empty() {
        return Err(ToolsError::Invalid(format!(
            "trailing bytes after RLP item: {} byte(s)",
            buf.len()
        )));
    }
    Ok(v)
}

fn encode_into(v: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), ToolsError> {
    use serde_json::Value;
    match v {
        Value::String(s) => {
            let bytes = string_bytes(s)?;
            encode_bytes(&bytes, out);
            Ok(())
        }
        Value::Number(n) => {
            let u = n
                .as_u64()
                .ok_or_else(|| ToolsError::Invalid(format!("number out of range: {n}")))?;
            let mut be = u.to_be_bytes().to_vec();
            // Strip leading zeros for minimal encoding.
            while be.first() == Some(&0) {
                be.remove(0);
            }
            encode_bytes(&be, out);
            Ok(())
        }
        Value::Array(items) => {
            // Encode children to a buffer, then prepend a list header.
            let mut payload = Vec::new();
            for item in items {
                encode_into(item, &mut payload)?;
            }
            let header = Header {
                list: true,
                payload_length: payload.len(),
            };
            header.encode(out);
            out.extend_from_slice(&payload);
            Ok(())
        }
        Value::Bool(_) | Value::Null | Value::Object(_) => Err(ToolsError::Invalid(
            "RLP only supports strings, unsigned numbers, and arrays".into(),
        )),
    }
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < EMPTY_STRING_CODE {
        out.push(bytes[0]);
        return;
    }
    let header = Header {
        list: false,
        payload_length: bytes.len(),
    };
    header.encode(out);
    out.extend_from_slice(bytes);
}

fn string_bytes(s: &str) -> Result<Vec<u8>, ToolsError> {
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        hex::decode(stripped).map_err(|e| ToolsError::Hex(e.to_string()))
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

fn decode_one(buf: &mut &[u8]) -> Result<serde_json::Value, ToolsError> {
    if buf.is_empty() {
        return Err(ToolsError::Invalid("empty RLP input".into()));
    }
    let first = buf[0];
    let is_list = first >= EMPTY_LIST_CODE;
    let header = Header::decode(buf).map_err(|e| ToolsError::Invalid(e.to_string()))?;
    if header.payload_length > buf.len() {
        return Err(ToolsError::Invalid("truncated RLP payload".into()));
    }
    let (payload, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    if is_list {
        let mut p = payload;
        let mut items = Vec::new();
        while !p.is_empty() {
            items.push(decode_one(&mut p)?);
        }
        Ok(serde_json::Value::Array(items))
    } else {
        Ok(serde_json::json!({ "hex": format!("0x{}", hex::encode(payload)) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_short_string() {
        // "dog" -> 0x83 'd' 'o' 'g'
        let v = serde_json::json!("dog");
        let out = rlp_encode(&v).unwrap();
        assert_eq!(out, "0x83646f67");
    }

    #[test]
    fn encode_empty_list() {
        let v = serde_json::json!([]);
        let out = rlp_encode(&v).unwrap();
        assert_eq!(out, "0xc0");
    }

    #[test]
    fn encode_uint_zero_is_empty_string() {
        let v = serde_json::json!(0);
        let out = rlp_encode(&v).unwrap();
        assert_eq!(out, "0x80");
    }

    #[test]
    fn encode_uint_15() {
        // 15 -> single byte 0x0f
        let v = serde_json::json!(15);
        let out = rlp_encode(&v).unwrap();
        assert_eq!(out, "0x0f");
    }

    #[test]
    fn round_trip_nested() {
        // Spec asks for [0x83, 0xff, [0x01]] — encode then decode.
        let v = serde_json::json!(["0x83", "0xff", ["0x01"]]);
        let encoded = rlp_encode(&v).unwrap();
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap()).unwrap();
        let decoded = rlp_decode(&bytes).unwrap();
        // Decoded structure: top-level is array with 3 elements.
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["hex"].as_str().unwrap(), "0x83");
        assert_eq!(arr[1]["hex"].as_str().unwrap(), "0xff");
        let inner = arr[2].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0]["hex"].as_str().unwrap(), "0x01");
    }

    #[test]
    fn decode_known_dog() {
        let bytes = hex::decode("83646f67").unwrap();
        let v = rlp_decode(&bytes).unwrap();
        assert_eq!(v["hex"].as_str().unwrap(), "0x646f67");
    }
}
