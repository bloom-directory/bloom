//! ABI encode/decode and EIP-712 helpers.

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::{Address, U256};
use alloy_dyn_abi::TypedData;

use crate::ToolsError;

/// Encode a Solidity-style call.
///
/// `method_sig` is either:
/// - a function signature like `transfer(address,uint256)` (calldata
///   prefixed with the 4-byte selector), or
/// - a tuple type like `(uint256,address,bytes32)` (raw ABI tuple
///   encoding, no selector).
///
/// `args` is a JSON array of arguments matching the type spec.
pub fn abi_encode(method_sig: &str, args: &serde_json::Value) -> Result<String, ToolsError> {
    let trimmed = method_sig.trim();
    let arr = args
        .as_array()
        .ok_or_else(|| ToolsError::Invalid("args must be a JSON array".into()))?;

    if let Some(stripped) = strip_tuple(trimmed) {
        // Bare tuple type — raw encoding without selector.
        let types = split_tuple(stripped)?;
        if types.len() != arr.len() {
            return Err(ToolsError::Invalid(format!(
                "expected {} args, got {}",
                types.len(),
                arr.len()
            )));
        }
        let mut sol_values = Vec::with_capacity(types.len());
        for (i, (ty_str, arg)) in types.iter().zip(arr.iter()).enumerate() {
            let ty: DynSolType = ty_str
                .parse()
                .map_err(|e: alloy::dyn_abi::Error| ToolsError::Abi(format!("input {i}: {e}")))?;
            let v =
                json_to_sol(&ty, arg).map_err(|e| ToolsError::Abi(format!("input {i}: {e}")))?;
            sol_values.push(v);
        }
        let tuple = DynSolValue::Tuple(sol_values);
        let encoded = tuple.abi_encode_params();
        Ok(format!("0x{}", hex::encode(encoded)))
    } else {
        // Function signature with selector. Delegate to encode_call which
        // already implements this.
        crate::encode_call(trimmed, args).map_err(Into::into)
    }
}

/// Decode raw ABI bytes given a list of solidity type strings.
///
/// Returns a JSON array of decoded values. Numbers are stringified to
/// preserve precision, addresses are EIP-55 checksummed, bytes are 0x-
/// prefixed hex.
pub fn abi_decode(types: &[&str], data: &[u8]) -> Result<serde_json::Value, ToolsError> {
    let mut sol_types = Vec::with_capacity(types.len());
    for (i, t) in types.iter().enumerate() {
        let ty: DynSolType = t
            .parse()
            .map_err(|e: alloy::dyn_abi::Error| ToolsError::Abi(format!("type {i}: {e}")))?;
        sol_types.push(ty);
    }
    let tuple_ty = DynSolType::Tuple(sol_types);
    let decoded = tuple_ty
        .abi_decode_params(data)
        .map_err(|e| ToolsError::Abi(e.to_string()))?;
    let arr = match decoded {
        DynSolValue::Tuple(t) => t,
        other => vec![other],
    };
    Ok(serde_json::Value::Array(
        arr.iter().map(sol_to_json).collect(),
    ))
}

/// Compute the EIP-712 v4 signing hash from a JSON-encoded typed data.
///
/// `typed_data` must be the canonical EIP-712 JSON shape with
/// `domain`, `types`, `primaryType`, `message`.
pub fn eip712_hash(typed_data: &str) -> Result<String, ToolsError> {
    let td: TypedData = serde_json::from_str(typed_data)
        .map_err(|e| ToolsError::Invalid(format!("typed-data json: {e}")))?;
    let h = td
        .eip712_signing_hash()
        .map_err(|e| ToolsError::Abi(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(h)))
}

// -- helpers --

/// If `s` looks like a parenthesised type list `(a,b,c)` return the inner.
fn strip_tuple(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.starts_with('(') && s.ends_with(')') {
        // Make sure this is a *bare* tuple (not e.g. `foo(uint256)`).
        // The first paren is at index 0.
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

/// Split a top-level comma-separated type list, respecting nested
/// parens / brackets.
fn split_tuple(s: &str) -> Result<Vec<String>, ToolsError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        if depth < 0 {
            return Err(ToolsError::Invalid("unbalanced parens in type list".into()));
        }
    }
    if depth != 0 {
        return Err(ToolsError::Invalid("unbalanced parens in type list".into()));
    }
    out.push(s[start..].trim().to_string());
    Ok(out)
}

pub fn json_to_sol(ty: &DynSolType, v: &serde_json::Value) -> Result<DynSolValue, String> {
    use serde_json::Value;
    match ty {
        DynSolType::Address => {
            let s = v.as_str().ok_or("address must be string")?;
            let a: Address = s
                .parse()
                .map_err(|e: alloy::hex::FromHexError| e.to_string())?;
            Ok(DynSolValue::Address(a))
        }
        DynSolType::Bool => Ok(DynSolValue::Bool(
            v.as_bool().ok_or("bool must be boolean")?,
        )),
        DynSolType::String => Ok(DynSolValue::String(
            v.as_str().ok_or("string must be string")?.to_string(),
        )),
        DynSolType::Bytes => {
            let s = v.as_str().ok_or("bytes must be hex string")?;
            Ok(DynSolValue::Bytes(decode_hex_str(s)?))
        }
        DynSolType::FixedBytes(n) => {
            let s = v.as_str().ok_or("bytes must be hex string")?;
            let b = decode_hex_str(s)?;
            if b.len() != *n {
                return Err(format!("expected {} bytes, got {}", n, b.len()));
            }
            let mut arr = [0u8; 32];
            arr[..b.len()].copy_from_slice(&b);
            Ok(DynSolValue::FixedBytes(arr.into(), *n))
        }
        DynSolType::Uint(bits) => {
            let n = match v {
                Value::String(s) => U256::from_str_radix(
                    s.trim_start_matches("0x"),
                    if s.starts_with("0x") { 16 } else { 10 },
                )
                .map_err(|e| e.to_string())?,
                Value::Number(n) => U256::from(n.as_u64().ok_or("number out of range")?),
                _ => return Err("uint must be number or string".into()),
            };
            Ok(DynSolValue::Uint(n, *bits))
        }
        DynSolType::Int(bits) => {
            let s = v
                .as_str()
                .map(String::from)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
                .ok_or("int must be number or string")?;
            let parsed: alloy::primitives::I256 = s
                .parse()
                .map_err(|e: alloy::primitives::ParseSignedError| e.to_string())?;
            Ok(DynSolValue::Int(parsed, *bits))
        }
        DynSolType::Array(inner) => {
            let arr = v.as_array().ok_or("array must be JSON array")?;
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                out.push(json_to_sol(inner, x)?);
            }
            Ok(DynSolValue::Array(out))
        }
        DynSolType::FixedArray(inner, n) => {
            let arr = v.as_array().ok_or("fixed array must be JSON array")?;
            if arr.len() != *n {
                return Err(format!("expected {} items, got {}", n, arr.len()));
            }
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                out.push(json_to_sol(inner, x)?);
            }
            Ok(DynSolValue::FixedArray(out))
        }
        DynSolType::Tuple(types) => {
            let arr = v.as_array().ok_or("tuple must be JSON array")?;
            if arr.len() != types.len() {
                return Err(format!(
                    "expected {} fields, got {}",
                    types.len(),
                    arr.len()
                ));
            }
            let mut out = Vec::with_capacity(arr.len());
            for (t, x) in types.iter().zip(arr.iter()) {
                out.push(json_to_sol(t, x)?);
            }
            Ok(DynSolValue::Tuple(out))
        }
        other => Err(format!("unsupported type {:?}", other)),
    }
}

fn decode_hex_str(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(|e| e.to_string())
}

pub fn sol_to_json(v: &DynSolValue) -> serde_json::Value {
    use serde_json::Value;
    match v {
        DynSolValue::Address(a) => Value::String(a.to_checksum(None)),
        DynSolValue::Bool(b) => Value::Bool(*b),
        DynSolValue::String(s) => Value::String(s.clone()),
        DynSolValue::Bytes(b) => Value::String(format!("0x{}", hex::encode(b))),
        DynSolValue::FixedBytes(b, n) => Value::String(format!("0x{}", hex::encode(&b[..*n]))),
        DynSolValue::Uint(u, _) => Value::String(u.to_string()),
        DynSolValue::Int(i, _) => Value::String(i.to_string()),
        DynSolValue::Array(a) | DynSolValue::FixedArray(a) => {
            Value::Array(a.iter().map(sol_to_json).collect())
        }
        DynSolValue::Tuple(t) => Value::Array(t.iter().map(sol_to_json).collect()),
        DynSolValue::Function(_) => Value::String("function(unsupported)".into()),
        DynSolValue::CustomStruct { tuple, .. } => {
            Value::Array(tuple.iter().map(sol_to_json).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_encode_transfer() {
        // transfer(address,uint256) — selector 0xa9059cbb
        let to = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let amt = "1000000000000000000";
        let calldata =
            abi_encode("transfer(address,uint256)", &serde_json::json!([to, amt])).unwrap();
        assert!(calldata.starts_with("0xa9059cbb"));
        // 4 + 32 + 32 = 68 bytes -> 136 hex chars + 2 for `0x`
        assert_eq!(calldata.len(), 138);
    }

    #[test]
    fn abi_encode_tuple_no_selector() {
        // (uint256,address) raw tuple
        let addr = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let out = abi_encode("(uint256,address)", &serde_json::json!(["1", addr])).unwrap();
        assert!(out.starts_with("0x"));
        // 32 bytes + 32 bytes = 64 -> 128 hex chars
        assert_eq!(out.len(), 130);
    }

    #[test]
    fn abi_decode_round_trip() {
        let to = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let amt = "1234567890";
        let cd = abi_encode("(address,uint256)", &serde_json::json!([to, amt])).unwrap();
        let bytes = hex::decode(cd.strip_prefix("0x").unwrap()).unwrap();
        let decoded = abi_decode(&["address", "uint256"], &bytes).unwrap();
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap().to_lowercase(), to.to_lowercase());
        assert_eq!(arr[1].as_str().unwrap(), amt);
    }

    #[test]
    fn eip712_hash_canonical_mail() {
        // Canonical EIP-712 Mail example, hash is well-known.
        let json = serde_json::json!({
            "domain": {},
            "types": {
                "EIP712Domain": [],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        });
        let h = eip712_hash(&json.to_string()).unwrap();
        assert_eq!(
            h,
            "0x25c3d40a39e639a4d0b6e4d2ace5e1281e039c88494d97d8d08f99a6ea75d775"
        );
    }
}
