//! Pure helper tools used by the `tools/` VFS subtree.
//!
//! All functions are dependency-free and side-effect-free; no RPC, no
//! filesystem. They are exposed as `tools/keccak`, `tools/abi/*`, etc.

#![forbid(unsafe_code)]

use alloy::dyn_abi::{DynSolType, JsonAbiExt};
use alloy::json_abi::Function;
use alloy::primitives::{Address, B256, keccak256};
use thiserror::Error;

pub mod abi;
pub mod encoding;
pub mod hashing;
pub mod rlp;

pub use abi::{abi_decode, abi_encode, eip712_hash};
pub use encoding::{base64_decode, base64_encode, hex_decode, hex_encode};
pub use hashing::{blake3_hex, sha256_hex};
pub use rlp::{rlp_decode, rlp_encode};

/// Error type for the new generation of tool helpers (abi, rlp, hex,
/// base64, eip-712, ...). The legacy [`ToolError`] type continues to be
/// re-exported for the existing `keccak_hex`, `selector`, `checksum`,
/// `encode_call`, `decode_call` helpers.
#[derive(Debug, Error)]
pub enum ToolsError {
    #[error("hex error: {0}")]
    Hex(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("abi: {0}")]
    Abi(String),
}

impl From<ToolError> for ToolsError {
    fn from(e: ToolError) -> Self {
        match e {
            ToolError::Hex(s) => ToolsError::Hex(s),
            ToolError::Invalid(s) => ToolsError::Invalid(s),
            ToolError::Abi(s) => ToolsError::Abi(s),
        }
    }
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("hex error: {0}")]
    Hex(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("abi: {0}")]
    Abi(String),
}

/// Keccak-256 of arbitrary bytes, returned as 0x-prefixed hex.
pub fn keccak_hex(input: &[u8]) -> String {
    let h: B256 = keccak256(input);
    format!("0x{}", hex::encode(h))
}

/// EIP-55 checksum for an address. Accepts 0x-prefixed hex; rejects
/// non-20-byte input.
pub fn checksum(addr: &str) -> Result<String, ToolError> {
    let a: Address = addr
        .parse()
        .map_err(|e: alloy::hex::FromHexError| ToolError::Hex(e.to_string()))?;
    Ok(a.to_checksum(None))
}

/// 4-byte function selector for a Solidity-style signature
/// (e.g. `transfer(address,uint256)`).
pub fn selector(signature: &str) -> String {
    let h = keccak256(signature.as_bytes());
    format!("0x{}", hex::encode(&h[..4]))
}

/// Encode a function call from a Solidity-style signature + JSON args.
///
/// Example: `encode_call("transfer(address,uint256)", json!(["0x...", "1"]))`
pub fn encode_call(signature: &str, args: &serde_json::Value) -> Result<String, ToolError> {
    let func = Function::parse(signature).map_err(|e| ToolError::Abi(e.to_string()))?;
    let arg_array = args
        .as_array()
        .ok_or_else(|| ToolError::Invalid("args must be a JSON array".into()))?;
    if arg_array.len() != func.inputs.len() {
        return Err(ToolError::Invalid(format!(
            "expected {} args, got {}",
            func.inputs.len(),
            arg_array.len()
        )));
    }
    let mut sol_values = Vec::with_capacity(arg_array.len());
    for (i, (param, arg)) in func.inputs.iter().zip(arg_array.iter()).enumerate() {
        let ty: DynSolType = param
            .ty
            .parse()
            .map_err(|e: alloy::dyn_abi::Error| ToolError::Abi(format!("input {i}: {e}")))?;
        let value =
            abi::json_to_sol(&ty, arg).map_err(|e| ToolError::Abi(format!("input {i}: {e}")))?;
        sol_values.push(value);
    }
    let encoded = func
        .abi_encode_input(&sol_values)
        .map_err(|e| ToolError::Abi(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(encoded)))
}

/// Decode calldata using a Solidity-style signature.
pub fn decode_call(signature: &str, calldata_hex: &str) -> Result<serde_json::Value, ToolError> {
    let func = Function::parse(signature).map_err(|e| ToolError::Abi(e.to_string()))?;
    let bytes = decode_hex(calldata_hex)?;
    if bytes.len() < 4 {
        return Err(ToolError::Invalid("calldata too short for selector".into()));
    }
    let selector_expected = func.selector();
    if bytes[..4] != selector_expected[..] {
        return Err(ToolError::Abi(format!(
            "selector {} != expected {}",
            hex::encode(&bytes[..4]),
            hex::encode(selector_expected)
        )));
    }
    let decoded = func
        .abi_decode_input(&bytes[4..])
        .map_err(|e| ToolError::Abi(e.to_string()))?;
    let mut out = Vec::with_capacity(decoded.len());
    for (param, value) in func.inputs.iter().zip(decoded.iter()) {
        out.push(serde_json::json!({
            "name": param.name,
            "type": param.ty,
            "value": abi::sol_to_json(value),
        }));
    }
    Ok(serde_json::Value::Array(out))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ToolError> {
    let s = s.trim().trim_start_matches("0x");
    hex::decode(s).map_err(|e| ToolError::Hex(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_known_vector() {
        // keccak("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            keccak_hex(b""),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn checksum_known() {
        let lower = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let checksummed = checksum(lower).unwrap();
        assert_eq!(checksummed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    }

    #[test]
    fn selector_transfer() {
        // bytes4(keccak256("transfer(address,uint256)")) = 0xa9059cbb
        assert_eq!(selector("transfer(address,uint256)"), "0xa9059cbb");
    }

    #[test]
    fn encode_decode_transfer() {
        let to = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let amount = "1000000000000000000"; // 1e18
        let calldata = encode_call(
            "transfer(address,uint256)",
            &serde_json::json!([to, amount]),
        )
        .unwrap();
        assert!(calldata.starts_with("0xa9059cbb"));
        let decoded = decode_call("transfer(address,uint256)", &calldata).unwrap();
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0]["value"].as_str().unwrap().to_lowercase(),
            to.to_lowercase()
        );
        assert_eq!(arr[1]["value"].as_str().unwrap(), amount);
    }
}
