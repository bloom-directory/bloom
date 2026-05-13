//! Decoder for Solidity's two well-known reverts: `Error(string)` and
//! `Panic(uint256)`. Always sits at the head of the chain so we can
//! short-circuit on these without ever hitting the network.

use alloy::primitives::Bytes;
use alloy::sol_types::SolError;
use async_trait::async_trait;

use crate::{DecodeContext, DecodeSource, DecodedRevert, RevertDecoder, selector_of};

alloy::sol! {
    #[allow(missing_docs)]
    error Error(string);
    #[allow(missing_docs)]
    error Panic(uint256);
}

const SELECTOR_ERROR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
const SELECTOR_PANIC: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

/// Resolve a Solidity panic code to a human-readable reason. Codes come
/// from the Solidity docs; unknown codes get a hex fallback.
fn panic_reason(code: u64) -> String {
    match code {
        0x00 => "generic panic".to_string(),
        0x01 => "assertion failure (assert(false))".to_string(),
        0x11 => "arithmetic overflow or underflow".to_string(),
        0x12 => "division or modulo by zero".to_string(),
        0x21 => "tried to convert an out-of-range value into an enum".to_string(),
        0x22 => "accessed an incorrectly encoded storage byte array".to_string(),
        0x31 => ".pop() on an empty array".to_string(),
        0x32 => "array index out of bounds".to_string(),
        0x41 => "allocated too much memory or created an array that's too large".to_string(),
        0x51 => "called a zero-initialised internal function variable".to_string(),
        other => format!("panic(0x{other:02x})"),
    }
}

#[derive(Debug, Default, Clone)]
pub struct BuiltinDecoder;

impl BuiltinDecoder {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RevertDecoder for BuiltinDecoder {
    fn name(&self) -> &'static str {
        "builtin"
    }

    async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert> {
        let raw = &ctx.returndata;
        if raw.is_empty() {
            return Some(DecodedRevert::empty());
        }
        let sel = selector_of(raw)?;

        if sel == SELECTOR_ERROR {
            let decoded = Error::abi_decode(raw).ok()?;
            return Some(DecodedRevert {
                selector: Some(SELECTOR_ERROR),
                name: Some("Error".to_string()),
                signature: Some("Error(string)".to_string()),
                args: vec![serde_json::Value::String(decoded.0.clone())],
                message: Some(decoded.0),
                raw: Bytes::copy_from_slice(raw),
                source: DecodeSource::Builtin,
            });
        }

        if sel == SELECTOR_PANIC {
            let decoded = Panic::abi_decode(raw).ok()?;
            let code = decoded.0;
            let code_u64 = if code.bit_len() <= 64 {
                code.try_into().unwrap_or(u64::MAX)
            } else {
                u64::MAX
            };
            let reason = panic_reason(code_u64);
            return Some(DecodedRevert {
                selector: Some(SELECTOR_PANIC),
                name: Some("Panic".to_string()),
                signature: Some("Panic(uint256)".to_string()),
                args: vec![serde_json::Value::String(code.to_string())],
                message: Some(reason),
                raw: Bytes::copy_from_slice(raw),
                source: DecodeSource::Builtin,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    fn ctx(raw: Vec<u8>) -> DecodeContext {
        DecodeContext {
            returndata: raw.into(),
            to: None,
            chain_id: 1,
        }
    }

    #[tokio::test]
    async fn empty_returndata_yields_empty_marker() {
        let d = BuiltinDecoder::new();
        let out = d.try_decode(&ctx(Vec::new())).await.unwrap();
        assert!(out.selector.is_none());
        assert_eq!(out.source, DecodeSource::Builtin);
        assert_eq!(out.message.as_deref(), Some("reverted without reason"));
    }

    #[tokio::test]
    async fn error_string_round_trip() {
        let encoded = Error("Hello".to_string()).abi_encode();
        let d = BuiltinDecoder::new();
        let out = d.try_decode(&ctx(encoded)).await.unwrap();
        assert_eq!(out.signature.as_deref(), Some("Error(string)"));
        assert_eq!(out.message.as_deref(), Some("Hello"));
        assert_eq!(out.args, vec![serde_json::Value::String("Hello".into())]);
        assert_eq!(out.source, DecodeSource::Builtin);
    }

    #[tokio::test]
    async fn panic_arithmetic_decoded() {
        let encoded = Panic(U256::from(0x11u64)).abi_encode();
        let d = BuiltinDecoder::new();
        let out = d.try_decode(&ctx(encoded)).await.unwrap();
        assert_eq!(out.name.as_deref(), Some("Panic"));
        assert_eq!(out.signature.as_deref(), Some("Panic(uint256)"));
        assert_eq!(out.args, vec![serde_json::Value::String("17".into())]);
        assert_eq!(
            out.message.as_deref(),
            Some("arithmetic overflow or underflow")
        );
    }

    #[tokio::test]
    async fn panic_unknown_code_falls_back_to_hex() {
        let encoded = Panic(U256::from(0xabu64)).abi_encode();
        let d = BuiltinDecoder::new();
        let out = d.try_decode(&ctx(encoded)).await.unwrap();
        assert_eq!(out.message.as_deref(), Some("panic(0xab)"));
    }

    #[tokio::test]
    async fn unknown_selector_yields_none() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
        let d = BuiltinDecoder::new();
        assert!(d.try_decode(&ctx(raw)).await.is_none());
    }

    #[tokio::test]
    async fn truncated_returndata_yields_none() {
        // 3 bytes — not enough for a selector.
        let d = BuiltinDecoder::new();
        assert!(d.try_decode(&ctx(vec![0x08, 0xc3, 0x79])).await.is_none());
    }
}
