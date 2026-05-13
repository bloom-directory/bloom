//! ABI-driven decoder. Walks the verified contract's `errors` map looking
//! for a 4-byte selector match and decodes the payload via
//! [`alloy_dyn_abi`]. Independent of the actual ABI source via the
//! [`AbiSource`] trait.

use std::sync::Arc;

use alloy::primitives::Bytes;
use alloy_dyn_abi::{DynSolType, Specifier};
use async_trait::async_trait;

use crate::{
    AbiSource, DecodeContext, DecodeSource, DecodedRevert, RevertDecoder, dyn_value_to_json,
    selector_of,
};

/// Decoder that consults a verified-contract ABI fetched via
/// [`AbiSource`]. Always second in the chain after [`super::BuiltinDecoder`].
#[derive(Clone)]
pub struct EtherscanAbiDecoder {
    source: Arc<dyn AbiSource>,
}

impl EtherscanAbiDecoder {
    pub fn new(source: Arc<dyn AbiSource>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl RevertDecoder for EtherscanAbiDecoder {
    fn name(&self) -> &'static str {
        "etherscan_abi"
    }

    async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert> {
        let Some(to) = ctx.to else {
            tracing::debug!("etherscan_abi.no_to_address");
            return None;
        };
        let Some(sel) = selector_of(&ctx.returndata) else {
            tracing::debug!(len = ctx.returndata.len(), "etherscan_abi.no_selector");
            return None;
        };
        let sel_hex = format!("0x{}", hex::encode(sel));
        let Some(abi) = self.source.abi_for(ctx.chain_id, to).await else {
            tracing::debug!(%to, selector = %sel_hex, "etherscan_abi.no_abi");
            return None;
        };
        for err in abi.errors() {
            if err.selector() == sel {
                let payload = &ctx.returndata[4..];
                let types: Result<Vec<DynSolType>, _> =
                    err.inputs.iter().map(|p| p.resolve()).collect();
                let types = match types {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!(error = %e, name = %err.name, "abi_decode.bad_inputs");
                        return None;
                    }
                };
                let values = match decode_inputs(payload, &types) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, name = %err.name, "abi_decode.payload_failed");
                        return None;
                    }
                };
                let args = values.iter().map(dyn_value_to_json).collect::<Vec<_>>();
                let signature = err.signature();
                let message = render_message(&err.name, &args);
                return Some(DecodedRevert {
                    selector: Some(sel),
                    name: Some(err.name.clone()),
                    signature: Some(signature),
                    args,
                    message: Some(message),
                    raw: Bytes::copy_from_slice(&ctx.returndata),
                    source: DecodeSource::EtherscanAbi,
                });
            }
        }
        let abi_error_names: Vec<&str> = abi.errors().map(|e| e.name.as_str()).collect();
        tracing::debug!(
            %to,
            selector = %sel_hex,
            abi_errors = abi_error_names.len(),
            known = ?abi_error_names,
            "etherscan_abi.selector_not_in_abi"
        );
        None
    }
}

/// Decode `payload` against a sequence of expected types. We can't go via
/// `Error::abi_decode_input` directly because that's wired to the
/// alloy-dyn-abi `JsonAbiExt` trait; we keep it explicit here so we can
/// avoid the typeck branch and surface clearer error logs.
fn decode_inputs(
    payload: &[u8],
    types: &[DynSolType],
) -> Result<Vec<alloy_dyn_abi::DynSolValue>, alloy_dyn_abi::Error> {
    let tuple = DynSolType::Tuple(types.to_vec());
    let value = tuple.abi_decode_params(payload)?;
    Ok(value.as_tuple().map(|s| s.to_vec()).unwrap_or_default())
}

/// Best-effort one-line summary: `Name(arg0, arg1, ...)` with each arg's
/// JSON rendering (strings unquoted, numbers as digits).
fn render_message(name: &str, args: &[serde_json::Value]) -> String {
    let parts: Vec<String> = args.iter().map(render_arg).collect();
    format!("{name}({})", parts.join(", "))
}

fn render_arg(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256, address};
    use alloy_dyn_abi::{DynSolValue, JsonAbiExt as _};
    use serde_json::json;

    /// Stub AbiSource that hands back a hand-crafted JsonAbi.
    struct StubAbi(alloy::json_abi::JsonAbi);

    #[async_trait]
    impl AbiSource for StubAbi {
        async fn abi_for(
            &self,
            _chain_id: u64,
            _addr: Address,
        ) -> Option<alloy::json_abi::JsonAbi> {
            Some(self.0.clone())
        }
    }

    /// Build a JsonAbi containing a single custom error and encode a
    /// returndata payload from a matching set of values.
    fn fixture() -> (alloy::json_abi::JsonAbi, Vec<u8>) {
        let abi_json = serde_json::json!([
            {
                "type": "error",
                "name": "InsufficientAllowance",
                "inputs": [
                    { "name": "spender", "type": "address" },
                    { "name": "needed", "type": "uint256" },
                    { "name": "actual", "type": "uint256" }
                ]
            }
        ]);
        let abi: alloy::json_abi::JsonAbi = serde_json::from_value(abi_json).unwrap();
        let err = abi.error("InsufficientAllowance").unwrap()[0].clone();
        let values = vec![
            DynSolValue::Address(address!("0x1111111111111111111111111111111111111111")),
            DynSolValue::Uint(U256::from(1000u64), 256),
            DynSolValue::Uint(U256::from(500u64), 256),
        ];
        let raw = err.abi_encode_input(&values).unwrap();
        (abi, raw)
    }

    #[tokio::test]
    async fn decodes_known_selector_into_args() {
        let (abi, raw) = fixture();
        let decoder = EtherscanAbiDecoder::new(Arc::new(StubAbi(abi)));
        let ctx = DecodeContext {
            returndata: raw.into(),
            to: Some(Address::ZERO),
            chain_id: 1,
        };
        let out = decoder.try_decode(&ctx).await.expect("should decode");
        assert_eq!(out.name.as_deref(), Some("InsufficientAllowance"));
        assert_eq!(
            out.signature.as_deref(),
            Some("InsufficientAllowance(address,uint256,uint256)")
        );
        assert_eq!(
            out.args,
            vec![
                json!("0x1111111111111111111111111111111111111111"),
                json!("1000"),
                json!("500"),
            ]
        );
        assert_eq!(out.source, DecodeSource::EtherscanAbi);
    }

    #[tokio::test]
    async fn no_to_address_yields_none() {
        let (abi, raw) = fixture();
        let decoder = EtherscanAbiDecoder::new(Arc::new(StubAbi(abi)));
        let ctx = DecodeContext {
            returndata: raw.into(),
            to: None,
            chain_id: 1,
        };
        assert!(decoder.try_decode(&ctx).await.is_none());
    }

    #[tokio::test]
    async fn unknown_selector_yields_none() {
        let (abi, _) = fixture();
        let decoder = EtherscanAbiDecoder::new(Arc::new(StubAbi(abi)));
        let raw = vec![0xab, 0xcd, 0xef, 0x12, 0, 0, 0, 0];
        let ctx = DecodeContext {
            returndata: raw.into(),
            to: Some(Address::ZERO),
            chain_id: 1,
        };
        assert!(decoder.try_decode(&ctx).await.is_none());
    }
}
