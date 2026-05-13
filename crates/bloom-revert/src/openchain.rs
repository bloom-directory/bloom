//! Decoder backed by the public Openchain selector database.
//!
//! Hits `api.openchain.xyz/signature-database/v1/lookup?function=0x<sel>`
//! with the 4-byte returndata selector. The same `function=` endpoint is
//! the one heimdall-rs uses for resolving error selectors (errors and
//! functions share the 4-byte selector space and the same database
//! bucket). When the lookup yields one or more candidate signatures we
//! pick the highest-scoring (i.e. least-likely-to-be-a-collision) one
//! and decode the returndata payload against it via `alloy_dyn_abi`.
//!
//! Network failures and lookup misses both return `None` so the chain
//! can fall through to the next decoder.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::Bytes;
use alloy_dyn_abi::DynSolType;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    DecodeContext, DecodeSource, DecodedRevert, RevertDecoder, dyn_value_to_json, fmt_selector,
    selector_of,
};

const DEFAULT_BASE_URL: &str = "https://api.openchain.xyz";
const REQUEST_TIMEOUT_SECS: u64 = 8;

/// Cached lookup outcome. `Hit` carries the signature string that was
/// chosen at resolution time; `Miss` records that the selector is known
/// to be absent so we don't re-hit the endpoint on repeated reverts.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedLookup {
    Hit { signature: String },
    Miss,
}

/// Decoder that consults the Openchain selector database.
///
/// Always-on (no feature flag); sits after the Etherscan ABI decoder so
/// verified ABIs win on the contracts we have one for.
#[derive(Clone)]
pub struct OpenchainDecoder {
    http: reqwest::Client,
    base_url: String,
    cache: Arc<RwLock<HashMap<[u8; 4], CachedLookup>>>,
}

impl OpenchainDecoder {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            http: client,
            base_url: DEFAULT_BASE_URL.to_string(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Override the base URL (tests). Trailing slashes are stripped so
    /// path concatenation stays clean.
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }
}

impl Default for OpenchainDecoder {
    fn default() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();
        Self::new(http)
    }
}

#[async_trait]
impl RevertDecoder for OpenchainDecoder {
    fn name(&self) -> &'static str {
        "openchain"
    }

    async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert> {
        let sel = selector_of(&ctx.returndata)?;

        let cached = self.cache.read().await.get(&sel).cloned();
        let signature = match cached {
            Some(CachedLookup::Hit { signature }) => signature,
            Some(CachedLookup::Miss) => return None,
            None => match self.lookup(sel).await {
                Ok(Some(sig)) => {
                    self.cache.write().await.insert(
                        sel,
                        CachedLookup::Hit {
                            signature: sig.clone(),
                        },
                    );
                    sig
                }
                Ok(None) => {
                    self.cache.write().await.insert(sel, CachedLookup::Miss);
                    return None;
                }
                Err(e) => {
                    tracing::debug!(error = %e, selector = %fmt_selector(&sel), "openchain.lookup_failed");
                    return None;
                }
            },
        };

        decode_with_signature(&signature, sel, &ctx.returndata)
    }
}

impl OpenchainDecoder {
    /// Hit the openchain endpoint and return the highest-scoring signature
    /// string for `selector`, or `None` when the database has no entry.
    async fn lookup(&self, selector: [u8; 4]) -> Result<Option<String>, reqwest::Error> {
        let sel_hex = hex::encode(selector);
        let url = format!(
            "{}/signature-database/v1/lookup?function=0x{}&filter=true",
            self.base_url, sel_hex
        );
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            tracing::debug!(status = %resp.status(), "openchain.non_200");
            return Ok(None);
        }
        let value: serde_json::Value = resp.json().await?;
        Ok(pick_signature(&value, &sel_hex))
    }
}

/// Drill into the openchain response and pull the best signature string
/// for `sel_hex`. Tries the `function` bucket first (errors live there),
/// then falls back to `event` for completeness.
fn pick_signature(value: &serde_json::Value, sel_hex: &str) -> Option<String> {
    let key = format!("0x{sel_hex}");
    let result = value.get("result")?;
    let arr = result
        .get("function")
        .and_then(|f| f.get(&key))
        .and_then(|x| x.as_array())
        .or_else(|| {
            result
                .get("event")
                .and_then(|e| e.get(&key))
                .and_then(|x| x.as_array())
        })?;

    // openchain's `filter=true` returns candidates already de-duplicated
    // and ranked least-likely-collision-first; take the first that has a
    // parseable name.
    for entry in arr {
        if let Some(name) = entry.get("name").and_then(|n| n.as_str()) {
            return Some(name.to_string());
        }
    }
    None
}

/// Parse `signature` (e.g. `"InsufficientAllowance(address,uint256,uint256)"`)
/// into its components, decode the payload after the selector, and produce
/// a [`DecodedRevert`]. Returns `None` when the signature is malformed or
/// the payload doesn't decode.
fn decode_with_signature(signature: &str, selector: [u8; 4], raw: &Bytes) -> Option<DecodedRevert> {
    let (name, params) = split_signature(signature)?;
    let types = parse_types(params)?;
    let payload = if raw.len() >= 4 { &raw[4..] } else { &[] };
    let tuple = DynSolType::Tuple(types);
    let value = match tuple.abi_decode_params(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, signature, "openchain.decode_failed");
            return None;
        }
    };
    let values = value.as_tuple().map(|s| s.to_vec()).unwrap_or_default();
    let args: Vec<serde_json::Value> = values.iter().map(dyn_value_to_json).collect();
    let message = render_message(name, &args);
    Some(DecodedRevert {
        selector: Some(selector),
        name: Some(name.to_string()),
        signature: Some(signature.to_string()),
        args,
        message: Some(message),
        raw: Bytes::copy_from_slice(raw),
        source: DecodeSource::Openchain,
    })
}

/// Pull the name and the comma-separated parameter list out of a
/// canonical signature, e.g. `"Foo(address,uint256)"` ⇒ `("Foo",
/// "address,uint256")`. Returns `None` if the parens are missing or
/// unbalanced.
fn split_signature(sig: &str) -> Option<(&str, &str)> {
    let open = sig.find('(')?;
    if !sig.ends_with(')') {
        return None;
    }
    let name = &sig[..open];
    let params = &sig[open + 1..sig.len() - 1];
    if name.is_empty() {
        return None;
    }
    Some((name, params))
}

/// Split a parameter list at top-level commas (i.e. ignoring commas
/// nested inside `(...)` for tuples) and parse each element as a
/// [`DynSolType`]. An empty input yields an empty Vec.
fn parse_types(params: &str) -> Option<Vec<DynSolType>> {
    let params = params.trim();
    if params.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let bytes = params.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                let part = params[start..i].trim();
                out.push(DynSolType::parse(part).ok()?);
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = params[start..].trim();
    out.push(DynSolType::parse(last).ok()?);
    Some(out)
}

fn render_message(name: &str, args: &[serde_json::Value]) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect();
    format!("{name}({})", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};
    use alloy_dyn_abi::DynSolValue;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ctx_for(raw: Vec<u8>) -> DecodeContext {
        DecodeContext {
            returndata: raw.into(),
            to: None,
            chain_id: 1,
        }
    }

    /// Encode `values` as ABI-tuple parameters (the layout used after
    /// the 4-byte selector in revert returndata). Mirrors the encoding
    /// path in `alloy::sol_types::SolError::abi_encode_input`.
    fn encode_params(values: &[DynSolValue]) -> Vec<u8> {
        let tuple = DynSolValue::Tuple(values.to_vec());
        tuple.abi_encode_params()
    }

    #[tokio::test]
    async fn lookup_hit_decodes_args() {
        let server = MockServer::start().await;
        let body = json!({
            "ok": true,
            "result": {
                "event": {},
                "function": {
                    "0xa1b2c3d4": [
                        { "name": "InsufficientAllowance(address,uint256,uint256)", "filtered": false }
                    ]
                }
            }
        });
        Mock::given(method("GET"))
            .and(path("/signature-database/v1/lookup"))
            .and(query_param("function", "0xa1b2c3d4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        // Build a returndata: selector || encoded(address, uint256, uint256)
        let mut raw = vec![0xa1, 0xb2, 0xc3, 0xd4];
        let payload = encode_params(&[
            DynSolValue::Address(address!("0x1111111111111111111111111111111111111111")),
            DynSolValue::Uint(U256::from(1000u64), 256),
            DynSolValue::Uint(U256::from(500u64), 256),
        ]);
        raw.extend_from_slice(&payload);

        let dec = OpenchainDecoder::default().with_base_url(server.uri());
        let out = dec.try_decode(&ctx_for(raw)).await.expect("hit");
        assert_eq!(out.source, DecodeSource::Openchain);
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
    }

    #[tokio::test]
    async fn lookup_miss_returns_none() {
        let server = MockServer::start().await;
        let body = json!({
            "ok": true,
            "result": {
                "event": {},
                "function": { "0xdeadbeef": [] }
            }
        });
        Mock::given(method("GET"))
            .and(path("/signature-database/v1/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        let dec = OpenchainDecoder::default().with_base_url(server.uri());
        assert!(dec.try_decode(&ctx_for(raw)).await.is_none());
    }

    #[tokio::test]
    async fn http_error_returns_none_does_not_panic() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/signature-database/v1/lookup"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let raw = vec![0x12, 0x34, 0x56, 0x78];
        let dec = OpenchainDecoder::default().with_base_url(server.uri());
        assert!(dec.try_decode(&ctx_for(raw)).await.is_none());
    }

    #[tokio::test]
    async fn truncated_returndata_yields_none() {
        let dec = OpenchainDecoder::default();
        assert!(dec.try_decode(&ctx_for(vec![0x12, 0x34])).await.is_none());
        assert!(dec.try_decode(&ctx_for(vec![])).await.is_none());
    }

    #[tokio::test]
    async fn cache_hit_avoids_second_request() {
        let server = MockServer::start().await;
        let body = json!({
            "ok": true,
            "result": {
                "event": {},
                "function": {
                    "0xaabbccdd": [
                        { "name": "Boom(uint256)", "filtered": false }
                    ]
                }
            }
        });
        Mock::given(method("GET"))
            .and(path("/signature-database/v1/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let mut raw = vec![0xaa, 0xbb, 0xcc, 0xdd];
        raw.extend_from_slice(&encode_params(&[DynSolValue::Uint(U256::from(7u64), 256)]));

        let dec = OpenchainDecoder::default().with_base_url(server.uri());
        let _ = dec.try_decode(&ctx_for(raw.clone())).await.expect("hit");
        let _ = dec.try_decode(&ctx_for(raw.clone())).await.expect("hit");

        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            1,
            "second decode must serve from cache; got {} requests",
            received.len()
        );
    }

    #[tokio::test]
    async fn cache_negative_lookup_avoids_second_request() {
        let server = MockServer::start().await;
        let body = json!({
            "ok": true,
            "result": {
                "event": {},
                "function": { "0xfeedface": [] }
            }
        });
        Mock::given(method("GET"))
            .and(path("/signature-database/v1/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let raw = vec![0xfe, 0xed, 0xfa, 0xce];
        let dec = OpenchainDecoder::default().with_base_url(server.uri());
        assert!(dec.try_decode(&ctx_for(raw.clone())).await.is_none());
        assert!(dec.try_decode(&ctx_for(raw)).await.is_none());
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
    }

    #[test]
    fn parse_types_handles_nested_tuples() {
        let t = parse_types("(uint256,address),bytes32").expect("parse");
        assert_eq!(t.len(), 2);
        match &t[0] {
            DynSolType::Tuple(inner) => assert_eq!(inner.len(), 2),
            other => panic!("expected tuple, got {other:?}"),
        }
    }

    #[test]
    fn split_signature_round_trip() {
        let (n, p) = split_signature("Boom(uint256)").unwrap();
        assert_eq!(n, "Boom");
        assert_eq!(p, "uint256");
        let (n, p) = split_signature("NoArgs()").unwrap();
        assert_eq!(n, "NoArgs");
        assert_eq!(p, "");
    }
}
