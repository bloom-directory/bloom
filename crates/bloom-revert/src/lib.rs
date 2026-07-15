//! Tiered EVM revert returndata decoder.
//!
//! Surfaces a [`DecoderChain`] that walks a list of [`RevertDecoder`]s in
//! order, returning the first one that matches the selector. Builtin
//! decoding (Solidity `Error(string)` / `Panic(uint256)`) is always tried
//! first; richer decoders (ABI-driven, public selector lookup, bytecode
//! decompile) plug in by being pushed onto the chain.
//!
//! Stages 4 and 5 (Openchain selector lookup, Heimdall decompile) are
//! reserved as [`DecodeSource`] variants but not implemented here — the
//! second-pass agent appends decoder impls without altering core types.

#![forbid(unsafe_code)]

use std::sync::Arc;

use alloy::primitives::{Address, Bytes};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

mod abi;
mod builtin;
mod chain;
mod etherscan;
mod openchain;

#[cfg(feature = "bytecode-decompile")]
mod heimdall;

pub use abi::{AbiSource, EtherscanAbiSource};
pub use builtin::BuiltinDecoder;
pub use chain::DecoderChain;
pub use etherscan::EtherscanAbiDecoder;
pub use openchain::OpenchainDecoder;

#[cfg(feature = "bytecode-decompile")]
pub use heimdall::{BytecodeSource, ChainRegistryBytecodeSource, HeimdallDecompileDecoder};

/// Source attribution for a decoded revert. Variants for stages 4 and 5
/// are reserved here so decoders added later can populate them without
/// touching this crate's public types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeSource {
    Builtin,
    EtherscanAbi,
    Openchain,
    HeimdallDecompile,
    Unknown,
}

/// Decoded revert returndata.
///
/// The shape is intentionally JSON-friendly so the VFS can serialise it
/// directly. `args` carries one entry per decoded ABI input, rendered
/// with the same conventions as `serde_json` output for `DynSolValue`s
/// (addresses as `0x…` strings, large integers as decimal strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedRevert {
    /// 4-byte selector when one is present (i.e. `raw.len() >= 4`). Empty
    /// returndata or returndata shorter than 4 bytes leaves this `None`.
    #[serde(serialize_with = "ser_selector", deserialize_with = "de_selector")]
    pub selector: Option<[u8; 4]>,
    /// Error name (e.g. `"Error"`, `"Panic"`, or a custom error name).
    pub name: Option<String>,
    /// Canonical signature, e.g. `"Error(string)"`.
    pub signature: Option<String>,
    /// One entry per decoded input.
    pub args: Vec<serde_json::Value>,
    /// Human-readable summary; for `Error(string)` this is the message,
    /// for `Panic(uint256)` it's the standard reason text.
    pub message: Option<String>,
    /// Original returndata bytes.
    pub raw: Bytes,
    /// Which decoder produced the match.
    pub source: DecodeSource,
}

impl DecodedRevert {
    /// Returndata that's missing entirely (the contract reverted with no
    /// reason). Always sourced from [`BuiltinDecoder`].
    pub fn empty() -> Self {
        Self {
            selector: None,
            name: None,
            signature: None,
            args: Vec::new(),
            message: Some("reverted without reason".to_string()),
            raw: Bytes::new(),
            source: DecodeSource::Builtin,
        }
    }

    /// Build a fall-through result when no decoder matched. Carries the
    /// selector so the caller can still display something useful.
    pub fn unknown(raw: Bytes) -> Self {
        let selector = if raw.len() >= 4 {
            let mut s = [0u8; 4];
            s.copy_from_slice(&raw[..4]);
            Some(s)
        } else {
            None
        };
        Self {
            selector,
            name: None,
            signature: None,
            args: Vec::new(),
            message: None,
            raw,
            source: DecodeSource::Unknown,
        }
    }
}

fn ser_selector<S: serde::Serializer>(v: &Option<[u8; 4]>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(b) => s.serialize_str(&format!("0x{}", hex::encode(b))),
        None => s.serialize_none(),
    }
}

fn de_selector<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<[u8; 4]>, D::Error> {
    use serde::de::Error;
    let v: Option<String> = Option::deserialize(d)?;
    let Some(s) = v else { return Ok(None) };
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(D::Error::custom)?;
    if bytes.len() != 4 {
        return Err(D::Error::custom("selector must be 4 bytes"));
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

/// Inputs to a single decode attempt.
#[derive(Debug, Clone)]
pub struct DecodeContext {
    /// The raw revert returndata captured via `eth_call` replay.
    pub returndata: Bytes,
    /// `to` of the original tx, used by ABI-driven decoders to fetch a
    /// per-contract error catalog. May be `None` for contract-creation
    /// reverts; ABI decoders should return `None` in that case.
    pub to: Option<Address>,
    /// Chain id for ABI-source lookups (Etherscan multichain, etc.).
    pub chain_id: u64,
}

/// One stage in the decode pipeline.
///
/// Implementors should return `Some` only when the returndata matches a
/// known signature; on uncertain matches return `None` so the chain can
/// fall through. Errors are *not* part of the surface — a decoder that
/// can't reach its data source (network failure, missing config) must
/// log internally and yield `None`.
#[async_trait]
pub trait RevertDecoder: Send + Sync {
    async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert>;
    fn name(&self) -> &'static str;
}

/// Convenience: decoded selector, when one is present.
pub fn selector_of(raw: &[u8]) -> Option<[u8; 4]> {
    if raw.len() < 4 {
        return None;
    }
    let mut s = [0u8; 4];
    s.copy_from_slice(&raw[..4]);
    Some(s)
}

/// Convenience: hex-format a selector for display.
pub fn fmt_selector(sel: &[u8; 4]) -> String {
    format!("0x{}", hex::encode(sel))
}

/// Render a DynSolValue as a JSON value with addresses / fixed bytes /
/// integers as strings (so 256-bit values don't get coerced to f64).
pub(crate) fn dyn_value_to_json(v: &alloy_dyn_abi::DynSolValue) -> serde_json::Value {
    use alloy_dyn_abi::DynSolValue::*;
    match v {
        Bool(b) => serde_json::Value::Bool(*b),
        Int(n, _) => serde_json::Value::String(n.to_string()),
        Uint(n, _) => serde_json::Value::String(n.to_string()),
        FixedBytes(b, n) => serde_json::Value::String(format!("0x{}", hex::encode(&b[..*n]))),
        Address(a) => serde_json::Value::String(format!("{a:#x}")),
        Function(_) => serde_json::Value::String("<function>".to_string()),
        Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
        String(s) => serde_json::Value::String(s.clone()),
        Array(xs) | FixedArray(xs) | Tuple(xs) => {
            serde_json::Value::Array(xs.iter().map(dyn_value_to_json).collect())
        }
        CustomStruct {
            prop_names, tuple, ..
        } => {
            let mut m = serde_json::Map::new();
            for (k, v) in prop_names.iter().zip(tuple.iter()) {
                m.insert(k.clone(), dyn_value_to_json(v));
            }
            serde_json::Value::Object(m)
        }
    }
}

/// Wrap a decoder for insertion into a chain.
pub fn boxed<D: RevertDecoder + 'static>(d: D) -> Arc<dyn RevertDecoder> {
    Arc::new(d)
}
