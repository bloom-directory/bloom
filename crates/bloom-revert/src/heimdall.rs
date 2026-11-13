//! Bytecode-decompile fallback decoder.
//!
//! When all earlier decoders miss (no Etherscan ABI, no Openchain hit)
//! we ask heimdall-rs to decompile the deployed runtime bytecode and
//! reconstruct an ABI. Anything in `abi.errors` whose selector matches
//! the returndata is then decoded the same way as the Etherscan path.
//!
//! heimdall pinned to rev a981d489 (HEAD of main on 2026-05-09). The
//! integration surface is `heimdall_decompiler::{decompile,
//! DecompilerArgsBuilder, DecompileResult}`; bumping the rev requires
//! re-checking those names compile.
//!
//! Decompile is best-effort — timeouts, panics, and malformed bytecode
//! all collapse to `None` so the chain falls through cleanly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use alloy::json_abi::JsonAbi;
use alloy::primitives::{Address, B256, Bytes};
use alloy_dyn_abi::{DynSolType, Specifier};
use async_trait::async_trait;
use bloom_evm::ChainRegistry;
use sha3::{Digest, Keccak256};
use tokio::sync::RwLock;

use crate::{
    DecodeContext, DecodeSource, DecodedRevert, RevertDecoder, dyn_value_to_json, fmt_selector,
    selector_of,
};

const DECOMPILE_TIMEOUT: Duration = Duration::from_secs(30);

/// Source of deployed runtime bytecode for a `(chain_id, address)`.
///
/// Pulled into a trait so unit tests can hand a static blob to the
/// decoder without standing up an RPC. The production impl is
/// [`ChainRegistryBytecodeSource`].
#[async_trait]
pub trait BytecodeSource: Send + Sync {
    async fn code_for(&self, chain_id: u64, addr: Address) -> Option<Bytes>;
}

/// Production [`BytecodeSource`] backed by the daemon's chain registry.
/// Picks the first registered client whose `chain_id` matches and calls
/// `eth_getCode` through it.
#[derive(Clone)]
pub struct ChainRegistryBytecodeSource {
    chains: ChainRegistry,
}

impl ChainRegistryBytecodeSource {
    pub fn new(chains: ChainRegistry) -> Self {
        Self { chains }
    }
}

#[async_trait]
impl BytecodeSource for ChainRegistryBytecodeSource {
    async fn code_for(&self, chain_id: u64, addr: Address) -> Option<Bytes> {
        for name in self.chains.list_names() {
            let Some(client) = self.chains.get(&name) else {
                continue;
            };
            if client.spec().chain_id != chain_id {
                continue;
            }
            match client.code(addr).await {
                Ok(code) if !code.is_empty() => return Some(Bytes::from(code)),
                Ok(_) => return None,
                Err(e) => {
                    tracing::debug!(error = %e, %addr, chain_id, "heimdall.code_for_failed");
                    return None;
                }
            }
        }
        None
    }
}

/// Decoder that decompiles deployed bytecode via heimdall-rs.
///
/// Caches the reconstructed [`JsonAbi`] on disk keyed by codehash so
/// repeated reverts on the same contract decompile only once.
pub struct HeimdallDecompileDecoder {
    bytecode: Arc<dyn BytecodeSource>,
    cache_dir: Option<PathBuf>,
    in_memory: Arc<RwLock<HashMap<B256, Option<JsonAbi>>>>,
    timeout: Duration,
}

impl HeimdallDecompileDecoder {
    pub fn new(bytecode: Arc<dyn BytecodeSource>) -> Self {
        Self {
            bytecode,
            cache_dir: None,
            in_memory: Arc::new(RwLock::new(HashMap::new())),
            timeout: DECOMPILE_TIMEOUT,
        }
    }

    /// Persist decompiled ABIs under `dir/<codehash>.json`. Optional —
    /// without one, ABIs are kept only in process memory.
    pub fn with_cache_dir(mut self, dir: PathBuf) -> Self {
        self.cache_dir = Some(dir);
        self
    }

    /// Override the per-decode timeout (default 30s).
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

#[async_trait]
impl RevertDecoder for HeimdallDecompileDecoder {
    fn name(&self) -> &'static str {
        "heimdall_decompile"
    }

    async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert> {
        let to = ctx.to?;
        let sel = selector_of(&ctx.returndata)?;

        let code = self.bytecode.code_for(ctx.chain_id, to).await?;
        if code.is_empty() {
            return None;
        }
        let codehash = keccak256(&code);

        let abi = self.abi_for(codehash, &code).await?;
        decode_against_abi(&abi, sel, &ctx.returndata)
    }
}

impl HeimdallDecompileDecoder {
    async fn abi_for(&self, codehash: B256, code: &[u8]) -> Option<JsonAbi> {
        if let Some(entry) = self.in_memory.read().await.get(&codehash).cloned() {
            return entry;
        }
        if let Some(dir) = &self.cache_dir
            && let Some(abi) = read_disk_cache(dir, codehash)
        {
            self.in_memory
                .write()
                .await
                .insert(codehash, Some(abi.clone()));
            return Some(abi);
        }

        let abi = match self.run_decompile(code).await {
            Some(a) => a,
            None => {
                self.in_memory.write().await.insert(codehash, None);
                return None;
            }
        };

        if let Some(dir) = &self.cache_dir
            && let Err(e) = write_disk_cache(dir, codehash, &abi)
        {
            tracing::debug!(error = %e, "heimdall.cache_write_failed");
        }
        self.in_memory
            .write()
            .await
            .insert(codehash, Some(abi.clone()));
        Some(abi)
    }

    async fn run_decompile(&self, code: &[u8]) -> Option<JsonAbi> {
        let target = format!("0x{}", hex::encode(code));
        // include_solidity=true is required for heimdall's analyzer to
        // surface error selectors at all — the bare-ABI analyzer skips
        // the solidity_heuristic that walks REVERT opcodes and records
        // `function.errors`. Without it, abi.errors is always empty.
        // skip_resolving=false lets heimdall enrich the names via
        // openchain; if that fails it falls back to `CustomError_<sel>`
        // with empty inputs (which decode_against_abi will skip).
        let args = match heimdall_decompiler::DecompilerArgsBuilder::new()
            .target(target)
            .skip_resolving(false)
            .include_solidity(true)
            .include_yul(false)
            .build()
        {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(error = %e, "heimdall.args_build_failed");
                return None;
            }
        };

        // heimdall has been observed to panic on adversarial inputs, so
        // we wrap the call in catch_unwind under tokio::task::spawn_blocking
        // alternative: tokio::time::timeout + catch_unwind via FutureExt
        // is not safe across awaits. We isolate via tokio::spawn so a
        // panic just kills that task and surfaces a JoinError.
        let fut = tokio::spawn(async move { heimdall_decompiler::decompile(args).await });
        let result = match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(Ok(r))) => r,
            Ok(Ok(Err(e))) => {
                tracing::debug!(error = %e, "heimdall.decompile_err");
                return None;
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "heimdall.task_join_err");
                return None;
            }
            Err(_) => {
                tracing::debug!(timeout = ?self.timeout, "heimdall.timeout");
                return None;
            }
        };
        Some(result.abi)
    }
}

fn decode_against_abi(abi: &JsonAbi, selector: [u8; 4], raw: &Bytes) -> Option<DecodedRevert> {
    for err in abi.errors() {
        if err.selector() == selector {
            let payload = if raw.len() >= 4 { &raw[4..] } else { &[] };
            let types: Result<Vec<DynSolType>, _> =
                err.inputs.iter().map(|p| p.resolve()).collect();
            let types = match types {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(error = %e, name = %err.name, "heimdall.bad_inputs");
                    return None;
                }
            };
            let tuple = DynSolType::Tuple(types);
            let value = match tuple.abi_decode_params(payload) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, name = %err.name, "heimdall.payload_failed");
                    return None;
                }
            };
            let values = value.as_tuple().map(|s| s.to_vec()).unwrap_or_default();
            let args: Vec<serde_json::Value> = values.iter().map(dyn_value_to_json).collect();
            let signature = err.signature();
            let message = render_message(&err.name, &args);
            return Some(DecodedRevert {
                selector: Some(selector),
                name: Some(err.name.clone()),
                signature: Some(signature),
                args,
                message: Some(message),
                raw: Bytes::copy_from_slice(raw),
                source: DecodeSource::HeimdallDecompile,
            });
        }
    }
    tracing::debug!(selector = %fmt_selector(&selector), "heimdall.selector_not_in_abi");
    None
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

fn keccak256(bytes: &[u8]) -> B256 {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    B256::from_slice(&out)
}

fn cache_path(dir: &Path, codehash: B256) -> PathBuf {
    dir.join(format!("{}.json", hex::encode(codehash.as_slice())))
}

fn read_disk_cache(dir: &Path, codehash: B256) -> Option<JsonAbi> {
    let p = cache_path(dir, codehash);
    let bytes = std::fs::read(&p).ok()?;
    serde_json::from_slice::<JsonAbi>(&bytes).ok()
}

fn write_disk_cache(dir: &Path, codehash: B256, abi: &JsonAbi) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = cache_path(dir, codehash);
    let bytes = serde_json::to_vec_pretty(abi).map_err(std::io::Error::other)?;
    std::fs::write(&p, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};

    /// Hand a fixed bytecode for any (chain_id, addr).
    struct StaticBytecode(Bytes);

    #[async_trait]
    impl BytecodeSource for StaticBytecode {
        async fn code_for(&self, _chain_id: u64, _addr: Address) -> Option<Bytes> {
            Some(self.0.clone())
        }
    }

    /// Always returns None — exercises the "no code" short-circuit.
    struct NoBytecode;

    #[async_trait]
    impl BytecodeSource for NoBytecode {
        async fn code_for(&self, _chain_id: u64, _addr: Address) -> Option<Bytes> {
            None
        }
    }

    fn ctx_for(raw: Vec<u8>, to: Address) -> DecodeContext {
        DecodeContext {
            returndata: raw.into(),
            to: Some(to),
            chain_id: 31337,
        }
    }

    /// Runtime bytecode of the test `Reverter` contract used in
    /// `crates/bloom-it/tests/revert_decoding.rs`. Carries the custom
    /// error `Boom(uint256)` (selector 0x1167d8fb). This is the
    /// *deployed* bytecode (constructor stripped) — captured by reading
    /// `eth_getCode` on a deployed Reverter; it's what heimdall sees in
    /// production.
    const REVERTER_RUNTIME: &str = "0x608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806376764977146100435780639af2e98214610061578063f89ecf4c1461006b575b5f5ffd5b61004b610075565b6040516100589190610123565b60405180910390f35b610069610092565b005b6100736100cd565b005b5f5f600190505f5f9050808261008b9190610169565b9250505090565b6040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100c4906101f3565b60405180910390fd5b602a6040517f1167d8fb0000000000000000000000000000000000000000000000000000000081526004016101029190610253565b60405180910390fd5b5f819050919050565b61011d8161010b565b82525050565b5f6020820190506101365f830184610114565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6101738261010b565b915061017e8361010b565b92508261018e5761018d61013c565b5b828204905092915050565b5f82825260208201905092915050565b7f626f6f6d000000000000000000000000000000000000000000000000000000005f82015250565b5f6101dd600483610199565b91506101e8826101a9565b602082019050919050565b5f6020820190508181035f83015261020a816101d1565b9050919050565b5f819050919050565b5f819050919050565b5f61023d61023861023384610211565b61021a565b61010b565b9050919050565b61024d81610223565b82525050565b5f6020820190506102665f830184610244565b9291505056fea26469706673582212205a030e5a0c4b57beea5bbeefe8fb9a089760752121d1f1a9bc5b7e3c55a52c2464736f6c634300081e0033";

    #[tokio::test(flavor = "multi_thread")]
    async fn decodes_custom_error_via_decompile() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("info,bloom_revert=debug,heimdall=debug")
                }),
            )
            .with_test_writer()
            .try_init();
        let code = Bytes::from(hex::decode(REVERTER_RUNTIME.trim_start_matches("0x")).unwrap());
        let dec = HeimdallDecompileDecoder::new(Arc::new(StaticBytecode(code)));

        // Boom(uint256) — selector 0x1167d8fb, payload = encoded uint256 = 42.
        let mut raw = vec![0x11, 0x67, 0xd8, 0xfb];
        let payload = alloy_dyn_abi::DynSolValue::Tuple(vec![alloy_dyn_abi::DynSolValue::Uint(
            U256::from(42u64),
            256,
        )])
        .abi_encode_params();
        raw.extend_from_slice(&payload);

        let target = address!("0x0000000000000000000000000000000000001234");
        let out = dec
            .try_decode(&ctx_for(raw, target))
            .await
            .expect("heimdall should decode Boom");
        assert_eq!(out.source, DecodeSource::HeimdallDecompile);
        assert_eq!(out.name.as_deref(), Some("Boom"));
        assert_eq!(out.signature.as_deref(), Some("Boom(uint256)"));
        assert_eq!(out.args, vec![serde_json::json!("42")]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_bytecode_returns_none_without_panic() {
        let dec = HeimdallDecompileDecoder::new(Arc::new(StaticBytecode(Bytes::from(vec![
            0xff, 0xfe, 0xfd,
        ]))))
        .with_timeout(Duration::from_secs(5));
        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        let target = address!("0x0000000000000000000000000000000000001234");
        // Either decompile yields an ABI that doesn't contain the
        // selector (None) or the run errors out (None). Both are fine.
        let out = dec.try_decode(&ctx_for(raw, target)).await;
        assert!(out.is_none(), "expected None, got {out:?}");
    }

    #[tokio::test]
    async fn no_to_address_yields_none() {
        let dec = HeimdallDecompileDecoder::new(Arc::new(NoBytecode));
        let ctx = DecodeContext {
            returndata: vec![0xde, 0xad, 0xbe, 0xef].into(),
            to: None,
            chain_id: 1,
        };
        assert!(dec.try_decode(&ctx).await.is_none());
    }

    #[tokio::test]
    async fn empty_bytecode_yields_none() {
        let dec = HeimdallDecompileDecoder::new(Arc::new(NoBytecode));
        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        let target = address!("0x0000000000000000000000000000000000001234");
        assert!(dec.try_decode(&ctx_for(raw, target)).await.is_none());
    }
}
