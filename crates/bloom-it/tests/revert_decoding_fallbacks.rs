//! Category: integration
//!
//! End-to-end test for the heimdall bytecode-decompile fallback.
//!
//! Mirrors `revert_decoding.rs` but runs without an Etherscan ABI
//! source — the unverified-contract path that exercises stages 4-5.
//! Openchain is intentionally skipped here to avoid network flakiness;
//! its coverage lives in the `bloom-revert` unit tests.
//!
//! Gated on the `bytecode-decompile` feature. Run with:
//!
//! ```text
//! cargo test -p bloom-it --test revert_decoding_fallbacks \
//!     --features bytecode-decompile -- --nocapture
//! ```
//!
//! Requires `anvil` and `cast` from Foundry on `$PATH` (override with
//! `BLOOM_ANVIL_BIN` / `BLOOM_CAST_BIN`).

#![cfg(feature = "bytecode-decompile")]

use std::sync::Arc;
use std::time::Duration;

mod reverter;

use alloy::primitives::Address;
use anyhow::Result;
use async_trait::async_trait;
use bloom_evm::ChainClient;
use bloom_it::{FUNDER_PRIV_KEY, spawn_anvil};
use bloom_revert::{
    BuiltinDecoder, BytecodeSource, DecodeContext, DecodeSource, DecoderChain,
    HeimdallDecompileDecoder, boxed,
};
use reverter::*;
use tokio::time::sleep;

/// BytecodeSource that pulls runtime code via the live ChainClient.
/// The decoder asks for `(chain_id, addr)`; we ignore chain_id since
/// our test only operates on one anvil instance.
struct ClientBytecodeSource(ChainClient);

#[async_trait]
impl BytecodeSource for ClientBytecodeSource {
    async fn code_for(&self, _chain_id: u64, addr: Address) -> Option<alloy::primitives::Bytes> {
        match self.0.code(addr).await {
            Ok(c) if !c.is_empty() => Some(alloy::primitives::Bytes::from(c)),
            _ => None,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn anvil_heimdall_recovers_unverified_custom_error() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,bloom_revert=info,bloom_evm=info")
            }),
        )
        .with_test_writer()
        .try_init();

    let _ = FUNDER_PRIV_KEY;
    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();
    let chain = build_chain_client(&rpc_url)?;

    // Build the decoder chain *without* an Etherscan ABI source. With
    // Builtin -> Heimdall the only path that can decode `Boom(uint256)`
    // is the bytecode-decompile fallback.
    let bytecode_source: Arc<dyn BytecodeSource> = Arc::new(ClientBytecodeSource(chain.clone()));
    let decoders = DecoderChain::new()
        .with(boxed(BuiltinDecoder))
        .with(boxed(HeimdallDecompileDecoder::new(bytecode_source)));

    // Deploy the unverified Reverter contract.
    let contract = deploy(&rpc_url).await?;
    sleep(Duration::from_millis(200)).await;

    // Trigger the custom-error revert path.
    let h = send_revert(&rpc_url, contract, SEL_CUSTOM).await?;
    sleep(Duration::from_millis(200)).await;

    let returndata = chain
        .trace_revert(h)
        .await?
        .expect("trace_revert should yield revert data");
    assert_eq!(
        &returndata.as_ref()[..4],
        &SEL_BOOM,
        "expected Boom selector at start of returndata"
    );

    let chain_id = chain.chain_id().await?;
    let dec = decoders
        .decode(&DecodeContext {
            returndata,
            to: Some(contract),
            chain_id,
        })
        .await;

    assert_eq!(dec.source, DecodeSource::HeimdallDecompile, "{dec:?}");
    assert_eq!(dec.name.as_deref(), Some("Boom"));
    assert_eq!(dec.signature.as_deref(), Some("Boom(uint256)"));
    assert_eq!(dec.args, vec![serde_json::json!("42")]);
    Ok(())
}
