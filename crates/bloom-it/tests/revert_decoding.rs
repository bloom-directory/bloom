//! Category: integration
//!
//! End-to-end test for the tiered revert-decoding pipeline.
//!
//! Runs against a real `anvil` instance: deploys a hand-rolled `Reverter`
//! contract that exposes three deterministic revert paths, sends one
//! reverting tx of each kind, then walks every tx through
//! `ChainClient::trace_revert` + `DecoderChain` and asserts the decoded
//! attribution matches the expected source / signature / args.
//!
//! Requires `anvil` and `cast` from Foundry on `$PATH` (override with
//! `BLOOM_ANVIL_BIN` / `BLOOM_CAST_BIN`).

use std::sync::Arc;
use std::time::Duration;

mod reverter;

use alloy::primitives::Address;
use anyhow::Result;
use bloom_it::{FUNDER_PRIV_KEY, spawn_anvil};
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecodeContext, DecodeSource, DecoderChain, EtherscanAbiDecoder,
    boxed,
};
use reverter::*;
use tokio::time::sleep;

/// Stub AbiSource that returns the Reverter contract's ABI. The decoder
/// queries this in place of Etherscan; the JSON is the canonical artifact
/// shape from `solc --combined-json abi`.
struct StubAbi(alloy::json_abi::JsonAbi);

#[async_trait::async_trait]
impl AbiSource for StubAbi {
    async fn abi_for(&self, _chain_id: u64, _addr: Address) -> Option<alloy::json_abi::JsonAbi> {
        Some(self.0.clone())
    }
}

fn reverter_abi() -> alloy::json_abi::JsonAbi {
    let abi_json = serde_json::json!([
        { "type": "error", "name": "Boom", "inputs": [{ "name": "code", "type": "uint256" }] },
        { "type": "function", "name": "reasonRevert", "inputs": [], "outputs": [], "stateMutability": "pure" },
        { "type": "function", "name": "panicRevert",  "inputs": [], "outputs": [{"type":"uint256"}], "stateMutability": "pure" },
        { "type": "function", "name": "customRevert", "inputs": [], "outputs": [], "stateMutability": "pure" }
    ]);
    serde_json::from_value(abi_json).unwrap()
}

/// Deploy via `cast send --create` and capture the deployed address from
/// the JSON receipt.
fn build_decoder_chain(abi: alloy::json_abi::JsonAbi) -> DecoderChain {
    let abi_source: Arc<dyn AbiSource> = Arc::new(StubAbi(abi));
    DecoderChain::new()
        .with(boxed(BuiltinDecoder))
        .with(boxed(EtherscanAbiDecoder::new(abi_source)))
}

#[tokio::test(flavor = "multi_thread")]
async fn anvil_decodes_three_revert_kinds() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,bloom_revert=info,bloom_evm=info")
            }),
        )
        .with_test_writer()
        .try_init();

    // 1. Anvil + a chain client for it.
    let _ = FUNDER_PRIV_KEY; // referenced via cast_send internally.
    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();
    let chain = build_chain_client(&rpc_url)?;
    let decoders = build_decoder_chain(reverter_abi());

    // 2. Deploy the Reverter contract.
    let contract = deploy(&rpc_url).await?;

    // Allow anvil to advance one block past the deploy so receipt is
    // available for the *replay* path used by trace_revert.
    sleep(Duration::from_millis(200)).await;

    // 3. Each reverting tx → trace_revert → DecoderChain → assertion.
    //    Subtest A: revert("boom")  ⇒ Builtin Error(string).
    let h_reason = send_revert(&rpc_url, contract, SEL_REASON).await?;
    sleep(Duration::from_millis(200)).await;
    let returndata = chain
        .trace_revert(h_reason)
        .await?
        .expect("trace_revert should yield revert data");
    let chain_id = chain.chain_id().await?;
    let dec = decoders
        .decode(&DecodeContext {
            returndata: returndata.clone(),
            to: Some(contract),
            chain_id,
        })
        .await;
    assert_eq!(dec.source, DecodeSource::Builtin, "{dec:?}");
    assert_eq!(dec.name.as_deref(), Some("Error"));
    assert_eq!(dec.message.as_deref(), Some("boom"));
    assert_eq!(dec.signature.as_deref(), Some("Error(string)"));

    // Subtest B: division by zero  ⇒ Builtin Panic(uint256), code 0x12.
    let h_panic = send_revert(&rpc_url, contract, SEL_PANIC).await?;
    sleep(Duration::from_millis(200)).await;
    let returndata = chain
        .trace_revert(h_panic)
        .await?
        .expect("trace_revert should yield revert data");
    let dec = decoders
        .decode(&DecodeContext {
            returndata,
            to: Some(contract),
            chain_id,
        })
        .await;
    assert_eq!(dec.source, DecodeSource::Builtin, "{dec:?}");
    assert_eq!(dec.name.as_deref(), Some("Panic"));
    let msg = dec.message.unwrap_or_default();
    assert!(
        msg.contains("division") || msg.contains("0x12"),
        "panic message should reference div-by-zero, got: {msg:?}"
    );

    // Subtest C: revert Boom(42)  ⇒ EtherscanAbi (stubbed) Boom(uint256).
    let h_custom = send_revert(&rpc_url, contract, SEL_CUSTOM).await?;
    sleep(Duration::from_millis(200)).await;
    let returndata = chain
        .trace_revert(h_custom)
        .await?
        .expect("trace_revert should yield revert data");
    assert_eq!(
        &returndata.as_ref()[..4],
        &SEL_BOOM,
        "expected Boom selector at start of returndata"
    );
    let dec = decoders
        .decode(&DecodeContext {
            returndata,
            to: Some(contract),
            chain_id,
        })
        .await;
    assert_eq!(dec.source, DecodeSource::EtherscanAbi, "{dec:?}");
    assert_eq!(dec.name.as_deref(), Some("Boom"));
    assert_eq!(dec.signature.as_deref(), Some("Boom(uint256)"));
    assert_eq!(dec.args, vec![serde_json::json!("42")]);

    Ok(())
}
