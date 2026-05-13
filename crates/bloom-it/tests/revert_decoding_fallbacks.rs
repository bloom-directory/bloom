//! End-to-end test for the heimdall bytecode-decompile fallback.
//!
//! Mirrors `revert_decoding.rs` but runs without an Etherscan ABI
//! source — the unverified-contract path that exercises stages 4-5.
//! Openchain is intentionally skipped here to avoid network flakiness;
//! its coverage lives in the `bloom-revert` unit tests.
//!
//! Marked `#[ignore]` and gated on the `bytecode-decompile` feature.
//! Run with:
//!
//! ```text
//! cargo test -p bloom-it --test revert_decoding_fallbacks \
//!     --features bytecode-decompile -- --ignored --nocapture
//! ```
//!
//! Requires `anvil` and `cast` from Foundry on `$PATH` (override with
//! `BLOOM_ANVIL_BIN` / `BLOOM_CAST_BIN`).

#![cfg(feature = "bytecode-decompile")]

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bloom_chain::ChainClient;
use bloom_it::{FUNDER_PRIV_KEY, cast_send, spawn_anvil};
use bloom_proto::ChainSpec;
use bloom_revert::{
    BuiltinDecoder, BytecodeSource, DecodeContext, DecodeSource, DecoderChain,
    HeimdallDecompileDecoder, boxed,
};
use tokio::time::sleep;

/// Same Reverter contract as `revert_decoding.rs`. We re-deploy it
/// locally so the heimdall path actually has live bytecode to fetch.
const REVERTER_BYTECODE: &str = "0x6080604052348015600e575f5ffd5b506102a28061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806376764977146100435780639af2e98214610061578063f89ecf4c1461006b575b5f5ffd5b61004b610075565b6040516100589190610123565b60405180910390f35b610069610092565b005b6100736100cd565b005b5f5f600190505f5f9050808261008b9190610169565b9250505090565b6040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100c4906101f3565b60405180910390fd5b602a6040517f1167d8fb0000000000000000000000000000000000000000000000000000000081526004016101029190610253565b60405180910390fd5b5f819050919050565b61011d8161010b565b82525050565b5f6020820190506101365f830184610114565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6101738261010b565b915061017e8361010b565b92508261018e5761018d61013c565b5b828204905092915050565b5f82825260208201905092915050565b7f626f6f6d000000000000000000000000000000000000000000000000000000005f82015250565b5f6101dd600483610199565b91506101e8826101a9565b602082019050919050565b5f6020820190508181035f83015261020a816101d1565b9050919050565b5f819050919050565b5f819050919050565b5f61023d61023861023384610211565b61021a565b61010b565b9050919050565b61024d81610223565b82525050565b5f6020820190506102665f830184610244565b9291505056fea26469706673582212205a030e5a0c4b57beea5bbeefe8fb9a089760752121d1f1a9bc5b7e3c55a52c2464736f6c634300081e0033";

const SEL_CUSTOM: &str = "0xf89ecf4c"; // customRevert()
const SEL_BOOM: [u8; 4] = [0x11, 0x67, 0xd8, 0xfb]; // Boom(uint256)

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

async fn deploy(rpc_url: &str) -> Result<Address> {
    let stdout = cast_send(rpc_url, &["--create", REVERTER_BYTECODE, "--json"]).await?;
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .with_context(|| format!("parse cast output: {stdout}"))?;
    let addr_hex = v
        .get("contractAddress")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no contractAddress in receipt: {stdout}"))?;
    Ok(addr_hex.parse()?)
}

async fn send_revert(rpc_url: &str, to: Address, selector: &str) -> Result<B256> {
    let to_str = format!("{to:#x}");
    let stdout = cast_send(
        rpc_url,
        &[
            "--legacy",
            "--gas-limit",
            "200000",
            "--json",
            &to_str,
            selector,
        ],
    )
    .await?;
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .with_context(|| format!("parse cast output: {stdout}"))?;
    let h = v
        .get("transactionHash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no txHash: {stdout}"))?;
    Ok(h.parse()?)
}

fn build_chain_client(rpc_url: &str) -> Result<ChainClient> {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    Ok(ChainClient::new(spec)?)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn anvil_heimdall_recovers_unverified_custom_error() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,bloom_revert=info,bloom_chain=info")
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
