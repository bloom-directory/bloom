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
//! Marked `#[ignore]` so it only runs explicitly:
//!
//! ```text
//! cargo test -p bloom-it --test revert_decoding -- --ignored --nocapture
//! ```
//!
//! Requires `anvil` and `cast` from Foundry on `$PATH` (override with
//! `BLOOM_ANVIL_BIN` / `BLOOM_CAST_BIN`).

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result, anyhow};
use bloom_evm::ChainClient;
use bloom_it::{FUNDER_PRIV_KEY, cast_send, spawn_anvil};
use bloom_proto::ChainSpec;
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecodeContext, DecodeSource, DecoderChain, EtherscanAbiDecoder,
    boxed,
};
use tokio::time::sleep;

/// Pre-compiled bytecode of the test contract:
///
/// ```solidity
/// pragma solidity ^0.8.24;
/// contract Reverter {
///     error Boom(uint256 code);
///     function reasonRevert() external pure { revert("boom"); }
///     function panicRevert()  external pure returns (uint256) {
///         uint256 a = 1; uint256 b = 0; return a / b;
///     }
///     function customRevert() external pure { revert Boom(42); }
/// }
/// ```
const REVERTER_BYTECODE: &str = "0x6080604052348015600e575f5ffd5b506102a28061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806376764977146100435780639af2e98214610061578063f89ecf4c1461006b575b5f5ffd5b61004b610075565b6040516100589190610123565b60405180910390f35b610069610092565b005b6100736100cd565b005b5f5f600190505f5f9050808261008b9190610169565b9250505090565b6040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100c4906101f3565b60405180910390fd5b602a6040517f1167d8fb0000000000000000000000000000000000000000000000000000000081526004016101029190610253565b60405180910390fd5b5f819050919050565b61011d8161010b565b82525050565b5f6020820190506101365f830184610114565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6101738261010b565b915061017e8361010b565b92508261018e5761018d61013c565b5b828204905092915050565b5f82825260208201905092915050565b7f626f6f6d000000000000000000000000000000000000000000000000000000005f82015250565b5f6101dd600483610199565b91506101e8826101a9565b602082019050919050565b5f6020820190508181035f83015261020a816101d1565b9050919050565b5f819050919050565b5f819050919050565b5f61023d61023861023384610211565b61021a565b61010b565b9050919050565b61024d81610223565b82525050565b5f6020820190506102665f830184610244565b9291505056fea26469706673582212205a030e5a0c4b57beea5bbeefe8fb9a089760752121d1f1a9bc5b7e3c55a52c2464736f6c634300081e0033";

const SEL_REASON: &str = "0x9af2e982"; // reasonRevert()
const SEL_PANIC: &str = "0x76764977"; // panicRevert()
const SEL_CUSTOM: &str = "0xf89ecf4c"; // customRevert()
const SEL_BOOM_ERR: [u8; 4] = [0x11, 0x67, 0xd8, 0xfb]; // Boom(uint256)

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

/// Send a tx that we expect to revert. cast returns success exit even on
/// reverts as long as the tx is mined. Returns the tx hash.
async fn send_revert(rpc_url: &str, to: Address, selector: &str) -> Result<B256> {
    let to_str = format!("{to:#x}");
    // Use `--legacy` to avoid eip-1559 fields and let anvil mine without
    // dynamic fee. `--gas-limit` ensures the tx is included even though
    // estimateGas would otherwise fail (the call reverts).
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

fn build_decoder_chain(abi: alloy::json_abi::JsonAbi) -> DecoderChain {
    let abi_source: Arc<dyn AbiSource> = Arc::new(StubAbi(abi));
    DecoderChain::new()
        .with(boxed(BuiltinDecoder))
        .with(boxed(EtherscanAbiDecoder::new(abi_source)))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
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
        &SEL_BOOM_ERR,
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
