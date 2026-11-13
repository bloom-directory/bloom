//! The `Reverter` test contract shared by the revert-decoding tests.
#![allow(dead_code)]

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result, anyhow};
use bloom_evm::ChainClient;
use bloom_it::cast_send;
use bloom_proto::ChainSpec;

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
pub const REVERTER_BYTECODE: &str = "0x6080604052348015600e575f5ffd5b506102a28061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806376764977146100435780639af2e98214610061578063f89ecf4c1461006b575b5f5ffd5b61004b610075565b6040516100589190610123565b60405180910390f35b610069610092565b005b6100736100cd565b005b5f5f600190505f5f9050808261008b9190610169565b9250505090565b6040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100c4906101f3565b60405180910390fd5b602a6040517f1167d8fb0000000000000000000000000000000000000000000000000000000081526004016101029190610253565b60405180910390fd5b5f819050919050565b61011d8161010b565b82525050565b5f6020820190506101365f830184610114565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6101738261010b565b915061017e8361010b565b92508261018e5761018d61013c565b5b828204905092915050565b5f82825260208201905092915050565b7f626f6f6d000000000000000000000000000000000000000000000000000000005f82015250565b5f6101dd600483610199565b91506101e8826101a9565b602082019050919050565b5f6020820190508181035f83015261020a816101d1565b9050919050565b5f819050919050565b5f819050919050565b5f61023d61023861023384610211565b61021a565b61010b565b9050919050565b61024d81610223565b82525050565b5f6020820190506102665f830184610244565b9291505056fea26469706673582212205a030e5a0c4b57beea5bbeefe8fb9a089760752121d1f1a9bc5b7e3c55a52c2464736f6c634300081e0033";

pub const SEL_REASON: &str = "0x9af2e982"; // reasonRevert()
pub const SEL_PANIC: &str = "0x76764977"; // panicRevert()
pub const SEL_CUSTOM: &str = "0xf89ecf4c"; // customRevert()
pub const SEL_BOOM: [u8; 4] = [0x11, 0x67, 0xd8, 0xfb]; // Boom(uint256)

pub async fn deploy(rpc_url: &str) -> Result<Address> {
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
pub async fn send_revert(rpc_url: &str, to: Address, selector: &str) -> Result<B256> {
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

pub fn build_chain_client(rpc_url: &str) -> Result<ChainClient> {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    Ok(ChainClient::new(spec)?)
}
