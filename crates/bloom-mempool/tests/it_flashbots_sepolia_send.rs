#![cfg(feature = "live-providers")]

use alloy::eips::Encodable2718;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::eth::TransactionRequest;
use bloom_mempool::private::PrivateRpcProvider;
use bloom_mempool::providers::flashbots::{FlashbotsProvider, SEPOLIA_URL};

const DEFAULT_WALLET: &str = "dest1";
const DEFAULT_RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const DEFAULT_TRANSFER_WEI: u128 = 100_000_000_000_000; // 0.0001 Sepolia ETH
const DEFAULT_PRIORITY_FEE_WEI: u128 = 1_000_000_000; // 1 gwei
const GAS_LIMIT: u64 = 21_000;
const SEPOLIA_CHAIN_ID_HEX: &str = "0xaa36a7";

#[tokio::test]
async fn flashbots_sepolia_private_send_real_value_transfer() -> anyhow::Result<()> {
    if std::env::var("BLOOM_RUN_SEPOLIA_PRIVATE_SEND")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!("skipping: set BLOOM_RUN_SEPOLIA_PRIVATE_SEND=1 to send Sepolia ETH");
        return Ok(());
    }

    let rpc_url = required_env_any(&["BLOOM_SEPOLIA_RPC_URL", "BETH_SEPOLIA_RPC_URL"])?;
    let live_home = required_env_any(&["BLOOM_LIVE_HOME", "BETH_LIVE_HOME"])?;
    let passphrase = required_env_any(&["BLOOM_PASSPHRASE", "BETH_PASSPHRASE"])?;
    let expected_sender: Address =
        required_env_any(&["BLOOM_LIVE_DEST1", "BETH_LIVE_DEST1"])?.parse()?;
    let wallet_name = env_any(&["BLOOM_LIVE_WALLET", "BETH_LIVE_WALLET"])
        .unwrap_or_else(|_| DEFAULT_WALLET.into());
    let recipient: Address = env_any(&["BLOOM_SEPOLIA_RECIPIENT", "BETH_SEPOLIA_RECIPIENT"])
        .unwrap_or_else(|_| DEFAULT_RECIPIENT.into())
        .parse()?;
    let value_wei = env_u128_any(
        &["BLOOM_SEPOLIA_TRANSFER_WEI", "BETH_SEPOLIA_TRANSFER_WEI"],
        DEFAULT_TRANSFER_WEI,
    )?;
    anyhow::ensure!(value_wei > 0, "Sepolia transfer amount must be > 0");

    let keystore =
        bloom_keystore::Keystore::new(std::path::Path::new(&live_home).join("keystore"))?;
    let info = keystore.info(&wallet_name)?;
    anyhow::ensure!(
        info.address == expected_sender,
        "wallet {wallet_name} address {} does not match BLOOM_LIVE_DEST1 {expected_sender}",
        info.address
    );
    keystore.unlock(&wallet_name, &passphrase)?;
    let signer = keystore.signer(&wallet_name)?;

    let chain_id = rpc_str(&rpc_url, "eth_chainId", serde_json::json!([])).await?;
    anyhow::ensure!(
        chain_id == SEPOLIA_CHAIN_ID_HEX,
        "BLOOM_SEPOLIA_RPC_URL is not Sepolia: eth_chainId returned {chain_id}"
    );

    let nonce_hex = rpc_str(
        &rpc_url,
        "eth_getTransactionCount",
        serde_json::json!([format!("{:#x}", signer.address()), "pending"]),
    )
    .await?;
    let nonce = parse_hex_u64(&nonce_hex)?;

    let base_fee = latest_base_fee(&rpc_url).await?;
    let priority_fee = env_u128_any(
        &[
            "BLOOM_SEPOLIA_PRIORITY_FEE_WEI",
            "BETH_SEPOLIA_PRIORITY_FEE_WEI",
        ],
        DEFAULT_PRIORITY_FEE_WEI,
    )?;
    anyhow::ensure!(priority_fee > 0, "priority fee must be > 0");
    let max_fee = match env_any(&[
        "BLOOM_SEPOLIA_MAX_FEE_PER_GAS_WEI",
        "BETH_SEPOLIA_MAX_FEE_PER_GAS_WEI",
    ]) {
        Ok(v) => v.parse::<u128>()?,
        Err(_) => base_fee.saturating_mul(2).saturating_add(priority_fee),
    };
    anyhow::ensure!(
        max_fee >= priority_fee,
        "max fee per gas must be >= priority fee"
    );

    let balance_hex = rpc_str(
        &rpc_url,
        "eth_getBalance",
        serde_json::json!([format!("{:#x}", signer.address()), "pending"]),
    )
    .await?;
    let balance = U256::from_str_radix(balance_hex.trim_start_matches("0x"), 16)?;
    let required =
        U256::from(value_wei) + U256::from(GAS_LIMIT).saturating_mul(U256::from(max_fee));
    anyhow::ensure!(
        balance >= required,
        "sender has insufficient Sepolia ETH: balance={balance}, required={required}"
    );

    let tx = TransactionRequest::default()
        .with_from(signer.address())
        .with_to(recipient)
        .with_value(U256::from(value_wei))
        .with_nonce(nonce)
        .with_chain_id(bloom_mempool::SEPOLIA_CHAIN_ID)
        .with_gas_limit(GAS_LIMIT)
        .with_max_fee_per_gas(max_fee)
        .with_max_priority_fee_per_gas(priority_fee);

    let wallet = EthereumWallet::from((*signer).clone());
    let envelope = tx.build(&wallet).await?;
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    let raw = Bytes::from(raw);

    let flashbots_url = env_any(&["BLOOM_SEPOLIA_FLASHBOTS_URL", "BETH_SEPOLIA_FLASHBOTS_URL"])
        .unwrap_or_else(|_| SEPOLIA_URL.to_string());
    let provider = FlashbotsProvider::new(flashbots_url)?;
    let hash = provider.submit(&raw).await?;
    eprintln!(
        "submitted Sepolia private transfer: hash={hash:#x} from={:#x} to={recipient:#x} value_wei={value_wei}",
        signer.address()
    );

    let receipt = wait_for_receipt(&rpc_url, &format!("{hash:#x}")).await?;
    let status = receipt
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    anyhow::ensure!(status == "0x1", "Sepolia tx did not succeed: {receipt}");

    Ok(())
}

async fn wait_for_receipt(rpc_url: &str, hash: &str) -> anyhow::Result<serde_json::Value> {
    for _ in 0..30 {
        let result = rpc_result(
            rpc_url,
            "eth_getTransactionReceipt",
            serde_json::json!([hash]),
        )
        .await?;
        if !result.is_null() {
            return Ok(result);
        }
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    }
    anyhow::bail!("timed out waiting for Sepolia receipt for {hash}");
}

async fn latest_base_fee(rpc_url: &str) -> anyhow::Result<u128> {
    let block = rpc_result(
        rpc_url,
        "eth_getBlockByNumber",
        serde_json::json!(["latest", false]),
    )
    .await?;
    let base_fee = block
        .get("baseFeePerGas")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("latest block missing baseFeePerGas"))?;
    parse_hex_u128(base_fee)
}

async fn rpc_str(rpc_url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<String> {
    rpc_result(rpc_url, method, params)
        .await?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("{method} returned a non-string result"))
}

async fn rpc_result(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp: serde_json::Value = reqwest::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("{method} returned error: {err}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{method} response missing result"))
}

fn required_env_any(names: &[&str]) -> anyhow::Result<String> {
    env_any(names).map_err(|_| anyhow::anyhow!("one of {} must be set", names.join(", ")))
}

fn env_any(names: &[&str]) -> Result<String, std::env::VarError> {
    let mut last_err = std::env::VarError::NotPresent;
    for name in names {
        match std::env::var(name) {
            Ok(v) => return Ok(v),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn env_u128_any(names: &[&str], default: u128) -> anyhow::Result<u128> {
    match env_any(names) {
        Ok(v) => Ok(v.parse()?),
        Err(_) => Ok(default),
    }
}

fn parse_hex_u64(s: &str) -> anyhow::Result<u64> {
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn parse_hex_u128(s: &str) -> anyhow::Result<u128> {
    Ok(u128::from_str_radix(s.trim_start_matches("0x"), 16)?)
}
