#![cfg(feature = "live-providers")]

use alloy::eips::Encodable2718;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::rpc::types::eth::TransactionRequest;
use alloy::signers::SignerSync;
use bloom_mempool::providers::flashbots::SEPOLIA_URL;

const DEFAULT_WALLET: &str = "dest1";
const DEFAULT_RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const DEFAULT_TRANSFER_WEI: u128 = 100_000_000_000_000; // 0.0001 Sepolia ETH
const DEFAULT_PRIORITY_FEE_WEI: u128 = 50_000_000_000; // 50 gwei
const GAS_LIMIT: u64 = 21_000;
const SEPOLIA_CHAIN_ID_HEX: &str = "0xaa36a7";

#[tokio::test]
async fn flashbots_sepolia_accepts_private_real_value_transfer() -> anyhow::Result<()> {
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
        .or_else(|_| env_any(&["BLOOM_LIVE_DEST2", "BETH_LIVE_DEST2"]))
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
    let recipient_code = rpc_str(
        &rpc_url,
        "eth_getCode",
        serde_json::json!([format!("{recipient:#x}"), "latest"]),
    )
    .await?;
    anyhow::ensure!(
        recipient_code == "0x",
        "Sepolia recipient {recipient:#x} has contract code; choose an EOA recipient for a 21,000 gas transfer"
    );

    let nonce_hex = rpc_str(
        &rpc_url,
        "eth_getTransactionCount",
        serde_json::json!([format!("{:#x}", signer.address()), "pending"]),
    )
    .await?;
    let nonce = parse_hex_u64(&nonce_hex)?;
    let current_block_hex = rpc_str(&rpc_url, "eth_blockNumber", serde_json::json!([])).await?;
    let max_block = parse_hex_u64(&current_block_hex)?.saturating_add(50);

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
    ensure_sepolia_flashbots_url(&flashbots_url)?;
    let hash = send_flashbots_private_tx(&flashbots_url, &raw, max_block, &signer).await?;
    eprintln!(
        "Sepolia Flashbots relay accepted private transfer: hash={hash:#x} relay={flashbots_url} from={:#x} to={recipient:#x} value_wei={value_wei}",
        signer.address()
    );

    Ok(())
}

fn ensure_sepolia_flashbots_url(url: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Flashbots URL has no host: {url}"))?;
    anyhow::ensure!(
        host.contains("sepolia"),
        "Sepolia Flashbots test must target a Sepolia relay, got {url}"
    );
    anyhow::ensure!(
        !matches!(host, "rpc.flashbots.net" | "relay.flashbots.net"),
        "Sepolia Flashbots test must not target mainnet Flashbots relay {url}"
    );
    Ok(())
}

async fn send_flashbots_private_tx(
    url: &str,
    raw: &Bytes,
    max_block: u64,
    signer: &alloy::signers::local::PrivateKeySigner,
) -> anyhow::Result<B256> {
    let raw_hex = format!("0x{}", hex::encode(raw.as_ref()));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendPrivateTransaction",
        "params": [{
            "tx": raw_hex,
            "maxBlockNumber": format!("0x{max_block:x}"),
            "preferences": {"fast": true},
        }],
    });
    let body = serde_json::to_string(&body)?;
    let body_hash = keccak256(body.as_bytes());
    let body_hash_hex = format!("{body_hash:#x}");
    let signature = signer.sign_message_sync(body_hash_hex.as_bytes())?;
    let auth = format!(
        "{:#x}:0x{}",
        signer.address(),
        hex::encode(signature.as_bytes())
    );
    let resp = reqwest::Client::new()
        .post(url)
        .header("X-Flashbots-Signature", auth)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    anyhow::ensure!(
        status.is_success(),
        "Flashbots relay returned HTTP {status}: {text}"
    );
    let resp: serde_json::Value = serde_json::from_str(&text)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("eth_sendPrivateTransaction returned error: {err}");
    }
    let hash = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("eth_sendPrivateTransaction missing result"))?;
    Ok(hash.parse()?)
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
