//! Alchemy mempool provider — subscribes via WebSocket to
//! `alchemy_pendingTransactions` and yields full-body PendingTx.

use std::time::SystemTime;

use alloy::primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::provider::{MempoolError, MempoolProvider, PendingTx, TxFees};

pub struct AlchemyProvider {
    ws_url: String,
}

impl AlchemyProvider {
    pub fn new(ws_url: impl Into<String>) -> Self {
        Self {
            ws_url: ws_url.into(),
        }
    }
}

#[async_trait]
impl MempoolProvider for AlchemyProvider {
    fn id(&self) -> &'static str {
        "alchemy"
    }
    fn delivers_bodies(&self) -> bool {
        true
    }

    async fn subscribe(
        &self,
    ) -> Result<futures::stream::BoxStream<'static, PendingTx>, MempoolError> {
        let url = self.ws_url.clone();
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;
        let (mut sink, stream) = ws.split();

        let sub_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": ["alchemy_pendingTransactions", {"hashesOnly": false}]
        });
        sink.send(Message::Text(sub_msg.to_string()))
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;

        let stream = stream.filter_map(|msg| async move {
            let txt = msg.ok()?.into_text().ok()?;
            let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
            let params = v.get("params")?;
            let result = params.get("result")?;
            decode_alchemy_pending(result)
        });
        // Reconnect-on-drop is handled at the daemon stream level; the
        // provider itself returns a single attempt.
        Ok(Box::pin(stream))
    }
}

fn decode_alchemy_pending(v: &serde_json::Value) -> Option<PendingTx> {
    let hash: B256 = v.get("hash")?.as_str()?.parse().ok()?;
    let from: Address = v.get("from")?.as_str()?.parse().ok()?;
    let to: Option<Address> = v
        .get("to")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse().ok());
    let nonce: u64 =
        u64::from_str_radix(v.get("nonce")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let value: U256 =
        U256::from_str_radix(v.get("value")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let gas_limit: u64 =
        u64::from_str_radix(v.get("gas")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let input = Bytes::from(hex::decode(v.get("input")?.as_str()?.trim_start_matches("0x")).ok()?);

    let fees = if let (Some(mfp), Some(mpfg)) = (
        v.get("maxFeePerGas").and_then(|x| x.as_str()),
        v.get("maxPriorityFeePerGas").and_then(|x| x.as_str()),
    ) {
        TxFees::Eip1559 {
            max_fee_per_gas: u128::from_str_radix(mfp.trim_start_matches("0x"), 16).ok()?,
            max_priority_fee_per_gas: u128::from_str_radix(mpfg.trim_start_matches("0x"), 16)
                .ok()?,
        }
    } else {
        TxFees::Legacy {
            gas_price: u128::from_str_radix(
                v.get("gasPrice")?.as_str()?.trim_start_matches("0x"),
                16,
            )
            .ok()?,
        }
    };

    Some(PendingTx {
        hash,
        from,
        to,
        nonce,
        value,
        gas_limit,
        fees,
        input,
        observed_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_alchemy_pending_parses_full_eip1559_payload() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{
            "hash":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "from":"0x2222222222222222222222222222222222222222",
            "to":"0x3333333333333333333333333333333333333333",
            "nonce":"0x5",
            "value":"0xde0b6b3a7640000",
            "gas":"0x5208",
            "maxFeePerGas":"0xb2d05e00",
            "maxPriorityFeePerGas":"0x3b9aca00",
            "input":"0xabcd"
        }"#,
        )
        .unwrap();
        let tx = decode_alchemy_pending(&v).unwrap();
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.value, U256::from(10u64).pow(U256::from(18u64)));
        assert!(matches!(tx.fees, TxFees::Eip1559 { .. }));
    }

    #[test]
    fn decode_alchemy_pending_returns_none_for_hash_only_payload() {
        // alchemy_pendingTransactions with hashesOnly: true sends just the hash.
        // Our decoder requires full body fields — should return None.
        let v: serde_json::Value = serde_json::from_str(
            r#""0x1111111111111111111111111111111111111111111111111111111111111111""#,
        )
        .unwrap();
        assert!(decode_alchemy_pending(&v).is_none());
    }

    #[test]
    fn decode_alchemy_pending_handles_contract_creation_to_null() {
        // Contract-creation txs have to = null.
        let v: serde_json::Value = serde_json::from_str(
            r#"{
            "hash":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "from":"0x2222222222222222222222222222222222222222",
            "to":null,
            "nonce":"0x0",
            "value":"0x0",
            "gas":"0x5208",
            "maxFeePerGas":"0xb2d05e00",
            "maxPriorityFeePerGas":"0x3b9aca00",
            "input":"0x"
        }"#,
        )
        .unwrap();
        let tx = decode_alchemy_pending(&v).unwrap();
        assert!(tx.to.is_none());
        assert_eq!(
            tx.from.to_string().to_lowercase(),
            "0x2222222222222222222222222222222222222222"
        );
    }

    #[cfg(feature = "live-providers")]
    #[tokio::test]
    #[ignore = "requires ALCHEMY_API_KEY env and network access"]
    async fn alchemy_live_subscribe_yields_pending_tx() {
        use crate::provider::MempoolProvider;
        use futures::StreamExt;
        let key = std::env::var("ALCHEMY_API_KEY").expect("set ALCHEMY_API_KEY to run live test");
        let url = format!("wss://eth-mainnet.g.alchemy.com/v2/{key}");
        let provider = AlchemyProvider::new(url);
        let mut stream = provider.subscribe().await.expect("subscribe");
        let tx = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await
            .expect("timeout waiting for first pending tx")
            .expect("stream ended before yielding");
        assert_ne!(tx.hash, alloy::primitives::B256::ZERO);
    }

    #[test]
    fn decode_alchemy_pending_parses_legacy_payload() {
        // Pre-1559 txs use `gasPrice` instead of maxFeePerGas/maxPriorityFeePerGas.
        let v: serde_json::Value = serde_json::from_str(
            r#"{
            "hash":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "from":"0x2222222222222222222222222222222222222222",
            "to":"0x3333333333333333333333333333333333333333",
            "nonce":"0x7",
            "value":"0x0",
            "gas":"0x5208",
            "gasPrice":"0x3b9aca00",
            "input":"0x"
        }"#,
        )
        .unwrap();
        let tx = decode_alchemy_pending(&v).unwrap();
        assert_eq!(tx.nonce, 7);
        match tx.fees {
            TxFees::Legacy { gas_price } => assert_eq!(gas_price, 1_000_000_000),
            other => panic!("expected legacy fees, got {other:?}"),
        }
    }
}
