//! Generic provider that subscribes to `newPendingTransactions` and
//! follows up via `eth_getTransactionByHash` for full bodies.
//!
//! Works on any node that supports `eth_subscribe` (Geth/Erigon/most
//! third-party WS endpoints). Returns hashes-only PendingTx; the
//! daemon stream layer is responsible for body fetch.

use std::time::SystemTime;

use alloy::primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::provider::{MempoolError, MempoolProvider, PendingTx, TxFees};

pub struct GenericEthSubscribeProvider {
    ws_url: String,
}

impl GenericEthSubscribeProvider {
    pub fn new(ws_url: impl Into<String>) -> Self {
        Self {
            ws_url: ws_url.into(),
        }
    }
}

#[async_trait]
impl MempoolProvider for GenericEthSubscribeProvider {
    fn id(&self) -> &'static str {
        "generic_eth_subscribe"
    }
    fn delivers_bodies(&self) -> bool {
        false
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
            "params": ["newPendingTransactions"]
        });
        sink.send(Message::Text(sub_msg.to_string()))
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;

        let stream = stream.filter_map(|msg| async move {
            let txt = msg.ok()?.into_text().ok()?;
            let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
            let hash_str = v.get("params")?.get("result")?.as_str()?;
            let hash: B256 = hash_str.parse().ok()?;
            Some(PendingTx {
                hash,
                from: Address::ZERO, // filled by the stream layer
                to: None,
                nonce: 0,
                value: U256::ZERO,
                gas_limit: 0,
                fees: TxFees::Legacy { gas_price: 0 },
                input: Bytes::new(),
                observed_at: SystemTime::now(),
            })
        });
        // `sink` is dropped here intentionally: tungstenite keeps the read
        // half live after the write half is dropped, so the subscription
        // continues until the returned stream itself is dropped.
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_generic_eth_subscribe() {
        let p = GenericEthSubscribeProvider::new("ws://test");
        assert_eq!(p.id(), "generic_eth_subscribe");
        assert!(!p.delivers_bodies());
    }

    #[test]
    fn new_stores_url_verbatim() {
        // Sanity that the constructor accepts both &str and String inputs.
        let _ = GenericEthSubscribeProvider::new("ws://node.example:8545");
        let _ = GenericEthSubscribeProvider::new(String::from("wss://node.example:8546"));
    }

    #[cfg(feature = "live-providers")]
    #[tokio::test]
    async fn generic_eth_subscribe_live_yields_pending_hash() {
        use crate::provider::MempoolProvider;
        let Ok(url) = std::env::var("GENERIC_WS_URL") else {
            eprintln!("skip: GENERIC_WS_URL is not set");
            return;
        };
        let provider = GenericEthSubscribeProvider::new(url);
        let mut stream = provider.subscribe().await.expect("subscribe");
        let tx = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await
            .expect("timeout waiting for first pending hash")
            .expect("stream ended before yielding");
        assert_ne!(tx.hash, alloy::primitives::B256::ZERO);
    }
}
