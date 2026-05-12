//! Long-lived mempool subscription task. Owns the per-chain
//! PendingTxIndex and broadcasts each observed tx to listeners.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::broadcast;

use crate::index::PendingTxIndex;
use crate::provider::{MempoolProvider, PendingTx};

/// Sink for events observed by a `MempoolStream` reconnect loop.
/// Implementors react to each transaction and to subscription state
/// transitions. The default `MempoolStream` impl just updates the
/// shared `PendingTxIndex` and broadcasts on its internal channel,
/// preserving the original behavior for callers that don't need the
/// richer surface (tests, future consumers).
pub trait MempoolSink: Send + Sync {
    fn ingest(&self, tx: PendingTx);
    fn set_subscribed(&self) {}
    fn set_disconnected(&self) {}
    fn increment_dropped(&self, _n: u64) {}
}

#[derive(Clone)]
pub struct MempoolStream {
    pub tx: broadcast::Sender<PendingTx>,
    pub index: Arc<PendingTxIndex>,
}

impl MempoolStream {
    pub fn new(index: Arc<PendingTxIndex>) -> Self {
        Self {
            tx: broadcast::channel(4096).0,
            index,
        }
    }
}

impl MempoolSink for MempoolStream {
    fn ingest(&self, tx: PendingTx) {
        self.index.insert(tx.clone());
        let _ = self.tx.send(tx);
    }
}

/// Spawn a tokio task that subscribes via `provider`, reconnects on
/// disconnect (1s → 30s exponential backoff), and calls `sink` for
/// every observed PendingTx and state transition. Returns a oneshot
/// Sender; drop it or send `()` to ask the task to stop after its
/// current iteration.
pub fn spawn(
    chain_name: String,
    provider: Arc<dyn MempoolProvider>,
    sink: Arc<dyn MempoolSink>,
) -> tokio::sync::oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                connect = provider.subscribe() => {
                    match connect {
                        Ok(mut s) => {
                            backoff = Duration::from_secs(1);
                            sink.set_subscribed();
                            tracing::info!(chain = %chain_name, provider = provider.id(), "mempool.subscribed");
                            loop {
                                tokio::select! {
                                    _ = &mut shutdown_rx => return,
                                    next = s.next() => match next {
                                        Some(tx) => {
                                            sink.ingest(tx);
                                        }
                                        None => {
                                            tracing::warn!(chain = %chain_name, "mempool.disconnected");
                                            sink.set_disconnected();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(chain = %chain_name, error = %e, "mempool.subscribe_failed");
                            sink.set_disconnected();
                        }
                    }
                }
            }
            tokio::select! {
                _ = &mut shutdown_rx => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(max_backoff);
        }
    });
    shutdown_tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{MockMempoolProvider, PendingTx, TxFees};
    use alloy::primitives::{Address, B256, Bytes, U256};
    use std::time::SystemTime;

    fn fx(b: u8) -> PendingTx {
        let mut h = [0u8; 32];
        h[0] = b;
        PendingTx {
            hash: B256::from(h),
            from: Address::ZERO,
            to: None,
            // Distinct nonce per fixture: same-(addr, nonce) inserts collapse
            // to a single index entry, which would mask the count assertion.
            nonce: b as u64,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn stream_inserts_provider_items_into_index_and_broadcasts() {
        let provider: Arc<dyn MempoolProvider> =
            Arc::new(MockMempoolProvider::new("mock", vec![fx(1), fx(2)]));
        let index = PendingTxIndex::new(8);
        let stream = Arc::new(MempoolStream::new(index.clone()));
        let mut rx = stream.tx.subscribe();
        let _shutdown = spawn(
            "ethereum".into(),
            provider,
            stream.clone() as Arc<dyn MempoolSink>,
        );
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(
            first.hash,
            B256::from({
                let mut a = [0u8; 32];
                a[0] = 1;
                a
            })
        );
    }
}
