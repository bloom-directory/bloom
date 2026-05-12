//! Long-lived mempool subscription task. Owns the per-chain
//! PendingTxIndex and broadcasts each observed tx to listeners.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::broadcast;

use crate::index::PendingTxIndex;
use crate::provider::{MempoolProvider, PendingTx};

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

/// Spawn a tokio task that subscribes via `provider`, reconnects on
/// disconnect (1s → 30s exponential backoff), and broadcasts every
/// observed PendingTx. Returns a oneshot Sender; drop it or send `()`
/// to ask the task to stop after its current iteration.
pub fn spawn(
    chain_name: String,
    provider: Arc<dyn MempoolProvider>,
    stream: MempoolStream,
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
                            tracing::info!(chain = %chain_name, provider = provider.id(), "mempool.subscribed");
                            loop {
                                tokio::select! {
                                    _ = &mut shutdown_rx => return,
                                    next = s.next() => match next {
                                        Some(tx) => {
                                            stream.index.insert(tx.clone());
                                            let _ = stream.tx.send(tx);
                                        }
                                        None => {
                                            tracing::warn!(chain = %chain_name, "mempool.disconnected");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(chain = %chain_name, error = %e, "mempool.subscribe_failed");
                        }
                    }
                }
            }
            tokio::time::sleep(backoff).await;
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
            nonce: 0,
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
        let stream = MempoolStream::new(index.clone());
        let mut rx = stream.tx.subscribe();
        let _shutdown = spawn("ethereum".into(), provider, stream);
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
