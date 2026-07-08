//! Block-pinned read sessions.
//!
//! A `Session<'a>` snapshots the chain head at construction time and
//! tags every subsequent read with the captured block hash. This lets
//! a multi-call logical operation (tx staging, an aggregate VFS leaf
//! fan-out) observe a self-consistent state across the layered fallback
//! transport — even if individual calls land on different upstream
//! providers, every call asks for the same `(blockHash, ...)` tuple.
//!
//! When a fallback peer doesn't have the pinned hash (it's behind, on a
//! different fork, or already evicted from its cache), the session
//! transparently retries with `BlockId::Number(pinned_number)` and sets
//! `is_degraded() == true` so the caller can decide whether the looser
//! consistency is acceptable. The spec (§C.6) explicitly accepts that
//! degraded path; sessions are still strictly better than the no-pin
//! status quo because the worst case (Latest fall-through) only fires
//! when no provider has the pinned hash.
//!
//! See `docs/specs/rpc-robustness.md` §C.2 / §C.6 / §E for design
//! rationale. The `client: &'a ChainClient` shape in the spec sketch is
//! realised here as a borrow of the alloy `RootProvider<Ethereum>` to
//! avoid a circular dep with `bloom-evm` — that crate's
//! `open_session` constructor wraps the borrow.

use std::sync::atomic::{AtomicBool, Ordering};

use alloy::eips::BlockId;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::eth::TransactionRequest;
use alloy::transports::TransportError;
use tracing::warn;

use crate::error::BloomRpcError;

/// A short-lived handle that pins reads to a specific block hash so
/// multi-call operations stay self-consistent across a fallback event.
///
/// Construct with `bloom_evm::ChainClient::open_session`. While the
/// session is alive its borrow keeps the underlying provider valid; do
/// not drop the originating `ChainClient` early. Sessions are cheap to
/// open (one `eth_getBlockByNumber(latest)` call) so callers can scope
/// them tightly around the fanout they need consistency over.
#[derive(Debug)]
pub struct Session<'a> {
    provider: &'a RootProvider<Ethereum>,
    chain_name: String,
    pinned_number: u64,
    pinned_hash: B256,
    degraded: AtomicBool,
}

impl<'a> Session<'a> {
    /// Internal constructor used by `bloom-evm`'s `open_session`. The
    /// caller is responsible for resolving the (latest_number,
    /// latest_hash) tuple before invoking this — the constructor stays
    /// pure-sync once it has the pinned values.
    pub fn from_pinned(
        provider: &'a RootProvider<Ethereum>,
        chain_name: impl Into<String>,
        pinned_number: u64,
        pinned_hash: B256,
    ) -> Self {
        Self {
            provider,
            chain_name: chain_name.into(),
            pinned_number,
            pinned_hash,
            degraded: AtomicBool::new(false),
        }
    }

    /// Block number captured at session open.
    pub fn block_number(&self) -> u64 {
        self.pinned_number
    }

    /// Block hash captured at session open.
    pub fn block_hash(&self) -> B256 {
        self.pinned_hash
    }

    /// True if any session call had to fall back to `BlockId::Number`
    /// because the pinned hash was unavailable on the upstream that
    /// served the request. Once tripped, the flag stays set for the
    /// lifetime of the session — callers that need strict consistency
    /// should drop and re-open.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// Chain name this session belongs to. Useful for log/event context
    /// in callers that hold sessions across `?`-propagating layers.
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// `eth_getBalance(addr, pinned)`.
    pub async fn balance(&self, addr: Address) -> Result<U256, BloomRpcError> {
        self.run_with_pin(|block| self.provider.get_balance(addr).block_id(block))
            .await
    }

    /// `eth_getTransactionCount(addr, pinned)`. Note this is the
    /// *historical* transaction count at the pinned block, not the
    /// pending nonce — the engine's pending semantics live on
    /// `ChainClient::nonce` for staging-time use cases that need
    /// in-flight tx awareness.
    pub async fn nonce(&self, addr: Address) -> Result<u64, BloomRpcError> {
        self.run_with_pin(|block| self.provider.get_transaction_count(addr).block_id(block))
            .await
    }

    /// `eth_getCode(addr, pinned)`.
    pub async fn code(&self, addr: Address) -> Result<Vec<u8>, BloomRpcError> {
        let bytes = self
            .run_with_pin(|block| self.provider.get_code_at(addr).block_id(block))
            .await?;
        Ok(bytes.to_vec())
    }

    /// `eth_call(req, pinned)`.
    pub async fn eth_call(&self, req: TransactionRequest) -> Result<Bytes, BloomRpcError> {
        // `EthCall::block` doesn't share the `RpcWithBlock` builder, so
        // we duplicate the retry shape inline. The behaviour mirrors
        // `run_with_pin`: try by hash, on "block not found" retry by
        // number and set degraded.
        let by_hash = self
            .provider
            .call(req.clone())
            .block(BlockId::Hash(self.pinned_hash.into()));
        match by_hash.await {
            Ok(v) => Ok(v),
            Err(e) if is_unknown_block_error(&e) => {
                self.mark_degraded();
                let by_num = self
                    .provider
                    .call(req)
                    .block(BlockId::Number(self.pinned_number.into()));
                Ok(by_num.await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `eth_getStorageAt(addr, slot, pinned)`. Returns a `B256` (the
    /// raw 32-byte word) so callers can interpret packed structs
    /// without an extra conversion.
    pub async fn get_storage_at(&self, addr: Address, slot: U256) -> Result<B256, BloomRpcError> {
        let val: U256 = self
            .run_with_pin(|block| self.provider.get_storage_at(addr, slot).block_id(block))
            .await?;
        Ok(B256::from(val.to_be_bytes::<32>()))
    }

    /// Run an `RpcWithBlock`-shaped call against the pinned hash and,
    /// on an "unknown block" error from the upstream, retry against
    /// `BlockId::Number` while flipping the degraded flag.
    ///
    /// The closure is called twice on the degraded path so that each
    /// attempt builds a fresh request (the `RpcWithBlock` future
    /// consumes its inner state on `await`). Callers that don't fit
    /// the `RpcWithBlock` shape — `eth_call` is the only one today —
    /// inline an equivalent dance.
    async fn run_with_pin<F, Fut, T>(&self, build: F) -> Result<T, BloomRpcError>
    where
        F: Fn(BlockId) -> Fut,
        Fut: std::future::IntoFuture<Output = Result<T, TransportError>>,
    {
        let by_hash = build(BlockId::Hash(self.pinned_hash.into()));
        match by_hash.into_future().await {
            Ok(v) => Ok(v),
            Err(e) if is_unknown_block_error(&e) => {
                self.mark_degraded();
                let by_num = build(BlockId::Number(self.pinned_number.into()));
                Ok(by_num.into_future().await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn mark_degraded(&self) {
        let was = self.degraded.swap(true, Ordering::AcqRel);
        if !was {
            warn!(
                chain = %self.chain_name,
                pinned_number = self.pinned_number,
                pinned_hash = %self.pinned_hash,
                "rpc.session.degraded_pinned_hash_unavailable"
            );
        }
    }
}

/// Heuristic match on the upstream error message for "block not found"
/// shaped errors. Permissive on purpose: each major provider phrases
/// this differently and the spec (§C.6) calls for a forgiving match.
///
/// Critically this must NOT match "method not supported" or other
/// deterministic capability gaps — those should propagate as-is so the
/// session doesn't silently mask a real bug.
fn is_unknown_block_error(error: &TransportError) -> bool {
    let msg = match error {
        TransportError::ErrorResp(payload) => payload.message.to_ascii_lowercase(),
        TransportError::DeserError { text, .. } => text.to_ascii_lowercase(),
        other => other.to_string().to_ascii_lowercase(),
    };
    // Common phrasings across geth/erigon/anvil/Alchemy/Infura/QuickNode.
    msg.contains("unknown block")
        || msg.contains("block not found")
        || msg.contains("header not found")
        || msg.contains("could not find block")
        || msg.contains("hash is not currently canonical")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::rpc::json_rpc::ErrorPayload;

    fn err_resp(code: i64, message: &str) -> TransportError {
        let payload: ErrorPayload = serde_json::from_str(&format!(
            r#"{{"code":{code},"message":{}}}"#,
            serde_json::to_string(message).unwrap()
        ))
        .unwrap();
        TransportError::ErrorResp(payload)
    }

    #[test]
    fn unknown_block_matchers_are_permissive() {
        // All five vendor phrasings should trip the matcher. If a
        // provider invents a sixth, we'll see it as a non-degraded
        // error and can extend.
        assert!(is_unknown_block_error(&err_resp(-32000, "unknown block")));
        assert!(is_unknown_block_error(&err_resp(-32000, "Block not found")));
        assert!(is_unknown_block_error(&err_resp(
            -32000,
            "header not found"
        )));
        assert!(is_unknown_block_error(&err_resp(
            -32000,
            "could not find block 0x..."
        )));
        assert!(is_unknown_block_error(&err_resp(
            -32000,
            "hash is not currently canonical"
        )));
    }

    #[test]
    fn unknown_block_matcher_does_not_swallow_method_not_supported() {
        // Regression: "method not supported" is a deterministic
        // capability gap — the session must surface it intact rather
        // than degrading. If this test fails after a string-match
        // refactor we'd silently turn unsupported `debug_traceCall`s
        // into degraded sessions on every chain.
        assert!(!is_unknown_block_error(&err_resp(
            -32601,
            "the method debug_traceCall does not exist/is not available"
        )));
        assert!(!is_unknown_block_error(&err_resp(
            -32004,
            "method not supported"
        )));
    }

    #[test]
    fn unknown_block_matcher_ignores_unrelated_errors() {
        assert!(!is_unknown_block_error(&err_resp(3, "execution reverted")));
        assert!(!is_unknown_block_error(&err_resp(
            -32000,
            "insufficient funds for gas * price + value"
        )));
    }
}
