//! Mempool observability + private orderflow + MEV heuristic.
//!
//! See `docs/specs/2026-05-12-mempool-and-private-orderflow-design.md`.

pub mod bump;
pub mod heuristic;
pub mod index;
pub mod private;
pub mod provider;
pub mod providers;
pub mod stream;

pub use bump::compute_replacement_fees;
pub use heuristic::{
    HeuristicConfig, MevRisk, MevRiskReport, QuoteOracle, StaticQuoter, decode_swap_path, evaluate,
};
pub use index::PendingTxIndex;
pub use private::{
    HealthStatus, MAINNET_CHAIN_ID, MockPrivateRpcProvider, PrivateRpcError, PrivateRpcProvider,
    SEPOLIA_CHAIN_ID,
};
pub use provider::{MempoolError, MempoolProvider, MockMempoolProvider, PendingTx, TxFees};
pub use stream::MempoolStream;
