//! Shared types and config for bloom.
//!
//! Re-exports thin wrappers around alloy primitive types plus first-class
//! types for chains, wallets, intents, plans, audit log entries and the
//! daemon's on-disk layout.

#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod chain;
pub mod config;
pub mod home;
pub mod intent;
pub mod plan;
pub mod policy;
pub mod units;

pub use address::{AddressBook, AddressBookError, checksum_address, parse_address};
pub use audit::{AuditLog, AuditRecord};
pub use chain::{ChainId, ChainRef, ChainSpec, EndpointSpec, default_endpoint_weight};
pub use config::{
    Backend, BackendsConfig, Config, ConfigError, EnsoConfig, EtherscanConfig, MempoolChainConfig,
    PrivateRpcChainConfig,
};
pub use home::{HomeDir, HomeError};
pub use intent::{
    EnsoIntent, GasStrategy, RawIntent, RawIntentBody, ShellIntent, TxIntent, ValueOrToken,
};
pub use plan::{NftAction, NftRef, PlanRender, StagedTx, TokenRef, TxStatus};
pub use policy::{Policy, PolicyCheck, PolicyOutcome};
pub use units::{ParsedAmount, format_units, parse_amount, parse_eth, parse_units};

/// Re-exports of alloy types we use across the workspace.
pub mod prelude {
    pub use alloy::primitives::{Address, B256, Bytes, U256};
}
