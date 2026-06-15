//! Shared types and config for bloom.
//!
//! Re-exports thin wrappers around alloy primitive types plus first-class
//! types for chains, wallets, intents, plans, audit log entries and the
//! daemon's on-disk layout.

#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod ceremony;
pub mod chain;
pub mod config;
pub mod defi_policy;
pub mod home;
pub mod intent;
pub mod plan;
pub mod policy;
pub mod polymarket_policy;
pub mod units;

pub use address::{AddressBook, AddressBookError, checksum_address, parse_address};
pub use audit::{AuditLog, AuditRecord};
pub use ceremony::{CeremonyIntent, CeremonyIntentKind};
pub use chain::{ChainId, ChainRef, ChainSpec, EndpointSpec, default_endpoint_weight};
pub use config::{
    Backend, BackendsConfig, Config, ConfigError, EnsoConfig, EtherscanConfig, MempoolChainConfig,
    PrivateRpcChainConfig,
};
pub use defi_policy::{
    DefiPolicy, DefiRouteCtx, ReceiverClass, evaluate_defi_route, has_deny as defi_has_deny,
    has_warn as defi_has_warn,
};
pub use home::{HomeDir, HomeError, HomeWritePermit};
pub use intent::{
    EnsoIntent, GasStrategy, RawIntent, RawIntentBody, ShellIntent, TxIntent, ValueOrToken,
};
pub use plan::{NftAction, NftRef, PlanRender, StagedTx, TokenRef, TxStatus};
pub use policy::{
    AgentAutonomyMode, ApprovalPolicy, AuthorizationSubject, AuthorizationSurface,
    AutonomyDecision, BroadcastApprovalDecision, BudgetSnapshot, LimitsPolicy, Policy, PolicyCheck,
    PolicyOutcome, evaluate_action_authorization, evaluate_broadcast_approval,
};
pub use polymarket_policy::{
    PolicySide, PolymarketOrderCtx, PolymarketPolicy, evaluate_polymarket_order,
};
pub use units::{ParsedAmount, format_units, parse_amount, parse_eth, parse_units};

/// Re-exports of alloy types we use across the workspace.
pub mod prelude {
    pub use alloy::primitives::{Address, B256, Bytes, U256};
}
