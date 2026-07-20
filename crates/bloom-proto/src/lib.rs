//! Shared types and config for bloom.
//!
//! Re-exports thin wrappers around alloy primitive types plus first-class
//! types for chains, wallets, intents, plans, audit log entries and the
//! daemon's on-disk layout.

#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod audit_ext;
pub mod capability;
pub mod ceremony;
pub mod chain;
pub mod config;
pub mod defi_policy;
pub mod home;
pub mod hyperliquid;
pub mod hyperliquid_policy;
pub mod hyperliquid_review;
pub mod hyperliquid_session;
pub mod intent;
pub mod plan;
pub mod policy;
pub mod polymarket_policy;
pub mod serde_micro;
pub mod tokens;
pub mod units;

pub use address::{AddressBook, AddressBookError, checksum_address, parse_address};
pub use audit::{AuditLog, AuditRecord};
pub use audit_ext::{append_auth_event, auth_event};
pub use capability::{CapabilityStatus, CapabilityViewEntry, SigningModel, Venue};
pub use ceremony::{CeremonyIntent, CeremonyIntentKind, policy_session_mint_intent};
pub use chain::{ChainId, ChainRef, ChainSpec, EndpointSpec, default_endpoint_weight};
pub use config::{
    Backend, BackendsConfig, Config, ConfigError, EnsoConfig, EtherscanConfig, MempoolChainConfig,
    PrivateRpcChainConfig,
};
pub use defi_policy::{DefiPolicy, DefiRouteCtx, ReceiverClass, evaluate_defi_route};
pub use home::{HomeDir, HomeError, HomeWritePermit};
pub use hyperliquid_policy::{
    HyperliquidActionCtx, HyperliquidPolicy, evaluate_hyperliquid_action,
};
pub use hyperliquid_review::{
    DEFAULT_HYPERLIQUID_AGENT_SESSION_NAME, hyperliquid_write_unlock_intent,
    resolve_hyperliquid_agent_session_name,
};
pub use hyperliquid_session::{BreachAction, HyperliquidSession, SessionStatus};
pub use intent::{
    EnsoIntent, GasStrategy, RawIntent, RawIntentBody, ShellIntent, TxIntent, ValueOrToken,
};
pub use plan::{NftAction, NftRef, PlanRender, StagedTx, TokenRef, TxStatus};
pub use policy::{
    AgentAutonomyMode, ApprovalPolicy, ApprovalStepUpPolicy, AuthorizationSubject,
    AuthorizationSurface, AutonomyDecision, BudgetSnapshot, LimitsPolicy, Policy, PolicyCheck,
    PolicyEditClass, PolicyOutcome, PolicyRuleClass, StepUpRuleCeiling,
    StepUpRuleCeilingValidation, classify_policy_edit, evaluate_action_authorization, has_deny,
    has_soft_violation, has_warn, validate_step_up_rule_ceilings,
};
pub use polymarket_policy::PolymarketPolicy;
pub use units::{ParsedAmount, format_units, parse_amount, parse_eth, parse_units};

/// Re-exports of alloy types we use across the workspace.
pub mod prelude {
    pub use alloy::primitives::{Address, B256, Bytes, U256};
}
