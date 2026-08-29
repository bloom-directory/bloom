//! Shared types and config for bloom.
//!
//! Re-exports thin wrappers around alloy primitive types plus first-class
//! types for chains, wallets, intents, plans, audit log entries and the
//! daemon's on-disk layout.

#![forbid(unsafe_code)]

pub mod address;
pub mod assurance;
pub mod audit;
pub mod audit_ext;
pub mod capability;
pub mod ceremony;
pub mod chain;
pub mod config;
pub mod defi_policy;
pub mod home;
pub mod intent;
pub mod petal_identity;
pub mod plan;
pub mod policy;
pub mod polymarket_policy;
pub mod serde_micro;
pub mod tokens;
pub mod units;
pub mod valuation;

pub use address::{AddressBook, AddressBookError, checksum_address, parse_address};
pub use assurance::AssuranceLevel;
pub use audit::{AuditIdentity, AuditLog, AuditRecord, AuditTrustedPredecessor};
pub use audit_ext::{append_auth_event, auth_event};
pub use capability::{CapabilityStatus, CapabilityViewEntry, SigningModel, Venue};
pub use ceremony::{CeremonyIntent, CeremonyIntentKind};
pub use chain::{
    ChainId, ChainRef, ChainSpec, EndpointSpec, SOLANA_MAINNET_BETA_GENESIS_HASH, SolanaSpec,
    default_endpoint_weight,
};
pub use config::{
    Backend, BackendsConfig, Config, ConfigError, EnsoConfig, EtherscanConfig, MempoolChainConfig,
    PrivateRpcChainConfig,
};
pub use defi_policy::{DefiPolicy, DefiRouteCtx, ReceiverClass, evaluate_defi_route};
pub use home::{HomeDir, HomeError, HomeWritePermit};
pub use intent::{
    EnsoIntent, GasStrategy, INTENT_HASH_DOMAIN, RawIntent, RawIntentBody, ShellIntent, TxIntent,
    ValueOrToken, intent_hash_of,
};
pub use plan::{NftAction, NftRef, PlanRender, StagedTx, TokenRef, TxActionKind, TxStatus};
pub use policy::{
    AgentAutonomyMode, ApprovalPolicy, ApprovalStepUpPolicy, AuthorizationSubject,
    AuthorizationSurface, AutonomyDecision, BudgetSnapshot, LimitsPolicy, Policy, PolicyCheck,
    PolicyEditClass, PolicyOutcome, PolicyRuleClass, StepUpRuleCeiling,
    StepUpRuleCeilingValidation, classify_policy_edit, evaluate_action_authorization, has_deny,
    has_soft_violation, has_warn, validate_step_up_rule_ceilings,
};
pub use polymarket_policy::PolymarketPolicy;
pub use units::{ParsedAmount, format_units, parse_amount, parse_eth, parse_units};
pub use valuation::{ValuationError, ValuationPolicy, ValuationQuote};

/// Re-exports of alloy types we use across the workspace.
pub mod prelude {
    pub use alloy::primitives::{Address, B256, Bytes, U256};
}
