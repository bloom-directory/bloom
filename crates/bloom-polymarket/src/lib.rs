//! Polymarket v2 client for bloom (hand-roll path).
//!
//! Pure library crate — no VFS coupling, no `bloom-keystore` dependency. It
//! provides:
//!
//! - read clients for the three public Polymarket APIs ([`GammaClient`],
//!   [`DataClient`], [`ClobClient`]);
//! - the **auth-signing foundation**: L1 `ClobAuth` EIP-712 (mint/derive CLOB
//!   API credentials) and L2 HMAC-SHA256 request signing, both driven by
//!   [`KeystoreSigner`] — a thin, non-custodial wrapper over a pure-alloy
//!   [`alloy::signers::local::PrivateKeySigner`] that the caller supplies;
//! - the deterministic deposit-wallet address derivation ([`eip712`]);
//! - **onboarding**: the idempotent, resumable state machine ([`Onboarder`]:
//!   deploy → fund → approve → creds → sync) over the hand-rolled relayer
//!   client ([`RelayerClient`]), the V2 approval-call builders ([`wallet`]),
//!   and the 0600 CLOB credential store ([`CredentialStore`]);
//! - the fail-closed [`GeoblockClient`] refuse-line.
//!
//! - **orders** ([`order`]): V2 EIP-712 order building/signing for the
//!   deposit-wallet path (signatureType 3 / POLY_1271) with integer micro-unit
//!   amount math, verified by known-answer tests against independent EIP-712
//!   implementations and official SDK source shapes.
//!
//! The private key never leaves the supplied signer; no code path serializes
//! it. The reference for every byte-exact signing detail is the official
//! `Polymarket/rs-clob-client-v2` SDK (we hand-roll to avoid pulling its
//! `alloy 1.6` major alongside bloom's `alloy 2`).

#![forbid(unsafe_code)]

pub mod builder_creds;
pub mod clob;
pub mod creds;
pub mod data;
pub mod eip712;
pub mod gamma;
pub mod geoblock;
pub mod onboard;
pub mod order;
pub mod order_store;
pub mod relayer;
pub mod signer;
#[cfg(test)]
pub(crate) mod testutil;
pub mod trade;
pub mod types;
pub mod wallet;

pub use builder_creds::{BuilderApiKeyInfo, BuilderCredentialStore, BuilderCredentials};
pub use clob::ClobClient;
pub use creds::CredentialStore;
pub use data::DataClient;
pub use eip712::{deposit_wallet_implementation, derive_deposit_wallet_address};
pub use gamma::GammaClient;
pub use geoblock::{GeoblockClient, GeoblockStatus};
pub use onboard::{
    ChainReader, OnboardEvent, OnboardMode, OnboardState, OnboardStore, Onboarder, Stage,
    validate_wallet_name,
};
pub use order_store::{DraftStatus, OrderDraft, OrderLock, OrderReceipt, OrderStore};
pub use relayer::{RelayerClient, RelayerTx};
pub use signer::KeystoreSigner;
pub use types::{BookLevel, Credentials, Market, OrderBook, Position, Side, TokenMarket, Trade};

/// Polygon mainnet chain id — where Polymarket settles.
pub const POLYGON: u64 = 137;
/// Polygon Amoy testnet chain id (used by the SDK's known-answer vectors).
pub const AMOY: u64 = 80_002;

/// Default public base URLs for the three Polymarket APIs.
pub const DEFAULT_GAMMA_URL: &str = "https://gamma-api.polymarket.com";
pub const DEFAULT_DATA_URL: &str = "https://data-api.polymarket.com";
pub const DEFAULT_CLOB_URL: &str = "https://clob.polymarket.com";

/// Errors surfaced by the Polymarket clients.
#[derive(Debug, thiserror::Error)]
pub enum PolymarketError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Non-2xx HTTP response from a Polymarket API.
    #[error("polymarket api error (status {status}): {body}")]
    Api { status: u16, body: String },
    /// A signing / credential-derivation failure.
    #[error("signing: {0}")]
    Signing(String),
    /// Malformed or unexpected input (bad address, empty result, …).
    #[error("invalid: {0}")]
    Invalid(String),
}

impl PolymarketError {
    pub fn signing(s: impl Into<String>) -> Self {
        PolymarketError::Signing(s.into())
    }
    pub fn invalid(s: impl Into<String>) -> Self {
        PolymarketError::Invalid(s.into())
    }
}

pub type Result<T> = std::result::Result<T, PolymarketError>;
