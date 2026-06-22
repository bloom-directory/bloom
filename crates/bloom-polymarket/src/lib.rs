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
#[cfg(feature = "native-client")]
pub mod clob;
pub mod creds;
#[cfg(feature = "native-client")]
pub mod data;
pub mod eip712;
#[cfg(feature = "native-client")]
pub mod gamma;
#[cfg(feature = "native-client")]
pub mod geoblock;
#[cfg(feature = "native-client")]
pub mod onboard;
pub mod order;
pub mod order_store;
#[cfg(feature = "native-client")]
pub mod relayer;
pub mod signer;
#[cfg(test)]
pub(crate) mod testutil;
#[cfg(feature = "native-client")]
pub mod trade;
pub mod types;
pub mod wallet;

pub use builder_creds::{BuilderApiKeyInfo, BuilderCredentialStore, BuilderCredentials};
#[cfg(feature = "native-client")]
pub use clob::ClobClient;
pub use creds::CredentialStore;
#[cfg(feature = "native-client")]
pub use data::DataClient;
pub use eip712::{deposit_wallet_implementation, derive_deposit_wallet_address};
#[cfg(feature = "native-client")]
pub use gamma::GammaClient;
#[cfg(feature = "native-client")]
pub use geoblock::{GeoblockClient, GeoblockStatus};
#[cfg(feature = "native-client")]
pub use onboard::{
    ChainReader, OnboardEvent, OnboardMode, OnboardState, OnboardStore, Onboarder, Stage,
};
pub use order_store::{DraftStatus, OrderDraft, OrderLock, OrderReceipt, OrderStore};
#[cfg(feature = "native-client")]
pub use relayer::{RelayerClient, RelayerTx};
pub use signer::KeystoreSigner;
pub use types::{BookLevel, Credentials, Market, OrderBook, Position, Side, TokenMarket, Trade};
pub use wallet_name::validate_wallet_name;

mod wallet_name {
    use crate::{PolymarketError, Result};

    pub fn validate_wallet_name(name: &str) -> Result<()> {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
            || name == "."
            || name == ".."
        {
            return Err(PolymarketError::invalid(format!(
                "invalid wallet name '{name}'"
            )));
        }
        Ok(())
    }
}

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
    #[cfg(feature = "native-client")]
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
