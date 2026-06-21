//! Capability model: the unified read-only shape for bounded trading
//! authority across all venues (Hyperliquid agent sessions, EVM
//! policy-sessions, future Polymarket capabilities).
//!
//! [`CapabilityView`] is the trait that each venue implements to project
//! its native store into the common shape rendered at
//! `/wallets/<w>/capabilities/active.json`.
//!
//! `signing_model` is **load-bearing security truth** — agents and humans
//! must know whether the owner key is still in the loop for every action
//! inside this capability.

use serde::Serialize;

/// Which venue a capability governs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Venue {
    /// EVM outbox confirm batches via policy-session.
    EvmOutbox,
    /// Hyperliquid perp/spot trading via agent sessions.
    Hyperliquid,
    /// Polymarket prediction-market orders.
    Polymarket,
    /// DeFi intent routes via Enso shortcuts.
    Defi,
}

/// Who signs actions authorised by this capability.
///
/// This is **not** an implementation detail. It tells the agent (and the
/// human at review time) whether the owner key is still resident and needed
/// for every action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningModel {
    /// The capability holds an ephemeral key the venue accepts as a delegated
    /// signer. The owner key is needed only at capability-creation time
    /// (e.g. Hyperliquid `approveAgent`).
    HoldsDelegatedKey,
    /// The capability authorises actions but every action is still signed by
    /// the owner key (which must be resident in daemon RAM for the window).
    /// This is the EVM `policy-session` and planned Polymarket model.
    AuthorizesOwnerSigning,
    /// The capability is a service credential only (HMAC / API key). It never
    /// moves funds — the owner must still sign value-moving operations
    /// separately (e.g. Polymarket builder API keys, Enso API keys).
    ServiceAuthOnly,
}

/// Lifecycle status of a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Active and accepting actions.
    Active,
    /// Time-bound expiry reached; no new actions accepted.
    Expired,
    /// Risk breach or breach-action trigger; trading halted.
    Halted,
    /// Explicitly revoked by owner or agent.
    Revoked,
    /// Daemon restart lost the in-memory signing key (HL sessions only).
    /// Owner must perform orphan recovery.
    Orphaned,
}

/// The common read-only projection of any venue's bounded authority.
///
/// Implementors: the Hyperliquid session handler and the EVM policy-session
/// store.  Future: Polymarket capability primitive.
///
/// ## Design note
///
/// Monetary limits are exposed as `limits() -> serde_json::Value` so each
/// venue can expose its own structured caps (HL has max order, max position,
/// max loss, max leverage; EVM has a single USD budget).  The `allowed` /
/// `denied` summary strings are the human-readable prose version of the
/// same information.
pub trait CapabilityView {
    fn id(&self) -> &str;
    fn wallet(&self) -> &str;
    fn venue(&self) -> Venue;
    fn signing_model(&self) -> SigningModel;
    fn created_ms(&self) -> u128;
    /// `None` for non-expiring capabilities (e.g. service credentials).
    fn expires_ms(&self) -> Option<u128>;
    fn status(&self) -> CapabilityStatus;
    /// Venue-structured monetary caps: max_order_usd, max_position_usd,
    /// max_loss_usd, max_leverage (HL); max_usd + allowed_pending_ids
    /// (EVM); max_order_usd + max_cumulative_usd + allowed_slugs
    /// (Polymarket future).  Read by machines; rendered by `allowed` /
    /// `denied` for humans.
    fn limits(&self) -> serde_json::Value;
    /// The concrete VFS path the agent should write to for the next action.
    fn next_write_path(&self) -> &str;
    /// The concrete VFS path that stops/revokes this capability.
    fn revoke_path(&self) -> &str;
    /// Pointer to the capability's audit log or journal.
    fn audit_ref(&self) -> &str;
    /// Lightweight reference to what the human approved (e.g. path to the
    /// review-intent JSON, or a content-hash).  The full envelope is
    /// available through venue-specific reads for audits.
    fn review_ref(&self) -> &str;
    /// Human-readable bullets of what this capability allows.
    fn allowed_summary(&self) -> Vec<String>;
    /// Human-readable bullets of what is explicitly excluded.
    fn denied_summary(&self) -> Vec<String>;
}

/// A serializable snapshot of a capability — what gets rendered in
/// `/wallets/<w>/capabilities/active.json`.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityViewEntry {
    pub id: String,
    pub wallet: String,
    pub venue: Venue,
    pub signing_model: SigningModel,
    pub created_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    pub status: CapabilityStatus,
    /// Venue-structured limits blob.  See [`CapabilityView::limits`].
    pub limits: serde_json::Value,
    pub next_write_path: String,
    pub revoke_path: String,
    pub audit_ref: String,
    pub review_ref: String,
    /// Prose summary of what is allowed.
    pub allowed: Vec<String>,
    /// Prose summary of what is explicitly excluded.
    pub denied: Vec<String>,
}

impl CapabilityViewEntry {
    pub fn from_view(v: &dyn CapabilityView) -> Self {
        let now_ms = now_ms_u128();
        let (expires_ms, expires_in) = if let Some(exp) = v.expires_ms() {
            let secs = if exp > now_ms {
                Some(((exp - now_ms) / 1000) as u64)
            } else {
                None
            };
            (Some(exp), secs)
        } else {
            (None, None)
        };
        Self {
            id: v.id().to_string(),
            wallet: v.wallet().to_string(),
            venue: v.venue(),
            signing_model: v.signing_model(),
            created_ms: v.created_ms(),
            expires_ms,
            expires_in_secs: expires_in,
            status: v.status(),
            limits: v.limits(),
            next_write_path: v.next_write_path().to_string(),
            revoke_path: v.revoke_path().to_string(),
            audit_ref: v.audit_ref().to_string(),
            review_ref: v.review_ref().to_string(),
            allowed: v.allowed_summary(),
            denied: v.denied_summary(),
        }
    }
}

pub fn now_ms_u128() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
