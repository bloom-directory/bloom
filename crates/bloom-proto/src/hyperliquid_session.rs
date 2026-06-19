//! Pure data model + lifecycle for a bounded Hyperliquid trading session.
//!
//! A session is minted by one passkey ceremony that approves an ephemeral API
//! ("agent") wallet (see `bloom_hyperliquid::sign_approve_agent`). This module
//! is the **pure** core: no signer, no network. The daemon holds the agent key
//! and feeds in clearinghouse snapshots; this type decides when the session has
//! expired or breached its risk envelope and what to do about it.
//!
//! It is the real drawdown stop that the per-action policy gate
//! ([`crate::hyperliquid_policy`]) cannot be — losses accrue on resting
//! positions from market moves, so the stop must be re-evaluated continuously
//! against live account value, not only at order time.

use crate::hyperliquid_policy::HyperliquidPolicy;

/// Default session lifetime when the policy sets no `max_session_secs`.
pub const DEFAULT_SESSION_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    /// TTL elapsed — no new risk; resting orders should be cancelled.
    Expired,
    /// A hard risk breach — positions should be flattened.
    Halted,
}

/// Escalating action the daemon should take, from a session evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachAction {
    None,
    /// Stop trading: cancel resting orders (e.g. on expiry).
    CancelAll,
    /// Flatten: cancel orders **and** close positions (e.g. loss breach).
    CloseAll,
}

/// A bounded trading session and its live risk state.
#[derive(Debug, Clone)]
pub struct HyperliquidSession {
    pub id: String,
    pub wallet: String,
    /// The ephemeral agent (API) wallet address this session trades through.
    pub agent_address: String,
    pub bounds: HyperliquidPolicy,
    pub created_ms: u128,
    pub expires_ms: u128,
    /// Account value at mint, micro-USD — the drawdown baseline.
    pub starting_account_value_micro: Option<u64>,
    // ── live risk (updated from snapshots) ──
    pub account_value_micro: Option<u64>,
    pub unrealized_loss_micro: u64,
    pub cumulative_notional_micro: u64,
    pub open_orders: u32,
    pub open_positions: u32,
    pub status: SessionStatus,
}

impl HyperliquidSession {
    pub fn new(
        id: impl Into<String>,
        wallet: impl Into<String>,
        agent_address: impl Into<String>,
        bounds: HyperliquidPolicy,
        starting_account_value_micro: Option<u64>,
        now_ms: u128,
    ) -> Self {
        let ttl = bounds.max_session_secs.unwrap_or(DEFAULT_SESSION_SECS);
        Self {
            id: id.into(),
            wallet: wallet.into(),
            agent_address: agent_address.into(),
            bounds,
            created_ms: now_ms,
            expires_ms: now_ms + (ttl as u128) * 1000,
            starting_account_value_micro,
            account_value_micro: starting_account_value_micro,
            unrealized_loss_micro: 0,
            cumulative_notional_micro: 0,
            open_orders: 0,
            open_positions: 0,
            status: SessionStatus::Active,
        }
    }

    pub fn is_expired(&self, now_ms: u128) -> bool {
        now_ms >= self.expires_ms
    }

    /// Drawdown from the session's starting account value, micro-USD. This is
    /// the true session loss (includes market moves on resting positions), as
    /// opposed to a single order's notional.
    pub fn drawdown_micro(&self) -> u64 {
        match (self.starting_account_value_micro, self.account_value_micro) {
            (Some(start), Some(now)) => start.saturating_sub(now),
            // Fall back to observed unrealized loss when account value is unknown.
            _ => self.unrealized_loss_micro,
        }
    }

    /// Feed a fresh clearinghouse snapshot into the session.
    pub fn update_risk(
        &mut self,
        account_value_micro: Option<u64>,
        unrealized_loss_micro: u64,
        open_orders: u32,
        open_positions: u32,
    ) {
        if account_value_micro.is_some() {
            self.account_value_micro = account_value_micro;
        }
        self.unrealized_loss_micro = unrealized_loss_micro;
        self.open_orders = open_orders;
        self.open_positions = open_positions;
    }

    /// Record an authorized order's notional against the cumulative budget.
    pub fn record_order(&mut self, notional_micro: u64) {
        self.cumulative_notional_micro = self
            .cumulative_notional_micro
            .saturating_add(notional_micro);
    }

    /// Decide what the daemon should do right now. Loss breach (a hard risk
    /// event) escalates to `CloseAll`; expiry to `CancelAll`. Mutates `status`.
    pub fn evaluate(&mut self, now_ms: u128) -> BreachAction {
        // Loss breach takes precedence — flatten regardless of expiry.
        if let Some(cap) = self.bounds.max_loss_usd
            && self.drawdown_micro() > cap
        {
            self.status = SessionStatus::Halted;
            return BreachAction::CloseAll;
        }
        if self.is_expired(now_ms) {
            self.status = SessionStatus::Expired;
            return BreachAction::CancelAll;
        }
        BreachAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(
        now: u128,
        max_loss: Option<u64>,
        ttl: Option<u64>,
        start: Option<u64>,
    ) -> HyperliquidSession {
        let bounds = HyperliquidPolicy {
            max_loss_usd: max_loss,
            max_session_secs: ttl,
            ..Default::default()
        };
        HyperliquidSession::new("s1", "alice", "0xagent", bounds, start, now)
    }

    #[test]
    fn ttl_defaults_and_expiry() {
        let s = session(0, None, None, None);
        assert_eq!(s.expires_ms, (DEFAULT_SESSION_SECS as u128) * 1000);
        assert!(!s.is_expired(1000));
        assert!(s.is_expired(s.expires_ms));
    }

    #[test]
    fn expiry_triggers_cancel_all() {
        let mut s = session(0, None, Some(60), Some(1_000_000));
        assert_eq!(s.evaluate(1000), BreachAction::None);
        let exp = s.expires_ms;
        assert_eq!(s.evaluate(exp), BreachAction::CancelAll);
        assert_eq!(s.status, SessionStatus::Expired);
    }

    #[test]
    fn drawdown_breach_triggers_close_all_even_before_expiry() {
        // Start $1000, cap loss $20.
        let mut s = session(0, Some(20_000_000), Some(3600), Some(1_000_000_000));
        // Market moves: account value drops to $975 → $25 drawdown > $20.
        s.update_risk(Some(975_000_000), 25_000_000, 1, 1);
        assert_eq!(s.drawdown_micro(), 25_000_000);
        assert_eq!(s.evaluate(1000), BreachAction::CloseAll);
        assert_eq!(s.status, SessionStatus::Halted);
    }

    #[test]
    fn within_bounds_is_no_action() {
        let mut s = session(0, Some(100_000_000), Some(3600), Some(1_000_000_000));
        s.update_risk(Some(995_000_000), 5_000_000, 2, 1);
        assert_eq!(s.evaluate(1000), BreachAction::None);
        assert_eq!(s.status, SessionStatus::Active);
    }

    #[test]
    fn cumulative_notional_accumulates() {
        let mut s = session(0, None, Some(3600), None);
        s.record_order(30_000_000);
        s.record_order(20_000_000);
        assert_eq!(s.cumulative_notional_micro, 50_000_000);
    }

    #[test]
    fn drawdown_falls_back_to_unrealized_when_account_value_unknown() {
        let mut s = session(0, Some(10_000_000), Some(3600), None); // no start value
        s.update_risk(None, 12_000_000, 1, 1);
        assert_eq!(s.drawdown_micro(), 12_000_000);
        assert_eq!(s.evaluate(1000), BreachAction::CloseAll);
    }
}
