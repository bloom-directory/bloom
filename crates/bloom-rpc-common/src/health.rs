//! Endpoint health: passive sample tracking, cooldown state machine,
//! and serialisable snapshots.
//!
//! WP-3 owns this module. Two responsibilities:
//!
//! 1. Maintain one `EndpointHealth` per configured endpoint, updated by
//!    the active probe loop in `transport.rs`. The state machine
//!    follows §C.7 of the spec: 5 consecutive failures arm a 60 s
//!    cooldown, 2 consecutive successes clear it, and a fresh cooldown
//!    within 5 minutes of a recovery escalates to 600 s
//!    (chronic-failer escalation).
//!
//! 2. Produce `EndpointHealthSnapshot` values for the VFS leaves under
//!    `chains/<n>/endpoints/<idx>/*`. Snapshots use `SystemTime` for
//!    `cooldown_until` so they serialise cleanly into the daemon's
//!    JSON/text leaves and can be read by external tooling without
//!    needing access to the in-process `Instant` clock.
//!
//! ## Scope note (filtering the fallback pool)
//!
//! Alloy's `FallbackLayer` does not expose a runtime hook to exclude
//! transports based on Bloom-side health. For WP-3 we therefore observe
//! and report cooldowns but do not actively yank an endpoint out of
//! the parallel fan-out — `cooled_down_indices()` is provided for the
//! day we either gain that hook upstream or build our own selection
//! layer. Until then, cooldowns are an observability signal only.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;
use serde::Serialize;

/// EWMA smoothing factor for endpoint latency. 0.3 weights the freshest
/// sample fairly heavily so a single slow probe is visible without a
/// burst of bad samples being able to drag the average to a value we
/// can't recover from in normal operation.
const LATENCY_EWMA_ALPHA: f64 = 0.3;

/// Rolling success-rate window length. Mirrors alloy's own internal
/// `FallbackService` window so the two health views report comparable
/// shapes for the same traffic.
const SAMPLE_WINDOW: usize = 10;

/// Consecutive failures that arm a fresh cooldown.
const FAILURE_COOLDOWN_THRESHOLD: u32 = 5;

/// Consecutive successes during cooldown that clear it.
const RECOVERY_SUCCESS_THRESHOLD: u32 = 2;

/// Default cooldown applied when the failure threshold is hit and no
/// vendor-supplied backoff hint is available.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// Escalated cooldown applied when an endpoint trips back into
/// cooldown within `CHRONIC_WINDOW` of a recovery.
const CHRONIC_COOLDOWN: Duration = Duration::from_secs(600);

/// Window in which a fresh cooldown after a recovery counts as
/// chronic-failer behaviour.
const CHRONIC_WINDOW: Duration = Duration::from_secs(300);

/// Latency past which the latency component of `score()` floors at 0.
/// Two seconds is also the active-probe timeout, so any responding
/// endpoint stays inside this band; anything slower is by definition
/// a probe miss.
const LATENCY_FLOOR_MS: u64 = 2_000;

/// Per-endpoint health state. Lives inside the `HealthRegistry` and is
/// only read/written via the registry's `record_*` methods so the
/// state-machine invariants stay in one place.
#[derive(Debug, Clone)]
pub struct EndpointHealth {
    /// Operator-facing label for the endpoint. Mirrors the URL the
    /// engine was configured with so snapshots can carry a stable id
    /// even after the endpoint cools down.
    pub last_url: String,
    /// `Some(deadline)` while the endpoint is parked. Cleared on
    /// recovery; never auto-cleared by the passage of time so callers
    /// see the full cooldown window when they snapshot.
    pub cooldown_until: Option<Instant>,
    /// EWMA of probe round-trip latency.
    pub avg_latency: Duration,
    /// Last `SAMPLE_WINDOW` outcomes — `true` for success.
    pub sample_window: VecDeque<bool>,
    /// Run of consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Run of consecutive successes since the last failure.
    pub consecutive_successes: u32,
    /// Last block number observed via this endpoint, if any.
    pub last_block: Option<u64>,
    /// Wall-clock time of the most recent successful probe. Used by
    /// the chronic-failer escalation logic.
    pub last_ok: Option<Instant>,
}

impl EndpointHealth {
    /// Build a fresh health record for `url`. All metrics start empty;
    /// the active probe loop populates them.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            last_url: url.into(),
            cooldown_until: None,
            avg_latency: Duration::ZERO,
            sample_window: VecDeque::with_capacity(SAMPLE_WINDOW),
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_block: None,
            last_ok: None,
        }
    }

    /// Success rate over the rolling sample window. Returns 0.0 when
    /// the window is empty so a brand-new endpoint is treated as
    /// "unknown" rather than "perfect".
    pub fn success_rate(&self) -> f64 {
        if self.sample_window.is_empty() {
            return 0.0;
        }
        let ok = self.sample_window.iter().filter(|b| **b).count();
        ok as f64 / self.sample_window.len() as f64
    }

    /// Composite score: 70 % success rate, 30 % latency. Both
    /// components are clamped to `[0, 1]` and the latency component
    /// degrades linearly from 0 ms (1.0) to `LATENCY_FLOOR_MS` (0.0).
    pub fn score(&self) -> f64 {
        let stability = self.success_rate();
        let latency_ms = self.avg_latency.as_millis() as f64;
        let latency_factor = (1.0 - (latency_ms / LATENCY_FLOOR_MS as f64)).clamp(0.0, 1.0);
        stability * 0.7 + latency_factor * 0.3
    }

    fn push_sample(&mut self, success: bool) {
        if self.sample_window.len() == SAMPLE_WINDOW {
            self.sample_window.pop_front();
        }
        self.sample_window.push_back(success);
    }

    fn update_latency(&mut self, sample: Duration) {
        if self.avg_latency.is_zero() {
            self.avg_latency = sample;
            return;
        }
        let prev = self.avg_latency.as_secs_f64();
        let next = sample.as_secs_f64();
        let blended = LATENCY_EWMA_ALPHA * next + (1.0 - LATENCY_EWMA_ALPHA) * prev;
        self.avg_latency = Duration::from_secs_f64(blended.max(0.0));
    }
}

/// A point-in-time view of one endpoint's health, suitable for the VFS
/// `status/chains/<n>/endpoints/<idx>/*` leaves. All fields
/// `Serialize` cleanly so callers can also embed the snapshot in
/// `daemon.json`-style aggregates.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EndpointHealthSnapshot {
    /// Configured URL for this endpoint. Callers that need to display
    /// the URL should redact it first (the VFS handler uses
    /// `redact_url` for that).
    pub url: String,
    /// Composite score in `[0, 1]`.
    pub score: f64,
    /// Cooldown deadline as wall-clock time, if currently parked.
    /// Serialised by `serde`'s default `SystemTime` impl (a `secs`/
    /// `nanos_since_epoch` object); the VFS leaf for `cooldown_until`
    /// renders the Unix-seconds form for terminal-friendly reads.
    /// `None` when the endpoint is healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_until: Option<SystemTime>,
    /// EWMA latency in milliseconds.
    pub latency_ms: u64,
    /// Success rate over the rolling sample window, `[0, 1]`.
    pub success_rate: f64,
    /// Last block number observed via this endpoint, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_block: Option<u64>,
}

/// Shared registry of endpoint health, owned by `RpcEngine` and
/// updated by the probe loop.
#[derive(Clone)]
pub struct HealthRegistry {
    inner: Arc<RwLock<Vec<EndpointHealth>>>,
}

impl HealthRegistry {
    /// Build a registry seeded with one entry per URL.
    pub fn new<I, S>(urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let inner = urls.into_iter().map(EndpointHealth::new).collect();
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// Number of endpoints tracked.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// True when no endpoints have been registered.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Record a successful probe for `idx`. `latency` is folded into
    /// the EWMA; `block` updates `last_block` when present.
    pub fn record_success(&self, idx: usize, latency: Duration, block: Option<u64>) {
        let mut guard = self.inner.write();
        let Some(h) = guard.get_mut(idx) else { return };
        h.update_latency(latency);
        h.push_sample(true);
        h.consecutive_failures = 0;
        h.consecutive_successes = h.consecutive_successes.saturating_add(1);
        h.last_ok = Some(Instant::now());
        if let Some(b) = block {
            h.last_block = Some(b);
        }
        if h.cooldown_until.is_some() && h.consecutive_successes >= RECOVERY_SUCCESS_THRESHOLD {
            h.cooldown_until = None;
        }
    }

    /// Record a failed probe for `idx`. The retryable flag is currently
    /// informational; the cooldown decision is driven by the
    /// consecutive-failure counter so chronic flakiness still arms a
    /// cooldown even when individual errors look transient.
    /// `backoff_hint`, when supplied (e.g. from `Retry-After`), is used
    /// as the cooldown duration instead of the default.
    pub fn record_failure(
        &self,
        idx: usize,
        _retryable: bool,
        backoff_hint: Option<Duration>,
    ) -> CooldownDecision {
        let mut guard = self.inner.write();
        let Some(h) = guard.get_mut(idx) else {
            return CooldownDecision::None;
        };
        h.push_sample(false);
        h.consecutive_successes = 0;
        h.consecutive_failures = h.consecutive_failures.saturating_add(1);
        if h.consecutive_failures >= FAILURE_COOLDOWN_THRESHOLD {
            let now = Instant::now();
            let chronic = h
                .last_ok
                .map(|t| now.duration_since(t) < CHRONIC_WINDOW)
                .unwrap_or(false);
            let dur = if chronic {
                CHRONIC_COOLDOWN
            } else {
                backoff_hint.unwrap_or(DEFAULT_COOLDOWN)
            };
            h.cooldown_until = Some(now + dur);
            // Reset the counter so we don't retrip on the very next
            // failure inside the same cooldown window.
            h.consecutive_failures = 0;
            return if chronic {
                CooldownDecision::Chronic(dur)
            } else {
                CooldownDecision::Fresh(dur)
            };
        }
        CooldownDecision::None
    }

    /// Snapshot of every endpoint's current health.
    pub fn snapshot(&self) -> Vec<EndpointHealthSnapshot> {
        let guard = self.inner.read();
        let now_instant = Instant::now();
        let now_system = SystemTime::now();
        guard
            .iter()
            .map(|h| {
                let cooldown_until = h.cooldown_until.and_then(|deadline| {
                    deadline
                        .checked_duration_since(now_instant)
                        .map(|remaining| now_system + remaining)
                });
                EndpointHealthSnapshot {
                    url: h.last_url.clone(),
                    score: h.score(),
                    cooldown_until,
                    latency_ms: h.avg_latency.as_millis() as u64,
                    success_rate: h.success_rate(),
                    last_block: h.last_block,
                }
            })
            .collect()
    }

    /// Indices of endpoints currently in cooldown. See the scope note
    /// at the top of the module: this is exposed for the eventual
    /// fallback-pool filter, today it is purely observability.
    pub fn cooled_down_indices(&self) -> Vec<usize> {
        let guard = self.inner.read();
        let now = Instant::now();
        guard
            .iter()
            .enumerate()
            .filter_map(|(i, h)| match h.cooldown_until {
                Some(deadline) if deadline > now => Some(i),
                _ => None,
            })
            .collect()
    }

    /// Number of endpoints currently in cooldown. Convenience for
    /// status-style displays that don't need the full index list.
    pub fn cooled_down_count(&self) -> usize {
        self.cooled_down_indices().len()
    }
}

/// What `record_failure` ended up doing — useful to the probe loop for
/// pretty tracing without it having to re-query the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownDecision {
    /// Failure recorded but no cooldown armed.
    None,
    /// A fresh cooldown was armed for the given duration.
    Fresh(Duration),
    /// Endpoint is a chronic failer — escalated cooldown applied.
    Chronic(Duration),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_for(url: &str) -> HealthRegistry {
        HealthRegistry::new(std::iter::once(url))
    }

    fn force_cooldown(reg: &HealthRegistry, idx: usize) {
        for _ in 0..FAILURE_COOLDOWN_THRESHOLD {
            reg.record_failure(idx, true, None);
        }
    }

    #[test]
    fn health_records_success_failure() {
        let reg = registry_for("http://example/0");
        // Record one success and one failure; the sample window must
        // reflect both and the EWMA latency must be non-zero.
        reg.record_success(0, Duration::from_millis(120), Some(42));
        reg.record_failure(0, true, None);
        let snap = reg.snapshot().pop().unwrap();
        assert_eq!(snap.url, "http://example/0");
        assert!(snap.latency_ms > 0, "latency should be populated");
        assert_eq!(snap.last_block, Some(42));
        // 1/2 successes ⇒ 0.5 success rate.
        assert!((snap.success_rate - 0.5).abs() < 1e-6);
        // Score is 0.7 * 0.5 + 0.3 * latency_factor; both terms
        // bounded so just sanity-check the range.
        assert!((0.0..=1.0).contains(&snap.score));
    }

    #[test]
    fn cooldown_after_5_failures() {
        let reg = registry_for("http://example/0");
        for _ in 0..(FAILURE_COOLDOWN_THRESHOLD - 1) {
            reg.record_failure(0, true, None);
        }
        assert!(
            reg.cooled_down_indices().is_empty(),
            "shouldn't cooldown before the threshold"
        );
        let decision = reg.record_failure(0, true, None);
        assert!(matches!(decision, CooldownDecision::Fresh(_)));
        assert_eq!(reg.cooled_down_indices(), vec![0]);
    }

    #[test]
    fn recovery_after_2_successes() {
        let reg = registry_for("http://example/0");
        force_cooldown(&reg, 0);
        assert_eq!(reg.cooled_down_count(), 1);
        // First success during cooldown resets the failure counter
        // but does NOT clear the cooldown.
        reg.record_success(0, Duration::from_millis(50), Some(1));
        assert_eq!(reg.cooled_down_count(), 1);
        // Second success clears the cooldown.
        reg.record_success(0, Duration::from_millis(50), Some(2));
        assert_eq!(reg.cooled_down_count(), 0);
    }

    #[test]
    fn chronic_failer_escalates() {
        let reg = registry_for("http://example/0");
        // First, record a successful probe so `last_ok` is set —
        // chronic escalation requires a recovery to compare against.
        reg.record_success(0, Duration::from_millis(80), Some(1));
        // Trip the cooldown.
        force_cooldown(&reg, 0);
        // Recover.
        reg.record_success(0, Duration::from_millis(80), Some(2));
        reg.record_success(0, Duration::from_millis(80), Some(3));
        assert_eq!(reg.cooled_down_count(), 0);
        // Re-trip immediately — within the chronic window.
        for _ in 0..(FAILURE_COOLDOWN_THRESHOLD - 1) {
            reg.record_failure(0, true, None);
        }
        let decision = reg.record_failure(0, true, None);
        match decision {
            CooldownDecision::Chronic(d) => assert_eq!(d, CHRONIC_COOLDOWN),
            other => panic!("expected chronic escalation, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_serialises_cleanly() {
        let reg = registry_for("https://rpc.example.com");
        reg.record_success(0, Duration::from_millis(200), Some(99));
        let snaps = reg.snapshot();
        let json = serde_json::to_string(&snaps).unwrap();
        // Round-trip sanity: structurally the field set we expose must
        // survive serde (we don't impl Deserialize, so just parse as
        // an opaque value and check the keys we care about exist).
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let row = &parsed[0];
        assert_eq!(row["url"], "https://rpc.example.com");
        assert_eq!(row["last_block"], 99);
        assert!(row["latency_ms"].is_u64());
        assert!(row["success_rate"].is_number());
        assert!(row["score"].is_number());
        // Healthy endpoint ⇒ no cooldown_until field thanks to
        // `skip_serializing_if`.
        assert!(row.get("cooldown_until").is_none());
    }
}
