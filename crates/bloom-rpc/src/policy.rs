//! Retry policy layered on top of alloy's `RateLimitRetryPolicy`.
//!
//! Alloy already covers HTTP 429 / 503, JSON-RPC `-32005` / `-32007`,
//! Infura's `data.rate.backoff_seconds`, "rate limited, try again in
//! Xms" messages, and `null` responses. This module adds the
//! vendor-specific patterns alloy doesn't already match (Alchemy
//! "exceeded its compute units", "over rate limit", "capacity"
//! responses) plus the HTTP 408/502/504 set that surfaces from flaky
//! frontends — sourced from [`bloom_rpc_common::retry`], the same
//! chain-neutral rule table `bloom-solana`'s transport classifies
//! against, so the two transports can't drift apart (Fix H,
//! PLAN-SOLANA-PR-FIXES.md). Deterministic JSON-RPC errors like "method
//! not supported" are explicitly NOT retried — pinned by a unit test
//! below.

use std::time::Duration;

use alloy::transports::TransportError;
use alloy::transports::layers::{RateLimitRetryPolicy, RetryPolicy};
use bloom_rpc_common::retry::{RetrySignal, should_retry as shared_should_retry};

/// Bloom's retry policy. Composes alloy's default with extra
/// detection rules; the alloy policy still runs as the fallback so any
/// future signal upstream adds (without us noticing) is honoured for
/// free.
#[derive(Debug, Clone, Default)]
pub struct BloomRetryPolicy {
    inner: RateLimitRetryPolicy,
}

impl RetryPolicy for BloomRetryPolicy {
    fn should_retry(&self, error: &TransportError) -> bool {
        if self.inner.should_retry(error) {
            return true;
        }
        if matches_extended_rule(error) {
            return true;
        }
        false
    }

    fn backoff_hint(&self, error: &TransportError) -> Option<Duration> {
        self.inner.backoff_hint(error)
    }
}

/// Returns true if the error matches one of the shared retry rules.
/// Overlaps with what alloy's default `RateLimitRetryPolicy` already
/// handles (429/503, -32005/-32007, "rate limited ...") are harmless —
/// `should_retry` consults the inner policy first, this is the fallback —
/// and keeping the full shared table here (rather than only the subset
/// alloy doesn't cover) is exactly what keeps this in lockstep with
/// `bloom-solana`'s classification instead of two hand-maintained lists.
fn matches_extended_rule(error: &TransportError) -> bool {
    use alloy::transports::TransportErrorKind;

    if let TransportError::Transport(TransportErrorKind::HttpError(http)) = error
        && shared_should_retry(RetrySignal::HttpStatus(http.status))
    {
        return true;
    }
    if let TransportError::ErrorResp(payload) = error
        && shared_should_retry(RetrySignal::RpcError {
            code: payload.code,
            message: &payload.message,
        })
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::rpc::json_rpc::ErrorPayload;
    use alloy::transports::TransportErrorKind;

    fn http_err(status: u16) -> TransportError {
        TransportErrorKind::http_error(status, "{}".into())
    }

    fn err_resp(code: i64, message: &str) -> TransportError {
        let payload: ErrorPayload = serde_json::from_str(&format!(
            r#"{{"code":{code},"message":{}}}"#,
            serde_json::to_string(message).unwrap()
        ))
        .unwrap();
        TransportError::ErrorResp(payload)
    }

    #[test]
    fn retry_policy_extends_alloy_for_429() {
        // Sentinel: anything alloy already handles must still be
        // retried after we wrap. A regression here means we accidentally
        // shadowed the inner policy's decision.
        let policy = BloomRetryPolicy::default();
        assert!(policy.should_retry(&http_err(429)));
        assert!(policy.should_retry(&http_err(503)));
        assert!(policy.should_retry(&err_resp(-32005, "rate limited, try again in 4ms")));
    }

    #[test]
    fn retry_policy_handles_alchemy_compute_units() {
        let policy = BloomRetryPolicy::default();
        let err = err_resp(
            -32600,
            "Your app has exceeded its compute units per second capacity.",
        );
        assert!(policy.should_retry(&err));
    }

    #[test]
    fn retry_policy_handles_408_502_504() {
        let policy = BloomRetryPolicy::default();
        for status in [408u16, 502, 504] {
            assert!(
                policy.should_retry(&http_err(status)),
                "expected retry on HTTP {status}"
            );
        }
        // Spot-check a non-retryable status so we don't accidentally
        // start retrying everything 4xx.
        assert!(!policy.should_retry(&http_err(400)));
        assert!(!policy.should_retry(&http_err(401)));
    }

    #[test]
    fn retry_policy_does_not_retry_method_not_supported() {
        // §F.2 of the spec: deterministic JSON-RPC errors must NOT
        // rotate transports. `debug_traceCall` not being available on a
        // free-tier endpoint is a deterministic capability gap, not a
        // transient rate-limit. Pinning the behaviour here keeps a
        // future cleanup of the policy from accidentally widening it.
        let policy = BloomRetryPolicy::default();
        let err = err_resp(
            -32601,
            "the method debug_traceCall does not exist/is not available",
        );
        assert!(!policy.should_retry(&err));
        let err = err_resp(-32004, "method not supported");
        assert!(!policy.should_retry(&err));
    }

    #[test]
    fn retry_policy_handles_capacity_messages() {
        let policy = BloomRetryPolicy::default();
        assert!(policy.should_retry(&err_resp(429, "you are over rate limit")));
        assert!(policy.should_retry(&err_resp(429, "node at capacity, try later")));
    }
}
