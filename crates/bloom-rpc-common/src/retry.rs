//! Chain-neutral retry classification, shared by `bloom-rpc` (EVM) and
//! `bloom-solana`.
//!
//! Both transports need the same answer to "is this failure transient and
//! safe to retry / fail over on, or a deterministic error that rotating
//! endpoints won't fix" — but each transport collapses its own
//! chain-specific error type (alloy's `TransportError` for EVM, a raw
//! JSON-RPC response for Solana) down to the same two shapes first:
//! an HTTP status, or a JSON-RPC coded error with its message. This module
//! is the single rule table both classify against, so a divergence between
//! the two transports (the exact failure mode this module replaces — see
//! Fix H, PLAN-SOLANA-PR-FIXES.md) becomes structurally impossible rather
//! than a hand-maintained invariant.
//!
//! Retry: HTTP 408/429/502/503/504, JSON-RPC `-32005`/`-32007`, and the
//! free-form "rate limited", "over rate limit", "exceeded its compute
//! units", "capacity" vendor-throttling messages.
//! Never retry: deterministic errors like `-32601` method-not-found or
//! `-32004` method-not-supported — a capability gap, not a transient blip.

/// A classification input: the transport collapsed its failure to either an
/// HTTP status or a JSON-RPC error, so the policy stays transport-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySignal<'a> {
    HttpStatus(u16),
    RpcError { code: i64, message: &'a str },
}

/// Whether the signal is transient and safe to retry.
pub fn should_retry(signal: RetrySignal<'_>) -> bool {
    match signal {
        RetrySignal::HttpStatus(status) => matches!(status, 408 | 429 | 502 | 503 | 504),
        RetrySignal::RpcError { code, message } => {
            // Coded rate-limit signals.
            if matches!(code, -32005 | -32007) {
                return true;
            }
            // Free-form vendor throttling messages.
            if message.contains("rate limited")
                || message.contains("over rate limit")
                || message.contains("exceeded its compute units")
                || message.contains("capacity")
            {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_transient_http_statuses() {
        for status in [408u16, 429, 502, 503, 504] {
            assert!(should_retry(RetrySignal::HttpStatus(status)), "{status}");
        }
        assert!(!should_retry(RetrySignal::HttpStatus(400)));
        assert!(!should_retry(RetrySignal::HttpStatus(401)));
        assert!(!should_retry(RetrySignal::HttpStatus(500)));
    }

    #[test]
    fn retries_coded_rate_limit() {
        assert!(should_retry(RetrySignal::RpcError {
            code: -32005,
            message: "node is unhealthy"
        }));
        assert!(should_retry(RetrySignal::RpcError {
            code: -32007,
            message: "slot skipped"
        }));
    }

    #[test]
    fn retries_freeform_throttling_messages() {
        for message in [
            "rate limited, try again in 4ms",
            "you are over rate limit",
            "Your app has exceeded its compute units per second capacity.",
            "node at capacity, try later",
        ] {
            assert!(
                should_retry(RetrySignal::RpcError {
                    code: -32600,
                    message
                }),
                "{message}"
            );
        }
    }

    #[test]
    fn does_not_retry_deterministic_errors() {
        assert!(!should_retry(RetrySignal::RpcError {
            code: -32601,
            message: "the method getFoo does not exist/is not available"
        }));
        assert!(!should_retry(RetrySignal::RpcError {
            code: -32004,
            message: "method not supported"
        }));
    }
}
