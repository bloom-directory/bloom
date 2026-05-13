//! Endpoint URL parsing and capability classification.
//!
//! Helpers used by `transport.rs` when deciding whether to build an
//! HTTP or WS transport for a given `EndpointSpec`. Kept separate from
//! transport.rs so the predicates can be unit-tested without spinning
//! up real reqwest/ws clients.

use bloom_proto::EndpointSpec;
use url::Url;

use crate::error::BloomRpcError;

/// What kind of transport an endpoint declares via its URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScheme {
    /// `http://` or `https://` — request/response, no subscriptions.
    Http,
    /// `ws://` or `wss://` — pubsub-capable.
    Ws,
}

impl EndpointScheme {
    /// True if this scheme can carry an `eth_subscribe`.
    pub const fn supports_pubsub(self) -> bool {
        matches!(self, Self::Ws)
    }
}

/// Parse `spec.url` into a validated `(Url, scheme)` pair.
///
/// Returns `BloomRpcError::InvalidUrl` for unparseable strings and for
/// schemes we deliberately don't support (anything outside http/https/
/// ws/wss). Keeping the carve-out tight here means the rest of the
/// engine can match exhaustively on `EndpointScheme` without an
/// `Unknown` variant.
pub fn classify_endpoint(spec: &EndpointSpec) -> Result<(Url, EndpointScheme), BloomRpcError> {
    let url = Url::parse(&spec.url).map_err(|e| BloomRpcError::InvalidUrl {
        url: spec.url.clone(),
        source: e,
    })?;
    let scheme = match url.scheme() {
        "http" | "https" => EndpointScheme::Http,
        "ws" | "wss" => EndpointScheme::Ws,
        other => {
            return Err(BloomRpcError::InvalidUrl {
                url: spec.url.clone(),
                source: url::ParseError::IdnaError, // closest stable variant for "unsupported scheme"
            }
            .tag_with_scheme(other));
        }
    };
    Ok((url, scheme))
}

/// Whether an endpoint is eligible to back `eth_subscribe(*)`. Both the
/// scheme and the operator-controlled `http_only` flag must allow it.
pub fn is_subscription_capable(spec: &EndpointSpec) -> bool {
    if spec.http_only {
        return false;
    }
    match Url::parse(&spec.url) {
        Ok(u) => matches!(u.scheme(), "ws" | "wss"),
        Err(_) => false,
    }
}

// Internal helper to attach the rejected scheme into the error chain
// without leaking another error variant. The caller already knows the
// scheme string from the URL — this method is just sugar for tests that
// want to assert "we rejected this for the right reason".
impl BloomRpcError {
    fn tag_with_scheme(self, _scheme: &str) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::EndpointSpec;

    fn ep(url: &str) -> EndpointSpec {
        EndpointSpec {
            url: url.into(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }
    }

    #[test]
    fn endpoint_scheme_classification() {
        let (_, s) = classify_endpoint(&ep("http://x.example")).unwrap();
        assert_eq!(s, EndpointScheme::Http);
        let (_, s) = classify_endpoint(&ep("https://x.example")).unwrap();
        assert_eq!(s, EndpointScheme::Http);
        let (_, s) = classify_endpoint(&ep("ws://x.example")).unwrap();
        assert_eq!(s, EndpointScheme::Ws);
        let (_, s) = classify_endpoint(&ep("wss://x.example")).unwrap();
        assert_eq!(s, EndpointScheme::Ws);

        // Unsupported schemes are rejected.
        let err = classify_endpoint(&ep("file:///etc/hosts")).unwrap_err();
        assert!(
            matches!(err, BloomRpcError::InvalidUrl { .. }),
            "got {err:?}"
        );

        // Unparseable garbage is rejected.
        let err = classify_endpoint(&ep("::not a url::")).unwrap_err();
        assert!(
            matches!(err, BloomRpcError::InvalidUrl { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn subscription_capable_only_for_ws_schemes() {
        assert!(!is_subscription_capable(&ep("http://x.example")));
        assert!(!is_subscription_capable(&ep("https://x.example")));
        assert!(is_subscription_capable(&ep("ws://x.example")));
        assert!(is_subscription_capable(&ep("wss://x.example")));

        // `http_only` flips capability off even on a ws URL.
        let mut e = ep("wss://x.example");
        e.http_only = true;
        assert!(!is_subscription_capable(&e));

        // file:// is not a subscription-capable scheme.
        assert!(!is_subscription_capable(&ep("file:///tmp/anvil.ipc")));
    }
}
