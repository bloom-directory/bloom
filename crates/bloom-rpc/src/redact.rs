//! Keeps endpoint URLs out of errors and logs.
//!
//! RPC vendors put API keys in the URL's path (Alchemy, Infura), its query
//! or its userinfo. alloy's HTTP transport lets the URL out twice:
//!
//! - reqwest's error messages quote it, as in `error sending request for url
//!   (https://eth-mainnet.g.alchemy.com/v2/KEY)`, and those messages reach
//!   debug and warn logs and the `ChainError` text users and agents read;
//! - alloy records it in a debug span around every request, so with debug
//!   logging on, every log line emitted inside a request carries it.
//!
//! So each endpoint is called through [`EndpointHttp`], which sends requests
//! as alloy's `Http<reqwest::Client>` does but names the endpoint only by
//! its origin, and every log line names an endpoint by [`redact_url`].

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::transports::http::reqwest;
use alloy::transports::{TransportError, TransportErrorKind, TransportFut, TransportResult};
use tower::Service;
use tracing::{Instrument, debug, debug_span};
use url::Url;

/// The URL as safe to show: scheme, host and port, without userinfo, path,
/// query or fragment. A string that does not parse keeps only what looks
/// like its scheme and host.
pub fn redact_url(raw: &str) -> String {
    if let Ok(url) = Url::parse(raw) {
        return origin(&url);
    }
    match raw.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            format!("{scheme}://{host}")
        }
        None => "<unparseable url>".to_owned(),
    }
}

fn origin(url: &Url) -> String {
    let host = url.host_str().unwrap_or("?");
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{host}{port}", url.scheme())
}

/// One endpoint's HTTP transport. It posts each JSON-RPC request and reads
/// the reply as alloy's `Http<reqwest::Client>` does: a non-2xx status is an
/// HTTP error carrying the body, and a body that is not JSON-RPC is a
/// deserialization error carrying it. Unlike alloy's, neither its tracing
/// span nor its errors contain the URL.
#[derive(Clone)]
pub(crate) struct EndpointHttp {
    client: reqwest::Client,
    url: Url,
    origin: Arc<str>,
}

impl EndpointHttp {
    pub(crate) fn new(client: reqwest::Client, url: Url) -> Self {
        Self {
            client,
            origin: origin(&url).into(),
            url,
        }
    }

    async fn request(self, req: RequestPacket) -> TransportResult<ResponsePacket> {
        let failed = |err: reqwest::Error| {
            TransportErrorKind::custom(EndpointFailure::new(err, self.url.as_str(), &self.origin))
        };
        let resp = self
            .client
            .post(self.url.clone())
            .json(&req)
            .headers(req.headers())
            .send()
            .await
            .map_err(failed)?;
        let status = resp.status();
        debug!(%status, "received response from server");
        // Read the body whatever the status: an error status may still
        // explain itself in it.
        let body = resp.bytes().await.map_err(failed)?;
        if !status.is_success() {
            return Err(TransportErrorKind::http_error(
                status.as_u16(),
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|err| TransportError::deser_err(err, String::from_utf8_lossy(&body)))
    }
}

impl Service<RequestPacket> for EndpointHttp {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // reqwest is always ready.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let this = self.clone();
        let span = debug_span!("rpc_request", endpoint = %this.origin);
        Box::pin(this.request(req).instrument(span.or_current()))
    }
}

/// A request to one endpoint that failed before it was answered, described
/// without the endpoint's URL.
#[derive(Debug)]
struct EndpointFailure(String);

impl EndpointFailure {
    fn new(err: reqwest::Error, url: &str, origin: &str) -> Self {
        let what = if err.is_timeout() {
            "request timed out"
        } else if err.is_connect() {
            "connection failed"
        } else if err.is_body() || err.is_decode() {
            "reading the response failed"
        } else {
            "request failed"
        };
        // The causes say why (a refused connection, a DNS failure), and
        // only reqwest's own message quotes the URL.
        let err = err.without_url();
        let mut message = format!("{what} ({origin})");
        let mut cause = err.source();
        while let Some(source) = cause {
            message.push_str(": ");
            message.push_str(&source.to_string());
            cause = source.source();
        }
        // Should a cause ever quote the URL, it still must not get out.
        Self(message.replace(url, origin))
    }
}

impl fmt::Display for EndpointFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for EndpointFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_keeps_only_scheme_host_and_port() {
        for (raw, shown) in [
            (
                "https://eth-mainnet.g.alchemy.com/v2/SECRET",
                "https://eth-mainnet.g.alchemy.com",
            ),
            (
                "https://rpc.example.com/?apikey=SECRET",
                "https://rpc.example.com",
            ),
            (
                "https://user:SECRET@rpc.example.com:8545/x#frag",
                "https://rpc.example.com:8545",
            ),
            (
                "wss://user:SECRET@ws.example.com/v3/SECRET",
                "wss://ws.example.com",
            ),
            // Unparseable (an invalid port): still no userinfo or path.
            (
                "https://user:SECRET@rpc.example.com:99999999/v2/SECRET",
                "https://rpc.example.com:99999999",
            ),
            ("not a url SECRET", "<unparseable url>"),
        ] {
            assert_eq!(redact_url(raw), shown, "{raw}");
        }
    }
}
