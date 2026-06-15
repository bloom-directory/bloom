//! The geoblock gate — a hard, fail-closed precondition for onboarding (and,
//! later, trading).
//!
//! `GET https://polymarket.com/api/geoblock` (note: polymarket.com, not an API
//! host) answers `{blocked, ip, country, region}`. Policy, non-negotiable:
//!
//! - `blocked: true` → refuse, naming the country/region;
//! - transport or parse failure → **refuse** ("could not verify region
//!   availability") — an unverifiable region is treated as blocked;
//! - there is **no production URL override and no bypass affordance**. The
//!   endpoint is deliberately not configurable; the only override is the
//!   `#[doc(hidden)]` test hook below.
//!
//! Verdicts are cached briefly so repeated preconditions don't hammer the
//! endpoint.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{PolymarketError, Result};

const GEOBLOCK_URL: &str = "https://polymarket.com/api/geoblock";
const CACHE_TTL: Duration = Duration::from_secs(300);

/// The geoblock verdict for the caller's egress IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoblockStatus {
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub region: String,
}

pub struct GeoblockClient {
    url: String,
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<Option<(Instant, GeoblockStatus)>>,
}

impl Default for GeoblockClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoblockClient {
    pub fn new() -> Self {
        Self {
            url: GEOBLOCK_URL.to_string(),
            http: reqwest::Client::new(),
            ttl: CACHE_TTL,
            cache: Mutex::new(None),
        }
    }

    /// Test-only URL override (canned servers). **Not production API** — using
    /// it to point production at a permissive endpoint defeats the refuse-line
    /// this client exists to enforce.
    #[doc(hidden)]
    pub fn with_base_url_for_tests(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    #[doc(hidden)]
    pub fn with_ttl_for_tests(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The current verdict (cached up to the TTL). Errors mean "unverifiable",
    /// which callers must treat as blocked — fail closed.
    pub async fn check(&self) -> Result<GeoblockStatus> {
        if let Some((at, status)) = self.cache.lock().unwrap().clone()
            && at.elapsed() < self.ttl
        {
            return Ok(status);
        }
        let status = self.fetch().await.map_err(|e| {
            PolymarketError::invalid(format!(
                "could not verify region availability (geoblock check failed: {e}); refusing"
            ))
        })?;
        *self.cache.lock().unwrap() = Some((Instant::now(), status.clone()));
        Ok(status)
    }

    async fn fetch(&self) -> Result<GeoblockStatus> {
        let resp = self.http.get(&self.url).send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(PolymarketError::Api { status, body });
        }
        Ok(serde_json::from_str(&body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rule, ScriptedServer};

    #[tokio::test]
    async fn parses_the_d5_vector_and_caches() {
        let server = ScriptedServer::start(vec![Rule::get(
            "/api/geoblock",
            r#"{"blocked":false,"ip":"1.2.3.4","country":"AR","region":"X"}"#,
        )])
        .await;
        let c =
            GeoblockClient::new().with_base_url_for_tests(format!("{}/api/geoblock", server.url()));

        let v = c.check().await.unwrap();
        assert!(!v.blocked);
        assert_eq!((v.country.as_str(), v.region.as_str()), ("AR", "X"));

        // Second check within the TTL is served from cache: one request total.
        let v2 = c.check().await.unwrap();
        assert!(!v2.blocked);
        assert_eq!(server.seen().len(), 1);
    }

    #[tokio::test]
    async fn missing_fields_default_and_blocked_round_trips() {
        let server =
            ScriptedServer::start(vec![Rule::get("/api/geoblock", r#"{"blocked":true}"#)]).await;
        let c =
            GeoblockClient::new().with_base_url_for_tests(format!("{}/api/geoblock", server.url()));
        let v = c.check().await.unwrap();
        assert!(v.blocked);
        assert_eq!(v.country, "");
    }

    #[tokio::test]
    async fn transport_error_fails_closed() {
        let c = GeoblockClient::new().with_base_url_for_tests("http://127.0.0.1:1/api/geoblock");
        let err = c.check().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("could not verify region availability"),
            "unverifiable must read as a refusal: {err}"
        );
    }

    #[tokio::test]
    async fn parse_error_fails_closed() {
        let server =
            ScriptedServer::start(vec![Rule::get("/api/geoblock", "<html>nope</html>")]).await;
        let c =
            GeoblockClient::new().with_base_url_for_tests(format!("{}/api/geoblock", server.url()));
        assert!(c.check().await.is_err());
    }
}
