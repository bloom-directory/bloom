//! Data API client — public user/market analytics (no auth).

use url::Url;

use crate::types::{Position, Trade};
use crate::{DEFAULT_DATA_URL, PolymarketError, Result};

/// Client for `data-api.polymarket.com`.
#[derive(Debug, Clone)]
pub struct DataClient {
    base_url: Url,
    http: reqwest::Client,
}

impl Default for DataClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DataClient {
    pub fn new() -> Self {
        Self {
            base_url: Url::parse(DEFAULT_DATA_URL).expect("valid default data url"),
            http: reqwest::Client::new(),
        }
    }

    pub fn with_base_url(mut self, base: Url) -> Self {
        self.base_url = base;
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `GET /positions?user=<address>`.
    pub async fn positions(&self, user: &str) -> Result<Vec<Position>> {
        self.get_with_user("/positions", user).await
    }

    /// `GET /closed-positions?user=<address>`.
    pub async fn closed_positions(&self, user: &str) -> Result<Vec<Position>> {
        self.get_with_user("/closed-positions", user).await
    }

    /// `GET /trades?user=<address>`.
    pub async fn trades(&self, user: &str) -> Result<Vec<Trade>> {
        self.get_with_user("/trades", user).await
    }

    /// `GET /activity?user=<address>` — returned untyped (rich, varied feed).
    pub async fn activity(&self, user: &str) -> Result<serde_json::Value> {
        self.get_with_user("/activity", user).await
    }

    /// `GET /oi?market=<conditionId>[,<conditionId>...]` — open interest.
    pub async fn open_interest(&self, condition_ids: &[&str]) -> Result<serde_json::Value> {
        let mut url = self.base_url.join("/oi")?;
        url.query_pairs_mut()
            .append_pair("market", &condition_ids.join(","));
        self.get(url).await
    }

    async fn get_with_user<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        user: &str,
    ) -> Result<T> {
        let mut url = self.base_url.join(path)?;
        url.query_pairs_mut().append_pair("user", user);
        self.get(url).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T> {
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(PolymarketError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }
}
