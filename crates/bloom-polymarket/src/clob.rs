//! CLOB API client — public market-data reads, L1 credential mint/derive, and
//! L2 authenticated requests (account reads + the onboarding
//! `balance-allowance` sync). Order placement/cancel (signed POLY_1271 orders)
//! is a later PR.

use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::signer::{self, OnboardSigner};
use crate::types::{Credentials, OrderBook, Side, TokenMarket};
use crate::{DEFAULT_CLOB_URL, POLYGON, PolymarketError, Result};

/// Client for `clob.polymarket.com`.
#[derive(Debug, Clone)]
pub struct ClobClient {
    base_url: Url,
    http: reqwest::Client,
    chain_id: u64,
}

impl Default for ClobClient {
    fn default() -> Self {
        Self::new(POLYGON)
    }
}

impl ClobClient {
    pub fn new(chain_id: u64) -> Self {
        Self {
            base_url: Url::parse(DEFAULT_CLOB_URL).expect("valid default clob url"),
            http: reqwest::Client::new(),
            chain_id,
        }
    }

    pub fn with_base_url(mut self, base: Url) -> Self {
        self.base_url = base;
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ── public market data ──────────────────────────────────────────────────

    /// `GET /version` — which order version the CLOB accepts (1 or 2). Bloom
    /// only builds V2 orders; callers must refuse to trade on version != 2.
    pub async fn server_version(&self) -> Result<u32> {
        let url = self.base_url.join("/version")?;
        let v: serde_json::Value = self.get_public(url).await?;
        v.get("version")
            .and_then(|n| n.as_u64())
            .map(|n| n as u32)
            .ok_or_else(|| PolymarketError::invalid(format!("bad /version response: {v}")))
    }

    /// `GET /tick-size?token_id=<id>` — minimum tick in integer micro-units
    /// (e.g. `0.01` → `10_000`). Parsed via the JSON number's shortest decimal
    /// representation to avoid float drift.
    pub async fn tick_size_micro(&self, token_id: &str) -> Result<u64> {
        let mut url = self.base_url.join("/tick-size")?;
        url.query_pairs_mut().append_pair("token_id", token_id);
        let v: serde_json::Value = self.get_public(url).await?;
        let raw = v
            .get("minimum_tick_size")
            .ok_or_else(|| PolymarketError::invalid(format!("bad /tick-size response: {v}")))?;
        let s = match raw {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        crate::order::parse_micro(&s)
    }

    /// `GET /neg-risk?token_id=<id>` — whether the token settles through the
    /// neg-risk exchange (changes the EIP-712 verifying contract).
    pub async fn neg_risk(&self, token_id: &str) -> Result<bool> {
        let mut url = self.base_url.join("/neg-risk")?;
        url.query_pairs_mut().append_pair("token_id", token_id);
        let v: serde_json::Value = self.get_public(url).await?;
        v.get("neg_risk")
            .and_then(|b| b.as_bool())
            .ok_or_else(|| PolymarketError::invalid(format!("bad /neg-risk response: {v}")))
    }

    /// `GET /book?token_id=<id>`.
    pub async fn book(&self, token_id: &str) -> Result<OrderBook> {
        let mut url = self.base_url.join("/book")?;
        url.query_pairs_mut().append_pair("token_id", token_id);
        self.get_public(url).await
    }

    /// `GET /markets-by-token/{token_id}` — token → condition id (+ YES/NO).
    pub async fn markets_by_token(&self, token_id: &str) -> Result<TokenMarket> {
        let url = self
            .base_url
            .join(&format!("/markets-by-token/{token_id}"))?;
        self.get_public(url).await
    }

    /// `GET /price?token_id=<id>&side=BUY|SELL` — untyped (`{ "price": "…" }`).
    pub async fn price(&self, token_id: &str, side: Side) -> Result<serde_json::Value> {
        let mut url = self.base_url.join("/price")?;
        let side = match side {
            Side::Buy => "BUY",
            Side::Sell => "SELL",
        };
        url.query_pairs_mut()
            .append_pair("token_id", token_id)
            .append_pair("side", side);
        self.get_public(url).await
    }

    /// `GET /midpoint?token_id=<id>` — untyped (`{ "mid": "…" }`).
    pub async fn midpoint(&self, token_id: &str) -> Result<serde_json::Value> {
        let mut url = self.base_url.join("/midpoint")?;
        url.query_pairs_mut().append_pair("token_id", token_id);
        self.get_public(url).await
    }

    /// `GET /spread?token_id=<id>` — untyped (`{ "spread": "…" }`).
    pub async fn spread(&self, token_id: &str) -> Result<serde_json::Value> {
        let mut url = self.base_url.join("/spread")?;
        url.query_pairs_mut().append_pair("token_id", token_id);
        self.get_public(url).await
    }

    // ── L1: credential mint / derive ──────────────────────────────────────────

    /// `POST /auth/api-key` (create) with L1 headers. Returns creds tagged with
    /// the `nonce` used (save it — it's required to re-derive the same creds).
    pub async fn create_credentials(
        &self,
        signer: &dyn OnboardSigner,
        nonce: u32,
    ) -> Result<Credentials> {
        self.auth_creds(signer, nonce, reqwest::Method::POST, "/auth/api-key")
            .await
    }

    /// `GET /auth/derive-api-key` with L1 headers — idempotent re-derivation.
    pub async fn derive_credentials(
        &self,
        signer: &dyn OnboardSigner,
        nonce: u32,
    ) -> Result<Credentials> {
        self.auth_creds(signer, nonce, reqwest::Method::GET, "/auth/derive-api-key")
            .await
    }

    /// Create if possible, else fall back to derive — the practical onboarding
    /// path (creating twice with the same nonce errors; deriving recovers).
    ///
    /// The fallback is narrow on purpose: an "already created for this nonce"
    /// response is a 4xx, so only a 4xx (and not auth `401/403` or rate-limit
    /// `429`) triggers a derive. Server errors (`5xx`), throttling, and auth
    /// failures propagate instead of being masked behind a second failing call.
    pub async fn mint_or_derive_credentials(
        &self,
        signer: &dyn OnboardSigner,
        nonce: u32,
    ) -> Result<Credentials> {
        match self.create_credentials(signer, nonce).await {
            Ok(c) => Ok(c),
            Err(PolymarketError::Api { status, .. })
                if (400..500).contains(&status) && !matches!(status, 401 | 403 | 429) =>
            {
                self.derive_credentials(signer, nonce).await
            }
            Err(e) => Err(e),
        }
    }

    async fn auth_creds(
        &self,
        signer: &dyn OnboardSigner,
        nonce: u32,
        method: reqwest::Method,
        path: &str,
    ) -> Result<Credentials> {
        let ts = now_secs();
        let headers = signer.clob_auth_headers(self.chain_id, ts, nonce).await?;
        let url = self.base_url.join(path)?;
        let mut rb = self.http.request(method, url);
        for (name, value) in &headers {
            rb = rb.header(name, value);
        }
        let (status, body) = send(rb).await?;
        if !(200..300).contains(&status) {
            return Err(PolymarketError::Api { status, body });
        }
        let mut creds: Credentials = serde_json::from_str(&body)?;
        creds.nonce = nonce;
        Ok(creds)
    }

    // ── L2: authenticated requests ────────────────────────────────────────────

    /// `GET /time` — the CLOB's clock in unix seconds. Used to recover from
    /// local clock skew on auth failures.
    pub async fn server_time(&self) -> Result<u64> {
        let url = self.base_url.join("/time")?;
        let (status, body) = send(self.http.get(url)).await?;
        if !(200..300).contains(&status) {
            return Err(PolymarketError::Api { status, body });
        }
        body.trim()
            .trim_matches('"')
            .parse::<f64>()
            .map(|t| t as u64)
            .map_err(|_| PolymarketError::invalid(format!("bad /time response: {body}")))
    }

    /// One L2 request path for everything authenticated. The HMAC preimage is
    /// `{ts}{METHOD}{path}{body}` — query parameters are appended to the URL
    /// but excluded from the signature, matching the SDK. On a 401-class
    /// response the request is retried **once** with the CLOB's own clock so
    /// local skew doesn't produce opaque auth failures.
    async fn l2_send(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut ts = now_secs();
        let mut retried = false;
        loop {
            let mut url = self.base_url.join(path)?;
            for (k, v) in query {
                url.query_pairs_mut().append_pair(k, v);
            }
            let headers = signer::l2_headers(
                owner,
                &creds.key,
                &creds.passphrase,
                &creds.secret,
                ts,
                method.as_str(),
                url.path(),
                body.unwrap_or(""),
            )?;
            let mut rb = self.http.request(method.clone(), url);
            if let Some(b) = body {
                rb = rb
                    .header("content-type", "application/json")
                    .body(b.to_string());
            }
            for (name, value) in &headers {
                rb = rb.header(*name, value);
            }
            let (status, resp) = send(rb).await?;
            if (status == 401 || status == 403)
                && !retried
                && let Ok(t) = self.server_time().await
            {
                ts = t;
                retried = true;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(PolymarketError::Api { status, body: resp });
            }
            // Some endpoints (e.g. balance-allowance/update) return 2xx with
            // an empty body; that is success, not malformed JSON.
            if resp.trim().is_empty() {
                return Ok(serde_json::Value::Null);
            }
            return Ok(serde_json::from_str(&resp)?);
        }
    }

    /// Generic L2 request against `path` for `owner`, signed with `creds`.
    pub async fn authed_request(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value> {
        self.l2_send(creds, owner, method, path, query, None).await
    }

    /// Generic L2 `GET` against `path` (no query) for `owner`.
    pub async fn authed_get(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        path: &str,
    ) -> Result<serde_json::Value> {
        self.authed_request(creds, owner, reqwest::Method::GET, path, &[])
            .await
    }

    /// Open orders for `owner` (`GET /data/orders`).
    pub async fn open_orders(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
    ) -> Result<serde_json::Value> {
        self.authed_get(creds, owner, "/data/orders").await
    }

    /// Buying power / allowance as the CLOB sees it
    /// (`GET /balance-allowance?asset_type=&signature_type=`).
    pub async fn balance_allowance(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        asset_type: &str,
        signature_type: u8,
    ) -> Result<serde_json::Value> {
        self.authed_request(
            creds,
            owner,
            reqwest::Method::GET,
            "/balance-allowance",
            &[
                ("asset_type", asset_type),
                ("signature_type", &signature_type.to_string()),
            ],
        )
        .await
    }

    /// Conditional-token balance / allowance as the CLOB sees it
    /// (`GET /balance-allowance?asset_type=CONDITIONAL&token_id=&signature_type=`).
    pub async fn conditional_balance_allowance(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        token_id: &str,
        signature_type: u8,
    ) -> Result<serde_json::Value> {
        self.authed_request(
            creds,
            owner,
            reqwest::Method::GET,
            "/balance-allowance",
            &[
                ("asset_type", "CONDITIONAL"),
                ("token_id", token_id),
                ("signature_type", &signature_type.to_string()),
            ],
        )
        .await
    }

    /// Make the CLOB recompute buying power after funding/approvals
    /// (`GET /balance-allowance/update?asset_type=&signature_type=`) — the
    /// onboarding `sync` stage.
    pub async fn update_balance_allowance(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        asset_type: &str,
        signature_type: u8,
    ) -> Result<serde_json::Value> {
        self.authed_request(
            creds,
            owner,
            reqwest::Method::GET,
            "/balance-allowance/update",
            &[
                ("asset_type", asset_type),
                ("signature_type", &signature_type.to_string()),
            ],
        )
        .await
    }

    /// Make the CLOB recompute conditional-token selling power for one token id.
    pub async fn update_conditional_balance_allowance(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        token_id: &str,
        signature_type: u8,
    ) -> Result<serde_json::Value> {
        self.authed_request(
            creds,
            owner,
            reqwest::Method::GET,
            "/balance-allowance/update",
            &[
                ("asset_type", "CONDITIONAL"),
                ("token_id", token_id),
                ("signature_type", &signature_type.to_string()),
            ],
        )
        .await
    }

    /// Generic L2 `POST` against `path` with a JSON body for `owner`.
    /// The HMAC preimage includes the body.
    pub async fn authed_post(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        path: &str,
        body: &str,
    ) -> Result<serde_json::Value> {
        self.l2_send(creds, owner, reqwest::Method::POST, path, &[], Some(body))
            .await
    }

    /// Post a signed order to the CLOB (`POST /order`).
    pub async fn post_order(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        body: &crate::order::OrderBody,
    ) -> Result<serde_json::Value> {
        let body_str = serde_json::to_string(body)?;
        self.authed_post(creds, owner, "/order", &body_str).await
    }

    // ── builder API keys (relayer submission auth, not wallet authority) ──────

    /// `POST /auth/builder-api-key` — mint a builder API key under the
    /// authenticated account (no request body, matching the official client).
    /// The response contains secrets; callers must not log it.
    pub async fn create_builder_api_key(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
    ) -> Result<crate::builder_creds::BuilderCredentials> {
        let v = self
            .l2_send(
                creds,
                owner,
                reqwest::Method::POST,
                "/auth/builder-api-key",
                &[],
                None,
            )
            .await?;
        let mut bc: crate::builder_creds::BuilderCredentials = serde_json::from_value(v)?;
        bc.created_at_ms = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        bc.source = "clob_l2_auth".into();
        Ok(bc)
    }

    /// `GET /auth/builder-api-key` — list this account's builder API keys.
    /// Lenient across the two observed response shapes (UUID strings or
    /// objects with `key`/`created_at`/`revoked_at`).
    pub async fn list_builder_api_keys(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
    ) -> Result<Vec<crate::builder_creds::BuilderApiKeyInfo>> {
        let v = self
            .l2_send(
                creds,
                owner,
                reqwest::Method::GET,
                "/auth/builder-api-key",
                &[],
                None,
            )
            .await?;
        let arr = v
            .as_array()
            .ok_or_else(|| PolymarketError::invalid(format!("bad builder-key list: {v}")))?;
        Ok(arr
            .iter()
            .filter_map(crate::builder_creds::BuilderApiKeyInfo::from_value)
            .collect())
    }

    /// `DELETE /auth/builder-api-key` — revoke a builder API key. The official
    /// client sends no body (revokes the account's key); passing `key` adds a
    /// `{"key": …}` body to target a specific key id.
    pub async fn revoke_builder_api_key(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        key: Option<&str>,
    ) -> Result<()> {
        let body = key.map(|k| serde_json::json!({ "key": k }).to_string());
        self.l2_send(
            creds,
            owner,
            reqwest::Method::DELETE,
            "/auth/builder-api-key",
            &[],
            body.as_deref(),
        )
        .await
        .map(|_| ())
    }

    /// Cancel one order (`DELETE /order` with `{"orderID": …}`), matching the
    /// official client's wire shape. L2-authed; the body is in the HMAC.
    pub async fn cancel_order(
        &self,
        creds: &Credentials,
        owner: alloy::primitives::Address,
        order_id: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::to_string(&serde_json::json!({ "orderID": order_id }))?;
        self.l2_send(
            creds,
            owner,
            reqwest::Method::DELETE,
            "/order",
            &[],
            Some(&body),
        )
        .await
    }

    async fn get_public<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T> {
        let (status, body) = send(self.http.get(url)).await?;
        if !(200..300).contains(&status) {
            return Err(PolymarketError::Api { status, body });
        }
        Ok(serde_json::from_str(&body)?)
    }
}

async fn send(rb: reqwest::RequestBuilder) -> Result<(u16, String)> {
    let resp = rb.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await?;
    Ok((status, body))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rule, ScriptedServer};

    fn test_creds() -> Credentials {
        Credentials {
            key: "test-api-key".into(),
            // valid base64url so HMAC construction succeeds
            secret: "c2VjcmV0LXNlY3JldC1zZWNyZXQ=".into(),
            passphrase: "pass".into(),
            nonce: 0,
        }
    }

    fn owner() -> alloy::primitives::Address {
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn cancel_sends_delete_order_with_order_id_body() {
        let server = ScriptedServer::start(vec![Rule {
            method: "DELETE",
            path_contains: "/order",
            status: 200,
            body: r#"{"canceled":["0xabc"],"not_canceled":{}}"#.into(),
        }])
        .await;
        let clob = ClobClient::new(POLYGON).with_base_url(Url::parse(&server.url()).unwrap());
        let v = clob
            .cancel_order(&test_creds(), owner(), "0xabc")
            .await
            .unwrap();
        assert_eq!(v["canceled"][0], "0xabc");

        let seen = server.seen_paths_containing("/order");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "DELETE");
        assert_eq!(seen[0].body, r#"{"orderID":"0xabc"}"#);
        // L2 headers present
        assert!(seen[0].header("poly_signature").is_some());
        assert!(seen[0].header("poly_api_key").is_some());
    }

    #[tokio::test]
    async fn l2_retries_once_with_server_time_on_401() {
        let server = ScriptedServer::start(vec![
            Rule {
                method: "DELETE",
                path_contains: "/order",
                status: 401,
                body: r#"{"error":"unauthorized"}"#.into(),
            },
            Rule::get("/time", "1765432100"),
        ])
        .await;
        let clob = ClobClient::new(POLYGON).with_base_url(Url::parse(&server.url()).unwrap());
        let err = clob
            .cancel_order(&test_creds(), owner(), "0xabc")
            .await
            .unwrap_err();
        assert!(matches!(err, PolymarketError::Api { status: 401, .. }));

        // one original attempt + one server-time retry, exactly once
        assert_eq!(server.seen_paths_containing("/order").len(), 2);
        let time_calls = server.seen_paths_containing("/time");
        assert_eq!(time_calls.len(), 1);
        // the retry signed with the server's clock
        let retry = &server.seen_paths_containing("/order")[1];
        assert_eq!(retry.header("poly_timestamp"), Some("1765432100"));
    }

    #[tokio::test]
    async fn mint_or_derive_only_falls_back_on_client_errors() {
        use crate::signer::KeystoreSigner;
        use alloy::signers::local::PrivateKeySigner;
        use std::str::FromStr;
        use std::sync::Arc;
        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = || KeystoreSigner::new(Arc::new(PrivateKeySigner::from_str(pk).unwrap()));

        // 400 on create ("already exists") → derive recovers.
        let server = ScriptedServer::start(vec![
            Rule {
                method: "POST",
                path_contains: "/auth/api-key",
                status: 400,
                body: r#"{"error":"creds already exist"}"#.into(),
            },
            Rule::get("/auth/derive-api-key", creds_body()),
        ])
        .await;
        let clob = ClobClient::new(POLYGON).with_base_url(Url::parse(&server.url()).unwrap());
        let c = clob.mint_or_derive_credentials(&signer(), 0).await.unwrap();
        assert_eq!(c.key, "11111111-2222-3333-4444-555555555555");
        assert_eq!(
            server.seen_paths_containing("/auth/derive-api-key").len(),
            1
        );

        // 500 on create → surfaced, NO derive attempt.
        let server = ScriptedServer::start(vec![
            Rule {
                method: "POST",
                path_contains: "/auth/api-key",
                status: 500,
                body: "boom".into(),
            },
            Rule::get("/auth/derive-api-key", creds_body()),
        ])
        .await;
        let clob = ClobClient::new(POLYGON).with_base_url(Url::parse(&server.url()).unwrap());
        let err = clob
            .mint_or_derive_credentials(&signer(), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, PolymarketError::Api { status: 500, .. }));
        assert!(
            server
                .seen_paths_containing("/auth/derive-api-key")
                .is_empty(),
            "5xx must not be masked by a derive fallback"
        );
    }

    fn creds_body() -> &'static str {
        r#"{"apiKey":"11111111-2222-3333-4444-555555555555","secret":"c2VjcmV0","passphrase":"pp"}"#
    }

    /// Live, network-gated. Confirms book + token→condition round-trip (the
    /// invariants the discovery probe proved) still hold.
    #[tokio::test]
    #[ignore = "hits live clob.polymarket.com"]
    async fn live_book_and_token_roundtrip() {
        // Opt-in only (production Polymarket 403s cloud/CI IPs). Self-skip unless
        // BLOOM_LIVE_POLYMARKET is set, so the acceptance job stays green.
        match std::env::var("BLOOM_LIVE_POLYMARKET") {
            Ok(v) if !v.is_empty() => {}
            _ => {
                eprintln!("skip: set BLOOM_LIVE_POLYMARKET=1 to run live Polymarket tests");
                return;
            }
        }
        let gamma = crate::GammaClient::new();
        let market = gamma
            .list_markets(false, 1, Some("volumeNum"), false)
            .await
            .unwrap()
            .remove(0);
        let yes = market.yes_token_id().unwrap().to_string();

        let clob = ClobClient::new(POLYGON);
        let book = clob.book(&yes).await.unwrap();
        assert_eq!(book.asset_id, yes, "book echoes requested token");

        let tm = clob.markets_by_token(&yes).await.unwrap();
        assert_eq!(tm.condition_id, book.market);
        assert_eq!(tm.condition_id, market.condition_id);
    }
}
