//! Hand-rolled Polymarket relayer client — gasless deposit-wallet deploy +
//! on-chain wallet batches (approvals, transfers).
//!
//! Two submission shapes (`POST /submit`):
//! - `WALLET-CREATE` — deploys the deposit wallet; **no user signature**.
//! - `WALLET` — runs a signed `Batch` of calls; the `Batch` is EIP-712-signed
//!   (plain 65-byte) by [`KeystoreSigner`] under the `DepositWallet` domain.
//!
//! Status is polled via `GET /transaction?id=` to `STATE_CONFIRMED` (not merely
//! `STATE_MINED`, which can precede relayer registry readiness). Request shapes
//! follow the documented relayer API; response parsing is defensive across the
//! formats `rs-builder-relayer-client` handles. **The submit/poll round-trip
//! needs live (Amoy) verification** — it requires relayer/builder auth — but the
//! fund-authorizing `Batch` signature is fully covered by offline vectors.

use std::time::Duration;

use alloy::primitives::{Address, U256};

use crate::eip712::{self, Batch, Call, FACTORY};
use crate::signer::OnboardSigner;
use crate::{POLYGON, PolymarketError, Result};

const DEFAULT_RELAYER_URL: &str = "https://relayer-v2.polymarket.com";
/// Terminal success state we poll for.
pub const STATE_CONFIRMED: &str = "STATE_CONFIRMED";

/// A submitted relayer transaction and its last-known state.
#[derive(Debug, Clone)]
pub struct RelayerTx {
    pub id: String,
    pub state: String,
    pub tx_hash: Option<String>,
}

impl RelayerTx {
    pub fn is_confirmed(&self) -> bool {
        self.state == STATE_CONFIRMED
    }
    pub fn is_failed(&self) -> bool {
        let s = self.state.to_ascii_uppercase();
        s.contains("FAIL") || s.contains("INVALID")
    }
}

/// How the relayer authenticates us. Two independent schemes (per the relayer
/// OpenAPI: `/submit` is "Authenticated using Builder API Keys or Relayer API
/// Keys"):
/// - `RelayerKey`: static `RELAYER_API_KEY` / `RELAYER_API_KEY_ADDRESS`
///   headers (manually created at polymarket.com settings);
/// - `BuilderKey`: per-request `POLY_BUILDER_*` HMAC headers from a builder
///   API key bloom mints via CLOB L2 auth. Submission auth only — never
///   wallet authority.
#[derive(Debug, Clone, Default)]
pub enum RelayerAuth {
    #[default]
    None,
    RelayerKey {
        key: String,
        address: String,
    },
    BuilderKey(crate::builder_creds::BuilderCredentials),
}

/// Builder HMAC signature, byte-exact with the official
/// `rs-builder-relayer-client` (`src/auth/builder.rs`): the base64 secret is
/// decoded, the preimage is `timestamp + METHOD + path + body` (path **without**
/// scheme/host/query), and the output is standard base64 made URL-safe
/// (`+`→`-`, `/`→`_`, padding kept).
pub fn builder_hmac_signature(
    secret: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String> {
    use base64::Engine as _;
    use hmac::Mac as _;
    let engine = &base64::engine::general_purpose::STANDARD;
    let url_engine = &base64::engine::general_purpose::URL_SAFE;
    let url_engine_np = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = engine
        .decode(secret)
        .or_else(|_| url_engine.decode(secret))
        .or_else(|_| url_engine_np.decode(secret))
        .map_err(|e| PolymarketError::signing(format!("builder secret base64: {e}")))?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&decoded)
        .map_err(|e| PolymarketError::signing(format!("builder hmac key: {e}")))?;
    mac.update(format!("{timestamp}{method}{path}{body}").as_bytes());
    let out = engine.encode(mac.finalize().into_bytes());
    Ok(out.replace('+', "-").replace('/', "_"))
}

#[derive(Debug, Clone)]
pub struct RelayerClient {
    base_url: String,
    http: reqwest::Client,
    chain_id: u64,
    auth: RelayerAuth,
}

impl Default for RelayerClient {
    fn default() -> Self {
        Self::new(POLYGON)
    }
}

impl RelayerClient {
    pub fn new(chain_id: u64) -> Self {
        Self {
            base_url: DEFAULT_RELAYER_URL.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            chain_id,
            auth: RelayerAuth::None,
        }
    }

    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into().trim_end_matches('/').to_string();
        self
    }

    /// Attach manual relayer API-key auth (`[polymarket]` config:
    /// `relayer_api_key` / `relayer_api_key_address`).
    pub fn with_api_key(mut self, key: impl Into<String>, address: impl Into<String>) -> Self {
        self.auth = RelayerAuth::RelayerKey {
            key: key.into(),
            address: address.into(),
        };
        self
    }

    /// Attach builder-key HMAC auth (bloom-minted via CLOB L2).
    pub fn with_builder_key(mut self, creds: crate::builder_creds::BuilderCredentials) -> Self {
        self.auth = RelayerAuth::BuilderKey(creds);
        self
    }

    pub fn has_auth(&self) -> bool {
        !matches!(self.auth, RelayerAuth::None)
    }

    /// Auth headers for one request. The builder HMAC signs
    /// `timestamp + METHOD + path + body` where `path` excludes scheme, host,
    /// and query — matching the official client, which signs `/submit` only.
    fn auth_headers(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<Vec<(&'static str, String)>> {
        match &self.auth {
            RelayerAuth::None => Ok(vec![]),
            RelayerAuth::RelayerKey { key, address } => Ok(vec![
                ("RELAYER_API_KEY", key.clone()),
                ("RELAYER_API_KEY_ADDRESS", address.clone()),
            ]),
            RelayerAuth::BuilderKey(creds) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .to_string();
                let sig = builder_hmac_signature(&creds.secret, &ts, method, path, body)?;
                Ok(vec![
                    ("POLY_BUILDER_API_KEY", creds.key.clone()),
                    ("POLY_BUILDER_TIMESTAMP", ts),
                    ("POLY_BUILDER_PASSPHRASE", creds.passphrase.clone()),
                    ("POLY_BUILDER_SIGNATURE", sig),
                ])
            }
        }
    }

    /// Whether `wallet` already exists on-chain (`GET /deployed`).
    pub async fn is_deployed(&self, wallet: Address) -> Result<bool> {
        let v = self
            .get_json("/deployed", &format!("?address={wallet:#x}"))
            .await?;
        Ok(v.as_bool()
            .or_else(|| v.as_str().map(|s| s == "true"))
            .or_else(|| v.get("deployed").and_then(serde_json::Value::as_bool))
            .unwrap_or(false))
    }

    /// Current `WALLET`-type nonce for `owner` (`GET /nonce`). The relayer nonce
    /// can lag; an on-chain read is the robust path (deferred to a follow-up).
    /// An unparsable response is an **error** — silently defaulting to 0 would
    /// reuse a nonce, the exact double-submit failure onboarding must avoid.
    pub async fn wallet_nonce(&self, owner: Address) -> Result<u64> {
        let v = self
            .get_json("/nonce", &format!("?address={owner:#x}&type=WALLET"))
            .await?;
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .or_else(|| v.get("nonce").and_then(parse_u64_field))
            .ok_or_else(|| {
                PolymarketError::invalid(format!("relayer /nonce response unparsable: {v}"))
            })
    }

    /// Deploy the deposit wallet for `owner` — `WALLET-CREATE`, no signature.
    pub async fn deploy_deposit_wallet(&self, owner: Address) -> Result<RelayerTx> {
        let body = serde_json::json!({
            "type": "WALLET-CREATE",
            "from": format!("{owner:#x}"),
            "to": format!("{FACTORY:#x}"),
        });
        self.submit(body).await
    }

    /// Sign and submit a `WALLET` batch of calls from `deposit_wallet`.
    pub async fn submit_wallet_batch(
        &self,
        owner: Address,
        deposit_wallet: Address,
        calls: Vec<Call>,
        nonce: u64,
        deadline: u64,
        signer: &dyn OnboardSigner,
    ) -> Result<RelayerTx> {
        let batch = Batch {
            wallet: deposit_wallet,
            nonce: U256::from(nonce),
            deadline: U256::from(deadline),
            calls: calls.clone(),
        };
        let hash = eip712::batch_signing_hash(&batch, self.chain_id, deposit_wallet);
        let signature = signer.sign_eip712_hash(&hash).await?;
        let calls_json: Vec<serde_json::Value> = calls
            .iter()
            .map(|c| {
                serde_json::json!({
                    "target": format!("{:#x}", c.target),
                    "value": c.value.to_string(),
                    "data": format!("0x{}", hex::encode(&c.data)),
                })
            })
            .collect();
        let body = serde_json::json!({
            "type": "WALLET",
            "from": format!("{owner:#x}"),
            "to": format!("{FACTORY:#x}"),
            "nonce": nonce.to_string(),
            "signature": signature.to_string(),
            "depositWalletParams": {
                "depositWallet": format!("{deposit_wallet:#x}"),
                "deadline": deadline.to_string(),
                "calls": calls_json,
            },
        });
        self.submit(body).await
    }

    /// Fetch a transaction's current state (`GET /transaction?id=`).
    pub async fn transaction(&self, id: &str) -> Result<RelayerTx> {
        let v = self.get_json("/transaction", &format!("?id={id}")).await?;
        parse_transaction_response(id, &v)
    }

    /// Poll `tx` to `STATE_CONFIRMED`, erroring on a failed/invalid state or
    /// when `timeout` elapses.
    pub async fn poll_confirmed(&self, tx: &RelayerTx, timeout: Duration) -> Result<RelayerTx> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let cur = self.transaction(&tx.id).await?;
            if cur.is_confirmed() {
                return Ok(cur);
            }
            if cur.is_failed() {
                return Err(PolymarketError::Api {
                    status: 0,
                    body: format!("relayer tx {} {}", cur.id, cur.state),
                });
            }
            if std::time::Instant::now() >= deadline {
                return Err(PolymarketError::Api {
                    status: 0,
                    body: format!(
                        "relayer tx {} not confirmed before timeout (last: {})",
                        cur.id, cur.state
                    ),
                });
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn submit(&self, body: serde_json::Value) -> Result<RelayerTx> {
        // Serialize once: the builder HMAC must sign the exact bytes on the
        // wire, so the same string feeds both the signature and the body.
        let body_str = serde_json::to_string(&body)?;
        let url = format!("{}/submit", self.base_url);
        let mut rb = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body_str.clone());
        for (k, v) in self.auth_headers("POST", "/submit", &body_str)? {
            rb = rb.header(k, v);
        }
        let resp = rb.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(relayer_http_error(status, text));
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let id = ["transactionID", "transactionId", "transaction_id", "id"]
            .iter()
            .find_map(|k| v.get(*k).and_then(serde_json::Value::as_str))
            .ok_or_else(|| PolymarketError::Api {
                status,
                body: format!("relayer /submit response missing transaction id: {text}"),
            })?
            .to_string();
        let state = v
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("STATE_NEW")
            .to_string();
        Ok(RelayerTx {
            id,
            state,
            tx_hash: None,
        })
    }

    /// GET with auth headers attached; the HMAC signs the bare `path` (no
    /// query), and on 401/403 the request retries once **without** auth —
    /// the reference client sends no auth on GETs, so acceptance of signed
    /// GETs is treated as best-effort.
    async fn get_json(&self, path: &str, query: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}{}", self.base_url, path, query);
        let mut with_auth = self.has_auth();
        loop {
            let mut rb = self.http.get(&url);
            if with_auth {
                for (k, v) in self.auth_headers("GET", path, "")? {
                    rb = rb.header(k, v);
                }
            }
            let resp = rb.send().await?;
            let status = resp.status().as_u16();
            let text = resp.text().await?;
            if (status == 401 || status == 403) && with_auth {
                with_auth = false;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(relayer_http_error(status, text));
            }
            return Ok(serde_json::from_str(&text)?);
        }
    }
}

/// Map a non-2xx relayer response to an error. 401/403 keep their HTTP status
/// (`PolymarketError::Api`) so callers can run stale-builder-credential
/// recovery, with an actionable message in the body.
fn relayer_http_error(status: u16, body: String) -> PolymarketError {
    if status == 401 || status == 403 {
        return PolymarketError::Api {
            status,
            body: format!(
                "relayer rejected the request (status {status}). Bloom's default is an \
                 auto-created builder API key (CLOB-credential-derived; revocable with \
                 `bloom polymarket builder-keys revoke`) — if this keeps failing, the stored \
                 builder key may be revoked or invalid; bloom repairs it once automatically. \
                 Manual fallback: set [polymarket].relayer_api_key + relayer_api_key_address \
                 (polymarket.com/settings?tab=api-keys). response: {body}"
            ),
        };
    }
    PolymarketError::Api { status, body }
}

fn parse_u64_field(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn parse_transaction_response(id: &str, v: &serde_json::Value) -> Result<RelayerTx> {
    let tx = match v {
        serde_json::Value::Array(items) => items
            .iter()
            .find(|item| tx_id_matches(item, id))
            .or_else(|| items.first())
            .ok_or_else(|| {
                PolymarketError::invalid(format!("empty relayer /transaction response for {id}"))
            })?,
        other => other,
    };
    let state = tx
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            PolymarketError::invalid(format!(
                "relayer /transaction response for {id} missing state: {v}"
            ))
        })?
        .to_string();
    let tx_hash = tx
        .get("transactionHash")
        .or_else(|| tx.get("transaction_hash"))
        .or_else(|| tx.get("hash"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let parsed_id = ["transactionID", "transactionId", "transaction_id", "id"]
        .iter()
        .find_map(|k| tx.get(*k).and_then(serde_json::Value::as_str))
        .unwrap_or(id)
        .to_string();
    Ok(RelayerTx {
        id: parsed_id,
        state,
        tx_hash,
    })
}

fn tx_id_matches(v: &serde_json::Value, id: &str) -> bool {
    ["transactionID", "transactionId", "transaction_id", "id"]
        .iter()
        .any(|k| v.get(*k).and_then(serde_json::Value::as_str) == Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relayer_tx_state_predicates() {
        let confirmed = RelayerTx {
            id: "1".into(),
            state: STATE_CONFIRMED.into(),
            tx_hash: None,
        };
        assert!(confirmed.is_confirmed() && !confirmed.is_failed());
        for s in ["STATE_FAILED", "STATE_INVALID"] {
            let t = RelayerTx {
                id: "1".into(),
                state: s.into(),
                tx_hash: None,
            };
            assert!(t.is_failed() && !t.is_confirmed());
        }
    }

    #[test]
    fn transaction_response_parses_object_or_array() {
        let obj = serde_json::json!({
            "id": "tx-1",
            "state": "STATE_CONFIRMED",
            "transactionHash": "0xabc"
        });
        let tx = parse_transaction_response("tx-1", &obj).unwrap();
        assert_eq!(tx.id, "tx-1");
        assert_eq!(tx.state, STATE_CONFIRMED);
        assert_eq!(tx.tx_hash.as_deref(), Some("0xabc"));

        let arr = serde_json::json!([
            {"id":"other","state":"STATE_NEW"},
            {"transactionID":"tx-2","state":"STATE_CONFIRMED","hash":"0xdef"}
        ]);
        let tx = parse_transaction_response("tx-2", &arr).unwrap();
        assert_eq!(tx.id, "tx-2");
        assert_eq!(tx.state, STATE_CONFIRMED);
        assert_eq!(tx.tx_hash.as_deref(), Some("0xdef"));
    }

    #[test]
    fn transaction_response_missing_state_is_error() {
        let err =
            parse_transaction_response("tx-1", &serde_json::json!([{"id":"tx-1"}])).unwrap_err();
        assert!(err.to_string().contains("missing state"));
    }

    #[tokio::test]
    async fn wallet_nonce_parses_or_errors_never_defaults() {
        use crate::testutil::{Rule, ScriptedServer};
        let owner = Address::ZERO;

        for (body, expect) in [
            ("7", Some(7u64)),
            (r#""12""#, Some(12)),
            (r#"{"nonce":"3"}"#, Some(3)),
            (r#"{"unexpected":true}"#, None),
            (r#"null"#, None),
        ] {
            let server = ScriptedServer::start(vec![Rule::get("/nonce", body)]).await;
            let c = RelayerClient::new(POLYGON).with_base_url(server.url());
            match expect {
                Some(n) => assert_eq!(c.wallet_nonce(owner).await.unwrap(), n, "body {body}"),
                None => {
                    let err = c.wallet_nonce(owner).await.unwrap_err();
                    assert!(
                        err.to_string().contains("unparsable"),
                        "body {body} must error (nonce-0 fallback is a double-submit vector), got: {err}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn submit_sends_api_key_headers_and_none_without() {
        use crate::testutil::{Rule, ScriptedServer};

        // With a key: both headers present.
        let server = ScriptedServer::start(vec![Rule::post(
            "/submit",
            r#"{"transactionID":"tx-1","state":"STATE_NEW"}"#,
        )])
        .await;
        let c = RelayerClient::new(POLYGON)
            .with_base_url(server.url())
            .with_api_key("key-abc", "0xOwner");
        c.deploy_deposit_wallet(Address::ZERO).await.unwrap();
        let seen = server.seen_paths_containing("/submit");
        assert_eq!(seen[0].header("RELAYER_API_KEY"), Some("key-abc"));
        assert_eq!(seen[0].header("RELAYER_API_KEY_ADDRESS"), Some("0xOwner"));

        // Without a key: no auth headers (EOA-path callers never build this).
        let server = ScriptedServer::start(vec![Rule::post(
            "/submit",
            r#"{"transactionID":"tx-2","state":"STATE_NEW"}"#,
        )])
        .await;
        let c = RelayerClient::new(POLYGON).with_base_url(server.url());
        c.deploy_deposit_wallet(Address::ZERO).await.unwrap();
        let seen = server.seen_paths_containing("/submit");
        assert!(seen[0].header("RELAYER_API_KEY").is_none());
    }

    #[tokio::test]
    async fn submit_401_maps_to_actionable_error() {
        use crate::testutil::{Rule, ScriptedServer};
        let server = ScriptedServer::start(vec![Rule {
            method: "POST",
            path_contains: "/submit",
            status: 401,
            body: "invalid authorization".to_string(),
        }])
        .await;
        let c = RelayerClient::new(POLYGON).with_base_url(server.url());
        let err = c.deploy_deposit_wallet(Address::ZERO).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("builder") && msg.contains("relayer_api_key"),
            "401 must yield an actionable error naming both auth paths, got: {msg}"
        );
    }

    /// KAT verbatim from the official `rs-builder-relayer-client`
    /// `src/auth/builder.rs` unit test.
    #[test]
    fn builder_hmac_known_answer() {
        let sig = builder_hmac_signature(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "1000000",
            "test-sign",
            "/orders",
            r#"{"hash": "0x123"}"#,
        )
        .unwrap();
        assert_eq!(sig, "ZwAdJKvoYRlEKDkNMwd5BuwNNtg93kNaR_oU2HrfVvc=");
    }

    #[tokio::test]
    async fn submit_sends_builder_headers_and_no_relayer_key_headers() {
        use crate::testutil::{Rule, ScriptedServer};
        let server = ScriptedServer::start(vec![Rule::post(
            "/submit",
            r#"{"transactionID":"tx-9","state":"STATE_NEW"}"#,
        )])
        .await;
        let c = RelayerClient::new(POLYGON)
            .with_base_url(server.url())
            .with_builder_key(crate::builder_creds::BuilderCredentials {
                key: "builder-uuid".into(),
                secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                passphrase: "pp".into(),
                created_at_ms: 0,
                source: "test".into(),
            });
        c.deploy_deposit_wallet(Address::ZERO).await.unwrap();
        let seen = server.seen_paths_containing("/submit");
        assert_eq!(seen[0].header("POLY_BUILDER_API_KEY"), Some("builder-uuid"));
        assert_eq!(seen[0].header("POLY_BUILDER_PASSPHRASE"), Some("pp"));
        assert!(seen[0].header("POLY_BUILDER_TIMESTAMP").is_some());
        assert!(seen[0].header("POLY_BUILDER_SIGNATURE").is_some());
        assert!(seen[0].header("RELAYER_API_KEY").is_none());
        // The HMAC must have signed the exact wire body.
        let ts = seen[0].header("POLY_BUILDER_TIMESTAMP").unwrap();
        let expect = builder_hmac_signature(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ts,
            "POST",
            "/submit",
            &seen[0].body,
        )
        .unwrap();
        assert_eq!(seen[0].header("POLY_BUILDER_SIGNATURE").unwrap(), expect);
    }

    #[tokio::test]
    async fn authed_get_retries_bare_on_401() {
        use crate::testutil::{Rule, ScriptedServer};
        // Server 401s every request; the client must try twice (auth then
        // bare) and surface the error from the bare attempt.
        let server = ScriptedServer::start(vec![Rule {
            method: "GET",
            path_contains: "/nonce",
            status: 401,
            body: "no".to_string(),
        }])
        .await;
        let c = RelayerClient::new(POLYGON)
            .with_base_url(server.url())
            .with_builder_key(crate::builder_creds::BuilderCredentials {
                key: "k".into(),
                secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                passphrase: "p".into(),
                created_at_ms: 0,
                source: "test".into(),
            });
        let _ = c.wallet_nonce(Address::ZERO).await.unwrap_err();
        let seen = server.seen_paths_containing("/nonce");
        assert_eq!(seen.len(), 2, "one authed attempt + one bare retry");
        assert!(seen[0].header("POLY_BUILDER_API_KEY").is_some());
        assert!(seen[1].header("POLY_BUILDER_API_KEY").is_none());
    }

    #[test]
    fn default_base_url_has_no_trailing_slash() {
        let c = RelayerClient::default();
        assert_eq!(c.base_url, "https://relayer-v2.polymarket.com");
        assert_eq!(
            RelayerClient::new(POLYGON)
                .with_base_url("http://x/")
                .base_url,
            "http://x"
        );
    }
}
