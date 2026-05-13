//! `prices/...` — DefiLlama price oracle.
//!
//! Coin format on the wire:
//!
//! * a symbol: `eth`, `usdc`, ... (resolved via the built-in
//!   [`bloom_prices::CoinId::Symbol`] table)
//! * a `chain:address` pair: `ethereum:0xa0b8...` (any DefiLlama chain
//!   slug)
//! * a `coingecko:slug` form: `coingecko:lido`
//!
//! Supported paths:
//!
//! | path                                 | semantics                  |
//! | ------------------------------------ | -------------------------- |
//! | `prices/`                            | dir: `[spot, change_24h]`  |
//! | `prices/spot/<coin>`                 | current price (JSON)       |
//! | `prices/spot/<coin>.usd`             | current price scalar (txt) |
//! | `prices/change_24h/<coin>`           | 24h pct change (txt)       |

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bloom_prices::{CoinId, PricesClient, PricesError};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct PricesHandler {
    pub client: Arc<PricesClient>,
}

impl PricesHandler {
    pub fn new(client: PricesClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    fn parse_coin(s: &str) -> Result<CoinId, HandlerError> {
        if s.contains(':') {
            CoinId::parse(s).map_err(|e| HandlerError::invalid(e.to_string()))
        } else {
            Ok(CoinId::Symbol(s.to_string()))
        }
    }
}

fn err_be(e: PricesError) -> HandlerError {
    match e {
        PricesError::NotFound(s) => HandlerError::NotFound(s),
        PricesError::InvalidCoinId(s) => HandlerError::Invalid(s),
        other => HandlerError::backend(other.to_string()),
    }
}

#[async_trait]
impl Handler for PricesHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "prices.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "prices.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "prices.list_err");
        }
        r
    }

    /// DefiLlama is rate-limited keyless; 30s on quotes is plenty for
    /// agent-driven workflows and saves us from being throttled.
    fn cache_ttl(&self, _path: &VfsPath) -> Option<Duration> {
        Some(Duration::from_secs(30))
    }
}

impl PricesHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        match segs[0].as_str() {
            "spot" => match segs.len() {
                1 => Ok(Entry::dir("spot")),
                2 => Ok(Entry::file(&segs[1])),
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            },
            "change_24h" => match segs.len() {
                1 => Ok(Entry::dir("change_24h")),
                2 => Ok(Entry::file(&segs[1])),
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            },
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.len() != 2 {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        match segs[0].as_str() {
            "spot" => {
                // Strip optional .usd suffix → return scalar price as text.
                let (coin_seg, scalar) = match segs[1].strip_suffix(".usd") {
                    Some(s) => (s, true),
                    None => (segs[1].as_str(), false),
                };
                let coin = Self::parse_coin(coin_seg)?;
                let q = self.client.current(coin).await.map_err(err_be)?;
                if scalar {
                    Ok(format!("{}\n", q.price).into_bytes())
                } else {
                    let body = serde_json::to_vec_pretty(&q)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    Ok(body)
                }
            }
            "change_24h" => {
                let coin = Self::parse_coin(&segs[1])?;
                let pct = self.client.change_24h(coin).await.map_err(err_be)?;
                Ok(format!("{pct}\n").into_bytes())
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            return Ok(vec![Entry::dir("spot"), Entry::dir("change_24h")]);
        }
        match path.segments()[0].as_str() {
            "spot" if path.segments().len() == 1 => Ok(vec![]),
            "change_24h" if path.segments().len() == 1 => Ok(vec![]),
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal canned-response HTTP server. Returns `body` for any request.
    async fn spawn_canned(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        (addr, h)
    }

    #[tokio::test]
    async fn spot_returns_json_quote() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":3500.5,"symbol":"ETH","decimals":18,"timestamp":1700000000,"confidence":0.99}}}"#;
        let (addr, _h) = spawn_canned(body).await;
        let client = PricesClient::with_base_url(format!("http://{addr}"));
        let h = PricesHandler::new(client);
        let p = VfsPath::parse("/spot/eth").unwrap();
        let bytes = h.read(&p).await.unwrap();
        let q: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(q["price"], 3500.5);
    }

    #[tokio::test]
    async fn spot_with_usd_suffix_returns_scalar() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":3500.5,"symbol":"ETH","decimals":18,"timestamp":1700000000,"confidence":0.99}}}"#;
        let (addr, _h) = spawn_canned(body).await;
        let client = PricesClient::with_base_url(format!("http://{addr}"));
        let h = PricesHandler::new(client);
        let p = VfsPath::parse("/spot/eth.usd").unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim(), "3500.5");
    }

    #[tokio::test]
    async fn root_lists_spot_and_change() {
        let client = PricesClient::with_base_url("http://127.0.0.1:1");
        let h = PricesHandler::new(client);
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"spot"));
        assert!(names.contains(&"change_24h"));
    }
}
