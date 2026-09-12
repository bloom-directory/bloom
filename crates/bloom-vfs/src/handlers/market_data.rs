//! Public market context for the mounted views.
//!
//! Three keyless public sources, read here and never by the browser: DefiLlama
//! chain fees, DefiLlama DEX volume, and CoinGecko's market list. The pages
//! that use these carry no script and make no requests of their own, so every
//! figure is fetched by the daemon and rendered into the HTML.
//!
//! Everything degrades to `None`. A source that is slow, rate-limited, or
//! missing leaves a panel saying so, and never becomes a zero: "no fee data
//! for this chain" and "this chain collected no fees" are different claims.
//!
//! Results are cached for [`CACHE_TTL`], because a page renders on every read
//! of the mount and these endpoints are neither fast nor unmetered.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Public context changes slowly; daily fee totals change once a day. A page
/// read must not become an upstream request.
const CACHE_TTL: Duration = Duration::from_secs(900);

/// One upstream call's budget. A view must render even when a provider hangs.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// How many completed days of fee history a panel keeps. The provider returns
/// a chain's entire history — thousands of points — which is an unreadable
/// chart and a multi-megabyte page, not a month of context.
const FEE_DAYS: usize = 30;

const FEES_URL: &str = "https://api.llama.fi/summary/fees";
const DEXS_URL: &str = "https://api.llama.fi/overview/dexs";
const MARKETS_URL: &str = "https://api.coingecko.com/api/v3/coins/markets\
                           ?vs_currency=usd&order=volume_desc&per_page=20&page=1\
                           &sparkline=false&price_change_percentage=24h";

/// DefiLlama's own slug for a chain, keyed on the chain id this daemon knows.
/// A chain absent from this table simply has no fee or volume panel; guessing
/// a slug would silently attribute another chain's figures to it.
const CHAIN_SLUGS: &[(u64, &str)] = &[
    (1, "ethereum"),
    (56, "bsc"),
    (100, "gnosis"),
    (137, "polygon"),
    (999, "hyperliquid"),
    (4663, "robinhood-chain"),
    (8453, "base"),
    (42161, "arbitrum"),
    (43114, "avalanche"),
    (59144, "linea"),
];

/// The DefiLlama slug for a chain id, when one is known.
pub fn chain_slug(chain_id: u64) -> Option<&'static str> {
    CHAIN_SLUGS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, slug)| *slug)
}

/// Daily fees paid by everyone using a chain, newest last, beside the
/// provider's own cumulative totals.
#[derive(Clone, Debug, Default)]
pub struct FeeSeries {
    /// `(unix seconds, USD for that UTC day)`, ascending, gaps preserved.
    pub points: Vec<(u64, f64)>,
    /// The provider's own description of what it counts.
    pub methodology: Option<String>,
    /// Cumulative fees over each window the provider reports. All-time is the
    /// total anyone has ever paid to use the chain, which is the measure of
    /// how much use it has actually been worth paying for.
    pub total_24h: Option<f64>,
    pub total_7d: Option<f64>,
    pub total_30d: Option<f64>,
    pub total_1y: Option<f64>,
    pub total_all_time: Option<f64>,
}

/// Reported DEX volume for a chain.
#[derive(Clone, Debug, Default)]
pub struct ChainVolume {
    pub total_24h: Option<f64>,
    pub change_1d: Option<f64>,
}

/// One row of the provider's market list.
#[derive(Clone, Debug)]
pub struct TokenMarket {
    pub name: String,
    pub symbol: String,
    pub price: Option<f64>,
    pub change_24h: Option<f64>,
    pub volume_24h: Option<f64>,
    pub last_updated: Option<String>,
}

#[derive(Clone)]
enum Cached {
    Fees(FeeSeries),
    Volume(ChainVolume),
    Markets(Vec<TokenMarket>),
}

struct Entry {
    value: Cached,
    fetched_at: Instant,
}

/// Reader for public market context, with a cache in front of every source.
#[derive(Clone)]
pub struct MarketData {
    http: reqwest::Client,
    fees_url: String,
    dexs_url: String,
    markets_url: String,
    cache: Arc<RwLock<HashMap<String, Entry>>>,
}

impl Default for MarketData {
    fn default() -> Self {
        Self::new()
    }
}

impl MarketData {
    pub fn new() -> Self {
        Self {
            http: http_client(),
            fees_url: FEES_URL.to_owned(),
            dexs_url: DEXS_URL.to_owned(),
            markets_url: MARKETS_URL.to_owned(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Point every source at one base URL. Tests use this to prove the pages
    /// render when the providers answer with nothing at all.
    pub fn with_base_url(url: &str) -> Self {
        let base = url.trim_end_matches('/');
        Self {
            http: http_client(),
            fees_url: format!("{base}/fees"),
            dexs_url: format!("{base}/dexs"),
            markets_url: format!("{base}/markets"),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Daily fee totals for a chain, or `None` when the provider does not
    /// answer. The current UTC day is excluded: it is still accruing, and
    /// drawing a part-day beside whole ones reads as a collapse in usage.
    pub async fn fees(&self, slug: &str) -> Option<FeeSeries> {
        let key = format!("fees:{slug}");
        if let Some(Cached::Fees(series)) = self.cached(&key) {
            return Some(series);
        }
        let url = format!("{}/{slug}?dataType=dailyFees", self.fees_url);
        let body: serde_json::Value = self.get_json(&url).await?;
        let cutoff = start_of_utc_day(now_secs());
        let mut points: Vec<(u64, f64)> = body
            .get("totalDataChart")
            .and_then(|chart| chart.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        let pair = row.as_array()?;
                        let ts = pair.first()?.as_u64()?;
                        let usd = pair.get(1)?.as_f64()?;
                        (usd >= 0.0 && ts < cutoff).then_some((ts, usd))
                    })
                    .collect()
            })
            .unwrap_or_default();
        points.sort_unstable_by_key(|(ts, _)| *ts);
        points.dedup_by_key(|(ts, _)| *ts);
        // Only the last completed days. The provider returns a chain's entire
        // history — thousands of points — which is an unreadable chart and a
        // multi-megabyte page, not a month of context.
        if points.len() > FEE_DAYS {
            points.drain(..points.len() - FEE_DAYS);
        }
        let total = |key: &str| body.get(key).and_then(|value| value.as_f64());
        let series = FeeSeries {
            points,
            methodology: body
                .pointer("/methodology/Fees")
                .and_then(|text| text.as_str())
                .map(str::to_owned),
            total_24h: total("total24h"),
            total_7d: total("total7d"),
            total_30d: total("total30d"),
            total_1y: total("total1y"),
            total_all_time: total("totalAllTime"),
        };
        self.store(key, Cached::Fees(series.clone()));
        Some(series)
    }

    /// Reported 24h DEX volume for a chain, and its change against the day
    /// before, as the provider reports them.
    pub async fn volume(&self, slug: &str) -> Option<ChainVolume> {
        let key = format!("volume:{slug}");
        if let Some(Cached::Volume(volume)) = self.cached(&key) {
            return Some(volume);
        }
        let url = format!(
            "{}/{slug}?excludeTotalDataChart=true&excludeTotalDataChartBreakdown=true",
            self.dexs_url
        );
        let body: serde_json::Value = self.get_json(&url).await?;
        let volume = ChainVolume {
            total_24h: body.get("total24h").and_then(|v| v.as_f64()),
            change_1d: body.get("change_1d").and_then(|v| v.as_f64()),
        };
        self.store(key, Cached::Volume(volume.clone()));
        Some(volume)
    }

    /// The provider's most-traded list. Rows without a usable price are
    /// dropped rather than shown as zero.
    pub async fn markets(&self) -> Option<Vec<TokenMarket>> {
        let key = "markets".to_owned();
        if let Some(Cached::Markets(rows)) = self.cached(&key) {
            return Some(rows);
        }
        let body: serde_json::Value = self.get_json(&self.markets_url.clone()).await?;
        let rows: Vec<TokenMarket> = body
            .as_array()?
            .iter()
            .filter_map(|row| {
                Some(TokenMarket {
                    name: row.get("name")?.as_str()?.to_owned(),
                    symbol: row
                        .get("symbol")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_ascii_uppercase(),
                    price: row.get("current_price").and_then(|v| v.as_f64()),
                    change_24h: row
                        .get("price_change_percentage_24h")
                        .and_then(|v| v.as_f64()),
                    volume_24h: row.get("total_volume").and_then(|v| v.as_f64()),
                    last_updated: row
                        .get("last_updated")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                })
            })
            .collect();
        if rows.is_empty() {
            return None;
        }
        self.store(key, Cached::Markets(rows.clone()));
        Some(rows)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Option<T> {
        let request = self.http.get(url).send();
        let response = match tokio::time::timeout(REQUEST_TIMEOUT, request).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                tracing::debug!(%url, error = %error, "views.market.transport");
                return None;
            }
            Err(_) => {
                tracing::debug!(%url, "views.market.timeout");
                return None;
            }
        };
        if !response.status().is_success() {
            tracing::debug!(%url, status = %response.status(), "views.market.status");
            return None;
        }
        match response.json::<T>().await {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::debug!(%url, error = %error, "views.market.decode");
                None
            }
        }
    }

    fn cached(&self, key: &str) -> Option<Cached> {
        let guard = self.cache.read();
        let entry = guard.get(key)?;
        (entry.fetched_at.elapsed() <= CACHE_TTL).then(|| entry.value.clone())
    }

    fn store(&self, key: String, value: Cached) {
        self.cache.write().insert(
            key,
            Entry {
                value,
                fetched_at: Instant::now(),
            },
        );
    }
}

/// A client that identifies itself. `reqwest` sends no User-Agent by default,
/// and a provider that rejects anonymous clients answers with an error rather
/// than data — which reaches a page as "the provider did not answer", with
/// nothing to say the request was never really made.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("bloom-vfs/", env!("CARGO_PKG_VERSION")))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_default()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

fn start_of_utc_day(secs: u64) -> u64 {
    secs - (secs % 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_without_a_known_slug_gets_no_panel() {
        assert_eq!(chain_slug(1), Some("ethereum"));
        assert_eq!(chain_slug(8453), Some("base"));
        assert_eq!(chain_slug(4663), Some("robinhood-chain"));
        // Tempo and Anvil are not DefiLlama chains. Guessing a slug would
        // attribute another chain's fees to them.
        assert_eq!(chain_slug(4217), None);
        assert_eq!(chain_slug(31337), None);
    }

    #[test]
    fn the_current_partial_day_is_excluded() {
        // 12:00 UTC on any day rounds down to that day's midnight, which is
        // the cutoff a still-accruing day must fall on or after.
        assert_eq!(start_of_utc_day(86_400 + 43_200), 86_400);
        assert_eq!(start_of_utc_day(86_400), 86_400);
    }

    #[tokio::test]
    async fn an_unroutable_provider_yields_nothing_rather_than_zero() {
        let market = MarketData::with_base_url("http://127.0.0.1:1");
        assert!(market.fees("ethereum").await.is_none());
        assert!(market.volume("ethereum").await.is_none());
        assert!(market.markets().await.is_none());
    }
}
