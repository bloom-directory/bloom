//! The [`UpdateChecker`]: a clone-cheap, Arc-shareable holder for the
//! latest known release snapshot, plus a background task that
//! refreshes it on a 5-minute interval.
//!
//! `UpdateChecker` is constructed once at daemon boot, then cloned
//! into both the daemon's `Arc<UpdateChecker>` field and the
//! `StatusHandler` (via a snapshot-producer closure, to avoid a
//! `bloom-vfs → bloom-update` reverse dep). VFS reads hit the
//! in-memory snapshot for fast responses; the network call only
//! happens on the background task and on explicit `refresh()`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, warn};

use crate::cache;
use crate::snapshot::{UpdateSnapshot, UpdateStatus};

/// GitHub `releases/latest` endpoint. Unauthenticated, so we're
/// capped at 60 req/h per IP; the 5-minute refresh interval + the
/// disk cache make this comfortable in practice.
const RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/bloom-directory/bloom/releases/latest";

/// GitHub rejects API requests without a valid User-Agent. Keep the
/// product name stable without disclosing the installed version.
const USER_AGENT_PREFIX: &str = "bloom";

/// Environment switch for operators who do not want automatic network
/// requests from a long-lived daemon. Explicit `bloom update check` remains
/// available because it constructs and refreshes a checker directly.
pub const DISABLE_AUTO_CHECK_ENV: &str = "BLOOM_DISABLE_UPDATE_CHECK";

pub fn automatic_checks_disabled() -> bool {
    std::env::var(DISABLE_AUTO_CHECK_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// How long to wait for the GitHub response.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the background task refreshes.
const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Minimum age of a cached snapshot before the CLI hint treats it as
/// fresh enough to print. 24 hours is the upper bound — anything
/// older is too stale to act on.
const CACHE_FRESHNESS: Duration = Duration::from_secs(24 * 60 * 60);

/// Errors from the checker. Most paths use the `Error { reason }`
/// variant of [`UpdateStatus`] instead of propagating; this type
/// exists for [`UpdateChecker::new`] which has to surface setup
/// failures.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("failed to construct reqwest client: {0}")]
    HttpClient(#[from] reqwest::Error),
}

/// The update checker. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct UpdateChecker {
    inner: Arc<Inner>,
}

struct Inner {
    /// In-memory copy of the latest known snapshot. Cheap to clone
    /// via `RwLock::read` for VFS reads.
    snapshot: RwLock<UpdateSnapshot>,
    /// `reqwest::Client` with a 10s timeout. Reused across refreshes.
    http: reqwest::Client,
    /// Release endpoint. Fixed in production and replaceable in unit
    /// tests so the real request headers and response handling are
    /// exercised without contacting GitHub.
    releases_url: String,
    /// Cache file directory. `home.cache_dir()` for production;
    /// tempdir for tests.
    cache_dir: PathBuf,
}

impl UpdateChecker {
    /// Build a new checker. The first snapshot is loaded from the
    /// on-disk cache (if any) or initialised to `Unknown`. The caller
    /// should then call [`Self::refresh`] or [`Self::spawn_background`]
    /// to populate it.
    pub fn new(
        installed: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, UpdateError> {
        let installed = installed.into();
        let cache_dir = cache_dir.into();
        Self::with_releases_url(installed, cache_dir, RELEASES_LATEST_URL.to_string())
    }

    fn with_releases_url(
        installed: String,
        cache_dir: PathBuf,
        releases_url: String,
    ) -> Result<Self, UpdateError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(USER_AGENT_PREFIX)
            .build()?;
        // Seed from disk cache if present; otherwise leave as Unknown
        // until the first network refresh completes.
        let initial =
            cache::read(&cache_dir).unwrap_or_else(|| UpdateSnapshot::unknown(installed.clone()));
        // If the cached snapshot was for a different installed version
        // (e.g. user upgraded the binary), keep the latest/release_url
        // but update the installed field. This avoids a stale
        // "behind by N" reading after a self-upgrade.
        let initial = UpdateSnapshot {
            installed,
            ..initial
        };
        Ok(Self {
            inner: Arc::new(Inner {
                snapshot: RwLock::new(initial),
                http,
                releases_url,
                cache_dir,
            }),
        })
    }

    /// Cheap snapshot read. Use this for VFS leaves and the CLI hint.
    pub fn snapshot(&self) -> UpdateSnapshot {
        self.inner.snapshot.read().clone()
    }

    /// Read the cached snapshot only if it's younger than
    /// [`CACHE_FRESHNESS`]. Used by the CLI hint to avoid printing
    /// "you're behind" based on ancient data.
    pub fn quick_check_cached(&self) -> Option<UpdateSnapshot> {
        let snap = self.snapshot();
        let checked_at = snap.checked_at?;
        let age = std::time::SystemTime::now()
            .duration_since(checked_at)
            .unwrap_or(Duration::MAX);
        if age <= CACHE_FRESHNESS {
            Some(snap)
        } else {
            None
        }
    }

    /// Force a refresh: GET the GitHub endpoint, parse the response,
    /// write the cache file, and update the in-memory snapshot. On
    /// error, only the in-memory status is marked as errored; the last
    /// successful cache entry remains available across restarts.
    pub async fn refresh(&self) -> UpdateSnapshot {
        let new_snapshot = match self.fetch().await {
            Ok(snap) => snap,
            Err(reason) => {
                warn!(reason = %reason, "bloom_update.refresh_failed");
                // Update only the error status; preserve any existing
                // latest/release_url so the VFS keeps showing them.
                let mut current = self.snapshot();
                current.status = UpdateStatus::Error.as_str().to_string();
                current.error_reason = Some(reason);
                *self.inner.snapshot.write() = current.clone();
                return current;
            }
        };
        *self.inner.snapshot.write() = new_snapshot.clone();
        if let Err(e) = cache::write(&self.inner.cache_dir, &new_snapshot) {
            warn!(error = %e, "bloom_update.cache_write_failed");
        }
        debug!(
            installed = %new_snapshot.installed,
            latest = ?new_snapshot.latest,
            "bloom_update.refresh_ok"
        );
        new_snapshot
    }

    /// Spawn a background tokio task that refreshes every 5 minutes.
    /// Returns a `oneshot::Sender<()>`; drop the sender to stop the
    /// task at the next iteration (the existing daemon shutdown
    /// pattern). The task also kicks once immediately, so the first
    /// VFS read after `spawn` is fresh within a few hundred ms.
    pub fn spawn_background(self: Arc<Self>) -> tokio::sync::oneshot::Sender<()> {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            // Kick once immediately so /status/update is fresh on
            // first read.
            self.refresh().await;
            let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the immediate first tick (interval fires
            // immediately on first poll, which we don't want because
            // we just did a refresh above).
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        debug!("bloom_update.background_shutdown");
                        return;
                    }
                    _ = ticker.tick() => {
                        self.refresh().await;
                    }
                }
            }
        });
        tx
    }

    /// Issue the GitHub request and parse the response. Returns
    /// `Err(reason)` on any failure (network, non-2xx, malformed
    /// JSON, etc.) so the caller can put it in the snapshot's
    /// `Error { reason }` field.
    async fn fetch(&self) -> Result<UpdateSnapshot, String> {
        let installed = self.snapshot().installed;
        let resp = self
            .inner
            .http
            .get(&self.inner.releases_url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| format!("network: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("http {status}"));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {e}"))?;
        // GitHub release objects have `tag_name` (e.g. "v0.2.0" or
        // the literal "latest" if the release is named that). We
        // pass it through; the semver parser will yield None for
        // anything not shaped like vX.Y.Z, and the snapshot's
        // `available` will return Unknown. This is the right
        // behaviour: we don't want to claim "behind" against a
        // non-semver release name.
        let tag_name = body
            .get("tag_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing tag_name".to_string())?
            .to_string();
        let html_url = body
            .get("html_url")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(UpdateSnapshot::ok(installed, Some(tag_name), html_url))
    }
}

/// Helper: read the cache file directly, without constructing a
/// `UpdateChecker`. Useful for the CLI hint path where the daemon
/// isn't running and we just want whatever's on disk.
pub fn read_cache_only(installed: &str, cache_dir: &Path) -> UpdateSnapshot {
    let cached =
        cache::read(cache_dir).unwrap_or_else(|| UpdateSnapshot::unknown(installed.to_string()));
    UpdateSnapshot {
        installed: installed.to_string(),
        ..cached
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Minimal one-shot HTTP fixture. It returns a canned response and
    /// sends the raw request headers back to the test for assertions.
    fn http_fixture(
        status: u16,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("mock server addr");
        let (request_tx, request_rx) = mpsc::channel();
        let header_lines = headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\r\n"))
            .collect::<String>();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock HTTP request");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).expect("read mock HTTP request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .expect("return captured request");
            let reason = if status == 404 { "Not Found" } else { "OK" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n{header_lines}connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        (format!("http://{addr}/resource"), request_rx)
    }

    fn make_checker(dir: &Path, url: &str) -> UpdateChecker {
        UpdateChecker::with_releases_url("0.1.0".to_string(), dir.to_path_buf(), url.to_string())
            .expect("build checker")
    }

    #[test]
    fn disable_auto_check_accepts_common_truthy_values() {
        for value in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert!(is_truthy(value), "expected {value:?} to disable checks");
        }
        for value in ["", "0", "false", "no", "off"] {
            assert!(!is_truthy(value), "expected {value:?} to enable checks");
        }
    }

    #[test]
    fn fresh_checker_is_unknown_until_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let checker = UpdateChecker::new("0.1.0", dir.path()).unwrap();
        let snap = checker.snapshot();
        assert_eq!(snap.installed, "0.1.0");
        assert!(snap.latest.is_none());
        assert_eq!(snap.status_kind(), UpdateStatus::Unknown);
    }

    #[test]
    fn loads_existing_cache() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-seed the cache.
        let cached = UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.2.0".into()),
            Some("https://example/v0.2.0".into()),
        );
        cache::write(dir.path(), &cached).unwrap();
        let checker = UpdateChecker::new("0.1.0", dir.path()).unwrap();
        let snap = checker.snapshot();
        assert_eq!(snap.latest.as_deref(), Some("0.2.0"));
        assert_eq!(snap.status_kind(), UpdateStatus::Ok);
    }

    #[test]
    fn new_installed_overrides_cached_installed() {
        // After a self-upgrade, the new binary's installed version
        // should be reflected in the snapshot, even if the cache was
        // written by the old binary.
        let dir = tempfile::tempdir().unwrap();
        let cached = UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.3.0".into()),
            Some("https://example/v0.3.0".into()),
        );
        cache::write(dir.path(), &cached).unwrap();
        let checker = UpdateChecker::new("0.2.0", dir.path()).unwrap();
        let snap = checker.snapshot();
        assert_eq!(snap.installed, "0.2.0");
        // latest is preserved from cache so the user sees the
        // upgrade is still pending.
        assert_eq!(snap.latest.as_deref(), Some("0.3.0"));
        // Now we're "behind" again from 0.2.0's perspective.
        assert_eq!(snap.available(), crate::UpdateAvailable::OutOfDate);
    }

    #[test]
    fn cache_only_read_overrides_cached_installed() {
        let dir = tempfile::tempdir().unwrap();
        let cached = UpdateSnapshot::ok("0.1.0".into(), Some("0.3.0".into()), None);
        cache::write(dir.path(), &cached).unwrap();

        let snap = read_cache_only("0.2.0", dir.path());

        assert_eq!(snap.installed, "0.2.0");
        assert_eq!(snap.latest.as_deref(), Some("0.3.0"));
        assert_eq!(snap.available(), crate::UpdateAvailable::OutOfDate);
    }

    #[test]
    fn quick_check_cached_respects_freshness() {
        let dir = tempfile::tempdir().unwrap();
        // Fresh snapshot: quick_check returns Some.
        let fresh = UpdateSnapshot::ok("0.1.0".into(), Some("0.2.0".into()), None);
        cache::write(dir.path(), &fresh).unwrap();
        let checker = UpdateChecker::new("0.1.0", dir.path()).unwrap();
        assert!(checker.quick_check_cached().is_some());

        // Stale snapshot (checked_at = UNIX_EPOCH): quick_check returns None.
        let stale = UpdateSnapshot {
            installed: "0.1.0".into(),
            latest: Some("0.2.0".into()),
            release_url: None,
            checked_at: Some(std::time::UNIX_EPOCH),
            status: UpdateStatus::Ok.as_str().to_string(),
            error_reason: None,
        };
        cache::write(dir.path(), &stale).unwrap();
        // The read-only helper updates the running version without
        // changing the cache timestamp.
        let snap = read_cache_only("0.1.0", dir.path());
        assert_eq!(snap.checked_at, Some(std::time::UNIX_EPOCH));
    }

    #[tokio::test]
    async fn refresh_sends_user_agent_and_parses_release() {
        let (url, request_rx) = http_fixture(
            200,
            &[("content-type", "application/json")],
            br#"{"tag_name":"v9.9.9","html_url":"https://example/v9.9.9"}"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let checker = make_checker(dir.path(), &url);

        let snap = checker.refresh().await;

        assert_eq!(snap.latest.as_deref(), Some("v9.9.9"));
        assert_eq!(snap.status_kind(), UpdateStatus::Ok);
        let request = request_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("captured request")
            .to_ascii_lowercase();
        assert!(
            request.contains("\r\nuser-agent: bloom\r\n"),
            "request did not contain Bloom User-Agent:\n{request}"
        );
    }

    #[tokio::test]
    async fn fetch_handles_404_gracefully() {
        let (url, _request_rx) = http_fixture(
            404,
            &[("content-type", "application/json")],
            br#"{"message":"Not Found"}"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let cached = UpdateSnapshot::ok("0.1.0".into(), Some("0.1.5".into()), None);
        cache::write(dir.path(), &cached).unwrap();
        let checker = make_checker(dir.path(), &url);

        let snap = checker.refresh().await;

        assert_eq!(snap.latest.as_deref(), Some("0.1.5"));
        assert_eq!(snap.status_kind(), UpdateStatus::Error);
        assert_eq!(snap.error_reason.as_deref(), Some("http 404 Not Found"));

        // A failed refresh is transient and must not replace the last
        // successful cache entry or its successful-refresh timestamp.
        let cached_after_failure = cache::read(dir.path()).expect("successful cache retained");
        assert_eq!(cached_after_failure.status_kind(), UpdateStatus::Ok);
        assert_eq!(cached_after_failure.latest.as_deref(), Some("0.1.5"));
        assert_eq!(
            cached_after_failure.checked_at, cached.checked_at,
            "failed refresh must not rewrite checked_at"
        );
    }
}
