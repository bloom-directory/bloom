//! Snapshot types for the update checker.
//!
//! The snapshot is the single source of truth for "what do we know
//! about the latest release on GitHub". It is held behind a
//! `parking_lot::RwLock` inside [`UpdateChecker`](crate::UpdateChecker)
//! and cloned cheaply for VFS reads.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Three-valued status of the latest known release. Used internally
/// for type-safe branching; the on-disk / on-wire shape is a flat
/// string in the [`UpdateSnapshot::status`] field plus an optional
/// [`UpdateSnapshot::error_reason`] for the error case (not exposed
/// in the VFS — kept for logs only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// We successfully reached GitHub and parsed a release.
    Ok,
    /// We have never successfully reached GitHub (no cache file, or
    /// the cache is empty). The VFS renders this as
    /// `available = "unknown"`.
    Unknown,
    /// A refresh attempt failed. The reason is on the snapshot's
    /// `error_reason` field.
    Error,
}

impl UpdateStatus {
    /// String form used in JSON and the VFS: one of `"ok"`,
    /// `"unknown"`, `"error"`.
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateStatus::Ok => "ok",
            UpdateStatus::Unknown => "unknown",
            UpdateStatus::Error => "error",
        }
    }
}

impl std::str::FromStr for UpdateStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ok" => Ok(UpdateStatus::Ok),
            "unknown" => Ok(UpdateStatus::Unknown),
            "error" => Ok(UpdateStatus::Error),
            _ => Err(()),
        }
    }
}

/// What an agent or user should do based on the snapshot. This is
/// derived from the snapshot (not stored) so the VFS can render it
/// without doing semver math at read time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateAvailable {
    /// `latest > installed` (semver compare succeeded and shows a
    /// newer version).
    OutOfDate,
    /// `latest <= installed` (we're on the latest or ahead).
    UpToDate,
    /// We can't tell (no network yet, or GitHub errored, or the
    /// release tag isn't parseable as semver).
    Unknown,
}

/// Immutable view of "what do we know about the latest release".
/// Cloning is cheap (all fields are `String` / `Option<String>` /
/// `Option<SystemTime>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSnapshot {
    /// The version this binary was compiled with
    /// (`env!("CARGO_PKG_VERSION")`). Set at construction and never
    /// changes.
    pub installed: String,
    /// The latest known release tag from GitHub, e.g. `Some("0.2.0")`.
    /// `None` if we haven't successfully fetched yet.
    pub latest: Option<String>,
    /// The HTML URL of the latest release, e.g.
    /// `Some("https://github.com/.../releases/tag/v0.2.0")`. `None`
    /// if unknown.
    pub release_url: Option<String>,
    /// When the last successful refresh happened. `None` if we've
    /// never successfully refreshed.
    pub checked_at: Option<SystemTime>,
    /// Status of the last refresh, as a flat string: `"ok"`,
    /// `"unknown"`, or `"error"`. Use [`UpdateSnapshot::status_kind`]
    /// for the typed enum.
    pub status: String,
    /// Human-readable reason for the most recent error, if any. Not
    /// persisted to the cache file (the cache only stores successful
    /// snapshots, and the error state is transient — it gets cleared
    /// on the next successful refresh or restart). Used for
    /// `tracing::warn!` and `eprintln!` only.
    #[serde(skip)]
    pub error_reason: Option<String>,
}

impl UpdateSnapshot {
    /// Convenience constructor for the "just been refreshed OK" case.
    pub fn ok(installed: String, latest: Option<String>, release_url: Option<String>) -> Self {
        Self {
            installed,
            latest,
            release_url,
            checked_at: Some(SystemTime::now()),
            status: UpdateStatus::Ok.as_str().to_string(),
            error_reason: None,
        }
    }

    /// Constructor for the empty / never-refreshed case. Used at
    /// startup before the first network call completes.
    pub fn unknown(installed: String) -> Self {
        Self {
            installed,
            latest: None,
            release_url: None,
            checked_at: None,
            status: UpdateStatus::Unknown.as_str().to_string(),
            error_reason: None,
        }
    }

    /// Constructor for the "last refresh errored" case. `reason` is
    /// stored on the snapshot but is not surfaced in the VFS.
    pub fn error(installed: String, reason: String) -> Self {
        Self {
            installed,
            latest: None,
            release_url: None,
            checked_at: Some(SystemTime::now()),
            status: UpdateStatus::Error.as_str().to_string(),
            error_reason: Some(reason),
        }
    }

    /// Typed status for branching code. Defaults to [`UpdateStatus::Unknown`]
    /// if the string is not one of the three known values (forward
    /// compat for future variants).
    pub fn status_kind(&self) -> UpdateStatus {
        self.status.parse().unwrap_or(UpdateStatus::Unknown)
    }

    /// Map this snapshot to an [`UpdateAvailable`] verdict using
    /// the crate's semver parser. The VFS reads this for the
    /// `update/available` leaf and the `summary.json`.
    pub fn available(&self) -> UpdateAvailable {
        if self.status_kind() != UpdateStatus::Ok {
            return UpdateAvailable::Unknown;
        }
        let Some(latest) = self.latest.as_deref() else {
            return UpdateAvailable::Unknown;
        };
        let (Some(installed), Some(latest)) = (
            crate::semver::parse_semver(&self.installed),
            crate::semver::parse_semver(latest),
        ) else {
            return UpdateAvailable::Unknown;
        };
        match installed.cmp_precedence(&latest) {
            std::cmp::Ordering::Less => UpdateAvailable::OutOfDate,
            _ => UpdateAvailable::UpToDate,
        }
    }

    /// "Behind by" count, or `None` if we don't have enough
    /// information. See [`crate::cache::behind_by`] for the
    /// counting rule.
    pub fn behind_by(&self) -> Option<u64> {
        crate::cache::behind_by(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_no_latest() {
        let s = UpdateSnapshot::unknown("0.1.0".into());
        assert_eq!(s.available(), UpdateAvailable::Unknown);
        assert_eq!(s.behind_by(), None);
    }

    #[test]
    fn out_of_date_when_latest_newer() {
        let s = UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.2.0".into()),
            Some("https://example/v0.2.0".into()),
        );
        assert_eq!(s.available(), UpdateAvailable::OutOfDate);
        assert_eq!(s.behind_by(), Some(100));
    }

    #[test]
    fn up_to_date_when_same() {
        let s = UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.1.0".into()),
            Some("https://example/v0.1.0".into()),
        );
        assert_eq!(s.available(), UpdateAvailable::UpToDate);
        assert_eq!(s.behind_by(), Some(0));
    }

    #[test]
    fn up_to_date_when_ahead() {
        // Pre-release or dev install that's newer than the latest
        // stable release should still report "up to date", not
        // "behind by N".
        let s = UpdateSnapshot::ok(
            "0.3.0".into(),
            Some("0.2.0".into()),
            Some("https://example/v0.2.0".into()),
        );
        assert_eq!(s.available(), UpdateAvailable::UpToDate);
        assert_eq!(s.behind_by(), Some(0));
    }

    #[test]
    fn unknown_when_either_version_is_not_semver() {
        let invalid_latest = UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("latest".into()),
            Some("https://example/latest".into()),
        );
        assert_eq!(invalid_latest.available(), UpdateAvailable::Unknown);
        assert_eq!(invalid_latest.behind_by(), None);

        let invalid_installed = UpdateSnapshot::ok(
            "development".into(),
            Some("v0.2.0".into()),
            Some("https://example/v0.2.0".into()),
        );
        assert_eq!(invalid_installed.available(), UpdateAvailable::Unknown);
        assert_eq!(invalid_installed.behind_by(), None);
    }

    #[test]
    fn unknown_when_status_is_error() {
        let s = UpdateSnapshot::error("0.1.0".into(), "boom".into());
        // We have a latest version field, but the status is errored.
        // `available` returns Unknown so a transient blip doesn't
        // downgrade a known-good state to false-positive.
        assert_eq!(s.available(), UpdateAvailable::Unknown);
    }

    #[test]
    fn error_status_serialises_with_status_string() {
        let s = UpdateSnapshot::error("0.1.0".into(), "network down".into());
        let json = serde_json::to_value(&s).unwrap();
        // `status` is a flat string, not a tagged object.
        assert_eq!(json["status"], serde_json::json!("error"));
        // The reason is `skip`-serialised (not in the VFS payload,
        // not in the cache file).
        assert!(json.get("error_reason").is_none());
    }
}
