//! On-disk JSON cache for the latest known release.
//!
//! One pretty-printed JSON file at `~/.bloom/cache/update_cache.json`,
//! rewritten on every successful refresh via temp-file + atomic
//! rename. No fsync: this is a UX nicety, not a security boundary;
//! losing the cache just means the next VFS read reports
//! `status: "unknown"` until the next refresh.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::snapshot::UpdateSnapshot;

/// Filename of the on-disk cache, relative to `home.cache_dir()`.
pub const CACHE_FILENAME: &str = "update_cache.json";

/// On-disk layout for the cache file. A thin wrapper over
/// [`UpdateSnapshot`] that adds a version field so we can change the
/// shape later without breaking already-serialised caches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSnapshot {
    /// Format version, currently always 1.
    pub version: u32,
    /// The snapshot itself, in its serialisable form.
    #[serde(flatten)]
    pub snapshot: UpdateSnapshot,
}

impl CachedSnapshot {
    /// Wrap a snapshot for writing.
    pub fn new(snapshot: UpdateSnapshot) -> Self {
        Self {
            version: 1,
            snapshot,
        }
    }
}

/// Resolve the cache file path. `cache_dir` is typically
/// `home.cache_dir()`; the function does not create the directory —
/// the caller must ensure it exists (the daemon's `home.ensure()`
/// already does this).
pub fn cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(CACHE_FILENAME)
}

/// Read the cache file. Returns `None` if the file doesn't exist,
/// can't be read, or fails to parse. We treat all errors as "no
/// cache" because the worst case is a single missed update check.
pub fn read(cache_dir: &Path) -> Option<UpdateSnapshot> {
    let path = cache_path(cache_dir);
    let raw = std::fs::read(&path).ok()?;
    let cached: CachedSnapshot = serde_json::from_slice(&raw).ok()?;
    if cached.version != 1 {
        return None;
    }
    Some(cached.snapshot)
}

/// Write the snapshot to the cache file atomically. Creates the
/// parent directory if it doesn't exist. Returns an error if the
/// write or rename fails — callers decide whether to log or
/// surface it.
pub fn write(cache_dir: &Path, snapshot: &UpdateSnapshot) -> std::io::Result<()> {
    std::fs::create_dir_all(cache_dir)?;
    let cached = CachedSnapshot::new(snapshot.clone());
    let bytes = serde_json::to_vec_pretty(&cached).map_err(std::io::Error::other)?;
    // Atomic write: write to a temp file in the same directory, then
    // rename over the target. Same-filesystem rename is atomic on
    // POSIX, and Windows treats rename-over-existing as atomic since
    // Rust 1.5 (via `std::fs::rename`).
    let mut tmp = tempfile::NamedTempFile::new_in(cache_dir)?;
    std::io::Write::write_all(&mut tmp, &bytes)?;
    tmp.flush()?;
    tmp.persist(cache_path(cache_dir))
        .map_err(|e| std::io::Error::other(format!("cache persist: {e}")))?;
    Ok(())
}

/// Compute the "behind by" count for the snapshot, or `None` if we
/// don't have enough information to tell (e.g. `latest` is unknown).
///
/// The counting rule is intentionally simple: total patch-equivalent
/// differences across major/minor/patch components. A jump from
/// `0.1.0` to `0.4.0` reports `300` (3 minor bumps × 100 each),
/// which is good enough to show in the VFS without claiming an exact
/// "you are N releases behind" count.
pub fn behind_by(snapshot: &UpdateSnapshot) -> Option<u64> {
    use crate::semver::parse_semver;
    use crate::snapshot::UpdateStatus;

    if snapshot.status_kind() != UpdateStatus::Ok {
        return None;
    }
    let installed = parse_semver(&snapshot.installed)?;
    let latest = parse_semver(snapshot.latest.as_deref()?)?;
    match installed.cmp_precedence(&latest) {
        std::cmp::Ordering::Less => {
            let distance = behind_count(
                (installed.major, installed.minor, installed.patch),
                (latest.major, latest.minor, latest.patch),
            );
            Some(distance.max(1))
        }
        _ => Some(0),
    }
}

fn behind_count(installed: (u64, u64, u64), latest: (u64, u64, u64)) -> u64 {
    let (ai, bi, ci) = installed;
    let (al, bl, cl) = latest;
    al.saturating_sub(ai) * 10_000 + bl.saturating_sub(bi) * 100 + cl.saturating_sub(ci)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{UpdateAvailable, UpdateStatus};

    fn snap() -> UpdateSnapshot {
        UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.2.0".into()),
            Some("https://github.com/bloom-directory/bloom/releases/tag/v0.2.0".into()),
        )
    }

    #[test]
    fn round_trips_via_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let original = snap();
        write(dir.path(), &original).expect("write cache");

        let loaded = read(dir.path()).expect("read cache");
        assert_eq!(loaded.installed, original.installed);
        assert_eq!(loaded.latest, original.latest);
        assert_eq!(loaded.release_url, original.release_url);
        assert_eq!(loaded.status_kind(), UpdateStatus::Ok);
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn read_garbage_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(cache_path(dir.path()), b"not json").unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn read_wrong_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({"version": 99, "installed": "0.1.0"}).to_string();
        std::fs::write(cache_path(dir.path()), raw).unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn write_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("dir");
        write(&nested, &snap()).expect("write into missing dir");
        assert!(nested.join(CACHE_FILENAME).exists());
    }

    #[test]
    fn behind_by_counts() {
        let mut s = snap();
        s.installed = "0.1.0".into();
        s.latest = Some("0.2.0".into());
        // 0.1.0 -> 0.2.0: minor bump, 0*10000 + 1*100 + 0 = 100
        assert_eq!(behind_by(&s), Some(100));

        s.installed = "0.1.0".into();
        s.latest = Some("0.4.0".into());
        // 0.1.0 -> 0.4.0: minor jump 3, 3*100 = 300
        assert_eq!(behind_by(&s), Some(300));

        s.installed = "0.2.0".into();
        s.latest = Some("0.1.0".into());
        // 0.2.0 -> 0.1.0: we're ahead, 0
        assert_eq!(behind_by(&s), Some(0));

        s.latest = None;
        // No info: unknown
        assert_eq!(behind_by(&s), None);
    }

    #[test]
    fn behind_by_handles_two_digit_minor() {
        // The lexicographic trap: 1.9.0 vs 1.10.0. As semver u64
        // components this is 1*10000 + 9*100 = 10900 vs
        // 1*10000 + 10*100 = 11000, so 1.9.0 is behind by 100.
        let mut s = snap();
        s.installed = "1.9.0".into();
        s.latest = Some("1.10.0".into());
        assert_eq!(behind_by(&s), Some(100));
    }

    #[test]
    fn behind_by_counts_prerelease_to_stable_as_one() {
        let mut s = snap();
        s.installed = "0.2.0-rc.1".into();
        s.latest = Some("0.2.0".into());
        assert_eq!(s.available(), UpdateAvailable::OutOfDate);
        assert_eq!(behind_by(&s), Some(1));
    }

    #[test]
    fn behind_by_is_unknown_for_non_semver() {
        let mut s = snap();
        s.latest = Some("latest".into());
        assert_eq!(behind_by(&s), None);

        s.latest = Some("0.2.0".into());
        s.installed = "development".into();
        assert_eq!(behind_by(&s), None);
    }

    #[test]
    fn behind_by_is_unknown_after_failed_refresh() {
        let mut s = snap();
        s.status = UpdateStatus::Error.as_str().to_string();
        assert_eq!(s.available(), UpdateAvailable::Unknown);
        assert_eq!(behind_by(&s), None);
    }
}
