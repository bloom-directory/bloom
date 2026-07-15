//! Semver parsing and comparison.
//!
//! We avoid the `semver` crate because the only ops we need are
//! split-on-`.`, parse `u64`, and lexicographic compare on 3-tuples.
//! Pre-release suffixes (`-rc.1`, `-beta.2`) are tolerated on the way
//! in but stripped before comparison — we treat `0.2.0-rc.1` as
//! `0.2.0` because GitHub's release tag is what the user cares about,
//! and we don't want a release-candidate tag to make the daemon think
//! "you have a newer version" when the stable one is what people
//! actually download.

/// Parse a version string like `"0.2.0"` or `"v0.2.0-rc.1"` into a
/// `(major, minor, patch)` tuple. Returns `None` for any input that
/// doesn't start with `v?` followed by three integer components
/// separated by dots.
pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // The third component may carry a pre-release suffix
    // ("0.2.0-rc.1" → "0-rc.1"). We split on '-' to strip it; if
    // a `-` is present we tolerate an additional dot-separated tail
    // ("0.2.0-rc.1" has 4 dot-separated parts: "0", "2", "0-rc", "1").
    let third = parts.next()?;
    let (patch_str, had_prerelease) = match third.split_once('-') {
        Some((p, _rest)) => (p, true),
        None => (third, false),
    };
    let patch = patch_str.parse().ok()?;
    // A 4th dot-separated component is only OK if it came from a
    // pre-release suffix (e.g. the "1" in "rc.1"). A bare
    // "1.2.3.4" is rejected.
    if let Some(extra) = parts.next()
        && (!had_prerelease || !extra.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some((major, minor, patch))
}

/// Lexicographic compare on `(major, minor, patch)` tuples. Returns
/// `Ordering::Less` if `a < b`, `Greater` if `a > b`, `Equal` if
/// `a == b`. Either input being unparseable yields `Equal` (we don't
/// want a bad tag to crash the daemon or show as "behind by ∞").
pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_semver(a), parse_semver(b)) {
        (Some(av), Some(bv)) => av.cmp(&bv),
        // If either is unparseable, claim equality. The caller is
        // expected to gate the comparison on `parse_semver` succeeding
        // for both; if not, the worst case is a stale "up to date"
        // status, never a false "behind".
        _ => std::cmp::Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn parses_plain_semver() {
        assert_eq!(parse_semver("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("0.2.3"), Some((0, 2, 3)));
        assert_eq!(parse_semver("10.20.30"), Some((10, 20, 30)));
    }

    #[test]
    fn parses_v_prefix() {
        assert_eq!(parse_semver("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn strips_prerelease() {
        assert_eq!(parse_semver("0.2.0-rc.1"), Some((0, 2, 0)));
        assert_eq!(parse_semver("v1.0.0-beta.2"), Some((1, 0, 0)));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("0.1"), None);
        assert_eq!(parse_semver("0.1.0.0"), None);
        assert_eq!(parse_semver("a.b.c"), None);
        assert_eq!(parse_semver("0.1.x"), None);
    }

    #[test]
    fn compare_basic() {
        assert_eq!(compare_semver("0.1.0", "0.2.0"), Ordering::Less);
        assert_eq!(compare_semver("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_semver("0.1.0", "0.1.0"), Ordering::Equal);
    }

    /// The classic lexicographic trap: `"1.9.0" > "1.10.0"` if you
    /// compare as strings. u64 compare on the components fixes it.
    #[test]
    fn compare_handles_two_digit_minor() {
        assert_eq!(compare_semver("1.9.0", "1.10.0"), Ordering::Less);
        assert_eq!(compare_semver("1.10.0", "1.9.0"), Ordering::Greater);
    }

    #[test]
    fn compare_ignores_prerelease() {
        // Both parse to (0, 2, 0); release-candidate and stable
        // are considered the same version for the "behind by" count.
        assert_eq!(compare_semver("0.2.0-rc.1", "0.2.0"), Ordering::Equal);
    }

    #[test]
    fn compare_unparseable_is_equal() {
        // Garbage on either side should not crash and should not
        // produce a misleading "behind" status.
        assert_eq!(compare_semver("garbage", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_semver("0.1.0", "garbage"), Ordering::Equal);
        assert_eq!(compare_semver("nope", "nope"), Ordering::Equal);
    }
}
