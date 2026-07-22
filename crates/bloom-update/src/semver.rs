//! SemVer parsing and precedence comparison.

/// Parse a version string like `"0.2.0"` or `"v0.2.0-rc.1"`.
///
/// GitHub release tags conventionally use a leading `v`, while the Rust
/// `semver` crate expects the version without it. The standard parser is
/// used so prerelease identifiers and SemVer validation follow the spec.
pub fn parse_semver(s: &str) -> Option<semver::Version> {
    let normalized = s.strip_prefix('v').unwrap_or(s);
    normalized.parse().ok()
}

/// Compare SemVer precedence, ignoring build metadata as required by SemVer.
/// Either input being unparseable yields `Equal` so malformed release tags
/// cannot make the daemon claim it is behind an infinite version.
pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_semver(a), parse_semver(b)) {
        (Some(av), Some(bv)) => av.cmp_precedence(&bv),
        _ => std::cmp::Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    fn version(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn parses_plain_semver() {
        assert_eq!(parse_semver("0.1.0"), Some(version("0.1.0")));
        assert_eq!(parse_semver("0.2.3"), Some(version("0.2.3")));
        assert_eq!(parse_semver("10.20.30"), Some(version("10.20.30")));
    }

    #[test]
    fn parses_v_prefix() {
        assert_eq!(parse_semver("v0.1.0"), Some(version("0.1.0")));
        assert_eq!(parse_semver("v1.2.3"), Some(version("1.2.3")));
    }

    #[test]
    fn preserves_prerelease_ordering() {
        assert_eq!(parse_semver("0.2.0-rc.1"), Some(version("0.2.0-rc.1")));
        assert_eq!(compare_semver("0.2.0-rc.1", "0.2.0"), Ordering::Less);
        assert_eq!(
            compare_semver("0.2.0-rc.1.2", "0.2.0-rc.1.10"),
            Ordering::Less
        );
    }

    #[test]
    fn ignores_build_metadata_for_precedence() {
        assert_eq!(
            compare_semver("1.2.3+build.1", "1.2.3+build.2"),
            Ordering::Equal
        );
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("0.1"), None);
        assert_eq!(parse_semver("0.1.0.0"), None);
        assert_eq!(parse_semver("a.b.c"), None);
        assert_eq!(parse_semver("0.1.x"), None);
        assert_eq!(parse_semver("1.01.0"), None);
    }

    #[test]
    fn compare_basic() {
        assert_eq!(compare_semver("0.1.0", "0.2.0"), Ordering::Less);
        assert_eq!(compare_semver("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_semver("0.1.0", "0.1.0"), Ordering::Equal);
    }

    #[test]
    fn compare_handles_two_digit_minor() {
        assert_eq!(compare_semver("1.9.0", "1.10.0"), Ordering::Less);
        assert_eq!(compare_semver("1.10.0", "1.9.0"), Ordering::Greater);
    }

    #[test]
    fn compare_unparseable_is_equal() {
        assert_eq!(compare_semver("garbage", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_semver("0.1.0", "garbage"), Ordering::Equal);
        assert_eq!(compare_semver("nope", "nope"), Ordering::Equal);
    }
}
