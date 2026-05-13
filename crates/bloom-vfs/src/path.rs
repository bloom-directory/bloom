//! Path parsing and normalisation for VFS operations.

use std::fmt;

/// Percent-decode a single path component received from the NFS kernel.
///
/// The mount adapter is the only chokepoint where kernel-supplied bytes
/// become VFS path segments. The kernel splits paths on `/` and hands us
/// each component verbatim, so users embed bytes that the shell/kernel
/// can't pass literally (notably space, `?`, `#`, etc.) using percent-
/// escapes — `cat /bloom/tools/keccak/hello%20world` should hash the
/// six-byte string `hello world`, not the literal ASCII `hello%20world`.
///
/// Decoding rules:
/// - `%XX` where `XX` is two hex digits decodes to the corresponding
///   byte. Mixed-case hex is accepted.
/// - A bare `%` not followed by two hex digits, or followed by non-hex,
///   is a malformed escape and returns `Err(PercentDecodeError)`.
/// - All other bytes pass through unchanged. We do NOT decode `/` (the
///   caller has already split on `/`); a `%2F` in input therefore stays
///   meaningful — it decodes to a literal `/` byte inside one segment,
///   which is the only way a user can put a `/` inside a single VFS
///   segment.
/// - The decoded bytes must be valid UTF-8; segments are `String` in
///   `VfsPath`. Non-UTF-8 input returns `Err(PercentDecodeError)`.
pub fn percent_decode_segment(input: &str) -> Result<String, PercentDecodeError> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(PercentDecodeError::Truncated);
            }
            let h = hex_nibble(bytes[i + 1]).ok_or(PercentDecodeError::BadHex)?;
            let l = hex_nibble(bytes[i + 2]).ok_or(PercentDecodeError::BadHex)?;
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PercentDecodeError::NotUtf8)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PercentDecodeError {
    #[error("truncated percent-escape (need two hex digits after `%`)")]
    Truncated,
    #[error("invalid hex digit in percent-escape")]
    BadHex,
    #[error("decoded bytes are not valid UTF-8")]
    NotUtf8,
}

/// A normalised, slash-separated path. No leading `/`, no `.`/`..` components.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VfsPath {
    segments: Vec<String>,
}

impl VfsPath {
    pub fn root() -> Self {
        Self { segments: vec![] }
    }

    pub fn parse(input: &str) -> Result<Self, PathError> {
        let mut out = Vec::new();
        for raw in input.split('/') {
            if raw.is_empty() || raw == "." {
                continue;
            }
            if raw == ".." {
                if out.pop().is_none() {
                    return Err(PathError::Escape);
                }
                continue;
            }
            if raw.contains('\\') || raw.contains('\0') {
                return Err(PathError::InvalidSegment(raw.to_string()));
            }
            out.push(raw.to_string());
        }
        Ok(Self { segments: out })
    }

    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn first(&self) -> Option<&str> {
        self.segments.first().map(|s| s.as_str())
    }

    /// Drop the leading segment and return the remainder.
    pub fn shift(&self) -> VfsPath {
        if self.segments.is_empty() {
            self.clone()
        } else {
            VfsPath {
                segments: self.segments[1..].to_vec(),
            }
        }
    }

    /// Return a new path with `seg` prepended.
    pub fn prepend(&self, seg: &str) -> VfsPath {
        let mut s = vec![seg.to_string()];
        s.extend(self.segments.iter().cloned());
        VfsPath { segments: s }
    }

    pub fn join(&self, seg: &str) -> VfsPath {
        let mut s = self.segments.clone();
        s.push(seg.to_string());
        VfsPath { segments: s }
    }

    pub fn to_string_path(&self) -> String {
        if self.segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }
}

impl fmt::Display for VfsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_path())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("path escapes root")]
    Escape,
    #[error("invalid segment: {0}")]
    InvalidSegment(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple() {
        let p = VfsPath::parse("/chains/ethereum/head/number").unwrap();
        assert_eq!(p.segments(), &["chains", "ethereum", "head", "number"]);
    }

    #[test]
    fn root_normalises() {
        assert!(VfsPath::parse("").unwrap().is_root());
        assert!(VfsPath::parse("/").unwrap().is_root());
        assert!(VfsPath::parse("//").unwrap().is_root());
    }

    #[test]
    fn rejects_escape() {
        assert!(VfsPath::parse("../etc").is_err());
    }

    #[test]
    fn dotdot_in_middle_pops() {
        let p = VfsPath::parse("a/b/../c").unwrap();
        assert_eq!(p.segments(), &["a", "c"]);
    }

    #[test]
    fn shift_drops_first() {
        let p = VfsPath::parse("a/b/c").unwrap();
        assert_eq!(p.shift().segments(), &["b", "c"]);
    }

    #[test]
    fn display_round_trip() {
        let p = VfsPath::parse("/x/y").unwrap();
        assert_eq!(p.to_string_path(), "/x/y");
        assert_eq!(VfsPath::root().to_string_path(), "/");
    }

    #[test]
    fn percent_decode_space() {
        assert_eq!(
            percent_decode_segment("hello%20world").unwrap(),
            "hello world"
        );
    }

    #[test]
    fn percent_decode_passthrough() {
        assert_eq!(percent_decode_segment("plain").unwrap(), "plain");
    }

    #[test]
    fn percent_decode_uppercase_and_mixed_hex() {
        assert_eq!(percent_decode_segment("%2A").unwrap(), "*");
        assert_eq!(percent_decode_segment("%2a").unwrap(), "*");
        assert_eq!(percent_decode_segment("%2F").unwrap(), "/");
    }

    #[test]
    fn percent_decode_literal_percent() {
        // The only way to embed a literal `%` is `%25`, and it must
        // round-trip cleanly so users with `%` in path components
        // (rare but legal) aren't mangled.
        assert_eq!(percent_decode_segment("%25").unwrap(), "%");
        assert_eq!(percent_decode_segment("100%25done").unwrap(), "100%done");
    }

    #[test]
    fn percent_decode_consecutive_escapes() {
        // " " then " " — common from `cat /tools/keccak/hello%20%20world`.
        assert_eq!(percent_decode_segment("a%20%20b").unwrap(), "a  b");
    }

    #[test]
    fn percent_decode_truncated_is_error() {
        assert!(matches!(
            percent_decode_segment("ab%2"),
            Err(PercentDecodeError::Truncated)
        ));
        assert!(matches!(
            percent_decode_segment("ab%"),
            Err(PercentDecodeError::Truncated)
        ));
    }

    #[test]
    fn percent_decode_bad_hex_is_error() {
        assert!(matches!(
            percent_decode_segment("ab%ZZ"),
            Err(PercentDecodeError::BadHex)
        ));
        assert!(matches!(
            percent_decode_segment("a%2Gb"),
            Err(PercentDecodeError::BadHex)
        ));
    }

    #[test]
    fn percent_decode_non_utf8_is_error() {
        // 0xFF is not a valid UTF-8 start byte on its own.
        assert!(matches!(
            percent_decode_segment("%FF"),
            Err(PercentDecodeError::NotUtf8)
        ));
    }

    #[test]
    fn percent_decode_segment_then_join_into_path() {
        // End-to-end: kernel hands us "hello%20world" as a child name;
        // adapter decodes to "hello world" and joins onto the parent.
        let parent = VfsPath::parse("/tools/keccak").unwrap();
        let decoded = percent_decode_segment("hello%20world").unwrap();
        let child = parent.join(&decoded);
        assert_eq!(child.segments(), &["tools", "keccak", "hello world"]);
    }
}
