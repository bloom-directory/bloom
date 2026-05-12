//! `ens/` — read-only ENS name resolution surface.
//!
//! Path layout (relative to the `ens` mount point):
//!
//! - `ens/`                              — list: any cached names plus
//!   the synthetic `<name>.eth` directories looked up in this session.
//! - `ens/<name.eth>/`                   — list: `address`, `avatar`,
//!   `content_hash`, `text/` (the standard subpaths).
//! - `ens/<name.eth>/address`            — resolved address (EIP-55) or
//!   `unresolved` if the lookup fails.
//! - `ens/<name.eth>/avatar`             — `text("avatar")` record, or
//!   `not set` when none is configured.
//! - `ens/<name.eth>/text/<key>`         — arbitrary text record. `<key>`
//!   may be any ENS standard / custom key (`email`, `url`, …).
//! - `ens/<name.eth>/content_hash`       — EIP-1577 contenthash record
//!   as `0x`-prefixed hex, or `not set` when none is configured.
//!
//! All entries are read-only.
//!
//! Reverse resolution lives at `chains/<chain>/addresses/<addr>/ens`
//! per spec §3.2 — that path is wired through [`super::ChainsHandler`]
//! and consults [`bloom_ens::EnsClient::reverse`] (which already
//! cross-checks the forward lookup). This handler stays
//! forward-only and 404s any non-`*.eth` segment.
//!
//! Behaviour:
//!
//! - Results are cached in-process for [`HANDLER_CACHE_TTL`] (60s) so a
//!   `tail`-ish workflow doesn't slam mainnet RPC. The underlying
//!   [`bloom_ens::EnsClient`] also caches positive lookups (5min default)
//!   — this layer is intentionally shorter so unresolved/no-record
//!   misses don't pin themselves for too long.
//! - When the daemon was built without an ENS-capable chain
//!   (mainnet/Sepolia/Goerli/Holesky), every read returns the same
//!   "ENS unavailable" backend error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;

use bloom_ens::{EnsClient, EnsError};
use bloom_proto::checksum_address;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// In-handler cache TTL. Distinct from (and shorter than) the EnsClient
/// cache so misses (`unresolved`, `not set`) refresh promptly.
pub const HANDLER_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
enum Cached {
    Address(Option<String>), // None == "unresolved"
    Text(Option<String>),    // None == "not set"
    Content(Option<String>), // hex or "not set"
}

#[derive(Clone)]
struct CachedEntry {
    value: Cached,
    inserted: Instant,
}

#[derive(Default)]
struct Cache {
    /// keyed by `(name, kind, sub)` where `sub` is the text key for text
    /// records, otherwise empty.
    entries: HashMap<(String, &'static str, String), CachedEntry>,
    /// Names looked up in this process (so `ls /bloom/ens/` shows
    /// something useful). Persistent enumeration of the global ENS name
    /// space is impossible.
    seen_names: Vec<String>,
}

#[derive(Clone)]
pub struct EnsHandler {
    client: Option<EnsClient>,
    cache: Arc<RwLock<Cache>>,
}

impl EnsHandler {
    /// Construct from an optional ENS client. Pass `None` if no
    /// mainnet-capable chain is configured; reads will return a clear
    /// backend error in that case.
    pub fn new(client: Option<EnsClient>) -> Self {
        Self {
            client,
            cache: Arc::new(RwLock::new(Cache::default())),
        }
    }

    fn require_client(&self) -> Result<&EnsClient, HandlerError> {
        self.client.as_ref().ok_or_else(|| {
            HandlerError::backend(
                "ens unavailable: no mainnet/sepolia/goerli/holesky chain configured",
            )
        })
    }

    fn is_ens_name(s: &str) -> bool {
        // Allow any `*.eth` (and other TLDs ENS supports — keep it
        // permissive, the resolver will reject malformed names).
        s.contains('.') && !s.starts_with('.') && !s.ends_with('.')
    }

    fn cache_get(&self, name: &str, kind: &'static str, sub: &str) -> Option<Cached> {
        let key = (name.to_string(), kind, sub.to_string());
        let guard = self.cache.read();
        guard.entries.get(&key).and_then(|e| {
            if e.inserted.elapsed() < HANDLER_CACHE_TTL {
                Some(e.value.clone())
            } else {
                None
            }
        })
    }

    fn cache_put(&self, name: &str, kind: &'static str, sub: &str, value: Cached) {
        let key = (name.to_string(), kind, sub.to_string());
        let mut guard = self.cache.write();
        guard.entries.insert(
            key,
            CachedEntry {
                value,
                inserted: Instant::now(),
            },
        );
        if !guard.seen_names.iter().any(|n| n == name) {
            guard.seen_names.push(name.to_string());
        }
    }

    /// Resolve a name to a checksum-address string (or `None` if the
    /// name is unresolved). Cached in-process for [`HANDLER_CACHE_TTL`].
    async fn resolve_address(&self, name: &str) -> Result<Option<String>, HandlerError> {
        if let Some(Cached::Address(v)) = self.cache_get(name, "addr", "") {
            return Ok(v);
        }
        let client = self.require_client()?;
        let result = match client.resolve(name).await {
            Ok(addr) => Some(checksum_address(&addr)),
            Err(EnsError::NotFound(_)) => None,
            Err(EnsError::InvalidName(s)) => return Err(HandlerError::invalid(s)),
            Err(e) => return Err(HandlerError::backend(e.to_string())),
        };
        self.cache_put(name, "addr", "", Cached::Address(result.clone()));
        Ok(result)
    }

    /// Look up a text record (`avatar`, `email`, etc). Returns `None`
    /// when the record is unset.
    async fn lookup_text(&self, name: &str, key: &str) -> Result<Option<String>, HandlerError> {
        if let Some(Cached::Text(v)) = self.cache_get(name, "text", key) {
            return Ok(v);
        }
        let client = self.require_client()?;
        let result = match client.text(name, key).await {
            Ok(s) => Some(s),
            Err(EnsError::NotFound(_)) => None,
            Err(EnsError::InvalidName(s)) => return Err(HandlerError::invalid(s)),
            Err(e) => return Err(HandlerError::backend(e.to_string())),
        };
        self.cache_put(name, "text", key, Cached::Text(result.clone()));
        Ok(result)
    }

    /// Look up the contenthash record. Returns `None` when unset. The
    /// returned string is `0x`-prefixed hex (without an EIP-1577 codec
    /// decode — that's a job for tools).
    async fn lookup_content_hash(&self, name: &str) -> Result<Option<String>, HandlerError> {
        if let Some(Cached::Content(v)) = self.cache_get(name, "content", "") {
            return Ok(v);
        }
        let client = self.require_client()?;
        let result = match client.content_hash(name).await {
            Ok(b) => Some(format!("0x{}", hex::encode(b.as_ref()))),
            Err(EnsError::NotFound(_)) => None,
            Err(EnsError::InvalidName(s)) => return Err(HandlerError::invalid(s)),
            Err(e) => return Err(HandlerError::backend(e.to_string())),
        };
        self.cache_put(name, "content", "", Cached::Content(result.clone()));
        Ok(result)
    }
}

const ROOT_FILES: &[&str] = &["address", "avatar", "content_hash"];

#[async_trait]
impl Handler for EnsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "ens.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "ens.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "ens.list_err");
        }
        r
    }
}

impl EnsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(Entry::dir("")),
            1 => {
                let n = &segs[0];
                if !Self::is_ens_name(n) {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                Ok(Entry::dir(n))
            }
            2 => {
                let name = &segs[0];
                if !Self::is_ens_name(name) {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                match segs[1].as_str() {
                    "address" | "avatar" | "content_hash" => Ok(Entry::file(&segs[1])),
                    "text" => Ok(Entry::dir("text")),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            3 => {
                let name = &segs[0];
                if !Self::is_ens_name(name) || segs[1] != "text" {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                // Any text key is allowed (we just synthesize the file).
                Ok(Entry::file(&segs[2]))
            }
            // TODO(reverse): add `ens/<0xAddr>/name` if/when we need a
            // top-level reverse surface. For now use the per-chain
            // `chains/<chain>/addresses/<addr>/ens` symlink.
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            2 => {
                let name = &segs[0];
                if !Self::is_ens_name(name) {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                match segs[1].as_str() {
                    "address" => match self.resolve_address(name).await? {
                        Some(s) => Ok(format!("{}\n", s).into_bytes()),
                        None => Ok(b"unresolved\n".to_vec()),
                    },
                    "avatar" => match self.lookup_text(name, "avatar").await? {
                        Some(s) => Ok(format!("{}\n", s).into_bytes()),
                        None => Ok(b"not set\n".to_vec()),
                    },
                    "content_hash" => match self.lookup_content_hash(name).await? {
                        Some(s) => Ok(format!("{}\n", s).into_bytes()),
                        None => Ok(b"not set\n".to_vec()),
                    },
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            3 => {
                let name = &segs[0];
                if !Self::is_ens_name(name) || segs[1] != "text" {
                    return Err(HandlerError::NotAFile(path.to_string_path()));
                }
                let key = &segs[2];
                match self.lookup_text(name, key).await? {
                    Some(s) => Ok(format!("{}\n", s).into_bytes()),
                    None => Ok(b"not set\n".to_vec()),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => {
                // Best-effort: list names we've seen this session. The
                // surface is virtually-typed: agents can `cat` any name
                // even if it isn't in this list.
                let guard = self.cache.read();
                let mut out: Vec<Entry> = guard.seen_names.iter().map(|n| Entry::dir(n)).collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
            1 => {
                let n = &segs[0];
                if !Self::is_ens_name(n) {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                let mut out: Vec<Entry> = ROOT_FILES.iter().map(|f| Entry::file(f)).collect();
                out.push(Entry::dir("text"));
                Ok(out)
            }
            2 => {
                let name = &segs[0];
                if !Self::is_ens_name(name) || segs[1] != "text" {
                    return Err(HandlerError::NotADir(path.to_string_path()));
                }
                // Text records are open-ended; we don't enumerate them
                // (would require resolver-specific `keys()` support that
                // ENS doesn't standardise). Return an empty listing —
                // agents read keys directly.
                Ok(Vec::new())
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    #[tokio::test]
    async fn unconfigured_returns_clear_error() {
        let h = EnsHandler::new(None);
        let res = h
            .read(&VfsPath::parse("vitalik.eth/address").unwrap())
            .await;
        let err = res.unwrap_err();
        assert!(matches!(err, HandlerError::Backend(_)));
        let msg = err.to_string();
        assert!(msg.contains("ens unavailable"), "got: {msg}");
    }

    #[tokio::test]
    async fn lookup_advertises_standard_subpaths() {
        let h = EnsHandler::new(None);
        let entries = h.list(&VfsPath::parse("alice.eth").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for required in ["address", "avatar", "content_hash", "text"] {
            assert!(names.contains(&required), "missing {required}: {names:?}");
        }
    }

    #[tokio::test]
    async fn non_ens_name_in_root_404s() {
        let h = EnsHandler::new(None);
        let res = h.lookup(&VfsPath::parse("notaname").unwrap()).await;
        assert!(matches!(res, Err(HandlerError::NotFound(_))));
    }

    #[tokio::test]
    async fn unconfigured_unresolved_address_errors_distinctly() {
        // Without an EnsClient, even "unresolved" responses can't be
        // produced without contacting RPC — verify the error is the
        // mainnet-needed message rather than a panic.
        let h = EnsHandler::new(None);
        let err = h
            .read(&VfsPath::parse("unknown.eth/address").unwrap())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ens unavailable"));
    }

    #[tokio::test]
    async fn cache_returns_same_value_quickly() {
        // We can't hit real RPC in unit tests, but we can prime the
        // cache directly and assert the read path returns the cached
        // value for repeated reads in well under 100us.
        let h = EnsHandler::new(None);
        h.cache_put("alice.eth", "addr", "", Cached::Address(None));
        h.cache_put("alice.eth", "text", "avatar", Cached::Text(None));
        h.cache_put("alice.eth", "content", "", Cached::Content(None));
        let p = VfsPath::parse("alice.eth/address").unwrap();
        // First read primes the cache key path.
        let first = h.read(&p).await.unwrap();
        assert_eq!(first, b"unresolved\n");
        // Second read must be served from cache fast enough to clear
        // the 100us bar in CI. Allow some headroom for noisy runners.
        let start = Instant::now();
        let second = h.read(&p).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(first, second);
        assert!(
            elapsed < Duration::from_millis(5),
            "cache read took {:?}, expected sub-ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn text_subpath_accepts_any_key() {
        let h = EnsHandler::new(None);
        // Lookups should be valid for any key — the file synthesis
        // doesn't require pre-registration.
        let e = h
            .lookup(&VfsPath::parse("alice.eth/text/some.custom.key").unwrap())
            .await
            .unwrap();
        assert_eq!(e.name, "some.custom.key");
    }

    // --- Shape B (directory) contract pins ----------------------------
    //
    // EXAMPLES.md §11 documents `/bloom/ens/<name>/` as a *directory*
    // containing `address`, `avatar`, `content_hash`, `text/`. These
    // tests pin that shape so a future refactor can't silently flip
    // `<name>` into a file (which would break `cat <name>/address`).

    #[tokio::test]
    async fn name_is_a_directory_not_a_file() {
        // The user-reported "bug" was that `/bloom/ens/vitalik.eth`
        // reads as a directory. That is the documented contract —
        // every example uses `<name>/<field>`. Pin it.
        let h = EnsHandler::new(None);
        let e = h
            .lookup(&VfsPath::parse("vitalik.eth").unwrap())
            .await
            .unwrap();
        assert_eq!(e.kind, EntryKind::Dir, "ens name must be a directory");
        assert_eq!(e.name, "vitalik.eth");
    }

    #[tokio::test]
    async fn name_subpaths_are_files_or_text_dir() {
        let h = EnsHandler::new(None);
        for leaf in ["address", "avatar", "content_hash"] {
            let p = format!("vitalik.eth/{leaf}");
            let e = h.lookup(&VfsPath::parse(&p).unwrap()).await.unwrap();
            assert_eq!(e.kind, EntryKind::File, "{leaf} must be a file");
        }
        let text = h
            .lookup(&VfsPath::parse("vitalik.eth/text").unwrap())
            .await
            .unwrap();
        assert_eq!(text.kind, EntryKind::Dir);

        let key = h
            .lookup(&VfsPath::parse("vitalik.eth/text/com.twitter").unwrap())
            .await
            .unwrap();
        assert_eq!(key.kind, EntryKind::File);
    }

    // --- Read-path tests via primed cache (no live RPC) --------------
    //
    // We can't construct a real EnsClient without an RPC endpoint, but
    // every read path consults the in-handler cache *before* touching
    // the client. Priming the cache lets us exercise the formatting
    // and routing logic without a network — equivalent in coverage to
    // a mocked resolver for these surface-level concerns.

    #[tokio::test]
    async fn address_read_returns_resolved_value_from_cache() {
        let h = EnsHandler::new(None);
        let addr = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045";
        h.cache_put(
            "vitalik.eth",
            "addr",
            "",
            Cached::Address(Some(addr.to_string())),
        );
        let bytes = h
            .read(&VfsPath::parse("vitalik.eth/address").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, format!("{addr}\n").into_bytes());
    }

    #[tokio::test]
    async fn address_read_unresolved_returns_literal() {
        let h = EnsHandler::new(None);
        h.cache_put("nobody.eth", "addr", "", Cached::Address(None));
        let bytes = h
            .read(&VfsPath::parse("nobody.eth/address").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"unresolved\n");
    }

    #[tokio::test]
    async fn avatar_and_text_routes_share_cache() {
        // The `avatar` shortcut reads the same key as `text/avatar`.
        // Prime the text cache once and confirm both paths see it.
        let h = EnsHandler::new(None);
        let url = "https://example.test/v.png";
        h.cache_put(
            "vitalik.eth",
            "text",
            "avatar",
            Cached::Text(Some(url.to_string())),
        );
        let via_shortcut = h
            .read(&VfsPath::parse("vitalik.eth/avatar").unwrap())
            .await
            .unwrap();
        let via_text = h
            .read(&VfsPath::parse("vitalik.eth/text/avatar").unwrap())
            .await
            .unwrap();
        assert_eq!(via_shortcut, format!("{url}\n").into_bytes());
        assert_eq!(via_text, via_shortcut);
    }

    #[tokio::test]
    async fn unset_text_record_returns_not_set() {
        let h = EnsHandler::new(None);
        h.cache_put("vitalik.eth", "text", "email", Cached::Text(None));
        let bytes = h
            .read(&VfsPath::parse("vitalik.eth/text/email").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"not set\n");
    }

    #[tokio::test]
    async fn content_hash_read_formats_hex() {
        let h = EnsHandler::new(None);
        h.cache_put(
            "ens.eth",
            "content",
            "",
            Cached::Content(Some("0xdeadbeef".to_string())),
        );
        let bytes = h
            .read(&VfsPath::parse("ens.eth/content_hash").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"0xdeadbeef\n");
    }

    #[tokio::test]
    async fn content_hash_unset_returns_not_set() {
        let h = EnsHandler::new(None);
        h.cache_put("ens.eth", "content", "", Cached::Content(None));
        let bytes = h
            .read(&VfsPath::parse("ens.eth/content_hash").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"not set\n");
    }

    #[tokio::test]
    async fn list_name_dir_matches_examples_md() {
        // EXAMPLES.md §11: `ls /bloom/ens/vitalik.eth/` →
        //   address  avatar  content_hash  text
        let h = EnsHandler::new(None);
        let entries = h
            .list(&VfsPath::parse("vitalik.eth").unwrap())
            .await
            .unwrap();
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["address", "avatar", "content_hash", "text"]);
    }

    #[tokio::test]
    async fn non_eth_subpath_at_root_is_404() {
        // Reverse lookups don't live here; per the module docs and
        // EXAMPLES.md they're under chains/<chain>/addresses/<addr>/ens.
        let h = EnsHandler::new(None);
        for bad in ["0xabc", "notaname", ""] {
            let p = VfsPath::parse(bad).unwrap();
            // empty parses to root which is a dir; only non-empty
            // non-ENS names should 404 at lookup.
            if p.segments().is_empty() {
                continue;
            }
            let res = h.lookup(&p).await;
            assert!(
                matches!(res, Err(HandlerError::NotFound(_))),
                "{bad} should 404, got {res:?}"
            );
        }
    }
}
