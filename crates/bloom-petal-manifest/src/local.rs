//! Local handler-petal manifest schema (`petal.toml`).
//!
//! Local petals use the same wasm custom-section name as chain petals, but
//! the payload is the authored TOML bytes. Chain manifest decoding remains
//! canonical-codec based; this module is the strict local-mode path used at
//! install time.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Schema string for v1 local handler petals.
pub const LOCAL_SCHEMA: &str = "bloom.petal.local.v1";

/// v1 local-petal capabilities. Default is deny; absence means no host powers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LocalCapability {
    /// Read public VFS paths through the host.
    #[serde(rename = "vfs.read")]
    VfsRead,
    /// Write public VFS paths through the host.
    #[serde(rename = "vfs.write")]
    VfsWrite,
    /// Make daemon-mediated HTTP(S) requests.
    #[serde(rename = "net.fetch")]
    NetFetch,
    /// Ask the daemon keystore to sign a 32-byte hash.
    #[serde(rename = "sign")]
    Sign,
    /// Use private per-petal storage.
    #[serde(rename = "store")]
    Store,
}

impl LocalCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalCapability::VfsRead => "vfs.read",
            LocalCapability::VfsWrite => "vfs.write",
            LocalCapability::NetFetch => "net.fetch",
            LocalCapability::Sign => "sign",
            LocalCapability::Store => "store",
        }
    }
}

impl fmt::Display for LocalCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provider declaration. v1 accepts only `kind = "vfs"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProvides {
    /// Provider kind. v1 validates this as exactly `vfs`.
    pub kind: String,
    /// Single segment served below `apps/<mount>/`.
    pub mount: String,
    /// Declared capabilities. Runtime masks may narrow this set.
    #[serde(default)]
    pub caps: Vec<LocalCapability>,
}

/// Top-level local handler manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPetalManifest {
    /// Must be [`LOCAL_SCHEMA`].
    pub schema: String,
    /// Human-readable petal name.
    pub name: String,
    /// What this petal provides.
    pub provides: LocalProvides,
    /// Optional network policy.
    #[serde(default)]
    pub net: Option<NetSection>,
    /// Optional endpoint hints keyed by mount-relative paths.
    #[serde(default)]
    pub endpoint: Vec<EndpointSpec>,
}

impl LocalPetalManifest {
    /// Declared capabilities as a set.
    pub fn cap_set(&self) -> BTreeSet<LocalCapability> {
        self.provides.caps.iter().copied().collect()
    }

    /// Mount segment served below `apps/`.
    pub fn mount(&self) -> &str {
        &self.provides.mount
    }
}

/// Network-policy TOML section.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetSection {
    /// Explicit allow rules. Empty means no network access.
    #[serde(default)]
    pub allow: Vec<NetAllowRule>,
}

/// HTTP method accepted by the local network policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
        }
    }
}

/// One exact-host allow rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetAllowRule {
    /// Exact host name. Wildcards and ports are rejected.
    pub host: String,
    /// Allowed HTTP methods. Omitted means GET only.
    #[serde(default)]
    pub methods: Option<Vec<HttpMethod>>,
    /// Allowed URL paths. Omitted means any path on the host.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

impl NetAllowRule {
    /// Effective method list after applying TOML defaults.
    pub fn effective_methods(&self) -> Vec<HttpMethod> {
        self.methods
            .clone()
            .unwrap_or_else(|| vec![HttpMethod::Get])
    }
}

/// Per-endpoint cache/behavior hints.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSpec {
    /// Mount-relative path glob/prefix.
    pub path: String,
    /// Optional router cache TTL.
    #[serde(default)]
    pub cache_ttl_ms: Option<u64>,
    /// Whether this path is writable.
    #[serde(default)]
    pub write: bool,
    /// Whether writes dispatch off the NFS COMMIT path.
    #[serde(default, rename = "async")]
    pub async_dispatch: bool,
    /// Whether reads have externally visible side effects.
    #[serde(default, alias = "is_read_side_effecting")]
    pub read_side_effecting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalManifestError {
    #[error("missing local manifest custom section")]
    Missing,
    #[error("duplicate local manifest custom sections")]
    Duplicate,
    #[error("manifest payload is not utf-8: {0}")]
    Utf8(String),
    #[error("manifest TOML decode failed: {0}")]
    Toml(String),
    #[error("invalid local manifest: {0}")]
    Invalid(String),
    #[error("invalid wasm: {0}")]
    InvalidWasm(String),
}

/// Parse authored `petal.toml` bytes and validate the v1 local schema.
pub fn parse_local_manifest_toml(bytes: &[u8]) -> Result<LocalPetalManifest, LocalManifestError> {
    parse_local_manifest_toml_with_mounts(bytes, std::iter::empty::<&str>())
}

/// Parse authored `petal.toml` bytes and reject mounts already in use.
pub fn parse_local_manifest_toml_with_mounts<'a>(
    bytes: &[u8],
    occupied: impl IntoIterator<Item = &'a str>,
) -> Result<LocalPetalManifest, LocalManifestError> {
    let s = std::str::from_utf8(bytes).map_err(|e| LocalManifestError::Utf8(e.to_string()))?;
    let manifest: LocalPetalManifest =
        toml::from_str(s).map_err(|e| LocalManifestError::Toml(e.to_string()))?;
    validate_local_manifest_with_mounts(&manifest, occupied)?;
    Ok(manifest)
}

/// Validate a local manifest without considering already-installed mounts.
pub fn validate_local_manifest(m: &LocalPetalManifest) -> Result<(), LocalManifestError> {
    validate_local_manifest_with_mounts(m, std::iter::empty::<&str>())
}

/// Validate a local manifest and reject mount collisions against `occupied`.
pub fn validate_local_manifest_with_mounts<'a>(
    m: &LocalPetalManifest,
    occupied: impl IntoIterator<Item = &'a str>,
) -> Result<(), LocalManifestError> {
    if m.schema != LOCAL_SCHEMA {
        return invalid(format!(
            "unsupported schema {:?}; expected {LOCAL_SCHEMA:?}",
            m.schema
        ));
    }
    validate_name(&m.name)?;
    if m.provides.kind != "vfs" {
        return invalid(format!(
            "unsupported provides.kind {:?}; v1 supports only \"vfs\"",
            m.provides.kind
        ));
    }
    validate_mount(&m.provides.mount)?;
    if occupied.into_iter().any(|mount| mount == m.provides.mount) {
        return invalid(format!("mount {:?} is already installed", m.provides.mount));
    }

    let caps = validate_caps_unique(&m.provides.caps)?;
    let net_rules = m.net.as_ref().map(|n| n.allow.as_slice()).unwrap_or(&[]);
    if caps.contains(&LocalCapability::NetFetch) {
        if net_rules.is_empty() {
            return invalid("net.fetch requires at least one [[net.allow]] rule");
        }
    } else if m.net.is_some() {
        return invalid("[net] requires the net.fetch capability");
    }
    for rule in net_rules {
        validate_net_rule(rule)?;
    }
    for endpoint in &m.endpoint {
        validate_endpoint(endpoint)?;
    }
    Ok(())
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, LocalManifestError> {
    Err(LocalManifestError::Invalid(msg.into()))
}

fn validate_caps_unique(
    caps: &[LocalCapability],
) -> Result<BTreeSet<LocalCapability>, LocalManifestError> {
    let mut set = BTreeSet::new();
    for cap in caps {
        if !set.insert(*cap) {
            return invalid(format!("duplicate capability {cap}"));
        }
    }
    Ok(set)
}

fn validate_name(name: &str) -> Result<(), LocalManifestError> {
    if name.is_empty() {
        return invalid("name must not be empty");
    }
    if name.len() > 128 {
        return invalid("name is too long");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return invalid("name must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_mount(mount: &str) -> Result<(), LocalManifestError> {
    if mount.is_empty() {
        return invalid("mount must not be empty");
    }
    if mount == "." || mount == ".." {
        return invalid("mount must be a normal path segment");
    }
    if mount.contains('/') || mount.contains('\\') || mount.bytes().any(|b| b == 0) {
        return invalid("mount must be a single path segment");
    }
    if !mount
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return invalid("mount must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_net_rule(rule: &NetAllowRule) -> Result<(), LocalManifestError> {
    validate_hostname(&rule.host)?;
    let methods = rule.effective_methods();
    if methods.is_empty() {
        return invalid(format!("net.allow for {:?} has no methods", rule.host));
    }
    let mut seen = BTreeSet::new();
    for method in methods {
        if !seen.insert(method) {
            return invalid(format!(
                "duplicate HTTP method {} for host {:?}",
                method.as_str(),
                rule.host
            ));
        }
    }
    if let Some(paths) = &rule.paths {
        if paths.is_empty() {
            return invalid(format!("net.allow for {:?} has empty paths", rule.host));
        }
        for path in paths {
            validate_path_glob(path, "net.allow path")?;
        }
    }
    Ok(())
}

fn validate_hostname(host: &str) -> Result<(), LocalManifestError> {
    if host.is_empty() || host.len() > 253 {
        return invalid("net.allow host must be a non-empty hostname");
    }
    if host.contains('*') || host.contains(':') || host.contains('/') || host.contains('\\') {
        return invalid(format!(
            "net.allow host {:?} must be an exact hostname without wildcard, port, or path",
            host
        ));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return invalid(format!(
            "net.allow host {:?} must not be an IP literal",
            host
        ));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return invalid(format!("invalid hostname label in {:?}", host));
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return invalid(format!(
                "hostname label must not start or end with '-' in {:?}",
                host
            ));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return invalid(format!("invalid hostname character in {:?}", host));
        }
    }
    Ok(())
}

fn validate_endpoint(endpoint: &EndpointSpec) -> Result<(), LocalManifestError> {
    if endpoint.path.is_empty() {
        return invalid("endpoint path must not be empty");
    }
    if endpoint.path.starts_with('/') {
        return invalid(format!(
            "endpoint path {:?} must be relative to the petal mount",
            endpoint.path
        ));
    }
    validate_path_glob_inner(&endpoint.path, "endpoint path", false)
}

fn validate_path_glob(path: &str, what: &str) -> Result<(), LocalManifestError> {
    validate_path_glob_inner(path, what, true)
}

fn validate_path_glob_inner(
    path: &str,
    what: &str,
    require_leading_slash: bool,
) -> Result<(), LocalManifestError> {
    if path.is_empty() {
        return invalid(format!("{what} must not be empty"));
    }
    if require_leading_slash && !path.starts_with('/') {
        return invalid(format!("{what} {:?} must start with '/'", path));
    }
    if !require_leading_slash && path.starts_with('/') {
        return invalid(format!("{what} {:?} must be relative", path));
    }
    if path.contains("//") {
        return invalid(format!("{what} {:?} must not contain empty segments", path));
    }
    if path.contains('?') || path.contains('#') || path.contains('\\') || path.contains("://") {
        return invalid(format!(
            "{what} {:?} must be a path glob, not a URL, query, or fragment",
            path
        ));
    }
    for segment in path.trim_start_matches('/').split('/') {
        if segment == "." || segment == ".." {
            return invalid(format!("{what} {:?} must not contain dot segments", path));
        }
        if segment.is_empty() {
            return invalid(format!("{what} {:?} must not contain empty segments", path));
        }
        let star_count = segment.bytes().filter(|b| *b == b'*').count();
        if star_count > 0 && !(segment == "*" || (star_count == 1 && segment.ends_with('*'))) {
            return invalid(format!(
                "{what} {:?} may use '*' only as a full path segment or final segment suffix",
                path
            ));
        }
    }
    for b in path.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~' | b'*');
        if !ok {
            return invalid(format!(
                "{what} {:?} contains an unsupported path-glob byte",
                path
            ));
        }
    }
    Ok(())
}

/// Map a versioned local host import to the capability it requires.
///
/// Returns `Ok(None)` for imports outside Bloom's local host module.
pub fn local_capability_for_import(
    module: &str,
    name: &str,
) -> Result<Option<LocalCapability>, LocalManifestError> {
    if module != "bloom.v1" {
        if module == "bloom" || module.starts_with("bloom.") {
            return invalid(format!(
                "local handler petals may not import reserved host module {module:?}"
            ));
        }
        return Ok(None);
    }
    let cap = match name {
        "vfs_read" | "vfs_list" => LocalCapability::VfsRead,
        "vfs_write" => LocalCapability::VfsWrite,
        "http_fetch" => LocalCapability::NetFetch,
        "sign_hash" => LocalCapability::Sign,
        "store_get" | "store_put" | "store_put_new" | "store_list" | "store_del"
        | "store_del_if_value" => LocalCapability::Store,
        other => {
            return invalid(format!("unknown bloom.v1 host import {other:?}"));
        }
    };
    Ok(Some(cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> &'static str {
        r#"
schema = "bloom.petal.local.v1"
name = "polymarket"

[provides]
kind = "vfs"
mount = "polymarket"
caps = ["vfs.read", "vfs.write", "net.fetch", "sign", "store"]

[[net.allow]]
host = "clob.polymarket.com"
methods = ["GET", "POST"]
paths = ["/book", "/order", "/auth/*"]

[[endpoint]]
path = "onboard/*/begin"
write = true
async = true
"#
    }

    #[test]
    fn parses_and_validates_spec_example_shape() {
        let m = parse_local_manifest_toml(valid_toml().as_bytes()).unwrap();
        assert_eq!(m.schema, LOCAL_SCHEMA);
        assert_eq!(m.name, "polymarket");
        assert_eq!(m.mount(), "polymarket");
        assert!(m.cap_set().contains(&LocalCapability::NetFetch));
        assert_eq!(
            m.net.as_ref().unwrap().allow[0].effective_methods().len(),
            2
        );
        assert!(m.endpoint[0].async_dispatch);
    }

    #[test]
    fn net_fetch_requires_rules_and_rules_require_cap() {
        let no_rules = r#"
schema = "bloom.petal.local.v1"
name = "netty"
[provides]
kind = "vfs"
mount = "netty"
caps = ["net.fetch"]
"#;
        assert!(parse_local_manifest_toml(no_rules.as_bytes()).is_err());

        let no_cap = r#"
schema = "bloom.petal.local.v1"
name = "netty"
[provides]
kind = "vfs"
mount = "netty"
caps = []
[[net.allow]]
host = "example.com"
"#;
        assert!(parse_local_manifest_toml(no_cap.as_bytes()).is_err());
    }

    #[test]
    fn atomic_store_imports_use_store_capability() {
        assert_eq!(
            local_capability_for_import("bloom.v1", "store_put_new").unwrap(),
            Some(LocalCapability::Store)
        );
        assert_eq!(
            local_capability_for_import("bloom.v1", "store_del_if_value").unwrap(),
            Some(LocalCapability::Store)
        );
    }

    #[test]
    fn rejects_mount_escape_and_collisions() {
        let mut m = parse_local_manifest_toml(valid_toml().as_bytes()).unwrap();
        m.provides.mount = "../wallets".into();
        assert!(validate_local_manifest(&m).is_err());

        m.provides.mount = "polymarket".into();
        assert!(validate_local_manifest_with_mounts(&m, ["polymarket"]).is_err());
    }

    #[test]
    fn rejects_wildcard_or_ip_hosts() {
        let mut m = parse_local_manifest_toml(valid_toml().as_bytes()).unwrap();
        m.net.as_mut().unwrap().allow[0].host = "*.example.com".into();
        assert!(validate_local_manifest(&m).is_err());

        m.net.as_mut().unwrap().allow[0].host = "127.0.0.1".into();
        assert!(validate_local_manifest(&m).is_err());
    }

    #[test]
    fn omitted_net_methods_default_to_get() {
        let rule = NetAllowRule {
            host: "example.com".into(),
            methods: None,
            paths: None,
        };
        assert_eq!(rule.effective_methods(), vec![HttpMethod::Get]);
        validate_net_rule(&rule).unwrap();
    }

    #[test]
    fn rejects_unknown_toml_fields() {
        let typo = r#"
schema = "bloom.petal.local.v1"
name = "echo"
unexpected = true
[provides]
kind = "vfs"
mount = "echo"
caps = []
"#;
        assert!(matches!(
            parse_local_manifest_toml(typo.as_bytes()),
            Err(LocalManifestError::Toml(_))
        ));
    }

    #[test]
    fn rejects_empty_net_section_without_net_fetch() {
        let empty_net = r#"
schema = "bloom.petal.local.v1"
name = "echo"
[provides]
kind = "vfs"
mount = "echo"
caps = []
[net]
"#;
        assert!(parse_local_manifest_toml(empty_net.as_bytes()).is_err());
    }

    #[test]
    fn rejects_path_escape_query_fragment_and_bad_globs() {
        let mut m = parse_local_manifest_toml(valid_toml().as_bytes()).unwrap();
        let bad_net_paths = [
            "/../wallets/*",
            "/foo?admin=1",
            "/foo#frag",
            "//host/path",
            "/a*b*",
        ];
        for bad in bad_net_paths {
            m.net.as_mut().unwrap().allow[0].paths = Some(vec![bad.into()]);
            assert!(
                validate_local_manifest(&m).is_err(),
                "expected bad net path {bad:?} to fail"
            );
        }

        m = parse_local_manifest_toml(valid_toml().as_bytes()).unwrap();
        m.endpoint[0].path = "../wallets/*".into();
        assert!(validate_local_manifest(&m).is_err());
    }

    #[test]
    fn maps_versioned_imports_to_required_caps() {
        assert_eq!(
            local_capability_for_import("bloom.v1", "http_fetch").unwrap(),
            Some(LocalCapability::NetFetch)
        );
        assert_eq!(
            local_capability_for_import("bloom.v1", "vfs_list").unwrap(),
            Some(LocalCapability::VfsRead)
        );
        assert_eq!(
            local_capability_for_import("wasi_snapshot_preview1", "fd_write").unwrap(),
            None
        );
        assert!(local_capability_for_import("bloom.v1", "socket").is_err());
        assert!(local_capability_for_import("bloom", "vfs_read").is_err());
        assert!(local_capability_for_import("bloom.v2", "http_fetch").is_err());
        assert!(local_capability_for_import("bloom.local", "sign_hash").is_err());
    }
}
