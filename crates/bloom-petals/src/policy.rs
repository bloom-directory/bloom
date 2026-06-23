//! Runtime network policy for v2 local app petals.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::error::PetalError;
use crate::host::HostError;

/// Effective network allowlist for a single petal invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetPolicy {
    rules: Vec<NetRule>,
}

impl NetPolicy {
    /// Default-deny policy.
    pub fn deny_all() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn from_v2_manifest_toml(bytes: &[u8]) -> Result<Self, PetalError> {
        let manifest_toml = std::str::from_utf8(bytes)
            .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
        let manifest: V2PolicyManifest = toml::from_str(manifest_toml)?;
        let rules = manifest
            .net
            .map(|net| {
                net.allow
                    .into_iter()
                    .map(|rule| NetRule {
                        host: rule.host.to_ascii_lowercase(),
                        methods: rule
                            .methods
                            .into_iter()
                            .map(|method| method.to_ascii_uppercase())
                            .collect(),
                        paths: rule.paths.unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self { rules })
    }

    /// Intersect this policy with a runtime mask. Masks can only narrow.
    pub fn intersect(&self, mask: &NetPolicy) -> Self {
        let mut rules = Vec::new();
        for declared in &self.rules {
            for runtime in &mask.rules {
                if declared.host != runtime.host {
                    continue;
                }
                let methods: BTreeSet<String> = declared
                    .methods
                    .intersection(&runtime.methods)
                    .cloned()
                    .collect();
                if methods.is_empty() {
                    continue;
                }
                let paths = intersect_paths(&declared.paths, &runtime.paths);
                if paths.is_empty() && (!declared.paths.is_empty() || !runtime.paths.is_empty()) {
                    continue;
                }
                rules.push(NetRule {
                    host: declared.host.clone(),
                    methods,
                    paths,
                });
            }
        }
        Self { rules }
    }

    /// Enforce HTTPS, exact host, method, and path allowlist.
    pub fn check(&self, method: &str, url: &str) -> Result<(), HostError> {
        let url = url::Url::parse(url).map_err(|e| HostError::Invalid(format!("url: {e}")))?;
        if url.scheme() != "https" {
            return Err(HostError::Denied("net.fetch requires https".into()));
        }
        if let Some(port) = url.port()
            && port != 443
        {
            return Err(HostError::Denied(format!(
                "net.fetch disallows non-default https port {port}"
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| HostError::Invalid("url missing host".into()))?
            .to_ascii_lowercase();
        let method = method.to_ascii_uppercase();
        let path = url.path();
        for rule in &self.rules {
            if rule.host == host && rule.methods.contains(&method) && rule.path_allowed(path) {
                return Ok(());
            }
        }
        Err(HostError::Denied(format!("{method} {host}{path}")))
    }
}

/// Effective private-store namespace policy for a single petal invocation.
///
/// `None` at the VM `RunOptions` level preserves legacy/direct VM behavior.
/// When present for v2 apps, a route may only touch declared namespaces and
/// secret writes must match the namespace's declared visibility.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreNamespacePolicy {
    private: BTreeSet<String>,
    secret: BTreeSet<String>,
}

impl StoreNamespacePolicy {
    pub fn from_namespaces(
        private: impl IntoIterator<Item = String>,
        secret: impl IntoIterator<Item = String>,
    ) -> Self {
        let secret = secret.into_iter().collect::<BTreeSet<_>>();
        let mut private = private.into_iter().collect::<BTreeSet<_>>();
        private.extend(secret.iter().cloned());
        Self { private, secret }
    }

    pub fn namespaces(&self) -> &BTreeSet<String> {
        &self.private
    }

    pub fn secret_namespaces(&self) -> &BTreeSet<String> {
        &self.secret
    }

    pub fn is_empty(&self) -> bool {
        self.private.is_empty()
    }

    /// Intersect a manifest policy with a runtime mask. Namespaces must be
    /// present in both policies; secret classification is preserved if either
    /// side marks the namespace secret so a mask cannot downgrade secret writes.
    pub fn intersect(&self, mask: &StoreNamespacePolicy) -> Self {
        let private = self
            .private
            .intersection(&mask.private)
            .cloned()
            .collect::<BTreeSet<_>>();
        let secret_union = self
            .secret
            .union(&mask.secret)
            .cloned()
            .collect::<BTreeSet<_>>();
        let secret = private
            .intersection(&secret_union)
            .cloned()
            .collect::<BTreeSet<_>>();
        Self { private, secret }
    }

    pub fn check_namespace(&self, namespace: &str) -> Result<(), HostError> {
        if self.private.contains(namespace) {
            Ok(())
        } else {
            Err(HostError::Denied(format!(
                "store namespace {namespace:?} is not allowed"
            )))
        }
    }

    pub fn check_put(&self, namespace: &str, secret: bool) -> Result<(), HostError> {
        self.check_namespace(namespace)?;
        let declared_secret = self.secret.contains(namespace);
        match (declared_secret, secret) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(HostError::Denied(format!(
                "store namespace {namespace:?} requires secret writes"
            ))),
            (false, true) => Err(HostError::Denied(format!(
                "store namespace {namespace:?} is not declared secret"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetRule {
    host: String,
    methods: BTreeSet<String>,
    /// Empty means any path.
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct V2PolicyManifest {
    net: Option<V2NetPolicy>,
}

#[derive(Debug, Deserialize)]
struct V2NetPolicy {
    #[serde(default)]
    allow: Vec<V2NetRule>,
}

#[derive(Debug, Deserialize)]
struct V2NetRule {
    host: String,
    #[serde(default)]
    methods: Vec<String>,
    paths: Option<Vec<String>>,
}

impl NetRule {
    fn path_allowed(&self, path: &str) -> bool {
        self.paths.is_empty() || self.paths.iter().any(|glob| glob_matches(glob, path))
    }
}

fn intersect_paths(a: &[String], b: &[String]) -> Vec<String> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let mut out = Vec::new();
    for left in a {
        for right in b {
            if left == right {
                out.push(left.clone());
            } else if glob_subsumes(left, right) {
                out.push(right.clone());
            } else if glob_subsumes(right, left) {
                out.push(left.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn glob_subsumes(parent: &str, child: &str) -> bool {
    parent == child
        || parent == "/*"
        || parent
            .strip_suffix('*')
            .map(|prefix| child.starts_with(prefix))
            .unwrap_or(false)
}

fn glob_matches(glob: &str, path: &str) -> bool {
    if glob == "/*" {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    let glob_segments: Vec<&str> = glob.trim_start_matches('/').split('/').collect();
    let path_segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if glob_segments.len() != path_segments.len() {
        return false;
    }
    for (idx, glob_segment) in glob_segments.iter().enumerate() {
        let Some(path_segment) = path_segments.get(idx) else {
            return false;
        };
        if *glob_segment == "*" {
            continue;
        }
        if glob_segment != path_segment {
            return false;
        }
    }
    glob_segments.len() == path_segments.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_toml() -> &'static [u8] {
        br#"
schema = "bloom.petal.local-app.v2"
name = "netty"

[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["GET", "POST"]
paths = ["/markets*", "/auth/*", "/wallets/*/orders"]
"#
    }

    #[test]
    fn policy_enforces_https_host_method_and_path() {
        let policy = NetPolicy::from_v2_manifest_toml(manifest_toml()).expect("valid manifest");
        assert!(
            policy
                .check("GET", "https://api.example.com/markets")
                .is_ok()
        );
        assert!(
            policy
                .check("GET", "https://api.example.com:443/markets")
                .is_ok()
        );
        assert!(
            policy
                .check("GET", "https://api.example.com:8443/markets")
                .is_err()
        );
        assert!(
            policy
                .check("GET", "https://api.example.com/markets/1")
                .is_ok()
        );
        assert!(
            policy
                .check("POST", "https://api.example.com/auth/key")
                .is_ok()
        );
        assert!(
            policy
                .check("GET", "https://api.example.com/wallets/alice/orders")
                .is_ok()
        );
        assert!(
            policy
                .check("DELETE", "https://api.example.com/markets")
                .is_err()
        );
        assert!(
            policy
                .check("GET", "http://api.example.com/markets")
                .is_err()
        );
        assert!(
            policy
                .check("GET", "https://evil.example.com/markets")
                .is_err()
        );
    }

    #[test]
    fn runtime_mask_only_narrows() {
        let declared = NetPolicy::from_v2_manifest_toml(manifest_toml()).expect("valid manifest");
        let mask = NetPolicy {
            rules: vec![NetRule {
                host: "api.example.com".into(),
                methods: BTreeSet::from(["GET".to_string()]),
                paths: vec!["/markets*".into()],
            }],
        };
        let narrowed = declared.intersect(&mask);
        assert!(
            narrowed
                .check("GET", "https://api.example.com/markets")
                .is_ok()
        );
        assert!(
            narrowed
                .check("POST", "https://api.example.com/markets")
                .is_err()
        );
        assert!(
            narrowed
                .check("GET", "https://api.example.com/auth/key")
                .is_err()
        );
    }

    #[test]
    fn store_namespace_runtime_mask_only_narrows_and_preserves_secret_visibility() {
        let declared = StoreNamespacePolicy::from_namespaces(
            ["orders".to_string(), "funding".to_string()],
            ["credentials".to_string()],
        );
        let mask = StoreNamespacePolicy::from_namespaces(
            [
                "orders".to_string(),
                "credentials".to_string(),
                "sessions".to_string(),
            ],
            Vec::new(),
        );

        let narrowed = declared.intersect(&mask);
        assert!(narrowed.check_namespace("orders").is_ok());
        assert!(narrowed.check_namespace("credentials").is_ok());
        assert!(narrowed.check_namespace("funding").is_err());
        assert!(narrowed.check_namespace("sessions").is_err());
        assert!(narrowed.check_put("orders", false).is_ok());
        assert!(narrowed.check_put("orders", true).is_err());
        assert!(narrowed.check_put("credentials", true).is_ok());
        assert!(narrowed.check_put("credentials", false).is_err());
    }

    #[test]
    fn v2_manifest_policy_enforces_https_host_method_and_path() {
        let policy = NetPolicy::from_v2_manifest_toml(
            br#"
schema = "bloom.petal.local-app.v2"
name = "echo"

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/markets*"]
"#,
        )
        .unwrap();

        assert!(
            policy
                .check("GET", "https://api.example.com/markets/1")
                .is_ok()
        );
        assert!(
            policy
                .check("POST", "https://api.example.com/markets/1")
                .is_err()
        );
        assert!(policy.check("GET", "https://evil.example.com/").is_err());
    }
}
