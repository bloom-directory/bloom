//! Experimental v2 file-driven local app package scanner.
//!
//! This is intentionally small: it proves that `app/<name>/.../*.wasm`
//! can define routes, be matched deterministically, and dispatch through the
//! existing `petal_dispatch` compatibility ABI. It does not implement the v2
//! persistent package store, archive install, or component runner.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::PetalError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalAppPackage {
    pub name: String,
    pub app_root: String,
    pub routes: Vec<RouteRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub route_id: String,
    pub pattern: String,
    pub source_path: PathBuf,
    pub params: Vec<String>,
    pub specificity: RouteSpecificity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpecificity {
    pub segment_count: usize,
    pub static_segment_count: usize,
    pub file_score: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    pub route: &'a RouteRecord,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Deserialize)]
struct PetalToml {
    name: String,
}

impl PetalAppPackage {
    pub fn scan_dir(root: impl AsRef<Path>) -> Result<Self, PetalError> {
        let root = root.as_ref();
        require_file(root.join("petal.toml"))?;
        require_file(root.join("README.md"))?;
        require_file(root.join("AGENTS.md"))?;

        let petal_toml = std::fs::read_to_string(root.join("petal.toml"))?;
        let manifest: PetalToml = toml::from_str(&petal_toml)?;
        validate_app_name(&manifest.name)?;

        let app_root = root.join("app").join(&manifest.name);
        if !app_root.is_dir() {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package missing app/{}/ route root",
                manifest.name
            )));
        }

        let mut routes = Vec::new();
        scan_routes(&app_root, &app_root, &mut routes)?;
        routes.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        for (idx, route) in routes.iter_mut().enumerate() {
            route.route_id = format!("r{idx:06}");
        }
        validate_route_conflicts(&routes)?;

        Ok(Self {
            name: manifest.name.clone(),
            app_root: manifest.name,
            routes,
        })
    }

    pub fn match_route(&self, path: &str) -> Option<RouteMatch<'_>> {
        let path = normalize_request_path(path)?;
        let mut best: Option<RouteMatch<'_>> = None;
        for route in &self.routes {
            let Some(params) = match_pattern(&route.pattern, path) else {
                continue;
            };
            let candidate = RouteMatch { route, params };
            if best
                .as_ref()
                .map(|best| route.specificity > best.route.specificity)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
        best
    }
}

fn require_file(path: PathBuf) -> Result<(), PetalError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "v2 package missing required file {}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>")
        )))
    }
}

fn validate_app_name(name: &str) -> Result<(), PetalError> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.bytes().any(|b| b == 0)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "invalid v2 app name {name:?}"
        )))
    }
}

fn scan_routes(
    app_root: &Path,
    dir: &Path,
    routes: &mut Vec<RouteRecord>,
) -> Result<(), PetalError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            scan_routes(app_root, &path, routes)?;
        } else if ty.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".wasm"))
                .unwrap_or(false)
        {
            let pattern = route_pattern(app_root, &path)?;
            routes.push(RouteRecord {
                route_id: String::new(),
                params: route_params(&pattern)?,
                specificity: specificity(&pattern),
                pattern,
                source_path: path,
            });
        }
    }
    Ok(())
}

fn route_pattern(app_root: &Path, wasm_path: &Path) -> Result<String, PetalError> {
    let rel = wasm_path
        .strip_prefix(app_root)
        .map_err(|_| PetalError::InvalidWasm("route escaped app root".into()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        let std::path::Component::Normal(seg) = component else {
            return Err(PetalError::InvalidWasm(
                "route path contains non-normal segment".into(),
            ));
        };
        let seg = seg
            .to_str()
            .ok_or_else(|| PetalError::InvalidWasm("route path is not utf-8".into()))?;
        if seg.contains('\\') || seg.bytes().any(|b| b == 0) {
            return Err(PetalError::InvalidWasm(format!(
                "route path contains invalid segment {seg:?}"
            )));
        }
        parts.push(seg.to_string());
    }
    let Some(last) = parts.last_mut() else {
        return Err(PetalError::InvalidWasm("empty route path".into()));
    };
    *last = last
        .strip_suffix(".wasm")
        .ok_or_else(|| PetalError::InvalidWasm("route leaf is not .wasm".into()))?
        .to_string();
    Ok(parts.join("/"))
}

fn route_params(pattern: &str) -> Result<Vec<String>, PetalError> {
    let mut params = Vec::new();
    for segment in pattern.split('/') {
        if let Some((param, _suffix)) = dynamic_segment(segment)? {
            if params.iter().any(|existing| existing == param) {
                return Err(PetalError::InvalidWasm(format!(
                    "duplicate route param {param:?} in {pattern:?}"
                )));
            }
            params.push(param.to_string());
        }
    }
    Ok(params)
}

fn specificity(pattern: &str) -> RouteSpecificity {
    let segments = pattern.split('/').collect::<Vec<_>>();
    RouteSpecificity {
        segment_count: segments.len(),
        static_segment_count: segments
            .iter()
            .filter(|segment| !segment.starts_with('['))
            .count(),
        file_score: usize::from(!pattern.ends_with('/')),
    }
}

fn validate_route_conflicts(routes: &[RouteRecord]) -> Result<(), PetalError> {
    for (idx, a) in routes.iter().enumerate() {
        for b in routes.iter().skip(idx + 1) {
            if a.specificity == b.specificity && patterns_overlap(&a.pattern, &b.pattern)? {
                return Err(PetalError::InvalidWasm(format!(
                    "conflicting v2 routes {:?} and {:?}",
                    a.pattern, b.pattern
                )));
            }
        }
    }
    Ok(())
}

fn normalize_request_path(path: &str) -> Option<&str> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b == 0)
        || path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    Some(path)
}

fn match_pattern(pattern: &str, path: &str) -> Option<Vec<(String, String)>> {
    let pattern_segments = pattern.split('/').collect::<Vec<_>>();
    let path_segments = path.split('/').collect::<Vec<_>>();
    if pattern_segments.len() != path_segments.len() {
        return None;
    }
    let mut params = Vec::new();
    for (pattern, value) in pattern_segments.iter().zip(path_segments) {
        match dynamic_segment(pattern).ok()? {
            Some((param, suffix)) => {
                let bound = value.strip_suffix(suffix)?;
                if bound.is_empty() {
                    return None;
                }
                params.push((param.to_string(), bound.to_string()));
            }
            None if *pattern == value => {}
            None => return None,
        }
    }
    Some(params)
}

fn patterns_overlap(a: &str, b: &str) -> Result<bool, PetalError> {
    let a = a.split('/').collect::<Vec<_>>();
    let b = b.split('/').collect::<Vec<_>>();
    if a.len() != b.len() {
        return Ok(false);
    }
    for (a, b) in a.into_iter().zip(b) {
        if !segments_overlap(a, b)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn segments_overlap(a: &str, b: &str) -> Result<bool, PetalError> {
    match (dynamic_segment(a)?, dynamic_segment(b)?) {
        (None, None) => Ok(a == b),
        (Some((_param, suffix)), None) => Ok(b.ends_with(suffix)),
        (None, Some((_param, suffix))) => Ok(a.ends_with(suffix)),
        (Some((_a_param, a_suffix)), Some((_b_param, b_suffix))) => Ok(a_suffix == b_suffix
            || a_suffix.ends_with(b_suffix)
            || b_suffix.ends_with(a_suffix)),
    }
}

fn dynamic_segment(segment: &str) -> Result<Option<(&str, &str)>, PetalError> {
    if !segment.starts_with('[') {
        return Ok(None);
    }
    let Some(end) = segment.find(']') else {
        return Err(PetalError::InvalidWasm(format!(
            "dynamic route segment missing ]: {segment:?}"
        )));
    };
    let param = &segment[1..end];
    if param.is_empty()
        || !param
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "invalid route param in segment {segment:?}"
        )));
    }
    Ok(Some((param, &segment[end + 1..])))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crate::abi::{DispatchOp, DispatchRequest, DispatchResponse};
    use crate::host::DenyHost;
    use crate::vm::{PetalVm, RunOptions};

    use super::*;

    #[test]
    fn v2_scanner_matches_static_and_dynamic_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/hello.txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", b"\0asm");

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        assert_eq!(package.name, "echo");
        assert_eq!(package.routes.len(), 2);

        let static_match = package.match_route("hello.txt").unwrap();
        assert_eq!(static_match.route.pattern, "hello.txt");
        assert!(static_match.params.is_empty());

        let dynamic_match = package.match_route("alice.txt").unwrap();
        assert_eq!(dynamic_match.route.pattern, "[name].txt");
        assert_eq!(dynamic_match.params, vec![("name".into(), "alice".into())]);
        assert!(package.match_route("../alice.txt").is_none());
    }

    #[test]
    fn v2_scanner_rejects_equal_specificity_dynamic_conflicts() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "app/echo/[wallet].txt.wasm", b"\0asm");

        let err = PetalAppPackage::scan_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("conflicting v2 routes"));
    }

    #[tokio::test]
    async fn v2_route_dispatches_through_compat_petal_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let wasm = wat::parse_str(compat_read_wat("hello v2")).unwrap();
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", &wasm);

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        let matched = package.match_route("alice.txt").unwrap();
        assert_eq!(matched.params, vec![("name".into(), "alice".into())]);

        let route_wasm = std::fs::read(&matched.route.source_path).unwrap();
        let output = PetalVm::new()
            .unwrap()
            .dispatch(
                &route_wasm,
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "alice.txt".into(),
                    body: Vec::new(),
                    ctx: matched.params,
                },
                BTreeSet::new(),
                Arc::new(DenyHost),
                "v2-test-package",
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            output.response,
            DispatchResponse::Read(b"hello v2".to_vec())
        );
    }

    fn write_package_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn compat_read_wat(body: &str) -> String {
        let body = body.as_bytes();
        let mut response = vec![2];
        response.extend_from_slice(&(body.len() as u32).to_le_bytes());
        response.extend_from_slice(body);
        let escaped = response
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>();
        format!(
            r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 0) "{escaped}")
              (func (export "petal_alloc") (param i32) (result i32)
                (i32.const 1024))
              (func (export "petal_dispatch") (param i32 i32) (result i64)
                (i64.const {packed})))
            "#,
            packed = response.len()
        )
    }
}
