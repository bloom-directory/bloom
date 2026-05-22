//! Endpoint resolver — `path -> (petal_hash, fn, signature)`.
//!
//! This is **not** a new source of truth: it consumes the existing
//! [`ChainStateIface::resolve_path`] (`path -> Hash32`) and
//! [`ChainStateIface::load_manifest`] (`Hash32 -> PetalManifestStub`)
//! hooks and combines them. An endpoint path is the petal's signed
//! manifest `module_path` plus a trailing `/function` segment:
//!
//! ```text
//! /bloom/dex/pool/swap_exact_in
//! └────────────┬───┘ └─────┬────┘
//!     petal path        function
//! ```
//!
//! Resolution splits at the **last** `/`, resolves the petal-path prefix
//! to a hash via `resolve_path`, loads its manifest, and looks the
//! function up by name. Any miss (unknown path, missing manifest,
//! unknown function) is a typed [`ResolveError`] — the resolver fails
//! closed.

use bloom_chain_types::Hash32;
use bloom_script::{ChainStateIface, FunctionDeclStub, PetalManifestStub};

use crate::error::ResolveError;

/// A fully-resolved endpoint: the petal it lives in (path + pinned
/// hash), the function name, and the manifest needed to typecheck a
/// call to it.
///
/// The `manifest` is cloned out of the chain so callers can hold the
/// resolved signature without re-borrowing the chain on every
/// validation step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// The petal path (endpoint path minus the function suffix). Equals
    /// the manifest's `module_path`.
    pub petal_path: String,
    /// Content hash the petal path is bound to.
    pub petal_hash: Hash32,
    /// Function name within the petal.
    pub function: String,
    /// The petal's manifest projection (carries the function signatures).
    pub manifest: PetalManifestStub,
}

impl ResolvedEndpoint {
    /// The resolved function's declaration (the "abi" — arg kinds,
    /// type-params, returns). Always present: resolution verified it.
    pub fn signature(&self) -> &FunctionDeclStub {
        self.manifest
            .function(&self.function)
            .expect("function presence guaranteed at resolve time")
    }
}

/// Split an endpoint path into `(petal_path, function)` at the last `/`.
///
/// Returns `MalformedPath` if there is no separating `/` with non-empty
/// halves (e.g. `"swap"`, `"/swap"` with empty petal path, or `""`).
pub fn split_endpoint_path(path: &str) -> Result<(&str, &str), ResolveError> {
    let trimmed = path.trim();
    let Some(idx) = trimmed.rfind('/') else {
        return Err(ResolveError::MalformedPath {
            path: path.to_string(),
        });
    };
    let petal_path = &trimmed[..idx];
    let function = &trimmed[idx + 1..];
    if petal_path.is_empty() || function.is_empty() {
        return Err(ResolveError::MalformedPath {
            path: path.to_string(),
        });
    }
    Ok((petal_path, function))
}

/// Resolve an endpoint path against a chain interface.
///
/// `path -> (petal_hash, fn, abi)`, derived purely from the existing
/// `resolve_path` + `load_manifest` hooks. Fails closed on any miss.
pub fn resolve_endpoint(
    chain: &dyn ChainStateIface,
    path: &str,
) -> Result<ResolvedEndpoint, ResolveError> {
    let (petal_path, function) = split_endpoint_path(path)?;

    let petal_hash = chain
        .resolve_path(petal_path)
        .ok_or_else(|| ResolveError::UnknownPath {
            petal_path: petal_path.to_string(),
        })?;

    let manifest =
        chain
            .load_manifest(&petal_hash)
            .ok_or_else(|| ResolveError::ManifestNotFound {
                petal_path: petal_path.to_string(),
                hash: petal_hash,
            })?;

    if manifest.function(function).is_none() {
        return Err(ResolveError::UnknownFunction {
            petal_path: petal_path.to_string(),
            function: function.to_string(),
            hash: petal_hash,
        });
    }

    Ok(ResolvedEndpoint {
        petal_path: petal_path.to_string(),
        petal_hash,
        function: function.to_string(),
        manifest,
    })
}
