//! Token emission helpers shared by every macro module.
//!
//! These helpers produce `proc_macro2::TokenStream` fragments that:
//!
//! - Marshal `PetalManifestV0` instances into rust constants whose
//!   canonical-encoded bytes get embedded as the
//!   `bloom_petal_manifest_v0` wasm custom section (spec §8.1, §11.1).
//! - Emit `__petal_<fn>` wasm exports with the spec §11.1 signature.
//! - Emit `__inv_<idx>` wasm exports for invariants (spec §12.1).
//! - Re-emit user `pub fn`s with their original bodies preserved.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;

use crate::manifest::{FunctionDecl, PetalManifestV0};
use crate::manifest_codec;

// ---------------------------------------------------------------------------
// Manifest blob embedding
// ---------------------------------------------------------------------------

/// Generate the `#[link_section]` bytes constant that embeds the
/// canonical-encoded manifest into the wasm output as the
/// `bloom_petal_manifest_v0` custom section.
///
/// The macro emits the bytes as a `static [u8; N]` with a target-gated
/// `#[link_section]` attribute that only fires on wasm targets.
pub(crate) fn emit_manifest_section(
    manifest: &PetalManifestV0,
    section_unique_ident: &Ident,
) -> syn::Result<TokenStream> {
    let bytes = manifest_codec::encode(manifest).map_err(|e| {
        syn::Error::new(
            Span::call_site(),
            format!("internal: failed to encode manifest: {}", e),
        )
    })?;

    let len = bytes.len();
    let byte_lits: Vec<TokenStream> = bytes.iter().map(|b| quote! { #b }).collect();

    // The `link_section` attribute embeds the constant into the wasm
    // output as a custom section. On non-wasm targets we still emit the
    // static so host-side unit tests can inspect it; we omit the
    // `link_section` so non-wasm linkers don't try to interpret it.
    Ok(quote! {
        /// Canonical-encoded `PetalManifestV0` blob. Embedded into the
        /// wasm output as the `bloom_petal_manifest_v0` custom section
        /// (spec §8.1). Auto-generated; do not edit.
        #[cfg(target_arch = "wasm32")]
        #[unsafe(link_section = "bloom_petal_manifest_v0")]
        #[used]
        pub static #section_unique_ident: [u8; #len] = [#(#byte_lits),*];

        /// Host-side mirror of the wasm custom section. Identical bytes
        /// to the wasm-side static; surfaced so off-wasm tests and
        /// tooling can read the manifest without a wasm engine.
        #[cfg(not(target_arch = "wasm32"))]
        pub static #section_unique_ident: [u8; #len] = [#(#byte_lits),*];
    })
}

// ---------------------------------------------------------------------------
// `__petal_<fn>` wasm export shim
// ---------------------------------------------------------------------------

/// Build the `__petal_<fn_name>` wasm export that decodes args via
/// `ArgReader`, dispatches to the user function, and writes returns via
/// `RetWriter` (spec §11.1).
///
/// The shim is currently a stub: it returns `PetalError::Unsupported`
/// at runtime. Per-arg / per-return marshaling will land alongside the
/// `bloom-resource` runtime contract once `BloomType` is finalised
/// (spec §11.2 paragraph about monomorphization-at-PTB-time). The
/// shim's *signature* and *export name* are already on-spec so that the
/// chain VM can introspect the wasm without further changes.
pub(crate) fn emit_petal_shim(fn_decl: &FunctionDecl) -> TokenStream {
    let export_name = format!("__petal_{}", fn_decl.name);
    let shim_ident = Ident::new(
        &format!("__bloom_petal_{}", fn_decl.name),
        Span::call_site(),
    );

    quote! {
        /// Auto-generated wasm export shim for `#[bloom::petal]` fn
        /// (spec §11.1). Returns `PetalError::Unsupported` until the
        /// per-arg/per-return marshaling lands.
        ///
        /// Gated on `not(feature = "no-entrypoint")` so that downstream
        /// crates depending on this petal as a library can suppress the
        /// wasm export symbols and avoid duplicate-export link errors.
        #[cfg(all(target_arch = "wasm32", not(feature = "no-entrypoint")))]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #shim_ident(
            _args_ptr: i32,
            _args_len: i32,
            _ret_ptr: i32,
            _ret_cap: i32,
        ) -> i32 {
            // PetalError::Unsupported -> i32 (sentinel = 9 in spec §16.3)
            9
        }

        /// Host-side mirror of the wasm export shim. Always returns the
        /// `Unsupported` sentinel; used so host-side unit tests can
        /// reference the shim symbol without `extern "C"`.
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code)]
        pub fn #shim_ident(
            _args_ptr: i32,
            _args_len: i32,
            _ret_ptr: i32,
            _ret_cap: i32,
        ) -> i32 {
            9
        }
    }
}

// ---------------------------------------------------------------------------
// `__inv_<idx>` wasm export shim
// ---------------------------------------------------------------------------

/// Build the `__inv_<idx>` wasm export that runs the invariant predicate
/// against an encoded scope buffer (spec §12.2).
///
/// Like [`emit_petal_shim`], the body is currently a `return 1` stub
/// (predicate always satisfied). The shim signature matches the spec
/// so the chain can call it.
pub(crate) fn emit_invariant_shim(idx: u16) -> TokenStream {
    let export_name = format!("__inv_{}", idx);
    let shim_ident = Ident::new(
        &format!("__bloom_inv_{}", idx),
        Span::call_site(),
    );

    quote! {
        /// Auto-generated wasm export shim for `#[invariant]` (spec
        /// §12.1). Returns `1` (satisfied) as a stub until the
        /// predicate-AST → wasm-body lowering lands.
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #shim_ident(_scope_ptr: i32, _scope_len: i32) -> i32 {
            1
        }

        /// Host-side mirror of the invariant shim.
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code)]
        pub fn #shim_ident(_scope_ptr: i32, _scope_len: i32) -> i32 {
            1
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime manifest accessor
// ---------------------------------------------------------------------------

/// Emit a `pub fn __manifest_bytes() -> &'static [u8]` that exposes the
/// embedded manifest blob to host-side tooling. Useful for unit tests
/// and for tools that pre-flight a wasm before publishing.
pub(crate) fn emit_manifest_accessor(section_ident: &Ident) -> TokenStream {
    quote! {
        /// Returns the canonical-encoded `PetalManifestV0` bytes
        /// embedded into this petal at compile time.
        pub fn __bloom_manifest_bytes() -> &'static [u8] {
            &#section_ident[..]
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;

    fn empty_manifest() -> PetalManifestV0 {
        PetalManifestV0 {
            schema_version: SCHEMA_VERSION,
            module_path: "/p".to_string(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        }
    }

    #[test]
    fn manifest_section_includes_link_section_on_wasm() {
        let m = empty_manifest();
        let id = Ident::new("__BLOOM_M", Span::call_site());
        let toks = emit_manifest_section(&m, &id).unwrap();
        let s = toks.to_string();
        assert!(s.contains("link_section"));
        assert!(s.contains("bloom_petal_manifest_v0"));
        assert!(s.contains("__BLOOM_M"));
    }

    #[test]
    fn petal_shim_uses_proper_export_name() {
        let f = FunctionDecl {
            name: "swap".to_string(),
            ..Default::default()
        };
        let s = emit_petal_shim(&f).to_string();
        assert!(s.contains("__petal_swap"));
        assert!(s.contains("extern \"C\""));
        assert!(s.contains("_args_ptr"));
    }

    #[test]
    fn invariant_shim_uses_proper_export_name() {
        let s = emit_invariant_shim(7).to_string();
        assert!(s.contains("__inv_7"));
        assert!(s.contains("_scope_ptr"));
    }

    #[test]
    fn manifest_accessor_references_static() {
        let id = Ident::new("__BLOOM_M", Span::call_site());
        let s = emit_manifest_accessor(&id).to_string();
        assert!(s.contains("__bloom_manifest_bytes"));
        assert!(s.contains("__BLOOM_M"));
    }
}
