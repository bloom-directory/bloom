//! `#[bloom::petal]` module attribute (spec §11.1).
//!
//! ```ignore
//! #[bloom::petal(path = "/bloom/dex/pool", version = "0.1.0")]
//! pub mod pool {
//!     use bloom_resource::{Coin, UID};
//!
//!     #[object(abilities = "key, store", phantom = "A, B")]
//!     pub struct Pool<A, B, S> { id: UID, k_last: u128, ... }
//!
//!     pub fn swap_a_for_b<A, B, S>(...) -> Coin<B> { ... }
//! }
//! ```
//!
//! The macro orchestrates the inner `#[object]` / `#[capability]` /
//! `#[invariant]` attributes: it walks the module body, recognises
//! those attributes, builds a single [`PetalManifestV0`] from them, and
//! emits one canonical-encoded blob (`bloom_petal_manifest_v0` custom
//! section) plus one `__petal_<fn>` shim per `pub fn`.
//!
//! Because Rust's attribute-macro expansion order is bottom-up, the
//! petal macro re-parses each tagged item from source. The inner
//! attribute macros (defined in `object.rs` / `capability.rs` /
//! `invariant.rs`) can also be used standalone (e.g. in a test crate)
//! — they're idempotent with respect to the petal macro.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Attribute, FnArg, GenericParam, Item, ItemFn, ItemMod, ItemStruct, Meta, ReturnType, Type,
};

use crate::ast::{attr_is_named, fn_name, ident, parse_str_value, signer_arg};
use crate::capability::CapabilityAttr;
use crate::codegen::{
    PetalShimAst, ShimArgAst, emit_dispatch_helper, emit_invariant_shim, emit_manifest_accessor,
    emit_manifest_section, emit_petal_shim,
};
use crate::error::err_spanned;
use crate::invariant::InvariantAttr;
use crate::object::ObjectAttr;
use crate::type_tag::TypeTagCtx;
use bloom_petal_manifest::types::{
    ArgDecl, ArgKind, FunctionDecl, PetalManifestV0, SCHEMA_VERSION, SemVer, TypeParamDecl,
    TypeParamKind,
};

/// Parsed `#[bloom::petal(...)]` attribute.
#[derive(Debug, Default, Clone)]
pub(crate) struct PetalAttr {
    /// VFS path of the petal (`"/bloom/dex/pool"`).
    pub path: Option<String>,
    /// Framework version, e.g. `"0.1.0"`. Defaults to `(0, 1, 0)`.
    pub version: Option<SemVer>,
}

impl PetalAttr {
    /// Parse the bare attribute tokens (everything inside the `(...)`).
    pub fn parse(attr: TokenStream) -> syn::Result<Self> {
        if attr.is_empty() {
            return Ok(Self::default());
        }
        let attr_text = format!("#[petal({})]", attr);
        let attrs: Vec<Attribute> =
            syn::parse::Parser::parse_str(Attribute::parse_outer, &attr_text)?;
        let outer = attrs
            .into_iter()
            .next()
            .ok_or_else(|| syn::Error::new(Span::call_site(), "expected `#[petal(...)]`"))?;
        let mut out = Self::default();
        if let Meta::List(list) = &outer.meta {
            let nested = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;
            for meta in nested {
                match &meta {
                    Meta::NameValue(nv) if nv.path.is_ident("path") => {
                        out.path = Some(parse_str_value(nv)?);
                    }
                    Meta::NameValue(nv) if nv.path.is_ident("version") => {
                        let raw = parse_str_value(nv)?;
                        out.version = Some(parse_semver(&raw, nv)?);
                    }
                    other => {
                        return Err(err_spanned(
                            other,
                            "unknown #[bloom::petal] argument; expected `path` or `version`",
                        ));
                    }
                }
            }
        }
        Ok(out)
    }

    /// Resolved SemVer (defaults to 0.1.0).
    pub fn resolved_version(&self) -> SemVer {
        self.version.unwrap_or_else(|| SemVer::new(0, 1, 0))
    }

    /// Resolved VFS path (defaults to the module's ident if unset).
    pub fn resolved_path(&self, module: &ItemMod) -> String {
        self.path
            .clone()
            .unwrap_or_else(|| format!("/{}", module.ident))
    }
}

/// Parse `"x.y.z"` into a `SemVer` triple.
fn parse_semver(raw: &str, span: &impl syn::spanned::Spanned) -> syn::Result<SemVer> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(syn::Error::new(
            span.span(),
            format!("invalid semver `{}`; expected major.minor.patch", raw),
        ));
    }
    let major = parts[0]
        .parse::<u16>()
        .map_err(|_| syn::Error::new(span.span(), "invalid major version"))?;
    let minor = parts[1]
        .parse::<u16>()
        .map_err(|_| syn::Error::new(span.span(), "invalid minor version"))?;
    let patch = parts[2]
        .parse::<u16>()
        .map_err(|_| syn::Error::new(span.span(), "invalid patch version"))?;
    Ok(SemVer::new(major, minor, patch))
}

/// Walk a parsed module + accumulate every kind of declaration. Used
/// in tests and from [`expand`].
pub(crate) fn build_manifest(attr: &PetalAttr, module: &ItemMod) -> syn::Result<PetalManifestV0> {
    let (m, _) = build_manifest_with_asts(attr, module)?;
    Ok(m)
}

/// Same as [`build_manifest`] but also returns the per-function
/// [`PetalShimAst`] payload used by [`emit_petal_shim`] to lower the
/// `__petal_<fn>` wasm export body.
pub(crate) fn build_manifest_with_asts(
    attr: &PetalAttr,
    module: &ItemMod,
) -> syn::Result<(PetalManifestV0, Vec<PetalShimAst>)> {
    let mut m = PetalManifestV0 {
        schema_version: SCHEMA_VERSION,
        module_path: attr.resolved_path(module),
        framework_version: attr.resolved_version(),
        ..Default::default()
    };
    let mut shims: Vec<PetalShimAst> = Vec::new();

    let items = match &module.content {
        Some((_, items)) => items.as_slice(),
        None => {
            return Err(err_spanned(
                module,
                "`#[bloom::petal]` requires an inline module body `mod foo { ... }`",
            ));
        }
    };

    for item in items {
        match item {
            Item::Struct(s) => {
                handle_struct(s, &mut m)?;
            }
            Item::Fn(f) => {
                if let Some(shim) = handle_fn(f, &mut m)? {
                    shims.push(shim);
                }
            }
            _ => {
                // Other items are passed through unchanged.
            }
        }
    }

    Ok((m, shims))
}

/// Recognise a `#[capability]` or `#[object]` struct and push its decl
/// into the manifest.
fn handle_struct(s: &ItemStruct, m: &mut PetalManifestV0) -> syn::Result<()> {
    let object_attr = find_attr(&s.attrs, "object");
    let capability_attr = find_attr(&s.attrs, "capability");

    if object_attr.is_some() && capability_attr.is_some() {
        return Err(err_spanned(
            s,
            "a struct cannot be both `#[object]` and `#[capability]`",
        ));
    }

    if let Some(attr) = capability_attr {
        let cap_attr = CapabilityAttr::parse(meta_tokens(attr)?)?;
        let decl = crate::capability::build_decl(s, &cap_attr)?;
        m.capability_types.push(decl);
        return Ok(());
    }

    if let Some(attr) = object_attr {
        let obj_attr = ObjectAttr::parse(meta_tokens(attr)?)?;
        let decl = crate::object::build_decl(s, &obj_attr)?;
        m.object_types.push(decl);
        return Ok(());
    }

    Ok(())
}

/// Recognise `pub fn` items and push their decls into the manifest.
/// Also processes `#[invariant]` attributes on functions.
///
/// Returns the [`PetalShimAst`] payload for the function, or `None` if
/// the function was skipped (non-`pub`).
fn handle_fn(f: &ItemFn, m: &mut PetalManifestV0) -> syn::Result<Option<PetalShimAst>> {
    // Only `pub` fns are part of the petal surface.
    if !matches!(f.vis, syn::Visibility::Public(_)) {
        return Ok(None);
    }

    // Process #[invariant] first so the function decl can record the
    // invariant index.
    let mut attached: Vec<u16> = Vec::new();
    for a in &f.attrs {
        if attr_is_named(a, "invariant") {
            let inv_attr = InvariantAttr::parse(meta_tokens(a)?)?;
            let idx = m.invariants.len() as u16;
            let decl = crate::invariant::build_decl(&inv_attr, f, idx);
            m.invariants.push(decl);
            attached.push(idx);
        }
    }

    // Build the FunctionDecl.
    let mut type_params = Vec::new();
    let mut generic_names: Vec<String> = Vec::new();
    for p in &f.sig.generics.params {
        if let GenericParam::Type(t) = p {
            type_params.push(TypeParamDecl {
                name: t.ident.to_string(),
                // Function-level params default to Resource. Phantom
                // markers are only meaningful on object types in v0.
                kind: TypeParamKind::Resource,
                bounds: Vec::new(),
            });
            generic_names.push(t.ident.to_string());
        }
    }

    let ctx = TypeTagCtx::from_generic_names(generic_names.iter().cloned());

    let mut args = Vec::<ArgDecl>::new();
    let mut shim_args = Vec::<ShimArgAst>::new();
    let mut required_signers: u8 = 0;
    let mut required_capabilities = Vec::new();

    // Generic dispatch (spec §5): a fn like `identity<T>(c: Coin<T>)`
    // compiles to one *non-generic* `__petal_identity` wasm export. The
    // concrete type-args arrive at runtime as the leading slots of the
    // calldata (one canonical-encoded `TypeTag` per generic param, in
    // declaration order, ahead of the positional args). We emit a
    // shim-only `ArgKind::TypeArg(idx)` decode slot per generic param so
    // the shim reads those tags off the front of the buffer and binds
    // them into the per-call `bloom_resource::TypeArgs` context.
    //
    // These slots are deliberately *not* pushed into `args` (the
    // manifest `FunctionDecl.args`): the PTB validator checks
    // `cmd.args.len() == f.args.len()` and `cmd.type_args.len() ==
    // f.type_params.len()` separately — type-args live in the dedicated
    // `MoveCmd.type_args` vector, not in the positional arg list. The
    // synthetic slots only steer the shim's wire decode.
    for (idx, _name) in generic_names.iter().enumerate() {
        let idx_u16 = u16::try_from(idx)
            .map_err(|_| err_spanned(f, "too many generic type parameters (max 65535)"))?;
        shim_args.push(ShimArgAst {
            name: format!("__type_arg_{idx}"),
            is_ref: false,
            is_mut: false,
            // Unused for TypeArg decode (the shim reads a raw TypeTag via
            // `ArgReader::read_type_tag`), but `ShimArgAst` requires a
            // `syn::Type`; a `TypeTag` placeholder keeps it well-formed.
            inner_ty: syn::parse_quote!(::bloom_objects::TypeTag),
            kind: ArgKind::TypeArg(idx_u16),
        });
    }

    for (i, arg) in f.sig.inputs.iter().enumerate() {
        let FnArg::Typed(pat_ty) = arg else {
            return Err(err_spanned(
                arg,
                "`self` arguments are not allowed in petal `pub fn`s",
            ));
        };
        let arg_name = pat_to_name(&pat_ty.pat).unwrap_or_else(|| format!("_{}", i));

        // Strip a single `&` / `&mut` layer for ergonomic recognition;
        // the shim emits the dispatch wrapper as `&local` / `&mut local`
        // as appropriate.
        let (is_ref, is_mut, inner_ty) = match pat_ty.ty.as_ref() {
            Type::Reference(r) => (true, r.mutability.is_some(), (*r.elem).clone()),
            other => (false, false, other.clone()),
        };

        // Signer detection.
        if signer_arg(arg).is_some() {
            required_signers = required_signers.saturating_add(1);
            args.push(ArgDecl {
                name: arg_name.clone(),
                kind: ArgKind::Signer,
            });
            shim_args.push(ShimArgAst {
                name: arg_name,
                is_ref,
                is_mut,
                inner_ty,
                kind: ArgKind::Signer,
            });
            continue;
        }

        // Reject plain T in arg position.
        crate::type_tag::reject_plain_generic_in_payload(&pat_ty.ty, &generic_names)?;

        // Determine kind based on type shape + reference mode.
        let kind = arg_kind_for(&pat_ty.ty, &ctx, &mut required_capabilities)?;
        args.push(ArgDecl {
            name: arg_name.clone(),
            kind: kind.clone(),
        });
        shim_args.push(ShimArgAst {
            name: arg_name,
            is_ref,
            is_mut,
            inner_ty,
            kind,
        });
    }

    // Return tags + return-type AST (for codegen).
    let (returns, return_ast) = match &f.sig.output {
        ReturnType::Default => (Vec::new(), None),
        ReturnType::Type(_, ty) => match ty.as_ref() {
            // Returns unwrap `Resource<T>` to `T` for the same reason args
            // do (spec §11.2): a returned `Resource<T>` is an on-chain `T`
            // object id threaded to downstream commands.
            syn::Type::Tuple(t) => (
                t.elems
                    .iter()
                    .map(|t| ctx.lower(crate::type_tag::strip_resource_wrapper(t)))
                    .collect::<Result<Vec<_>, _>>()?,
                Some((**ty).clone()),
            ),
            other => (
                vec![ctx.lower(crate::type_tag::strip_resource_wrapper(other))?],
                Some((**ty).clone()),
            ),
        },
    };

    let fn_name_s = fn_name(f);
    let is_generic = !type_params.is_empty();

    m.functions.push(FunctionDecl {
        name: fn_name_s.clone(),
        type_params,
        args,
        returns: returns.clone(),
        required_signers,
        required_capabilities,
        attached_invariants: attached,
    });

    Ok(Some(PetalShimAst {
        fn_name: fn_name_s,
        args: shim_args,
        return_ast,
        return_tags: returns,
        is_generic,
        generic_names,
    }))
}

/// Map a `syn::Pat` to a `String` argument name (best effort).
fn pat_to_name(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(p) => Some(p.ident.to_string()),
        syn::Pat::Wild(_) => Some("_".to_string()),
        _ => None,
    }
}

/// Determine the `ArgKind` for a function argument based on its type.
///
/// Rules (best effort, spec §8.2 / §11.2):
/// - `Capability<T>` → `ArgKind::Object` + push `T` into
///   `required_capabilities`.
/// - `&T` / `&mut T` / bare `T` where `T` is concrete → `ArgKind::Object`
///   with the appropriate `AccessMode`.
/// - Anything else → `ArgKind::Const(ty)` as a fall-through (the chain
///   side decodes via the canonical codec).
fn arg_kind_for(
    ty: &syn::Type,
    ctx: &TypeTagCtx,
    required_capabilities: &mut Vec<bloom_objects::TypeTag>,
) -> syn::Result<ArgKind> {
    // Strip a single layer of `&` / `&mut`.
    let (access, inner) = match ty {
        syn::Type::Reference(r) => {
            let mode = if r.mutability.is_some() {
                bloom_objects::AccessMode::Mutable
            } else {
                bloom_objects::AccessMode::ReadOnly
            };
            (Some(mode), r.elem.as_ref())
        }
        other => (None, other),
    };

    // `Resource<T>` is a transparent handle wrapper; the on-chain object
    // arg is a `T`, so the manifest declares `T`'s tag (spec §11.2). The
    // access mode (computed from the outer `&`/`&mut`) is preserved.
    let inner = crate::type_tag::strip_resource_wrapper(inner);

    let tag = ctx.lower(inner)?;

    // Capability<T> → object + record capability requirement.
    if let bloom_objects::TypeTag::Concrete {
        type_name,
        type_args,
        ..
    } = &tag
    {
        if type_name == "Capability" {
            // Treat the inner T as the cap type.
            if let Some(inner) = type_args.first() {
                required_capabilities.push(inner.clone());
            }
            return Ok(ArgKind::Object {
                ty: tag,
                mode: access.unwrap_or(bloom_objects::AccessMode::ReadOnly),
            });
        }
    }

    // Heuristic: types we recognise as "owned objects" — `Coin`,
    // `Balance`, `Resource`, anything starting with an uppercase that
    // isn't a primitive integer.
    if is_object_like(inner) {
        let mode = access.unwrap_or(bloom_objects::AccessMode::Consume);
        return Ok(ArgKind::Object { ty: tag, mode });
    }

    Ok(ArgKind::Const(tag))
}

/// Heuristic: returns `true` for types that should be treated as
/// "object" args (linear, taken from the borrow table) rather than
/// canonical-codec consts. Primitive types (`u8`..`u128`, `bool`,
/// `Address`, etc.) come back as `false`.
fn is_object_like(ty: &syn::Type) -> bool {
    let syn::Type::Path(syn::TypePath { path, qself: None }) = ty else {
        return false;
    };
    let Some(seg) = path.segments.last() else {
        return false;
    };
    let n = seg.ident.to_string();

    if matches!(
        n.as_str(),
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "bool"
            | "String"
            | "Vec"
            | "Address"
            | "ObjectId"
            | "TypeTag"
    ) {
        return false;
    }

    // Single uppercase letter (e.g. `T`) is a generic, not an object.
    if n.len() == 1 && n.chars().next().unwrap().is_ascii_uppercase() {
        return false;
    }

    // Otherwise, assume CamelCase = object-like.
    n.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

/// Find the (last) attribute on a list matching `name`.
fn find_attr<'a>(attrs: &'a [Attribute], name: &str) -> Option<&'a Attribute> {
    attrs.iter().find(|a| attr_is_named(a, name))
}

/// Extract the inner `(...)` tokens of an attribute like
/// `#[object(abilities = "...")]` → `abilities = "..."`.
/// Returns an empty token stream for bare `#[object]`.
fn meta_tokens(attr: &Attribute) -> syn::Result<TokenStream> {
    match &attr.meta {
        Meta::Path(_) => Ok(TokenStream::new()),
        Meta::List(l) => Ok(l.tokens.clone()),
        Meta::NameValue(_) => Err(err_spanned(attr, "expected attribute list `(...)`")),
    }
}

/// Macro entry: parse the petal-mod, build the manifest, emit the
/// custom-section blob + per-fn shims, re-emit the module with the
/// macro-recognised attrs stripped so downstream compilers see clean
/// Rust.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let parsed: ItemMod = syn::parse2(item)?;
    let petal_attr = PetalAttr::parse(attr)?;
    let (manifest, shim_asts) = build_manifest_with_asts(&petal_attr, &parsed)?;

    // Manifest blob + accessor.
    let section_ident = ident("__BLOOM_PETAL_MANIFEST_BYTES", Span::call_site());
    let section = emit_manifest_section(&manifest, &section_ident)?;
    let accessor = emit_manifest_accessor(&section_ident);

    // Per-fn shims.
    let petal_shims: Vec<_> = shim_asts.iter().map(emit_petal_shim).collect();

    // Per-module dispatch helper (emitted exactly once; every shim in
    // the module routes through it for the panic-catching / ret-buffer
    // copy plumbing).
    let dispatch_helper = if petal_shims.is_empty() {
        TokenStream::new()
    } else {
        emit_dispatch_helper()
    };

    // Per-invariant shims.
    let inv_shims: Vec<_> = manifest
        .invariants
        .iter()
        .enumerate()
        .map(|(i, _)| emit_invariant_shim(i as u16))
        .collect();

    // Strip the petal-recognised inner attributes from the module
    // body so downstream compilation sees clean Rust. The user-facing
    // attrs (`#[bloom::petal]`, `#[object]`, ...) are inert sigil
    // macros once we've parsed them; if we *leave* them on the items
    // the inner `#[object]` macro will run a second time. Removing
    // them keeps the expansion idempotent.
    let mut output = parsed.clone();
    if let Some((_, items)) = &mut output.content {
        for item in items.iter_mut() {
            match item {
                Item::Struct(s) => {
                    s.attrs
                        .retain(|a| !attr_is_named(a, "object") && !attr_is_named(a, "capability"));
                }
                Item::Fn(f) => {
                    f.attrs.retain(|a| !attr_is_named(a, "invariant"));
                }
                _ => {}
            }
        }
    }

    // Build the generated trailing items as a single TokenStream and
    // splice it inside the module body. The emitted sub-fragments
    // sometimes lower to multiple syntactic items (a `cfg`-gated
    // pair, an extern fn, a const) — parsing back to `Item` would
    // fail, so we keep them as raw tokens.
    let extras = quote! {
        #section
        #accessor
        #dispatch_helper
        #(#petal_shims)*
        #(#inv_shims)*
    };

    let ItemMod {
        attrs,
        vis,
        unsafety,
        mod_token,
        ident: mod_ident,
        ..
    } = &output;
    let body_items: Vec<&Item> = match &output.content {
        Some((_, items)) => items.iter().collect(),
        None => Vec::new(),
    };

    Ok(quote! {
        #(#attrs)*
        #vis #unsafety #mod_token #mod_ident {
            #(#body_items)*
            #extras
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn parse_mod(toks: TokenStream) -> ItemMod {
        syn::parse2(toks).unwrap()
    }

    #[test]
    fn parse_attr_defaults() {
        let a = PetalAttr::parse(TokenStream::new()).unwrap();
        assert!(a.path.is_none());
        assert!(a.version.is_none());
        assert_eq!(a.resolved_version(), SemVer::new(0, 1, 0));
    }

    #[test]
    fn parse_attr_full() {
        let a = PetalAttr::parse(quote! { path = "/bloom/test", version = "1.2.3" }).unwrap();
        assert_eq!(a.path.as_deref(), Some("/bloom/test"));
        assert_eq!(a.resolved_version(), SemVer::new(1, 2, 3));
    }

    #[test]
    fn parse_attr_rejects_bad_semver() {
        assert!(PetalAttr::parse(quote! { version = "1.2" }).is_err());
        assert!(PetalAttr::parse(quote! { version = "abc" }).is_err());
    }

    #[test]
    fn parse_attr_rejects_unknown() {
        assert!(PetalAttr::parse(quote! { woof = "x" }).is_err());
    }

    #[test]
    fn build_manifest_minimal() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn noop() {}
            }
        });
        let attr = PetalAttr::parse(quote! { path = "/p" }).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.module_path, "/p");
        assert_eq!(manifest.functions.len(), 1);
        assert_eq!(manifest.functions[0].name, "noop");
    }

    #[test]
    fn build_manifest_collects_objects() {
        let m = parse_mod(quote! {
            pub mod p {
                #[object(abilities = "key, store")]
                pub struct Pool { id: UID, k_last: u128 }
            }
        });
        let attr = PetalAttr::parse(quote! { path = "/p" }).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.object_types.len(), 1);
        assert_eq!(manifest.object_types[0].name, "Pool");
        assert!(manifest.object_types[0].abilities.has_store());
    }

    #[test]
    fn build_manifest_collects_capabilities() {
        let m = parse_mod(quote! {
            pub mod p {
                #[capability]
                pub struct AdminCap { id: UID }
            }
        });
        let attr = PetalAttr::parse(quote! { path = "/p" }).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.capability_types.len(), 1);
        assert_eq!(manifest.capability_types[0].name, "AdminCap");
    }

    #[test]
    fn build_manifest_collects_invariants() {
        let m = parse_mod(quote! {
            pub mod p {
                #[invariant(name = "k_non_decreasing")]
                pub fn swap() {}
            }
        });
        let attr = PetalAttr::parse(quote! { path = "/p" }).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.invariants.len(), 1);
        assert_eq!(manifest.invariants[0].name, "k_non_decreasing");
        assert_eq!(manifest.invariants[0].wasm_export, "__inv_0");
        assert_eq!(manifest.functions[0].attached_invariants, vec![0]);
    }

    #[test]
    fn build_manifest_rejects_object_and_capability_on_same_struct() {
        let m = parse_mod(quote! {
            pub mod p {
                #[object]
                #[capability]
                pub struct Hybrid { id: UID }
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        assert!(build_manifest(&attr, &m).is_err());
    }

    #[test]
    fn build_manifest_records_signer() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn send(s: &Signer, amount: u128) {}
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.functions[0].required_signers, 1);
    }

    #[test]
    fn build_manifest_records_capability_arg() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn admin(cap: &Capability<AdminCap>, amount: u128) {}
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        let f = &manifest.functions[0];
        assert_eq!(f.required_capabilities.len(), 1);
        assert!(matches!(&f.args[0].kind, ArgKind::Object { .. }));
    }

    #[test]
    fn build_manifest_records_returns() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn mint(amount: u128) -> Coin<USDC> { Coin {} }
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.functions[0].returns.len(), 1);
    }

    #[test]
    fn build_manifest_records_tuple_returns() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn split(c: Coin<U>) -> (Coin<U>, Coin<U>) { unimplemented!() }
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.functions[0].returns.len(), 2);
    }

    #[test]
    fn build_manifest_skips_private_fns() {
        let m = parse_mod(quote! {
            pub mod p {
                pub fn public_one() {}
                fn private_one() {}
            }
        });
        let attr = PetalAttr::parse(quote! {}).unwrap();
        let manifest = build_manifest(&attr, &m).unwrap();
        assert_eq!(manifest.functions.len(), 1);
        assert_eq!(manifest.functions[0].name, "public_one");
    }

    #[test]
    fn expand_emits_manifest_section() {
        let toks = expand(
            quote! { path = "/p" },
            quote! {
                pub mod p {
                    pub fn noop() {}
                }
            },
        )
        .unwrap();
        let s = toks.to_string();
        assert!(s.contains("__BLOOM_PETAL_MANIFEST_BYTES"));
        assert!(s.contains("bloom_petal_manifest_v0"));
        assert!(s.contains("__petal_noop"));
    }
}
