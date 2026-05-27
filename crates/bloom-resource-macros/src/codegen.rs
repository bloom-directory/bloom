//! Token emission helpers shared by every macro module.
//!
//! These helpers produce `proc_macro2::TokenStream` fragments that:
//!
//! - Marshal `PetalManifestV0` instances into rust constants whose
//!   canonical-encoded bytes get embedded as the
//!   `bloom_petal_manifest_v0` wasm custom section (spec §8.1, §11.1).
//! - Emit `__petal_<fn>` wasm exports with the spec §11.1 signature,
//!   driving an [`bloom_resource::abi::ArgReader`] across the args
//!   buffer, dispatching to the user fn, and writing typed return
//!   values back via [`bloom_resource::abi::RetWriter`].
//! - Emit `__inv_<idx>` wasm exports for invariants (spec §12.1).
//! - Re-emit user `pub fn`s with their original bodies preserved.

use bloom_objects::TypeTag;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{GenericArgument, Ident, PathArguments, Type, TypePath};

use bloom_petal_manifest::codec as manifest_codec;
use bloom_petal_manifest::types::{ArgKind, PetalManifestV0};

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
    // output as a custom section. Transitive petal dependencies compile
    // with `no-entrypoint`; suppress their wasm-side manifest too, or
    // the linker concatenates multiple manifest blobs into one custom
    // section. On non-wasm targets we still emit the static so host-side
    // unit tests can inspect it.
    Ok(quote! {
        /// Canonical-encoded `PetalManifestV0` blob. Embedded into the
        /// wasm output as the `bloom_petal_manifest_v0` custom section
        /// (spec §8.1). Auto-generated; do not edit.
        #[cfg(all(target_arch = "wasm32", not(feature = "no-entrypoint")))]
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
// `__petal_<fn>` shim AST
// ---------------------------------------------------------------------------

/// Per-argument information [`emit_petal_shim`] needs to lower the
/// per-arg decode → user-fn dispatch glue. Parallels [`ArgDecl`](bloom_petal_manifest::types::ArgDecl)
/// but additionally carries the raw `syn::Type` so we can dispatch on
/// the inner type shape (`Coin<T>` / `Capability<T>` / primitive / …).
#[derive(Clone, Debug)]
pub(crate) struct ShimArgAst {
    /// Arg name (best-effort).
    pub(crate) name: String,
    /// `true` iff the user wrote `&T` or `&mut T`.
    pub(crate) is_ref: bool,
    /// `true` iff `is_ref` and the reference is `&mut`.
    pub(crate) is_mut: bool,
    /// The `T` after stripping any leading `&` / `&mut`.
    pub(crate) inner_ty: Type,
    /// Manifest-level arg kind (also drives the chain-side dispatch).
    pub(crate) kind: ArgKind,
}

/// Bundle of information [`emit_petal_shim`] needs for one `pub fn`.
#[derive(Clone, Debug)]
pub(crate) struct PetalShimAst {
    /// Function name (no `__petal_` prefix).
    pub(crate) fn_name: String,
    /// Argument descriptors in source order.
    pub(crate) args: Vec<ShimArgAst>,
    /// Original return-type AST (`Some(syn::Type)` for non-`()` returns).
    pub(crate) return_ast: Option<Type>,
    /// Manifest-level return tags (parallel to a flattened tuple).
    pub(crate) return_tags: Vec<TypeTag>,
    /// `true` when the user fn carries one or more type parameters
    /// (spec §5 generic dispatch). The shim decodes one leading
    /// `ArgKind::TypeArg` slot per generic param, binds them into a
    /// per-call `bloom_resource::TypeArgs` context, and dispatches to
    /// the user fn monomorphized over `bloom_resource::Erased`.
    pub(crate) is_generic: bool,
    /// Names of the user fn's type parameters, in declaration order.
    /// Any of these appearing inside an object-wrapper arg's type args
    /// is rewritten to `bloom_resource::Erased` so the non-generic wasm
    /// shim names a concrete wrapper type.
    pub(crate) generic_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// `__petal_<fn>` wasm export shim
// ---------------------------------------------------------------------------

/// Build the `__petal_<fn_name>` wasm export that decodes args via
/// [`bloom_resource::abi::ArgReader`], dispatches to the user fn, then
/// encodes returns via [`bloom_resource::abi::RetWriter`] and copies
/// them into the runtime-provided `ret_ptr[..ret_cap]` buffer
/// (spec §11.1).
///
/// Returns `0` on success or the `as_i32()` discriminant of a typed
/// [`bloom_resource::PetalError`] on failure. The return buffer is
/// populated with the canonical-encoded return values; the runtime
/// decodes them per the declared return TypeTags in the manifest.
pub(crate) fn emit_petal_shim(ast: &PetalShimAst) -> TokenStream {
    let fn_name = &ast.fn_name;
    let export_name = format!("__petal_{}", fn_name);
    let shim_ident = format_ident!("__bloom_petal_{}", fn_name);
    let user_fn_ident = format_ident!("{}", fn_name);

    // Per-arg decode statements and the call-site argument expressions.
    let mut decode_stmts: Vec<TokenStream> = Vec::new();
    let mut call_exprs: Vec<TokenStream> = Vec::new();
    for (i, arg) in ast.args.iter().enumerate() {
        let local_ident = format_ident!("__arg_{}", i);
        let (decode, expr) = emit_arg_decode(&local_ident, arg, &ast.generic_names);
        decode_stmts.push(decode);
        // `TypeArg` slots are decoded for their side effect (binding the
        // per-call type-args context) but are not positional call args;
        // they emit an empty expr we skip here.
        if !expr.is_empty() {
            call_exprs.push(expr);
        }
    }

    // Generic dispatch (spec §5): a generic user fn is invoked
    // monomorphized over `bloom_resource::Erased` for every type
    // parameter. The decoded per-param `TypeArg` tags drive the phantom
    // wrappers' `type_tag(idx)` lookups via the bound `TypeArgs` context.
    let user_call = if ast.is_generic {
        let erased = ast
            .generic_names
            .iter()
            .map(|_| quote! { ::bloom_resource::Erased });
        quote! { #user_fn_ident::<#(#erased),*>(#(#call_exprs),*) }
    } else {
        quote! { #user_fn_ident(#(#call_exprs),*) }
    };

    // For a generic fn the decoded `TypeArg` tags are accumulated into a
    // per-call `bloom_resource::TypeArgs` context (spec §5) so phantom
    // wrappers inside the body can resolve `T`'s concrete tag. The
    // `__bloom_type_args` vec is populated by the `TypeArg` decode
    // statements; for a non-generic fn the setup is empty.
    let (type_args_setup, type_args_bind) = if ast.is_generic {
        let setup = quote! {
            let mut __bloom_type_args: ::std::vec::Vec<::bloom_objects::TypeTag> =
                ::std::vec::Vec::new();
        };
        // Install the decoded tags as the per-call context for the
        // duration of the user-fn dispatch. The RAII guard restores the
        // prior context when it drops at the end of the closure.
        let bind = quote! {
            let __bloom_type_args_guard =
                ::bloom_resource::TypeArgs::bind(__bloom_type_args.clone());
        };
        (setup, bind)
    } else {
        (quote! {}, quote! {})
    };

    // Return-encode block. Build it before we splice it into the
    // overall closure so a tuple return can iterate each slot.
    let encode_returns = emit_return_encode(ast);

    quote! {
        /// Auto-generated wasm export shim for `#[bloom::petal]` fn
        /// (spec §11.1, chain-VM ABI). Reads the framed calldata via
        /// `chain.msg.calldata.read`, decodes args with `CallArgsReader`,
        /// dispatches to the user fn, encodes the count-prefixed return
        /// envelope, then delivers it through `chain.petal.return` — a
        /// trap the VM dispatcher treats as success — or via
        /// `chain.petal.revert` carrying the typed `PetalError` code.
        ///
        /// The export is the 2-arg `(calldata_offset, calldata_len) ->
        /// i32` shape the chain VM calls with `(0, len)`. The `i32`
        /// return is vestigial (delivery happens through the trap
        /// imports) but kept so the signature matches `get_typed_func`.
        ///
        /// Gated on `not(feature = "no-entrypoint")` so that downstream
        /// crates depending on this petal as a library can suppress the
        /// wasm export symbols and avoid duplicate-export link errors.
        #[cfg(all(target_arch = "wasm32", not(feature = "no-entrypoint")))]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #shim_ident(
            __calldata_offset: i32,
            __calldata_len: i32,
        ) -> i32 {
            __bloom_dispatch_petal_shim(
                __calldata_offset,
                __calldata_len,
                |__args, __ret_buf| {
                    let mut __reader = match ::bloom_resource::abi::CallArgsReader::new(__args) {
                        Ok(r) => r,
                        Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                    };
                    #type_args_setup
                    #(#decode_stmts)*
                    if __reader.expect_finished().is_err() {
                        return Err(::bloom_resource::PetalError::InvalidArgs);
                    }
                    #type_args_bind
                    let __ret = #user_call;
                    #encode_returns
                    Ok(())
                },
            )
        }

        /// Host-side mirror of the wasm export shim. Takes safe Rust
        /// slices so unit tests and tooling can drive the dispatch
        /// path without conjuring `i32`-encoded pointers (which would
        /// silently truncate on 64-bit hosts).
        ///
        /// Behavior matches the wasm export: returns 0 on success or a
        /// positive `PetalError::as_i32()` code on failure. The
        /// encoded return bytes are appended to `ret_buf`.
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code, clippy::too_many_arguments)]
        pub fn #shim_ident(args: &[u8], ret_buf: &mut ::std::vec::Vec<u8>) -> i32 {
            __bloom_dispatch_petal_shim_host(
                args,
                ret_buf,
                |__args, __ret_buf| {
                    let mut __reader = match ::bloom_resource::abi::CallArgsReader::new(__args) {
                        Ok(r) => r,
                        Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                    };
                    #type_args_setup
                    #(#decode_stmts)*
                    if __reader.expect_finished().is_err() {
                        return Err(::bloom_resource::PetalError::InvalidArgs);
                    }
                    #type_args_bind
                    let __ret = #user_call;
                    #encode_returns
                    Ok(())
                },
            )
        }
    }
}

/// Emit the decode statement(s) + the call-site argument expression for
/// a single shim arg. `generic_names` lists the enclosing fn's
/// type-param names so object wrappers can erase nested generics.
fn emit_arg_decode(
    local: &Ident,
    arg: &ShimArgAst,
    generic_names: &[String],
) -> (TokenStream, TokenStream) {
    match &arg.kind {
        ArgKind::Signer => {
            // The args buffer carries a 16-bit signer index per the
            // existing ArgReader contract (spec §6 / §7.1). The user fn
            // takes `&Signer` or `Signer`; we emit the matching
            // call-site expression.
            let decode = quote! {
                let #local: ::bloom_resource::Signer = match __reader.next_signer() {
                    Ok(idx) => ::bloom_resource::Signer::from_index(idx),
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
            };
            let expr = if arg.is_ref {
                quote! { &#local }
            } else {
                quote! { #local }
            };
            (decode, expr)
        }
        ArgKind::Const(_) => {
            let inner_ty = &arg.inner_ty;
            // `quote!` does not support arbitrary identifier-paste —
            // pre-build the per-arg "raw bytes" local with `format_ident!`
            // so the interpolation only needs to splice an `Ident`.
            let bytes_ident = format_ident!("__const_bytes_for_{}", local);
            // Const args are length-prefixed (spec §7.1 / §11.1) so the
            // shim consumes the same wire shape `BloomType::canonical_decode`
            // round-trips through.
            let decode = quote! {
                let #bytes_ident = match __reader.next_const_bytes() {
                    Ok(b) => b,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
                let #local: #inner_ty = match
                    <#inner_ty as ::bloom_resource::BloomType>::canonical_decode(&#bytes_ident)
                {
                    Ok(v) => v,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
            };
            let expr = if arg.is_ref {
                quote! { &#local }
            } else {
                quote! { #local }
            };
            (decode, expr)
        }
        ArgKind::Object { mode, .. } => {
            let access_mode_expr = match mode {
                bloom_objects::AccessMode::ReadOnly => {
                    quote! { ::bloom_objects::AccessMode::ReadOnly }
                }
                bloom_objects::AccessMode::Mutable => {
                    quote! { ::bloom_objects::AccessMode::Mutable }
                }
                bloom_objects::AccessMode::Consume => {
                    quote! { ::bloom_objects::AccessMode::Consume }
                }
            };
            // Pre-build per-arg `Ident`s so `quote!` only has to splice
            // single tokens (it cannot identifier-paste).
            let handle_ident = format_ident!("__handle_for_{}", local);
            let obj_id_ident = format_ident!("__obj_id_for_{}", local);
            let wrap_expr = wrap_object_handle(&arg.inner_ty, &handle_ident, generic_names);
            // A `&mut T` user arg needs the materialized local to be
            // mutable so the `&mut #local` call expression below can borrow
            // it; `&T` and by-value args bind immutably.
            let local_binding = if arg.is_mut {
                quote! { let mut #local = #wrap_expr; }
            } else {
                quote! { let #local = #wrap_expr; }
            };
            let decode = quote! {
                let #obj_id_ident = match __reader.next_object_id() {
                    Ok(id) => id,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
                let #handle_ident: ::bloom_resource::RuntimeHandle =
                    match ::bloom_resource::host::object_borrow(&#obj_id_ident, #access_mode_expr) {
                        Ok(h) => h,
                        Err(e) => return Err(e),
                    };
                #local_binding
            };
            // Pass `&local` / `&mut local` / `local` depending on the user fn signature.
            let expr = if arg.is_mut {
                quote! { &mut #local }
            } else if arg.is_ref {
                quote! { &#local }
            } else {
                quote! { #local }
            };
            (decode, expr)
        }
        ArgKind::TypeArg(idx) => {
            // TypeArg slots carry a serialized TypeTag at this position
            // in the args buffer (spec §7.1, ArgKind::TypeArg). The user
            // fn doesn't receive these as positional Rust args; the
            // decoded tags are *bound* into the per-call
            // `bloom_resource::TypeArgs` context (spec §5 generic
            // dispatch) so phantom-typed wrappers (`Coin<T>`) inside the
            // body can resolve `T`'s concrete tag.
            //
            // We decode the tag and place it at its declared
            // generic-param index in `__bloom_type_args` (declared by
            // the enclosing shim for generic fns). Decoding also keeps
            // the buffer cursor aligned for any subsequent positional
            // args.
            let stash = format_ident!("__type_arg_{}", idx);
            let idx_lit = *idx as usize;
            let decode = quote! {
                let #stash: ::bloom_objects::TypeTag = match __reader.next_type_arg() {
                    Ok(t) => t,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
                // Bind this type-arg at its declared generic-param index
                // so `current_type_arg(idx)` resolves it. Grow the vec
                // with placeholders if the TypeArg slots arrive out of
                // index order.
                {
                    let __idx: usize = #idx_lit;
                    if __bloom_type_args.len() <= __idx {
                        __bloom_type_args.resize(
                            __idx + 1,
                            ::bloom_objects::TypeTag::Generic { idx: 0 },
                        );
                    }
                    __bloom_type_args[__idx] = #stash;
                }
            };
            // TypeArg is not passed as a positional call argument.
            (decode, TokenStream::new())
        }
    }
}

/// Emit the wrapper-construction expression for an object-shaped arg.
///
/// Rules:
/// - Inner type `Coin<T>` → `::bloom_resource::Coin::<T>::from_handle(h)`
/// - Inner type `Capability<T>` → `::bloom_resource::Capability::<T>::from_handle(h)`
/// - Anything else recognised as object-like → `<inner>::from_handle(h)`
///
/// `generic_names` lists the enclosing fn's type-param names. Because
/// the macro-emitted shim is a *non-generic* wasm export, any of those
/// names appearing in a wrapper's type args is rewritten to
/// `::bloom_resource::Erased` so the wrapper is a concrete type (spec §5
/// generic dispatch). Concrete (non-generic) type args are preserved.
fn wrap_object_handle(inner: &Type, handle_ident: &Ident, generic_names: &[String]) -> TokenStream {
    let name = path_last_ident(inner);
    let turbofish = path_last_turbofish(inner, generic_names);

    match name.as_deref() {
        Some("Coin") => {
            // `turbofish` already carries its own leading `::<...>`
            // when generics are present (or is empty when not), so we
            // splice it directly after the path with no extra joiner.
            quote! { ::bloom_resource::Coin #turbofish ::from_handle(#handle_ident) }
        }
        Some("Capability") => {
            quote! { ::bloom_resource::Capability #turbofish ::from_handle(#handle_ident) }
        }
        Some("Resource") => {
            // `Resource<T>` is the generic object-handle wrapper. The user
            // names it directly (e.g. `pool: &mut Resource<Pool>`); we
            // splice its own turbofish so the materialized local is the
            // *same* `Resource<T>` the signature expects — not a
            // double-wrapped `Resource<Resource<T>>`. This is the
            // handle/tag dispatch convention for opaque on-chain objects
            // (spec §11.2): the body reads `.handle()` and operates on the
            // borrow-table handle rather than a concrete Rust struct.
            quote! { ::bloom_resource::Resource #turbofish ::from_handle(#handle_ident) }
        }
        _ => {
            // Fallback: wrap in Resource<inner>. The macro emits the
            // outer type *as-written* so the user can name it directly
            // in their function signature (e.g. `c: MyObj`) and the
            // shim materializes a `Resource<MyObj>`. This is the spec
            // §11.2 dispatch convention for any object-like arg the
            // macro doesn't specially recognise. Generic params in the
            // inner type are rewritten to `Erased`.
            let inner_erased = rewrite_generics_to_erased(inner, generic_names);
            quote! { ::bloom_resource::Resource::<#inner_erased>::from_handle(#handle_ident) }
        }
    }
}

/// Last path segment ident name, if `ty` is a single-path TypePath.
fn path_last_ident(ty: &Type) -> Option<String> {
    let Type::Path(TypePath { path, qself: None }) = ty else {
        return None;
    };
    path.segments.last().map(|s| s.ident.to_string())
}

/// Turbofish-rendered last-segment generic args (e.g. `::<USDC>`), with
/// any name in `generic_names` rewritten to `::bloom_resource::Erased`
/// (recursively, so nested `T`s like `MintCap<T>` are erased too).
/// Returns an empty `TokenStream` when the type has no generics so the
/// caller can splice the result directly after a path like
/// `::bloom_resource::Coin` without an extra `::` joiner.
fn path_last_turbofish(ty: &Type, generic_names: &[String]) -> TokenStream {
    let Type::Path(TypePath { path, qself: None }) = ty else {
        return TokenStream::new();
    };
    let Some(seg) = path.segments.last() else {
        return TokenStream::new();
    };
    match &seg.arguments {
        PathArguments::AngleBracketed(ab) => {
            let args: Vec<TokenStream> = ab
                .args
                .iter()
                .map(|arg| match arg {
                    GenericArgument::Type(t) => rewrite_generics_to_erased(t, generic_names),
                    other => quote! { #other },
                })
                .collect();
            if args.is_empty() {
                TokenStream::new()
            } else {
                quote! { ::<#(#args),*> }
            }
        }
        _ => TokenStream::new(),
    }
}

/// Rewrite a `syn::Type` so that any path naming a fn type-param (from
/// `generic_names`) becomes `::bloom_resource::Erased`. Concrete types
/// pass through unchanged.
///
/// The rewrite recurses into nested generic arguments so a `T` appearing
/// inside a wrapper — `Capability<MintCap<T>>`, `Supply<T>` — is erased
/// wherever it sits, not only at the top level. The macro-emitted shim
/// is a *non-generic* wasm export, so every `T` it would otherwise
/// mention must be replaced with the concrete `Erased` marker for the
/// wrapper type to name-resolve (spec §5 generic dispatch).
fn rewrite_generics_to_erased(ty: &Type, generic_names: &[String]) -> TokenStream {
    if let Type::Path(TypePath { path, qself: None }) = ty {
        // A bare single-segment path naming a type-param erases directly.
        if path.segments.len() == 1 {
            let seg = path.segments.first().expect("checked len == 1");
            if matches!(seg.arguments, PathArguments::None)
                && generic_names.iter().any(|n| seg.ident == n.as_str())
            {
                return quote! { ::bloom_resource::Erased };
            }
        }
        // Otherwise rebuild the path, recursing into each segment's
        // angle-bracketed type args so nested `T`s are erased too.
        let leading = path.leading_colon.map(|_| quote! { :: });
        let segments: Vec<TokenStream> = path
            .segments
            .iter()
            .map(|seg| {
                let ident = &seg.ident;
                match &seg.arguments {
                    PathArguments::AngleBracketed(ab) => {
                        let args: Vec<TokenStream> = ab
                            .args
                            .iter()
                            .map(|arg| match arg {
                                GenericArgument::Type(t) => {
                                    rewrite_generics_to_erased(t, generic_names)
                                }
                                other => quote! { #other },
                            })
                            .collect();
                        quote! { #ident<#(#args),*> }
                    }
                    _ => quote! { #ident },
                }
            })
            .collect();
        return quote! { #leading #(#segments)::* };
    }
    quote! { #ty }
}

/// Emit the return-encode block: write each return slot into the
/// `RetWriter` and copy the finished buffer into `__ret_buf`.
fn emit_return_encode(ast: &PetalShimAst) -> TokenStream {
    let generic_names = &ast.generic_names;
    let Some(ret_ast) = &ast.return_ast else {
        // No return: emit a count-prefixed empty envelope (count == 0) so
        // the executor's `unmarshal_outputs` reads back zero return slots
        // rather than choking on a bare buffer.
        return quote! {
            let _ = __ret;
            let mut __writer = ::bloom_resource::abi::RetWriter::new();
            __writer.write_u32(0u32);
            __ret_buf.extend_from_slice(&__writer.finish());
        };
    };

    match ret_ast {
        Type::Tuple(t) => {
            // Tuple return: a count-prefixed envelope with one slot per
            // element, in declaration order.
            let arity = t.elems.len() as u32;
            let mut writes = Vec::new();
            for (i, elem) in t.elems.iter().enumerate() {
                let idx = syn::Index::from(i);
                let write_expr = emit_return_write(elem, &quote! { __ret.#idx }, generic_names);
                writes.push(write_expr);
            }
            quote! {
                let mut __writer = ::bloom_resource::abi::RetWriter::new();
                __writer.write_u32(#arity);
                #(#writes)*
                __ret_buf.extend_from_slice(&__writer.finish());
            }
        }
        single => {
            // Single return: a count-prefixed envelope with exactly one slot.
            let write_expr = emit_return_write(single, &quote! { __ret }, generic_names);
            quote! {
                let mut __writer = ::bloom_resource::abi::RetWriter::new();
                __writer.write_u32(1u32);
                #write_expr
                __ret_buf.extend_from_slice(&__writer.finish());
            }
        }
    }
}

/// Emit a single return-slot write into `__writer` for the given Rust
/// return type. The handle/tag model encodes every on-chain object
/// wrapper (`Coin<_>`, `Capability<_>`, `Resource<_>`) as its stable
/// 32-byte `ObjectId` so a downstream command's `Use(cmd, ret)` can
/// re-borrow it; `Option<wrapper>` becomes a present/absent slot; and
/// plain values route through `BloomType::canonical_encode`.
///
/// `generic_names` lists the enclosing fn's type-param names so the
/// `BloomType` fallback can erase any phantom generic to
/// `bloom_resource::Erased` (the non-generic shim must name a concrete
/// type — spec §5).
fn emit_return_write(ty: &Type, value_expr: &TokenStream, generic_names: &[String]) -> TokenStream {
    // `Option<Inner>` → a present/absent slot. `Some` writes the inner
    // value's encoding (recursively); `None` writes a zero-length slot the
    // reader interprets as absent. This lets petals return optional coin
    // remainders (e.g. `swap_exact_out`) within the fixed count-prefixed
    // envelope.
    if let Some(inner) = option_inner(ty) {
        let some_write = emit_return_write(inner, &quote! { __opt_inner }, generic_names);
        return quote! {
            {
                match (#value_expr) {
                    ::core::option::Option::Some(__opt_inner) => { #some_write }
                    ::core::option::Option::None => { __writer.write_bytes(&[]); }
                }
            }
        };
    }

    let name = path_last_ident(ty);
    match name.as_deref() {
        Some("Coin") | Some("Capability") | Some("Resource") => {
            // Object wrappers carry an ephemeral `RuntimeHandle`, but a
            // return slot that crosses a command boundary must be the
            // object's stable 32-byte `ObjectId` so a downstream `Use` can
            // re-borrow it. Resolve the id via the `object.id` host import
            // and write it length-prefixed like every other slot in the
            // count-prefixed envelope. (`Resource` returns the created
            // object's id rather than its payload bytes for exactly this
            // cross-command threading — spec §11.2 handle/tag model.)
            quote! {
                {
                    let __slot_id = match ::bloom_resource::host::object_id((#value_expr).handle()) {
                        Ok(id) => id,
                        Err(e) => return Err(e),
                    };
                    __writer.write_bytes(&__slot_id.0);
                }
            }
        }
        _ => {
            // Fallback: BloomType::canonical_encode, wrapped in a
            // length prefix so multiple return slots can be parsed
            // back unambiguously. Erase any phantom generic so the
            // non-generic shim names a concrete `BloomType` impl.
            let ty_erased = rewrite_generics_to_erased(ty, generic_names);
            quote! {
                {
                    let __v = (#value_expr);
                    let __bytes = <#ty_erased as ::bloom_resource::BloomType>::canonical_encode(&__v);
                    __writer.write_bytes(&__bytes);
                }
            }
        }
    }
}

/// If `ty` is `Option<Inner>` (single-segment path), return `Inner`.
fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(TypePath { path, qself: None }) = ty else {
        return None;
    };
    let seg = path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(ab) = &seg.arguments else {
        return None;
    };
    match ab.args.first()? {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    }
}

/// Internal helper emitted exactly once per petal module: runs the
/// per-fn dispatch closure and delivers its result back to the chain VM.
///
/// On `wasm32` the closure's framed return buffer is delivered via the
/// `chain.petal.return` trap import (success) or its typed error code via
/// `chain.petal.revert` (revert); both diverge, matching the proven
/// hand-written WAT petals the VM dispatcher already drives. On the host
/// the closure runs inside a panic-catching wrapper that appends the
/// encoded returns to a scratch buffer and applies the
/// `Result<(), PetalError>` discriminant.
pub(crate) fn emit_dispatch_helper() -> TokenStream {
    quote! {
        /// Common dispatch wrapper for every wasm-target `__petal_<fn>`
        /// shim in this module. Pulls the framed calldata in via
        /// `chain.msg.calldata.read`, runs the user closure, then delivers
        /// the count-prefixed return envelope through `chain.petal.return`
        /// (a trap the VM treats as success) or, on a typed error, the
        /// error code through `chain.petal.revert`.
        #[cfg(target_arch = "wasm32")]
        #[allow(dead_code)]
        #[inline]
        fn __bloom_dispatch_petal_shim<F>(
            __calldata_offset: i32,
            __calldata_len: i32,
            body: F,
        ) -> i32
        where
            F: FnOnce(&[u8], &mut ::std::vec::Vec<u8>) -> ::core::result::Result<(), ::bloom_resource::PetalError>,
        {
            // Pull the framed calldata in from the host. The VM dispatcher
            // calls us with offset 0 and the full calldata length.
            let __args: ::std::vec::Vec<u8> = if __calldata_len <= 0 {
                ::std::vec::Vec::new()
            } else {
                ::bloom_resource::host::calldata_read(__calldata_offset, __calldata_len as usize)
            };

            let mut __ret_buf: ::std::vec::Vec<u8> = ::std::vec::Vec::new();
            // Wasm32 aborts the instance on panic so unwinding is not
            // available; the user-fn's typed `Result` returns are the only
            // error channel. Both delivery imports trap, so neither arm
            // falls through to the (vestigial) `i32` return.
            match body(&__args, &mut __ret_buf) {
                Ok(()) => ::bloom_resource::host::petal_return(&__ret_buf),
                Err(e) => ::bloom_resource::host::petal_revert(&e.as_i32().to_be_bytes()),
            }
        }

        /// Host-side dispatch wrapper. Same control flow as the wasm
        /// helper but takes safe Rust slices so tests and tooling can
        /// drive the shim without conjuring `i32`-encoded pointers
        /// (which would truncate on 64-bit hosts). Catches panics so a
        /// bug in user code can't take down the test process.
        ///
        /// Returns 0 on success or a positive `PetalError::as_i32()`
        /// code on failure. Encoded return bytes are appended to
        /// `ret_buf`.
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code)]
        #[inline]
        fn __bloom_dispatch_petal_shim_host<F>(
            args: &[u8],
            ret_buf: &mut ::std::vec::Vec<u8>,
            body: F,
        ) -> i32
        where
            F: FnOnce(&[u8], &mut ::std::vec::Vec<u8>) -> ::core::result::Result<(), ::bloom_resource::PetalError>,
        {
            let mut __scratch: ::std::vec::Vec<u8> = ::std::vec::Vec::new();
            // AssertUnwindSafe is fine here: the closure consumes its
            // captures (FnOnce) and any `&mut` borrows it makes are
            // local to its body.
            let __result = ::std::panic::catch_unwind(
                ::std::panic::AssertUnwindSafe(|| body(args, &mut __scratch))
            )
                .unwrap_or(Err(::bloom_resource::PetalError::Aborted));

            match __result {
                Ok(()) => {
                    ret_buf.extend_from_slice(&__scratch);
                    0
                }
                Err(e) => e.as_i32(),
            }
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
    let shim_ident = format_ident!("__bloom_inv_{}", idx);

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
        #[cfg(any(not(target_arch = "wasm32"), not(feature = "no-entrypoint")))]
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
    use bloom_petal_manifest::types::*;

    fn empty_manifest() -> PetalManifestV0 {
        PetalManifestV0 {
            schema_version: SCHEMA_VERSION,
            module_path: "/p".to_string(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        }
    }

    fn empty_shim_ast(name: &str) -> PetalShimAst {
        PetalShimAst {
            fn_name: name.to_string(),
            args: Vec::new(),
            return_ast: None,
            return_tags: Vec::new(),
            is_generic: false,
            generic_names: Vec::new(),
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
        let ast = empty_shim_ast("swap");
        let s = emit_petal_shim(&ast).to_string();
        assert!(s.contains("__petal_swap"));
        assert!(s.contains("extern \"C\""));
        // Chain-VM ABI: the export is the 2-arg
        // `(calldata_offset, calldata_len) -> i32` shape.
        assert!(s.contains("__calldata_offset"));
        assert!(s.contains("__calldata_len"));
        // The shim now dispatches through the helper rather than
        // returning a hard-coded sentinel.
        assert!(s.contains("__bloom_dispatch_petal_shim"));
    }

    #[test]
    fn petal_shim_call_site_uses_user_fn_ident() {
        let ast = empty_shim_ast("mint");
        let s = emit_petal_shim(&ast).to_string();
        // Empty arg list calls `mint()` rather than the macro's
        // internal helper name.
        assert!(s.contains("mint ("));
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

    #[test]
    fn dispatch_helper_defines_local_fn() {
        let s = emit_dispatch_helper().to_string();
        assert!(s.contains("__bloom_dispatch_petal_shim"));
        // wasm path pulls calldata in and delivers via the chain-VM
        // trap imports rather than copying into a ret buffer.
        assert!(s.contains("calldata_read"));
        assert!(s.contains("petal_return"));
        assert!(s.contains("petal_revert"));
        // host path still catches panics so a buggy petal can't take
        // down the test process.
        assert!(s.contains("catch_unwind"));
    }

    #[test]
    fn wrap_object_handle_routes_coin() {
        let ty: Type = syn::parse_str("Coin<U>").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site()), &[]).to_string();
        assert!(s.contains("Coin"));
        assert!(s.contains("from_handle"));
    }

    #[test]
    fn wrap_object_handle_routes_capability() {
        let ty: Type = syn::parse_str("Capability<AdminCap>").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site()), &[]).to_string();
        assert!(s.contains("Capability"));
        assert!(s.contains("from_handle"));
    }

    #[test]
    fn wrap_object_handle_routes_resource_fallback() {
        let ty: Type = syn::parse_str("MyObject").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site()), &[]).to_string();
        assert!(s.contains("Resource"));
        assert!(s.contains("from_handle"));
    }

    #[test]
    fn wrap_object_handle_resource_is_not_double_wrapped() {
        // `Resource<Pool>` must materialize a `Resource::<Pool>`, not a
        // `Resource::<Resource<Pool>>` — the user names the wrapper and the
        // shim local must match the signature exactly (handle/tag model).
        let ty: Type = syn::parse_str("Resource<Pool>").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site()), &[]).to_string();
        assert!(s.contains("Resource"));
        assert!(s.contains("Pool"));
        assert!(s.contains("from_handle"));
        // Exactly one `Resource` mention → no double wrap.
        assert_eq!(s.matches("Resource").count(), 1, "double-wrapped: {s}");
    }

    #[test]
    fn emit_return_write_resource_encodes_object_id() {
        // Object wrappers (incl. Resource) cross command boundaries as
        // their stable 32-byte ObjectId, resolved via `object.id`.
        let ty: Type = syn::parse_str("Resource<Pool>").unwrap();
        let s = emit_return_write(&ty, &quote! { __ret }, &[]).to_string();
        assert!(s.contains("object_id"));
        assert!(s.contains("handle"));
        // Must not fall back to the old `.bytes()` payload encoding.
        assert!(
            !s.contains(". bytes ()"),
            "should not emit payload bytes: {s}"
        );
    }

    #[test]
    fn emit_return_write_coin_encodes_object_id() {
        let ty: Type = syn::parse_str("Coin<USDC>").unwrap();
        let s = emit_return_write(&ty, &quote! { __ret }, &[]).to_string();
        assert!(s.contains("object_id"));
    }

    #[test]
    fn emit_return_write_option_wrapper_emits_present_absent_slot() {
        // `Option<Coin<T>>` → a match: Some writes the ObjectId, None
        // writes a zero-length slot.
        let ty: Type = syn::parse_str("Option<Coin<A>>").unwrap();
        let s = emit_return_write(&ty, &quote! { __ret }, &["A".to_string()]).to_string();
        assert!(s.contains("Some"));
        assert!(s.contains("None"));
        assert!(s.contains("object_id"));
        assert!(s.contains("write_bytes"));
    }

    #[test]
    fn emit_return_write_fallback_erases_generics() {
        // A plain `BloomType` return naming a fn type-param erases it so
        // the non-generic shim names a concrete type.
        let ty: Type = syn::parse_str("Wrapper<T>").unwrap();
        let s = emit_return_write(&ty, &quote! { __ret }, &["T".to_string()]).to_string();
        assert!(s.contains("Erased"));
        assert!(s.contains("canonical_encode"));
    }
}
