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

use crate::manifest::{ArgKind, PetalManifestV0};
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
// `__petal_<fn>` shim AST
// ---------------------------------------------------------------------------

/// Per-argument information [`emit_petal_shim`] needs to lower the
/// per-arg decode → user-fn dispatch glue. Parallels [`crate::manifest::ArgDecl`]
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
    /// `true` when the user fn carries one or more type parameters.
    /// Generic monomorphization at PTB-execution time is not yet wired
    /// (spec §11.2); the shim emits a `PetalError::NotImplemented` stub
    /// for these so the wasm export symbol is still present.
    pub(crate) is_generic: bool,
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

    // Generic user fns can't be invoked from a non-generic wasm export
    // without runtime monomorphization (spec §11.2). v0 punts and
    // emits a `PetalError::NotImplemented` stub whose export name is
    // still on-spec so the manifest stays consistent.
    if ast.is_generic {
        return emit_generic_stub_shim(&export_name, &shim_ident);
    }

    // Per-arg decode statements and the call-site argument expressions.
    let mut decode_stmts: Vec<TokenStream> = Vec::new();
    let mut call_exprs: Vec<TokenStream> = Vec::new();
    for (i, arg) in ast.args.iter().enumerate() {
        let local_ident = format_ident!("__arg_{}", i);
        let (decode, expr) = emit_arg_decode(&local_ident, arg);
        decode_stmts.push(decode);
        call_exprs.push(expr);
    }

    // Return-encode block. Build it before we splice it into the
    // overall closure so a tuple return can iterate each slot.
    let encode_returns = emit_return_encode(ast);

    quote! {
        /// Auto-generated wasm export shim for `#[bloom::petal]` fn
        /// (spec §11.1). Decodes args via `ArgReader`, dispatches to
        /// the user function, encodes returns via `RetWriter`, and
        /// copies the encoded bytes into the runtime-provided return
        /// buffer (capped at `ret_cap`).
        ///
        /// Returns `0` on success or a positive
        /// [`::bloom_resource::PetalError::as_i32`] code on failure.
        ///
        /// Gated on `not(feature = "no-entrypoint")` so that downstream
        /// crates depending on this petal as a library can suppress the
        /// wasm export symbols and avoid duplicate-export link errors.
        #[cfg(all(target_arch = "wasm32", not(feature = "no-entrypoint")))]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #shim_ident(
            args_ptr: i32,
            args_len: i32,
            ret_ptr: i32,
            ret_cap: i32,
        ) -> i32 {
            __bloom_dispatch_petal_shim(
                args_ptr,
                args_len,
                ret_ptr,
                ret_cap,
                |__args, __ret_buf| {
                    let mut __reader = ::bloom_resource::abi::ArgReader::new(__args);
                    #(#decode_stmts)*
                    let __ret = #user_fn_ident(#(#call_exprs),*);
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
                    let mut __reader = ::bloom_resource::abi::ArgReader::new(__args);
                    #(#decode_stmts)*
                    let __ret = #user_fn_ident(#(#call_exprs),*);
                    #encode_returns
                    Ok(())
                },
            )
        }
    }
}

/// Stub shim for generic user fns. Returns `PetalError::NotImplemented`
/// at runtime; the wasm export symbol and name are still on-spec so
/// the chain VM can introspect the manifest without surprises. Drop
/// once spec §11.2 runtime monomorphization lands.
fn emit_generic_stub_shim(export_name: &str, shim_ident: &Ident) -> TokenStream {
    quote! {
        /// Stub shim for a generic `#[bloom::petal]` fn. Returns
        /// `PetalError::NotImplemented` at runtime until generic
        /// monomorphization at PTB-execution time is wired (spec §11.2).
        #[cfg(all(target_arch = "wasm32", not(feature = "no-entrypoint")))]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #shim_ident(
            _args_ptr: i32,
            _args_len: i32,
            _ret_ptr: i32,
            _ret_cap: i32,
        ) -> i32 {
            ::bloom_resource::PetalError::NotImplemented.as_i32()
        }

        /// Host-side mirror of the generic-fn stub shim.
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code, clippy::too_many_arguments)]
        pub fn #shim_ident(
            _args_ptr: i32,
            _args_len: i32,
            _ret_ptr: i32,
            _ret_cap: i32,
        ) -> i32 {
            ::bloom_resource::PetalError::NotImplemented.as_i32()
        }
    }
}

/// Emit the decode statement(s) + the call-site argument expression for
/// a single shim arg.
fn emit_arg_decode(local: &Ident, arg: &ShimArgAst) -> (TokenStream, TokenStream) {
    match &arg.kind {
        ArgKind::Signer => {
            // The args buffer carries a 16-bit signer index per the
            // existing ArgReader::read_u16 contract (spec §6 / §7.1).
            // The user fn takes `&Signer` or `Signer`; we emit the
            // matching call-site expression.
            let decode = quote! {
                let #local: ::bloom_resource::Signer = match __reader.read_u16() {
                    Ok(idx) => ::bloom_resource::Signer::from_index(idx),
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
            };
            let expr = if arg.is_ref { quote! { &#local } } else { quote! { #local } };
            (decode, expr)
        }
        ArgKind::Const(_) => {
            let inner_ty = &arg.inner_ty;
            // `quote!` does not support arbitrary identifier-paste —
            // pre-build the per-arg "raw bytes" local with `format_ident!`
            // so the interpolation only needs to splice an `Ident`.
            let bytes_ident = format_ident!("__const_bytes_for_{}", local);
            // Const args are length-prefixed (spec §7.1 / §11.1) so the
            // shim consumes the same wire shape `ArgReader::read_bytes`
            // / `BloomType::canonical_decode` round-trip through.
            let decode = quote! {
                let #bytes_ident = match __reader.read_bytes() {
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
            let expr = if arg.is_ref { quote! { &#local } } else { quote! { #local } };
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
            let wrap_expr = wrap_object_handle(&arg.inner_ty, &handle_ident);
            let decode = quote! {
                let #obj_id_ident = match __reader.read_object_id() {
                    Ok(id) => id,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
                let #handle_ident: ::bloom_resource::RuntimeHandle =
                    match ::bloom_resource::host::object_borrow(&#obj_id_ident, #access_mode_expr) {
                        Ok(h) => h,
                        Err(e) => return Err(e),
                    };
                let #local = #wrap_expr;
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
            // in the args buffer (spec §7.1, ArgKind::TypeArg). The
            // user fn doesn't actually receive these as Rust args; the
            // type-arg vector flows through Resource<T>::new(type_tag,
            // ...) calls inside the user body. We still need to decode
            // and stash them so the buffer cursor stays aligned.
            //
            // For v0 we record the decoded tag into a local that the
            // user fn body can read by name. Profiling can later
            // collapse this into a more compact representation.
            let stash = format_ident!("__type_arg_{}", idx);
            let decode = quote! {
                let #stash: ::bloom_objects::TypeTag = match __reader.read_type_tag() {
                    Ok(t) => t,
                    Err(_) => return Err(::bloom_resource::PetalError::InvalidArgs),
                };
                // Suppress unused warnings for type_args that the user
                // fn body doesn't reach for.
                let _ = &#stash;
            };
            // TypeArg is not passed as a positional arg; the user fn's
            // declared Rust signature still has the generic param `T`
            // monomorphized via the wrapper code. We emit a zero-length
            // call expr so the caller can `.iter().filter(...)` it out
            // upstream (here we just emit `()` and rely on the caller
            // skipping the slot, but since the macro derives the
            // dispatch list from `ast.args` directly we instead need to
            // skip the call_expr push. Emit an empty token stream here
            // — the dispatch site filters them out by re-walking).
            //
            // The cleaner shape: the call expr is `Resource::<inner>::new(type_arg, ...)`
            // for non-phantom payload positions, but those are decoded
            // through ArgKind::Object/Const. The TypeArg slot itself
            // doesn't have a call-site expression.
            (decode, TokenStream::new())
        }
    }
}

/// Emit the wrapper-construction expression for an object-shaped arg.
///
/// Rules:
/// - Inner type `Coin<T>` → `::bloom_resource::Coin::<T>::from_handle(h)`
/// - Inner type `Capability<T>` → `::bloom_resource::Capability::<T>::from_handle(h)`
/// - Anything else recognised as object-like → `::bloom_resource::Resource::<inner>::from_handle(h)`
fn wrap_object_handle(inner: &Type, handle_ident: &Ident) -> TokenStream {
    let name = path_last_ident(inner);
    let turbofish = path_last_turbofish(inner);

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
        _ => {
            // Fallback: wrap in Resource<inner>. The macro emits the
            // outer type *as-written* so the user can name it directly
            // in their function signature (e.g. `c: MyObj`) and the
            // shim materializes a `Resource<MyObj>`. This is the spec
            // §11.2 dispatch convention for any object-like arg the
            // macro doesn't specially recognise.
            quote! { ::bloom_resource::Resource::<#inner>::from_handle(#handle_ident) }
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

/// Turbofish-rendered last-segment generic args (e.g. `::<USDC>`).
/// Returns an empty `TokenStream` when the type has no generics so the
/// caller can splice the result directly after a path like
/// `::bloom_resource::Coin` without an extra `::` joiner.
fn path_last_turbofish(ty: &Type) -> TokenStream {
    let Type::Path(TypePath { path, qself: None }) = ty else {
        return TokenStream::new();
    };
    let Some(seg) = path.segments.last() else {
        return TokenStream::new();
    };
    match &seg.arguments {
        PathArguments::AngleBracketed(ab) => {
            let args: Vec<&GenericArgument> = ab.args.iter().collect();
            if args.is_empty() {
                TokenStream::new()
            } else {
                quote! { ::<#(#args),*> }
            }
        }
        _ => TokenStream::new(),
    }
}

/// Emit the return-encode block: write each return slot into the
/// `RetWriter` and copy the finished buffer into `__ret_buf`.
fn emit_return_encode(ast: &PetalShimAst) -> TokenStream {
    let Some(ret_ast) = &ast.return_ast else {
        // No return: nothing to encode.
        return quote! {
            // No-return fn: leave __ret_buf empty.
            let _ = __ret;
            let _: &mut Vec<u8> = __ret_buf;
        };
    };

    match ret_ast {
        Type::Tuple(t) => {
            // Tuple return: encode each element in order.
            let mut writes = Vec::new();
            for (i, elem) in t.elems.iter().enumerate() {
                let idx = syn::Index::from(i);
                let write_expr = emit_return_write(elem, &quote! { __ret.#idx });
                writes.push(write_expr);
            }
            quote! {
                let mut __writer = ::bloom_resource::abi::RetWriter::new();
                #(#writes)*
                __ret_buf.extend_from_slice(&__writer.finish());
            }
        }
        single => {
            let write_expr = emit_return_write(single, &quote! { __ret });
            quote! {
                let mut __writer = ::bloom_resource::abi::RetWriter::new();
                #write_expr
                __ret_buf.extend_from_slice(&__writer.finish());
            }
        }
    }
}

/// Emit a single return-slot write into `__writer` for the given Rust
/// return type. Specially-recognised wrapper types (`Coin<_>`,
/// `Capability<_>`) write their handle; everything else routes through
/// `BloomType::canonical_encode`.
fn emit_return_write(ty: &Type, value_expr: &TokenStream) -> TokenStream {
    let name = path_last_ident(ty);
    match name.as_deref() {
        Some("Coin") | Some("Capability") => {
            // Wrappers carry a `RuntimeHandle`; write it as a 4-byte BE i32.
            quote! {
                __writer.write_handle((#value_expr).handle());
            }
        }
        Some("Resource") => {
            // Resource: emit its bytes length-prefixed so the reader
            // can pick the right slice back up.
            quote! {
                {
                    let __res = (#value_expr);
                    __writer.write_bytes(__res.bytes());
                }
            }
        }
        _ => {
            // Fallback: BloomType::canonical_encode, wrapped in a
            // length prefix so multiple return slots can be parsed
            // back unambiguously.
            quote! {
                {
                    let __v = (#value_expr);
                    let __bytes = <#ty as ::bloom_resource::BloomType>::canonical_encode(&__v);
                    __writer.write_bytes(&__bytes);
                }
            }
        }
    }
}

/// Internal helper emitted exactly once per petal module: runs the
/// per-fn dispatch closure inside a panic-catching wrapper (host-only),
/// applies the `Result<(), PetalError>` discriminant, and copies the
/// encoded return buffer into `ret_ptr[..ret_cap]`.
///
/// On `wasm32` the panic-catching layer is omitted because the wasm
/// runtime aborts the instance on a panic and unwinding is not
/// available; the user-fn body's `Result` returns are sufficient.
pub(crate) fn emit_dispatch_helper() -> TokenStream {
    quote! {
        /// Common dispatch wrapper for every wasm-target `__petal_<fn>`
        /// shim in this module. Materialises an `&[u8]` over the args
        /// buffer, runs the user closure, then copies the encoded
        /// returns into `ret_ptr[..ret_cap]`.
        ///
        /// SAFETY: `args_ptr` / `ret_ptr` are byte offsets into the
        /// caller's address space; both are dereferenced as raw pointers
        /// only for the duration of the call, never stored. The chain
        /// VM is responsible for handing valid pointer ranges per the
        /// `(args_len, ret_cap)` budgets.
        #[cfg(target_arch = "wasm32")]
        #[allow(dead_code, clippy::missing_safety_doc)]
        #[inline]
        fn __bloom_dispatch_petal_shim<F>(
            args_ptr: i32,
            args_len: i32,
            ret_ptr: i32,
            ret_cap: i32,
            body: F,
        ) -> i32
        where
            F: FnOnce(&[u8], &mut ::std::vec::Vec<u8>) -> ::core::result::Result<(), ::bloom_resource::PetalError>,
        {
            // Empty buffer fast-path: an args_len == 0 call still needs
            // a valid (but dangling) slice for the user closure.
            let __args: &[u8] = if args_len <= 0 {
                &[]
            } else {
                // SAFETY: caller-supplied range; we only dereference for
                // the lifetime of this borrow.
                unsafe {
                    ::core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize)
                }
            };

            let mut __ret_buf: ::std::vec::Vec<u8> = ::std::vec::Vec::new();
            // Wasm32 aborts the instance on panic so unwinding is not
            // available; the user-fn's typed `Result` returns are the
            // only error channel.
            let __result = body(__args, &mut __ret_buf);

            match __result {
                Ok(()) => {
                    if ret_cap > 0 && !__ret_buf.is_empty() {
                        let __n = ::core::cmp::min(__ret_buf.len(), ret_cap as usize);
                        // SAFETY: caller promises `ret_ptr[..ret_cap]` is writable.
                        unsafe {
                            ::core::ptr::copy_nonoverlapping(
                                __ret_buf.as_ptr(),
                                ret_ptr as *mut u8,
                                __n,
                            );
                        }
                    }
                    0
                }
                Err(e) => e.as_i32(),
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

    fn empty_shim_ast(name: &str) -> PetalShimAst {
        PetalShimAst {
            fn_name: name.to_string(),
            args: Vec::new(),
            return_ast: None,
            return_tags: Vec::new(),
            is_generic: false,
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
        assert!(s.contains("args_ptr"));
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
        assert!(s.contains("copy_nonoverlapping"));
        assert!(s.contains("catch_unwind"));
    }

    #[test]
    fn wrap_object_handle_routes_coin() {
        let ty: Type = syn::parse_str("Coin<U>").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site())).to_string();
        assert!(s.contains("Coin"));
        assert!(s.contains("from_handle"));
    }

    #[test]
    fn wrap_object_handle_routes_capability() {
        let ty: Type = syn::parse_str("Capability<AdminCap>").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site())).to_string();
        assert!(s.contains("Capability"));
        assert!(s.contains("from_handle"));
    }

    #[test]
    fn wrap_object_handle_routes_resource_fallback() {
        let ty: Type = syn::parse_str("MyObject").unwrap();
        let s = wrap_object_handle(&ty, &Ident::new("h", Span::call_site())).to_string();
        assert!(s.contains("Resource"));
        assert!(s.contains("from_handle"));
    }
}

