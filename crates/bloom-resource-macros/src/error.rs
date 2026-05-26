//! `syn::Error` helpers used by every macro module.
//!
//! Every macro returns a `proc_macro2::TokenStream` on success; on
//! failure it emits a `syn::Error::into_compile_error()` token tree so
//! the user sees a normal compile-time diagnostic with the right span.

use proc_macro2::TokenStream;
use quote::ToTokens;

/// Build a `syn::Error` anchored at `span` with the given `message`.
pub fn err_spanned<T: ToTokens, S: Into<String>>(span: &T, message: S) -> syn::Error {
    syn::Error::new_spanned(span, message.into())
}

/// Convenience: produce the compile-error `TokenStream` directly from a
/// span + message pair.
pub fn compile_error<T: ToTokens, S: Into<String>>(span: &T, message: S) -> TokenStream {
    err_spanned(span, message).to_compile_error()
}
