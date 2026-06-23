//! Proc-macros for the Bloom local handler petal SDK.

#![deny(unsafe_op_in_unsafe_fn)]

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

/// Mark a local handler function as the `petal_dispatch` entrypoint.
///
/// The annotated function must accept a `DispatchRequest` and return a
/// `DispatchResponse`. The macro preserves the function and emits the v1
/// `petal_alloc` and `petal_dispatch` exports expected by the daemon.
#[proc_macro_attribute]
pub fn petal(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[petal] takes no arguments",
        )
        .to_compile_error()
        .into();
    }

    let input = parse_macro_input!(item as ItemFn);
    let ident = &input.sig.ident;
    let sdk = sdk_crate_path();
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub extern "C" fn petal_alloc(len: usize) -> *mut u8 {
            #sdk::petal_alloc(len)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn petal_dispatch(ptr: i32, len: i32) -> i64 {
            #sdk::dispatch_export(ptr, len, #ident)
        }
    }
    .into()
}

fn sdk_crate_path() -> TokenStream2 {
    match crate_name("bloom-petal-sdk") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::bloom_petal_sdk),
    }
}
