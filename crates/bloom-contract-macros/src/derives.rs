//! `#[derive(AbiEncode)]`, `#[derive(AbiDecode)]`, `#[derive(AbiType)]`.
//!
//! Supported shapes:
//!
//! - Named-field structs: each field encoded/decoded sequentially in source
//!   order.
//! - Tuple structs: same, by positional field order.
//! - Unit structs: zero-byte encoding.
//! - Enums (C-like or payload-bearing): single-byte discriminant + variant
//!   fields. Variant order in the source is the discriminant order.
//! - Newtype tuple structs may opt into pass-through encoding with
//!   `#[abi(transparent)]` — the wrapper encodes exactly like its inner type.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields, Ident, parse_macro_input};

pub fn derive_abi_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_g, ty_g, where_c) = input.generics.split_for_impl();
    let transparent = is_transparent(&input);

    let body = match &input.data {
        Data::Struct(s) => encode_struct(s, transparent),
        Data::Enum(e) => encode_enum(e, name),
        Data::Union(_) => panic!("AbiEncode cannot be derived on unions"),
    };

    quote! {
        impl #impl_g ::bloom_contract::abi::AbiEncode for #name #ty_g #where_c {
            fn encode_into(
                &self,
                enc: &mut ::bloom_contract::abi::Encoder,
            ) -> ::core::result::Result<(), ::bloom_contract::abi::AbiEncodeError> {
                #body
                Ok(())
            }
        }
    }
    .into()
}

pub fn derive_abi_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_g, ty_g, where_c) = input.generics.split_for_impl();
    let transparent = is_transparent(&input);

    let body = match &input.data {
        Data::Struct(s) => decode_struct(s, name, transparent),
        Data::Enum(e) => decode_enum(e, name),
        Data::Union(_) => panic!("AbiDecode cannot be derived on unions"),
    };

    quote! {
        impl #impl_g ::bloom_contract::abi::AbiDecode for #name #ty_g #where_c {
            fn decode(
                buf: &mut ::bloom_contract::abi::Buf<'_>,
            ) -> ::core::result::Result<Self, ::bloom_contract::abi::AbiError> {
                #body
            }
        }
    }
    .into()
}

pub fn derive_abi_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();
    let (impl_g, ty_g, where_c) = input.generics.split_for_impl();
    let transparent = is_transparent(&input);

    let (abi_type_str, schema_expr) = match &input.data {
        Data::Struct(s) => {
            if transparent {
                let ty = transparent_inner_type(s)
                    .expect("transparent struct must have exactly one field");
                (
                    quote! { <#ty as ::bloom_contract::abi::AbiType>::ABI_TYPE },
                    quote! { <#ty as ::bloom_contract::abi::AbiType>::schema() },
                )
            } else {
                let (fields_q, abi_q) = struct_schema(s);
                (
                    quote! { #abi_q },
                    quote! {
                        ::bloom_contract::abi::TypeSchema::Struct {
                            name: #name_str,
                            fields: { let mut v = ::bloom_contract::__private::Vec::new(); #fields_q v },
                        }
                    },
                )
            }
        }
        Data::Enum(e) => {
            let (variants_q, abi_q) = enum_schema(e);
            (
                quote! { #abi_q },
                quote! {
                    ::bloom_contract::abi::TypeSchema::Enum {
                        name: #name_str,
                        variants: { let mut v = ::bloom_contract::__private::Vec::new(); #variants_q v },
                    }
                },
            )
        }
        Data::Union(_) => panic!("AbiType cannot be derived on unions"),
    };

    quote! {
        impl #impl_g ::bloom_contract::abi::AbiType for #name #ty_g #where_c {
            const ABI_TYPE: &'static str = #abi_type_str;
            fn schema() -> ::bloom_contract::abi::TypeSchema {
                #schema_expr
            }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// Struct helpers
// ---------------------------------------------------------------------------

fn is_transparent(input: &DeriveInput) -> bool {
    input.attrs.iter().any(|a| {
        if !a.path().is_ident("abi") {
            return false;
        }
        let mut transparent = false;
        let _ = a.parse_nested_meta(|m| {
            if m.path.is_ident("transparent") {
                transparent = true;
            }
            Ok(())
        });
        transparent
    })
}

fn transparent_inner_type(s: &DataStruct) -> Option<&syn::Type> {
    match &s.fields {
        Fields::Unnamed(u) if u.unnamed.len() == 1 => Some(&u.unnamed.first().unwrap().ty),
        Fields::Named(n) if n.named.len() == 1 => Some(&n.named.first().unwrap().ty),
        _ => None,
    }
}

fn encode_struct(s: &DataStruct, transparent: bool) -> TokenStream2 {
    if transparent {
        return match &s.fields {
            Fields::Unnamed(_) => quote! {
                ::bloom_contract::abi::AbiEncode::encode_into(&self.0, enc)?;
            },
            Fields::Named(n) => {
                let f = n.named.first().unwrap().ident.as_ref().unwrap();
                quote! { ::bloom_contract::abi::AbiEncode::encode_into(&self.#f, enc)?; }
            }
            Fields::Unit => quote! {},
        };
    }
    match &s.fields {
        Fields::Named(n) => {
            let stmts = n.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                quote! { ::bloom_contract::abi::AbiEncode::encode_into(&self.#ident, enc)?; }
            });
            quote! { #(#stmts)* }
        }
        Fields::Unnamed(u) => {
            let stmts = (0..u.unnamed.len()).map(|i| {
                let idx = syn::Index::from(i);
                quote! { ::bloom_contract::abi::AbiEncode::encode_into(&self.#idx, enc)?; }
            });
            quote! { #(#stmts)* }
        }
        Fields::Unit => quote! {},
    }
}

fn decode_struct(s: &DataStruct, name: &Ident, transparent: bool) -> TokenStream2 {
    if transparent {
        return match &s.fields {
            Fields::Unnamed(u) => {
                let ty = &u.unnamed.first().unwrap().ty;
                quote! {
                    let inner = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?;
                    Ok(Self(inner))
                }
            }
            Fields::Named(n) => {
                let f = n.named.first().unwrap();
                let ident = f.ident.as_ref().unwrap();
                let ty = &f.ty;
                quote! {
                    let inner = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?;
                    Ok(Self { #ident: inner })
                }
            }
            Fields::Unit => quote! { Ok(Self) },
        };
    }
    match &s.fields {
        Fields::Named(n) => {
            let reads = n.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                let ty = &f.ty;
                quote! { let #ident = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?; }
            });
            let assigns = n.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                quote! { #ident }
            });
            quote! {
                #(#reads)*
                Ok(#name { #(#assigns),* })
            }
        }
        Fields::Unnamed(u) => {
            let reads = u.unnamed.iter().enumerate().map(|(i, f)| {
                let ident = syn::Ident::new(&format!("__f{i}"), proc_macro2::Span::call_site());
                let ty = &f.ty;
                quote! { let #ident = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?; }
            });
            let idents = (0..u.unnamed.len())
                .map(|i| syn::Ident::new(&format!("__f{i}"), proc_macro2::Span::call_site()));
            quote! {
                #(#reads)*
                Ok(#name(#(#idents),*))
            }
        }
        Fields::Unit => quote! { Ok(#name) },
    }
}

fn struct_schema(s: &DataStruct) -> (TokenStream2, TokenStream2) {
    match &s.fields {
        Fields::Named(n) => {
            let entries = n.named.iter().map(|f| {
                let ident_str = f.ident.as_ref().unwrap().to_string();
                let ty = &f.ty;
                quote! {
                    v.push((#ident_str, <#ty as ::bloom_contract::abi::AbiType>::schema()));
                }
            });
            (quote! { #(#entries)* }, quote! { "struct" })
        }
        Fields::Unnamed(u) => {
            let entries = u.unnamed.iter().enumerate().map(|(i, f)| {
                let ident_str =
                    ::std::boxed::Box::leak(format!("_{i}").into_boxed_str()) as &'static str;
                let ty = &f.ty;
                quote! {
                    v.push((#ident_str, <#ty as ::bloom_contract::abi::AbiType>::schema()));
                }
            });
            (quote! { #(#entries)* }, quote! { "struct" })
        }
        Fields::Unit => (quote! {}, quote! { "struct" }),
    }
}

// ---------------------------------------------------------------------------
// Enum helpers
// ---------------------------------------------------------------------------

fn encode_enum(e: &DataEnum, name: &Ident) -> TokenStream2 {
    let arms = e.variants.iter().enumerate().map(|(i, v)| {
        let v_ident = &v.ident;
        let disc = i as u8;
        match &v.fields {
            Fields::Unit => quote! {
                #name::#v_ident => {
                    enc.push_bytes(&[#disc]);
                }
            },
            Fields::Unnamed(u) => {
                let binds = (0..u.unnamed.len())
                    .map(|j| syn::Ident::new(&format!("__v{j}"), proc_macro2::Span::call_site()))
                    .collect::<Vec<_>>();
                let writes = binds.iter().map(|b| {
                    quote! {
                        ::bloom_contract::abi::AbiEncode::encode_into(#b, enc)?;
                    }
                });
                quote! {
                    #name::#v_ident(#(#binds),*) => {
                        enc.push_bytes(&[#disc]);
                        #(#writes)*
                    }
                }
            }
            Fields::Named(n) => {
                let binds = n
                    .named
                    .iter()
                    .map(|f| f.ident.clone().unwrap())
                    .collect::<Vec<_>>();
                let writes = binds.iter().map(|b| {
                    quote! {
                        ::bloom_contract::abi::AbiEncode::encode_into(#b, enc)?;
                    }
                });
                quote! {
                    #name::#v_ident { #(#binds),* } => {
                        enc.push_bytes(&[#disc]);
                        #(#writes)*
                    }
                }
            }
        }
    });
    quote! { match self { #(#arms,)* } }
}

fn decode_enum(e: &DataEnum, name: &Ident) -> TokenStream2 {
    let arms = e.variants.iter().enumerate().map(|(i, v)| {
        let v_ident = &v.ident;
        let disc = i as u8;
        match &v.fields {
            Fields::Unit => quote! {
                #disc => Ok(#name::#v_ident)
            },
            Fields::Unnamed(u) => {
                let reads = u.unnamed.iter().enumerate().map(|(j, f)| {
                    let id = syn::Ident::new(&format!("__v{j}"), proc_macro2::Span::call_site());
                    let ty = &f.ty;
                    quote! { let #id = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?; }
                });
                let idents = (0..u.unnamed.len())
                    .map(|j| syn::Ident::new(&format!("__v{j}"), proc_macro2::Span::call_site()));
                quote! {
                    #disc => {
                        #(#reads)*
                        Ok(#name::#v_ident(#(#idents),*))
                    }
                }
            }
            Fields::Named(n) => {
                let reads = n.named.iter().map(|f| {
                    let ident = f.ident.as_ref().unwrap();
                    let ty = &f.ty;
                    quote! { let #ident = <#ty as ::bloom_contract::abi::AbiDecode>::decode(buf)?; }
                });
                let idents = n.named.iter().map(|f| f.ident.as_ref().unwrap());
                quote! {
                    #disc => {
                        #(#reads)*
                        Ok(#name::#v_ident { #(#idents),* })
                    }
                }
            }
        }
    });
    quote! {
        let tag = <u8 as ::bloom_contract::abi::AbiDecode>::decode(buf)?;
        match tag {
            #(#arms,)*
            other => Err(::bloom_contract::abi::AbiError::InvalidDiscriminant(other)),
        }
    }
}

fn enum_schema(e: &DataEnum) -> (TokenStream2, TokenStream2) {
    let entries = e.variants.iter().map(|v| {
        let v_str = v.ident.to_string();
        let payload = match &v.fields {
            Fields::Unit => quote! { ::bloom_contract::__private::Vec::new() },
            Fields::Unnamed(u) => {
                let pushes = u.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote! { tmp.push(<#ty as ::bloom_contract::abi::AbiType>::schema()); }
                });
                quote! { {
                    let mut tmp = ::bloom_contract::__private::Vec::new();
                    #(#pushes)*
                    tmp
                } }
            }
            Fields::Named(n) => {
                let pushes = n.named.iter().map(|f| {
                    let ty = &f.ty;
                    quote! { tmp.push(<#ty as ::bloom_contract::abi::AbiType>::schema()); }
                });
                quote! { {
                    let mut tmp = ::bloom_contract::__private::Vec::new();
                    #(#pushes)*
                    tmp
                } }
            }
        };
        quote! { v.push((#v_str, #payload)); }
    });
    (quote! { #(#entries)* }, quote! { "enum" })
}
