//! `#[derive(BloomType)]` support for plain value structs/enums.

use bloom_petal_manifest::types::{
    DataTypeDecl, EnumTypeDecl, FieldDecl, TypeParamDecl, TypeParamKind, VariantDecl,
    VariantFieldsDecl,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, GenericParam, Generics, ItemEnum, ItemStruct,
    Meta, Path, Type, parse_quote,
};

use crate::ast::{attr_is_named, struct_name};
use crate::error::err_spanned;
use crate::type_tag::TypeTagCtx;

/// Macro entry for `#[derive(BloomType)]`.
pub(crate) fn expand(item: proc_macro2::TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(item)?;
    match &input.data {
        Data::Struct(data) => emit_struct_impl(&input.ident, &input.generics, &data.fields, false),
        Data::Enum(data) => emit_enum_impl(&input, &data.variants),
        Data::Union(_) => Err(err_spanned(
            &input.ident,
            "`BloomType` cannot be derived for unions",
        )),
    }
}

/// Emit a `BloomType` impl for a struct item.
pub(crate) fn emit_struct_impl_for_item(
    item: &ItemStruct,
    skip_phantom_data: bool,
) -> syn::Result<TokenStream> {
    emit_struct_impl(&item.ident, &item.generics, &item.fields, skip_phantom_data)
}

fn emit_struct_impl(
    name: &syn::Ident,
    generics: &Generics,
    fields: &Fields,
    skip_phantom_data: bool,
) -> syn::Result<TokenStream> {
    ensure_type_generics_only(generics)?;
    let impl_generics = bloom_type_generics(generics);
    let (_, ty_generics, where_clause) = impl_generics.split_for_impl();
    let (impl_generics, _, _) = impl_generics.split_for_impl();
    let encode_fields = encode_fields(fields, skip_phantom_data);
    let decode_body = decode_struct_body(fields, skip_phantom_data)?;
    let type_tag = self_type_tag_expr(name, generics);

    Ok(quote! {
        impl #impl_generics ::bloom_resource::BloomType for #name #ty_generics #where_clause {
            fn canonical_encode(&self) -> ::std::vec::Vec<u8> {
                let mut __out = ::std::vec::Vec::new();
                #(#encode_fields)*
                __out
            }

            fn canonical_decode(buf: &[u8]) -> ::core::result::Result<Self, ::bloom_resource::AbiError> {
                let mut __cursor = buf;
                let __value = <Self as ::bloom_resource::BloomType>::canonical_decode_from(&mut __cursor)?;
                if __cursor.is_empty() {
                    Ok(__value)
                } else {
                    Err(::bloom_resource::AbiError::TrailingBytes {
                        remaining: __cursor.len(),
                    })
                }
            }

            fn canonical_decode_from(
                buf: &mut &[u8],
            ) -> ::core::result::Result<Self, ::bloom_resource::AbiError> {
                #decode_body
            }

            fn type_tag() -> ::bloom_resource::TypeTag {
                #type_tag
            }
        }
    })
}

fn emit_enum_impl(
    input: &DeriveInput,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::Result<TokenStream> {
    ensure_type_generics_only(&input.generics)?;
    let name = &input.ident;
    let impl_generics = bloom_type_generics(&input.generics);
    let (_, ty_generics, where_clause) = impl_generics.split_for_impl();
    let (impl_generics, _, _) = impl_generics.split_for_impl();
    let type_tag = self_type_tag_expr(name, &input.generics);

    let encode_arms = variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| encode_variant_arm(name, idx as u64, variant))
        .collect::<syn::Result<Vec<_>>>()?;
    let decode_arms = variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| decode_variant_arm(idx as u64, variant))
        .collect::<syn::Result<Vec<_>>>()?;
    let variant_count = variants.len();

    Ok(quote! {
        impl #impl_generics ::bloom_resource::BloomType for #name #ty_generics #where_clause {
            fn canonical_encode(&self) -> ::std::vec::Vec<u8> {
                let mut __out = ::std::vec::Vec::new();
                match self {
                    #(#encode_arms)*
                }
                __out
            }

            fn canonical_decode(buf: &[u8]) -> ::core::result::Result<Self, ::bloom_resource::AbiError> {
                let mut __cursor = buf;
                let __value = <Self as ::bloom_resource::BloomType>::canonical_decode_from(&mut __cursor)?;
                if __cursor.is_empty() {
                    Ok(__value)
                } else {
                    Err(::bloom_resource::AbiError::TrailingBytes {
                        remaining: __cursor.len(),
                    })
                }
            }

            fn canonical_decode_from(
                buf: &mut &[u8],
            ) -> ::core::result::Result<Self, ::bloom_resource::AbiError> {
                let __disc = ::bloom_resource::read_uleb128(buf)
                    .map_err(|e| ::bloom_resource::AbiError::ValueCodec(e.to_string()))?;
                match __disc {
                    #(#decode_arms)*
                    other => Err(::bloom_resource::AbiError::ValueCodec(
                        format!("enum discriminant {} out of range {}", other, #variant_count)
                    )),
                }
            }

            fn type_tag() -> ::bloom_resource::TypeTag {
                #type_tag
            }
        }
    })
}

fn encode_fields(fields: &Fields, skip_phantom_data: bool) -> Vec<TokenStream> {
    field_accessors(fields, skip_phantom_data)
        .into_iter()
        .map(|(ty, access)| {
            quote! {
                __out.extend_from_slice(
                    &<#ty as ::bloom_resource::BloomType>::canonical_encode(#access)
                );
            }
        })
        .collect()
}

fn decode_struct_body(fields: &Fields, skip_phantom_data: bool) -> syn::Result<TokenStream> {
    Ok(match fields {
        Fields::Named(named) => {
            let entries = named
                .named
                .iter()
                .map(|field| {
                    let ident = field.ident.as_ref().expect("named field");
                    if skip_phantom_data && is_phantom_data_type(&field.ty) {
                        quote! { #ident: ::core::marker::PhantomData, }
                    } else {
                        let ty = &field.ty;
                        quote! {
                            #ident: <#ty as ::bloom_resource::BloomType>::canonical_decode_from(buf)?,
                        }
                    }
                })
                .collect::<Vec<_>>();
            quote! { Ok(Self { #(#entries)* }) }
        }
        Fields::Unnamed(unnamed) => {
            let entries = unnamed
                .unnamed
                .iter()
                .map(|field| {
                    if skip_phantom_data && is_phantom_data_type(&field.ty) {
                        quote! { ::core::marker::PhantomData, }
                    } else {
                        let ty = &field.ty;
                        quote! {
                            <#ty as ::bloom_resource::BloomType>::canonical_decode_from(buf)?,
                        }
                    }
                })
                .collect::<Vec<_>>();
            quote! { Ok(Self( #(#entries)* )) }
        }
        Fields::Unit => quote! { Ok(Self) },
    })
}

fn encode_variant_arm(
    enum_name: &syn::Ident,
    idx: u64,
    variant: &syn::Variant,
) -> syn::Result<TokenStream> {
    let vname = &variant.ident;
    Ok(match &variant.fields {
        Fields::Unit => quote! {
            #enum_name::#vname => {
                ::bloom_resource::write_uleb128(#idx, &mut __out);
            }
        },
        Fields::Unnamed(unnamed) => {
            let vars = (0..unnamed.unnamed.len())
                .map(|i| format_ident!("__field_{i}"))
                .collect::<Vec<_>>();
            let writes = unnamed
                .unnamed
                .iter()
                .zip(vars.iter())
                .map(|(field, var)| {
                    let ty = &field.ty;
                    quote! {
                        __out.extend_from_slice(
                            &<#ty as ::bloom_resource::BloomType>::canonical_encode(#var)
                        );
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                #enum_name::#vname( #(#vars),* ) => {
                    ::bloom_resource::write_uleb128(#idx, &mut __out);
                    #(#writes)*
                }
            }
        }
        Fields::Named(named) => {
            let vars = named
                .named
                .iter()
                .map(|f| f.ident.as_ref().expect("named field").clone())
                .collect::<Vec<_>>();
            let writes = named
                .named
                .iter()
                .map(|field| {
                    let ident = field.ident.as_ref().expect("named field");
                    let ty = &field.ty;
                    quote! {
                        __out.extend_from_slice(
                            &<#ty as ::bloom_resource::BloomType>::canonical_encode(#ident)
                        );
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                #enum_name::#vname { #(#vars),* } => {
                    ::bloom_resource::write_uleb128(#idx, &mut __out);
                    #(#writes)*
                }
            }
        }
    })
}

fn decode_variant_arm(idx: u64, variant: &syn::Variant) -> syn::Result<TokenStream> {
    let vname = &variant.ident;
    Ok(match &variant.fields {
        Fields::Unit => quote! {
            #idx => Ok(Self::#vname),
        },
        Fields::Unnamed(unnamed) => {
            let entries = unnamed
                .unnamed
                .iter()
                .map(|field| {
                    let ty = &field.ty;
                    quote! { <#ty as ::bloom_resource::BloomType>::canonical_decode_from(buf)?, }
                })
                .collect::<Vec<_>>();
            quote! {
                #idx => Ok(Self::#vname( #(#entries)* )),
            }
        }
        Fields::Named(named) => {
            let entries = named
                .named
                .iter()
                .map(|field| {
                    let ident = field.ident.as_ref().expect("named field");
                    let ty = &field.ty;
                    quote! {
                        #ident: <#ty as ::bloom_resource::BloomType>::canonical_decode_from(buf)?,
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                #idx => Ok(Self::#vname { #(#entries)* }),
            }
        }
    })
}

fn field_accessors(fields: &Fields, skip_phantom_data: bool) -> Vec<(&Type, TokenStream)> {
    match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .filter(|field| !(skip_phantom_data && is_phantom_data_type(&field.ty)))
            .map(|field| {
                let ident = field.ident.as_ref().expect("named field");
                (&field.ty, quote! { &self.#ident })
            })
            .collect(),
        Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .filter(|(_, field)| !(skip_phantom_data && is_phantom_data_type(&field.ty)))
            .map(|(idx, field)| {
                let idx = syn::Index::from(idx);
                (&field.ty, quote! { &self.#idx })
            })
            .collect(),
        Fields::Unit => Vec::new(),
    }
}

pub(crate) fn is_phantom_data_type(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "PhantomData")
}

fn self_type_tag_expr(name: &syn::Ident, generics: &Generics) -> TokenStream {
    let type_name = name.to_string();
    let type_args = generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => {
                let ident = &t.ident;
                Some(quote! { <#ident as ::bloom_resource::BloomType>::type_tag() })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    quote! {
        ::bloom_resource::TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: #type_name.to_string(),
            type_args: vec![#(#type_args),*],
        }
    }
}

fn bloom_type_generics(generics: &Generics) -> Generics {
    let mut out = generics.clone();
    for param in out.type_params_mut() {
        param.bounds.push(parse_quote!(::bloom_resource::BloomType));
    }
    out
}

fn ensure_type_generics_only(generics: &Generics) -> syn::Result<()> {
    for param in &generics.params {
        if !matches!(param, GenericParam::Type(_)) {
            return Err(err_spanned(
                param,
                "`BloomType` derive supports type parameters only",
            ));
        }
    }
    Ok(())
}

/// True iff an item has `#[derive(BloomType)]`.
pub(crate) fn has_bloom_type_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr_is_named(attr, "derive") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return false;
        };
        let Ok(paths) = list
            .parse_args_with(syn::punctuated::Punctuated::<Path, syn::Token![,]>::parse_terminated)
        else {
            return false;
        };
        paths
            .iter()
            .any(|p| p.segments.last().is_some_and(|s| s.ident == "BloomType"))
    })
}

/// Build a manifest declaration for a derived plain data struct.
pub(crate) fn build_data_decl(item: &ItemStruct) -> syn::Result<DataTypeDecl> {
    let (type_params, generic_names) = type_params(&item.generics)?;
    let fields = fields_decl(&item.fields, &generic_names)?;
    Ok(DataTypeDecl {
        name: struct_name(item),
        type_params,
        fields,
    })
}

/// Build a manifest declaration for a derived plain enum.
pub(crate) fn build_enum_decl(item: &ItemEnum) -> syn::Result<EnumTypeDecl> {
    let (type_params, generic_names) = type_params(&item.generics)?;
    let ctx = TypeTagCtx::from_generic_names(generic_names.iter().cloned());
    let variants = item
        .variants
        .iter()
        .map(|variant| {
            let fields = match &variant.fields {
                Fields::Unit => VariantFieldsDecl::Unit,
                Fields::Unnamed(unnamed) => {
                    for field in &unnamed.unnamed {
                        crate::type_tag::reject_plain_generic_in_payload(
                            &field.ty,
                            &generic_names,
                        )?;
                    }
                    VariantFieldsDecl::Tuple(
                        unnamed
                            .unnamed
                            .iter()
                            .map(|field| ctx.lower(&field.ty))
                            .collect::<syn::Result<Vec<_>>>()?,
                    )
                }
                Fields::Named(named) => VariantFieldsDecl::Struct(named_fields_decl(
                    &named.named,
                    &ctx,
                    &generic_names,
                )?),
            };
            Ok(VariantDecl {
                name: variant.ident.to_string(),
                fields,
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(EnumTypeDecl {
        name: item.ident.to_string(),
        type_params,
        variants,
    })
}

fn type_params(generics: &Generics) -> syn::Result<(Vec<TypeParamDecl>, Vec<String>)> {
    ensure_type_generics_only(generics)?;
    let mut decls = Vec::new();
    let mut names = Vec::new();
    for param in &generics.params {
        let GenericParam::Type(ty) = param else {
            unreachable!("checked by ensure_type_generics_only");
        };
        let name = ty.ident.to_string();
        decls.push(TypeParamDecl {
            name: name.clone(),
            kind: TypeParamKind::Resource,
            bounds: Vec::new(),
        });
        names.push(name);
    }
    Ok((decls, names))
}

fn fields_decl(fields: &Fields, generic_names: &[String]) -> syn::Result<Vec<FieldDecl>> {
    let ctx = TypeTagCtx::from_generic_names(generic_names.iter().cloned());
    match fields {
        Fields::Named(named) => named_fields_decl(&named.named, &ctx, generic_names),
        Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(idx, field)| field_decl(field, idx.to_string(), &ctx, generic_names))
            .collect(),
        Fields::Unit => Ok(Vec::new()),
    }
}

fn named_fields_decl(
    fields: &syn::punctuated::Punctuated<Field, syn::Token![,]>,
    ctx: &TypeTagCtx,
    generic_names: &[String],
) -> syn::Result<Vec<FieldDecl>> {
    fields
        .iter()
        .map(|field| {
            let name = field.ident.as_ref().expect("named field").to_string();
            field_decl(field, name, ctx, generic_names)
        })
        .collect()
}

fn field_decl(
    field: &Field,
    name: String,
    ctx: &TypeTagCtx,
    generic_names: &[String],
) -> syn::Result<FieldDecl> {
    crate::type_tag::reject_plain_generic_in_payload(&field.ty, generic_names)?;
    Ok(FieldDecl {
        name,
        ty: ctx.lower(&field.ty)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn data_decl_records_fields() {
        let item: ItemStruct = syn::parse2(quote! {
            struct Pair<T> { a: u64, b: Resource<T> }
        })
        .unwrap();
        let decl = build_data_decl(&item).unwrap();
        assert_eq!(decl.name, "Pair");
        assert_eq!(decl.type_params.len(), 1);
        assert_eq!(decl.fields.len(), 2);
        assert_eq!(decl.fields[0].name, "a");
    }

    #[test]
    fn enum_decl_records_variants() {
        let item: ItemEnum = syn::parse2(quote! {
            enum E { A, B(u64), C { value: String } }
        })
        .unwrap();
        let decl = build_enum_decl(&item).unwrap();
        assert_eq!(decl.variants.len(), 3);
        assert_eq!(decl.variants[2].name, "C");
    }

    #[test]
    fn derive_detector_accepts_qualified_path() {
        let item: ItemStruct = syn::parse2(quote! {
            #[derive(Clone, bloom::BloomType)]
            struct X;
        })
        .unwrap();
        assert!(has_bloom_type_derive(&item.attrs));
    }
}
