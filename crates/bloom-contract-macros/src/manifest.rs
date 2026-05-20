//! Compile-time manifest skeleton builder.
//!
//! At expansion time, `#[bloom::contract]` already holds the canonical
//! parse of its mod body — every selector, signature, mutability flag, and
//! interface alias is in hand. To make that data available to the
//! `bloom contract build` tool without instantiating the wasm or rebuilding
//! the crate host-side, we serialize a partial manifest (everything the
//! macro can compute statically) to JSON and embed it in a `bloom_manifest`
//! custom wasm section via `#[link_section]`.
//!
//! The build tool fills in the runtime-derived fields (`wasm_hash`,
//! `source_hash`, `imports`) and rewrites the manifest as the on-disk
//! `<name>.manifest.json`.
//!
//! Scope:
//!
//! - Inputs are the raw `syn` items the contract macro already parsed
//!   (handler list + interface idents), plus a sweep of the mod body for
//!   `#[storage]` / `#[event]` / `#[error]` items. We re-derive the same
//!   blake3-based selectors/topics/slots those sibling macros emit so the
//!   manifest matches the runtime tables byte-for-byte.
//! - Output is a JSON string that decodes back into
//!   `bloom_contract_metadata::Manifest`. To keep the macro crate free of
//!   a `bloom-contract-metadata` dep (which would form a chain through
//!   `serde`), we build the JSON via `serde_json::json!` against the same
//!   schema directly.

use blake3::Hasher;
use serde_json::{Value, json};
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, Ident, Item, ItemEnum, ItemMod, ItemStruct,
    LitStr, Meta, Type, Variant,
};

/// Mutability marker as it appears in the manifest JSON.
#[derive(Clone, Copy, Debug)]
pub enum Mutability {
    Mutating,
    View,
    Payable,
}

impl Mutability {
    fn as_str(self) -> &'static str {
        match self {
            Mutability::Mutating => "mutating",
            Mutability::View => "view",
            Mutability::Payable => "payable",
        }
    }
}

/// One row in the `abi.methods` table — populated from the contract
/// macro's own `HandlerSpec`s.
pub struct ManifestMethod {
    pub name: String,
    pub signature: String,
    pub selector: [u8; 4],
    pub mutability: Mutability,
    pub arg_idents: Vec<String>,
    pub arg_types: Vec<Type>,
    pub return_type: Option<Type>,
}

/// Build the manifest JSON for the contract module.
///
/// `module_ident` is the source-level mod name (used as the contract
/// `name`). `domain` is the canonical domain prefix. `methods` is the
/// already-parsed handler set. `interfaces` carries the trait idents
/// listed in `interfaces(...)` — we emit them as `name` strings since the
/// macro can't resolve their `ABI_DOMAIN` at compile time.
///
/// The mod body is re-scanned for `#[storage]`, `#[event]`, and `#[error]`
/// attributed items to fill out the rest of the manifest.
pub fn build_skeleton_json(
    module: &ItemMod,
    domain: &str,
    methods: &[ManifestMethod],
    interfaces: &[Ident],
) -> String {
    let items = module
        .content
        .as_ref()
        .map(|(_, items)| items.as_slice())
        .unwrap_or(&[]);

    let mut storage_fields: Vec<Value> = Vec::new();
    let mut event_entries: Vec<Value> = Vec::new();
    let mut error_entries: Vec<Value> = Vec::new();

    for item in items {
        match item {
            Item::Struct(s) => {
                if let Some(storage_attr) = find_attr(&s.attrs, "storage") {
                    let derive_input = struct_to_derive_input(s);
                    let storage_domain = parse_domain_arg(storage_attr)
                        .unwrap_or_else(|| pascal_to_snake(&s.ident.to_string()));
                    if let Some(mut fields) = collect_storage_fields(&derive_input, &storage_domain) {
                        storage_fields.append(&mut fields);
                    }
                } else if let Some(event_attr) = find_attr(&s.attrs, "event") {
                    let event_domain = parse_domain_arg(event_attr).unwrap_or_default();
                    if let Some(entry) = build_event_entry(s, &event_domain) {
                        event_entries.push(entry);
                    }
                }
            }
            Item::Enum(e) => {
                if let Some(error_attr) = find_attr(&e.attrs, "error") {
                    let error_domain = parse_domain_arg(error_attr).unwrap_or_default();
                    let mut entries = build_error_entries(e, &error_domain);
                    error_entries.append(&mut entries);
                }
            }
            _ => {}
        }
    }

    // `methods` already carries everything the macro needs.
    let methods_json: Vec<Value> = methods
        .iter()
        .map(|m| {
            json!({
                "name": m.name,
                "selector": hex_4(m.selector),
                "signature": m.signature,
                "inputs": m
                    .arg_idents
                    .iter()
                    .zip(m.arg_types.iter())
                    .map(|(name, ty)| json!({ "name": name, "ty": ty_label(ty) }))
                    .collect::<Vec<_>>(),
                "outputs": match &m.return_type {
                    Some(ty) => vec![json!({ "name": "", "ty": ty_label(ty) })],
                    None => Vec::new(),
                },
                "mutability": m.mutability.as_str(),
            })
        })
        .collect();

    let interface_names: Vec<String> = interfaces.iter().map(|i| i.to_string()).collect();

    let manifest = json!({
        "schema_version": 2,
        "contract": {
            "name": module.ident.to_string(),
            "domain": domain,
            "version": "0.1.0",
        },
        "abi": { "methods": methods_json },
        "storage": { "fields": storage_fields },
        "events": event_entries,
        "errors": error_entries,
        // Macro can't resolve `<I as ContractInterface>::METHODS` at
        // expansion time (consts are link-time). It emits just the
        // declared trait names here; the build crate resolves each name
        // to a full `InterfaceManifest` record by reading the
        // `bloom_interfaces` custom section the interface macro embedded.
        "interfaces": interface_names,
        "imports": [],
        "limits": { "max_memory_pages": 256, "max_wasm_bytes": 262144 },
        "wasm_hash": "",
        "source_hash": "",
    });

    serde_json::to_string(&manifest).expect("manifest skeleton serializes")
}

// ===========================================================================
// Field-shape inspection
// ===========================================================================

fn find_attr<'a>(attrs: &'a [Attribute], name: &str) -> Option<&'a Attribute> {
    attrs.iter().find(|a| a.path().is_ident(name))
}

/// `#[storage(domain = "...")]`, `#[event(domain = "...")]`, etc. Returns
/// `None` if the attribute carries no `domain` arg or no list at all.
fn parse_domain_arg(attr: &Attribute) -> Option<String> {
    let list = match &attr.meta {
        Meta::List(l) => l,
        _ => return None,
    };
    let mut out: Option<String> = None;
    let _ = list.parse_nested_meta(|nested| {
        if nested.path.is_ident("domain")
            && let Ok(v) = nested.value().and_then(|s| s.parse::<LitStr>()) {
                out = Some(v.value());
            }
        Ok(())
    });
    out
}

fn struct_to_derive_input(s: &ItemStruct) -> DeriveInput {
    DeriveInput {
        attrs: s.attrs.clone(),
        vis: s.vis.clone(),
        ident: s.ident.clone(),
        generics: s.generics.clone(),
        data: Data::Struct(syn::DataStruct {
            struct_token: s.struct_token,
            fields: s.fields.clone(),
            semi_token: s.semi_token,
        }),
    }
}

// ===========================================================================
// Storage
// ===========================================================================

fn collect_storage_fields(input: &DeriveInput, domain: &str) -> Option<Vec<Value>> {
    let named = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => return None,
        },
        _ => return None,
    };
    let mut out: Vec<Value> = Vec::new();
    for field in named {
        let ident = match &field.ident {
            Some(i) => i,
            None => continue,
        };
        let name = ident.to_string();
        let compat = parse_storage_compat_tag(&field.attrs);
        let (shape, kind_json, slot_hex) = classify_storage_field(&field.ty, domain, &name, compat.as_deref())?;
        let _ = shape;
        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), Value::String(name));
        entry.insert("kind".into(), kind_json);
        entry.insert("slot".into(), Value::String(slot_hex));
        if let Some(tag) = compat {
            entry.insert("compat_tag".into(), Value::String(tag));
        }
        out.push(Value::Object(entry));
    }
    Some(out)
}

fn parse_storage_compat_tag(attrs: &[Attribute]) -> Option<String> {
    for a in attrs {
        if !a.path().is_ident("storage") {
            continue;
        }
        if let Meta::List(list) = &a.meta {
            let mut tag: Option<String> = None;
            let _ = list.parse_nested_meta(|nested| {
                if nested.path.is_ident("compat_tag")
                    && let Ok(v) = nested.value().and_then(|s| s.parse::<LitStr>()) {
                        tag = Some(v.value());
                    }
                Ok(())
            });
            return tag;
        }
    }
    None
}

enum StorageShape<'a> {
    Scalar(&'a Type),
    Map(&'a Type, &'a Type),
    Vec(&'a Type),
}

fn classify_storage_shape(ty: &Type) -> Option<StorageShape<'_>> {
    if let Type::Path(tp) = ty {
        let last = tp.path.segments.last()?;
        let name = last.ident.to_string();
        if let syn::PathArguments::AngleBracketed(ab) = &last.arguments {
            let args: Vec<&Type> = ab
                .args
                .iter()
                .filter_map(|a| match a {
                    syn::GenericArgument::Type(t) => Some(t),
                    _ => None,
                })
                .collect();
            return match (name.as_str(), args.as_slice()) {
                ("StorageValue", [t]) => Some(StorageShape::Scalar(t)),
                ("Map", [k, v]) => Some(StorageShape::Map(k, v)),
                ("VecStore", [t]) => Some(StorageShape::Vec(t)),
                _ => None,
            };
        }
    }
    None
}

fn classify_storage_field<'a>(
    ty: &'a Type,
    domain: &str,
    name: &str,
    compat: Option<&str>,
) -> Option<(StorageShape<'a>, Value, String)> {
    let shape = classify_storage_shape(ty)?;
    let kind = match &shape {
        StorageShape::Scalar(inner) => json!({ "kind": "scalar", "ty": ty_label(inner) }),
        StorageShape::Map(k, v) => {
            json!({ "kind": "map", "key_ty": ty_label(k), "value_ty": ty_label(v) })
        }
        StorageShape::Vec(inner) => json!({ "kind": "vec", "ty": ty_label(inner) }),
    };
    let slot = match (&shape, compat) {
        (StorageShape::Map(_, _), _) => [0u8; 32],
        (_, Some(tag)) => slot_for_compat_tag(tag),
        (_, None) => slot_for_field(domain, name),
    };
    Some((shape, kind, hex_32(slot)))
}

fn slot_for_compat_tag(tag: &str) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(tag.as_bytes());
    *h.finalize().as_bytes()
}

fn slot_for_field(domain: &str, field: &str) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"storage:");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(field.as_bytes());
    *h.finalize().as_bytes()
}

// ===========================================================================
// Events
// ===========================================================================

fn build_event_entry(s: &ItemStruct, domain: &str) -> Option<Value> {
    let named = match &s.fields {
        Fields::Named(n) => &n.named,
        _ => return None,
    };
    let event_name = s.ident.to_string();
    let mut field_arr: Vec<Value> = Vec::new();
    for f in named {
        let ident = f.ident.as_ref()?;
        let indexed = f.attrs.iter().any(|a| a.path().is_ident("indexed"));
        field_arr.push(json!({
            "name": ident.to_string(),
            "ty": ty_label(&f.ty),
            "indexed": indexed,
        }));
    }
    let signature = build_event_signature(domain, &event_name, named);
    let topic0 = *blake3::hash(signature.as_bytes()).as_bytes();
    Some(json!({
        "name": event_name,
        "topic0": hex_32(topic0),
        "fields": field_arr,
        "version": 2,
        "signature": signature,
    }))
}

fn build_event_signature(
    domain: &str,
    name: &str,
    fields: &syn::punctuated::Punctuated<Field, syn::Token![,]>,
) -> String {
    let mut s = String::new();
    if !domain.is_empty() {
        s.push_str(domain);
        s.push_str("::");
    }
    s.push_str(name);
    s.push('(');
    let mut first = true;
    for f in fields {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&ty_label(&f.ty));
    }
    s.push(')');
    s
}

// ===========================================================================
// Errors
// ===========================================================================

fn build_error_entries(e: &ItemEnum, domain: &str) -> Vec<Value> {
    let enum_name = e.ident.to_string();
    let mut out: Vec<Value> = Vec::new();
    for variant in &e.variants {
        let entry = build_error_variant_entry(domain, &enum_name, variant);
        out.push(entry);
    }
    out
}

fn build_error_variant_entry(domain: &str, enum_name: &str, variant: &Variant) -> Value {
    let v_name = variant.ident.to_string();
    let signature = build_variant_signature(domain, enum_name, &v_name, &variant.fields);
    let sel_full = blake3::hash(signature.as_bytes());
    let sel = &sel_full.as_bytes()[..4];
    let payload: Vec<Value> = match &variant.fields {
        Fields::Unit => Vec::new(),
        Fields::Unnamed(u) => u
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, f)| {
                json!({ "name": format!("_{i}"), "ty": ty_label(&f.ty) })
            })
            .collect(),
        Fields::Named(n) => n
            .named
            .iter()
            .map(|f| {
                json!({
                    "name": f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                    "ty": ty_label(&f.ty),
                })
            })
            .collect(),
    };
    json!({
        "name": v_name,
        "selector": hex_4([sel[0], sel[1], sel[2], sel[3]]),
        "payload": payload,
        "signature": signature,
    })
}

fn build_variant_signature(domain: &str, enum_name: &str, variant: &str, fields: &Fields) -> String {
    let mut s = String::new();
    if !domain.is_empty() {
        s.push_str(domain);
        s.push_str("::");
    }
    s.push_str(enum_name);
    s.push_str("::");
    s.push_str(variant);
    s.push('(');
    let mut first = true;
    let mut push = |ty: &Type, s: &mut String| {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&ty_label(ty));
    };
    match fields {
        Fields::Unit => {}
        Fields::Unnamed(u) => {
            for f in &u.unnamed {
                push(&f.ty, &mut s);
            }
        }
        Fields::Named(n) => {
            for f in &n.named {
                push(&f.ty, &mut s);
            }
        }
    }
    s.push(')');
    s
}

// ===========================================================================
// Shared formatting helpers
// ===========================================================================

/// Canonical type label — matches the form selectors and topics are
/// hashed against. `Vec<U256>` → `vec<u256>`, `(u8, u16)` → `(u8,u16)`,
/// `[u8; 32]` → `[u8;32]`. Fallback `"?"` is intentional — the build tool
/// sees the raw label and the user gets a chance to spot mismatches in
/// the manifest.
pub fn ty_label(ty: &Type) -> String {
    crate::sig::type_label(ty)
}

fn hex_4(b: [u8; 4]) -> String {
    let mut s = String::with_capacity(8);
    for byte in b {
        s.push_str(&hex_byte(byte));
    }
    s
}

fn hex_32(b: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&hex_byte(byte));
    }
    s
}

fn hex_byte(b: u8) -> String {
    const TAB: &[u8; 16] = b"0123456789abcdef";
    let hi = TAB[(b >> 4) as usize];
    let lo = TAB[(b & 0x0f) as usize];
    String::from_utf8(vec![hi, lo]).unwrap()
}

fn pascal_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
