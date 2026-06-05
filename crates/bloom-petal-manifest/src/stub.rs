//! Projector from the canonical [`crate::types::PetalManifestV0`] to the
//! validator-facing [`bloom_script::PetalManifestStub`].
//!
//! The full manifest carries everything a tool or social-layer reader
//! might want (fuel hints, ability bits, predicate ASTs, …). The
//! PTB validator only needs:
//! - `module_path` (for path/hash binding verification, spec §7.2)
//! - `functions` (for arg-count + arg-kind + type typechecks, spec §7.2 / §8.2)
//! - `object_types` (for ability lookup on `Consume`d args)
//! - `external_type_refs` (so `TypeTag::External` refs can be resolved
//!   at typecheck time)
//!
//! This projection is total — every `PetalManifestV0` produces a valid
//! `PetalManifestStub`. It is *not* round-trippable; the back-projection
//! requires the original manifest's invariant + fuel + host-import data.

use bloom_chain_types::Hash32;
use bloom_script::{
    ArgDeclStub, CapabilityTypeDeclStub, DataTypeDeclStub, EnumTypeDeclStub, ExternalTypeRefStub,
    FieldDeclStub, FieldLayoutStub, FunctionDeclStub, InvariantDeclStub, InvariantTargetStub,
    ObjectTypeDeclStub, PetalManifestStub, TypeParamDeclStub, VariantDeclStub,
    VariantFieldsDeclStub,
};

use crate::types::{
    ArgKind, CapabilityDecl, DataTypeDecl, EnumTypeDecl, FieldDecl, FunctionDecl, InvariantDecl,
    InvariantTarget, ObjectTypeDecl, PetalManifestV0, TypeParamDecl, TypeParamKind, VariantDecl,
    VariantFieldsDecl, is_numeric_invariant_field,
};

/// Project a full canonical manifest down to the validator-facing stub.
///
/// Spec §8.2 + §11.4. The chain calls this immediately after decoding a
/// `bloom_petal_manifest_v0` custom section so the validator can
/// typecheck `Command::Move`s without re-parsing the full manifest on
/// every PTB.
pub fn to_petal_manifest_stub(m: &PetalManifestV0) -> PetalManifestStub {
    PetalManifestStub {
        module_path: m.module_path.clone(),
        functions: m
            .functions
            .iter()
            .map(|f| project_function(f, &m.invariants))
            .collect(),
        object_types: m.object_types.iter().map(project_object_type).collect(),
        capability_types: m
            .capability_types
            .iter()
            .map(project_capability_type)
            .collect(),
        data_types: m.data_types.iter().map(project_data_type).collect(),
        enum_types: m.enum_types.iter().map(project_enum_type).collect(),
        external_type_refs: m
            .external_type_refs
            .iter()
            .map(|r| ExternalTypeRefStub {
                placeholder: r.placeholder.clone(),
                declared_petal_path: r.declared_petal_path.clone(),
                declared_type_name: r.declared_type_name.clone(),
                declared_content_hash: r.declared_content_hash.map(Hash32),
            })
            .collect(),
    }
}

fn project_function(f: &FunctionDecl, all_invariants: &[InvariantDecl]) -> FunctionDeclStub {
    FunctionDeclStub {
        name: f.name.clone(),
        view: f.view,
        type_params: f.type_params.iter().map(project_type_param).collect(),
        args: f
            .args
            .iter()
            .map(|a| match &a.kind {
                ArgKind::Signer => ArgDeclStub::Signer,
                ArgKind::Const(ty) => ArgDeclStub::Const(ty.clone()),
                ArgKind::Object { ty, mode } => ArgDeclStub::Object {
                    ty: ty.clone(),
                    mode: *mode,
                },
                ArgKind::TypeArg(idx) => ArgDeclStub::TypeArg(*idx),
            })
            .collect(),
        returns: f.returns.clone(),
        required_signers: f.required_signers,
        required_capabilities: f.required_capabilities.clone(),
        attached_invariants: f
            .attached_invariants
            .iter()
            .filter_map(|idx| all_invariants.get(*idx as usize).map(project_invariant))
            .collect(),
    }
}

fn project_object_type(o: &ObjectTypeDecl) -> ObjectTypeDeclStub {
    // Project only statically-addressable unsigned integer fields into the
    // invariant numeric scope. Bool is fixed-width but not a numeric u8 domain.
    let field_layout = o
        .fields
        .iter()
        .filter(|f| is_numeric_invariant_field(f))
        .map(|f| FieldLayoutStub {
            name: f.name.clone(),
            offset: f.offset.expect("numeric invariant field has offset"),
            width: f.width.expect("numeric invariant field has width"),
        })
        .collect();
    ObjectTypeDeclStub {
        name: o.name.clone(),
        abilities: o.abilities,
        type_params: o.type_params.iter().map(project_type_param).collect(),
        fields: o.fields.iter().map(project_field).collect(),
        field_layout,
    }
}

fn project_capability_type(c: &CapabilityDecl) -> CapabilityTypeDeclStub {
    CapabilityTypeDeclStub {
        name: c.name.clone(),
        type_params: c.type_params.iter().map(project_type_param).collect(),
        fields: c.fields.iter().map(project_field).collect(),
    }
}

fn project_data_type(d: &DataTypeDecl) -> DataTypeDeclStub {
    DataTypeDeclStub {
        name: d.name.clone(),
        type_params: d.type_params.iter().map(project_type_param).collect(),
        fields: d.fields.iter().map(project_field).collect(),
    }
}

fn project_enum_type(e: &EnumTypeDecl) -> EnumTypeDeclStub {
    EnumTypeDeclStub {
        name: e.name.clone(),
        type_params: e.type_params.iter().map(project_type_param).collect(),
        variants: e.variants.iter().map(project_variant).collect(),
    }
}

fn project_field(field: &FieldDecl) -> FieldDeclStub {
    FieldDeclStub {
        name: field.name.clone(),
        ty: field.ty.clone(),
    }
}

fn project_variant(variant: &VariantDecl) -> VariantDeclStub {
    VariantDeclStub {
        name: variant.name.clone(),
        fields: match &variant.fields {
            VariantFieldsDecl::Unit => VariantFieldsDeclStub::Unit,
            VariantFieldsDecl::Tuple(types) => VariantFieldsDeclStub::Tuple(types.clone()),
            VariantFieldsDecl::Struct(fields) => {
                VariantFieldsDeclStub::Struct(fields.iter().map(project_field).collect())
            }
        },
    }
}

fn project_type_param(p: &TypeParamDecl) -> TypeParamDeclStub {
    TypeParamDeclStub {
        name: p.name.clone(),
        phantom: matches!(p.kind, TypeParamKind::Phantom),
    }
}

/// The base type name with any generic arguments stripped:
/// `"Pool<A, B, S>"` → `"Pool"`. Object-type invariant targets are
/// matched against a borrow row's type name, which carries no generics.
fn base_type_name(s: &str) -> String {
    s.split('<').next().unwrap_or(s).trim().to_string()
}

/// Project a single canonical `InvariantDecl` into the runtime stub,
/// preserving its target so the executor can route function-exit vs
/// object-type invariants. The `__inv_<idx>` export is carried by
/// `inv.wasm_export`.
pub fn project_invariant(inv: &InvariantDecl) -> InvariantDeclStub {
    let target = match &inv.target {
        InvariantTarget::ObjectType { name } => InvariantTargetStub::ObjectType {
            name: base_type_name(name),
        },
        InvariantTarget::FunctionExit { name } => {
            InvariantTargetStub::FunctionExit { name: name.clone() }
        }
    };
    InvariantDeclStub {
        name: inv.name.clone(),
        wasm_export: inv.wasm_export.clone(),
        // human_text is excluded — it is only used by tooling/arbitration
        // (ADR-003 spec↔intent), not by the runtime validator or executor.
        // InvariantDeclStub has no human_text field.
        argspec: vec![],
        target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArgDecl, FunctionDecl, InvariantDecl, InvariantTarget, ObjectTypeDecl, PetalManifestV0,
        PredicateAst, TypeParamDecl, TypeParamKind,
    };
    use bloom_objects::{AbilitySet, AccessMode, TypeTag};

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    #[test]
    fn projects_module_path_and_functions() {
        let m = PetalManifestV0 {
            module_path: "/bloom/test".into(),
            functions: vec![FunctionDecl {
                name: "f".into(),
                view: true,
                type_params: vec![TypeParamDecl {
                    name: "T".into(),
                    kind: TypeParamKind::Phantom,
                    bounds: vec![],
                }],
                args: vec![
                    ArgDecl {
                        name: "s".into(),
                        kind: ArgKind::Signer,
                    },
                    ArgDecl {
                        name: "c".into(),
                        kind: ArgKind::Const(concrete("u64")),
                    },
                    ArgDecl {
                        name: "o".into(),
                        kind: ArgKind::Object {
                            ty: concrete("Pool"),
                            mode: AccessMode::Mutable,
                        },
                    },
                    ArgDecl {
                        name: "t".into(),
                        kind: ArgKind::TypeArg(0),
                    },
                ],
                returns: vec![concrete("u128")],
                required_signers: 1,
                required_capabilities: vec![],
                attached_invariants: vec![0],
            }],
            invariants: vec![InvariantDecl {
                name: "inv".into(),
                target: InvariantTarget::FunctionExit { name: "f".into() },
                predicate: PredicateAst::Opaque,
                wasm_export: "__inv_0".into(),
                human_text: String::new(),
            }],
            ..Default::default()
        };
        let s = to_petal_manifest_stub(&m);
        assert_eq!(s.module_path, "/bloom/test");
        assert_eq!(s.functions.len(), 1);
        let f = &s.functions[0];
        assert_eq!(f.name, "f");
        assert!(f.view);
        assert_eq!(f.type_params.len(), 1);
        assert!(f.type_params[0].phantom);
        assert_eq!(f.args.len(), 4);
        assert!(matches!(f.args[0], ArgDeclStub::Signer));
        assert!(matches!(f.args[1], ArgDeclStub::Const(_)));
        assert!(matches!(
            f.args[2],
            ArgDeclStub::Object {
                mode: AccessMode::Mutable,
                ..
            }
        ));
        assert!(matches!(f.args[3], ArgDeclStub::TypeArg(0)));
        assert_eq!(f.returns.len(), 1);
        assert_eq!(f.attached_invariants.len(), 1);
        assert_eq!(f.attached_invariants[0].wasm_export, "__inv_0");
        assert!(matches!(
            f.attached_invariants[0].target,
            InvariantTargetStub::FunctionExit { .. }
        ));
    }

    #[test]
    fn projects_object_types() {
        let m = PetalManifestV0 {
            module_path: "/p".into(),
            object_types: vec![ObjectTypeDecl {
                name: "Pool".into(),
                abilities: AbilitySet::key_store(),
                type_params: vec![],
                fields: vec![],
            }],
            ..Default::default()
        };
        let s = to_petal_manifest_stub(&m);
        assert_eq!(s.object_types.len(), 1);
        assert_eq!(s.object_types[0].name, "Pool");
        assert_eq!(s.object_types[0].abilities, AbilitySet::key_store());
    }

    #[test]
    fn object_field_layout_excludes_bool_from_numeric_invariant_scope() {
        let m = PetalManifestV0 {
            module_path: "/p".into(),
            object_types: vec![ObjectTypeDecl {
                name: "Flags".into(),
                abilities: AbilitySet::key_store(),
                type_params: vec![],
                fields: vec![
                    FieldDecl {
                        name: "enabled".into(),
                        ty: concrete("bool"),
                        offset: Some(0),
                        width: Some(1),
                    },
                    FieldDecl {
                        name: "count".into(),
                        ty: concrete("u64"),
                        offset: Some(1),
                        width: Some(8),
                    },
                ],
            }],
            ..Default::default()
        };

        let s = to_petal_manifest_stub(&m);
        assert_eq!(s.object_types[0].field_layout.len(), 1);
        assert_eq!(s.object_types[0].field_layout[0].name, "count");
    }
}
