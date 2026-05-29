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
    ArgDeclStub, ExternalTypeRefStub, FunctionDeclStub, InvariantDeclStub, ObjectTypeDeclStub,
    PetalManifestStub, TypeParamDeclStub,
};

use crate::types::{
    ArgKind, FunctionDecl, InvariantDecl, ObjectTypeDecl, PetalManifestV0, TypeParamDecl,
    TypeParamKind,
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
        functions: m.functions.iter().map(project_function).collect(),
        object_types: m.object_types.iter().map(project_object_type).collect(),
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

fn project_function(f: &FunctionDecl) -> FunctionDeclStub {
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
        attached_invariants: f
            .attached_invariants
            .iter()
            .map(|idx| project_invariant_idx(*idx))
            .collect(),
    }
}

fn project_object_type(o: &ObjectTypeDecl) -> ObjectTypeDeclStub {
    ObjectTypeDeclStub {
        name: o.name.clone(),
        abilities: o.abilities,
    }
}

fn project_type_param(p: &TypeParamDecl) -> TypeParamDeclStub {
    TypeParamDeclStub {
        name: p.name.clone(),
        phantom: matches!(p.kind, TypeParamKind::Phantom),
    }
}

/// Best-effort `InvariantDeclStub` from just the manifest-index `idx`.
///
/// The validator never reads invariant bodies; it only needs the wasm
/// export name + the argspec to know whether to fire it post-call. We
/// don't have access to the full invariant list at projection time
/// because `attached_invariants` carries indices, not handles. The
/// chain-side executor resolves the actual export by looking up the
/// invariant inside the canonical manifest via the same index.
///
/// For Phase 1 we record only the index-derived export name
/// (`__inv_<idx>`); a richer projection (including the predicate AST
/// and argspec) is a Phase 2 follow-up once the executor wants to
/// auto-marshal scope buffers.
fn project_invariant_idx(idx: u16) -> InvariantDeclStub {
    InvariantDeclStub {
        name: format!("__inv_{idx}"),
        wasm_export: format!("__inv_{idx}"),
        argspec: vec![],
    }
}

/// Optional helper: project a single invariant decl. Not used by the
/// projector above (which is bound by manifest's argspec-less `Vec<u16>`
/// representation of attached invariants) but kept for tooling.
pub fn project_invariant(inv: &InvariantDecl, idx: u16) -> InvariantDeclStub {
    InvariantDeclStub {
        name: inv.name.clone(),
        wasm_export: inv.wasm_export.clone(),
        argspec: vec![idx],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArgDecl, FunctionDecl, ObjectTypeDecl, PetalManifestV0, TypeParamDecl, TypeParamKind,
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
                attached_invariants: vec![3],
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
        assert_eq!(f.attached_invariants[0].wasm_export, "__inv_3");
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
}
