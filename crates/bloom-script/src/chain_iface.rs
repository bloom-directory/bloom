//! Trait the validator and executor use to read chain state.
//!
//! The real chain (Phase 2) implements [`ChainStateIface`] over
//! `bloom-chain-state`; tests in this crate implement it over an
//! in-memory `MockChainState`. Keeping the interface here means the
//! validator/executor have no compile-time dependency on the chain
//! crate.
//!
//! ## Manifest stubs
//!
//! The full `PetalManifest` (spec §8.2) lives in
//! `bloom-resource-macros` once that crate lands; the chain reads it
//! out of the wasm custom section. For Phase 1 we model only the
//! pieces the validator's type-check needs, in the form of
//! [`PetalManifestStub`] + friends. The producer-side macros will emit
//! `From<PetalManifest>` for the stub when the macro crate is wired
//! in, so chain code does not need a second copy of the full schema.

use bloom_chain_types::Hash32;
use bloom_objects::{AbilitySet, AccessMode, Object, ObjectId, TypeTag};

use crate::predicate::PredicateAstStub;

// ---------------------------------------------------------------------------
// Manifest stubs
// ---------------------------------------------------------------------------

/// Minimal manifest projection the PTB validator consults at typecheck
/// time. Mirrors the relevant subset of `PetalManifest` (spec §8.2).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PetalManifestStub {
    /// VFS path the petal is published at (mirrors the macro-emitted
    /// `module_path` in the full manifest).
    pub module_path: String,
    /// Function decls; lookup is by name.
    pub functions: Vec<FunctionDeclStub>,
    /// Object-type decls (currently used only for abilities lookup).
    pub object_types: Vec<ObjectTypeDeclStub>,
    /// Capability declarations for schema-driven value validation.
    pub capability_types: Vec<CapabilityTypeDeclStub>,
    /// Plain data struct declarations for schema-driven value validation.
    pub data_types: Vec<DataTypeDeclStub>,
    /// Plain enum declarations for schema-driven value validation.
    pub enum_types: Vec<EnumTypeDeclStub>,
    /// External type refs from other petals (paths + pinned hashes).
    pub external_type_refs: Vec<ExternalTypeRefStub>,
}

impl PetalManifestStub {
    /// Find a function decl by name (`None` if not present).
    pub fn function(&self, name: &str) -> Option<&FunctionDeclStub> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Find an object-type decl by name.
    pub fn object_type(&self, name: &str) -> Option<&ObjectTypeDeclStub> {
        self.object_types.iter().find(|o| o.name == name)
    }

    /// Object-type invariants whose target matches `type_name`. The
    /// executor fires these against dirty borrow rows of that type after
    /// any command that mutates such a row (ADR-010) — Move calls and
    /// built-ins (`MergeCoins`/`SplitCoins`) alike. Every invariant is
    /// attached to its host function, so scanning `functions` enumerates
    /// them all; each invariant is attached exactly once, so there are no
    /// duplicates.
    pub fn object_invariants<'a>(
        &'a self,
        type_name: &'a str,
    ) -> impl Iterator<Item = &'a InvariantDeclStub> + 'a {
        self.functions
            .iter()
            .flat_map(|f| f.attached_invariants.iter())
            .filter(move |inv| {
                matches!(&inv.target, InvariantTargetStub::ObjectType { name } if name == type_name)
            })
    }
}

/// Function declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FunctionDeclStub {
    /// Function name (PTB `MoveCmd::function` must equal this).
    pub name: String,
    /// True if this function is declared read-only and may be called as a view.
    pub view: bool,
    /// Generic type parameters.
    pub type_params: Vec<TypeParamDeclStub>,
    /// Declared argument kinds (in order).
    pub args: Vec<ArgDeclStub>,
    /// Declared return TypeTags (in order).
    pub returns: Vec<TypeTag>,
    /// Count of distinct signer authorities required by the manifest.
    pub required_signers: u8,
    /// Capability authorities required by the manifest.
    pub required_capabilities: Vec<TypeTag>,
    /// Attached invariants (resolved by the executor after the call).
    pub attached_invariants: Vec<InvariantDeclStub>,
}

/// Generic-parameter declaration.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TypeParamDeclStub {
    /// Parameter name (for diagnostics only).
    pub name: String,
    /// `true` if phantom (does not appear in payload bytes).
    pub phantom: bool,
}

/// What kind of argument the declared function expects at a given
/// position. Mirrors `ArgKind` from spec §8.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgDeclStub {
    /// A reference to a PTB signer.
    Signer,
    /// A canonical-codec literal of the given type.
    Const(TypeTag),
    /// An on-chain object with the given type + access mode.
    Object {
        /// Expected object type.
        ty: TypeTag,
        /// Access mode (ReadOnly / Mutable / Consume).
        mode: AccessMode,
    },
    /// A `TypeTag` passed as a value to drive generic dispatch (refers
    /// to the i-th declared type parameter).
    TypeArg(u16),
}

/// Statically-known canonical-payload location of one object field
/// (ADR-011). Only fields in the fixed-width prefix appear here; the
/// scope builder uses these to extract named field values at runtime
/// without re-parsing the type-defining petal's serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldLayoutStub {
    /// Field name.
    pub name: String,
    /// Byte offset within the canonical object payload.
    pub offset: u32,
    /// Fixed byte width of the field.
    pub width: u32,
}

/// Object-type declaration; only abilities are consulted by the
/// validator today (e.g. to ensure a `Consume`d object can be dropped).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObjectTypeDeclStub {
    /// Type name within the petal.
    pub name: String,
    /// Declared abilities.
    pub abilities: AbilitySet,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDeclStub>,
    /// Payload fields in canonical order.
    pub fields: Vec<FieldDeclStub>,
    /// Layout of the statically-addressable (fixed-prefix) fields,
    /// used by the invariant scope builder.
    pub field_layout: Vec<FieldLayoutStub>,
}

/// Capability declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CapabilityTypeDeclStub {
    /// Type name within the petal.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDeclStub>,
    /// Payload fields in canonical order.
    pub fields: Vec<FieldDeclStub>,
}

/// Plain data-struct declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DataTypeDeclStub {
    /// Type name within the petal.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDeclStub>,
    /// Fields in canonical order.
    pub fields: Vec<FieldDeclStub>,
}

/// Plain enum declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EnumTypeDeclStub {
    /// Type name within the petal.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDeclStub>,
    /// Variants in declaration order.
    pub variants: Vec<VariantDeclStub>,
}

/// Struct/object field declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDeclStub {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: TypeTag,
}

/// Enum variant declaration in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantDeclStub {
    /// Variant name.
    pub name: String,
    /// Variant payload layout.
    pub fields: VariantFieldsDeclStub,
}

/// Enum variant payload shape in the manifest stub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantFieldsDeclStub {
    /// Unit variant.
    Unit,
    /// Tuple fields.
    Tuple(Vec<TypeTag>),
    /// Struct fields.
    Struct(Vec<FieldDeclStub>),
}

/// Resolved external-type reference (`/path/to/petal::TypeName ->
/// pinned content hash`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExternalTypeRefStub {
    /// Placeholder string (e.g. `"$external_0"`) used by the manifest
    /// to refer to this entry.
    pub placeholder: String,
    /// Path of the petal that defines the referenced type.
    pub declared_petal_path: String,
    /// Type name within that petal.
    pub declared_type_name: String,
    /// Content hash resolved at build time (may be `None` until
    /// `petals.lock` is consulted).
    pub declared_content_hash: Option<Hash32>,
}

/// Where an invariant attaches. Runtime mirror of the manifest's
/// `InvariantTarget` (the two crates can't share the type without a
/// dependency cycle, since the manifest projector depends on this crate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvariantTargetStub {
    /// Fires after every mutation of the named object type.
    ObjectType {
        /// Base object type name (generics stripped).
        name: String,
    },
    /// Fires on exit from the named function.
    FunctionExit {
        /// Function name.
        name: String,
    },
}

impl Default for InvariantTargetStub {
    fn default() -> Self {
        InvariantTargetStub::FunctionExit {
            name: String::new(),
        }
    }
}

/// Invariant declaration projected for runtime enforcement.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct InvariantDeclStub {
    /// Human-readable name (matches the source attribute).
    pub name: String,
    /// Wasm export name (e.g. `"__inv_0"`).
    ///
    /// Kept for ABI compatibility/tooling; runtime enforcement uses
    /// [`predicate`](Self::predicate), not the arbitrary wasm return byte.
    pub wasm_export: String,
    /// Machine-readable manifest predicate interpreted by the host.
    pub predicate: PredicateAstStub,
    /// Indices into the function's args/returns that the invariant
    /// receives (encoded as `Vec<u16>`; the executor builds the scope
    /// buffer from these positions). Empty for object-type invariants,
    /// which build their scope from the borrow row's payloads.
    pub argspec: Vec<u16>,
    /// Where the invariant attaches (object-type vs function-exit).
    pub target: InvariantTargetStub,
}

// ---------------------------------------------------------------------------
// ChainStateIface
// ---------------------------------------------------------------------------

/// The narrow chain interface the PTB validator and executor need.
///
/// All accessors are read-only; the executor accumulates writes in an
/// [`crate::executor::ExecutionReport`] and the caller applies them.
pub trait ChainStateIface {
    /// Load an object by id. Returns `None` if the object does not
    /// exist in the chain state.
    fn load_object(&self, id: &ObjectId) -> Option<Object>;
    /// Load a petal's wasm bytes by its content hash.
    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>>;
    /// Load a petal's manifest projection by its content hash.
    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub>;
    /// Resolve a VFS path to the petal hash bound at that path (used
    /// by the validator to verify a `(path, hash)` PetalRef agrees
    /// with the on-chain VFS state).
    fn resolve_path(&self, path: &str) -> Option<Hash32>;
    /// Iterate VFS path bindings as `(path, petal_hash)`. Handlers use this
    /// for namespace projection; callers should not assume a particular order.
    fn iter_vfs(&self) -> Vec<(String, Hash32)> {
        Vec::new()
    }
    /// Iterate every live object as `(id, object)`. Handlers use this for
    /// latest-snapshot projections; callers should not assume a particular
    /// order.
    fn iter_objects(&self) -> Vec<(ObjectId, Object)> {
        Vec::new()
    }
    /// Current block height for the expiry check.
    fn current_block(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_function_lookup() {
        let m = PetalManifestStub {
            functions: vec![FunctionDeclStub {
                name: "swap".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(m.function("swap").is_some());
        assert!(m.function("absent").is_none());
    }

    #[test]
    fn manifest_object_type_lookup() {
        let m = PetalManifestStub {
            object_types: vec![ObjectTypeDeclStub {
                name: "Pool".to_string(),
                abilities: AbilitySet::key_store(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(m.object_type("Pool").is_some());
        assert!(m.object_type("Nope").is_none());
    }

    #[test]
    fn object_invariants_selects_matching_object_type_targets() {
        let inv = |name: &str, target| InvariantDeclStub {
            name: name.to_string(),
            wasm_export: name.to_string(),
            predicate: PredicateAstStub::Opaque,
            argspec: vec![],
            target,
        };
        let m = PetalManifestStub {
            functions: vec![
                FunctionDeclStub {
                    name: "swap".to_string(),
                    attached_invariants: vec![
                        inv(
                            "pool_k",
                            InvariantTargetStub::ObjectType {
                                name: "Pool".to_string(),
                            },
                        ),
                        inv(
                            "fn_exit",
                            InvariantTargetStub::FunctionExit {
                                name: "swap".to_string(),
                            },
                        ),
                    ],
                    ..Default::default()
                },
                FunctionDeclStub {
                    name: "drain".to_string(),
                    attached_invariants: vec![inv(
                        "vault_ok",
                        InvariantTargetStub::ObjectType {
                            name: "Vault".to_string(),
                        },
                    )],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        // Only the Pool-targeted invariant matches, across all functions.
        let pool: Vec<&str> = m
            .object_invariants("Pool")
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(pool, vec!["pool_k"]);
        let vault: Vec<&str> = m
            .object_invariants("Vault")
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(vault, vec!["vault_ok"]);
        assert_eq!(m.object_invariants("Nope").count(), 0);
    }
}
