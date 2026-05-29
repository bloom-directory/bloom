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
//! The full `PetalManifestV0` (spec §8.2) lives in
//! `bloom-resource-macros` once that crate lands; the chain reads it
//! out of the wasm custom section. For Phase 1 we model only the
//! pieces the validator's type-check needs, in the form of
//! [`PetalManifestStub`] + friends. The producer-side macros will emit
//! `From<PetalManifestV0>` for the stub when the macro crate is wired
//! in, so chain code does not need a second copy of the full schema.

use bloom_chain_types::Hash32;
use bloom_objects::{AbilitySet, AccessMode, Object, ObjectId, TypeTag};

// ---------------------------------------------------------------------------
// Manifest stubs
// ---------------------------------------------------------------------------

/// Minimal manifest projection the PTB validator consults at typecheck
/// time. Mirrors the relevant subset of `PetalManifestV0` (spec §8.2).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PetalManifestStub {
    /// VFS path the petal is published at (mirrors the macro-emitted
    /// `module_path` in the full manifest).
    pub module_path: String,
    /// Function decls; lookup is by name.
    pub functions: Vec<FunctionDeclStub>,
    /// Object-type decls (currently used only for abilities lookup).
    pub object_types: Vec<ObjectTypeDeclStub>,
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

/// Object-type declaration; only abilities are consulted by the
/// validator today (e.g. to ensure a `Consume`d object can be dropped).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObjectTypeDeclStub {
    /// Type name within the petal.
    pub name: String,
    /// Declared abilities.
    pub abilities: AbilitySet,
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

/// Invariant declaration. The executor calls the wasm export after
/// the function returns; predicate is checked guest-side and the host
/// reads the 1/0 return code.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct InvariantDeclStub {
    /// Human-readable name (matches the source attribute).
    pub name: String,
    /// Wasm export name (e.g. `"__inv_0"`).
    pub wasm_export: String,
    /// Indices into the function's args/returns that the invariant
    /// receives (encoded as `Vec<u16>`; the executor builds the scope
    /// buffer from these positions).
    pub argspec: Vec<u16>,
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
            }],
            ..Default::default()
        };
        assert!(m.object_type("Pool").is_some());
        assert!(m.object_type("Nope").is_none());
    }
}
