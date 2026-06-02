//! `PetalManifestV0` — the canonical manifest schema emitted by
//! `#[bloom::petal]` as a wasm custom section (spec §8, §8.2).
//!
//! These types are pure data; no `syn`/`quote` dependencies. The
//! canonical codec lives in [`crate::codec`], and a
//! [`crate::stub::to_petal_manifest_stub`] conversion produces the
//! validator's lean view ([`bloom_script::PetalManifestStub`]).

use bloom_objects::{AbilitySet, AccessMode, TypeTag};

/// Schema version this crate produces. Bumped when the manifest layout
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 3;

/// Custom section name embedded into every new-framework petal (spec §8.1).
pub const MANIFEST_CUSTOM_SECTION: &str = "bloom_petal_manifest_v0";

/// Top-level manifest emitted by `#[bloom::petal]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PetalManifestV0 {
    /// `= SCHEMA_VERSION` for this crate's emission.
    pub schema_version: u32,
    /// VFS path the petal lives at, e.g. `"/bloom/petals/dex/pool"`.
    pub module_path: String,
    /// `bloom-resource` framework version the petal was compiled against.
    pub framework_version: SemVer,
    /// Upgrade-lineage content hash, or `None` for first publishes.
    pub parent_version: Option<[u8; 32]>,
    /// All `#[object]`-annotated structs in declaration order.
    pub object_types: Vec<ObjectTypeDecl>,
    /// All `#[capability]`-annotated structs in declaration order.
    pub capability_types: Vec<CapabilityDecl>,
    /// Plain `#[derive(BloomType)]` structs in declaration order.
    pub data_types: Vec<DataTypeDecl>,
    /// Plain `#[derive(BloomType)]` enums in declaration order.
    pub enum_types: Vec<EnumTypeDecl>,
    /// All `pub fn`s in declaration order; the petal's public surface.
    pub functions: Vec<FunctionDecl>,
    /// All `#[invariant]`-annotated invariants, indexed by `__inv_<idx>`.
    pub invariants: Vec<InvariantDecl>,
    /// Host imports the petal relies on (subset of `NEW_HOST_IMPORTS`).
    pub required_host_imports: Vec<HostImportDecl>,
    /// External-type references resolved at build time via `petals.lock`.
    pub external_type_refs: Vec<ExternalTypeRef>,
    /// Declared per-function fuel ceilings (opt-in).
    pub fuel_hints: FuelHints,
}

impl Default for PetalManifestV0 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            module_path: String::new(),
            framework_version: SemVer::default(),
            parent_version: None,
            object_types: Vec::new(),
            capability_types: Vec::new(),
            data_types: Vec::new(),
            enum_types: Vec::new(),
            functions: Vec::new(),
            invariants: Vec::new(),
            required_host_imports: Vec::new(),
            external_type_refs: Vec::new(),
            fuel_hints: FuelHints::default(),
        }
    }
}

/// Semantic version triple. Carried in the manifest so chain/explorers
/// can correlate petal builds with framework releases.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SemVer {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

impl SemVer {
    /// Build a fresh `SemVer` triple.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Declaration of an `#[object]`-annotated struct (spec §4, §8.2).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObjectTypeDecl {
    /// Struct name (within the petal).
    pub name: String,
    /// Move-style ability bitfield.
    pub abilities: AbilitySet,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDecl>,
    /// Field declarations, in source order.
    pub fields: Vec<FieldDecl>,
}

/// Generic-parameter declaration on an object/function (spec §8.2 / §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeParamDecl {
    /// Parameter name.
    pub name: String,
    /// `Phantom` if the parameter only appears in TypeTags;
    /// `Resource` if it appears in payload bytes via `Resource<T>`.
    pub kind: TypeParamKind,
    /// Future-use bounds; empty in v0.
    pub bounds: Vec<TypeTag>,
}

/// Kind discriminant for a generic parameter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeParamKind {
    /// Phantom (compile-time only).
    Phantom,
    /// Non-phantom; must be wrapped in `Resource<T>` to appear in payload.
    Resource,
}

/// Field on an `#[object]` struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    /// Field name.
    pub name: String,
    /// Field's recorded `TypeTag` (best-effort, see `crate::type_tag`).
    pub ty: TypeTag,
}

/// Declaration of a `#[capability]`-annotated struct (spec §5).
///
/// Capabilities are a sugar over `#[object(abilities = "key, store, copy")]`
/// plus a `CapabilityMarker` impl; this decl carries the same payload fields
/// as an object so capabilities participate in the same canonical codec.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CapabilityDecl {
    /// Struct name.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDecl>,
    /// Field declarations, in source order.
    pub fields: Vec<FieldDecl>,
}

/// Plain data struct declaration emitted by `#[derive(BloomType)]`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DataTypeDecl {
    /// Struct name.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDecl>,
    /// Field declarations, in source order.
    pub fields: Vec<FieldDecl>,
}

/// Plain enum declaration emitted by `#[derive(BloomType)]`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EnumTypeDecl {
    /// Enum name.
    pub name: String,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDecl>,
    /// Variants in source order; discriminants are their zero-based index.
    pub variants: Vec<VariantDecl>,
}

/// Enum variant declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantDecl {
    /// Variant name.
    pub name: String,
    /// Payload fields.
    pub fields: VariantFieldsDecl,
}

/// Enum variant payload shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantFieldsDecl {
    /// Unit variant.
    Unit,
    /// Tuple variant fields.
    Tuple(Vec<TypeTag>),
    /// Struct variant fields.
    Struct(Vec<FieldDecl>),
}

/// `pub fn` declaration (spec §8.2 / §11.1).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FunctionDecl {
    /// Function name (`__petal_<name>` wasm export drops the prefix).
    pub name: String,
    /// True if this function is declared read-only and may be called as a view.
    pub view: bool,
    /// Generic parameters in declaration order.
    pub type_params: Vec<TypeParamDecl>,
    /// Argument decls in source order.
    pub args: Vec<ArgDecl>,
    /// Return TypeTags (one per Rust return position; a tuple is flattened).
    pub returns: Vec<TypeTag>,
    /// Count of distinct `&Signer` args.
    pub required_signers: u8,
    /// Capability args, by their declared TypeTag.
    pub required_capabilities: Vec<TypeTag>,
    /// Indices into `PetalManifestV0::invariants` that fire after this fn.
    pub attached_invariants: Vec<u16>,
}

/// Argument kind discriminant (spec §8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// `&Signer` reference.
    Signer,
    /// A canonical-codec-encoded literal of the given type.
    Const(TypeTag),
    /// An on-chain object with the given type + access mode.
    Object {
        /// Type tag of the borrowed object.
        ty: TypeTag,
        /// Access mode (ReadOnly / Mutable / Consume).
        mode: AccessMode,
    },
    /// `TypeTag` passed as a value to drive generic dispatch.
    TypeArg(u16),
}

/// Function-argument declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgDecl {
    /// Argument name (best-effort; underscored args appear as `_`).
    pub name: String,
    /// Argument kind.
    pub kind: ArgKind,
}

/// Invariant declaration (spec §12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantDecl {
    /// Human-readable invariant name.
    pub name: String,
    /// Object-type or function-exit target.
    pub target: InvariantTarget,
    /// Machine-readable predicate AST.
    pub predicate: PredicateAst,
    /// Wasm export name (`__inv_<idx>`).
    pub wasm_export: String,
}

/// Where the invariant attaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvariantTarget {
    /// Fires after every mutation of the named object type.
    ObjectType {
        /// Object type name.
        name: String,
    },
    /// Fires on exit from the named function.
    FunctionExit {
        /// Function name.
        name: String,
    },
}

/// Machine-readable summary of the invariant predicate. The actual
/// predicate body is compiled into the `__inv_<idx>` wasm export; this
/// enum is what the social layer reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PredicateAst {
    /// `lhs >= rhs` comparison over named fields.
    FieldGe {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// `lhs <= rhs` comparison over named fields.
    FieldLe {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// `lhs == rhs` comparison over named fields.
    FieldEq {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// Pool-style `S::k(p) >= p.k_last` invariant (spec §12.1).
    StrategyKNonDecreasing {
        /// Generic strategy parameter name (`S`).
        strategy_param: String,
        /// Pool field that stores the prior `k` value (`k_last`).
        pool_field: String,
    },
    /// Router-style "all pools' k non-decreasing" (spec §14.3).
    AllPoolsKNonDecreasing,
    /// Catch-all when the AST shape isn't recognized in v0.
    Opaque,
}

/// Wasm-side host-import declaration. Mirrors `bloom_objects::HostImport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostImportDecl {
    /// Wasm module name (`"object"`, `"cap"`, `"signer"`, `"ptb"`, `"log"`).
    pub module: String,
    /// Function name within the module.
    pub name: String,
    /// Wasm function signature.
    pub signature: WasmFuncSig,
}

/// Wasm function signature: parameter and result types.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WasmFuncSig {
    /// Parameter wasm value types.
    pub params: Vec<WasmValType>,
    /// Result wasm value types.
    pub results: Vec<WasmValType>,
}

/// Wasm value type variants used by the bloom host surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WasmValType {
    /// 32-bit signed integer.
    I32,
    /// 64-bit signed integer.
    I64,
}

/// External-type reference resolved at build time via `petals.lock`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExternalTypeRef {
    /// Placeholder string (e.g. `"$external_0"`).
    pub placeholder: String,
    /// VFS path of the petal that declares the type.
    pub declared_petal_path: String,
    /// Type name within that petal.
    pub declared_type_name: String,
    /// Content hash resolved by `petals.lock`, if any.
    pub declared_content_hash: Option<[u8; 32]>,
}

/// Per-function fuel ceiling hints (opt-in, advisory).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FuelHints {
    /// `(function_name, fuel_ceiling)` pairs.
    pub per_function: Vec<(String, u64)>,
    /// Default ceiling applied when a function lacks an explicit hint.
    pub default: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_three() {
        assert_eq!(SCHEMA_VERSION, 3);
    }

    #[test]
    fn semver_new() {
        let v = SemVer::new(0, 1, 2);
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 2);
    }

    #[test]
    fn default_manifest_is_empty() {
        let m = PetalManifestV0::default();
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert!(m.functions.is_empty());
        assert!(m.object_types.is_empty());
        assert!(m.capability_types.is_empty());
        assert!(m.data_types.is_empty());
        assert!(m.enum_types.is_empty());
    }

    #[test]
    fn type_param_kind_discrim_distinct() {
        assert_ne!(TypeParamKind::Phantom, TypeParamKind::Resource);
    }

    #[test]
    fn predicate_ast_variants_distinct() {
        let a = PredicateAst::FieldGe {
            lhs: "a".into(),
            rhs: "b".into(),
        };
        let b = PredicateAst::FieldLe {
            lhs: "a".into(),
            rhs: "b".into(),
        };
        assert_ne!(a, b);
    }
}
