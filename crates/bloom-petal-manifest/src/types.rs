//! `PetalManifest` — the canonical manifest schema emitted by
//! `#[bloom::petal]` as a wasm custom section (spec §8, §8.2).
//!
//! These types are pure data; no `syn`/`quote` dependencies. The
//! canonical codec lives in [`crate::codec`], and a
//! [`crate::stub::to_petal_manifest_stub`] conversion produces the
//! validator's lean view ([`bloom_script::PetalManifestStub`]).

use bloom_objects::{AbilitySet, AccessMode, TypeTag};

/// Schema version this crate produces. Bumped when the manifest layout
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 4;

/// Custom section name embedded into every new-framework petal (spec §8.1).
pub const MANIFEST_CUSTOM_SECTION: &str = "bloom_petal_manifest";

/// Top-level manifest emitted by `#[bloom::petal]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PetalManifest {
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

impl Default for PetalManifest {
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

/// Fixed canonical byte width of a field type, or `None` for
/// variable-width types (ADR-011, S7a–S7d).
///
/// The widths mirror the canonical payload encoding: fixed-width
/// integers are their byte size; `bool` is one byte; the 32-byte
/// identity/hash types (`ObjectId`/`Address`/`Hash32`/`UID`) and the
/// `Coin<T>`/`Resource<T>` object-handle wrappers are 32 bytes.
/// Variable-width types (`Vec<u8>`, `String`, a nested `TypeTag`) and
/// unresolved generics return `None`.
pub fn canonical_byte_width(ty: &TypeTag) -> Option<u32> {
    match ty {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => {
            if !type_args.is_empty() {
                // The only fixed-width generic carriers are the 32-byte
                // object-handle wrappers.
                return match type_name.as_str() {
                    "Coin" | "Resource" => Some(32),
                    _ => None,
                };
            }
            match type_name.as_str() {
                "u8" | "bool" => Some(1),
                "u16" => Some(2),
                "u32" => Some(4),
                "u64" => Some(8),
                "u128" => Some(16),
                "ObjectId" | "Address" | "Hash32" | "UID" => Some(32),
                _ => None,
            }
        }
        TypeTag::Generic { .. } | TypeTag::External { .. } => None,
    }
}

/// Numeric field width accepted by the v1 invariant field-table evaluator.
///
/// This is intentionally narrower than [`canonical_byte_width`]: booleans are
/// fixed-width in the canonical codec, but their semantic domain is `{0, 1}`,
/// not the full `u8` range. Until the invariant schema carries scalar-domain
/// metadata, only unsigned integer primitives are exposed as numeric fields.
pub fn invariant_numeric_byte_width(ty: &TypeTag) -> Option<u32> {
    match ty {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } if type_args.is_empty() => match type_name.as_str() {
            "u8" => Some(1),
            "u16" => Some(2),
            "u32" => Some(4),
            "u64" => Some(8),
            "u128" => Some(16),
            _ => None,
        },
        _ => None,
    }
}

/// Field on an `#[object]` struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    /// Field name.
    pub name: String,
    /// Field's recorded `TypeTag` (best-effort, see `crate::type_tag`).
    pub ty: TypeTag,
    /// Byte offset of this field within the canonical object payload, or
    /// `None` if not statically known (ADR-011). Under the *fixed-prefix
    /// rule*, `offset` is `Some` only while every preceding field has a
    /// known fixed width; the first variable-width field and everything
    /// after it are `None` and not invariant-addressable in v1.
    pub offset: Option<u32>,
    /// Fixed canonical byte width of this field, or `None` for
    /// variable-width types (`Vec<u8>`, `String`, nested `TypeTag`).
    pub width: Option<u32>,
}

/// `true` iff `ty` is one of the unsigned integer types the invariant
/// evaluator models as a numeric `u128` domain.
///
/// `bool` is deliberately excluded even though its canonical width is one
/// byte: treating it as a numeric `u8` admits arithmetic/domain claims that
/// are not boolean semantics.
pub fn is_numeric_invariant_type(ty: &TypeTag) -> bool {
    invariant_numeric_byte_width(ty).is_some()
}

/// `true` iff `field` can be exposed in the v1 invariant numeric scope:
/// fixed-prefix, at most 16 bytes wide, and an unsigned integer type.
pub fn is_numeric_invariant_field(field: &FieldDecl) -> bool {
    field.offset.is_some() && field.width == invariant_numeric_byte_width(&field.ty)
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
    /// Indices into `PetalManifest::invariants` that fire after this fn.
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
    /// Optional natural-language claim paired with the predicate (ADR-003,
    /// spec↔intent). Empty string = none. Not consumed by evaluation; it is
    /// surfaced for rendering/arbitration and is the human half the
    /// deploy-time intent-conformance work checks against.
    pub human_text: String,
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
    /// Bounded-arithmetic comparison `lhs <op> rhs` over scope fields
    /// (plan §7). Operands are `u128`; intermediates widen so the
    /// comparison never overflows. This is the general form that, e.g.,
    /// `after.reserve_a * after.reserve_b >= before.k_last` lowers to.
    ArithCmp {
        /// Comparison operator.
        op: CmpOp,
        /// Left-hand arithmetic expression.
        lhs: ArithExpr,
        /// Right-hand arithmetic expression.
        rhs: ArithExpr,
    },
    /// Boolean conjunction (`lhs && rhs`).
    And(Box<PredicateAst>, Box<PredicateAst>),
    /// Boolean disjunction (`lhs || rhs`).
    Or(Box<PredicateAst>, Box<PredicateAst>),
    /// Boolean negation (`!inner`).
    Not(Box<PredicateAst>),
    /// Catch-all when the AST shape isn't recognized in v0.
    Opaque,
}

/// Comparison operator for [`PredicateAst::ArithCmp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    /// `>=`
    Ge,
    /// `<=`
    Le,
    /// `==`
    Eq,
}

/// Checked arithmetic operation (plan §7). Operands widen per
/// [`Widening`]; overflow follows [`OverflowPolicy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedArithOp {
    /// Checked addition.
    Add,
    /// Checked subtraction (saturating at zero is *not* implied).
    Sub,
    /// Checked multiplication.
    Mul,
}

/// Intermediate widening domain for bounded arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Widening {
    /// Stay in `u128`; overflow follows [`OverflowPolicy`].
    None,
    /// Widen intermediates to 256 bits.
    U256,
    /// Widen intermediates to 512 bits.
    U512,
}

/// What to do when a bounded-arithmetic step overflows its domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Overflow ⇒ the predicate result is indeterminate (never violated).
    Indeterminate,
    /// Overflow ⇒ saturate at the domain max (rarely correct).
    Saturate,
}

/// An arithmetic expression over scope fields, evaluated with checked
/// widening arithmetic. Realizes plan §7's `BoundedArith` as a
/// composable, SMT-encodable value node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArithExpr {
    /// Reference to a named scope field (e.g. `"after.reserve_a"`).
    Field(String),
    /// A literal `u128` value.
    Literal(u128),
    /// `lhs <op> rhs` with the given widening / overflow policy.
    Bounded {
        /// Arithmetic operation.
        op: BoundedArithOp,
        /// Left operand.
        lhs: Box<ArithExpr>,
        /// Right operand.
        rhs: Box<ArithExpr>,
        /// Intermediate widening domain.
        widening: Widening,
        /// Overflow behaviour.
        on_overflow: OverflowPolicy,
    },
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
    fn schema_version_is_four() {
        assert_eq!(SCHEMA_VERSION, 4);
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
        let m = PetalManifest::default();
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

    #[test]
    fn invariant_numeric_width_excludes_bool_domain() {
        let tag = |name: &str| TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        };

        assert_eq!(canonical_byte_width(&tag("bool")), Some(1));
        assert_eq!(invariant_numeric_byte_width(&tag("bool")), None);
        assert!(!is_numeric_invariant_type(&tag("bool")));

        assert_eq!(invariant_numeric_byte_width(&tag("u8")), Some(1));
        assert!(is_numeric_invariant_type(&tag("u128")));
    }

    #[test]
    fn invariant_numeric_field_requires_unsigned_integer_layout() {
        let tag = |name: &str| TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        };
        let field = |name: &str, ty: TypeTag, width: Option<u32>| FieldDecl {
            name: name.to_string(),
            ty,
            offset: Some(0),
            width,
        };

        assert!(is_numeric_invariant_field(&field("x", tag("u64"), Some(8))));
        assert!(!is_numeric_invariant_field(&field(
            "enabled",
            tag("bool"),
            Some(1)
        )));
        assert!(!is_numeric_invariant_field(&field("x", tag("u64"), None)));
        assert!(!is_numeric_invariant_field(&field(
            "x",
            tag("u64"),
            Some(16)
        )));
    }
}
