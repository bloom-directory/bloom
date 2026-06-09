//! Canonical encoder / decoder for [`crate::types::PetalManifest`].
//!
//! Wire format (deterministic, BE):
//! - 4-byte BE counts for lists.
//! - 2-byte BE counts for short lists (strings, type-args).
//! - 1-byte enum discriminants.
//! - `TypeTag` via [`bloom_objects::TypeTag::encode_into`].
//!
//! The codec is symmetric (round-trip preserves bytes). The validator-side
//! projection ([`bloom_script::PetalManifestStub`]) is built by
//! [`crate::stub::to_petal_manifest_stub`] from a decoded manifest, so
//! both the proc-macros (compile-time encode) and the chain node
//! (runtime decode + project) share the same canonical schema.

use bloom_objects::codec::{
    self, CodecError, read_bytes32, read_string, read_u8, read_u16_be, read_u32_be, read_u64_be,
    write_bytes32, write_string, write_u8, write_u16_be, write_u32_be, write_u64_be,
};
use bloom_objects::{AbilitySet, AccessMode, TypeTag};

use crate::types::{
    ArgDecl, ArgKind, ArithExpr, BoundedArithOp, CapabilityDecl, CmpOp, DataTypeDecl, EnumTypeDecl,
    ExternalTypeRef, FieldDecl, FuelHints, FunctionDecl, HostImportDecl, InvariantDecl,
    InvariantTarget, ObjectTypeDecl, OverflowPolicy, PetalManifest, PredicateAst, SCHEMA_VERSION,
    SemVer, TypeParamDecl, TypeParamKind, VariantDecl, VariantFieldsDecl, WasmFuncSig, WasmValType,
    Widening,
};

const MAX_MANIFEST_LIST_ITEMS: usize = 16_384;

// ===========================================================================
// Public API
// ===========================================================================

/// Canonical-encode the manifest into a fresh `Vec<u8>`.
pub fn encode(manifest: &PetalManifest) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_into(manifest, &mut out)?;
    Ok(out)
}

/// Canonical-encode the manifest into an existing buffer.
pub fn encode_into(manifest: &PetalManifest, buf: &mut Vec<u8>) -> Result<(), CodecError> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(CodecError::InvalidLength(manifest.schema_version as u64));
    }
    write_u32_be(buf, manifest.schema_version);
    write_string(buf, &manifest.module_path)?;
    write_semver(buf, &manifest.framework_version);
    write_option_hash(buf, manifest.parent_version.as_ref());
    write_list(buf, &manifest.object_types, write_object_type_decl)?;
    write_list(buf, &manifest.capability_types, write_capability_decl)?;
    write_list(buf, &manifest.data_types, write_data_type_decl)?;
    write_list(buf, &manifest.enum_types, write_enum_type_decl)?;
    write_list(buf, &manifest.functions, write_function_decl)?;
    write_list(buf, &manifest.invariants, write_invariant_decl)?;
    write_list(buf, &manifest.required_host_imports, write_host_import_decl)?;
    write_list(buf, &manifest.external_type_refs, write_external_type_ref)?;
    write_fuel_hints(buf, &manifest.fuel_hints)?;
    Ok(())
}

/// Canonical-decode a manifest from `bytes`, rejecting trailing data.
pub fn decode(bytes: &[u8]) -> Result<PetalManifest, CodecError> {
    let mut rdr = bytes;
    let m = decode_from(&mut rdr)?;
    codec::expect_eof(rdr)?;
    Ok(m)
}

/// Decode from a cursor (allows trailing bytes; used when nested).
pub fn decode_from(rdr: &mut &[u8]) -> Result<PetalManifest, CodecError> {
    let schema_version = read_u32_be(rdr)?;
    if schema_version != SCHEMA_VERSION {
        return Err(CodecError::InvalidLength(schema_version as u64));
    }
    let module_path = read_string(rdr)?;
    let framework_version = read_semver(rdr)?;
    let parent_version = read_option_hash(rdr)?;
    let object_types = read_list(rdr, read_object_type_decl)?;
    let capability_types = read_list(rdr, read_capability_decl)?;
    let data_types = read_list(rdr, read_data_type_decl)?;
    let enum_types = read_list(rdr, read_enum_type_decl)?;
    let functions = read_list(rdr, read_function_decl)?;
    let invariants = read_list(rdr, read_invariant_decl)?;
    let required_host_imports = read_list(rdr, read_host_import_decl)?;
    let external_type_refs = read_list(rdr, read_external_type_ref)?;
    let fuel_hints = read_fuel_hints(rdr)?;
    Ok(PetalManifest {
        schema_version,
        module_path,
        framework_version,
        parent_version,
        object_types,
        capability_types,
        data_types,
        enum_types,
        functions,
        invariants,
        required_host_imports,
        external_type_refs,
        fuel_hints,
    })
}

// ===========================================================================
// Sub-encoders
// ===========================================================================

fn write_list<T, F>(buf: &mut Vec<u8>, items: &[T], mut w: F) -> Result<(), CodecError>
where
    F: FnMut(&mut Vec<u8>, &T) -> Result<(), CodecError>,
{
    let len: u32 =
        u32::try_from(items.len()).map_err(|_| CodecError::LengthOverflow(items.len() as u64))?;
    write_u32_be(buf, len);
    for item in items {
        w(buf, item)?;
    }
    Ok(())
}

fn read_list<T, F>(rdr: &mut &[u8], mut r: F) -> Result<Vec<T>, CodecError>
where
    F: FnMut(&mut &[u8]) -> Result<T, CodecError>,
{
    let len = read_u32_be(rdr)? as usize;
    if len > MAX_MANIFEST_LIST_ITEMS || len > rdr.len() {
        return Err(CodecError::InvalidLength(len as u64));
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(r(rdr)?);
    }
    Ok(out)
}

fn write_semver(buf: &mut Vec<u8>, v: &SemVer) {
    write_u16_be(buf, v.major);
    write_u16_be(buf, v.minor);
    write_u16_be(buf, v.patch);
}

fn read_semver(rdr: &mut &[u8]) -> Result<SemVer, CodecError> {
    let major = read_u16_be(rdr)?;
    let minor = read_u16_be(rdr)?;
    let patch = read_u16_be(rdr)?;
    Ok(SemVer {
        major,
        minor,
        patch,
    })
}

fn write_option_hash(buf: &mut Vec<u8>, h: Option<&[u8; 32]>) {
    match h {
        Some(bytes) => {
            write_u8(buf, 1);
            write_bytes32(buf, bytes);
        }
        None => write_u8(buf, 0),
    }
}

fn read_option_hash(rdr: &mut &[u8]) -> Result<Option<[u8; 32]>, CodecError> {
    let tag = read_u8(rdr)?;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_bytes32(rdr)?)),
        other => Err(CodecError::InvalidDiscriminant(other)),
    }
}

fn write_type_param(buf: &mut Vec<u8>, p: &TypeParamDecl) -> Result<(), CodecError> {
    write_string(buf, &p.name)?;
    let kind: u8 = match p.kind {
        TypeParamKind::Phantom => 0,
        TypeParamKind::Resource => 1,
    };
    write_u8(buf, kind);
    write_list(buf, &p.bounds, write_type_tag)?;
    Ok(())
}

fn read_type_param(rdr: &mut &[u8]) -> Result<TypeParamDecl, CodecError> {
    let name = read_string(rdr)?;
    let kind = match read_u8(rdr)? {
        0 => TypeParamKind::Phantom,
        1 => TypeParamKind::Resource,
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    let bounds = read_list(rdr, read_type_tag)?;
    Ok(TypeParamDecl { name, kind, bounds })
}

fn write_type_tag(buf: &mut Vec<u8>, t: &TypeTag) -> Result<(), CodecError> {
    t.encode_into(buf)
}

fn read_type_tag(rdr: &mut &[u8]) -> Result<TypeTag, CodecError> {
    TypeTag::decode_from(rdr, 0)
}

fn write_opt_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(n) => {
            write_u8(buf, 1);
            write_u32_be(buf, n);
        }
        None => write_u8(buf, 0),
    }
}

fn read_opt_u32(rdr: &mut &[u8]) -> Result<Option<u32>, CodecError> {
    match read_u8(rdr)? {
        0 => Ok(None),
        1 => Ok(Some(read_u32_be(rdr)?)),
        other => Err(CodecError::InvalidDiscriminant(other)),
    }
}

fn write_field_decl(buf: &mut Vec<u8>, f: &FieldDecl) -> Result<(), CodecError> {
    write_string(buf, &f.name)?;
    write_type_tag(buf, &f.ty)?;
    write_opt_u32(buf, f.offset);
    write_opt_u32(buf, f.width);
    Ok(())
}

fn read_field_decl(rdr: &mut &[u8]) -> Result<FieldDecl, CodecError> {
    let name = read_string(rdr)?;
    let ty = read_type_tag(rdr)?;
    let offset = read_opt_u32(rdr)?;
    let width = read_opt_u32(rdr)?;
    Ok(FieldDecl {
        name,
        ty,
        offset,
        width,
    })
}

fn write_object_type_decl(buf: &mut Vec<u8>, o: &ObjectTypeDecl) -> Result<(), CodecError> {
    write_string(buf, &o.name)?;
    write_u8(buf, o.abilities.bits());
    write_list(buf, &o.type_params, write_type_param)?;
    write_list(buf, &o.fields, write_field_decl)?;
    Ok(())
}

fn read_object_type_decl(rdr: &mut &[u8]) -> Result<ObjectTypeDecl, CodecError> {
    let name = read_string(rdr)?;
    let abilities = AbilitySet::from_bits(read_u8(rdr)?);
    let type_params = read_list(rdr, read_type_param)?;
    let fields = read_list(rdr, read_field_decl)?;
    Ok(ObjectTypeDecl {
        name,
        abilities,
        type_params,
        fields,
    })
}

fn write_capability_decl(buf: &mut Vec<u8>, c: &CapabilityDecl) -> Result<(), CodecError> {
    write_string(buf, &c.name)?;
    write_list(buf, &c.type_params, write_type_param)?;
    write_list(buf, &c.fields, write_field_decl)?;
    Ok(())
}

fn read_capability_decl(rdr: &mut &[u8]) -> Result<CapabilityDecl, CodecError> {
    let name = read_string(rdr)?;
    let type_params = read_list(rdr, read_type_param)?;
    let fields = read_list(rdr, read_field_decl)?;
    Ok(CapabilityDecl {
        name,
        type_params,
        fields,
    })
}

fn write_data_type_decl(buf: &mut Vec<u8>, d: &DataTypeDecl) -> Result<(), CodecError> {
    write_string(buf, &d.name)?;
    write_list(buf, &d.type_params, write_type_param)?;
    write_list(buf, &d.fields, write_field_decl)?;
    Ok(())
}

fn read_data_type_decl(rdr: &mut &[u8]) -> Result<DataTypeDecl, CodecError> {
    let name = read_string(rdr)?;
    let type_params = read_list(rdr, read_type_param)?;
    let fields = read_list(rdr, read_field_decl)?;
    Ok(DataTypeDecl {
        name,
        type_params,
        fields,
    })
}

fn write_enum_type_decl(buf: &mut Vec<u8>, e: &EnumTypeDecl) -> Result<(), CodecError> {
    write_string(buf, &e.name)?;
    write_list(buf, &e.type_params, write_type_param)?;
    write_list(buf, &e.variants, write_variant_decl)?;
    Ok(())
}

fn read_enum_type_decl(rdr: &mut &[u8]) -> Result<EnumTypeDecl, CodecError> {
    let name = read_string(rdr)?;
    let type_params = read_list(rdr, read_type_param)?;
    let variants = read_list(rdr, read_variant_decl)?;
    Ok(EnumTypeDecl {
        name,
        type_params,
        variants,
    })
}

fn write_variant_decl(buf: &mut Vec<u8>, v: &VariantDecl) -> Result<(), CodecError> {
    write_string(buf, &v.name)?;
    match &v.fields {
        VariantFieldsDecl::Unit => write_u8(buf, 0),
        VariantFieldsDecl::Tuple(types) => {
            write_u8(buf, 1);
            write_list(buf, types, write_type_tag)?;
        }
        VariantFieldsDecl::Struct(fields) => {
            write_u8(buf, 2);
            write_list(buf, fields, write_field_decl)?;
        }
    }
    Ok(())
}

fn read_variant_decl(rdr: &mut &[u8]) -> Result<VariantDecl, CodecError> {
    let name = read_string(rdr)?;
    let fields = match read_u8(rdr)? {
        0 => VariantFieldsDecl::Unit,
        1 => VariantFieldsDecl::Tuple(read_list(rdr, read_type_tag)?),
        2 => VariantFieldsDecl::Struct(read_list(rdr, read_field_decl)?),
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    Ok(VariantDecl { name, fields })
}

fn write_arg_decl(buf: &mut Vec<u8>, a: &ArgDecl) -> Result<(), CodecError> {
    write_string(buf, &a.name)?;
    match &a.kind {
        ArgKind::Signer => {
            write_u8(buf, 0);
        }
        ArgKind::Const(ty) => {
            write_u8(buf, 1);
            write_type_tag(buf, ty)?;
        }
        ArgKind::Object { ty, mode } => {
            write_u8(buf, 2);
            write_type_tag(buf, ty)?;
            write_u8(buf, mode.as_byte());
        }
        ArgKind::TypeArg(idx) => {
            write_u8(buf, 3);
            write_u16_be(buf, *idx);
        }
    }
    Ok(())
}

fn read_arg_decl(rdr: &mut &[u8]) -> Result<ArgDecl, CodecError> {
    let name = read_string(rdr)?;
    let kind = match read_u8(rdr)? {
        0 => ArgKind::Signer,
        1 => ArgKind::Const(read_type_tag(rdr)?),
        2 => {
            let ty = read_type_tag(rdr)?;
            let mode = AccessMode::from_byte(read_u8(rdr)?)?;
            ArgKind::Object { ty, mode }
        }
        3 => ArgKind::TypeArg(read_u16_be(rdr)?),
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    Ok(ArgDecl { name, kind })
}

fn write_function_decl(buf: &mut Vec<u8>, f: &FunctionDecl) -> Result<(), CodecError> {
    write_string(buf, &f.name)?;
    write_u8(buf, u8::from(f.view));
    write_list(buf, &f.type_params, write_type_param)?;
    write_list(buf, &f.args, write_arg_decl)?;
    write_list(buf, &f.returns, write_type_tag)?;
    write_u8(buf, f.required_signers);
    write_list(buf, &f.required_capabilities, write_type_tag)?;
    let inv_len: u32 = u32::try_from(f.attached_invariants.len())
        .map_err(|_| CodecError::LengthOverflow(f.attached_invariants.len() as u64))?;
    write_u32_be(buf, inv_len);
    for idx in &f.attached_invariants {
        write_u16_be(buf, *idx);
    }
    Ok(())
}

fn read_function_decl(rdr: &mut &[u8]) -> Result<FunctionDecl, CodecError> {
    let name = read_string(rdr)?;
    let view = match read_u8(rdr)? {
        0 => false,
        1 => true,
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    let type_params = read_list(rdr, read_type_param)?;
    let args = read_list(rdr, read_arg_decl)?;
    let returns = read_list(rdr, read_type_tag)?;
    let required_signers = read_u8(rdr)?;
    let required_capabilities = read_list(rdr, read_type_tag)?;
    let inv_len = read_u32_be(rdr)? as usize;
    let mut attached_invariants = Vec::with_capacity(inv_len);
    for _ in 0..inv_len {
        attached_invariants.push(read_u16_be(rdr)?);
    }
    Ok(FunctionDecl {
        name,
        view,
        type_params,
        args,
        returns,
        required_signers,
        required_capabilities,
        attached_invariants,
    })
}

fn write_invariant_decl(buf: &mut Vec<u8>, inv: &InvariantDecl) -> Result<(), CodecError> {
    write_string(buf, &inv.name)?;
    match &inv.target {
        InvariantTarget::ObjectType { name } => {
            write_u8(buf, 0);
            write_string(buf, name)?;
        }
        InvariantTarget::FunctionExit { name } => {
            write_u8(buf, 1);
            write_string(buf, name)?;
        }
    }
    write_predicate(buf, &inv.predicate)?;
    write_string(buf, &inv.wasm_export)?;
    write_string(buf, &inv.human_text)?;
    Ok(())
}

fn read_invariant_decl(rdr: &mut &[u8]) -> Result<InvariantDecl, CodecError> {
    let name = read_string(rdr)?;
    let target = match read_u8(rdr)? {
        0 => InvariantTarget::ObjectType {
            name: read_string(rdr)?,
        },
        1 => InvariantTarget::FunctionExit {
            name: read_string(rdr)?,
        },
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    let predicate = read_predicate(rdr)?;
    let wasm_export = read_string(rdr)?;
    let human_text = read_string(rdr)?;
    Ok(InvariantDecl {
        name,
        target,
        predicate,
        wasm_export,
        human_text,
    })
}

fn write_predicate(buf: &mut Vec<u8>, p: &PredicateAst) -> Result<(), CodecError> {
    match p {
        PredicateAst::FieldGe { lhs, rhs } => {
            write_u8(buf, 0);
            write_string(buf, lhs)?;
            write_string(buf, rhs)?;
        }
        PredicateAst::FieldLe { lhs, rhs } => {
            write_u8(buf, 1);
            write_string(buf, lhs)?;
            write_string(buf, rhs)?;
        }
        PredicateAst::FieldEq { lhs, rhs } => {
            write_u8(buf, 2);
            write_string(buf, lhs)?;
            write_string(buf, rhs)?;
        }
        PredicateAst::StrategyKNonDecreasing {
            strategy_param,
            pool_field,
        } => {
            write_u8(buf, 3);
            write_string(buf, strategy_param)?;
            write_string(buf, pool_field)?;
        }
        PredicateAst::AllPoolsKNonDecreasing => {
            write_u8(buf, 4);
        }
        PredicateAst::Opaque => {
            write_u8(buf, 5);
        }
        PredicateAst::ArithCmp { op, lhs, rhs } => {
            write_u8(buf, 6);
            write_u8(buf, cmp_op_tag(*op));
            write_arith_expr(buf, lhs)?;
            write_arith_expr(buf, rhs)?;
        }
        PredicateAst::And(lhs, rhs) => {
            write_u8(buf, 7);
            write_predicate(buf, lhs)?;
            write_predicate(buf, rhs)?;
        }
        PredicateAst::Or(lhs, rhs) => {
            write_u8(buf, 8);
            write_predicate(buf, lhs)?;
            write_predicate(buf, rhs)?;
        }
        PredicateAst::Not(inner) => {
            write_u8(buf, 9);
            write_predicate(buf, inner)?;
        }
    }
    Ok(())
}

fn cmp_op_tag(op: CmpOp) -> u8 {
    match op {
        CmpOp::Ge => 0,
        CmpOp::Le => 1,
        CmpOp::Eq => 2,
    }
}

fn read_cmp_op(rdr: &mut &[u8]) -> Result<CmpOp, CodecError> {
    Ok(match read_u8(rdr)? {
        0 => CmpOp::Ge,
        1 => CmpOp::Le,
        2 => CmpOp::Eq,
        other => return Err(CodecError::InvalidDiscriminant(other)),
    })
}

fn write_arith_expr(buf: &mut Vec<u8>, e: &ArithExpr) -> Result<(), CodecError> {
    match e {
        ArithExpr::Field(name) => {
            write_u8(buf, 0);
            write_string(buf, name)?;
        }
        ArithExpr::Literal(v) => {
            write_u8(buf, 1);
            write_u64_be(buf, (*v >> 64) as u64);
            write_u64_be(buf, *v as u64);
        }
        ArithExpr::Bounded {
            op,
            lhs,
            rhs,
            widening,
            on_overflow,
        } => {
            write_u8(buf, 2);
            write_u8(
                buf,
                match op {
                    BoundedArithOp::Add => 0,
                    BoundedArithOp::Sub => 1,
                    BoundedArithOp::Mul => 2,
                },
            );
            write_u8(
                buf,
                match widening {
                    Widening::None => 0,
                    Widening::U256 => 1,
                    Widening::U512 => 2,
                },
            );
            write_u8(
                buf,
                match on_overflow {
                    OverflowPolicy::Indeterminate => 0,
                    OverflowPolicy::Saturate => 1,
                },
            );
            write_arith_expr(buf, lhs)?;
            write_arith_expr(buf, rhs)?;
        }
    }
    Ok(())
}

fn read_arith_expr_at(rdr: &mut &[u8], depth: u32) -> Result<ArithExpr, CodecError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(CodecError::RecursionLimit);
    }
    Ok(match read_u8(rdr)? {
        0 => ArithExpr::Field(read_string(rdr)?),
        1 => {
            let hi = read_u64_be(rdr)? as u128;
            let lo = read_u64_be(rdr)? as u128;
            ArithExpr::Literal((hi << 64) | lo)
        }
        2 => {
            let op = match read_u8(rdr)? {
                0 => BoundedArithOp::Add,
                1 => BoundedArithOp::Sub,
                2 => BoundedArithOp::Mul,
                other => return Err(CodecError::InvalidDiscriminant(other)),
            };
            let widening = match read_u8(rdr)? {
                0 => Widening::None,
                1 => Widening::U256,
                2 => Widening::U512,
                other => return Err(CodecError::InvalidDiscriminant(other)),
            };
            let on_overflow = match read_u8(rdr)? {
                0 => OverflowPolicy::Indeterminate,
                1 => OverflowPolicy::Saturate,
                other => return Err(CodecError::InvalidDiscriminant(other)),
            };
            let lhs = Box::new(read_arith_expr_at(rdr, depth + 1)?);
            let rhs = Box::new(read_arith_expr_at(rdr, depth + 1)?);
            ArithExpr::Bounded {
                op,
                lhs,
                rhs,
                widening,
                on_overflow,
            }
        }
        other => return Err(CodecError::InvalidDiscriminant(other)),
    })
}

/// Maximum nesting depth a decoded `PredicateAst` / `ArithExpr` may reach.
/// A malicious manifest with a deeply-nested predicate would otherwise
/// stack-overflow the decoder (and thus the validating node) before any
/// higher-level gate runs. Far above any legitimate predicate; the deploy
/// fuel-headroom gate rejects merely-large (sub-overflow) predicates.
const MAX_PREDICATE_DEPTH: u32 = 256;

fn read_predicate(rdr: &mut &[u8]) -> Result<PredicateAst, CodecError> {
    read_predicate_at(rdr, 0)
}

fn read_predicate_at(rdr: &mut &[u8], depth: u32) -> Result<PredicateAst, CodecError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(CodecError::RecursionLimit);
    }
    Ok(match read_u8(rdr)? {
        0 => PredicateAst::FieldGe {
            lhs: read_string(rdr)?,
            rhs: read_string(rdr)?,
        },
        1 => PredicateAst::FieldLe {
            lhs: read_string(rdr)?,
            rhs: read_string(rdr)?,
        },
        2 => PredicateAst::FieldEq {
            lhs: read_string(rdr)?,
            rhs: read_string(rdr)?,
        },
        3 => PredicateAst::StrategyKNonDecreasing {
            strategy_param: read_string(rdr)?,
            pool_field: read_string(rdr)?,
        },
        4 => PredicateAst::AllPoolsKNonDecreasing,
        5 => PredicateAst::Opaque,
        6 => PredicateAst::ArithCmp {
            op: read_cmp_op(rdr)?,
            lhs: read_arith_expr_at(rdr, depth + 1)?,
            rhs: read_arith_expr_at(rdr, depth + 1)?,
        },
        7 => PredicateAst::And(
            Box::new(read_predicate_at(rdr, depth + 1)?),
            Box::new(read_predicate_at(rdr, depth + 1)?),
        ),
        8 => PredicateAst::Or(
            Box::new(read_predicate_at(rdr, depth + 1)?),
            Box::new(read_predicate_at(rdr, depth + 1)?),
        ),
        9 => PredicateAst::Not(Box::new(read_predicate_at(rdr, depth + 1)?)),
        other => return Err(CodecError::InvalidDiscriminant(other)),
    })
}

fn write_host_import_decl(buf: &mut Vec<u8>, h: &HostImportDecl) -> Result<(), CodecError> {
    write_string(buf, &h.module)?;
    write_string(buf, &h.name)?;
    write_wasm_func_sig(buf, &h.signature)?;
    Ok(())
}

fn read_host_import_decl(rdr: &mut &[u8]) -> Result<HostImportDecl, CodecError> {
    let module = read_string(rdr)?;
    let name = read_string(rdr)?;
    let signature = read_wasm_func_sig(rdr)?;
    Ok(HostImportDecl {
        module,
        name,
        signature,
    })
}

fn write_wasm_func_sig(buf: &mut Vec<u8>, s: &WasmFuncSig) -> Result<(), CodecError> {
    write_list(buf, &s.params, |b, v| {
        write_u8(b, wasm_val_type_byte(*v));
        Ok(())
    })?;
    write_list(buf, &s.results, |b, v| {
        write_u8(b, wasm_val_type_byte(*v));
        Ok(())
    })?;
    Ok(())
}

fn read_wasm_func_sig(rdr: &mut &[u8]) -> Result<WasmFuncSig, CodecError> {
    let params = read_list(rdr, read_wasm_val_type)?;
    let results = read_list(rdr, read_wasm_val_type)?;
    Ok(WasmFuncSig { params, results })
}

fn wasm_val_type_byte(v: WasmValType) -> u8 {
    match v {
        WasmValType::I32 => 0,
        WasmValType::I64 => 1,
    }
}

fn read_wasm_val_type(rdr: &mut &[u8]) -> Result<WasmValType, CodecError> {
    Ok(match read_u8(rdr)? {
        0 => WasmValType::I32,
        1 => WasmValType::I64,
        other => return Err(CodecError::InvalidDiscriminant(other)),
    })
}

fn write_external_type_ref(buf: &mut Vec<u8>, r: &ExternalTypeRef) -> Result<(), CodecError> {
    write_string(buf, &r.placeholder)?;
    write_string(buf, &r.declared_petal_path)?;
    write_string(buf, &r.declared_type_name)?;
    write_option_hash(buf, r.declared_content_hash.as_ref());
    Ok(())
}

fn read_external_type_ref(rdr: &mut &[u8]) -> Result<ExternalTypeRef, CodecError> {
    let placeholder = read_string(rdr)?;
    let declared_petal_path = read_string(rdr)?;
    let declared_type_name = read_string(rdr)?;
    let declared_content_hash = read_option_hash(rdr)?;
    Ok(ExternalTypeRef {
        placeholder,
        declared_petal_path,
        declared_type_name,
        declared_content_hash,
    })
}

fn write_fuel_hints(buf: &mut Vec<u8>, f: &FuelHints) -> Result<(), CodecError> {
    let len: u32 = u32::try_from(f.per_function.len())
        .map_err(|_| CodecError::LengthOverflow(f.per_function.len() as u64))?;
    write_u32_be(buf, len);
    for (name, fuel) in &f.per_function {
        write_string(buf, name)?;
        write_u64_be(buf, *fuel);
    }
    match f.default {
        Some(d) => {
            write_u8(buf, 1);
            write_u64_be(buf, d);
        }
        None => write_u8(buf, 0),
    }
    Ok(())
}

fn read_fuel_hints(rdr: &mut &[u8]) -> Result<FuelHints, CodecError> {
    let len = read_u32_be(rdr)? as usize;
    let mut per_function = Vec::with_capacity(len);
    for _ in 0..len {
        let name = read_string(rdr)?;
        let fuel = read_u64_be(rdr)?;
        per_function.push((name, fuel));
    }
    let default = match read_u8(rdr)? {
        0 => None,
        1 => Some(read_u64_be(rdr)?),
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    Ok(FuelHints {
        per_function,
        default,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn sample() -> PetalManifest {
        PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/bloom/petals/dex/pool".to_string(),
            framework_version: SemVer::new(0, 1, 0),
            parent_version: None,
            object_types: vec![ObjectTypeDecl {
                name: "Pool".to_string(),
                abilities: AbilitySet::key_store(),
                type_params: vec![TypeParamDecl {
                    name: "A".to_string(),
                    kind: TypeParamKind::Phantom,
                    bounds: vec![],
                }],
                fields: vec![FieldDecl {
                    name: "id".to_string(),
                    ty: TypeTag::Concrete {
                        petal_hash: [0u8; 32],
                        type_name: "UID".to_string(),
                        type_args: vec![],
                    },
                    offset: Some(0),
                    width: Some(32),
                }],
            }],
            capability_types: vec![CapabilityDecl {
                name: "AdminCap".to_string(),
                type_params: vec![],
                fields: vec![FieldDecl {
                    name: "id".to_string(),
                    ty: TypeTag::Concrete {
                        petal_hash: [0u8; 32],
                        type_name: "UID".to_string(),
                        type_args: vec![],
                    },
                    offset: Some(0),
                    width: Some(32),
                }],
            }],
            data_types: vec![DataTypeDecl {
                name: "Quote".to_string(),
                type_params: vec![],
                fields: vec![FieldDecl {
                    name: "amount".to_string(),
                    ty: TypeTag::Concrete {
                        petal_hash: [0u8; 32],
                        type_name: "u128".to_string(),
                        type_args: vec![],
                    },
                    offset: None,
                    width: Some(16),
                }],
            }],
            enum_types: vec![EnumTypeDecl {
                name: "Side".to_string(),
                type_params: vec![],
                variants: vec![
                    VariantDecl {
                        name: "Bid".to_string(),
                        fields: VariantFieldsDecl::Unit,
                    },
                    VariantDecl {
                        name: "Ask".to_string(),
                        fields: VariantFieldsDecl::Tuple(vec![TypeTag::Concrete {
                            petal_hash: [0u8; 32],
                            type_name: "u64".to_string(),
                            type_args: vec![],
                        }]),
                    },
                ],
            }],
            functions: vec![FunctionDecl {
                name: "swap".to_string(),
                view: false,
                type_params: vec![],
                args: vec![
                    ArgDecl {
                        name: "signer".to_string(),
                        kind: ArgKind::Signer,
                    },
                    ArgDecl {
                        name: "pool".to_string(),
                        kind: ArgKind::Object {
                            ty: TypeTag::Concrete {
                                petal_hash: [0u8; 32],
                                type_name: "Pool".to_string(),
                                type_args: vec![],
                            },
                            mode: AccessMode::Mutable,
                        },
                    },
                    ArgDecl {
                        name: "amount".to_string(),
                        kind: ArgKind::Const(TypeTag::Concrete {
                            petal_hash: [0u8; 32],
                            type_name: "u128".to_string(),
                            type_args: vec![],
                        }),
                    },
                ],
                returns: vec![],
                required_signers: 1,
                required_capabilities: vec![],
                attached_invariants: vec![0],
            }],
            invariants: vec![InvariantDecl {
                name: "k_non_decreasing".to_string(),
                target: InvariantTarget::FunctionExit {
                    name: "swap".to_string(),
                },
                predicate: PredicateAst::FieldGe {
                    lhs: "reserve_a".to_string(),
                    rhs: "k_last".to_string(),
                },
                wasm_export: "__inv_0".to_string(),
                human_text: String::new(),
            }],
            required_host_imports: vec![HostImportDecl {
                module: "object".to_string(),
                name: "borrow".to_string(),
                signature: WasmFuncSig {
                    params: vec![WasmValType::I32, WasmValType::I32],
                    results: vec![WasmValType::I32],
                },
            }],
            external_type_refs: vec![ExternalTypeRef {
                placeholder: "$external_0".to_string(),
                declared_petal_path: "/bloom/petals/core/fungible".to_string(),
                declared_type_name: "LOOM".to_string(),
                declared_content_hash: Some([0x42u8; 32]),
            }],
            fuel_hints: FuelHints {
                per_function: vec![("swap".to_string(), 50_000)],
                default: Some(10_000),
            },
        }
    }

    #[test]
    fn round_trip_full_sample() {
        let m = sample();
        let bytes = encode(&m).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn round_trip_empty() {
        let m = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/p".to_string(),
            framework_version: SemVer::new(0, 0, 1),
            ..Default::default()
        };
        let bytes = encode(&m).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn encoding_is_deterministic() {
        let m = sample();
        let a = encode(&m).unwrap();
        let b = encode(&m).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn snapshot_minimal_first_bytes() {
        // schema_version (4) || module_path ("/x" = 2 bytes)
        let m = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/x".to_string(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        };
        let bytes = encode(&m).unwrap();
        // [0,0,0,4] schema || [0,2] len || "/x" || semver [0,0,0,1,0,0] || option none [0] || empty declaration lists
        assert_eq!(&bytes[..4], &[0, 0, 0, 4]);
        assert_eq!(&bytes[4..6], &[0, 2]);
        assert_eq!(&bytes[6..8], b"/x");
        assert_eq!(&bytes[8..14], &[0, 0, 0, 1, 0, 0]);
        // parent_version = None
        assert_eq!(bytes[14], 0);
    }

    #[test]
    fn rejects_invalid_tag() {
        let bad = vec![0xFFu8; 4];
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let m = PetalManifest::default();
        let mut bytes = encode(&m).unwrap();
        bytes.push(0xFF);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_list_length_before_preallocating() {
        let mut bytes = Vec::new();
        write_u32_be(&mut bytes, SCHEMA_VERSION);
        write_string(&mut bytes, "/p").unwrap();
        write_semver(&mut bytes, &SemVer::new(0, 0, 1));
        write_option_hash(&mut bytes, None);
        write_u32_be(&mut bytes, u32::MAX);

        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(n) if n == u32::MAX as u64));
    }

    #[test]
    fn arg_kind_object_round_trips_each_mode() {
        for mode in [
            AccessMode::ReadOnly,
            AccessMode::Mutable,
            AccessMode::Consume,
        ] {
            let m = PetalManifest {
                module_path: "/p".to_string(),
                functions: vec![FunctionDecl {
                    name: "f".to_string(),
                    view: false,
                    args: vec![ArgDecl {
                        name: "o".to_string(),
                        kind: ArgKind::Object {
                            ty: TypeTag::Concrete {
                                petal_hash: [0; 32],
                                type_name: "T".to_string(),
                                type_args: vec![],
                            },
                            mode,
                        },
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            };
            let bytes = encode(&m).unwrap();
            let back = decode(&bytes).unwrap();
            assert_eq!(back, m);
        }
    }

    #[test]
    fn predicate_variants_round_trip() {
        let variants = [
            PredicateAst::FieldGe {
                lhs: "a".into(),
                rhs: "b".into(),
            },
            PredicateAst::FieldLe {
                lhs: "a".into(),
                rhs: "b".into(),
            },
            PredicateAst::FieldEq {
                lhs: "a".into(),
                rhs: "b".into(),
            },
            PredicateAst::StrategyKNonDecreasing {
                strategy_param: "S".into(),
                pool_field: "k_last".into(),
            },
            PredicateAst::AllPoolsKNonDecreasing,
            PredicateAst::Opaque,
            PredicateAst::ArithCmp {
                op: CmpOp::Ge,
                lhs: ArithExpr::Bounded {
                    op: BoundedArithOp::Mul,
                    lhs: Box::new(ArithExpr::Field("after.reserve_a".into())),
                    rhs: Box::new(ArithExpr::Field("after.reserve_b".into())),
                    widening: Widening::U256,
                    on_overflow: OverflowPolicy::Indeterminate,
                },
                rhs: ArithExpr::Field("before.k_last".into()),
            },
            PredicateAst::ArithCmp {
                op: CmpOp::Eq,
                lhs: ArithExpr::Literal(u128::MAX),
                rhs: ArithExpr::Bounded {
                    op: BoundedArithOp::Add,
                    lhs: Box::new(ArithExpr::Field("x".into())),
                    rhs: Box::new(ArithExpr::Literal(1)),
                    widening: Widening::None,
                    on_overflow: OverflowPolicy::Saturate,
                },
            },
            // Boolean composition (nested).
            PredicateAst::Or(
                Box::new(PredicateAst::FieldGe {
                    lhs: "after.reserve_a".into(),
                    rhs: "before.k_last".into(),
                }),
                Box::new(PredicateAst::Not(Box::new(PredicateAst::FieldEq {
                    lhs: "after.lp_supply".into(),
                    rhs: "before.lp_supply".into(),
                }))),
            ),
            PredicateAst::And(
                Box::new(PredicateAst::FieldLe {
                    lhs: "after.total".into(),
                    rhs: "after.cap".into(),
                }),
                Box::new(PredicateAst::FieldGe {
                    lhs: "after.total".into(),
                    rhs: "before.total".into(),
                }),
            ),
        ];
        for p in variants {
            let m = PetalManifest {
                module_path: "/p".to_string(),
                invariants: vec![InvariantDecl {
                    name: "x".to_string(),
                    target: InvariantTarget::ObjectType {
                        name: "T".to_string(),
                    },
                    predicate: p.clone(),
                    wasm_export: "__inv_0".to_string(),
                    human_text: String::new(),
                }],
                ..Default::default()
            };
            let bytes = encode(&m).unwrap();
            let back = decode(&bytes).unwrap();
            assert_eq!(back, m);
        }
    }

    #[test]
    fn sample_round_trip_is_bytewise_stable() {
        let m = sample();
        let bytes1 = encode(&m).unwrap();
        let bytes2 = encode(&decode(&bytes1).unwrap()).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn fuel_hints_round_trip() {
        let m = PetalManifest {
            module_path: "/p".to_string(),
            fuel_hints: FuelHints {
                per_function: vec![("a".to_string(), 1_000), ("b".to_string(), 2_000)],
                default: Some(5_000),
            },
            ..Default::default()
        };
        let back = decode(&encode(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn function_view_round_trips_in_current_schema() {
        let m = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/p".to_string(),
            functions: vec![FunctionDecl {
                name: "quote".to_string(),
                view: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let back = decode(&encode(&m).unwrap()).unwrap();
        assert_eq!(back.functions[0].name, "quote");
        assert!(back.functions[0].view);
    }

    #[test]
    fn schema_v1_manifest_is_rejected() {
        let m = PetalManifest {
            schema_version: 1,
            module_path: "/p".to_string(),
            functions: vec![FunctionDecl {
                name: "legacy".to_string(),
                view: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(encode(&m).is_err());
    }

    #[test]
    fn deeply_nested_predicate_decode_is_bounded() {
        // A run of `And` discriminants (0x07) with no terminating leaf
        // would recurse unbounded; the decoder must error rather than
        // stack-overflow (deploy-time DoS guard). Drive `read_predicate`
        // directly with crafted bytes past the depth limit.
        let bytes = vec![7u8; (MAX_PREDICATE_DEPTH as usize) + 8];
        let mut rdr = &bytes[..];
        let err = read_predicate(&mut rdr).unwrap_err();
        assert!(matches!(err, CodecError::RecursionLimit), "got {err:?}");
    }

    #[test]
    fn invariant_human_text_round_trips() {
        let m = PetalManifest {
            module_path: "/p".to_string(),
            invariants: vec![InvariantDecl {
                name: "x".to_string(),
                target: InvariantTarget::ObjectType {
                    name: "T".to_string(),
                },
                predicate: PredicateAst::FieldGe {
                    lhs: "after.a".into(),
                    rhs: "before.a".into(),
                },
                wasm_export: "__inv_0".to_string(),
                human_text: "a never decreases".to_string(),
            }],
            ..Default::default()
        };
        let back = decode(&encode(&m).unwrap()).unwrap();
        assert_eq!(back.invariants[0].human_text, "a never decreases");
        assert_eq!(back, m);
    }
}
