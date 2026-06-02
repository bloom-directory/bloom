//! Schema-driven canonical value validation over manifest stubs.

use bloom_objects::{BUILTIN_TYPE_HASH, TypeTag};
use bloom_value::{
    CodecLimits, FieldShape, Resolver, TypeShape, ValueCodecError, VariantFields, VariantShape,
    validate_value_bytes,
};

use crate::chain_iface::{
    CapabilityTypeDeclStub, DataTypeDeclStub, EnumTypeDeclStub, FieldDeclStub, ObjectTypeDeclStub,
    PetalManifestStub, VariantFieldsDeclStub,
};

/// Validate a PTB `Arg::Const` slot against a manifest-declared value type.
///
/// This is schema-driven and rejects unresolved or malformed custom types
/// instead of accepting opaque bytes.
pub fn validate_const_slot(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    bytes: &[u8],
) -> Result<(), String> {
    validate_with_tag(manifest, self_hash, tag, bytes)
}

/// Validate one Move return slot against a manifest-declared return type.
///
/// Runtime object handles (`Coin`, `Resource`, capability/object returns)
/// are validated as canonical `ObjectId` bytes; optional handles validate as
/// canonical `Option<ObjectId>` bytes.
pub fn validate_return_slot(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    bytes: &[u8],
) -> Result<(), String> {
    let effective = return_slot_tag(manifest, tag).unwrap_or_else(|| tag.clone());
    validate_with_tag(manifest, self_hash, &effective, bytes)
}

fn validate_with_tag(
    manifest: &PetalManifestStub,
    self_hash: [u8; 32],
    tag: &TypeTag,
    bytes: &[u8],
) -> Result<(), String> {
    let resolver = StubResolver::with_self_hash(manifest, self_hash);
    let limits = CodecLimits {
        max_value_bytes: bytes.len(),
        ..CodecLimits::default()
    };
    validate_value_bytes(&resolver, tag, bytes, &limits).map_err(|e| e.to_string())
}

fn return_slot_tag(manifest: &PetalManifestStub, tag: &TypeTag) -> Option<TypeTag> {
    if is_object_handle_tag(manifest, tag) {
        return Some(builtin_tag("ObjectId", Vec::new()));
    }
    let TypeTag::Concrete {
        petal_hash,
        type_name,
        type_args,
    } = tag
    else {
        return None;
    };
    if *petal_hash == BUILTIN_TYPE_HASH
        && type_name == "Option"
        && type_args.len() == 1
        && is_object_handle_tag(manifest, &type_args[0])
    {
        return Some(builtin_tag(
            "Option",
            vec![builtin_tag("ObjectId", Vec::new())],
        ));
    }
    None
}

fn is_object_handle_tag(manifest: &PetalManifestStub, tag: &TypeTag) -> bool {
    let TypeTag::Concrete { type_name, .. } = tag else {
        return false;
    };
    matches!(
        type_name.as_str(),
        "Coin" | "Balance" | "Resource" | "Capability"
    ) || manifest
        .object_types
        .iter()
        .any(|decl| decl.name == *type_name)
        || manifest
            .capability_types
            .iter()
            .any(|decl| decl.name == *type_name)
}

fn builtin_tag(type_name: &str, type_args: Vec<TypeTag>) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: BUILTIN_TYPE_HASH,
        type_name: type_name.to_string(),
        type_args,
    }
}

#[derive(Clone, Debug)]
struct StubResolver<'a> {
    manifest: &'a PetalManifestStub,
    self_hash: [u8; 32],
}

impl<'a> StubResolver<'a> {
    fn with_self_hash(manifest: &'a PetalManifestStub, self_hash: [u8; 32]) -> Self {
        Self {
            manifest,
            self_hash,
        }
    }

    fn is_self_hash(&self, hash: &[u8; 32]) -> bool {
        *hash == [0u8; 32] || *hash == self.self_hash
    }

    fn subst(&self, ty: &TypeTag, args: &[TypeTag]) -> Result<TypeTag, ValueCodecError> {
        match ty {
            TypeTag::Generic { idx } => args
                .get(*idx as usize)
                .cloned()
                .ok_or_else(|| ValueCodecError::UnresolvedType(format!("generic#{idx}"))),
            TypeTag::External { ref_idx } => {
                let ext = self
                    .manifest
                    .external_type_refs
                    .get(*ref_idx as usize)
                    .ok_or_else(|| {
                        ValueCodecError::UnresolvedType(format!("external#{ref_idx}"))
                    })?;
                let petal_hash = ext
                    .declared_content_hash
                    .ok_or_else(|| {
                        ValueCodecError::UnresolvedType(format!("external#{ref_idx} missing hash"))
                    })?
                    .0;
                Ok(TypeTag::Concrete {
                    petal_hash,
                    type_name: ext.declared_type_name.clone(),
                    type_args: Vec::new(),
                })
            }
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => Ok(TypeTag::Concrete {
                petal_hash: *petal_hash,
                type_name: type_name.clone(),
                type_args: type_args
                    .iter()
                    .map(|arg| self.subst(arg, args))
                    .collect::<Result<Vec<_>, _>>()?,
            }),
        }
    }

    fn subst_fields(
        &self,
        fields: &[FieldDeclStub],
        args: &[TypeTag],
    ) -> Result<Vec<FieldShape>, ValueCodecError> {
        fields
            .iter()
            .map(|field| {
                Ok(FieldShape {
                    name: field.name.clone(),
                    ty: self.subst(&field.ty, args)?,
                })
            })
            .collect()
    }

    fn check_arity(
        &self,
        name: &str,
        expected: usize,
        args: &[TypeTag],
    ) -> Result<(), ValueCodecError> {
        if expected == args.len() {
            Ok(())
        } else {
            Err(ValueCodecError::InvalidArity {
                name: name.to_string(),
                expected,
                got: args.len(),
            })
        }
    }

    fn object_shape(
        &self,
        decl: &ObjectTypeDeclStub,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn capability_shape(
        &self,
        decl: &CapabilityTypeDeclStub,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn data_shape(
        &self,
        decl: &DataTypeDeclStub,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn enum_shape(
        &self,
        decl: &EnumTypeDeclStub,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        let variants = decl
            .variants
            .iter()
            .map(|variant| {
                let fields = match &variant.fields {
                    VariantFieldsDeclStub::Unit => VariantFields::Unit,
                    VariantFieldsDeclStub::Tuple(types) => VariantFields::Tuple(
                        types
                            .iter()
                            .map(|ty| self.subst(ty, args))
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    VariantFieldsDeclStub::Struct(fields) => {
                        VariantFields::Struct(self.subst_fields(fields, args)?)
                    }
                };
                Ok(VariantShape {
                    name: variant.name.clone(),
                    fields,
                })
            })
            .collect::<Result<Vec<_>, ValueCodecError>>()?;
        Ok(TypeShape::Enum(variants))
    }
}

impl Resolver for StubResolver<'_> {
    fn resolve_shape(&self, tag: &TypeTag, _depth: usize) -> Result<TypeShape, ValueCodecError> {
        let TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } = tag
        else {
            return Err(ValueCodecError::UnresolvedType(
                bloom_value::type_tag_label(tag),
            ));
        };
        if !self.is_self_hash(petal_hash) {
            return Err(ValueCodecError::UnresolvedType(
                bloom_value::type_tag_label(tag),
            ));
        }
        if let Some(decl) = self
            .manifest
            .object_types
            .iter()
            .find(|decl| decl.name == *type_name)
        {
            return self.object_shape(decl, type_args);
        }
        if let Some(decl) = self
            .manifest
            .capability_types
            .iter()
            .find(|decl| decl.name == *type_name)
        {
            return self.capability_shape(decl, type_args);
        }
        if let Some(decl) = self
            .manifest
            .data_types
            .iter()
            .find(|decl| decl.name == *type_name)
        {
            return self.data_shape(decl, type_args);
        }
        if let Some(decl) = self
            .manifest
            .enum_types
            .iter()
            .find(|decl| decl.name == *type_name)
        {
            return self.enum_shape(decl, type_args);
        }
        Err(ValueCodecError::UnresolvedType(
            bloom_value::type_tag_label(tag),
        ))
    }
}
