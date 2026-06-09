//! Reflective type resolver for full petal manifests.
//!
//! The value codec is schema-driven and deliberately does not know this
//! manifest crate. This module bridges a decoded [`PetalManifest`] into the
//! neutral [`bloom_value::Resolver`] interface.

use bloom_objects::TypeTag;
use bloom_value::{FieldShape, Resolver, TypeShape, ValueCodecError, VariantFields, VariantShape};

use crate::types::{
    CapabilityDecl, DataTypeDecl, EnumTypeDecl, FieldDecl, ObjectTypeDecl, PetalManifest,
    VariantFieldsDecl,
};

/// Full-manifest resolver for user-defined object/capability/data/enum types.
#[derive(Clone, Debug)]
pub struct ManifestResolver<'a> {
    manifest: &'a PetalManifest,
    self_hash: Option<[u8; 32]>,
    external_manifests: &'a [([u8; 32], &'a PetalManifest)],
}

impl<'a> ManifestResolver<'a> {
    /// Create a resolver for `manifest` without a known publish hash.
    ///
    /// This resolves macro-time self references (`petal_hash == [0; 32]`).
    pub fn new(manifest: &'a PetalManifest) -> Self {
        Self {
            manifest,
            self_hash: None,
            external_manifests: &[],
        }
    }

    /// Create a resolver that also treats `self_hash` as this manifest's hash.
    pub fn with_self_hash(manifest: &'a PetalManifest, self_hash: [u8; 32]) -> Self {
        Self {
            manifest,
            self_hash: Some(self_hash),
            external_manifests: &[],
        }
    }

    /// Create a resolver that can structurally resolve foreign concrete tags
    /// through the supplied `(content_hash, manifest)` table.
    pub fn with_self_hash_and_external_manifests(
        manifest: &'a PetalManifest,
        self_hash: [u8; 32],
        external_manifests: &'a [([u8; 32], &'a PetalManifest)],
    ) -> Self {
        Self {
            manifest,
            self_hash: Some(self_hash),
            external_manifests,
        }
    }

    fn is_self_hash(&self, hash: &[u8; 32]) -> bool {
        *hash == [0u8; 32] || self.self_hash.as_ref() == Some(hash)
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
                let petal_hash = ext.declared_content_hash.ok_or_else(|| {
                    ValueCodecError::UnresolvedType(format!("external#{ref_idx} missing hash"))
                })?;
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
        fields: &[FieldDecl],
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
        decl: &ObjectTypeDecl,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn capability_shape(
        &self,
        decl: &CapabilityDecl,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn data_shape(
        &self,
        decl: &DataTypeDecl,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        Ok(TypeShape::Struct(self.subst_fields(&decl.fields, args)?))
    }

    fn enum_shape(
        &self,
        decl: &EnumTypeDecl,
        args: &[TypeTag],
    ) -> Result<TypeShape, ValueCodecError> {
        self.check_arity(&decl.name, decl.type_params.len(), args)?;
        let variants = decl
            .variants
            .iter()
            .map(|variant| {
                let fields = match &variant.fields {
                    VariantFieldsDecl::Unit => VariantFields::Unit,
                    VariantFieldsDecl::Tuple(types) => VariantFields::Tuple(
                        types
                            .iter()
                            .map(|ty| self.subst(ty, args))
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    VariantFieldsDecl::Struct(fields) => {
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

impl Resolver for ManifestResolver<'_> {
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
            if let Some((_, manifest)) = self
                .external_manifests
                .iter()
                .find(|(hash, _)| hash == petal_hash)
            {
                let resolver = ManifestResolver {
                    manifest,
                    self_hash: Some(*petal_hash),
                    external_manifests: self.external_manifests,
                };
                return resolver.resolve_shape(tag, _depth);
            }
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

/// Validate that manifest-defined declarations do not claim reserved built-in
/// type names.
pub fn validate_reserved_type_names(manifest: &PetalManifest) -> Result<(), ValueCodecError> {
    for name in manifest
        .object_types
        .iter()
        .map(|d| d.name.as_str())
        .chain(manifest.capability_types.iter().map(|d| d.name.as_str()))
        .chain(manifest.data_types.iter().map(|d| d.name.as_str()))
        .chain(manifest.enum_types.iter().map(|d| d.name.as_str()))
    {
        if is_reserved_builtin_name(name) {
            return Err(ValueCodecError::UnresolvedType(format!(
                "reserved built-in type name {name}"
            )));
        }
    }
    Ok(())
}

fn is_reserved_builtin_name(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "Address"
            | "address"
            | "ObjectId"
            | "Hash32"
            | "UID"
            | "TypeTag"
            | "bytes"
            | "String"
            | "string"
            | "vector"
            | "map"
            | "set"
            | "tuple"
            | "Option"
            | "Result"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::{AbilitySet, BUILTIN_TYPE_HASH};
    use bloom_value::{CodecLimits, Value, decode_value};

    use crate::types::{
        DataTypeDecl, EnumTypeDecl, ExternalTypeRef, FieldDecl, ObjectTypeDecl, TypeParamDecl,
        TypeParamKind, VariantDecl,
    };

    fn builtin(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    fn self_ty(name: &str, type_args: Vec<TypeTag>) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args,
        }
    }

    #[test]
    fn resolves_object_fields_and_decodes_payload() {
        let manifest = PetalManifest {
            object_types: vec![ObjectTypeDecl {
                name: "Thing".to_string(),
                abilities: AbilitySet::key_store(),
                type_params: vec![],
                fields: vec![
                    FieldDecl {
                        name: "id".to_string(),
                        ty: builtin("UID"),
                        offset: Some(0),
                        width: Some(32),
                    },
                    FieldDecl {
                        name: "name".to_string(),
                        ty: builtin("String"),
                        offset: None,
                        width: None,
                    },
                ],
            }],
            ..Default::default()
        };
        let resolver = ManifestResolver::new(&manifest);
        let mut payload = vec![0xAA; 32];
        payload.extend_from_slice(b"\x03cat");
        let value = decode_value(
            &resolver,
            &self_ty("Thing", vec![]),
            &payload,
            &CodecLimits::default(),
        )
        .unwrap();
        assert_eq!(
            value,
            Value::Struct(vec![
                ("id".to_string(), Value::Bytes32([0xAA; 32])),
                ("name".to_string(), Value::String("cat".to_string())),
            ])
        );
    }

    #[test]
    fn substitutes_generic_type_args() {
        let manifest = PetalManifest {
            data_types: vec![DataTypeDecl {
                name: "Boxed".to_string(),
                type_params: vec![TypeParamDecl {
                    name: "T".to_string(),
                    kind: TypeParamKind::Resource,
                    bounds: vec![],
                }],
                fields: vec![FieldDecl {
                    name: "value".to_string(),
                    ty: TypeTag::Generic { idx: 0 },
                    offset: None,
                    width: None,
                }],
            }],
            ..Default::default()
        };
        let resolver = ManifestResolver::new(&manifest);
        let tag = self_ty("Boxed", vec![builtin("u64")]);
        let value = decode_value(
            &resolver,
            &tag,
            &7u64.to_be_bytes(),
            &CodecLimits::default(),
        )
        .unwrap();
        assert_eq!(
            value,
            Value::Struct(vec![("value".to_string(), Value::U64(7))])
        );
    }

    #[test]
    fn resolves_enum_variants() {
        let manifest = PetalManifest {
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
                        fields: VariantFieldsDecl::Tuple(vec![builtin("u8")]),
                    },
                ],
            }],
            ..Default::default()
        };
        let resolver = ManifestResolver::new(&manifest);
        let value = decode_value(
            &resolver,
            &self_ty("Side", vec![]),
            &[1, 9],
            &CodecLimits::default(),
        )
        .unwrap();
        assert_eq!(
            value,
            Value::Enum {
                index: 1,
                name: "Ask".to_string(),
                fields: bloom_value::VariantValue::Tuple(vec![Value::U8(9)]),
            }
        );
    }

    #[test]
    fn resolves_external_type_refs_through_supplied_manifest() {
        let foreign_hash = [0xBB; 32];
        let manifest = PetalManifest {
            external_type_refs: vec![ExternalTypeRef {
                placeholder: "$external_0".to_string(),
                declared_petal_path: "/foreign".to_string(),
                declared_type_name: "Foreign".to_string(),
                declared_content_hash: Some(foreign_hash),
            }],
            data_types: vec![DataTypeDecl {
                name: "Local".to_string(),
                fields: vec![FieldDecl {
                    name: "foreign".to_string(),
                    ty: TypeTag::External { ref_idx: 0 },
                    offset: None,
                    width: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let foreign = PetalManifest {
            data_types: vec![DataTypeDecl {
                name: "Foreign".to_string(),
                fields: vec![FieldDecl {
                    name: "value".to_string(),
                    ty: builtin("u64"),
                    offset: None,
                    width: Some(8),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let externals = [(foreign_hash, &foreign)];
        let resolver = ManifestResolver::with_self_hash_and_external_manifests(
            &manifest, [0xAA; 32], &externals,
        );

        let value = decode_value(
            &resolver,
            &self_ty("Local", vec![]),
            &7u64.to_be_bytes(),
            &CodecLimits::default(),
        )
        .unwrap();

        assert_eq!(
            value,
            Value::Struct(vec![(
                "foreign".to_string(),
                Value::Struct(vec![("value".to_string(), Value::U64(7))])
            )])
        );
    }

    #[test]
    fn external_type_refs_reject_without_supplied_manifest() {
        let foreign_hash = [0xBB; 32];
        let manifest = PetalManifest {
            external_type_refs: vec![ExternalTypeRef {
                placeholder: "$external_0".to_string(),
                declared_petal_path: "/foreign".to_string(),
                declared_type_name: "Foreign".to_string(),
                declared_content_hash: Some(foreign_hash),
            }],
            data_types: vec![DataTypeDecl {
                name: "Local".to_string(),
                fields: vec![FieldDecl {
                    name: "foreign".to_string(),
                    ty: TypeTag::External { ref_idx: 0 },
                    offset: None,
                    width: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let resolver = ManifestResolver::with_self_hash(&manifest, [0xAA; 32]);

        assert!(
            decode_value(
                &resolver,
                &self_ty("Local", vec![]),
                &7u64.to_be_bytes(),
                &CodecLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_reserved_declaration_names() {
        let manifest = PetalManifest {
            data_types: vec![DataTypeDecl {
                name: "String".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(validate_reserved_type_names(&manifest).is_err());
    }
}
