//! `petals/` — executable view endpoints for deployed Bloom-native petals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use bloom_chain_types::Hash32;
use bloom_objects::{Object, ObjectId, Owner, TypeTag};
use bloom_petal_manifest::ManifestResolver;
use bloom_petal_manifest::extract_petal_manifest_v0;
use bloom_petal_manifest::types::{ObjectTypeDecl, PetalManifestV0};
use bloom_script::{ChainStateIface, PetalManifestStub};
use bloom_value::{CodecLimits, decode_json};
use serde_json::{Value, json};

use crate::handler::{Entry, Handler, HandlerError};
use crate::paginate;
use crate::path::VfsPath;

const PETAL_PREFIX: &str = "/bloom/petals/";
const PIPE_NODE: &str = ".pipe";
const STATE_NODE: &str = ".state";
const OBJECT_JSON: &str = "_object.json";
const PIPE_SHIM: &str =
    "#!/bin/sh\n# Bloom petal composition endpoint.\nexec bloom chain pipe \"$@\"\n";

#[derive(Clone)]
pub struct PetalsEndpointHandler {
    chain: Arc<dyn ChainStateIface + Send + Sync>,
}

#[derive(Clone, Debug)]
struct Binding {
    path: String,
    hash: Hash32,
    rel: Vec<String>,
}

impl PetalsEndpointHandler {
    pub fn new(chain: Arc<dyn ChainStateIface + Send + Sync>) -> Self {
        Self { chain }
    }

    fn bindings(&self) -> Vec<Binding> {
        let mut bindings = self
            .chain
            .iter_vfs()
            .into_iter()
            .filter_map(|(path, hash)| {
                let suffix = path.strip_prefix(PETAL_PREFIX)?;
                if suffix.is_empty() {
                    return None;
                }
                let rel = suffix.split('/').map(str::to_string).collect();
                Some(Binding { path, hash, rel })
            })
            .collect::<Vec<_>>();
        bindings.sort_by(|a, b| a.rel.cmp(&b.rel));
        bindings
    }

    fn manifest_for(&self, binding: &Binding) -> Option<PetalManifestStub> {
        self.chain.load_manifest(&binding.hash)
    }

    fn full_manifest_for(&self, binding: &Binding) -> Option<PetalManifestV0> {
        let wasm = self.chain.load_petal(&binding.hash)?;
        extract_petal_manifest_v0(&wasm)
    }

    fn external_full_manifests_for(
        &self,
        manifest: &PetalManifestV0,
    ) -> Vec<(Hash32, PetalManifestV0)> {
        let mut manifests = Vec::new();
        let mut visited = BTreeSet::new();
        self.collect_external_full_manifests(manifest, &mut manifests, &mut visited);
        manifests
    }

    fn collect_external_full_manifests(
        &self,
        manifest: &PetalManifestV0,
        out: &mut Vec<(Hash32, PetalManifestV0)>,
        visited: &mut BTreeSet<[u8; 32]>,
    ) {
        for external in &manifest.external_type_refs {
            let Some(content_hash) = external.declared_content_hash else {
                continue;
            };
            if !visited.insert(content_hash) {
                continue;
            }
            let hash = Hash32(content_hash);
            let Some(wasm) = self.chain.load_petal(&hash) else {
                continue;
            };
            let Some(external_manifest) = extract_petal_manifest_v0(&wasm) else {
                continue;
            };
            self.collect_external_full_manifests(&external_manifest, out, visited);
            out.push((hash, external_manifest));
        }
    }

    fn binding_at<'a>(&self, bindings: &'a [Binding], rel: &[String]) -> Option<&'a Binding> {
        bindings.iter().find(|binding| binding.rel == rel)
    }

    fn has_descendant(bindings: &[Binding], rel: &[String]) -> bool {
        bindings
            .iter()
            .any(|binding| binding.rel.len() > rel.len() && binding.rel.starts_with(rel))
    }

    fn endpoint_at<'a>(
        &'a self,
        bindings: &'a [Binding],
        rel: &[String],
    ) -> Option<(&'a Binding, String, bool)> {
        let (function, petal_rel) = rel.split_last()?;
        let binding = self.binding_at(bindings, petal_rel)?;
        let manifest = self.manifest_for(binding)?;
        manifest
            .functions
            .iter()
            .find(|f| f.name == *function && is_endpoint_segment(&f.name))
            .map(|f| (binding, function.clone(), f.view))
    }

    fn entries_for(&self, rel: &[String]) -> Result<Vec<Entry>, HandlerError> {
        let bindings = self.bindings();
        if !rel.is_empty()
            && self.binding_at(&bindings, rel).is_none()
            && !Self::has_descendant(&bindings, rel)
        {
            return Err(HandlerError::not_found(format!(
                "/bloom/petals/{}",
                rel.join("/")
            )));
        }

        let mut dirs = BTreeSet::new();
        for binding in &bindings {
            if binding.rel.len() > rel.len() && binding.rel.starts_with(rel) {
                dirs.insert(binding.rel[rel.len()].clone());
            }
        }

        let mut by_name = BTreeMap::new();
        for dir in dirs {
            by_name.insert(dir.clone(), Entry::dir(&dir));
        }

        if let Some(binding) = self.binding_at(&bindings, rel)
            && let Some(manifest) = self.manifest_for(binding)
        {
            by_name
                .entry(STATE_NODE.to_string())
                .or_insert_with(|| Entry::dir(STATE_NODE));
            for function in manifest
                .functions
                .iter()
                .filter(|function| is_endpoint_segment(&function.name))
            {
                by_name.insert(
                    function.name.clone(),
                    Entry::executable_file(&function.name),
                );
            }
        }

        let entries = by_name.into_values().collect::<Vec<_>>();
        Ok(match paginate::project(entries) {
            paginate::Projection::Direct(mut entries) => {
                if rel.is_empty() {
                    entries.insert(0, Entry::executable_file(PIPE_NODE));
                }
                entries
            }
            paginate::Projection::Paged { .. } => {
                if rel.is_empty() {
                    vec![Entry::executable_file(PIPE_NODE), Entry::dir("page")]
                } else {
                    vec![Entry::dir("page")]
                }
            }
        })
    }

    fn page_entries_for(&self, rel: &[String], index: usize) -> Result<Vec<Entry>, HandlerError> {
        let mut entries = self.entries_for_unpaged(rel)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(paginate::page_slice(&entries, index).to_vec())
    }

    fn entries_for_unpaged(&self, rel: &[String]) -> Result<Vec<Entry>, HandlerError> {
        let bindings = self.bindings();
        if !rel.is_empty()
            && self.binding_at(&bindings, rel).is_none()
            && !Self::has_descendant(&bindings, rel)
        {
            return Err(HandlerError::not_found(format!(
                "/bloom/petals/{}",
                rel.join("/")
            )));
        }

        let mut by_name = BTreeMap::new();
        for binding in &bindings {
            if binding.rel.len() > rel.len() && binding.rel.starts_with(rel) {
                let name = &binding.rel[rel.len()];
                by_name
                    .entry(name.clone())
                    .or_insert_with(|| Entry::dir(name));
            }
        }
        if let Some(binding) = self.binding_at(&bindings, rel)
            && let Some(manifest) = self.manifest_for(binding)
        {
            by_name
                .entry(STATE_NODE.to_string())
                .or_insert_with(|| Entry::dir(STATE_NODE));
            for function in manifest
                .functions
                .iter()
                .filter(|function| is_endpoint_segment(&function.name))
            {
                by_name.insert(
                    function.name.clone(),
                    Entry::executable_file(&function.name),
                );
            }
        }
        Ok(by_name.into_values().collect())
    }

    fn shim(path: &str, function: &str, view: bool) -> Vec<u8> {
        let command = if view { "view-call" } else { "call" };
        let comment = if view {
            "Bloom petal view endpoint."
        } else {
            "Bloom petal mutating endpoint."
        };
        format!(
            "#!/bin/sh\n# {comment}\nexec bloom chain {command} --path {} --function {} \"$@\"\n",
            shell_quote(path),
            shell_quote(function)
        )
        .into_bytes()
    }

    fn state_path<'a>(
        bindings: &'a [Binding],
        rel: &'a [String],
    ) -> Option<(&'a Binding, &'a [String])> {
        bindings
            .iter()
            .filter(|binding| rel.starts_with(&binding.rel))
            .max_by_key(|binding| binding.rel.len())
            .and_then(|binding| {
                let rest = &rel[binding.rel.len()..];
                if rest.first().map(String::as_str) == Some(STATE_NODE) {
                    Some((binding, &rest[1..]))
                } else {
                    None
                }
            })
    }

    fn state_unpaged_entries(
        &self,
        binding: &Binding,
        state_rel: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let manifest = self
            .full_manifest_for(binding)
            .ok_or_else(|| HandlerError::not_found(binding.path.clone()))?;
        match state_rel {
            [] => Ok(manifest
                .object_types
                .iter()
                .filter(|object_type| is_endpoint_segment(&object_type.name))
                .map(|object_type| Entry::dir(&object_type.name))
                .collect()),
            [type_name] => {
                if object_type_decl(&manifest, type_name).is_none() {
                    return Err(HandlerError::not_found(type_name.clone()));
                }
                let mut entries = self
                    .objects_for_type(binding.hash, type_name)
                    .into_iter()
                    .map(|(id, _)| Entry::dir(&hex::encode(id.0)))
                    .collect::<Vec<_>>();
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }
            [type_name, id_hex] => {
                let object_type = object_type_decl(&manifest, type_name)
                    .ok_or_else(|| HandlerError::not_found(type_name.clone()))?;
                self.state_object(binding.hash, type_name, id_hex)?;
                let mut entries = object_type
                    .fields
                    .iter()
                    .filter(|field| is_state_field_segment(&field.name))
                    .map(|field| Entry::file(&field.name))
                    .collect::<Vec<_>>();
                entries.push(Entry::file(OBJECT_JSON));
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }
            _ => Err(HandlerError::not_found(format!(
                "/bloom/petals/{}/{}",
                binding.rel.join("/"),
                state_rel.join("/")
            ))),
        }
    }

    fn state_lookup(&self, binding: &Binding, state_rel: &[String]) -> Result<Entry, HandlerError> {
        match state_rel {
            [] => Ok(Entry::dir(STATE_NODE)),
            [page] if page == "page" => {
                let total = self.state_unpaged_entries(binding, &[])?.len();
                if paginate::is_paged(total) {
                    Ok(Entry::dir("page"))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [page, index] if page == "page" => {
                let total = self.state_unpaged_entries(binding, &[])?.len();
                if paginate::is_paged(total) && paginate::parse_page_name(index).is_some() {
                    Ok(Entry::dir(index))
                } else {
                    Err(HandlerError::not_found(index.clone()))
                }
            }
            [type_name] => {
                self.full_manifest_for(binding)
                    .and_then(|manifest| object_type_decl(&manifest, type_name).cloned())
                    .ok_or_else(|| HandlerError::not_found(type_name.clone()))?;
                Ok(Entry::dir(type_name))
            }
            [type_name, page] if page == "page" => {
                let total = self
                    .state_unpaged_entries(binding, std::slice::from_ref(type_name))?
                    .len();
                if paginate::is_paged(total) {
                    Ok(Entry::dir("page"))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, page, index] if page == "page" => {
                let total = self
                    .state_unpaged_entries(binding, std::slice::from_ref(type_name))?
                    .len();
                if paginate::is_paged(total) && paginate::parse_page_name(index).is_some() {
                    Ok(Entry::dir(index))
                } else {
                    Err(HandlerError::not_found(index.clone()))
                }
            }
            [type_name, id_hex] => {
                self.state_object(binding.hash, type_name, id_hex)?;
                Ok(Entry::dir(id_hex))
            }
            [type_name, id_hex, page] if page == "page" => {
                let parent = vec![type_name.clone(), id_hex.clone()];
                let total = self.state_unpaged_entries(binding, &parent)?.len();
                if paginate::is_paged(total) {
                    Ok(Entry::dir("page"))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, id_hex, page, index] if page == "page" => {
                let parent = vec![type_name.clone(), id_hex.clone()];
                let total = self.state_unpaged_entries(binding, &parent)?.len();
                if paginate::is_paged(total) && paginate::parse_page_name(index).is_some() {
                    Ok(Entry::dir(index))
                } else {
                    Err(HandlerError::not_found(index.clone()))
                }
            }
            [type_name, id_hex, leaf] => {
                let manifest = self
                    .full_manifest_for(binding)
                    .ok_or_else(|| HandlerError::not_found(binding.path.clone()))?;
                let object_type = object_type_decl(&manifest, type_name)
                    .ok_or_else(|| HandlerError::not_found(type_name.clone()))?;
                self.state_object(binding.hash, type_name, id_hex)?;
                if leaf == OBJECT_JSON
                    || object_type
                        .fields
                        .iter()
                        .any(|field| field.name == *leaf && is_state_field_segment(&field.name))
                {
                    Ok(Entry::file(leaf))
                } else {
                    Err(HandlerError::not_found(leaf.clone()))
                }
            }
            _ => Err(HandlerError::not_found(state_rel.join("/"))),
        }
    }

    fn state_list(
        &self,
        binding: &Binding,
        state_rel: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        match state_rel {
            [page] if page == "page" => {
                let total = self.state_unpaged_entries(binding, &[])?.len();
                if paginate::is_paged(total) {
                    Ok(paginate::page_indices(total))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [page, index] if page == "page" => {
                let Some(index) = paginate::parse_page_name(index) else {
                    return Err(HandlerError::not_found(index.clone()));
                };
                let entries = self.state_unpaged_entries(binding, &[])?;
                if paginate::is_paged(entries.len()) {
                    Ok(paginate::page_slice(&entries, index).to_vec())
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, page] if page == "page" => {
                let total = self
                    .state_unpaged_entries(binding, std::slice::from_ref(type_name))?
                    .len();
                if paginate::is_paged(total) {
                    Ok(paginate::page_indices(total))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, page, index] if page == "page" => {
                let Some(index) = paginate::parse_page_name(index) else {
                    return Err(HandlerError::not_found(index.clone()));
                };
                let entries =
                    self.state_unpaged_entries(binding, std::slice::from_ref(type_name))?;
                if paginate::is_paged(entries.len()) {
                    Ok(paginate::page_slice(&entries, index).to_vec())
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, id_hex, page] if page == "page" => {
                let parent = vec![type_name.clone(), id_hex.clone()];
                let total = self.state_unpaged_entries(binding, &parent)?.len();
                if paginate::is_paged(total) {
                    Ok(paginate::page_indices(total))
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            [type_name, id_hex, page, index] if page == "page" => {
                let Some(index) = paginate::parse_page_name(index) else {
                    return Err(HandlerError::not_found(index.clone()));
                };
                let parent = vec![type_name.clone(), id_hex.clone()];
                let entries = self.state_unpaged_entries(binding, &parent)?;
                if paginate::is_paged(entries.len()) {
                    Ok(paginate::page_slice(&entries, index).to_vec())
                } else {
                    Err(HandlerError::not_found(page.clone()))
                }
            }
            _ => {
                let entries = self.state_unpaged_entries(binding, state_rel)?;
                Ok(match paginate::project(entries) {
                    paginate::Projection::Direct(entries) => entries,
                    paginate::Projection::Paged { .. } => vec![Entry::dir("page")],
                })
            }
        }
    }

    fn state_read(&self, binding: &Binding, state_rel: &[String]) -> Result<Vec<u8>, HandlerError> {
        let [type_name, id_hex, leaf] = state_rel else {
            return Err(HandlerError::NotAFile(state_rel.join("/")));
        };
        let manifest = self
            .full_manifest_for(binding)
            .ok_or_else(|| HandlerError::not_found(binding.path.clone()))?;
        let object_type = object_type_decl(&manifest, type_name)
            .ok_or_else(|| HandlerError::not_found(type_name.clone()))?;
        let (_id, object) = self.state_object(binding.hash, type_name, id_hex)?;
        let external_manifests = self.external_full_manifests_for(&manifest);
        let fields = decode_object_fields(
            binding.hash,
            &object,
            object_type,
            &manifest,
            &external_manifests,
        )?;
        let value = if leaf == OBJECT_JSON {
            state_object_json(&object, fields)
        } else {
            if !is_state_field_segment(leaf) {
                return Err(HandlerError::not_found(leaf.clone()));
            }
            fields
                .get(leaf)
                .cloned()
                .ok_or_else(|| HandlerError::not_found(leaf.clone()))?
        };
        let mut out =
            serde_json::to_vec(&value).map_err(|e| HandlerError::backend(e.to_string()))?;
        out.push(b'\n');
        Ok(out)
    }

    fn state_object(
        &self,
        petal_hash: Hash32,
        type_name: &str,
        id_hex: &str,
    ) -> Result<(ObjectId, Object), HandlerError> {
        let id = parse_object_id(id_hex)?;
        let object = self
            .chain
            .load_object(&id)
            .ok_or_else(|| HandlerError::not_found(id_hex.to_string()))?;
        if object_matches(&object, petal_hash, type_name) {
            Ok((id, object))
        } else {
            Err(HandlerError::not_found(id_hex.to_string()))
        }
    }

    fn objects_for_type(&self, petal_hash: Hash32, type_name: &str) -> Vec<(ObjectId, Object)> {
        tracing::debug!(%type_name, petal_hash = %hex::encode(petal_hash.0), "petals.state.scan_objects");
        self.chain
            .iter_objects()
            .into_iter()
            .filter(|(_, object)| object_matches(object, petal_hash, type_name))
            .collect()
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn split_page_path(segs: &[String]) -> Option<(&[String], Option<usize>)> {
    if let Some((page_index, rest)) = segs.split_last()
        && let Some((page, parent)) = rest.split_last()
        && page == "page"
    {
        return Some((parent, paginate::parse_page_name(page_index)));
    }
    None
}

fn is_endpoint_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment != "page"
        && !segment.starts_with('.')
        && !segment.contains('/')
        && !segment.contains('\\')
        && !segment.contains('\0')
        && !segment.chars().any(char::is_whitespace)
}

fn is_state_field_segment(segment: &str) -> bool {
    is_endpoint_segment(segment) && segment != OBJECT_JSON
}

fn parse_object_id(id_hex: &str) -> Result<ObjectId, HandlerError> {
    let bytes = hex::decode(id_hex).map_err(|_| HandlerError::not_found(id_hex.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HandlerError::not_found(id_hex.to_string()))?;
    Ok(ObjectId(arr))
}

fn object_matches(object: &Object, petal_hash: Hash32, type_name: &str) -> bool {
    matches!(
        &object.type_tag,
        TypeTag::Concrete {
            petal_hash: hash,
            type_name: name,
            ..
        } if *hash == petal_hash.0 && name == type_name
    )
}

fn object_type_decl<'a>(manifest: &'a PetalManifestV0, name: &str) -> Option<&'a ObjectTypeDecl> {
    if !is_endpoint_segment(name) {
        return None;
    }
    manifest
        .object_types
        .iter()
        .find(|object_type| object_type.name == name)
}

fn decode_object_fields(
    petal_hash: Hash32,
    object: &Object,
    _object_type: &ObjectTypeDecl,
    manifest: &PetalManifestV0,
    external_manifests: &[(Hash32, PetalManifestV0)],
) -> Result<BTreeMap<String, Value>, HandlerError> {
    let external_manifest_refs: Vec<([u8; 32], &PetalManifestV0)> = external_manifests
        .iter()
        .map(|(hash, manifest)| (hash.0, manifest))
        .collect();
    let resolver = ManifestResolver::with_self_hash_and_external_manifests(
        manifest,
        petal_hash.0,
        &external_manifest_refs,
    );
    let value = decode_json(
        &resolver,
        &object.type_tag,
        &object.payload,
        &CodecLimits::default(),
    )
    .map_err(|e| HandlerError::backend(format!("object payload decode failed: {e}")))?;
    let Value::Object(fields) = value else {
        return Err(HandlerError::backend(
            "object payload decoded to non-object JSON",
        ));
    };
    Ok(fields.into_iter().collect())
}

fn state_object_json(object: &Object, fields: BTreeMap<String, Value>) -> Value {
    let (type_name, petal_hash) = match &object.type_tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            ..
        } => (Some(type_name.clone()), Some(hex::encode(petal_hash))),
        _ => (None, None),
    };
    let (owner_kind, owner_addr) = match &object.owner {
        Owner::Address(addr) => ("address", Some(hex::encode(addr))),
        Owner::Object(id) => ("object", Some(hex::encode(id.0))),
        Owner::Shared => ("shared", None),
        Owner::Immutable => ("immutable", None),
    };
    json!({
        "id": hex::encode(object.id.0),
        "type_name": type_name,
        "petal_hash": petal_hash,
        "owner_kind": owner_kind,
        "owner_addr": owner_addr,
        "version": object.version,
        "payload": hex::encode(&object.payload),
        "fields": fields,
    })
}

#[async_trait]
impl Handler for PetalsEndpointHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        if segs.len() == 1 && segs[0] == PIPE_NODE {
            return Ok(Entry::executable_file(PIPE_NODE));
        }
        let bindings = self.bindings();
        if let Some((binding, state_rel)) = Self::state_path(&bindings, segs) {
            return self.state_lookup(binding, state_rel);
        }
        if let Some((parent, Some(_))) = split_page_path(segs) {
            let total = self.entries_for_unpaged(parent)?.len();
            if paginate::is_paged(total) {
                return Ok(Entry::dir(segs.last().expect("page path has leaf")));
            }
        }
        if matches!(segs.last().map(String::as_str), Some("page")) {
            let parent = &segs[..segs.len() - 1];
            let total = self.entries_for_unpaged(parent)?.len();
            if paginate::is_paged(total) {
                return Ok(Entry::dir("page"));
            }
        }

        if let Some((_binding, function, _view)) = self.endpoint_at(&bindings, segs) {
            return Ok(Entry::executable_file(&function));
        }
        if Self::has_descendant(&bindings, segs) {
            return Ok(Entry::dir(segs.last().expect("non-root has leaf")));
        }
        if self.binding_at(&bindings, segs).is_some() {
            return Ok(Entry::dir(segs.last().expect("non-root has leaf")));
        }
        Err(HandlerError::not_found(format!(
            "/bloom/petals/{}",
            segs.join("/")
        )))
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.len() == 1 && segs[0] == PIPE_NODE {
            return Ok(PIPE_SHIM.as_bytes().to_vec());
        }
        let bindings = self.bindings();
        if let Some((binding, state_rel)) = Self::state_path(&bindings, segs) {
            return self.state_read(binding, state_rel);
        }
        let Some((binding, function, view)) = self.endpoint_at(&bindings, segs) else {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        };
        Ok(Self::shim(&binding.path, &function, view))
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        let bindings = self.bindings();
        if let Some((binding, state_rel)) = Self::state_path(&bindings, segs) {
            return self.state_list(binding, state_rel);
        }
        if matches!(segs.last().map(String::as_str), Some("page")) {
            let parent = &segs[..segs.len() - 1];
            let total = self.entries_for_unpaged(parent)?.len();
            if paginate::is_paged(total) {
                return Ok(paginate::page_indices(total));
            }
        }
        if let Some((parent, Some(index))) = split_page_path(segs) {
            let total = self.entries_for_unpaged(parent)?.len();
            if paginate::is_paged(total) {
                return self.page_entries_for(parent, index);
            }
        }
        if split_page_path(segs).is_some() {
            return Err(HandlerError::not_found(path.to_string_path()));
        }
        self.entries_for(segs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use bloom_objects::{AbilitySet, BUILTIN_TYPE_HASH, Object, ObjectId};
    use bloom_petal_manifest::types::{
        DataTypeDecl, ExternalTypeRef, FieldDecl, ObjectTypeDecl, PetalManifestV0, TypeParamDecl,
        TypeParamKind,
    };
    use bloom_script::FunctionDeclStub;

    #[derive(Default)]
    struct MockChain {
        bindings: Mutex<Vec<(String, Hash32)>>,
        manifests: Mutex<HashMap<Hash32, PetalManifestStub>>,
        code: Mutex<HashMap<Hash32, Vec<u8>>>,
        objects: Mutex<HashMap<ObjectId, Object>>,
    }

    impl MockChain {
        fn bind(&self, path: &str, hash: Hash32, manifest: PetalManifestStub) {
            self.bindings.lock().unwrap().push((path.to_string(), hash));
            self.manifests.lock().unwrap().insert(hash, manifest);
        }

        fn bind_full(&self, path: &str, hash: Hash32, manifest: PetalManifestV0) {
            self.bindings.lock().unwrap().push((path.to_string(), hash));
            self.manifests.lock().unwrap().insert(
                hash,
                bloom_petal_manifest::to_petal_manifest_stub(&manifest),
            );
            let bytes = bloom_petal_manifest::encode(&manifest).unwrap();
            self.code
                .lock()
                .unwrap()
                .insert(hash, wasm_with_custom("bloom_petal_manifest_v0", &bytes));
        }

        fn put_object(&self, object: Object) {
            self.objects.lock().unwrap().insert(object.id, object);
        }
    }

    impl ChainStateIface for MockChain {
        fn load_object(&self, id: &ObjectId) -> Option<Object> {
            self.objects.lock().unwrap().get(id).cloned()
        }

        fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
            self.code.lock().unwrap().get(hash).cloned()
        }

        fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
            self.manifests.lock().unwrap().get(hash).cloned()
        }

        fn resolve_path(&self, path: &str) -> Option<Hash32> {
            self.bindings
                .lock()
                .unwrap()
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, h)| *h)
        }

        fn iter_vfs(&self) -> Vec<(String, Hash32)> {
            self.bindings.lock().unwrap().clone()
        }

        fn iter_objects(&self) -> Vec<(ObjectId, Object)> {
            self.objects
                .lock()
                .unwrap()
                .iter()
                .map(|(id, object)| (*id, object.clone()))
                .collect()
        }

        fn current_block(&self) -> u64 {
            1
        }
    }

    fn func(name: &str, view: bool) -> FunctionDeclStub {
        FunctionDeclStub {
            name: name.to_string(),
            view,
            ..Default::default()
        }
    }

    fn manifest(path: &str) -> PetalManifestStub {
        PetalManifestStub {
            module_path: path.to_string(),
            functions: vec![func("quote", true), func("swap", false)],
            ..Default::default()
        }
    }

    fn full_manifest(path: &str, object_types: Vec<ObjectTypeDecl>) -> PetalManifestV0 {
        PetalManifestV0 {
            module_path: path.to_string(),
            object_types,
            ..Default::default()
        }
    }

    fn prim(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    fn vector(elem: TypeTag) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: "vector".to_string(),
            type_args: vec![elem],
        }
    }

    fn object_type(name: &str, fields: Vec<(&str, TypeTag)>) -> ObjectTypeDecl {
        ObjectTypeDecl {
            name: name.to_string(),
            abilities: AbilitySet::key_store(),
            fields: fields
                .into_iter()
                .map(|(name, ty)| FieldDecl {
                    name: name.to_string(),
                    ty,
                    offset: None,
                    width: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn petal_object(id_byte: u8, petal_hash: Hash32, type_name: &str, payload: Vec<u8>) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: petal_hash.0,
                type_name: type_name.to_string(),
                type_args: vec![],
            },
            owner: Owner::Shared,
            version: 7,
            payload,
        }
    }

    fn wasm_with_custom(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        out.push(0x00);
        let mut body = Vec::new();
        leb128(&mut body, name.len() as u64);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(payload);
        leb128(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    fn leb128(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn vpath(p: &str) -> VfsPath {
        VfsPath::parse(p).unwrap()
    }

    #[tokio::test]
    async fn lists_bound_path_segments_and_all_endpoints() {
        let chain = Arc::new(MockChain::default());
        chain.bind(
            "/bloom/petals/dex/pool",
            Hash32([1; 32]),
            manifest("/bloom/petals/dex/pool"),
        );
        chain.bind(
            "/bloom/petals/core/fungible",
            Hash32([2; 32]),
            manifest("/bloom/petals/core/fungible"),
        );
        chain.bind(
            "/bloom/legacy/ignored",
            Hash32([3; 32]),
            manifest("/bloom/legacy/ignored"),
        );
        let h = PetalsEndpointHandler::new(chain);

        let root = h.list(&vpath("")).await.unwrap();
        assert_eq!(
            root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".pipe", "core", "dex"]
        );
        let dex = h.list(&vpath("dex")).await.unwrap();
        assert_eq!(dex[0].name, "pool");

        let pool = h.list(&vpath("dex/pool")).await.unwrap();
        assert_eq!(
            pool.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state", "quote", "swap"]
        );
        assert_eq!(pool[0].mode, 0o755);
        assert_eq!(pool[1].mode, 0o555);
        assert_eq!(pool[2].mode, 0o555);
    }

    #[tokio::test]
    async fn root_includes_pipe_node_and_reads_composition_shim() {
        let h = PetalsEndpointHandler::new(Arc::new(MockChain::default()));

        let root = h.list(&vpath("")).await.unwrap();
        let pipe = root.iter().find(|entry| entry.name == ".pipe").unwrap();
        assert_eq!(pipe.mode, 0o555);

        let entry = h.lookup(&vpath(".pipe")).await.unwrap();
        assert_eq!(entry.mode, 0o555);

        let shim = String::from_utf8(h.read(&vpath(".pipe")).await.unwrap()).unwrap();
        assert!(shim.starts_with("#!/bin/sh\n"));
        assert!(shim.contains("exec bloom chain pipe \"$@\""));
    }

    #[tokio::test]
    async fn root_pipe_node_is_not_paginated_with_projected_petals() {
        let chain = Arc::new(MockChain::default());
        for i in 0..=paginate::PAGE_SIZE {
            let path = format!("/bloom/petals/p{i:03}");
            chain.bind(&path, Hash32([i as u8; 32]), manifest(&path));
        }
        let h = PetalsEndpointHandler::new(chain);

        let root = h.list(&vpath("")).await.unwrap();
        assert_eq!(
            root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".pipe", "page"]
        );

        let page = h.list(&vpath("page/000000")).await.unwrap();
        assert!(!page.iter().any(|entry| entry.name == ".pipe"));
        assert!(page.iter().all(|entry| entry.name.starts_with('p')));
    }

    #[tokio::test]
    async fn state_projection_lists_objects_and_decodes_fields() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x11; 32]);
        let other_hash = Hash32([0x22; 32]);
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest(
                "/bloom/petals/dex/probe",
                vec![
                    object_type(
                        "Counter",
                        vec![
                            ("value", prim("u128")),
                            ("label", prim("String")),
                            ("ticks", vector(prim("u16"))),
                        ],
                    ),
                    object_type("Other", vec![("n", prim("u8"))]),
                ],
            ),
        );

        let mut payload = Vec::new();
        payload.extend_from_slice(&99u128.to_be_bytes());
        payload.push(2);
        payload.extend_from_slice(b"ok");
        payload.push(2);
        payload.extend_from_slice(&(7u16).to_be_bytes());
        payload.extend_from_slice(&(8u16).to_be_bytes());
        let counter = petal_object(0xA1, hash, "Counter", payload);
        let counter_id = hex::encode(counter.id.0);
        chain.put_object(counter);
        chain.put_object(petal_object(
            0xA2,
            other_hash,
            "Counter",
            1u128.to_be_bytes().to_vec(),
        ));
        chain.put_object(petal_object(0xA3, hash, "Other", vec![1]));

        let h = PetalsEndpointHandler::new(chain);

        let root = h.list(&vpath("dex/probe")).await.unwrap();
        assert_eq!(
            root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state"]
        );
        let types = h.list(&vpath("dex/probe/.state")).await.unwrap();
        assert_eq!(
            types.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["Counter", "Other"]
        );
        let counters = h.list(&vpath("dex/probe/.state/Counter")).await.unwrap();
        assert_eq!(
            counters.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![counter_id.as_str()]
        );
        let leaves = h
            .list(&vpath(&format!("dex/probe/.state/Counter/{counter_id}")))
            .await
            .unwrap();
        assert_eq!(
            leaves.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["_object.json", "label", "ticks", "value"]
        );

        let value = String::from_utf8(
            h.read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/value"
            )))
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value, "\"99\"\n");
        let object_json = h
            .read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/_object.json"
            )))
            .await
            .unwrap();
        let object_json: Value = serde_json::from_slice(&object_json).unwrap();
        assert_eq!(object_json["id"], counter_id);
        assert_eq!(object_json["type_name"], "Counter");
        assert_eq!(object_json["fields"]["value"], "99");
        assert_eq!(object_json["fields"]["label"], "ok");
        assert_eq!(object_json["fields"]["ticks"], json!([7, 8]));
        assert!(matches!(
            h.lookup(&vpath("dex/probe/.state/Missing")).await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            h.read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/missing"
            )))
            .await,
            Err(HandlerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn state_object_ids_are_paginated_and_state_files_are_read_only() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x12; 32]);
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest(
                "/bloom/petals/dex/probe",
                vec![object_type("Counter", vec![("value", prim("u128"))])],
            ),
        );
        for i in 0..=paginate::PAGE_SIZE {
            let mut id = [0u8; 32];
            id[30..].copy_from_slice(&(i as u16).to_be_bytes());
            chain.put_object(Object {
                id: ObjectId(id),
                type_tag: TypeTag::Concrete {
                    petal_hash: hash.0,
                    type_name: "Counter".to_string(),
                    type_args: vec![],
                },
                owner: Owner::Shared,
                version: 1,
                payload: (i as u128).to_be_bytes().to_vec(),
            });
        }
        let h = PetalsEndpointHandler::new(chain);

        let counters = h.list(&vpath("dex/probe/.state/Counter")).await.unwrap();
        assert_eq!(
            counters.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["page"]
        );
        let page = h
            .list(&vpath("dex/probe/.state/Counter/page/000000"))
            .await
            .unwrap();
        assert_eq!(page.len(), paginate::PAGE_SIZE);
        assert!(page.iter().all(|entry| entry.mode == 0o755));

        let first_id = &page[0].name;
        let value = h
            .lookup(&vpath(&format!(
                "dex/probe/.state/Counter/{first_id}/value"
            )))
            .await
            .unwrap();
        assert_eq!(value.mode, 0o444);
        assert!(matches!(
            h.write(
                &vpath(&format!("dex/probe/.state/Counter/{first_id}/value")),
                b"123"
            )
            .await,
            Err(HandlerError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn state_type_and_field_directories_page_when_advertised() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x13; 32]);
        let counter_fields = (0..=paginate::PAGE_SIZE)
            .map(|i| FieldDecl {
                name: format!("field_{i:03}"),
                ty: prim("u8"),
                offset: None,
                width: None,
            })
            .collect::<Vec<_>>();
        let counter_type = ObjectTypeDecl {
            name: "Counter".to_string(),
            abilities: AbilitySet::key_store(),
            fields: counter_fields,
            ..Default::default()
        };
        let mut object_types = vec![counter_type];
        for i in 0..=paginate::PAGE_SIZE {
            object_types.push(object_type(&format!("Type{i:03}"), vec![]));
        }
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest("/bloom/petals/dex/probe", object_types),
        );
        let counter = petal_object(0x13, hash, "Counter", vec![7; paginate::PAGE_SIZE + 1]);
        let counter_id = hex::encode(counter.id.0);
        chain.put_object(counter);
        let h = PetalsEndpointHandler::new(chain);

        let types = h.list(&vpath("dex/probe/.state")).await.unwrap();
        assert_eq!(
            types.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["page"]
        );
        h.lookup(&vpath("dex/probe/.state/page")).await.unwrap();
        let type_page = h
            .list(&vpath("dex/probe/.state/page/000000"))
            .await
            .unwrap();
        assert_eq!(type_page.len(), paginate::PAGE_SIZE);

        let leaves = h
            .list(&vpath(&format!("dex/probe/.state/Counter/{counter_id}")))
            .await
            .unwrap();
        assert_eq!(
            leaves.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["page"]
        );
        h.lookup(&vpath(&format!(
            "dex/probe/.state/Counter/{counter_id}/page"
        )))
        .await
        .unwrap();
        let field_page = h
            .list(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/page/000000"
            )))
            .await
            .unwrap();
        assert_eq!(field_page.len(), paginate::PAGE_SIZE);
        assert!(field_page.iter().any(|entry| entry.name == "_object.json"));
    }

    #[tokio::test]
    async fn invalid_state_type_names_are_not_exposed() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x14; 32]);
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest(
                "/bloom/petals/dex/probe",
                vec![
                    object_type("Counter", vec![("value", prim("u128"))]),
                    object_type("Foo/Bar", vec![("value", prim("u128"))]),
                    object_type("page", vec![("value", prim("u128"))]),
                    object_type(".state", vec![("value", prim("u128"))]),
                ],
            ),
        );
        let h = PetalsEndpointHandler::new(chain);

        let types = h.list(&vpath("dex/probe/.state")).await.unwrap();
        assert_eq!(
            types.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["Counter"]
        );
        assert!(matches!(
            h.lookup(&vpath("dex/probe/.state/page")).await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            h.lookup(&vpath("dex/probe/.state/.state")).await,
            Err(HandlerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn invalid_state_field_names_are_not_exposed() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x15; 32]);
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest(
                "/bloom/petals/dex/probe",
                vec![object_type(
                    "Counter",
                    vec![
                        ("value", prim("u8")),
                        ("page", prim("u8")),
                        (".state", prim("u8")),
                        ("Foo/Bar", prim("u8")),
                        (OBJECT_JSON, prim("u8")),
                    ],
                )],
            ),
        );
        let counter = petal_object(0x15, hash, "Counter", vec![9, 8, 7, 6, 5]);
        let counter_id = hex::encode(counter.id.0);
        chain.put_object(counter);
        let h = PetalsEndpointHandler::new(chain);

        let leaves = h
            .list(&vpath(&format!("dex/probe/.state/Counter/{counter_id}")))
            .await
            .unwrap();
        assert_eq!(
            leaves.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["_object.json", "value"]
        );
        assert!(matches!(
            h.lookup(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/page"
            )))
            .await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            h.read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/page"
            )))
            .await,
            Err(HandlerError::NotFound(_))
        ));
        let object_json = h
            .read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/{OBJECT_JSON}"
            )))
            .await
            .unwrap();
        let object_json: Value = serde_json::from_slice(&object_json).unwrap();
        assert_eq!(object_json["id"], counter_id);
        assert_eq!(object_json["fields"][OBJECT_JSON], json!(5));
    }

    #[tokio::test]
    async fn state_read_hard_errors_on_malformed_canonical_payload() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x16; 32]);
        chain.bind_full(
            "/bloom/petals/dex/probe",
            hash,
            full_manifest(
                "/bloom/petals/dex/probe",
                vec![object_type("Counter", vec![("value", prim("u128"))])],
            ),
        );
        let mut payload = 5u128.to_be_bytes().to_vec();
        payload.push(0xAA);
        let counter = petal_object(0x16, hash, "Counter", payload);
        let counter_id = hex::encode(counter.id.0);
        chain.put_object(counter);
        let h = PetalsEndpointHandler::new(chain);

        let err = h
            .read(&vpath(&format!(
                "dex/probe/.state/Counter/{counter_id}/{OBJECT_JSON}"
            )))
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::Backend(ref msg) if msg.contains("object payload decode failed")),
            "malformed canonical payload must hard-error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn state_read_resolves_external_fields() {
        let chain = Arc::new(MockChain::default());
        let hash = Hash32([0x17; 32]);
        let foreign_hash = Hash32([0x18; 32]);
        let object_type = object_type("Box", vec![("foreign", TypeTag::External { ref_idx: 0 })]);
        let mut manifest = full_manifest("/bloom/petals/dex/box", vec![object_type]);
        manifest.external_type_refs.push(ExternalTypeRef {
            placeholder: "$external_0".to_string(),
            declared_petal_path: "/bloom/petals/foreign".to_string(),
            declared_type_name: "Foreign".to_string(),
            declared_content_hash: Some(foreign_hash.0),
        });
        let foreign_manifest = PetalManifestV0 {
            module_path: "/bloom/petals/foreign".to_string(),
            data_types: vec![DataTypeDecl {
                name: "Foreign".to_string(),
                fields: vec![FieldDecl {
                    name: "value".to_string(),
                    ty: prim("u64"),
                    offset: None,
                    width: Some(8),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        chain.bind_full("/bloom/petals/dex/box", hash, manifest);
        chain.bind_full("/bloom/petals/foreign", foreign_hash, foreign_manifest);
        let object = petal_object(0x17, hash, "Box", 7u64.to_be_bytes().to_vec());
        let object_id = hex::encode(object.id.0);
        chain.put_object(object);
        let h = PetalsEndpointHandler::new(chain);

        let field = h
            .read(&vpath(&format!("dex/box/.state/Box/{object_id}/foreign")))
            .await
            .unwrap();
        let field: Value = serde_json::from_slice(&field).unwrap();
        assert_eq!(field, json!({ "value": "7" }));
    }

    #[tokio::test]
    async fn state_read_resolves_transitive_external_fields() {
        let chain = Arc::new(MockChain::default());
        let root_hash = Hash32([0x19; 32]);
        let middle_hash = Hash32([0x1A; 32]);
        let leaf_hash = Hash32([0x1B; 32]);
        let object_type = object_type("Box", vec![("foreign", TypeTag::External { ref_idx: 0 })]);
        let mut root_manifest = full_manifest("/bloom/petals/dex/box", vec![object_type]);
        root_manifest.external_type_refs.push(ExternalTypeRef {
            placeholder: "$external_0".to_string(),
            declared_petal_path: "/bloom/petals/middle".to_string(),
            declared_type_name: "Middle".to_string(),
            declared_content_hash: Some(middle_hash.0),
        });
        let mut middle_manifest = PetalManifestV0 {
            module_path: "/bloom/petals/middle".to_string(),
            data_types: vec![DataTypeDecl {
                name: "Middle".to_string(),
                fields: vec![FieldDecl {
                    name: "leaf".to_string(),
                    ty: TypeTag::External { ref_idx: 0 },
                    offset: None,
                    width: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        middle_manifest.external_type_refs.push(ExternalTypeRef {
            placeholder: "$external_0".to_string(),
            declared_petal_path: "/bloom/petals/leaf".to_string(),
            declared_type_name: "Leaf".to_string(),
            declared_content_hash: Some(leaf_hash.0),
        });
        let leaf_manifest = PetalManifestV0 {
            module_path: "/bloom/petals/leaf".to_string(),
            data_types: vec![DataTypeDecl {
                name: "Leaf".to_string(),
                fields: vec![FieldDecl {
                    name: "value".to_string(),
                    ty: prim("u64"),
                    offset: None,
                    width: Some(8),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        chain.bind_full("/bloom/petals/dex/box", root_hash, root_manifest);
        chain.bind_full("/bloom/petals/middle", middle_hash, middle_manifest);
        chain.bind_full("/bloom/petals/leaf", leaf_hash, leaf_manifest);
        let object = petal_object(0x19, root_hash, "Box", 7u64.to_be_bytes().to_vec());
        let object_id = hex::encode(object.id.0);
        chain.put_object(object);
        let h = PetalsEndpointHandler::new(chain);

        let field = h
            .read(&vpath(&format!("dex/box/.state/Box/{object_id}/foreign")))
            .await
            .unwrap();
        let field: Value = serde_json::from_slice(&field).unwrap();
        assert_eq!(field, json!({ "leaf": { "value": "7" } }));
    }

    #[test]
    fn state_field_decoder_substitutes_generics() {
        let hash = Hash32([0x33; 32]);
        let mut object_type = object_type("Box", vec![("inner", TypeTag::Generic { idx: 0 })]);
        object_type.type_params.push(TypeParamDecl {
            name: "T".to_string(),
            kind: TypeParamKind::Resource,
            bounds: vec![],
        });
        let mut payload = Vec::new();
        payload.extend_from_slice(&5u128.to_be_bytes());
        let object = Object {
            id: ObjectId([0x44; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: hash.0,
                type_name: "Box".to_string(),
                type_args: vec![prim("u128")],
            },
            owner: Owner::Immutable,
            version: 1,
            payload,
        };

        let manifest = full_manifest("/bloom/petals/dex/box", vec![object_type.clone()]);
        let fields = decode_object_fields(hash, &object, &object_type, &manifest, &[]).unwrap();
        assert_eq!(fields["inner"], "5");
    }

    #[test]
    fn state_field_decoder_errors_on_unresolved_fields() {
        let hash = Hash32([0x34; 32]);
        let object_type = object_type(
            "Box",
            vec![(
                "opaque",
                TypeTag::Concrete {
                    petal_hash: hash.0,
                    type_name: "Custom".to_string(),
                    type_args: vec![],
                },
            )],
        );
        let object = petal_object(0x34, hash, "Box", vec![0xAB, 0xCD]);
        let manifest = full_manifest("/bloom/petals/dex/box", vec![object_type.clone()]);
        assert!(decode_object_fields(hash, &object, &object_type, &manifest, &[]).is_err());
    }

    #[test]
    fn state_field_decoder_resolves_external_fields() {
        let hash = Hash32([0x35; 32]);
        let foreign_hash = Hash32([0x36; 32]);
        let object_type = object_type("Box", vec![("foreign", TypeTag::External { ref_idx: 0 })]);
        let mut manifest = full_manifest("/bloom/petals/dex/box", vec![object_type.clone()]);
        manifest.external_type_refs.push(ExternalTypeRef {
            placeholder: "$external_0".to_string(),
            declared_petal_path: "/bloom/petals/foreign".to_string(),
            declared_type_name: "Foreign".to_string(),
            declared_content_hash: Some(foreign_hash.0),
        });
        let foreign_manifest = PetalManifestV0 {
            module_path: "/bloom/petals/foreign".to_string(),
            data_types: vec![DataTypeDecl {
                name: "Foreign".to_string(),
                fields: vec![FieldDecl {
                    name: "value".to_string(),
                    ty: prim("u64"),
                    offset: None,
                    width: Some(8),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let object = petal_object(0x35, hash, "Box", 7u64.to_be_bytes().to_vec());

        assert!(decode_object_fields(hash, &object, &object_type, &manifest, &[]).is_err());
        let fields = decode_object_fields(
            hash,
            &object,
            &object_type,
            &manifest,
            &[(foreign_hash, foreign_manifest)],
        )
        .unwrap();
        assert_eq!(fields["foreign"], json!({ "value": "7" }));
    }

    #[test]
    fn state_field_decoder_decodes_nested_structs_and_vectors() {
        let hash = Hash32([0x55; 32]);
        let stats = object_type(
            "Stats",
            vec![("count", prim("u32")), ("enabled", prim("bool"))],
        );
        let object_type = object_type(
            "Vault",
            vec![
                (
                    "stats",
                    TypeTag::Concrete {
                        petal_hash: [0; 32],
                        type_name: "Stats".to_string(),
                        type_args: vec![],
                    },
                ),
                ("amounts", vector(prim("u128"))),
            ],
        );
        let manifest = full_manifest("/bloom/petals/dex/vault", vec![stats, object_type.clone()]);

        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_be_bytes());
        payload.push(1);
        payload.push(2);
        payload.extend_from_slice(&7u128.to_be_bytes());
        payload.extend_from_slice(&9u128.to_be_bytes());
        let object = Object {
            id: ObjectId([0x66; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: hash.0,
                type_name: "Vault".to_string(),
                type_args: vec![],
            },
            owner: Owner::Immutable,
            version: 1,
            payload,
        };

        let fields = decode_object_fields(hash, &object, &object_type, &manifest, &[]).unwrap();
        assert_eq!(fields["stats"], json!({ "count": 42, "enabled": true }));
        assert_eq!(fields["amounts"], json!(["7", "9"]));
    }

    #[test]
    fn state_field_decoder_rejects_zero_width_vector_elements() {
        let hash = Hash32([0x77; 32]);
        let empty = object_type("Empty", vec![]);
        let object_type = object_type(
            "Bag",
            vec![(
                "items",
                vector(TypeTag::Concrete {
                    petal_hash: [0; 32],
                    type_name: "Empty".to_string(),
                    type_args: vec![],
                }),
            )],
        );
        let manifest = full_manifest("/bloom/petals/dex/bag", vec![empty, object_type.clone()]);
        let payload = vec![1];
        let object = petal_object(0x77, hash, "Bag", payload);

        assert!(decode_object_fields(hash, &object, &object_type, &manifest, &[]).is_err());
    }

    #[tokio::test]
    async fn page_segment_is_only_pagination_when_parent_is_paged() {
        let chain = Arc::new(MockChain::default());
        chain.bind(
            "/bloom/petals/dex/page",
            Hash32([1; 32]),
            manifest("/bloom/petals/dex/page"),
        );
        let h = PetalsEndpointHandler::new(chain);

        let dex = h.list(&vpath("dex")).await.unwrap();
        assert_eq!(
            dex.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["page"]
        );

        let page = h.list(&vpath("dex/page")).await.unwrap();
        assert_eq!(
            page.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state", "quote", "swap"]
        );
    }

    #[tokio::test]
    async fn invalid_function_segments_are_not_exposed() {
        let chain = Arc::new(MockChain::default());
        chain.bind(
            "/bloom/petals/dex/pool",
            Hash32([1; 32]),
            PetalManifestStub {
                module_path: "/bloom/petals/dex/pool".to_string(),
                functions: vec![
                    func("quote", true),
                    func("foo/bar", true),
                    func("foo\\bar", true),
                    func("page", true),
                    func(".state", true),
                    func(".pipe", true),
                    func("set counter", true),
                ],
                ..Default::default()
            },
        );
        let h = PetalsEndpointHandler::new(chain);

        let pool = h.list(&vpath("dex/pool")).await.unwrap();
        assert_eq!(
            pool.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state", "quote"]
        );
        assert!(matches!(
            h.lookup(&vpath("dex/pool/page")).await,
            Err(HandlerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn reads_shim_with_baked_path_and_function() {
        let chain = Arc::new(MockChain::default());
        chain.bind(
            "/bloom/petals/dex/pool",
            Hash32([1; 32]),
            manifest("/bloom/petals/dex/pool"),
        );
        let h = PetalsEndpointHandler::new(chain);

        let entry = h.lookup(&vpath("dex/pool/quote")).await.unwrap();
        assert_eq!(entry.mode, 0o555);

        let shim = String::from_utf8(h.read(&vpath("dex/pool/quote")).await.unwrap()).unwrap();
        assert!(shim.starts_with("#!/bin/sh\n"));
        assert!(shim.contains("bloom chain view-call"));
        assert!(shim.contains("--path '/bloom/petals/dex/pool'"));
        assert!(shim.contains("--function 'quote'"));

        let swap = String::from_utf8(h.read(&vpath("dex/pool/swap")).await.unwrap()).unwrap();
        assert!(swap.contains("bloom chain call"));
        assert!(swap.contains("--path '/bloom/petals/dex/pool'"));
        assert!(swap.contains("--function 'swap'"));
    }

    #[tokio::test]
    async fn unbound_path_is_not_found() {
        let h = PetalsEndpointHandler::new(Arc::new(MockChain::default()));
        assert!(matches!(
            h.lookup(&vpath("dex/pool")).await,
            Err(HandlerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn endpoint_wins_over_same_named_descendant_directory() {
        let chain = Arc::new(MockChain::default());
        chain.bind(
            "/bloom/petals/dex",
            Hash32([1; 32]),
            PetalManifestStub {
                module_path: "/bloom/petals/dex".to_string(),
                functions: vec![func("pool", true)],
                ..Default::default()
            },
        );
        chain.bind(
            "/bloom/petals/dex/pool/child",
            Hash32([2; 32]),
            manifest("/bloom/petals/dex/pool/child"),
        );
        let h = PetalsEndpointHandler::new(chain);

        let dex = h.list(&vpath("dex")).await.unwrap();
        assert_eq!(
            dex.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state", "pool"]
        );
        assert_eq!(dex[1].mode, 0o555);

        let pool = h.lookup(&vpath("dex/pool")).await.unwrap();
        assert_eq!(pool.mode, 0o555);
        let shim = String::from_utf8(h.read(&vpath("dex/pool")).await.unwrap()).unwrap();
        assert!(shim.contains("--path '/bloom/petals/dex'"));
        assert!(shim.contains("--function 'pool'"));

        let child = h.list(&vpath("dex/pool/child")).await.unwrap();
        assert_eq!(
            child.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec![".state", "quote", "swap"]
        );
    }
}
