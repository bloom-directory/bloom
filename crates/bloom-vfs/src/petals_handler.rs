//! `petals/` — executable view endpoints for deployed Bloom-native petals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use bloom_chain_types::Hash32;
use bloom_script::{ChainStateIface, PetalManifestStub};

use crate::handler::{Entry, Handler, HandlerError};
use crate::paginate;
use crate::path::VfsPath;

const PETAL_PREFIX: &str = "/bloom/petals/";
const PIPE_NODE: &str = ".pipe";
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
            .find(|f| f.name == *function)
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
            for function in &manifest.functions {
                by_name
                    .entry(function.name.clone())
                    .or_insert_with(|| Entry::executable_file(&function.name));
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
            for function in &manifest.functions {
                by_name
                    .entry(function.name.clone())
                    .or_insert_with(|| Entry::executable_file(&function.name));
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
        if let Some((parent, Some(_))) = split_page_path(segs) {
            let _ = self.entries_for_unpaged(parent)?;
            return Ok(Entry::dir(segs.last().expect("page path has leaf")));
        }
        if matches!(segs.last().map(String::as_str), Some("page")) {
            let parent = &segs[..segs.len() - 1];
            let total = self.entries_for_unpaged(parent)?.len();
            if paginate::is_paged(total) {
                return Ok(Entry::dir("page"));
            }
        }

        let bindings = self.bindings();
        if Self::has_descendant(&bindings, segs) {
            return Ok(Entry::dir(segs.last().expect("non-root has leaf")));
        }
        if let Some((_binding, function, _view)) = self.endpoint_at(&bindings, segs) {
            return Ok(Entry::executable_file(&function));
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
        if Self::has_descendant(&bindings, segs) {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        let Some((binding, function, view)) = self.endpoint_at(&bindings, segs) else {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        };
        Ok(Self::shim(&binding.path, &function, view))
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        if matches!(segs.last().map(String::as_str), Some("page")) {
            let parent = &segs[..segs.len() - 1];
            let total = self.entries_for_unpaged(parent)?.len();
            return Ok(paginate::page_indices(total));
        }
        if let Some((parent, Some(index))) = split_page_path(segs) {
            return self.page_entries_for(parent, index);
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

    use bloom_objects::{Object, ObjectId};
    use bloom_script::FunctionDeclStub;

    #[derive(Default)]
    struct MockChain {
        bindings: Mutex<Vec<(String, Hash32)>>,
        manifests: Mutex<HashMap<Hash32, PetalManifestStub>>,
    }

    impl MockChain {
        fn bind(&self, path: &str, hash: Hash32, manifest: PetalManifestStub) {
            self.bindings.lock().unwrap().push((path.to_string(), hash));
            self.manifests.lock().unwrap().insert(hash, manifest);
        }
    }

    impl ChainStateIface for MockChain {
        fn load_object(&self, _id: &ObjectId) -> Option<Object> {
            None
        }

        fn load_petal(&self, _hash: &Hash32) -> Option<Vec<u8>> {
            None
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
        assert_eq!(pool.len(), 2);
        assert_eq!(pool[0].name, "quote");
        assert_eq!(pool[0].mode, 0o555);
        assert_eq!(pool[1].name, "swap");
        assert_eq!(pool[1].mode, 0o555);
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
    async fn descendant_directory_wins_over_same_named_view_endpoint() {
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
        assert_eq!(dex.len(), 1);
        assert_eq!(dex[0].name, "pool");
        assert_eq!(dex[0].mode, 0o755);

        let pool = h.lookup(&vpath("dex/pool")).await.unwrap();
        assert_eq!(pool.mode, 0o755);
        assert!(matches!(
            h.read(&vpath("dex/pool")).await,
            Err(HandlerError::NotAFile(_))
        ));
    }
}
