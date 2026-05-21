//! `ChainStateIface` adapter over `bloom_chain_state::State`.
//!
//! The PTB validator and executor (in `bloom-script`) operate against
//! the narrow [`bloom_script::ChainStateIface`] trait so they have no
//! compile-time dependency on the chain crate. This adapter is the
//! single production implementation.
//!
//! ## Phase 1 limitations
//!
//! - [`load_object`] reads from the in-memory `objects` map maintained
//!   on [`bloom_chain_state::State`] (spec §16.3 Phase 1; no merkleisation yet).
//! - [`load_manifest`] always returns `None` unless an in-memory
//!   manifest registry is supplied (see [`PtbChainAdapter::with_manifests`]).
//! - [`resolve_path`] always returns `None`; the on-chain VFS path index
//!   is not yet exposed by `bloom-chain-state`. The validator treats an
//!   unbound path as permissive, so pure-hash PetalRefs still validate.
//!
//! PTBs whose validation step requires any of these will fail with the
//! appropriate `PtbError` (`ObjectNotFound`, `PetalNotFound`,
//! `PetalNotPinned`) — which is exactly the conservative, fail-closed
//! behaviour we want.
//!
//! [`load_object`]: ChainStateIface::load_object
//! [`load_manifest`]: ChainStateIface::load_manifest
//! [`resolve_path`]: ChainStateIface::resolve_path

use std::collections::HashMap;

use bloom_chain_state::State;
use bloom_chain_types::Hash32;
use bloom_objects::{Object, ObjectId};
use bloom_script::{ChainStateIface, PetalManifestStub};

/// Adapter wrapping a borrowed [`State`] for PTB validation / execution.
///
/// `current_block` is supplied by the caller because the block height
/// is part of the executor's per-tx context (`apply_block` passes it
/// in), not a property of `State` itself.
pub struct PtbChainAdapter<'a> {
    state: &'a State,
    current_block: u64,
    manifests: Option<&'a HashMap<Hash32, PetalManifestStub>>,
}

impl<'a> PtbChainAdapter<'a> {
    /// Build an adapter without a manifest registry. `load_manifest`
    /// returns `None` for every petal hash.
    pub fn new(state: &'a State, current_block: u64) -> Self {
        Self { state, current_block, manifests: None }
    }

    /// Build an adapter with an injected manifest registry. Tests use
    /// this to stub out manifest lookup until the on-chain manifest
    /// store lands.
    pub fn with_manifests(
        state: &'a State,
        current_block: u64,
        manifests: &'a HashMap<Hash32, PetalManifestStub>,
    ) -> Self {
        Self { state, current_block, manifests: Some(manifests) }
    }
}

impl ChainStateIface for PtbChainAdapter<'_> {
    fn load_object(&self, id: &ObjectId) -> Option<Object> {
        self.state.get_object(id)
    }

    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
        self.state.get_code(hash).map(|b| b.to_vec())
    }

    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
        self.manifests.and_then(|m| m.get(hash).cloned())
    }

    fn resolve_path(&self, _path: &str) -> Option<Hash32> {
        // VFS path index not exposed by `bloom-chain-state` yet.
        None
    }

    fn current_block(&self) -> u64 {
        self.current_block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_state::State;

    #[test]
    fn current_block_is_returned_verbatim() {
        let state = State::new();
        let adapter = PtbChainAdapter::new(&state, 1234);
        assert_eq!(adapter.current_block(), 1234);
    }

    #[test]
    fn load_object_returns_none_when_absent() {
        let state = State::new();
        let adapter = PtbChainAdapter::new(&state, 0);
        assert!(adapter.load_object(&ObjectId([0u8; 32])).is_none());
    }

    #[test]
    fn load_object_reads_from_state_objects_map() {
        use bloom_objects::{Owner, TypeTag};
        let mut state = State::new();
        let id = ObjectId([0x42; 32]);
        let obj = Object {
            id,
            type_tag: TypeTag::Concrete {
                petal_hash: [0; 32],
                type_name: "Coin".to_string(),
                type_args: vec![],
            },
            owner: Owner::Address([0xAA; 32]),
            version: 7,
            payload: vec![9, 9, 9],
        };
        state.set_object(obj.clone());

        let adapter = PtbChainAdapter::new(&state, 0);
        assert_eq!(adapter.load_object(&id), Some(obj));
        assert!(adapter.load_object(&ObjectId([0u8; 32])).is_none());
    }

    #[test]
    fn resolve_path_returns_none_until_vfs_lands() {
        let state = State::new();
        let adapter = PtbChainAdapter::new(&state, 0);
        assert!(adapter.resolve_path("/anything").is_none());
    }

    #[test]
    fn load_manifest_returns_none_without_registry() {
        let state = State::new();
        let adapter = PtbChainAdapter::new(&state, 0);
        assert!(adapter.load_manifest(&Hash32([0u8; 32])).is_none());
    }

    #[test]
    fn load_manifest_returns_from_registry_when_present() {
        let state = State::new();
        let mut manifests = HashMap::new();
        manifests.insert(
            Hash32([7u8; 32]),
            PetalManifestStub {
                module_path: "/test/petal".to_string(),
                ..Default::default()
            },
        );
        let adapter = PtbChainAdapter::with_manifests(&state, 0, &manifests);
        let m = adapter.load_manifest(&Hash32([7u8; 32])).unwrap();
        assert_eq!(m.module_path, "/test/petal");
        assert!(adapter.load_manifest(&Hash32([0u8; 32])).is_none());
    }

    #[test]
    fn load_petal_returns_code_from_state() {
        let mut state = State::new();
        let wasm = vec![1, 2, 3, 4];
        let hash = state.insert_code(&wasm);
        let adapter = PtbChainAdapter::new(&state, 0);
        assert_eq!(adapter.load_petal(&hash).as_deref(), Some(&wasm[..]));
        assert!(adapter.load_petal(&Hash32([0u8; 32])).is_none());
    }
}
