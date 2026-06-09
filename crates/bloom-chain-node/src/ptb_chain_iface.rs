//! `ChainStateIface` adapter over `bloom_chain_state::State`.
//!
//! The PTB validator and executor (in `bloom-script`) operate against
//! the narrow [`bloom_script::ChainStateIface`] trait so they have no
//! compile-time dependency on the chain crate. This adapter is the
//! single production implementation.
//!
//! ## Manifest resolution (chain-authoritative)
//!
//! [`load_manifest`] consults two layers, in order:
//!
//! 1. **Optional overrides map** — supplied by `with_overrides(...)` and
//!    consulted first. Tests use this to inject hand-written
//!    `PetalManifestStub`s for petals that aren't real wasm (e.g.
//!    validator unit tests that exercise typecheck logic against
//!    synthetic manifests). Production never sets this.
//!
//! 2. **On-chain wasm custom section** — the adapter pulls the wasm by
//!    content hash via `state.get_code(...)`, walks it for the
//!    `bloom_petal_manifest` custom section (emitted by
//!    `#[bloom::petal]`, spec §8.1 / §11.1), decodes the bytes via the
//!    canonical codec, and projects them down to the validator's
//!    `PetalManifestStub` via
//!    [`bloom_petal_manifest::to_petal_manifest_stub`].
//!
//! Decoded stubs are memoised inside the adapter's lifetime so a PTB
//! with multiple commands hitting the same petal pays the wasm-walk
//! cost only once.
//!
//! [`load_object`] reads from the in-memory `objects` map maintained on
//! [`bloom_chain_state::State`] (spec §16.3 Phase 1; no merkleisation
//! yet). [`resolve_path`] consults `State::vfs_lookup`, populated by
//! a successful PTB publish path.
//!
//! [`load_object`]: ChainStateIface::load_object
//! [`load_manifest`]: ChainStateIface::load_manifest
//! [`resolve_path`]: ChainStateIface::resolve_path

use std::cell::RefCell;
use std::collections::HashMap;

use bloom_chain_state::State;
use bloom_chain_types::Hash32;
use bloom_objects::{Object, ObjectId};
use bloom_petal_manifest::{extract_petal_manifest, to_petal_manifest_stub};
use bloom_script::{ChainStateIface, PetalManifestStub};

/// Adapter wrapping a borrowed [`State`] for PTB validation / execution.
///
/// `current_block` is supplied by the caller because the block height
/// is part of the executor's per-tx context (`apply_block` passes it
/// in), not a property of `State` itself.
///
/// The adapter memoises decoded `PetalManifestStub`s for the duration
/// of its borrow so a multi-command PTB doesn't repeatedly walk the
/// same wasm.
pub struct PtbChainAdapter<'a> {
    state: &'a State,
    current_block: u64,
    /// Optional test-only override map. Consulted before the wasm
    /// custom-section path so tests can inject synthetic stubs for
    /// petals that aren't real wasm.
    overrides: Option<&'a HashMap<Hash32, PetalManifestStub>>,
    /// Per-adapter cache of stubs decoded from wasm custom sections.
    /// Keyed by petal content hash. `None` means "we tried and it
    /// wasn't a manifest"; absence means "we haven't tried yet".
    manifest_cache: RefCell<HashMap<Hash32, Option<PetalManifestStub>>>,
}

impl<'a> PtbChainAdapter<'a> {
    /// Build a production adapter without test overrides.
    /// `load_manifest` resolves entirely from wasm custom sections.
    pub fn new(state: &'a State, current_block: u64) -> Self {
        Self {
            state,
            current_block,
            overrides: None,
            manifest_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Build an adapter with an injected test-only override map.
    ///
    /// The overrides are consulted **before** the on-chain wasm
    /// custom-section path so a test can stub out a petal's manifest
    /// without needing a real wasm artefact. Production code paths use
    /// [`PtbChainAdapter::new`].
    pub fn with_overrides(
        state: &'a State,
        current_block: u64,
        overrides: &'a HashMap<Hash32, PetalManifestStub>,
    ) -> Self {
        Self {
            state,
            current_block,
            overrides: Some(overrides),
            manifest_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Back-compat alias for [`PtbChainAdapter::with_overrides`].
    ///
    /// Existing test code reads more naturally as `with_manifests` —
    /// keep the old spelling.
    pub fn with_manifests(
        state: &'a State,
        current_block: u64,
        overrides: &'a HashMap<Hash32, PetalManifestStub>,
    ) -> Self {
        Self::with_overrides(state, current_block, overrides)
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
        // Layer 1: test-only overrides take precedence.
        if let Some(map) = self.overrides
            && let Some(stub) = map.get(hash)
        {
            return Some(stub.clone());
        }

        // Layer 2: wasm custom-section parse + project, memoised.
        {
            let cache = self.manifest_cache.borrow();
            if let Some(slot) = cache.get(hash) {
                return slot.clone();
            }
        }

        let stub = self.state.get_code(hash).and_then(|wasm| {
            let m = extract_petal_manifest(wasm)?;
            Some(to_petal_manifest_stub(&m))
        });
        self.manifest_cache.borrow_mut().insert(*hash, stub.clone());
        stub
    }

    fn resolve_path(&self, path: &str) -> Option<Hash32> {
        self.state.vfs_lookup(path)
    }

    fn iter_vfs(&self) -> Vec<(String, Hash32)> {
        self.state
            .iter_vfs()
            .map(|(p, h)| (p.clone(), *h))
            .collect()
    }

    fn iter_objects(&self) -> Vec<(bloom_objects::ObjectId, Object)> {
        self.state
            .iter_objects()
            .map(|(id, obj)| (*id, obj.clone()))
            .collect()
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
    fn resolve_path_reads_from_state_vfs() {
        let mut state = State::new();
        state.set_vfs_binding("/bloom/test".into(), Hash32([0xAB; 32]));
        let adapter = PtbChainAdapter::new(&state, 0);
        assert_eq!(
            adapter.resolve_path("/bloom/test"),
            Some(Hash32([0xAB; 32]))
        );
        assert!(adapter.resolve_path("/missing").is_none());
    }

    #[test]
    fn load_manifest_returns_none_without_wasm_or_overrides() {
        let state = State::new();
        let adapter = PtbChainAdapter::new(&state, 0);
        assert!(adapter.load_manifest(&Hash32([0u8; 32])).is_none());
    }

    #[test]
    fn load_manifest_returns_from_overrides_when_present() {
        let state = State::new();
        let mut overrides = HashMap::new();
        overrides.insert(
            Hash32([7u8; 32]),
            PetalManifestStub {
                module_path: "/test/petal".to_string(),
                ..Default::default()
            },
        );
        let adapter = PtbChainAdapter::with_overrides(&state, 0, &overrides);
        let m = adapter.load_manifest(&Hash32([7u8; 32])).unwrap();
        assert_eq!(m.module_path, "/test/petal");
        assert!(adapter.load_manifest(&Hash32([0u8; 32])).is_none());
    }

    #[test]
    fn load_manifest_parses_wasm_custom_section() {
        use bloom_petal_manifest::codec;
        use bloom_petal_manifest::types::{PetalManifest, SCHEMA_VERSION, SemVer};

        // Build a minimal wasm with a `bloom_petal_manifest` section.
        let manifest = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/bloom/test/petal".into(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        };
        let manifest_bytes = codec::encode(&manifest).unwrap();
        let wasm = wasm_with_custom("bloom_petal_manifest", &manifest_bytes);

        let mut state = State::new();
        let hash = state.insert_code(&wasm);

        let adapter = PtbChainAdapter::new(&state, 0);
        let stub = adapter
            .load_manifest(&hash)
            .expect("manifest must decode from wasm custom section");
        assert_eq!(stub.module_path, "/bloom/test/petal");
    }

    #[test]
    fn load_manifest_caches_repeated_lookups() {
        // Ensures the adapter only parses each wasm once across multiple
        // load_manifest calls for the same hash.
        use bloom_petal_manifest::codec;
        use bloom_petal_manifest::types::{PetalManifest, SCHEMA_VERSION, SemVer};

        let manifest = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/bloom/test/petal".into(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        };
        let manifest_bytes = codec::encode(&manifest).unwrap();
        let wasm = wasm_with_custom("bloom_petal_manifest", &manifest_bytes);

        let mut state = State::new();
        let hash = state.insert_code(&wasm);

        let adapter = PtbChainAdapter::new(&state, 0);
        for _ in 0..3 {
            let stub = adapter.load_manifest(&hash).unwrap();
            assert_eq!(stub.module_path, "/bloom/test/petal");
        }
        // Cache hit semantics: at minimum verify the entry is present.
        assert!(adapter.manifest_cache.borrow().contains_key(&hash));
    }

    #[test]
    fn overrides_win_over_wasm_section() {
        use bloom_petal_manifest::codec;
        use bloom_petal_manifest::types::{PetalManifest, SCHEMA_VERSION, SemVer};

        let real = PetalManifest {
            schema_version: SCHEMA_VERSION,
            module_path: "/wasm/path".into(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        };
        let wasm = wasm_with_custom("bloom_petal_manifest", &codec::encode(&real).unwrap());

        let mut state = State::new();
        let hash = state.insert_code(&wasm);

        let mut overrides = HashMap::new();
        overrides.insert(
            hash,
            PetalManifestStub {
                module_path: "/override/path".into(),
                ..Default::default()
            },
        );

        let adapter = PtbChainAdapter::with_overrides(&state, 0, &overrides);
        let stub = adapter.load_manifest(&hash).unwrap();
        assert_eq!(stub.module_path, "/override/path");
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

    /// Build a minimal wasm with a custom section. Hand-emit the header
    /// + LEB-encoded section so we don't need a wasm-building dep.
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
            } else {
                out.push(b | 0x80);
            }
        }
    }
}
