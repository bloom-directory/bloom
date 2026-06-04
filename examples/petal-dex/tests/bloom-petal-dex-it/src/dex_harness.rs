//! Shared test harness for `bloom-petal-dex-it` integration tests.
//!
//! Adapted from `bloom-petal-it/src/harness.rs` and specialised for the DEX
//! scenario (pool / cpmm / router petals).
//!
//! Provides:
//! - [`build_state`] — produce a fresh `State` with N pre-funded accounts.
//! - [`submit_ptb`] — drive a `PtbTx` through `ChainPetalExecutorWithManifests`
//!   and apply the write set on success.
//! - [`seed_coin`] / [`genesis_coin_id`] — lower-level object seeding helpers.
//! - [`wat_to_wasm`] — convert WAT source to wasm bytes.
//! - [`manifest_nullary`] / [`single_manifest`] — manifest builder helpers.
//! - [`addr`] — deterministic `Address` from a seed byte.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command as OsCommand;
use std::sync::{Mutex, OnceLock};

use bloom_chain_node::{
    consensus_driver::{ExecOutput, PetalExecutor},
    petal_executor::ChainPetalExecutorWithManifests,
};
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{
    AccessMode, OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey, TypeTag,
};
use bloom_petal_fungible::ops::{
    coin_payload, decode_coin_value as fungible_decode_coin_value, type_tag_coin_loom,
};
use bloom_resource::BloomType;
use bloom_script::{
    Arg, CORE_FUNGIBLE_PATH, Command, DEFAULT_FUNGIBLE_PETAL_HASH, ExpectedVersion,
    FunctionDeclStub, MoveCmd, PetalManifestStub, PetalRef, PqSignature, UseRef, encode_ptb,
    types::PtbTx,
};

// ---------------------------------------------------------------------------
// Coin payload helpers
// ---------------------------------------------------------------------------

/// Canonical 16-byte coin payload: `[value BE (16)]`.
/// Delegates to `bloom_petal_fungible::ops::coin_payload`.
pub fn ptb_coin_payload(value: u128) -> Vec<u8> {
    coin_payload(value)
}

/// Decode the value from a canonical 16-byte coin payload.
/// Returns 0 on malformed input (test-harness convenience).
pub fn ptb_decode_coin_value(payload: &[u8]) -> u128 {
    fungible_decode_coin_value(payload).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// State seeding
// ---------------------------------------------------------------------------

/// Build a fresh `State` with each `(address, balance)` allocation:
/// 1. A `Coin<LOOM>` object with a deterministic id owned by the address.
/// 2. The `OwnershipIndex` updated to list the coin.
pub fn build_state(allocations: &[(Address, u128)]) -> State {
    let mut state = State::new();
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    let coin_type = type_tag_coin_loom();

    for (idx, (addr, balance)) in allocations.iter().enumerate() {
        let coin_id = genesis_coin_id(*addr, idx);

        let obj = Object {
            id: coin_id,
            type_tag: coin_type.clone(),
            owner: Owner::Address(addr.0),
            version: 0,
            payload: coin_payload(*balance),
        };
        state.set_object(obj.clone());

        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: addr.0,
        };
        let mut owned = state.get_ownership(&okey).unwrap_or_default();
        let pos = owned.partition_point(|id| id.0 < coin_id.0);
        owned.insert(pos, coin_id);
        state.set_ownership(okey, owned);
    }

    state
}

/// Derive a deterministic `ObjectId` for genesis-seeded `Coin<LOOM>` objects.
///
/// `blake3("bloom-petal-dex-it.genesis" || addr || idx_le32)`
pub fn genesis_coin_id(addr: Address, idx: usize) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-petal-dex-it.genesis");
    h.update(&addr.0);
    h.update(&(idx as u32).to_le_bytes());
    ObjectId(*h.finalize().as_bytes())
}

/// Insert a `Coin<LOOM>` object directly into `state` with a custom id.
pub fn seed_coin(state: &mut State, id: ObjectId, owner: Address, value: u128) {
    let obj = Object {
        id,
        type_tag: type_tag_coin_loom(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(value),
    };
    state.set_object(obj.clone());

    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    let pos = owned.partition_point(|id| id.0 < obj.id.0);
    owned.insert(pos, obj.id);
    state.set_ownership(okey, owned);
}

// ---------------------------------------------------------------------------
// PTB submission
// ---------------------------------------------------------------------------

/// Wrap `ptb` as a `TxKind::SubmitPtb` transaction, drive it through
/// the `ChainPetalExecutorWithManifests` executor with an **empty**
/// override map (so `PtbChainAdapter::load_manifest` falls through to
/// the wasm custom-section path — the production manifest source —
/// for every petal hash), apply the write set on success, and return
/// the `ExecOutput`.
///
/// See `bloom-petal-it`'s `submit_ptb_chain_auth` doc-comment for
/// rationale; this is a verbatim DEX-side mirror.
pub fn submit_ptb_chain_auth(state: &mut State, sender: Address, ptb: PtbTx) -> ExecOutput {
    submit_ptb(state, sender, ptb, HashMap::new())
}

/// Wrap `ptb` as a `TxKind::SubmitPtb` transaction, drive it through
/// `ChainPetalExecutorWithManifests`, **apply the write set on success**,
/// and return the `ExecOutput`.
pub fn submit_ptb(
    state: &mut State,
    sender: Address,
    ptb: PtbTx,
    manifests: HashMap<Hash32, PetalManifestStub>,
) -> ExecOutput {
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encode must not fail in harness");
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 0,
        max_fuel: 1_000_000,
        fee_per_unit: 0,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    };

    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    if out.success
        && let Some(ws) = out.write_set.clone()
    {
        state
            .apply(ws)
            .expect("apply write_set must not fail in harness");
    }

    out
}

// ---------------------------------------------------------------------------
// WAT helpers
// ---------------------------------------------------------------------------

/// Parse a WAT source string into wasm bytes. Panics on malformed WAT.
pub fn wat_to_wasm(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Append a `bloom_petal_manifest_v0` custom section carrying
/// `manifest_bytes` to `wasm`. See [`crate::dex_harness`] / the
/// `bloom-petal-it` mirror for the rationale: this pairs a real,
/// chain-authoritative manifest (as the macro emits into the wasm
/// custom section) with a hand-written WAT body so tests don't need
/// `wasm32-unknown-unknown` at compile time.
pub fn append_manifest_section(mut wasm: Vec<u8>, manifest_bytes: &[u8]) -> Vec<u8> {
    let name = "bloom_petal_manifest_v0";
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(manifest_bytes);
    wasm.push(0x00);
    leb128(&mut wasm, body.len() as u64);
    wasm.extend_from_slice(&body);
    wasm
}

/// Convenience: compile `wat_src` and append the
/// `bloom_petal_manifest_v0` custom section in one call.
pub fn wrap_with_real_manifest(wat_src: &str, manifest_bytes: &[u8]) -> Vec<u8> {
    let base = wat_to_wasm(wat_src);
    append_manifest_section(base, manifest_bytes)
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

/// The canonical-encoded `PetalManifestV0` bytes embedded in the real
/// `/bloom/petals/core/fungible` petal.
pub fn real_fungible_manifest_bytes() -> &'static [u8] {
    bloom_petal_fungible::fungible::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/petals/dex/pool` petal.
pub fn real_pool_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_pool::pool::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/petals/dex/wallet` petal.
pub fn real_wallet_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_wallet::wallet::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/petals/dex/strategy/cpmm` petal.
pub fn real_cpmm_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_cpmm::cpmm::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/petals/dex/router` petal.
pub fn real_router_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_router::router::__bloom_manifest_bytes()
}

// ---------------------------------------------------------------------------
// Manifest helpers
// ---------------------------------------------------------------------------

/// Build a `PetalManifestStub` declaring a single zero-arg, zero-return
/// `__petal_<fn_name>` function.
pub fn manifest_nullary(fn_name: &str) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/dex/petal-it".to_string(),
        functions: vec![FunctionDeclStub {
            view: false,
            name: fn_name.to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        }],
        ..Default::default()
    }
}

/// Build a one-entry manifest registry for a single petal.
pub fn single_manifest(hash: Hash32, fn_name: &str) -> HashMap<Hash32, PetalManifestStub> {
    let mut m = HashMap::new();
    m.insert(hash, manifest_nullary(fn_name));
    m
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Build a deterministic `Address` from a single seed byte.
pub fn addr(b: u8) -> Address {
    Address([b; 32])
}

// ---------------------------------------------------------------------------
// Real-wasm DEX helpers (shared by `real_wasm_pool.rs` and `pipe_litmus.rs`).
//
// These compile the real `bloom-petal-dex-pool` / `bloom-petal-dex-wallet`
// crates to `wasm32-unknown-unknown` and seed the type-erased coins the pool
// declares. `#[ignore]`-gated callers run them with `-- --ignored` (CI has no
// wasm32 target). Promoted out of `real_wasm_pool.rs` so the Phase F litmus
// builds on the same proven foundation.
// ---------------------------------------------------------------------------

static WASM_ARTIFACT_CACHE: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();

/// Build or resolve a workspace crate's `wasm32-unknown-unknown` release
/// artifact (default features — i.e. *with* the `__petal_*` entrypoints).
///
/// Resolution order:
/// 1. An explicit per-petal env var such as `BLOOM_PETAL_DEX_POOL_WASM`.
/// 2. `BLOOM_PETAL_DEX_WASM_DIR/<artifact>.wasm`.
/// 3. `BLOOM_DOCKER_PREBUILT_WASM_DIR/<artifact>.wasm`.
/// 4. A cached fallback `cargo build --release --target wasm32-unknown-unknown`.
///
/// For admin-specific faucet builds, shared directory lookup is only used for
/// the harness's default PTB signer admin. Custom-admin tests must either set
/// `BLOOM_PETAL_DEX_FAUCET_WASM` explicitly or fall back to Cargo.
fn build_petal_wasm_with_env(
    crate_name: &str,
    artifact_stem: &str,
    envs: &[(&str, String)],
) -> PathBuf {
    let cache_key = wasm_cache_key(crate_name, artifact_stem, envs);
    let cache = WASM_ARTIFACT_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("wasm artifact cache poisoned");

    if let Some(cached) = cache.get(&cache_key) {
        return cached.clone();
    }

    if let Some(prebuilt) = prebuilt_wasm_path(artifact_stem, envs) {
        cache.insert(cache_key, prebuilt.clone());
        return prebuilt;
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut cmd = OsCommand::new(env!("CARGO"));
    cmd.args([
        "build",
        "--release",
        "-p",
        crate_name,
        "--target",
        "wasm32-unknown-unknown",
    ])
    .current_dir(manifest_dir);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn cargo build for {crate_name}: {e}"));
    assert!(status.success(), "wasm32 build of {crate_name} failed");

    // Walk up to the workspace root (this crate is
    // examples/petal-dex/tests/bloom-petal-dex-it).
    let workspace_root = PathBuf::from(manifest_dir)
        .ancestors()
        .nth(4)
        .expect("workspace root four levels above the it crate")
        .to_path_buf();
    let artifact = workspace_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{artifact_stem}.wasm"));
    assert!(
        artifact.exists(),
        "expected wasm artifact at {}",
        artifact.display()
    );
    cache.insert(cache_key, artifact.clone());
    artifact
}

fn wasm_cache_key(crate_name: &str, artifact_stem: &str, envs: &[(&str, String)]) -> String {
    let mut key = format!("{crate_name}:{artifact_stem}");
    for (name, value) in envs {
        key.push('|');
        key.push_str(name);
        key.push('=');
        key.push_str(value);
    }
    key
}

fn prebuilt_wasm_path(artifact_stem: &str, envs: &[(&str, String)]) -> Option<PathBuf> {
    for env_key in prebuilt_wasm_env_keys(artifact_stem) {
        if let Some(path) = existing_wasm_path_from_env(env_key) {
            return Some(path);
        }
    }

    if !shared_wasm_dir_allowed(artifact_stem, envs) {
        return None;
    }

    for env_key in ["BLOOM_PETAL_DEX_WASM_DIR", "BLOOM_DOCKER_PREBUILT_WASM_DIR"] {
        let Ok(dir) = std::env::var(env_key) else {
            continue;
        };
        let path = PathBuf::from(dir).join(format!("{artifact_stem}.wasm"));
        assert!(
            path.is_file(),
            "{env_key} is set but {} does not exist",
            path.display()
        );
        return Some(path);
    }

    None
}

fn prebuilt_wasm_env_keys(artifact_stem: &str) -> &'static [&'static str] {
    match artifact_stem {
        "bloom_petal_dex_pool" => &["BLOOM_PETAL_DEX_POOL_WASM"],
        "bloom_petal_dex_wallet" => &["BLOOM_PETAL_DEX_WALLET_WASM"],
        "bloom_petal_dex_faucet" => &["BLOOM_PETAL_DEX_FAUCET_WASM"],
        "bloom_petal_dex_router" => &["BLOOM_PETAL_DEX_ROUTER_WASM"],
        "bloom_petal_dex_cpmm" => &["BLOOM_PETAL_DEX_CPMM_WASM"],
        _ => &[],
    }
}

fn existing_wasm_path_from_env(env_key: &str) -> Option<PathBuf> {
    let Ok(raw) = std::env::var(env_key) else {
        return None;
    };
    let path = PathBuf::from(raw);
    assert!(
        path.is_file(),
        "{env_key} is set but {} does not exist",
        path.display()
    );
    Some(path)
}

fn shared_wasm_dir_allowed(artifact_stem: &str, envs: &[(&str, String)]) -> bool {
    if artifact_stem != "bloom_petal_dex_faucet" {
        return envs.is_empty();
    }

    matches!(
        envs,
        [("BLOOM_DEX_FAUCET_ADMIN_HEX", admin_hex)] if admin_hex == &ptb_signer_pubkey_hex()
    )
}

fn build_petal_wasm(crate_name: &str, artifact_stem: &str) -> PathBuf {
    build_petal_wasm_with_env(crate_name, artifact_stem, &[])
}

/// Build `bloom-petal-dex-pool` for `wasm32-unknown-unknown`; returns the
/// artifact path.
pub fn build_pool_wasm() -> PathBuf {
    build_petal_wasm("bloom-petal-dex-pool", "bloom_petal_dex_pool")
}

/// Build `bloom-petal-dex-wallet` for `wasm32-unknown-unknown`; returns the
/// artifact path.
pub fn build_wallet_wasm() -> PathBuf {
    build_petal_wasm("bloom-petal-dex-wallet", "bloom_petal_dex_wallet")
}

/// Build `bloom-petal-dex-faucet` for `wasm32-unknown-unknown`; returns the
/// artifact path. The faucet's `mint(value) -> Coin<Erased>` is the on-chain
/// analog of [`seed_erased_coin`]: it provisions the type-erased coins the
/// pool's `create_pool` / `swap_exact_in` consume, on a chain where genesis
/// only emits `Coin<LOOM>` (the live-docker provisioning linchpin).
pub fn build_faucet_wasm() -> PathBuf {
    build_faucet_wasm_for_admin(ptb_signer_pubkey_hex())
}

pub fn build_faucet_wasm_for_admin(admin_hex: String) -> PathBuf {
    build_petal_wasm_with_env(
        "bloom-petal-dex-faucet",
        "bloom_petal_dex_faucet",
        &[("BLOOM_DEX_FAUCET_ADMIN_HEX", admin_hex)],
    )
}

/// Build `bloom-petal-dex-router` for `wasm32-unknown-unknown`; returns the
/// artifact path.
pub fn build_router_wasm() -> PathBuf {
    build_petal_wasm("bloom-petal-dex-router", "bloom_petal_dex_router")
}

/// Build `bloom-petal-dex-cpmm` for `wasm32-unknown-unknown`; returns the
/// artifact path.
pub fn build_cpmm_wasm() -> PathBuf {
    build_petal_wasm("bloom-petal-dex-cpmm", "bloom_petal_dex_cpmm")
}

// ---------------------------------------------------------------------------
// Live-chain inner-PTB xDSA signer (used by `docker_petal_dex.rs`).
//
// On a live 4-validator network the inner PTB is verified with the production
// xDSA verifier, so the docker driver must xDSA-sign each PTB over
// `ptb.signing_digest()`. The signer is deterministic so the genesis
// allocation and key-registry entry agree with this Rust driver.
// ---------------------------------------------------------------------------

/// Fixed 64-byte xDSA secret-key bytes (`mldsa_seed || ed25519_seed`) for the
/// inner-PTB signer. Test-only; never use this key outside the docker harness.
pub const PTB_SIGNER_SECRET_BYTES: [u8; 64] = [0x42; 64];

/// The deterministic xDSA signing key for inner PTBs.
pub fn ptb_signer_keypair() -> bloom_keystore::xdsa::XdsaSecretKey {
    bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&PTB_SIGNER_SECRET_BYTES)
        .expect("fixed PTB signer secret bytes are valid")
}

/// The full composite xDSA public key for the inner-PTB signer.
pub fn ptb_signer_xdsa_pubkey() -> bloom_keystore::xdsa::XdsaPublicKey {
    ptb_signer_keypair().public_key()
}

/// The 32-byte address for the inner-PTB signer.
pub fn ptb_signer_pubkey() -> [u8; 32] {
    bloom_chain_types::types::Address::from_pubkey_bytes(&ptb_signer_xdsa_pubkey().0).0
}

/// Lower-hex of [`ptb_signer_pubkey`] — the genesis allocation `address` and
/// the `owner_addr` the driver discovers the gas Coin<LOOM> under.
pub fn ptb_signer_pubkey_hex() -> String {
    hex::encode(ptb_signer_pubkey())
}

/// xDSA-sign `ptb` over its `signing_digest()`, installing the composite
/// signature into `ptb.signatures[0]` and the signer address into
/// `ptb.signers[0]`. Returns the `encode_ptb` bytes ready to be written to a
/// file for `bloom chain submit-ptb --ptb-file`.
pub fn sign_and_encode_ptb(mut ptb: PtbTx) -> Vec<u8> {
    let sk = ptb_signer_keypair();
    ptb.signers = vec![ptb_signer_pubkey()];
    let digest = ptb.signing_digest();
    let sig = sk.sign(&digest);
    ptb.signatures = vec![PqSignature(sig.to_bytes())];
    encode_ptb(&ptb).expect("encode signed PTB")
}

/// Compute the `blake3_tagged(PETAL, wasm)` petal hash host-side — the same
/// content hash the chain's `state.insert_code` / `Deploy` apply path derives
/// (see `bloom_chain_state::code_store` + `petal_executor.rs` Deploy arm). The
/// driver feeds this into each `PetalRef { hash: Some(..) }`.
pub fn petal_hash_of(wasm: &[u8]) -> Hash32 {
    bloom_chain_types::digest::blake3_tagged(bloom_chain_types::digest::tags::PETAL, wasm)
}

/// `TypeTag` for `Coin<Erased>` with the zero-`petal_hash` sentinel — the
/// on-chain shape the pool's `create_pool` / `swap_exact_in` declare for
/// their coin args (token identity rides on the tag, erased to `Erased` for
/// the type-agnostic pool).
pub fn coin_erased_tag() -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "Coin".to_string(),
        type_args: vec![erased_type_tag()],
    }
}

/// `TypeTag` for the `Erased` marker used as the concrete type arg in
/// generic DEX entrypoints.
pub fn erased_type_tag() -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "Erased".to_string(),
        type_args: vec![],
    }
}

/// Type args for two-token pool calls over the demo erased coin type.
pub fn erased_pair_type_args() -> Vec<TypeTag> {
    vec![erased_type_tag(), erased_type_tag()]
}

/// `TypeTag` for `FaucetAdmin` with a zero-petal self sentinel.
pub fn faucet_admin_cap_tag() -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "FaucetAdmin".to_string(),
        type_args: vec![],
    }
}

/// Seed a `FaucetAdmin` capability object owned by `owner` at `id`.
pub fn seed_faucet_admin_cap(state: &mut State, id: ObjectId, owner: Address) {
    let obj = Object {
        id,
        type_tag: faucet_admin_cap_tag(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: bloom_petal_dex_faucet::ops::cap_payload(),
    };
    state.set_object(obj);

    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    let pos = owned.partition_point(|x| x.0 < id.0);
    owned.insert(pos, id);
    state.set_ownership(okey, owned);
}

/// Deterministic id for a test-seeded faucet admin cap.
pub fn faucet_admin_cap_id(seed: &[u8]) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"dex-it.faucet-admin-cap");
    h.update(seed);
    ObjectId(*h.finalize().as_bytes())
}

/// Seed a `Coin<Erased>(value)` object owned by `owner` at `id`.
pub fn seed_erased_coin(state: &mut State, id: ObjectId, owner: Owner, value: u128) {
    let obj = Object {
        id,
        type_tag: coin_erased_tag(),
        owner: owner.clone(),
        version: 0,
        payload: coin_payload(value),
    };
    state.set_object(obj);

    if let Owner::Address(a) = owner {
        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: a,
        };
        let mut owned = state.get_ownership(&okey).unwrap_or_default();
        let pos = owned.partition_point(|x| x.0 < id.0);
        owned.insert(pos, id);
        state.set_ownership(okey, owned);
    }
}

/// Deterministic id for a test-seeded erased coin, namespaced by `seed`.
pub fn erased_coin_id(seed: &[u8]) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"dex-it.erased-coin");
    h.update(seed);
    ObjectId(*h.finalize().as_bytes())
}

/// Find whether `who` owns a `Coin` (type_name == "Coin") whose decoded
/// value equals `want`. Used to assert a swap/settlement credited the
/// expected output coin to the right party.
pub fn owner_has_coin_worth(state: &State, who: Address, want: u128) -> bool {
    state.iter_objects().any(|(_, o)| {
        matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Coin")
            && o.owner == Owner::Address(who.0)
            && bloom_petal_fungible::ops::decode_coin_value(&o.payload).ok() == Some(want)
    })
}

/// Stand up a shared 10000/10000 `Pool` (at `fee_bps`) via the real pool wasm,
/// signed by `alice`, and return its `ObjectId`.
///
/// `disc` namespaces the two seeded deposit coins so callers can build
/// **multiple distinct pools** in one state (each pool consumes its own
/// pair of `Coin<Erased>` deposits — needed for the two-hop litmus 5.2).
/// The resulting `Pool` carries the real pool `petal_hash` (stamped by the
/// VM's `object.create` self-sentinel path), the production shape a swapper
/// references as a shared object.
///
/// `fee_bps` also serves as a *content discriminator*: the chain VM derives
/// a created object's `ObjectId` from `petal_hash + per-PTB-counter +
/// type_tag + payload` (`derive_create_id`), with **no** mix-in of the tx
/// digest. Two pools built in separate single-create PTBs with identical
/// reserves *and* identical fee therefore collide on the same id. Callers
/// that need two distinct pools in one state (litmus 5.2) pass distinct
/// `fee_bps` so the payloads — and hence the ids — differ.
pub fn create_shared_pool(
    state: &mut State,
    alice: Address,
    pool_petal_hash: Hash32,
    disc: &[u8],
    fee_bps: u16,
) -> ObjectId {
    let mut a_seed = b"pool-a:".to_vec();
    a_seed.extend_from_slice(disc);
    let mut b_seed = b"pool-b:".to_vec();
    b_seed.extend_from_slice(disc);
    let coin_a = erased_coin_id(&a_seed);
    let coin_b = erased_coin_id(&b_seed);
    seed_erased_coin(state, coin_a, Owner::Address(alice.0), 10_000);
    seed_erased_coin(state, coin_b, Owner::Address(alice.0), 10_000);

    // Snapshot existing Pool ids so we can identify the *new* one after the
    // create (multiple pools in one state all start at 10000/10000, so we
    // cannot disambiguate by reserves alone — litmus 5.2 builds two).
    let before: std::collections::HashSet<ObjectId> = state
        .iter_objects()
        .filter(|(_, o)| {
            matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Pool")
        })
        .map(|(id, _)| *id)
        .collect();

    let params_bytes = fee_bps.to_be_bytes().to_vec().canonical_encode();
    let gas_payer = genesis_coin_id(alice, 0);
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "create_pool".to_string(),
                type_args: vec![erased_type_tag(), erased_type_tag()],
                args: vec![
                    Arg::Object {
                        id: coin_a,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: coin_b,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(params_bytes),
                ],
            }),
            // Share the Pool (return slot 0) so anyone can swap against it.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            // Give the LpPosition (return slot 1) to alice.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(alice.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(state, alice, ptb);
    assert!(
        out.success,
        "create_shared_pool({disc:?}) must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // Return the Pool id that did not exist before this create.
    let (id, _) = state
        .iter_objects()
        .find(|(id, o)| {
            matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Pool")
                && !before.contains(id)
        })
        .expect("a fresh Pool object must exist after create_pool");
    *id
}

#[cfg(test)]
mod ptb_signer_tests {
    use super::*;

    /// Prints the deterministic inner-PTB signer address hex.
    #[test]
    fn prints_ptb_signer_pubkey_hex() {
        println!("PTB_SIGNER_PK_HEX={}", ptb_signer_pubkey_hex());
        // Sanity: deterministic + 64 hex chars.
        assert_eq!(ptb_signer_pubkey_hex().len(), 64);
        assert_eq!(ptb_signer_pubkey_hex(), ptb_signer_pubkey_hex());
    }

    #[test]
    fn prints_ptb_signer_registry_entry() {
        use base64::Engine as _;
        println!("PTB_SIGNER_PK_HEX={}", ptb_signer_pubkey_hex());
        println!(
            "PTB_SIGNER_PUBKEY_B64={}",
            base64::engine::general_purpose::STANDARD.encode(ptb_signer_xdsa_pubkey().0)
        );
    }
}
