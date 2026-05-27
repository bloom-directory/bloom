//! Genesis file parsing (spec §5.4, §14).
//!
//! Parses `<bloom_home>/chain/genesis.toml` into a `Genesis` struct, builds
//! the initial `ValidatorSet`, applies genesis allocations to the accounts trie,
//! and computes the genesis hash.
//!
//! # Genesis TOML format
//!
//! ```toml
//! chain_id = "bloomchain.v0"
//! genesis_time_ms = 1747526400000
//!
//! [[validators]]
//! address = "b1abcd...wxyz"
//! pubkey  = "<base64 composite pubkey>"
//! voting_power = 100
//! # host = "127.0.0.1:26656"   (optional — required for run-validator)
//!
//! [[allocations]]
//! address = "b1dev1...0001"
//! amount  = "1000000000000000000000"
//!
//! [[petals]]
//! path = "/bloom/dex/pool"
//! wasm_hex = "<hex-encoded wasm bytes>"
//!
//! [[key_registry]]
//! address = "b1abcd...wxyz"
//! pubkey  = "<base64 composite pubkey>"
//! ```

use std::path::Path;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use bloom_chain_consensus::ValidatorSet;
use bloom_chain_consensus::validator_set::Validator;
use bloom_chain_state::{Account, State};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes};
use bloom_keystore::xdsa::XDSA_PK_LEN;
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::coin_payload;
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};
use serde::{Deserialize, Serialize};

use crate::error::NodeError;

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

/// Raw TOML representation of a validator entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Display address (b1-prefixed base32, 32-byte payload).
    pub address: String,
    /// Base64-encoded composite public key (1984 bytes).
    pub pubkey: String,
    /// Voting power (u64).
    pub voting_power: u64,
    /// `host:port` for TCP peering.  Required for run-validator; optional in
    /// genesis-only contexts.
    pub host: Option<String>,
}

/// Raw TOML representation of a genesis allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// b1-prefixed address.
    pub address: String,
    /// LOOM amount in bloomweis (string to avoid u128 precision loss in TOML).
    pub amount: String,
}

/// Raw TOML representation of a petal installed at genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisPetal {
    /// VFS module path exposed by the petal's manifest.
    pub path: String,
    /// Hex-encoded wasm bytes.
    pub wasm_hex: String,
}

/// Raw TOML representation of an xDSA key-registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisKeyRegistryEntry {
    /// b1-prefixed address derived from `pubkey`.
    pub address: String,
    /// Base64-encoded composite public key (1984 bytes).
    pub pubkey: String,
}

/// Parsed genesis file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisFile {
    pub chain_id: String,
    pub genesis_time_ms: u64,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub petals: Vec<GenesisPetal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_registry: Vec<GenesisKeyRegistryEntry>,
}

// ---------------------------------------------------------------------------
// Validated Genesis
// ---------------------------------------------------------------------------

/// Fully validated genesis data.
///
/// Produced by [`Genesis::from_file`].
#[derive(Debug, Clone)]
pub struct Genesis {
    pub chain_id: String,
    pub genesis_time_ms: u64,
    pub validator_set: ValidatorSet,
    /// Peers addresses `host:port` indexed by validator address bytes.
    pub peer_addrs: Vec<String>,
    pub allocations: Vec<(Address, u128)>,
    pub petals: Vec<(String, Vec<u8>)>,
    pub key_registry: Vec<(Address, PubKeyBytes)>,
    /// Genesis hash: `blake3("bloom-chain.v0.genesis:" || ssz(chain_id_bytes || genesis_time_ms))`.
    pub genesis_hash: Hash32,
}

impl Genesis {
    /// Parse and validate a genesis TOML file.
    pub fn from_file(path: &Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Genesis(format!("read {}: {e}", path.display())))?;
        let raw: GenesisFile = toml::from_str(&text)
            .map_err(|e| NodeError::Genesis(format!("parse genesis.toml: {e}")))?;
        Self::from_raw(raw)
    }

    /// Construct from a parsed [`GenesisFile`].
    pub fn from_raw(raw: GenesisFile) -> Result<Self, NodeError> {
        // Parse validators.
        let mut validators: Vec<Validator> = Vec::new();
        let mut peer_addrs: Vec<String> = Vec::new();

        for v in &raw.validators {
            let addr = parse_b1_address(&v.address)
                .map_err(|e| NodeError::Genesis(format!("validator address: {e}")))?;
            let pk_bytes = base64_decode(&v.pubkey)
                .map_err(|e| NodeError::Genesis(format!("validator pubkey: {e}")))?;
            let derived = Address::from_pubkey_bytes(&pk_bytes);
            if addr != derived {
                return Err(NodeError::Genesis(format!(
                    "validator address/pubkey mismatch: address {} derives {} from pubkey",
                    hex::encode(addr.0),
                    hex::encode(derived.0)
                )));
            }
            validators.push(Validator {
                address: addr,
                pubkey: PubKeyBytes(pk_bytes),
                voting_power: v.voting_power,
            });
            if let Some(host) = &v.host {
                peer_addrs.push(host.clone());
            }
        }

        if validators.is_empty() {
            return Err(NodeError::Genesis(
                "genesis must have at least one validator".into(),
            ));
        }

        let validator_set = ValidatorSet::new(validators)
            .map_err(|e| NodeError::Genesis(format!("validator set: {e}")))?;

        let mut key_registry: Vec<(Address, PubKeyBytes)> = validator_set
            .validators()
            .iter()
            .map(|v| (v.address, v.pubkey.clone()))
            .collect();

        // Parse allocations.
        let mut allocations: Vec<(Address, u128)> = Vec::new();
        for alloc in &raw.allocations {
            let addr = parse_b1_address(&alloc.address)
                .map_err(|e| NodeError::Genesis(format!("allocation address: {e}")))?;
            let amount: u128 = alloc.amount.parse().map_err(|e| {
                NodeError::Genesis(format!("allocation amount '{}': {e}", alloc.amount))
            })?;
            allocations.push((addr, amount));
        }

        // Parse genesis-installed petals.
        let mut petals: Vec<(String, Vec<u8>)> = Vec::new();
        for petal in &raw.petals {
            if !petal.path.starts_with('/') {
                return Err(NodeError::Genesis(format!(
                    "petal path must be absolute: {:?}",
                    petal.path
                )));
            }
            let wasm = hex::decode(&petal.wasm_hex)
                .map_err(|e| NodeError::Genesis(format!("petal wasm_hex: {e}")))?;
            if wasm.is_empty() {
                return Err(NodeError::Genesis(format!(
                    "petal {} has empty wasm_hex",
                    petal.path
                )));
            }
            petals.push((petal.path.clone(), wasm));
        }

        for entry in &raw.key_registry {
            let addr = parse_b1_address(&entry.address)
                .map_err(|e| NodeError::Genesis(format!("key_registry address: {e}")))?;
            let pk_bytes = base64_decode(&entry.pubkey)
                .map_err(|e| NodeError::Genesis(format!("key_registry pubkey: {e}")))?;
            let derived = Address::from_pubkey_bytes(&pk_bytes);
            if addr != derived {
                return Err(NodeError::Genesis(format!(
                    "key_registry address/pubkey mismatch: address {} derives {} from pubkey",
                    hex::encode(addr.0),
                    hex::encode(derived.0)
                )));
            }
            key_registry.push((addr, PubKeyBytes(pk_bytes)));
        }

        // Genesis hash.
        let genesis_hash = compute_genesis_hash(&raw.chain_id, raw.genesis_time_ms);

        Ok(Genesis {
            chain_id: raw.chain_id,
            genesis_time_ms: raw.genesis_time_ms,
            validator_set,
            peer_addrs,
            allocations,
            petals,
            key_registry,
            genesis_hash,
        })
    }

    /// Apply allocations to an empty `State`, producing the genesis state.
    ///
    /// For each allocation this method:
    /// 1. Writes `Account.loom = amount` (the derived cache, spec §9.2).
    /// 2. Emits a `Coin<LOOM>` object with a deterministic `ObjectId`
    ///    and transfers it to the recipient (equivalent to what running
    ///    `bloom_petal_fungible::ops::mint_genesis` on-chain would produce,
    ///    but written directly to avoid running wasm at genesis).
    ///
    /// `ObjectId` derivation (one deterministic id per allocation):
    /// `blake3("bloom.genesis.loom" || genesis_hash || idx_le32)`
    ///
    /// // EpochZero is implicit at genesis: the linear cap is consumed by
    /// // this genesis pipeline, not by an on-chain wasm call.
    pub fn apply_to_state(&self, state: &mut State) {
        for (addr, pubkey) in &self.key_registry {
            state.register_pubkey(*addr, pubkey.clone());
        }

        for (path, wasm) in &self.petals {
            let hash = state.insert_code(wasm);
            state.set_vfs_binding(path.clone(), hash);
        }

        let fungible_petal_hash = state
            .vfs_lookup(CORE_FUNGIBLE_PATH)
            .unwrap_or(DEFAULT_FUNGIBLE_PETAL_HASH);
        let coin_type = loom_coin_type_tag(fungible_petal_hash);

        for (idx, (addr, amount)) in self.allocations.iter().enumerate() {
            // ── 1. Account.loom cache (spec §9.2) ─────────────────────────
            let acct = Account {
                nonce: 0,
                loom: *amount,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            };
            state.set_account(*addr, acct);

            // ── 2. Coin<LOOM> object ───────────────────────────────────────
            //
            // Derive a deterministic ObjectId:
            // blake3("bloom.genesis.loom" || genesis_hash_bytes || idx_le32)
            let coin_id = {
                let mut h = blake3::Hasher::new();
                h.update(b"bloom.genesis.loom");
                h.update(&self.genesis_hash.0);
                h.update(&(idx as u32).to_le_bytes());
                ObjectId(*h.finalize().as_bytes())
            };

            let owner = Owner::Address(addr.0);
            let obj = Object {
                id: coin_id,
                type_tag: coin_type.clone(),
                owner: owner.clone(),
                version: 0,
                // coin_payload encodes ObjectId([0;32]) placeholder + u128 value
                payload: coin_payload(*amount),
            };
            state.set_object(obj);

            // Update the OwnershipIndex for this recipient.
            let okey = OwnershipIndexKey {
                owner_kind: OWNER_KIND_ADDRESS,
                owner_id: addr.0,
            };
            let mut owned = state.get_ownership(&okey).unwrap_or_default();
            // Insert coin_id maintaining sorted order.
            let pos = owned.partition_point(|id| id.0 < coin_id.0);
            owned.insert(pos, coin_id);
            state.set_ownership(okey, owned);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a `b1`-prefixed base32 address into a 32-byte `Address`.
///
/// v0 tolerance: if the string is exactly 64 hex chars, accept it as hex too
/// (useful in dev / test contexts before the display format is finalised).
pub fn parse_b1_address(s: &str) -> Result<Address> {
    // Allow raw hex for dev convenience.
    if s.len() == 64
        && let Ok(bytes) = hex::decode(s)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Address(arr));
    }

    // Strip b1 prefix.
    let rest = s
        .strip_prefix("b1")
        .ok_or_else(|| anyhow!("address must start with 'b1': {s:?}"))?;

    // Remove last 4-char checksum.
    if rest.len() < 4 {
        return Err(anyhow!("address too short: {s:?}"));
    }
    let (payload_b32, _checksum) = rest.split_at(rest.len() - 4);

    // Decode base32 (RFC 4648 lower, no padding).
    // Use zbase32's decode_full_bytes_str helper (same as bloom-chain-types uses).
    let bytes =
        zbase32::decode_full_bytes_str(payload_b32).map_err(|e| anyhow!("base32 decode: {e}"))?;

    if bytes.len() != 32 {
        return Err(anyhow!(
            "address payload must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Address(arr))
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("strict base64 decode: {e}"))?;
    if bytes.len() != XDSA_PK_LEN {
        return Err(anyhow!(
            "xDSA pubkey must be {XDSA_PK_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn compute_genesis_hash(chain_id: &str, genesis_time_ms: u64) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom-chain.v0.genesis:");
    hasher.update(chain_id.as_bytes());
    hasher.update(b":");
    hasher.update(&genesis_time_ms.to_be_bytes());
    let out = *hasher.finalize().as_bytes();
    Hash32(out)
}

fn is_false(value: &bool) -> bool {
    !*value
}

// ---------------------------------------------------------------------------
// Skeleton config.toml schema (for `chain init`)
// ---------------------------------------------------------------------------

/// Node config written to `<bloom_home>/chain/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// b1-prefixed address of the local validator key.
    pub validator_address: String,
    /// TCP address to listen on for peer connections (host:port).
    pub listen_addr: String,
    /// Optional `host:port` for the JSON-RPC TCP listener. When set, the
    /// validator binds a TCP listener with the same line-delimited JSON-RPC 2.0
    /// framing as the UDS socket; both run in parallel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_tcp_addr: Option<String>,
    /// Allow `rpc_tcp_addr` to bind a non-loopback or wildcard interface.
    /// This is intentionally off by default; public RPC exposure is unauthenticated
    /// in v0 and should only be used inside controlled docker/private networks.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unsafe_rpc_public_bind: bool,
    /// Path to genesis file (default: `chain/genesis.toml`).
    pub genesis_path: Option<String>,
    /// Log level.
    pub log_level: Option<String>,
    /// Fuel limit per block.
    pub fuel_limit: Option<u64>,
    /// Wasmtime version string (pinned per epoch, spec §7.5).
    pub wasmtime_version: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            validator_address: String::new(),
            listen_addr: "0.0.0.0:26656".into(),
            rpc_tcp_addr: None,
            unsafe_rpc_public_bind: false,
            genesis_path: None,
            log_level: Some("info".into()),
            fuel_limit: Some(30_000_000),
            wasmtime_version: Some(env!("CARGO_PKG_VERSION").into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_consensus::ValidatorSet;
    use bloom_chain_consensus::validator_set::Validator;
    use bloom_chain_types::types::PubKeyBytes;
    use bloom_objects::{OWNER_KIND_ADDRESS, OwnershipIndexKey};
    use bloom_petal_fungible::ops::decode_coin_value;

    /// Build a minimal `Genesis` (no file I/O needed) with `n` allocations.
    fn make_genesis(allocations: Vec<([u8; 32], u128)>) -> Genesis {
        let pk = PubKeyBytes(vec![0u8; 1984]);
        let addr = Address([0xAAu8; 32]);
        let validator = Validator {
            address: addr,
            pubkey: pk.clone(),
            voting_power: 1,
        };
        let validator_set = ValidatorSet::new(vec![validator]).unwrap();

        let allocs: Vec<(Address, u128)> = allocations
            .into_iter()
            .map(|(a, v)| (Address(a), v))
            .collect();

        let genesis_hash = Hash32([0x42u8; 32]);
        Genesis {
            chain_id: "bloomchain.test".into(),
            genesis_time_ms: 0,
            validator_set,
            peer_addrs: vec![],
            allocations: allocs,
            petals: vec![],
            key_registry: vec![(addr, pk)],
            genesis_hash,
        }
    }

    fn genesis_coin_id(genesis: &Genesis, idx: usize) -> ObjectId {
        let mut h = blake3::Hasher::new();
        h.update(b"bloom.genesis.loom");
        h.update(&genesis.genesis_hash.0);
        h.update(&(idx as u32).to_le_bytes());
        ObjectId(*h.finalize().as_bytes())
    }

    #[test]
    fn genesis_emits_coin_loom_objects_for_each_allocation() {
        let addr_a = [0x01u8; 32];
        let addr_b = [0x02u8; 32];
        let addr_c = [0x03u8; 32];
        let amount_a: u128 = 1_000_000;
        let amount_b: u128 = 2_000_000;
        let amount_c: u128 = 3_000_000;

        let genesis = make_genesis(vec![
            (addr_a, amount_a),
            (addr_b, amount_b),
            (addr_c, amount_c),
        ]);

        let mut state = State::new();

        // TDD: run apply_to_state and assert expected state.
        genesis.apply_to_state(&mut state);

        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);

        for (idx, (raw_addr, expected_amount)) in
            [(addr_a, amount_a), (addr_b, amount_b), (addr_c, amount_c)]
                .iter()
                .enumerate()
        {
            let addr = Address(*raw_addr);

            // 1. Account.loom cache must still match the allocation amount.
            let acct = state.get_account(&addr).expect("account must exist");
            assert_eq!(
                acct.loom, *expected_amount,
                "Account.loom cache mismatch for idx {idx}"
            );

            // 2. A Coin<LOOM> object must exist with deterministic id.
            let coin_id = genesis_coin_id(&genesis, idx);

            let obj = state
                .get_object(&coin_id)
                .unwrap_or_else(|| panic!("Coin<LOOM> object missing for idx {idx}"));

            // 3. TypeTag must be Coin<LOOM>.
            assert_eq!(obj.type_tag, coin_type, "TypeTag mismatch for idx {idx}");

            // 4. Payload must decode to the expected value.
            let decoded_value = decode_coin_value(&obj.payload)
                .unwrap_or_else(|_| panic!("payload decode failed for idx {idx}"));
            assert_eq!(
                decoded_value, *expected_amount,
                "coin value mismatch for idx {idx}"
            );

            // 5. Ownership entry must resolve to Owner::Address(addr).
            assert_eq!(
                obj.owner,
                Owner::Address(*raw_addr),
                "owner mismatch for idx {idx}"
            );

            // 6. OwnershipIndex must contain the coin_id for this address.
            let okey = OwnershipIndexKey {
                owner_kind: OWNER_KIND_ADDRESS,
                owner_id: *raw_addr,
            };
            let owned = state
                .get_ownership(&okey)
                .expect("ownership entry must exist");
            assert!(
                owned.contains(&coin_id),
                "OwnershipIndex missing coin_id for idx {idx}"
            );
        }
    }

    #[test]
    fn genesis_coin_type_uses_pinned_fungible_petal_hash_when_present() {
        let addr = [0x01u8; 32];
        let mut genesis = make_genesis(vec![(addr, 1_000_000)]);
        genesis.petals = vec![(CORE_FUNGIBLE_PATH.to_string(), vec![0x01, 0x02, 0x03])];

        let mut state = State::new();
        genesis.apply_to_state(&mut state);

        let fungible_hash = state
            .vfs_lookup(CORE_FUNGIBLE_PATH)
            .expect("fungible petal bound at genesis");
        assert_ne!(fungible_hash, DEFAULT_FUNGIBLE_PETAL_HASH);

        let obj = state
            .get_object(&genesis_coin_id(&genesis, 0))
            .expect("genesis Coin<LOOM>");
        assert_eq!(obj.type_tag, loom_coin_type_tag(fungible_hash));
    }

    #[test]
    fn genesis_coin_ids_are_unique_across_allocations() {
        // Same address, different amounts: ids must still be unique (indexed by idx).
        let addr = [0xBBu8; 32];
        let genesis = make_genesis(vec![(addr, 100), (addr, 200)]);
        let mut state = State::new();
        genesis.apply_to_state(&mut state);

        let id0 = {
            let mut h = blake3::Hasher::new();
            h.update(b"bloom.genesis.loom");
            h.update(&genesis.genesis_hash.0);
            h.update(&0u32.to_le_bytes());
            ObjectId(*h.finalize().as_bytes())
        };
        let id1 = {
            let mut h = blake3::Hasher::new();
            h.update(b"bloom.genesis.loom");
            h.update(&genesis.genesis_hash.0);
            h.update(&1u32.to_le_bytes());
            ObjectId(*h.finalize().as_bytes())
        };
        assert_ne!(id0, id1, "coin ids must differ across allocation indices");
        assert!(state.get_object(&id0).is_some());
        assert!(state.get_object(&id1).is_some());
    }

    #[test]
    fn genesis_loom_cache_matches_coin_value() {
        let addr = [0xCCu8; 32];
        let amount: u128 = 999_999_999_999_999_999;
        let genesis = make_genesis(vec![(addr, amount)]);
        let mut state = State::new();
        genesis.apply_to_state(&mut state);

        let acct = state.get_account(&Address(addr)).unwrap();
        assert_eq!(acct.loom, amount);

        let coin_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"bloom.genesis.loom");
            h.update(&genesis.genesis_hash.0);
            h.update(&0u32.to_le_bytes());
            ObjectId(*h.finalize().as_bytes())
        };
        let obj = state.get_object(&coin_id).unwrap();
        let value = decode_coin_value(&obj.payload).unwrap();
        assert_eq!(value, amount, "loom cache and coin payload must agree");
    }

    #[test]
    fn genesis_rejects_validator_address_pubkey_mismatch() {
        let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let derived = Address::from_pubkey_bytes(&pk.0);
        let mut wrong = derived;
        wrong.0[0] ^= 0xFF;
        let raw = GenesisFile {
            chain_id: "bloomchain.test".into(),
            genesis_time_ms: 0,
            validators: vec![ValidatorConfig {
                address: hex::encode(wrong.0),
                pubkey: base64::engine::general_purpose::STANDARD.encode(&pk.0),
                voting_power: 100,
                host: Some("127.0.0.1:26656".into()),
            }],
            allocations: vec![],
            petals: vec![],
            key_registry: vec![],
        };

        let err = Genesis::from_raw(raw).expect_err("mismatch must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("address/pubkey mismatch"),
            "unexpected error: {msg}"
        );
    }

    fn raw_genesis_with_pubkey(pubkey: String) -> GenesisFile {
        let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let address = Address::from_pubkey_bytes(&pk.0);
        GenesisFile {
            chain_id: "bloomchain.test".into(),
            genesis_time_ms: 0,
            validators: vec![ValidatorConfig {
                address: hex::encode(address.0),
                pubkey,
                voting_power: 100,
                host: Some("127.0.0.1:26656".into()),
            }],
            allocations: vec![],
            petals: vec![],
            key_registry: vec![],
        }
    }

    #[test]
    fn genesis_rejects_malformed_validator_pubkey_base64() {
        let err = Genesis::from_raw(raw_genesis_with_pubkey("AAAAA".into()))
            .expect_err("non-canonical base64 length must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("base64"), "unexpected error: {msg}");
    }

    #[test]
    fn genesis_rejects_invalid_validator_pubkey_padding() {
        let err = Genesis::from_raw(raw_genesis_with_pubkey("AA=A".into()))
            .expect_err("misplaced base64 padding must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("base64"), "unexpected error: {msg}");
    }

    #[test]
    fn genesis_rejects_wrong_validator_pubkey_length() {
        let short_pubkey = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let err = Genesis::from_raw(raw_genesis_with_pubkey(short_pubkey))
            .expect_err("wrong xDSA pubkey length must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("1984 bytes"), "unexpected error: {msg}");
    }
}
