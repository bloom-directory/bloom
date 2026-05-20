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
//! ```

use std::path::Path;

use anyhow::{Result, anyhow};
use bloom_chain_consensus::ValidatorSet;
use bloom_chain_consensus::validator_set::Validator;
use bloom_chain_state::{Account, State};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes};
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

/// Parsed genesis file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisFile {
    pub chain_id: String,
    pub genesis_time_ms: u64,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
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
    /// Genesis hash: `blake3("bloom-chain.v0.genesis:" || ssz(chain_id_bytes || genesis_time_ms))`.
    pub genesis_hash: Hash32,
}

impl Genesis {
    /// Parse and validate a genesis TOML file.
    pub fn from_file(path: &Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            NodeError::Genesis(format!("read {}: {e}", path.display()))
        })?;
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

        // Parse allocations.
        let mut allocations: Vec<(Address, u128)> = Vec::new();
        for alloc in &raw.allocations {
            let addr = parse_b1_address(&alloc.address)
                .map_err(|e| NodeError::Genesis(format!("allocation address: {e}")))?;
            let amount: u128 = alloc
                .amount
                .parse()
                .map_err(|e| NodeError::Genesis(format!("allocation amount '{}': {e}", alloc.amount)))?;
            allocations.push((addr, amount));
        }

        // Genesis hash.
        let genesis_hash = compute_genesis_hash(&raw.chain_id, raw.genesis_time_ms);

        Ok(Genesis {
            chain_id: raw.chain_id,
            genesis_time_ms: raw.genesis_time_ms,
            validator_set,
            peer_addrs,
            allocations,
            genesis_hash,
        })
    }

    /// Apply allocations to an empty `State`, producing the genesis state.
    pub fn apply_to_state(&self, state: &mut State) {
        for (addr, amount) in &self.allocations {
            let acct = Account {
                nonce: 0,
                loom: *amount,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            };
            state.set_account(*addr, acct);
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
            && bytes.len() == 32 {
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
    let bytes = zbase32::decode_full_bytes_str(payload_b32)
        .map_err(|e| anyhow!("base32 decode: {e}"))?;

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
    
    // Use the standard base64 alphabet.
    // We avoid pulling in the `base64` crate; use std's built-in decoder via
    // a simple wrapper.  Since the keystore already uses base64 via alloy, we
    // replicate a minimal impl here.
    //
    // Actually: just use the `base64` alphabet via the standard approach.
    // The workspace does have base64 = "0.22" in the bloom crate dev-deps;
    // however bloom-chain-node doesn't declare it.  Use a manual decode.
    //
    // For v0 simplicity, decode standard base64 by hand.
    fn val(c: u8) -> Result<u8> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0), // padding
            _ => Err(anyhow!("invalid base64 char: {c}")),
        }
    }

    let s = s.trim();
    let mut out = Vec::with_capacity((s.len() * 3) / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b0 = val(bytes[i])?;
        let b1 = val(bytes[i + 1])?;
        let b2 = val(bytes[i + 2])?;
        let b3 = val(bytes[i + 3])?;
        out.push((b0 << 2) | (b1 >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b1 << 4) | (b2 >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((b2 << 6) | b3);
        }
        i += 4;
    }
    Ok(out)
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
            genesis_path: None,
            log_level: Some("info".into()),
            fuel_limit: Some(30_000_000),
            wasmtime_version: Some(env!("CARGO_PKG_VERSION").into()),
        }
    }
}
