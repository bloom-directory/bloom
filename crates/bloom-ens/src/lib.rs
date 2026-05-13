//! ENS resolution against an Ethereum-compatible chain.
//!
//! The [`EnsClient`] uses a [`bloom_chain::ChainClient`] for transport and
//! talks to the standard ENS registry + a per-name resolver to perform:
//!
//! * forward resolution: `name -> address`
//! * reverse resolution: `address -> name` (with forward-resolution
//!   verification, per the standard ENS pattern)
//! * `text(name, key)` records (avatar, url, ...)
//! * `contenthash(name)` records
//!
//! Hashing uses the in-tree [`namehash`] implementation; ABI calls go
//! through alloy's `sol!`-generated bindings.
//!
//! Positive results are cached in-memory with a TTL (default 5 minutes).

#![forbid(unsafe_code)]

mod error;
mod namehash;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, FixedBytes, address};
use alloy::sol;
use parking_lot::RwLock;
use tracing::debug;

use bloom_chain::ChainClient;

pub use error::{EnsError, Result};
pub use namehash::{keccak256, namehash};

/// Mainnet ENS registry (also valid on Goerli, Sepolia, Holesky — same
/// CREATE2-deployed address).
pub const MAINNET_REGISTRY: Address = address!("00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

/// Default TTL for positive cache entries.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

// ---- ABI bindings -----------------------------------------------------------

sol! {
    #[sol(rpc)]
    contract IEnsRegistry {
        function resolver(bytes32 node) external view returns (address);
    }

    #[sol(rpc)]
    contract IEnsResolver {
        function addr(bytes32 node) external view returns (address);
        function name(bytes32 node) external view returns (string);
        function text(bytes32 node, string key) external view returns (string);
        function contenthash(bytes32 node) external view returns (bytes);
    }
}

// ---- Cache ------------------------------------------------------------------

#[derive(Clone)]
struct CacheEntry<T: Clone> {
    value: T,
    inserted: Instant,
}

#[derive(Default)]
struct Caches {
    forward: HashMap<String, CacheEntry<Address>>,
    reverse: HashMap<Address, CacheEntry<String>>,
    text: HashMap<(String, String), CacheEntry<String>>,
    content: HashMap<String, CacheEntry<Bytes>>,
    /// name -> resolver address
    resolver: HashMap<[u8; 32], CacheEntry<Address>>,
}

fn fresh<T: Clone>(entry: &CacheEntry<T>, ttl: Duration) -> Option<T> {
    if entry.inserted.elapsed() < ttl {
        Some(entry.value.clone())
    } else {
        None
    }
}

// ---- Client -----------------------------------------------------------------

/// ENS client bound to a single chain.
#[derive(Clone)]
pub struct EnsClient {
    provider: ChainClient,
    registry: Address,
    ttl: Duration,
    cache: Arc<RwLock<Caches>>,
}

impl EnsClient {
    /// Construct an `EnsClient` for ENS mainnet (registry at the canonical
    /// address). The provided `ChainClient` should point at a chain where
    /// that registry exists (mainnet, Goerli, Sepolia, Holesky, or a fork).
    pub fn mainnet(client: ChainClient) -> Self {
        Self::with_registry(client, MAINNET_REGISTRY)
    }

    /// Construct with a custom registry address.
    pub fn with_registry(client: ChainClient, registry: Address) -> Self {
        Self {
            provider: client,
            registry,
            ttl: DEFAULT_CACHE_TTL,
            cache: Arc::new(RwLock::new(Caches::default())),
        }
    }

    /// Override the cache TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Return the registry address used by this client.
    pub fn registry(&self) -> Address {
        self.registry
    }

    /// Resolve `name` to an address (ENS forward resolution).
    pub async fn resolve(&self, name: &str) -> Result<Address> {
        if name.is_empty() {
            return Err(EnsError::InvalidName("empty".into()));
        }
        if let Some(hit) = self
            .cache
            .read()
            .forward
            .get(name)
            .and_then(|e| fresh(e, self.ttl))
        {
            debug!(name, "ens.cache.hit forward");
            return Ok(hit);
        }
        let node = namehash(name);
        let resolver = self.resolver_for(node).await?;
        let provider = self.provider.provider();
        let resolver_contract = IEnsResolver::new(resolver, provider);
        let addr = resolver_contract
            .addr(FixedBytes::from(node))
            .call()
            .await
            .map_err(|e| EnsError::Decode(format!("addr({name}): {e}")))?;
        if addr.is_zero() {
            debug!(name, %resolver, "ens.resolve.addr_zero");
            return Err(EnsError::NotFound(format!("addr unset for '{name}'")));
        }
        self.cache.write().forward.insert(
            name.to_string(),
            CacheEntry {
                value: addr,
                inserted: Instant::now(),
            },
        );
        Ok(addr)
    }

    /// Reverse-resolve an address to its primary ENS name and verify the
    /// forward resolution matches.
    pub async fn reverse(&self, addr: Address) -> Result<String> {
        if let Some(hit) = self
            .cache
            .read()
            .reverse
            .get(&addr)
            .and_then(|e| fresh(e, self.ttl))
        {
            debug!(%addr, "ens.cache.hit reverse");
            return Ok(hit);
        }
        let reverse_name = format!("{}.addr.reverse", hex::encode(addr.as_slice()));
        let node = namehash(&reverse_name);
        let resolver = self.resolver_for(node).await?;
        let provider = self.provider.provider();
        let resolver_contract = IEnsResolver::new(resolver, provider);
        let name = resolver_contract
            .name(FixedBytes::from(node))
            .call()
            .await
            .map_err(|e| EnsError::Decode(format!("name({addr}): {e}")))?;
        if name.is_empty() {
            debug!(%addr, %resolver, "ens.reverse.name_empty");
            return Err(EnsError::NotFound(format!("no reverse record for {addr}")));
        }
        // Forward-verify: the claimed name must resolve back to `addr`.
        let forward = self.resolve(&name).await?;
        if forward != addr {
            debug!(%addr, name = %name, %forward, "ens.reverse.forward_mismatch");
            return Err(EnsError::NotFound(format!(
                "reverse '{name}' does not forward-resolve to {addr} (got {forward})"
            )));
        }
        self.cache.write().reverse.insert(
            addr,
            CacheEntry {
                value: name.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(name)
    }

    /// Read a text record (e.g. "url", "avatar", "com.twitter").
    pub async fn text(&self, name: &str, key: &str) -> Result<String> {
        if name.is_empty() {
            return Err(EnsError::InvalidName("empty".into()));
        }
        let cache_key = (name.to_string(), key.to_string());
        if let Some(hit) = self
            .cache
            .read()
            .text
            .get(&cache_key)
            .and_then(|e| fresh(e, self.ttl))
        {
            debug!(name, key, "ens.cache.hit text");
            return Ok(hit);
        }
        let node = namehash(name);
        let resolver = self.resolver_for(node).await?;
        let provider = self.provider.provider();
        let resolver_contract = IEnsResolver::new(resolver, provider);
        let value = resolver_contract
            .text(FixedBytes::from(node), key.to_string())
            .call()
            .await
            .map_err(|e| EnsError::Decode(format!("text({name},{key}): {e}")))?;
        if value.is_empty() {
            debug!(name, key, %resolver, "ens.text.empty");
            return Err(EnsError::NotFound(format!(
                "text '{key}' unset for '{name}'"
            )));
        }
        self.cache.write().text.insert(
            cache_key,
            CacheEntry {
                value: value.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(value)
    }

    /// Read a contenthash record (EIP-1577).
    pub async fn content_hash(&self, name: &str) -> Result<Bytes> {
        if name.is_empty() {
            return Err(EnsError::InvalidName("empty".into()));
        }
        if let Some(hit) = self
            .cache
            .read()
            .content
            .get(name)
            .and_then(|e| fresh(e, self.ttl))
        {
            debug!(name, "ens.cache.hit content_hash");
            return Ok(hit);
        }
        let node = namehash(name);
        let resolver = self.resolver_for(node).await?;
        let provider = self.provider.provider();
        let resolver_contract = IEnsResolver::new(resolver, provider);
        let value = resolver_contract
            .contenthash(FixedBytes::from(node))
            .call()
            .await
            .map_err(|e| EnsError::Decode(format!("contenthash({name}): {e}")))?;
        if value.is_empty() {
            debug!(name, %resolver, "ens.content_hash.empty");
            return Err(EnsError::NotFound(format!(
                "contenthash unset for '{name}'"
            )));
        }
        self.cache.write().content.insert(
            name.to_string(),
            CacheEntry {
                value: value.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(value)
    }

    /// Look up the resolver address for a node, with caching. Errors if
    /// no resolver is registered (zero address).
    async fn resolver_for(&self, node: [u8; 32]) -> Result<Address> {
        if let Some(hit) = self
            .cache
            .read()
            .resolver
            .get(&node)
            .and_then(|e| fresh(e, self.ttl))
        {
            debug!(node = %hex::encode(node), "ens.cache.hit resolver");
            return Ok(hit);
        }
        let provider = self.provider.provider();
        let registry = IEnsRegistry::new(self.registry, provider);
        let addr = registry
            .resolver(FixedBytes::from(node))
            .call()
            .await
            .map_err(|e| EnsError::Decode(format!("registry.resolver: {e}")))?;
        if addr.is_zero() {
            debug!(node = %hex::encode(node), "ens.resolver_for.unset");
            return Err(EnsError::NotFound(format!(
                "no resolver registered for node 0x{}",
                hex::encode(node)
            )));
        }
        self.cache.write().resolver.insert(
            node,
            CacheEntry {
                value: addr,
                inserted: Instant::now(),
            },
        );
        Ok(addr)
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namehash_canonical_vectors() {
        assert_eq!(namehash(""), [0u8; 32]);
        assert_eq!(
            hex::encode(namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn registry_address_is_canonical() {
        // 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
        assert_eq!(
            format!("{MAINNET_REGISTRY:?}").to_lowercase(),
            "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
        );
    }
}
