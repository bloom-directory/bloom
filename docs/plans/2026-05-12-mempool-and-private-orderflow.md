# Mempool + Private Orderflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement mempool observability, nonce-conflict detection, gas-bump suggestions, private orderflow routing, and stage-time MEV/sandwich warnings, addressing README.md:167 and the v1 non-goal at `docs/specs/2026-05-08-bloom-eth-design.md:78`.

**Architecture:** One new crate (`bloom-mempool`) owns the read-side mempool stream + index + provider traits + heuristic. `bloom-tx`, `bloom-rpc`, `bloom-vfs`, and `bloom-daemon` are extended to wire the new logic into staging, broadcast, the VFS, and the daemon lifecycle. Provider abstractions (`MempoolProvider`, `PrivateRpcProvider`) keep external dependencies behind feature flags. Reference spec: `docs/specs/2026-05-12-mempool-and-private-orderflow-design.md`.

**Tech Stack:** Rust 2024, tokio, alloy, async-trait, parking_lot, serde, tracing, reqwest (for private-RPC POSTs), futures (for streams). All existing workspace deps; no new top-level workspace deps.

---

## Conventions

- **TDD:** every task starts with a failing test, then minimal implementation, then green test.
- **Commits:** one commit per task, with a `feat(<crate>)`, `fix(<crate>)`, `test(<crate>)`, or `docs(<crate>)` prefix matching the existing repo style.
- **Test fixtures:** put new hand-crafted calldata + RPC fixtures under `crates/<crate>/tests/fixtures/` per existing convention.
- **Workspace lints:** `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` after every task before commit.
- **Mainnet chain id constant:** `pub const MAINNET_CHAIN_ID: u64 = 1;` lives in `bloom-mempool/src/private.rs`.

---

# Phase 1 — Foundation (no external deps)

Produces a buildable `bloom-mempool` crate with traits, mocks, the pending-tx index, the MEV heuristic, and the bump-fee math. Phase 1 must compile and test green standalone; no other crate depends on it yet.

---

### Task 1.1: Create `bloom-mempool` crate skeleton

**Files:**
- Create: `crates/bloom-mempool/Cargo.toml`
- Create: `crates/bloom-mempool/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Add crate to workspace members**

Modify the `members = [...]` block in `/Users/joshua/code/bloom-eth/Cargo.toml` to include `"crates/bloom-mempool"`. Place it alphabetically between `"crates/bloom-keystore"` and `"crates/bloom-mount"`.

- [ ] **Step 2: Write the crate Cargo.toml**

Create `crates/bloom-mempool/Cargo.toml`:

```toml
[package]
name = "bloom-mempool"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Mempool observability + private orderflow + MEV heuristic for bloom-eth"

[features]
default = ["alchemy", "generic_eth_subscribe", "mev_blocker", "flashbots"]
alchemy = ["dep:reqwest", "dep:tokio-tungstenite"]
generic_eth_subscribe = ["dep:tokio-tungstenite"]
mev_blocker = ["dep:reqwest"]
flashbots = ["dep:reqwest"]
# Opt-in: enables tests that hit real Alchemy / MEV-Blocker / Flashbots
# endpoints. Never enabled in CI.
live-providers = []

[dependencies]
bloom-proto.workspace = true
bloom-chain.workspace = true
bloom-tools.workspace = true
alloy.workspace = true
alloy-dyn-abi.workspace = true
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tokio = { workspace = true, features = ["sync", "time", "macros"] }
tracing.workspace = true
parking_lot.workspace = true
futures.workspace = true
hex.workspace = true
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"], optional = true }
tokio-tungstenite = { version = "0.24", default-features = false, features = ["rustls-tls-webpki-roots"], optional = true }

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros", "time"] }
tracing-subscriber.workspace = true
tempfile.workspace = true
```

- [ ] **Step 3: Write the lib.rs skeleton**

Create `crates/bloom-mempool/src/lib.rs`:

```rust
//! Mempool observability + private orderflow + MEV heuristic.
//!
//! See `docs/specs/2026-05-12-mempool-and-private-orderflow-design.md`.

pub mod bump;
pub mod heuristic;
pub mod index;
pub mod private;
pub mod provider;
pub mod stream;

pub use index::{PendingTxIndex, PendingTxRecord};
pub use private::{
    MAINNET_CHAIN_ID, PrivateRpcError, PrivateRpcProvider, MockPrivateRpcProvider,
};
pub use provider::{MempoolError, MempoolProvider, MockMempoolProvider, PendingTx, TxFees};
```

Create empty stub files so the crate compiles:

```bash
mkdir -p crates/bloom-mempool/src
for f in bump.rs heuristic.rs index.rs private.rs provider.rs stream.rs; do
  echo "//! stub" > crates/bloom-mempool/src/$f
done
```

- [ ] **Step 4: Verify the crate compiles**

Run: `cargo build -p bloom-mempool`
Expected: success with warnings only (unused modules).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/bloom-mempool/
git commit -m "feat(bloom-mempool): crate skeleton"
```

---

### Task 1.2: `PendingTx` domain type + `TxFees`

**Files:**
- Modify: `crates/bloom-mempool/src/provider.rs`
- Test: `crates/bloom-mempool/src/provider.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Replace the stub in `crates/bloom-mempool/src/provider.rs` with:

```rust
//! `MempoolProvider` trait + the `PendingTx` domain type.

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Fees normalised across legacy (gasPrice) and EIP-1559
/// (maxFeePerGas / maxPriorityFeePerGas) txs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TxFees {
    Legacy { gas_price: u128 },
    Eip1559 { max_fee_per_gas: u128, max_priority_fee_per_gas: u128 },
}

impl TxFees {
    /// The fee the user has authorised the protocol to charge per gas.
    pub fn max_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy { gas_price } => *gas_price,
            Self::Eip1559 { max_fee_per_gas, .. } => *max_fee_per_gas,
        }
    }

    /// Tip to the builder/miner.
    pub fn max_priority_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy { gas_price } => *gas_price,
            Self::Eip1559 { max_priority_fee_per_gas, .. } => *max_priority_fee_per_gas,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub fees: TxFees,
    pub input: Bytes,
    #[serde(with = "system_time_secs")]
    pub observed_at: SystemTime,
}

mod system_time_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        secs.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_fees_legacy_normalises_to_same_value() {
        let f = TxFees::Legacy { gas_price: 5 };
        assert_eq!(f.max_fee_per_gas(), 5);
        assert_eq!(f.max_priority_fee_per_gas(), 5);
    }

    #[test]
    fn tx_fees_eip1559_returns_distinct_fields() {
        let f = TxFees::Eip1559 { max_fee_per_gas: 50, max_priority_fee_per_gas: 2 };
        assert_eq!(f.max_fee_per_gas(), 50);
        assert_eq!(f.max_priority_fee_per_gas(), 2);
    }

    #[test]
    fn pending_tx_round_trips_through_json() {
        let tx = PendingTx {
            hash: B256::ZERO,
            from: Address::ZERO,
            to: None,
            nonce: 7,
            value: U256::from(10u64),
            gas_limit: 21_000,
            fees: TxFees::Eip1559 { max_fee_per_gas: 50, max_priority_fee_per_gas: 2 },
            input: Bytes::new(),
            observed_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        };
        let s = serde_json::to_string(&tx).unwrap();
        let back: PendingTx = serde_json::from_str(&s).unwrap();
        assert_eq!(back.nonce, 7);
        assert_eq!(back.gas_limit, 21_000);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p bloom-mempool --lib provider::tests`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/provider.rs
git commit -m "feat(bloom-mempool): PendingTx + TxFees domain types"
```

---

### Task 1.3: `PendingTxIndex` (bounded LRU keyed by hash + by (addr, nonce))

**Files:**
- Modify: `crates/bloom-mempool/src/index.rs`
- Test: `crates/bloom-mempool/src/index.rs` (inline)

- [ ] **Step 1: Write the failing test first**

Replace `crates/bloom-mempool/src/index.rs` with:

```rust
//! Bounded in-memory index of observed pending txs.
//!
//! Keyed by hash (primary), with a secondary `(address, nonce)` map
//! that powers the nonce-conflict check at stage time.

use alloy::primitives::{Address, B256};
use parking_lot::RwLock;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

use crate::provider::PendingTx;

#[derive(Debug, Clone)]
pub struct PendingTxRecord {
    pub tx: PendingTx,
    pub inserted_at: SystemTime,
}

#[derive(Debug)]
pub struct PendingTxIndex {
    inner: RwLock<Inner>,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Inner {
    by_hash: BTreeMap<B256, PendingTxRecord>,
    by_addr_nonce: BTreeMap<(Address, u64), B256>,
    order: VecDeque<B256>,
    evictions_total: u64,
}

impl PendingTxIndex {
    pub fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0, "PendingTxIndex capacity must be > 0");
        Arc::new(Self { inner: RwLock::new(Inner::default()), capacity })
    }

    pub fn insert(&self, tx: PendingTx) {
        let mut g = self.inner.write();
        let hash = tx.hash;
        let from = tx.from;
        let nonce = tx.nonce;
        let inserted_at = SystemTime::now();

        if g.by_hash.contains_key(&hash) {
            g.by_hash.insert(hash, PendingTxRecord { tx, inserted_at });
            return;
        }

        while g.order.len() >= self.capacity {
            if let Some(victim) = g.order.pop_front() {
                if let Some(rec) = g.by_hash.remove(&victim) {
                    g.by_addr_nonce.remove(&(rec.tx.from, rec.tx.nonce));
                }
                g.evictions_total += 1;
            } else {
                break;
            }
        }

        g.by_hash.insert(hash, PendingTxRecord { tx, inserted_at });
        g.by_addr_nonce.insert((from, nonce), hash);
        g.order.push_back(hash);
    }

    pub fn lookup_by_hash(&self, hash: &B256) -> Option<PendingTxRecord> {
        self.inner.read().by_hash.get(hash).cloned()
    }

    pub fn lookup_by_addr_nonce(&self, addr: Address, nonce: u64) -> Option<PendingTxRecord> {
        let g = self.inner.read();
        let hash = g.by_addr_nonce.get(&(addr, nonce))?;
        g.by_hash.get(hash).cloned()
    }

    pub fn remove(&self, hash: &B256) -> Option<PendingTxRecord> {
        let mut g = self.inner.write();
        let rec = g.by_hash.remove(hash)?;
        g.by_addr_nonce.remove(&(rec.tx.from, rec.tx.nonce));
        g.order.retain(|h| h != hash);
        Some(rec)
    }

    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn evictions_total(&self) -> u64 {
        self.inner.read().evictions_total
    }

    /// Snapshot of all observed nonces for a single address. Used by
    /// the VFS `by_address/<a>/nonces.json` handler.
    pub fn observed_nonces(&self, addr: Address) -> Vec<u64> {
        let g = self.inner.read();
        let mut out: Vec<u64> = g
            .by_addr_nonce
            .range((addr, 0)..=(addr, u64::MAX))
            .map(|((_, n), _)| *n)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{PendingTx, TxFees};
    use alloy::primitives::{Bytes, U256};

    fn make_tx(hash_byte: u8, addr_byte: u8, nonce: u64) -> PendingTx {
        let mut hash = [0u8; 32];
        hash[0] = hash_byte;
        let mut addr = [0u8; 20];
        addr[0] = addr_byte;
        PendingTx {
            hash: B256::from(hash),
            from: Address::from(addr),
            to: None,
            nonce,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: SystemTime::now(),
        }
    }

    #[test]
    fn insert_and_lookup_by_hash() {
        let idx = PendingTxIndex::new(8);
        let tx = make_tx(1, 1, 0);
        idx.insert(tx.clone());
        let got = idx.lookup_by_hash(&tx.hash).unwrap();
        assert_eq!(got.tx.nonce, 0);
    }

    #[test]
    fn insert_and_lookup_by_addr_nonce() {
        let idx = PendingTxIndex::new(8);
        let tx = make_tx(2, 3, 42);
        idx.insert(tx.clone());
        let got = idx.lookup_by_addr_nonce(tx.from, 42).unwrap();
        assert_eq!(got.tx.hash, tx.hash);
        assert!(idx.lookup_by_addr_nonce(tx.from, 43).is_none());
    }

    #[test]
    fn lru_evicts_oldest_at_capacity() {
        let idx = PendingTxIndex::new(2);
        let a = make_tx(1, 1, 0);
        let b = make_tx(2, 2, 0);
        let c = make_tx(3, 3, 0);
        idx.insert(a.clone());
        idx.insert(b.clone());
        idx.insert(c.clone());
        assert_eq!(idx.len(), 2);
        assert!(idx.lookup_by_hash(&a.hash).is_none(), "a should be evicted");
        assert!(idx.lookup_by_hash(&b.hash).is_some());
        assert!(idx.lookup_by_hash(&c.hash).is_some());
        assert_eq!(idx.evictions_total(), 1);
    }

    #[test]
    fn duplicate_insert_updates_in_place_no_eviction() {
        let idx = PendingTxIndex::new(2);
        let a = make_tx(1, 1, 0);
        idx.insert(a.clone());
        idx.insert(a.clone());
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.evictions_total(), 0);
    }

    #[test]
    fn observed_nonces_returns_sorted_dedup() {
        let idx = PendingTxIndex::new(8);
        idx.insert(make_tx(1, 7, 3));
        idx.insert(make_tx(2, 7, 1));
        idx.insert(make_tx(3, 7, 2));
        idx.insert(make_tx(4, 9, 5));
        let mut addr = [0u8; 20];
        addr[0] = 7;
        let ns = idx.observed_nonces(Address::from(addr));
        assert_eq!(ns, vec![1, 2, 3]);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p bloom-mempool --lib index::tests`
Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/index.rs
git commit -m "feat(bloom-mempool): bounded LRU PendingTxIndex"
```

---

### Task 1.4: `MempoolProvider` trait + `provider_test_suite!` macro

**Files:**
- Modify: `crates/bloom-mempool/src/provider.rs`

- [ ] **Step 1: Add the trait, error type, and conformance macro**

Append to `crates/bloom-mempool/src/provider.rs` (above the `#[cfg(test)]` block):

```rust
use async_trait::async_trait;
use futures::stream::BoxStream;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("websocket transport error: {0}")]
    Transport(String),
    #[error("provider returned malformed data: {0}")]
    Decode(String),
    #[error("provider not configured")]
    NotConfigured,
}

#[async_trait]
pub trait MempoolProvider: Send + Sync {
    fn id(&self) -> &'static str;

    /// Open a long-lived subscription. The returned stream lives until
    /// the caller drops it; the provider is responsible for cleanup.
    async fn subscribe(&self) -> Result<BoxStream<'static, PendingTx>, MempoolError>;

    /// True = stream already includes full tx fields; False = the
    /// stream yields hash-only `PendingTx`s with `input.is_empty()`
    /// and the daemon must follow up via `eth_getTransactionByHash`
    /// before storing in the index.
    fn delivers_bodies(&self) -> bool;
}

/// Conformance test suite. Any `MempoolProvider` implementation
/// should be exercised via `provider_test_suite!(MyProvider, build_fn, suite_mod_name)`
/// where `build_fn` is a `fn() -> MyProvider` and `suite_mod_name` is a unique
/// identifier for the generated test module.
///
/// Note: the `${ty}` metavariable expression form (macro_metavar_expr) is not yet
/// stable in Rust 1.91; the explicit `$mod_name:ident` fallback is used instead.
///
/// The suite runs two checks:
///   1. `id()` is non-empty.
///   2. `subscribe()` returns a stream that yields at least 1 item
///      when the upstream produces items.
///
/// (A future dedup-after-reconnect check is deferred to Phase 4, where it
/// will be exercised against `MempoolStream` rather than individual providers.)
#[macro_export]
macro_rules! provider_test_suite {
    ($t:ty, $build:expr, $mod_name:ident) => {
        #[allow(non_snake_case)]
        mod $mod_name {
            use $crate::provider::{MempoolProvider, PendingTx};

            #[tokio::test]
            async fn id_is_non_empty() {
                let p: $t = $build();
                assert!(!<$t as $crate::provider::MempoolProvider>::id(&p).is_empty());
            }

            #[tokio::test]
            async fn subscribe_yields_when_upstream_has_items() {
                use futures::StreamExt;
                let p: $t = $build();
                let mut s = <$t as $crate::provider::MempoolProvider>::subscribe(&p)
                    .await
                    .unwrap();
                let first = tokio::time::timeout(std::time::Duration::from_secs(2), s.next())
                    .await
                    .expect("provider must yield first item within 2s")
                    .expect("stream ended before yielding any item");
                assert_ne!(first.hash, alloy::primitives::B256::ZERO);
            }
        }
    };
}
```

Note: the macro takes a third `$mod_name:ident` argument because the `${ty}` metavariable
expression (macro_metavar_expr) is not stable on Rust 1.91. Each caller must supply a
unique module identifier, e.g. `provider_test_suite!(MockMempoolProvider, build_fn, mock_provider_conformance)`.

- [ ] **Step 2: Build the crate**

Run: `cargo build -p bloom-mempool`
Expected: success.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/provider.rs
git commit -m "feat(bloom-mempool): MempoolProvider trait + conformance macro"
```

---

### Task 1.5: `MockMempoolProvider` (fixture-fed)

**Files:**
- Modify: `crates/bloom-mempool/src/provider.rs`

- [ ] **Step 1: Add the mock and a test that uses the conformance macro**

Append to `crates/bloom-mempool/src/provider.rs` (above the existing `#[cfg(test)]` block):

```rust
use futures::stream;

/// In-memory mock that yields a fixed sequence of `PendingTx`s. Used
/// by integration tests in this crate and by `bloom-vfs` / `bloom-tx`
/// integration suites.
pub struct MockMempoolProvider {
    id: &'static str,
    fixtures: Vec<PendingTx>,
    delivers_bodies: bool,
}

impl MockMempoolProvider {
    pub fn new(id: &'static str, fixtures: Vec<PendingTx>) -> Self {
        Self { id, fixtures, delivers_bodies: true }
    }

    pub fn with_hashes_only(mut self) -> Self {
        self.delivers_bodies = false;
        self
    }
}

#[async_trait]
impl MempoolProvider for MockMempoolProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, PendingTx>, MempoolError> {
        let items = self.fixtures.clone();
        Ok(Box::pin(stream::iter(items)))
    }

    fn delivers_bodies(&self) -> bool {
        self.delivers_bodies
    }
}
```

Now extend the existing `#[cfg(test)]` block to include the conformance suite invocation:

```rust
    fn one_fixture() -> Vec<PendingTx> {
        vec![PendingTx {
            hash: B256::from([1u8; 32]),
            from: Address::from([2u8; 20]),
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: SystemTime::now(),
        }]
    }

    #[tokio::test]
    async fn mock_yields_fixture_items() {
        use futures::StreamExt;
        let p = MockMempoolProvider::new("mock", one_fixture());
        let mut s = p.subscribe().await.unwrap();
        let first = s.next().await.unwrap();
        assert_eq!(first.hash, B256::from([1u8; 32]));
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p bloom-mempool --lib provider::tests`
Expected: at least 4 tests pass (the 3 from Task 1.2 + `mock_yields_fixture_items`).

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/provider.rs
git commit -m "feat(bloom-mempool): MockMempoolProvider fixture provider"
```

---

### Task 1.6: `PrivateRpcProvider` trait + error type

**Files:**
- Modify: `crates/bloom-mempool/src/private.rs`

- [ ] **Step 1: Replace stub with the trait, error, and chain constant**

Replace `crates/bloom-mempool/src/private.rs` with:

```rust
//! Private orderflow — pluggable provider trait + mock for tests.
//! See Phase 4 for real adapters (MEV-Blocker, Flashbots Protect).

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;
use thiserror::Error;

pub const MAINNET_CHAIN_ID: u64 = 1;

#[derive(Debug, Error)]
pub enum PrivateRpcError {
    #[error("http transport error: {0}")]
    Transport(String),
    #[error("provider returned an error: {0}")]
    ProviderError(String),
    #[error("provider does not support chain id {0}")]
    UnsupportedChain(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[async_trait]
pub trait PrivateRpcProvider: Send + Sync {
    fn id(&self) -> &'static str;

    /// The chain ids this provider can serve. v1 implementations
    /// return `&[MAINNET_CHAIN_ID]`.
    fn supported_chains(&self) -> &'static [u64];

    /// Submit a signed raw tx privately. MUST return the tx hash on
    /// success. MUST NOT silently fall back to the public mempool.
    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError>;

    /// Cheap probe (e.g. `eth_blockNumber`) for status surface and
    /// daemon health.
    async fn health(&self) -> Result<HealthStatus, PrivateRpcError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_chain_id_is_one() {
        assert_eq!(MAINNET_CHAIN_ID, 1);
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p bloom-mempool && cargo test -p bloom-mempool --lib private::tests`
Expected: success; 1 test passes.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/private.rs
git commit -m "feat(bloom-mempool): PrivateRpcProvider trait + error types"
```

---

### Task 1.7: `MockPrivateRpcProvider` (captures submitted txs)

**Files:**
- Modify: `crates/bloom-mempool/src/private.rs`

- [ ] **Step 1: Add the mock and a test**

Append to `crates/bloom-mempool/src/private.rs`:

```rust
use alloy::primitives::keccak256;
use parking_lot::Mutex;
use std::sync::Arc;

/// Captures all submitted raw txs in memory. Used by `bloom-tx`
/// integration tests to assert that the broadcast routes correctly
/// when a wallet has `private.enabled = true`.
pub struct MockPrivateRpcProvider {
    id: &'static str,
    supported: &'static [u64],
    submissions: Arc<Mutex<Vec<Bytes>>>,
    health: HealthStatus,
}

impl MockPrivateRpcProvider {
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            supported: &[MAINNET_CHAIN_ID],
            submissions: Arc::new(Mutex::new(Vec::new())),
            health: HealthStatus::Healthy,
        }
    }

    pub fn with_supported_chains(mut self, ids: &'static [u64]) -> Self {
        self.supported = ids;
        self
    }

    pub fn with_health(mut self, h: HealthStatus) -> Self {
        self.health = h;
        self
    }

    pub fn submissions(&self) -> Vec<Bytes> {
        self.submissions.lock().clone()
    }
}

#[async_trait]
impl PrivateRpcProvider for MockPrivateRpcProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn supported_chains(&self) -> &'static [u64] {
        self.supported
    }

    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError> {
        self.submissions.lock().push(signed_raw_tx.clone());
        Ok(keccak256(signed_raw_tx))
    }

    async fn health(&self) -> Result<HealthStatus, PrivateRpcError> {
        Ok(self.health)
    }
}
```

Extend the `#[cfg(test)]` block:

```rust
    #[tokio::test]
    async fn mock_records_submissions_and_returns_keccak_hash() {
        let p = MockPrivateRpcProvider::new("mock");
        let raw = Bytes::from_static(b"\x01\x02\x03");
        let h = p.submit(&raw).await.unwrap();
        assert_eq!(h, keccak256(&raw));
        assert_eq!(p.submissions().len(), 1);
    }

    #[tokio::test]
    async fn mock_default_supports_mainnet_only() {
        let p = MockPrivateRpcProvider::new("mock");
        assert_eq!(p.supported_chains(), &[MAINNET_CHAIN_ID]);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bloom-mempool --lib private::tests`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/private.rs
git commit -m "feat(bloom-mempool): MockPrivateRpcProvider"
```

---

### Task 1.8: MEV/sandwich heuristic + DEX router fixtures

**Files:**
- Modify: `crates/bloom-mempool/src/heuristic.rs`
- Create: `crates/bloom-mempool/tests/fixtures/uniswap_v2_swap.hex`
- Create: `crates/bloom-mempool/tests/fixtures/uniswap_v2_zero_min.hex`

- [ ] **Step 1: Write the fixtures (hex calldata)**

Build the fixtures from the Uniswap V2 router `swapExactTokensForTokens` selector `0x38ed1739` with hand-built args. Write two files:

`crates/bloom-mempool/tests/fixtures/uniswap_v2_swap.hex` — a swap where `amountIn = 1e18`, `amountOutMin = 95e16` (95% — 500 bps slippage), `path = [tokenA, tokenB]`, `to = 0x...`, `deadline = u64::MAX`. Use the existing `bloom-tools` `abi.encode` helper at the REPL or generate via `cast calldata 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)' 1000000000000000000 950000000000000000 '[0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002]' 0x0000000000000000000000000000000000000003 18446744073709551615` and paste the resulting hex (without `0x`) into the file.

`crates/bloom-mempool/tests/fixtures/uniswap_v2_zero_min.hex` — same but `amountOutMin = 0` and `amountIn = 5e18`.

- [ ] **Step 2: Write the failing test**

Replace `crates/bloom-mempool/src/heuristic.rs` with:

```rust
//! Stage-time MEV/sandwich heuristic. Pure function over a staged tx.

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde::{Deserialize, Serialize};

sol! {
    #[allow(missing_docs)]
    interface IUniswapV2Router {
        function swapExactTokensForTokens(
            uint256 amountIn,
            uint256 amountOutMin,
            address[] calldata path,
            address to,
            uint256 deadline
        ) external returns (uint256[] memory amounts);

        function swapExactETHForTokens(
            uint256 amountOutMin,
            address[] calldata path,
            address to,
            uint256 deadline
        ) external payable returns (uint256[] memory amounts);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MevRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevRiskReport {
    pub risk: MevRisk,
    pub checks: Vec<String>,
    pub advice: String,
}

#[derive(Debug, Clone, Copy)]
pub struct HeuristicConfig {
    /// Warn if `(quoted - amountOutMin) / quoted` exceeds this (bps).
    pub max_slippage_bps: u32,
    /// Always flag high when amountIn (in wei or token units) exceeds
    /// this AND amountOutMin is zero.
    pub zero_min_amount_in_threshold: U256,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            max_slippage_bps: 100,
            zero_min_amount_in_threshold: U256::from(10u64).pow(U256::from(18u64)),
        }
    }
}

/// Quote oracle — abstracted so tests can inject a deterministic
/// quoter. Production wires this to `bloom-prices` or a direct
/// `eth_call` against a known quoter contract.
pub trait QuoteOracle: Send + Sync {
    /// Returns the expected output amount for `amount_in` of `path[0]`
    /// swapped along `path`, at the current block.
    fn quote(&self, amount_in: U256, path: &[Address]) -> Option<U256>;
}

pub struct StaticQuoter(pub U256);

impl QuoteOracle for StaticQuoter {
    fn quote(&self, _amount_in: U256, _path: &[Address]) -> Option<U256> {
        Some(self.0)
    }
}

pub fn evaluate(
    calldata: &Bytes,
    value: U256,
    cfg: &HeuristicConfig,
    quoter: &dyn QuoteOracle,
) -> MevRiskReport {
    // Try Uniswap V2 swapExactTokensForTokens.
    if let Ok(c) = IUniswapV2Router::swapExactTokensForTokensCall::abi_decode(calldata) {
        return evaluate_swap(c.amountIn, c.amountOutMin, &c.path, cfg, quoter);
    }
    // Try Uniswap V2 swapExactETHForTokens — amountIn comes from `value`.
    if let Ok(c) = IUniswapV2Router::swapExactETHForTokensCall::abi_decode(calldata) {
        return evaluate_swap(value, c.amountOutMin, &c.path, cfg, quoter);
    }

    MevRiskReport {
        risk: MevRisk::Low,
        checks: vec!["calldata_not_a_known_swap"],
        advice: String::new(),
    }
}

fn evaluate_swap(
    amount_in: U256,
    amount_out_min: U256,
    path: &[Address],
    cfg: &HeuristicConfig,
    quoter: &dyn QuoteOracle,
) -> MevRiskReport {
    let mut checks = Vec::new();
    let mut risk = MevRisk::Low;
    let mut advice = String::new();

    // Check 2 first (cheap, no oracle call).
    if amount_out_min.is_zero() && amount_in >= cfg.zero_min_amount_in_threshold {
        checks.push("amount_out_min_zero");
        risk = MevRisk::High;
        advice = format!(
            "amountOutMin is zero for amountIn = {}; the swap accepts any output. \
             Set amountOutMin to at least 99% of the current quote.",
            amount_in
        );
        return MevRiskReport { risk, checks, advice };
    }

    // Check 1: slippage exposure vs current quote.
    if let Some(quote) = quoter.quote(amount_in, path) {
        if quote.is_zero() {
            checks.push("quote_unavailable");
        } else if amount_out_min < quote {
            let diff = quote - amount_out_min;
            // bps = diff * 10_000 / quote
            let bps = diff.saturating_mul(U256::from(10_000u64)) / quote;
            checks.push("slippage_exposure");
            if bps > U256::from(cfg.max_slippage_bps) {
                risk = MevRisk::High;
                advice = format!(
                    "amountOutMin is {} bps below current quote (threshold {}); \
                     tighten slippage or route through a private RPC.",
                    bps, cfg.max_slippage_bps
                );
            }
        }
    } else {
        checks.push("quote_unavailable");
    }

    MevRiskReport { risk, checks, advice }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::hex;

    fn load_fixture(name: &str) -> Bytes {
        let path = format!("tests/fixtures/{name}");
        let hex_str = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        Bytes::from(hex::decode(hex_str.trim()).unwrap())
    }

    #[test]
    fn unknown_calldata_is_low_risk() {
        let cfg = HeuristicConfig::default();
        let q = StaticQuoter(U256::ZERO);
        let r = evaluate(&Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]), U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::Low);
        assert!(r.checks.iter().any(|s| s == "calldata_not_a_known_swap"));
    }

    #[test]
    fn uniswap_v2_swap_with_500bps_slippage_is_high_at_default_threshold() {
        let cfg = HeuristicConfig::default(); // max_slippage_bps = 100
        let quoted: U256 = U256::from(10u64).pow(U256::from(18u64)); // 1e18 expected out
        let q = StaticQuoter(quoted);
        let cd = load_fixture("uniswap_v2_swap.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::High);
        assert!(r.checks.iter().any(|s| s == "slippage_exposure"));
    }

    #[test]
    fn uniswap_v2_swap_with_500bps_slippage_is_low_when_threshold_relaxed() {
        let cfg = HeuristicConfig { max_slippage_bps: 1_000, ..HeuristicConfig::default() };
        let quoted: U256 = U256::from(10u64).pow(U256::from(18u64));
        let q = StaticQuoter(quoted);
        let cd = load_fixture("uniswap_v2_swap.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::Low);
    }

    #[test]
    fn zero_amount_out_min_above_threshold_is_high() {
        let cfg = HeuristicConfig::default();
        let q = StaticQuoter(U256::ZERO);
        let cd = load_fixture("uniswap_v2_zero_min.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::High);
        assert!(r.checks.iter().any(|s| s == "amount_out_min_zero"));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-mempool --lib heuristic::tests`
Expected: 4 tests pass. If fixture decoding fails, regenerate the hex using `cast calldata` (see Step 1) and check the file contains no trailing newline issues.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/heuristic.rs crates/bloom-mempool/tests/fixtures/
git commit -m "feat(bloom-mempool): stage-time MEV/sandwich slippage heuristic"
```

---

### Task 1.9: `bump::compute_replacement_fees` — EIP-1559 +12.5% math

**Files:**
- Modify: `crates/bloom-mempool/src/bump.rs`

- [ ] **Step 1: Write the failing test first**

Replace `crates/bloom-mempool/src/bump.rs` with:

```rust
//! Gas-bump fee math (EIP-1559 MIN_REPLACEMENT_FEE_INCREASE = 12.5%).

use crate::provider::TxFees;

/// Compute the replacement fees that satisfy EIP-1559's minimum
/// 12.5% increase rule. Rounds up so the result is always strictly
/// greater than the original.
///
/// For legacy txs, `gasPrice` is bumped by 12.5%.
/// For 1559 txs, **both** `maxFeePerGas` and `maxPriorityFeePerGas`
/// are bumped by 12.5%.
pub fn compute_replacement_fees(original: TxFees) -> TxFees {
    match original {
        TxFees::Legacy { gas_price } => TxFees::Legacy { gas_price: bump_125(gas_price) },
        TxFees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => TxFees::Eip1559 {
            max_fee_per_gas: bump_125(max_fee_per_gas),
            max_priority_fee_per_gas: bump_125(max_priority_fee_per_gas),
        },
    }
}

/// Multiply `v` by 1.125, rounding up.
///   bumped = ceil(v * 9 / 8)
fn bump_125(v: u128) -> u128 {
    let bumped = v.saturating_mul(9) / 8;
    // Ceil: if there's any remainder, add 1. Detect by checking
    // whether the truncated quotient × 8 equals v × 9.
    let exact = v.saturating_mul(9);
    if bumped.saturating_mul(8) == exact {
        // Bumped was exact, but EIP-1559 requires STRICTLY > original
        // when v > 0. Bumped is already > v for any v > 0 (since 9/8 > 1),
        // so no adjustment needed here. However, when v = 0 we return 1
        // to keep the post-condition `bumped > v` after a stuck tx with
        // zero priority fee.
        if v == 0 { 1 } else { bumped }
    } else {
        bumped + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_bumps_125_percent_rounded_up() {
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: 100 });
        match f {
            TxFees::Legacy { gas_price } => assert_eq!(gas_price, 113), // 100 * 9/8 = 112.5 → 113
            _ => panic!("expected legacy"),
        }
    }

    #[test]
    fn legacy_exact_multiple_of_eight_no_extra_rounding() {
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: 80 });
        match f {
            TxFees::Legacy { gas_price } => assert_eq!(gas_price, 90), // 80*9/8 = 90 exactly
            _ => panic!("expected legacy"),
        }
    }

    #[test]
    fn eip1559_bumps_both_fields() {
        let f = compute_replacement_fees(TxFees::Eip1559 {
            max_fee_per_gas: 50_000_000_000,    // 50 gwei
            max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        });
        match f {
            TxFees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
                assert_eq!(max_fee_per_gas, 56_250_000_000);    // 50*9/8 = 56.25 gwei
                assert_eq!(max_priority_fee_per_gas, 1_125_000_000); // 1*9/8 = 1.125 gwei
            }
            _ => panic!("expected 1559"),
        }
    }

    #[test]
    fn one_wei_bumps_to_two() {
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: 1 });
        match f {
            TxFees::Legacy { gas_price } => assert_eq!(gas_price, 2),
            _ => panic!("expected legacy"),
        }
    }

    #[test]
    fn zero_bumps_to_one() {
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: 0 });
        match f {
            TxFees::Legacy { gas_price } => assert_eq!(gas_price, 1),
            _ => panic!("expected legacy"),
        }
    }

    #[test]
    fn very_large_does_not_overflow() {
        let near_max = u128::MAX / 10;
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: near_max });
        match f {
            TxFees::Legacy { gas_price } => assert!(gas_price > near_max),
            _ => panic!("expected legacy"),
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bloom-mempool --lib bump::tests`
Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/bump.rs
git commit -m "feat(bloom-mempool): EIP-1559 +12.5%% replacement-fee math"
```

---

# Phase 2 — VFS surface

Produces the `chains/<chain>/mempool/` read tree and the new wallet-side artefacts, backed by the mocks from Phase 1. End of phase: an integration test mounts a `Vfs` with a `MockMempoolProvider` plugged in and reads each new path.

---

### Task 2.1: `chains_mempool.rs` handler skeleton (status.json only)

**Files:**
- Create: `crates/bloom-vfs/src/handlers/chains_mempool.rs`
- Modify: `crates/bloom-vfs/src/handlers/mod.rs`
- Modify: `crates/bloom-vfs/Cargo.toml` (add `bloom-mempool` dep)

- [ ] **Step 1: Add the dependency**

In `crates/bloom-vfs/Cargo.toml`, under `[dependencies]`, add:

```toml
bloom-mempool.workspace = true
```

And in the workspace `Cargo.toml` `[workspace.dependencies]`:

```toml
bloom-mempool = { path = "crates/bloom-mempool" }
```

- [ ] **Step 2: Add module declaration**

In `crates/bloom-vfs/src/handlers/mod.rs`, add (alphabetically among existing `pub mod` lines):

```rust
pub mod chains_mempool;
```

- [ ] **Step 3: Write the failing test first (in-crate integration test)**

Create `crates/bloom-vfs/src/handlers/chains_mempool.rs`:

```rust
//! Handler for `chains/<chain>/mempool/...`. Backed by a
//! `MempoolStream` from `bloom-mempool` (or a `MockMempoolProvider`
//! in tests).

use std::sync::Arc;

use async_trait::async_trait;
use bloom_mempool::{PendingTxIndex, PendingTx};
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Debug, Clone, Copy)]
pub enum SubscriptionState {
    Subscribed,
    Disconnected,
    NotConfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStatus {
    pub provider: String,
    pub subscribed: bool,
    pub observed_pending: u64,
    pub uptime_sec: u64,
    pub dropped_count: u64,
    pub evictions_total: u64,
    pub stale_for_secs: u64,
}

/// Per-chain mempool surface. The daemon constructs one instance per
/// chain that has a configured `[mempool.<chain>]` provider.
pub struct MempoolHandler {
    chain_name: String,
    index: Arc<PendingTxIndex>,
    provider_id: String,
    started_at: std::time::SystemTime,
    state: parking_lot::RwLock<SubscriptionState>,
    dropped: std::sync::atomic::AtomicU64,
    last_event_at: parking_lot::RwLock<std::time::SystemTime>,
}

impl MempoolHandler {
    pub fn new(chain_name: impl Into<String>, provider_id: impl Into<String>, index: Arc<PendingTxIndex>) -> Self {
        Self {
            chain_name: chain_name.into(),
            index,
            provider_id: provider_id.into(),
            started_at: std::time::SystemTime::now(),
            state: parking_lot::RwLock::new(SubscriptionState::Disconnected),
            dropped: std::sync::atomic::AtomicU64::new(0),
            last_event_at: parking_lot::RwLock::new(std::time::SystemTime::now()),
        }
    }

    pub fn set_state(&self, state: SubscriptionState) {
        *self.state.write() = state;
    }

    pub fn note_event(&self) {
        *self.last_event_at.write() = std::time::SystemTime::now();
    }

    pub fn increment_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    fn status(&self) -> MempoolStatus {
        let subscribed = matches!(*self.state.read(), SubscriptionState::Subscribed);
        MempoolStatus {
            provider: self.provider_id.clone(),
            subscribed,
            observed_pending: self.index.len() as u64,
            uptime_sec: self.started_at.elapsed().map(|d| d.as_secs()).unwrap_or(0),
            dropped_count: self.dropped.load(std::sync::atomic::Ordering::Relaxed),
            evictions_total: self.index.evictions_total(),
            stale_for_secs: self.last_event_at.read().elapsed().map(|d| d.as_secs()).unwrap_or(0),
        }
    }
}

#[async_trait]
impl Handler for MempoolHandler {
    async fn list(&self, _path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        Ok(vec![
            Entry::read_only_file("status.json"),
            Entry::read_only_file("recent.jsonl"),
            Entry::read_only_file("live"),
            Entry::dir("by_address"),
            Entry::dir("by_pool"),
        ])
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs.as_slice() {
            [_chain, "mempool", "status.json"] => {
                let s = self.status();
                Ok(serde_json::to_vec_pretty(&s).map_err(|e| HandlerError::backend(e.to_string()))?)
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
        Err(HandlerError::invalid("mempool is read-only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler() -> MempoolHandler {
        MempoolHandler::new("ethereum", "mock", PendingTxIndex::new(64))
    }

    #[tokio::test]
    async fn status_json_returns_disconnected_by_default() {
        let h = make_handler();
        let p = VfsPath::parse("chains/ethereum/mempool/status.json").unwrap();
        let body = h.read(&p).await.unwrap();
        let s: MempoolStatus = serde_json::from_slice(&body).unwrap();
        assert_eq!(s.provider, "mock");
        assert!(!s.subscribed);
        assert_eq!(s.observed_pending, 0);
    }

    #[tokio::test]
    async fn status_json_reflects_subscribed_state() {
        let h = make_handler();
        h.set_state(SubscriptionState::Subscribed);
        let p = VfsPath::parse("chains/ethereum/mempool/status.json").unwrap();
        let body = h.read(&p).await.unwrap();
        let s: MempoolStatus = serde_json::from_slice(&body).unwrap();
        assert!(s.subscribed);
    }
}
```

If `VfsPath::parse` doesn't exist under that name, check `crates/bloom-vfs/src/path.rs` for the correct constructor — likely `VfsPath::from_str` or `try_from`. Use whichever the existing handlers use (grep `crates/bloom-vfs/src/handlers/chains.rs` for `VfsPath::` to confirm).

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests`
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/Cargo.toml crates/bloom-vfs/src/handlers/mod.rs crates/bloom-vfs/src/handlers/chains_mempool.rs Cargo.toml
git commit -m "feat(bloom-vfs): chains_mempool handler skeleton with status.json"
```

---

### Task 2.2: `recent.jsonl` ring buffer

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/chains_mempool.rs`

- [ ] **Step 1: Extend the handler with a ring buffer**

Inside `chains_mempool.rs`, add a `RingBuffer` field on `MempoolHandler`:

```rust
const RECENT_RING_CAPACITY: usize = 500;

struct RingBuffer {
    items: std::collections::VecDeque<PendingTx>,
    capacity: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self { items: std::collections::VecDeque::with_capacity(capacity), capacity }
    }
    fn push(&mut self, tx: PendingTx) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(tx);
    }
    fn snapshot(&self) -> Vec<PendingTx> {
        self.items.iter().cloned().collect()
    }
}
```

Add to `MempoolHandler`:

```rust
    recent: parking_lot::RwLock<RingBuffer>,
```

And initialise it in `new`:

```rust
            recent: parking_lot::RwLock::new(RingBuffer::new(RECENT_RING_CAPACITY)),
```

Add an ingestion method:

```rust
    pub fn ingest(&self, tx: PendingTx) {
        self.recent.write().push(tx.clone());
        self.index.insert(tx);
        self.note_event();
    }
```

Add the `recent.jsonl` read branch to the `match` in `read()`:

```rust
            [_chain, "mempool", "recent.jsonl"] => {
                let items = self.recent.read().snapshot();
                let mut out = Vec::new();
                for it in &items {
                    serde_json::to_writer(&mut out, it)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    out.push(b'\n');
                }
                Ok(out)
            }
```

- [ ] **Step 2: Write the failing test**

Add to the `tests` module:

```rust
    use alloy::primitives::{Address, B256, Bytes, U256};
    use bloom_mempool::{PendingTx, TxFees};

    fn fixture_tx(hash_byte: u8) -> PendingTx {
        let mut h = [0u8; 32];
        h[0] = hash_byte;
        PendingTx {
            hash: B256::from(h),
            from: Address::ZERO,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn recent_jsonl_returns_ingested_items_in_order() {
        let h = make_handler();
        h.ingest(fixture_tx(1));
        h.ingest(fixture_tx(2));
        let p = VfsPath::parse("chains/ethereum/mempool/recent.jsonl").unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body.split(|c| *c == b'\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(lines.len(), 2);
        let first: PendingTx = serde_json::from_slice(lines[0]).unwrap();
        let second: PendingTx = serde_json::from_slice(lines[1]).unwrap();
        assert_eq!(first.hash, B256::from({ let mut a = [0u8; 32]; a[0] = 1; a }));
        assert_eq!(second.hash, B256::from({ let mut a = [0u8; 32]; a[0] = 2; a }));
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests`
Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/src/handlers/chains_mempool.rs
git commit -m "feat(bloom-vfs): chains_mempool recent.jsonl ring buffer"
```

---

### Task 2.3: `live` long-poll tail

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/chains_mempool.rs`

- [ ] **Step 1: Add a broadcast sender to the handler**

Add to `MempoolHandler`:

```rust
    live_tx: tokio::sync::broadcast::Sender<PendingTx>,
```

In `new`, after the existing initialisations, add:

```rust
            live_tx: tokio::sync::broadcast::channel(4096).0,
```

Modify `ingest` to also broadcast:

```rust
    pub fn ingest(&self, tx: PendingTx) {
        self.recent.write().push(tx.clone());
        self.index.insert(tx.clone());
        let _ = self.live_tx.send(tx);
        self.note_event();
    }
```

- [ ] **Step 2: Add the `live` read branch**

Inside the `match` in `read()`:

```rust
            [_chain, "mempool", "live"] => {
                // Long-poll: subscribe, then read for up to ~25s
                // (mirroring the NFS client read timeout) and accumulate
                // newly-broadcast items. If nothing arrives, return the
                // empty body so the client re-issues.
                let mut rx = self.live_tx.subscribe();
                let mut out = Vec::new();
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
                loop {
                    let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
                        Some(d) => d,
                        None => break,
                    };
                    let recv = tokio::time::timeout(remaining, rx.recv()).await;
                    match recv {
                        Ok(Ok(tx)) => {
                            serde_json::to_writer(&mut out, &tx)
                                .map_err(|e| HandlerError::backend(e.to_string()))?;
                            out.push(b'\n');
                            // After receiving one item, keep draining
                            // for up to 200 ms to coalesce bursts.
                            let burst_end = tokio::time::Instant::now()
                                + std::time::Duration::from_millis(200);
                            while let Ok(Ok(more)) =
                                tokio::time::timeout(
                                    burst_end.duration_since(tokio::time::Instant::now()),
                                    rx.recv(),
                                ).await
                            {
                                serde_json::to_writer(&mut out, &more)
                                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                                out.push(b'\n');
                            }
                            break;
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                            let lagged = serde_json::json!({"kind": "lagged", "skipped": n});
                            serde_json::to_writer(&mut out, &lagged)
                                .map_err(|e| HandlerError::backend(e.to_string()))?;
                            out.push(b'\n');
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                        Err(_) => break,
                    }
                }
                Ok(out)
            }
```

- [ ] **Step 3: Write the failing test**

Add:

```rust
    #[tokio::test]
    async fn live_tail_emits_ingested_items() {
        let h = Arc::new(make_handler());
        let h2 = Arc::clone(&h);
        let reader = tokio::spawn(async move {
            let p = VfsPath::parse("chains/ethereum/mempool/live").unwrap();
            h2.read(&p).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        h.ingest(fixture_tx(7));
        let body = tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("reader timeout")
            .expect("join")
            ;
        let lines: Vec<&[u8]> = body.split(|c| *c == b'\n').filter(|s| !s.is_empty()).collect();
        assert!(!lines.is_empty());
        let first: PendingTx = serde_json::from_slice(lines[0]).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 7;
        assert_eq!(first.hash, B256::from(expected));
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/src/handlers/chains_mempool.rs
git commit -m "feat(bloom-vfs): chains_mempool live long-poll tail"
```

---

### Task 2.4: `by_address/<addr>/{pending.jsonl, nonces.json}`

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/chains_mempool.rs`

- [ ] **Step 1: Add read branches**

Inside `read()` match, after the existing branches:

```rust
            [_chain, "mempool", "by_address", addr, "pending.jsonl"] => {
                let addr: alloy::primitives::Address = addr.parse()
                    .map_err(|e: alloy::primitives::AddressError| HandlerError::invalid(e.to_string()))?;
                let items = self.recent.read().snapshot();
                let mut out = Vec::new();
                for it in items.iter().filter(|t| t.from == addr || t.to == Some(addr)) {
                    serde_json::to_writer(&mut out, it)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [_chain, "mempool", "by_address", addr, "nonces.json"] => {
                let addr: alloy::primitives::Address = addr.parse()
                    .map_err(|e: alloy::primitives::AddressError| HandlerError::invalid(e.to_string()))?;
                let observed = self.index.observed_nonces(addr);
                let next_unused = observed.last().map(|n| n + 1).unwrap_or(0);
                let body = serde_json::json!({
                    "observed": observed,
                    "next_unused": next_unused,
                });
                Ok(serde_json::to_vec_pretty(&body)
                    .map_err(|e| HandlerError::backend(e.to_string()))?)
            }
```

If the alloy `AddressError` type name differs in the workspace's pinned alloy version, replace with `String`-based parsing (`alloy::primitives::Address::from_str(addr).map_err(|e| HandlerError::invalid(format!("{e}")))?`). Use `std::str::FromStr;` in the imports.

- [ ] **Step 2: Write the failing tests**

Add:

```rust
    #[tokio::test]
    async fn by_address_pending_filters_by_from_or_to() {
        let h = make_handler();
        let mut from_a = [0u8; 20];
        from_a[0] = 1;
        let a = Address::from(from_a);
        let mut t1 = fixture_tx(1);
        t1.from = a;
        let mut t2 = fixture_tx(2);
        t2.to = Some(a);
        let mut t3 = fixture_tx(3); // unrelated
        let mut other = [0u8; 20];
        other[0] = 9;
        t3.from = Address::from(other);
        h.ingest(t1);
        h.ingest(t2);
        h.ingest(t3);
        let p = VfsPath::parse(&format!("chains/ethereum/mempool/by_address/{a:?}/pending.jsonl"))
            .unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body.split(|c| *c == b'\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn by_address_nonces_json_reports_observed_and_next_unused() {
        let h = make_handler();
        let mut a = [0u8; 20];
        a[0] = 1;
        let addr = Address::from(a);
        let mut t1 = fixture_tx(1);
        t1.from = addr;
        t1.nonce = 4;
        let mut t2 = fixture_tx(2);
        t2.from = addr;
        t2.nonce = 6;
        h.ingest(t1);
        h.ingest(t2);
        let p = VfsPath::parse(&format!("chains/ethereum/mempool/by_address/{addr:?}/nonces.json"))
            .unwrap();
        let body = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["next_unused"], 7);
        assert_eq!(v["observed"], serde_json::json!([4, 6]));
    }
```

Confirm the alloy `Address` `Debug` impl prints in `0x…` form; if not, use `format!("0x{}", hex::encode(a))` instead of `{a:?}` to build the path.

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests`
Expected: 6 tests pass.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/src/handlers/chains_mempool.rs
git commit -m "feat(bloom-vfs): chains_mempool by_address/<a>/{pending,nonces}"
```

---

### Task 2.5: `by_pool/<addr>/recent.jsonl`

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/chains_mempool.rs`
- Modify: `crates/bloom-mempool/src/heuristic.rs` (export the swap-decode helper)

- [ ] **Step 1: Export a helper in `bloom-mempool` that extracts the `path`/router target**

In `crates/bloom-mempool/src/heuristic.rs`, add (above `evaluate`):

```rust
/// If the calldata decodes as a known DEX swap, return the addresses
/// in the path. `path[0]` is the input token; the router address
/// itself is the contract being called and is not in this list.
pub fn decode_swap_path(calldata: &Bytes) -> Option<Vec<Address>> {
    if let Ok(c) = IUniswapV2Router::swapExactTokensForTokensCall::abi_decode(calldata) {
        return Some(c.path.into_iter().collect());
    }
    if let Ok(c) = IUniswapV2Router::swapExactETHForTokensCall::abi_decode(calldata) {
        return Some(c.path.into_iter().collect());
    }
    None
}
```

Add a unit test:

```rust
    #[test]
    fn decode_swap_path_returns_path_addresses() {
        let cd = load_fixture("uniswap_v2_swap.hex");
        let path = decode_swap_path(&cd).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].as_slice()[0], 0); // tokenA leading zeros
    }
```

- [ ] **Step 2: Add `by_pool` branch to the VFS handler**

In `chains_mempool.rs` `read()`:

```rust
            [_chain, "mempool", "by_pool", pool, "recent.jsonl"] => {
                let pool: alloy::primitives::Address = pool.parse()
                    .map_err(|e| HandlerError::invalid(format!("{e}")))?;
                let items = self.recent.read().snapshot();
                let mut out = Vec::new();
                for it in &items {
                    let to_match = it.to == Some(pool);
                    let path_match = bloom_mempool::heuristic::decode_swap_path(&it.input)
                        .map(|p| p.contains(&pool))
                        .unwrap_or(false);
                    if to_match || path_match {
                        serde_json::to_writer(&mut out, it)
                            .map_err(|e| HandlerError::backend(e.to_string()))?;
                        out.push(b'\n');
                    }
                }
                Ok(out)
            }
```

Also re-export `heuristic` in `bloom-mempool/src/lib.rs`:

```rust
pub use heuristic::{HeuristicConfig, MevRisk, MevRiskReport, QuoteOracle, StaticQuoter, evaluate, decode_swap_path};
```

- [ ] **Step 3: Write the failing test**

Add to `chains_mempool.rs` tests:

```rust
    #[tokio::test]
    async fn by_pool_includes_txs_with_pool_in_swap_path() {
        let h = make_handler();
        let mut pool_bytes = [0u8; 20];
        pool_bytes[0] = 2; // matches the second address in uniswap_v2_swap.hex (0x00…02)
        let pool = Address::from(pool_bytes);
        let mut t = fixture_tx(1);
        t.input = Bytes::from(
            hex::decode(
                std::fs::read_to_string("../bloom-mempool/tests/fixtures/uniswap_v2_swap.hex")
                    .unwrap()
                    .trim(),
            )
            .unwrap(),
        );
        h.ingest(t);
        let p = VfsPath::parse(&format!("chains/ethereum/mempool/by_pool/{pool:?}/recent.jsonl"))
            .unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body.split(|c| *c == b'\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(lines.len(), 1);
    }
```

If `hex` isn't already a dev-dep in `bloom-vfs`, add it. The fixture path relative to the crate root may need adjusting (run `cargo test` and follow the error).

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests && cargo test -p bloom-mempool --lib heuristic::tests`
Expected: 7 + 5 tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-mempool/src/heuristic.rs crates/bloom-mempool/src/lib.rs crates/bloom-vfs/src/handlers/chains_mempool.rs crates/bloom-vfs/Cargo.toml
git commit -m "feat(bloom-vfs): chains_mempool by_pool/<addr>/recent.jsonl"
```

---

### Task 2.6: `<tx_hash>/{tx.json, decoded.json, status}`

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/chains_mempool.rs`

- [ ] **Step 1: Add JIT directory entries + read branches**

Add to the existing handler. Detection: if the third path segment is a 0x-hex hash of length 66, treat it as a tx-hash subdir.

In `list()`, when given a path with three segments ending in `mempool`, also enumerate any indexed hashes (capped at the ring snapshot to avoid unbounded `ls`):

```rust
        let segs = _path.segments();
        if segs.len() == 2 && segs[1] == "mempool" {
            return Ok(vec![
                Entry::read_only_file("status.json"),
                Entry::read_only_file("recent.jsonl"),
                Entry::read_only_file("live"),
                Entry::dir("by_address"),
                Entry::dir("by_pool"),
                // hash-subdirs are JIT — not enumerated in list() to
                // avoid 50k-entry directories.
            ]);
        }
        // Default: empty list (JIT dirs)
        Ok(Vec::new())
```

In `read()`, after existing branches, add:

```rust
            [_chain, "mempool", hash, leaf] if is_hash_segment(hash) => {
                let h_bytes = parse_hash(hash)?;
                let rec = self.index.lookup_by_hash(&h_bytes)
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                match *leaf {
                    "tx.json" => Ok(serde_json::to_vec_pretty(&rec.tx)
                        .map_err(|e| HandlerError::backend(e.to_string()))?),
                    "decoded.json" => {
                        let decoded = bloom_mempool::decode_swap_path(&rec.tx.input)
                            .map(|p| serde_json::json!({"kind": "swap", "path": p}))
                            .unwrap_or(serde_json::Value::Null);
                        Ok(serde_json::to_vec_pretty(&decoded)
                            .map_err(|e| HandlerError::backend(e.to_string()))?)
                    }
                    "status" => Ok(b"pending\n".to_vec()),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
```

Add helpers above the impl:

```rust
fn is_hash_segment(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hash(s: &str) -> Result<alloy::primitives::B256, HandlerError> {
    let bytes = hex::decode(&s[2..]).map_err(|e| HandlerError::invalid(e.to_string()))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| HandlerError::invalid("hash must be 32 bytes"))?;
    Ok(alloy::primitives::B256::from(arr))
}
```

- [ ] **Step 2: Write the failing test**

```rust
    #[tokio::test]
    async fn tx_hash_subtree_returns_tx_json_and_status() {
        let h = make_handler();
        let t = fixture_tx(0xab);
        let hash = t.hash;
        h.ingest(t.clone());
        let hex_hash = format!("0x{}", hex::encode(hash.as_slice()));
        let p_tx = VfsPath::parse(&format!("chains/ethereum/mempool/{hex_hash}/tx.json")).unwrap();
        let p_st = VfsPath::parse(&format!("chains/ethereum/mempool/{hex_hash}/status")).unwrap();
        let body_tx = h.read(&p_tx).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_tx).unwrap();
        assert_eq!(v["nonce"], 0);
        let body_st = h.read(&p_st).await.unwrap();
        assert_eq!(String::from_utf8(body_st).unwrap().trim(), "pending");
    }

    #[tokio::test]
    async fn tx_hash_subtree_not_found_for_unknown_hash() {
        let h = make_handler();
        let p = VfsPath::parse(
            "chains/ethereum/mempool/0x0000000000000000000000000000000000000000000000000000000000000000/tx.json",
        )
        .unwrap();
        let err = h.read(&p).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)) || format!("{err:?}").contains("not"));
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::chains_mempool::tests`
Expected: 9 tests pass.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/src/handlers/chains_mempool.rs
git commit -m "feat(bloom-vfs): chains_mempool <hash>/{tx,decoded,status}"
```

---

### Task 2.7: `wallets/<w>/chains/<c>/pending_external.jsonl` and `nonce_conflicts.json`

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/wallets.rs`
- Test: same file (inline)

- [ ] **Step 1: Locate the existing wallet/chain handler**

Read `crates/bloom-vfs/src/handlers/wallets.rs` to find the `match` arm that serves `wallets/<w>/chains/<c>/...`. The new branches go alongside `balance`, `nonce`, `activity/recent.jsonl`.

- [ ] **Step 2: Add a constructor parameter that takes the per-chain `PendingTxIndex`**

The `WalletsHandler` struct (or whatever it's called — check the file) needs access to the per-chain index. Add a field:

```rust
    mempool_indexes: std::collections::BTreeMap<String, std::sync::Arc<bloom_mempool::PendingTxIndex>>,
```

Constructor signature gets an additional argument; default is an empty map. Update the daemon-side wiring in Phase 3 / Phase 4.

- [ ] **Step 3: Write the failing test**

Add to the existing wallets test module — model the new test after the existing wallet `balance` test (search the file for `async fn balance` and copy its setup pattern). The new test:

```rust
    #[tokio::test]
    async fn pending_external_includes_index_txs_for_wallet_address() {
        // Set up: wallet with address A, ingest pending tx with from = A into the index.
        // Assert: read of wallets/<w>/chains/<c>/pending_external.jsonl returns that tx.
    }
```

Fill in the body using the same setup pattern as the existing test (likely involves a `TempDir` + a wallet manifest file + an `Address` field).

- [ ] **Step 4: Implement the branches**

```rust
            [_, wallet, "chains", chain, "pending_external.jsonl"] => {
                let idx = match self.mempool_indexes.get(*chain) {
                    Some(i) => i,
                    None => return Ok(Vec::new()),
                };
                let addr = self.wallet_address(wallet)?;
                // Iterate all observed txs and filter by from == addr that
                // we did NOT stage ourselves (i.e., absent from outbox).
                // For now, the "did NOT stage" check is best-effort: any
                // tx in the index whose hash doesn't appear in `outbox/sent/`
                // is treated as external. We accept some over-reporting in
                // v1 (the outbox-hash check is plumbed in Phase 3).
                let mut out = Vec::new();
                // Walk the index — exposed via a snapshot method we add below.
                for tx in idx.snapshot().into_iter().filter(|t| t.from == addr) {
                    serde_json::to_writer(&mut out, &tx)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [_, wallet, "chains", chain, "nonce_conflicts.json"] => {
                let idx = match self.mempool_indexes.get(*chain) {
                    Some(i) => i,
                    None => return Ok(b"{\"conflicts\":[]}".to_vec()),
                };
                let addr = self.wallet_address(wallet)?;
                let observed = idx.observed_nonces(addr);
                let body = serde_json::json!({
                    "address": format!("0x{}", hex::encode(addr.as_slice())),
                    "observed_nonces": observed,
                });
                Ok(serde_json::to_vec_pretty(&body)
                    .map_err(|e| HandlerError::backend(e.to_string()))?)
            }
```

`self.wallet_address(...)` is whatever helper the existing handler uses — adapt to the file's actual API. Add `snapshot()` to `PendingTxIndex`:

```rust
    pub fn snapshot(&self) -> Vec<PendingTx> {
        self.inner.read().by_hash.values().map(|r| r.tx.clone()).collect()
    }
```

(plus a unit test in `index.rs`).

- [ ] **Step 5: Run tests**

Run: `cargo test -p bloom-vfs --lib && cargo test -p bloom-mempool --lib`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-mempool/src/index.rs crates/bloom-vfs/src/handlers/wallets.rs
git commit -m "feat(bloom-vfs): wallet pending_external + nonce_conflicts views"
```

---

### Task 2.8: `status/backends/mempool` and `status/backends/private_rpc`

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/status.rs`

- [ ] **Step 1: Locate the existing status/backends handler**

Read `crates/bloom-vfs/src/handlers/status.rs` to find the existing backend declaration leaves (`contract_metadata`, `address_history`, `event_logs`, `storage_reads`, `proxy_detection`). The new leaves go alongside.

- [ ] **Step 2: Add data sources**

The status handler needs a snapshot of:
- per-chain mempool provider name + subscribed status
- per-(chain, provider) private RPC health

Add these as fields on the status handler:

```rust
    mempool_statuses: std::sync::Arc<parking_lot::RwLock<BTreeMap<String, MempoolBackendStatus>>>,
    private_rpc_healths: std::sync::Arc<parking_lot::RwLock<BTreeMap<(String, String), PrivateRpcBackendStatus>>>,
```

Define the structs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolBackendStatus {
    pub provider: String,
    pub subscribed: bool,
    pub fallback_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateRpcBackendStatus {
    pub last_status: String,    // "healthy" | "degraded" | "unhealthy"
    pub last_probed_at: u64,    // unix secs
}
```

- [ ] **Step 3: Add the new read branches**

```rust
            [_, "backends", "mempool"] => {
                let map = self.mempool_statuses.read().clone();
                Ok(serde_json::to_vec_pretty(&map)
                    .map_err(|e| HandlerError::backend(e.to_string()))?)
            }
            [_, "backends", "private_rpc"] => {
                let map = self.private_rpc_healths.read();
                let json: BTreeMap<String, BTreeMap<String, &PrivateRpcBackendStatus>> = {
                    let mut out: BTreeMap<String, BTreeMap<String, &PrivateRpcBackendStatus>> = BTreeMap::new();
                    for ((chain, prov), v) in map.iter() {
                        out.entry(chain.clone()).or_default().insert(prov.clone(), v);
                    }
                    out
                };
                Ok(serde_json::to_vec_pretty(&json)
                    .map_err(|e| HandlerError::backend(e.to_string()))?)
            }
            [_, "private_rpc", provider] => {
                let map = self.private_rpc_healths.read();
                let any = map.iter().find(|((_, p), _)| p == provider).map(|(_, v)| v);
                match any {
                    Some(v) => Ok(serde_json::to_vec_pretty(v)
                        .map_err(|e| HandlerError::backend(e.to_string()))?),
                    None => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
```

- [ ] **Step 4: Write the failing tests**

Mirror the existing tests in `status.rs` — find one that exercises `backends/contract_metadata` and copy the setup, swapping the leaf and the data source.

- [ ] **Step 5: Run tests**

Run: `cargo test -p bloom-vfs --lib handlers::status::tests`
Expected: existing tests still pass + new tests pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-vfs --all-targets -- -D warnings
git add crates/bloom-vfs/src/handlers/status.rs
git commit -m "feat(bloom-vfs): status/backends/{mempool,private_rpc} + status/private_rpc/<p>"
```

---

# Phase 3 — Tx-engine integration

Wires the new logic into `tx_engine::stage`, `tx_engine::broadcast`, and adds the `BumpScanner` background task. All work uses mocks from Phase 1; no real provider code yet.

---

### Task 3.1: Policy schema additions

**Files:**
- Modify: `crates/bloom-tx/src/policy_engine.rs`
- Modify: `crates/bloom-proto/src/...` (where `Policy` struct lives)

- [ ] **Step 1: Locate Policy struct**

```bash
grep -rn "pub struct Policy" crates/bloom-proto/src/
```

- [ ] **Step 2: Add the new fields with backward-compatible defaults**

In the `Policy` struct definition, add:

```rust
    #[serde(default)]
    pub private: PrivatePolicy,
    #[serde(default)]
    pub mev: MevPolicy,
    #[serde(default)]
    pub bump: BumpPolicy,
```

Define the sub-structs in the same file:

```rust
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PrivatePolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_private_provider")]
    pub provider: String,
}

fn default_private_provider() -> String {
    "mev_blocker".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MevPolicy {
    #[serde(default = "default_max_slippage_bps")]
    pub max_slippage_bps: u32,
    #[serde(default)]
    pub fail_on_high_risk: bool,
}

impl Default for MevPolicy {
    fn default() -> Self {
        Self { max_slippage_bps: 100, fail_on_high_risk: false }
    }
}

fn default_max_slippage_bps() -> u32 { 100 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BumpPolicy {
    #[serde(default = "default_stuck_after_secs")]
    pub stuck_after_secs: u64,
    #[serde(default = "default_basefee_overrun_pct")]
    pub basefee_overrun_pct: u32,
}

impl Default for BumpPolicy {
    fn default() -> Self {
        Self { stuck_after_secs: 90, basefee_overrun_pct: 20 }
    }
}

fn default_stuck_after_secs() -> u64 { 90 }
fn default_basefee_overrun_pct() -> u32 { 20 }
```

- [ ] **Step 3: Write the failing test**

In the `policy_engine.rs` test module (or wherever the `Policy` round-trip tests live):

```rust
    #[test]
    fn policy_defaults_when_new_sections_missing() {
        let toml_src = "max_eth_per_tx = 0.1";
        let p: Policy = toml::from_str(toml_src).unwrap();
        assert!(!p.private.enabled);
        assert_eq!(p.private.provider, "mev_blocker");
        assert_eq!(p.mev.max_slippage_bps, 100);
        assert_eq!(p.bump.stuck_after_secs, 90);
    }

    #[test]
    fn policy_parses_new_sections_when_present() {
        let toml_src = r#"
max_eth_per_tx = 0.1

[private]
enabled = true
provider = "flashbots"

[mev]
max_slippage_bps = 250
fail_on_high_risk = true

[bump]
stuck_after_secs = 30
basefee_overrun_pct = 50
"#;
        let p: Policy = toml::from_str(toml_src).unwrap();
        assert!(p.private.enabled);
        assert_eq!(p.private.provider, "flashbots");
        assert_eq!(p.mev.max_slippage_bps, 250);
        assert!(p.mev.fail_on_high_risk);
        assert_eq!(p.bump.stuck_after_secs, 30);
        assert_eq!(p.bump.basefee_overrun_pct, 50);
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-proto --lib && cargo test -p bloom-tx --lib`
Expected: existing tests still pass + new tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-proto/ crates/bloom-tx/src/policy_engine.rs
git commit -m "feat(bloom-proto): policy [private] [mev] [bump] schema"
```

---

### Task 3.2: Nonce-conflict check in `tx_engine::stage`

**Files:**
- Modify: `crates/bloom-tx/src/tx_engine.rs`
- Modify: `crates/bloom-tx/Cargo.toml`

- [ ] **Step 1: Add the dependency**

In `crates/bloom-tx/Cargo.toml`, add `bloom-mempool.workspace = true` under `[dependencies]`.

- [ ] **Step 2: Add an optional `PendingTxIndex` parameter to `stage`**

The `stage` method currently takes `(wallet, from, intent, chain, policy, address_book)`. Extending the signature breaks every caller. Instead: add a setter on `TxEngine` so the daemon registers the per-chain index map once at startup.

In `TxEngine`'s definition (search for `impl TxEngine`):

```rust
pub struct TxEngine {
    // ... existing fields
    mempool_indexes: parking_lot::RwLock<
        std::collections::BTreeMap<String, std::sync::Arc<bloom_mempool::PendingTxIndex>>,
    >,
}
```

Add a setter:

```rust
    pub fn set_mempool_index(&self, chain: impl Into<String>, idx: std::sync::Arc<bloom_mempool::PendingTxIndex>) {
        self.mempool_indexes.write().insert(chain.into(), idx);
    }
```

- [ ] **Step 3: Add a `NonceConflict` artefact writer in `outbox`**

In `crates/bloom-tx/src/outbox.rs`, add a method to `Outbox` that writes `pending/<id>/nonce_conflict.json`:

```rust
    pub fn write_nonce_conflict(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        body: &serde_json::Value,
    ) -> Result<(), OutboxError> {
        let dir = self.pending_dir(wallet, chain, id);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("nonce_conflict.json");
        std::fs::write(&path, serde_json::to_vec_pretty(body)?)?;
        Ok(())
    }
```

Use the existing `pending_dir` helper — search for `fn pending_dir` in the file.

- [ ] **Step 4: Wire the check into `stage`**

Inside `stage`, after the line `let nonce = match intent.nonce { ... }`, add:

```rust
        let chain_name = spec.name.clone();
        let conflict = self
            .mempool_indexes
            .read()
            .get(&chain_name)
            .and_then(|idx| idx.lookup_by_addr_nonce(from, nonce));
        if let Some(rec) = conflict {
            let body = serde_json::json!({
                "conflict_nonce": nonce,
                "external_hash": format!("0x{}", hex::encode(rec.tx.hash.as_slice())),
                "external_observed_at": rec.tx.observed_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                "advice": format!(
                    "external tx 0x{} is pending at this nonce; use a different nonce or wait for it to mine/drop",
                    hex::encode(rec.tx.hash.as_slice())
                ),
            });
            // staged_id is whatever the engine uses to label this stage; if it's
            // computed later, defer the write until after the StagedTx is built.
            self.outbox.write_nonce_conflict(wallet, &chain_name, &staged_id_placeholder, &body)?;
        }
```

You will need to thread the `staged_id` into a position where the conflict file can be written alongside the rest of the pending artefacts. The simplest approach: build the conflict JSON now, stash it in a local, and write it inside the existing pending-artefacts block (look for the line that calls `self.outbox.write_pending(&staged, &plan_md)`). Right after that, add:

```rust
        if let Some(body) = conflict_body {
            self.outbox.write_nonce_conflict(wallet, &chain_name, &staged.id, &body)?;
        }
```

…and capture `conflict_body: Option<serde_json::Value>` earlier.

- [ ] **Step 5: Write the failing test**

In `crates/bloom-tx/src/tx_engine.rs` (the inline `#[cfg(test)]` block at the bottom of the file):

```rust
    #[tokio::test]
    async fn stage_writes_nonce_conflict_when_index_has_same_addr_nonce() {
        use bloom_mempool::{PendingTx, PendingTxIndex, TxFees};
        use alloy::primitives::{Bytes, U256};
        // Existing test scaffolding lives in this file — search for an
        // existing test that calls `engine.stage(...)` and copy its
        // setup wholesale (it builds a ChainClient pointed at a
        // mock-server RPC + a test wallet).
        let (engine, chain, wallet, from_addr) = make_engine_for_test().await;
        let idx = PendingTxIndex::new(8);
        idx.insert(PendingTx {
            hash: alloy::primitives::B256::from([0xAB; 32]),
            from: from_addr,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        });
        engine.set_mempool_index(chain.spec().name.clone(), idx);

        let intent = make_send_eth_intent(/* to */ from_addr, /* eth */ "0.001", /* nonce */ Some(0));
        let policy = Policy::default();
        let staged = engine
            .stage(wallet, from_addr, intent, &chain, &policy, None)
            .await
            .unwrap();

        let body = std::fs::read(
            engine.outbox().pending_dir(wallet, &chain.spec().name, &staged.id).join("nonce_conflict.json")
        ).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["conflict_nonce"], 0);
        assert!(v["external_hash"].as_str().unwrap().starts_with("0xabab"));
    }
```

Find `make_engine_for_test` / `make_send_eth_intent` analogues in the existing file — they have different names. Search for `async fn stage` in the test module to copy the closest existing test.

- [ ] **Step 6: Run tests**

Run: `cargo test -p bloom-tx --lib tx_engine::tests::stage_writes_nonce_conflict`
Expected: passes.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-tx/
git commit -m "feat(bloom-tx): nonce-conflict detection in stage via PendingTxIndex"
```

---

### Task 3.3: MEV heuristic call in `tx_engine::stage`

**Files:**
- Modify: `crates/bloom-tx/src/tx_engine.rs`
- Modify: `crates/bloom-tx/src/outbox.rs`

- [ ] **Step 1: Add `write_mev_risk` to Outbox**

In `crates/bloom-tx/src/outbox.rs`:

```rust
    pub fn write_mev_risk(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        report: &bloom_mempool::MevRiskReport,
    ) -> Result<(), OutboxError> {
        let dir = self.pending_dir(wallet, chain, id);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("mev_risk.json");
        std::fs::write(&path, serde_json::to_vec_pretty(report)?)?;
        Ok(())
    }
```

- [ ] **Step 2: Add a `QuoteOracle` adapter that uses `bloom-prices` + a chain client**

Inside `tx_engine.rs`:

```rust
struct EthCallQuoteOracle<'a> {
    chain: &'a ChainClient,
}

impl<'a> bloom_mempool::QuoteOracle for EthCallQuoteOracle<'a> {
    fn quote(&self, _amount_in: alloy::primitives::U256, _path: &[alloy::primitives::Address]) -> Option<alloy::primitives::U256> {
        // v1: best-effort — return None until the chain quoter contract
        // address is wired in via config. The heuristic treats None as
        // `quote_unavailable` and degrades gracefully.
        None
    }
}
```

This is intentionally a stub for Phase 3; a follow-up task (Phase 4 final or follow-up spec) wires it to a real quoter.

- [ ] **Step 3: Run the heuristic inside `stage`**

After the existing simulate step, before `outbox.write_pending`:

```rust
        let mev_cfg = bloom_mempool::HeuristicConfig {
            max_slippage_bps: policy.mev.max_slippage_bps,
            zero_min_amount_in_threshold: alloy::primitives::U256::from(10u64).pow(alloy::primitives::U256::from(18u64)),
        };
        let quoter = EthCallQuoteOracle { chain };
        let mev_report = bloom_mempool::heuristic::evaluate(
            &alloy::primitives::Bytes::from(decode_data(&data_hex).unwrap_or_default()),
            value_wei,
            &mev_cfg,
            &quoter,
        );
        if policy.mev.fail_on_high_risk && matches!(mev_report.risk, bloom_mempool::MevRisk::High) {
            return Err(TxEngineError::PolicyDenied(format!(
                "mev heuristic risk=high: {}",
                mev_report.advice
            )));
        }
```

Then, after `write_pending`:

```rust
        self.outbox.write_mev_risk(wallet, &chain_name, &staged.id, &mev_report)?;
```

- [ ] **Step 4: Write the failing tests**

```rust
    #[tokio::test]
    async fn stage_writes_mev_risk_for_known_swap_with_zero_min() {
        // Build an intent whose calldata is the uniswap_v2_zero_min.hex fixture
        // and amountIn >= 1 ETH.
        // Stage with default policy.
        // Assert pending/<id>/mev_risk.json risk == "high".
        // ... copy setup from previous test
    }

    #[tokio::test]
    async fn stage_fails_when_mev_fail_on_high_risk_and_risk_high() {
        let mut policy = Policy::default();
        policy.mev.fail_on_high_risk = true;
        // craft same calldata, assert stage returns Err.
    }
```

Fill in with the patterns from existing stage tests.

- [ ] **Step 5: Run tests**

Run: `cargo test -p bloom-tx --lib`
Expected: green.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-tx/
git commit -m "feat(bloom-tx): MEV heuristic at stage time, writes mev_risk.json"
```

---

### Task 3.4: Private routing in `tx_engine::broadcast`

**Files:**
- Modify: `crates/bloom-tx/src/tx_engine.rs`

- [ ] **Step 1: Add the private-RPC registry to `TxEngine`**

```rust
    private_rpcs: parking_lot::RwLock<
        std::collections::BTreeMap<(u64, String), std::sync::Arc<dyn bloom_mempool::PrivateRpcProvider>>,
    >,
```

Setter:

```rust
    pub fn register_private_rpc(
        &self,
        chain_id: u64,
        provider: std::sync::Arc<dyn bloom_mempool::PrivateRpcProvider>,
    ) {
        self.private_rpcs
            .write()
            .insert((chain_id, provider.id().to_string()), provider);
    }
```

- [ ] **Step 2: Add the broadcast branch**

Locate the existing `broadcast` (or wherever `send_raw` is called) and add:

```rust
        let chain_id = chain.chain_id().await?;
        let hash = if policy.private.enabled && chain_id == bloom_mempool::MAINNET_CHAIN_ID {
            let map = self.private_rpcs.read();
            let provider = map.get(&(chain_id, policy.private.provider.clone()))
                .cloned()
                .ok_or_else(|| TxEngineError::PrivateProviderNotConfigured(policy.private.provider.clone()))?;
            drop(map);
            provider.submit(&raw).await
                .map_err(|e| TxEngineError::PrivateBroadcast(e.to_string()))?
        } else if policy.private.enabled {
            return Err(TxEngineError::PrivateNotSupportedOnChain(chain.spec().name.clone()));
        } else {
            chain.send_raw(raw).await?
        };
```

Add error variants:

```rust
    #[error("private RPC provider {0} not configured")]
    PrivateProviderNotConfigured(String),
    #[error("private RPC not supported on chain {0}")]
    PrivateNotSupportedOnChain(String),
    #[error("private RPC broadcast failed: {0}")]
    PrivateBroadcast(String),
```

- [ ] **Step 3: Write the failing tests**

```rust
    #[tokio::test]
    async fn broadcast_routes_private_when_policy_enabled_on_mainnet() {
        use bloom_mempool::MockPrivateRpcProvider;
        let (engine, chain, wallet, from) = make_engine_for_test_on_mainnet().await;
        let mock = std::sync::Arc::new(MockPrivateRpcProvider::new("mev_blocker"));
        engine.register_private_rpc(1, mock.clone());
        let mut policy = Policy::default();
        policy.private.enabled = true;
        policy.private.provider = "mev_blocker".into();
        // … stage + sign + broadcast a tx …
        assert_eq!(mock.submissions().len(), 1);
    }

    #[tokio::test]
    async fn broadcast_rejects_private_on_non_mainnet() {
        let (engine, chain, wallet, from) = make_engine_for_test().await; // anvil chain id
        let mut policy = Policy::default();
        policy.private.enabled = true;
        // … stage … broadcast → expect PrivateNotSupportedOnChain error
    }
```

Use the existing broadcast test as a template (search `async fn` in the test module for `broadcast` invocations).

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-tx --lib`
Expected: green.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-tx/
git commit -m "feat(bloom-tx): private routing via PrivateRpcProvider in broadcast"
```

---

### Task 3.5: `BumpScanner` background task

**Files:**
- Create: `crates/bloom-tx/src/bump_scanner.rs`
- Modify: `crates/bloom-tx/src/lib.rs`

- [ ] **Step 1: Write the scanner**

Create `crates/bloom-tx/src/bump_scanner.rs`:

```rust
//! Background scanner: walks outbox/sent/<hash>/ entries, identifies
//! stuck txs, and writes stageable bump.tx + bump_advice.json + cancel.tx.

use std::sync::Arc;
use std::time::Duration;

use bloom_mempool::{PendingTxIndex, TxFees};
use parking_lot::RwLock;
use std::collections::BTreeMap;

use crate::outbox::Outbox;

pub struct BumpScannerConfig {
    pub interval: Duration,
    pub stuck_after: Duration,
    pub basefee_overrun_pct: u32,
}

impl Default for BumpScannerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            stuck_after: Duration::from_secs(90),
            basefee_overrun_pct: 20,
        }
    }
}

pub struct BumpScanner {
    outbox: Arc<Outbox>,
    indexes: Arc<RwLock<BTreeMap<String, Arc<PendingTxIndex>>>>,
    basefee_provider: Arc<dyn BasefeeProvider>,
    cfg: BumpScannerConfig,
}

#[async_trait::async_trait]
pub trait BasefeeProvider: Send + Sync {
    async fn basefee_wei(&self, chain: &str) -> Option<u128>;
}

impl BumpScanner {
    pub fn new(
        outbox: Arc<Outbox>,
        indexes: Arc<RwLock<BTreeMap<String, Arc<PendingTxIndex>>>>,
        basefee_provider: Arc<dyn BasefeeProvider>,
        cfg: BumpScannerConfig,
    ) -> Self {
        Self { outbox, indexes, basefee_provider, cfg }
    }

    /// Run one scan pass. Public so tests can drive it deterministically.
    pub async fn tick(&self) -> anyhow::Result<()> {
        for entry in self.outbox.walk_all_sent()? {
            self.consider(entry).await?;
        }
        Ok(())
    }

    async fn consider(&self, entry: crate::outbox::SentEntry) -> anyhow::Result<()> {
        // Skip if already mined.
        if entry.mined.is_some() {
            return Ok(());
        }

        let basefee = self.basefee_provider.basefee_wei(&entry.chain).await;
        let max_fee = entry.fees.max_fee_per_gas();
        let basefee_trigger = matches!(
            basefee,
            Some(bf) if bf > max_fee.saturating_mul((100 + self.cfg.basefee_overrun_pct as u128)) / 100
        );

        let still_pending = self
            .indexes
            .read()
            .get(&entry.chain)
            .and_then(|idx| idx.lookup_by_hash(&entry.hash))
            .is_some();

        let dwell = entry.sent_at.elapsed().unwrap_or_default();
        let dwell_trigger = still_pending && dwell > self.cfg.stuck_after;

        if !(basefee_trigger || dwell_trigger) {
            return Ok(());
        }

        let bumped = bloom_mempool::bump::compute_replacement_fees(entry.fees);
        let bump_tx = serde_json::json!({
            "to": entry.to,
            "value": entry.value,
            "data": entry.data,
            "nonce": entry.nonce,
            "fees": bumped,
            "kind": "bump",
            "replaces": format!("0x{}", hex::encode(entry.hash.as_slice())),
        });
        let cancel_tx = serde_json::json!({
            "to": entry.from,
            "value": "0",
            "data": "0x",
            "nonce": entry.nonce,
            "fees": bumped,
            "kind": "cancel",
            "replaces": format!("0x{}", hex::encode(entry.hash.as_slice())),
        });
        let advice = serde_json::json!({
            "reason": if dwell_trigger { "stuck_dwell" } else { "basefee_overrun" },
            "dwell_secs": dwell.as_secs(),
            "current_basefee_wei": basefee,
            "original_max_fee_per_gas": max_fee,
            "bumped_pct": 12.5,
        });
        self.outbox.write_sent_sibling(&entry, "bump.tx", &serde_json::to_vec_pretty(&bump_tx)?)?;
        self.outbox.write_sent_sibling(&entry, "cancel.tx", &serde_json::to_vec_pretty(&cancel_tx)?)?;
        self.outbox.write_sent_sibling(&entry, "bump_advice.json", &serde_json::to_vec_pretty(&advice)?)?;
        Ok(())
    }

    /// Spawn the scanner in a tokio task. Returns a `CancellationToken`-like
    /// shutdown handle (a `tokio::sync::oneshot::Sender`).
    pub fn spawn(self: Arc<Self>) -> tokio::sync::oneshot::Sender<()> {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let interval = self.cfg.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = self.tick().await {
                            tracing::warn!(error = %e, "bump_scanner.tick.error");
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });
        tx
    }
}
```

Add `pub mod bump_scanner;` and `pub use bump_scanner::*;` to `crates/bloom-tx/src/lib.rs`.

You will need to add `walk_all_sent`, `write_sent_sibling`, and a `SentEntry` struct to `outbox.rs`:

```rust
#[derive(Debug, Clone)]
pub struct SentEntry {
    pub wallet: String,
    pub chain: String,
    pub hash: alloy::primitives::B256,
    pub from: alloy::primitives::Address,
    pub to: alloy::primitives::Address,
    pub value: alloy::primitives::U256,
    pub data: String,
    pub nonce: u64,
    pub fees: bloom_mempool::TxFees,
    pub sent_at: std::time::SystemTime,
    pub mined: Option<u64>,
}

impl Outbox {
    pub fn walk_all_sent(&self) -> Result<Vec<SentEntry>, OutboxError> {
        // Walk <home>/outbox/<wallet>/<chain>/sent/<hash>/ entries and
        // build SentEntry from receipt.json / staged.json siblings.
        // Implementation: re-use the existing `walk` helper if present;
        // otherwise iterate the directory and parse each entry's
        // already-persisted JSON.
        // Leave a TODO that this is best-effort and may skip malformed
        // entries with a tracing::warn — that is OK in v1.
        todo!("see comment")
    }

    pub fn write_sent_sibling(&self, entry: &SentEntry, name: &str, bytes: &[u8]) -> Result<(), OutboxError> {
        let dir = self.sent_dir(&entry.wallet, &entry.chain, entry.hash);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(name), bytes)?;
        Ok(())
    }
}
```

Implement `walk_all_sent` properly (don't leave the `todo!`): iterate `<home>/outbox/`, parse each entry's `staged.json` (or whatever persisted file holds the tx fields), and build `SentEntry`s. Skip entries you can't parse with a `tracing::warn!`.

`sent_dir` likely already exists — search the file.

- [ ] **Step 2: Write the failing tests**

```rust
#[cfg(test)]
mod scanner_tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct StaticBasefee(Option<u128>);
    #[async_trait::async_trait]
    impl BasefeeProvider for StaticBasefee {
        async fn basefee_wei(&self, _chain: &str) -> Option<u128> { self.0 }
    }

    #[tokio::test]
    async fn tick_writes_bump_when_basefee_climbed_past_threshold() {
        let tmp = TempDir::new().unwrap();
        let outbox = Arc::new(Outbox::new(tmp.path().to_path_buf()));
        // Seed a sent/<hash>/ entry with maxFeePerGas = 100, sent_at = now.
        // (Use existing test helpers in outbox.rs that build a sent entry,
        // OR write the JSON files directly here.)
        seed_sent_entry(&outbox, "alice", "ethereum", 100);

        let indexes = Arc::new(RwLock::new(BTreeMap::new()));
        let basefee = Arc::new(StaticBasefee(Some(150))); // 50% above max_fee
        let scanner = BumpScanner::new(outbox.clone(), indexes, basefee, BumpScannerConfig::default());
        scanner.tick().await.unwrap();

        let bump_path = outbox.sent_dir("alice", "ethereum", seeded_hash()).join("bump.tx");
        assert!(bump_path.exists());
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&bump_path).unwrap()).unwrap();
        assert_eq!(v["kind"], "bump");
        let bumped_max_fee = v["fees"]["max_fee_per_gas"].as_u64().unwrap_or_else(|| {
            // legacy
            v["fees"]["gas_price"].as_u64().unwrap()
        });
        assert_eq!(bumped_max_fee, 113); // 100 * 9/8 = 112.5 → ceil 113
    }

    #[tokio::test]
    async fn tick_skips_already_mined() {
        // Seed entry with mined = Some(123); assert no bump.tx is written.
    }
```

You will need to write the `seed_sent_entry` and `seeded_hash` helpers — they should write JSON files to the outbox directory in the same shape the existing code persists.

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-tx --lib bump_scanner`
Expected: green.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-tx/
git commit -m "feat(bloom-tx): BumpScanner background task with bump.tx + cancel.tx artefacts"
```

---

# Phase 4 — Real providers

Replaces the mocks from Phase 1 with real adapters: Alchemy + generic eth_subscribe for mempool, MEV-Blocker + Flashbots for private orderflow. Wires them into the daemon via config.

---

### Task 4.1: `AlchemyProvider`

**Files:**
- Create: `crates/bloom-mempool/src/providers/alchemy.rs`
- Create: `crates/bloom-mempool/src/providers/mod.rs`
- Modify: `crates/bloom-mempool/src/lib.rs`

- [ ] **Step 1: Add the providers module**

Create `crates/bloom-mempool/src/providers/mod.rs`:

```rust
//! Real `MempoolProvider` adapters. Each is feature-gated.

#[cfg(feature = "alchemy")]
pub mod alchemy;

#[cfg(feature = "generic_eth_subscribe")]
pub mod generic_eth_subscribe;
```

Add `pub mod providers;` to `crates/bloom-mempool/src/lib.rs`.

- [ ] **Step 2: Implement `AlchemyProvider`**

Create `crates/bloom-mempool/src/providers/alchemy.rs`:

```rust
//! Alchemy mempool provider — subscribes via WebSocket to
//! `alchemy_pendingTransactions` and yields full-body PendingTx.

use std::time::{Duration, SystemTime};

use alloy::primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::Deserialize;
use thiserror::Error;
use tokio_tungstenite::tungstenite::Message;

use crate::provider::{MempoolError, MempoolProvider, PendingTx, TxFees};

pub struct AlchemyProvider {
    ws_url: String,
}

impl AlchemyProvider {
    pub fn new(ws_url: impl Into<String>) -> Self {
        Self { ws_url: ws_url.into() }
    }
}

#[async_trait]
impl MempoolProvider for AlchemyProvider {
    fn id(&self) -> &'static str { "alchemy" }
    fn delivers_bodies(&self) -> bool { true }

    async fn subscribe(&self) -> Result<futures::stream::BoxStream<'static, PendingTx>, MempoolError> {
        let url = self.ws_url.clone();
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;
        let (mut sink, stream) = ws.split();

        let sub_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": ["alchemy_pendingTransactions", {"hashesOnly": false}]
        });
        sink.send(Message::Text(sub_msg.to_string()))
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;

        let stream = stream.filter_map(|msg| async move {
            let txt = msg.ok()?.into_text().ok()?;
            let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
            let params = v.get("params")?;
            let result = params.get("result")?;
            decode_alchemy_pending(result)
        });
        // Reconnect-on-drop is handled at the daemon stream level; the
        // provider itself returns a single attempt.
        Ok(Box::pin(stream))
    }
}

fn decode_alchemy_pending(v: &serde_json::Value) -> Option<PendingTx> {
    let hash: B256 = v.get("hash")?.as_str()?.parse().ok()?;
    let from: Address = v.get("from")?.as_str()?.parse().ok()?;
    let to: Option<Address> = v.get("to")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse().ok());
    let nonce: u64 = u64::from_str_radix(v.get("nonce")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let value: U256 = U256::from_str_radix(v.get("value")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let gas_limit: u64 = u64::from_str_radix(v.get("gas")?.as_str()?.trim_start_matches("0x"), 16).ok()?;
    let input = Bytes::from(hex::decode(v.get("input")?.as_str()?.trim_start_matches("0x")).ok()?);

    let fees = if let (Some(mfp), Some(mpfg)) = (
        v.get("maxFeePerGas").and_then(|x| x.as_str()),
        v.get("maxPriorityFeePerGas").and_then(|x| x.as_str()),
    ) {
        TxFees::Eip1559 {
            max_fee_per_gas: u128::from_str_radix(mfp.trim_start_matches("0x"), 16).ok()?,
            max_priority_fee_per_gas: u128::from_str_radix(mpfg.trim_start_matches("0x"), 16).ok()?,
        }
    } else {
        TxFees::Legacy {
            gas_price: u128::from_str_radix(
                v.get("gasPrice")?.as_str()?.trim_start_matches("0x"),
                16,
            ).ok()?,
        }
    };

    Some(PendingTx {
        hash, from, to, nonce, value, gas_limit, fees, input,
        observed_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_alchemy_pending_parses_full_eip1559_payload() {
        let v: serde_json::Value = serde_json::from_str(r#"{
            "hash":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "from":"0x2222222222222222222222222222222222222222",
            "to":"0x3333333333333333333333333333333333333333",
            "nonce":"0x5",
            "value":"0xde0b6b3a7640000",
            "gas":"0x5208",
            "maxFeePerGas":"0xb2d05e00",
            "maxPriorityFeePerGas":"0x3b9aca00",
            "input":"0xabcd"
        }"#).unwrap();
        let tx = decode_alchemy_pending(&v).unwrap();
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.value, U256::from(10u64).pow(U256::from(18u64)));
        assert!(matches!(tx.fees, TxFees::Eip1559 { .. }));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-mempool --features alchemy --lib providers::alchemy::tests`
Expected: pass.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/providers/
git commit -m "feat(bloom-mempool): AlchemyProvider for alchemy_pendingTransactions"
```

---

### Task 4.2: `GenericEthSubscribeProvider`

**Files:**
- Create: `crates/bloom-mempool/src/providers/generic_eth_subscribe.rs`

- [ ] **Step 1: Implement the provider**

Create the file:

```rust
//! Generic provider that subscribes to `newPendingTransactions` and
//! follows up via `eth_getTransactionByHash` for full bodies.
//!
//! Works on any node that supports `eth_subscribe` (Geth/Erigon/most
//! third-party WS endpoints). Returns hashes-only PendingTx; the
//! daemon stream layer is responsible for body fetch.

use std::time::SystemTime;

use alloy::primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::provider::{MempoolError, MempoolProvider, PendingTx, TxFees};

pub struct GenericEthSubscribeProvider {
    ws_url: String,
}

impl GenericEthSubscribeProvider {
    pub fn new(ws_url: impl Into<String>) -> Self {
        Self { ws_url: ws_url.into() }
    }
}

#[async_trait]
impl MempoolProvider for GenericEthSubscribeProvider {
    fn id(&self) -> &'static str { "generic_eth_subscribe" }
    fn delivers_bodies(&self) -> bool { false }

    async fn subscribe(&self) -> Result<futures::stream::BoxStream<'static, PendingTx>, MempoolError> {
        let url = self.ws_url.clone();
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;
        let (mut sink, stream) = ws.split();
        let sub_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": ["newPendingTransactions"]
        });
        sink.send(Message::Text(sub_msg.to_string()))
            .await
            .map_err(|e| MempoolError::Transport(e.to_string()))?;

        let stream = stream.filter_map(|msg| async move {
            let txt = msg.ok()?.into_text().ok()?;
            let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
            let hash_str = v.get("params")?.get("result")?.as_str()?;
            let hash: B256 = hash_str.parse().ok()?;
            Some(PendingTx {
                hash,
                from: Address::ZERO,        // filled by the stream layer
                to: None,
                nonce: 0,
                value: U256::ZERO,
                gas_limit: 0,
                fees: TxFees::Legacy { gas_price: 0 },
                input: Bytes::new(),
                observed_at: SystemTime::now(),
            })
        });
        Ok(Box::pin(stream))
    }
}
```

- [ ] **Step 2: Write a tiny unit test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_generic_eth_subscribe() {
        let p = GenericEthSubscribeProvider::new("ws://test");
        assert_eq!(p.id(), "generic_eth_subscribe");
        assert!(!p.delivers_bodies());
    }
}
```

- [ ] **Step 3: Run tests + commit**

```bash
cargo test -p bloom-mempool --features generic_eth_subscribe --lib providers::generic_eth_subscribe
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/providers/generic_eth_subscribe.rs crates/bloom-mempool/src/providers/mod.rs
git commit -m "feat(bloom-mempool): GenericEthSubscribeProvider (hashes-only)"
```

---

### Task 4.3: `MevBlockerProvider`

**Files:**
- Create: `crates/bloom-mempool/src/providers/mev_blocker.rs`
- Modify: `crates/bloom-mempool/src/providers/mod.rs`

- [ ] **Step 1: Add gating + implementation**

In `mod.rs`:

```rust
#[cfg(feature = "mev_blocker")]
pub mod mev_blocker;

#[cfg(feature = "flashbots")]
pub mod flashbots;
```

Create `mev_blocker.rs`:

```rust
//! MEV-Blocker private orderflow adapter.
//!
//! Speaks `eth_sendRawTransaction` over JSON-RPC against
//! `https://rpc.mevblocker.io` (or a configured URL). No auth.

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;

use crate::private::{HealthStatus, PrivateRpcError, PrivateRpcProvider, MAINNET_CHAIN_ID};

pub const DEFAULT_URL: &str = "https://rpc.mevblocker.io";

pub struct MevBlockerProvider {
    url: String,
    http: reqwest::Client,
}

impl MevBlockerProvider {
    pub fn new(url: impl Into<String>) -> Result<Self, PrivateRpcError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        Ok(Self { url: url.into(), http })
    }

    pub fn default_endpoint() -> Result<Self, PrivateRpcError> {
        Self::new(DEFAULT_URL)
    }
}

#[async_trait]
impl PrivateRpcProvider for MevBlockerProvider {
    fn id(&self) -> &'static str { "mev_blocker" }
    fn supported_chains(&self) -> &'static [u64] { &[MAINNET_CHAIN_ID] }

    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError> {
        let raw_hex = format!("0x{}", hex::encode(signed_raw_tx.as_ref()));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
        });
        let resp: serde_json::Value = self.http.post(&self.url).json(&body).send().await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .json().await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(PrivateRpcError::ProviderError(err.to_string()));
        }
        let hash_str = resp.get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PrivateRpcError::ProviderError("missing result".into()))?;
        hash_str.parse()
            .map_err(|e: alloy::primitives::FromHexError| PrivateRpcError::ProviderError(e.to_string()))
    }

    async fn health(&self) -> Result<HealthStatus, PrivateRpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        });
        let resp: serde_json::Value = self.http.post(&self.url).json(&body).send().await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .json().await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        if resp.get("result").is_some() {
            Ok(HealthStatus::Healthy)
        } else {
            Ok(HealthStatus::Degraded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_supported_chains() {
        let p = MevBlockerProvider::default_endpoint().unwrap();
        assert_eq!(p.id(), "mev_blocker");
        assert_eq!(p.supported_chains(), &[MAINNET_CHAIN_ID]);
    }
}
```

If `alloy::primitives::FromHexError` is not the actual error type returned by `<B256 as FromStr>::Err` in the workspace's alloy version, replace with a `String`-based mapping: `.map_err(|e| PrivateRpcError::ProviderError(format!("{e}")))`.

- [ ] **Step 2: Run tests + commit**

```bash
cargo test -p bloom-mempool --features mev_blocker --lib providers::mev_blocker
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/providers/mev_blocker.rs crates/bloom-mempool/src/providers/mod.rs
git commit -m "feat(bloom-mempool): MevBlockerProvider for private orderflow"
```

---

### Task 4.4: `FlashbotsProvider`

**Files:**
- Create: `crates/bloom-mempool/src/providers/flashbots.rs`

- [ ] **Step 1: Implement (near-identical to MEV-Blocker)**

Create `crates/bloom-mempool/src/providers/flashbots.rs`. **Copy** the entire body of `mev_blocker.rs` verbatim, then:

- Replace `pub const DEFAULT_URL: &str = "https://rpc.mevblocker.io";` with `pub const DEFAULT_URL: &str = "https://rpc.flashbots.net/fast";`
- Replace `pub struct MevBlockerProvider` with `pub struct FlashbotsProvider`
- Replace `impl MevBlockerProvider` with `impl FlashbotsProvider`
- Replace `impl PrivateRpcProvider for MevBlockerProvider` with `impl PrivateRpcProvider for FlashbotsProvider`
- Replace `"mev_blocker"` (the `id()` return) with `"flashbots"`
- Update the test's `assert_eq!(p.id(), "mev_blocker")` to `"flashbots"`
- Replace the type name in the test (`MevBlockerProvider` → `FlashbotsProvider`)

The skill says "repeat the code — the engineer may be reading tasks out of order" — but in this case the two providers are deliberately near-identical, and the engineer must follow the substitutions exactly. Future PRs may merge them behind a shared `JsonRpcPrivateProvider` if a third adapter justifies the refactor.

- [ ] **Step 2: Run tests + commit**

```bash
cargo test -p bloom-mempool --features flashbots --lib providers::flashbots
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/providers/flashbots.rs
git commit -m "feat(bloom-mempool): FlashbotsProvider for private orderflow"
```

---

### Task 4.5: `MempoolStream` task with reconnect

**Files:**
- Modify: `crates/bloom-mempool/src/stream.rs`

- [ ] **Step 1: Replace stub**

Replace `crates/bloom-mempool/src/stream.rs` with:

```rust
//! Long-lived mempool subscription task. Owns the per-chain
//! PendingTxIndex and broadcasts each observed tx to listeners.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::broadcast;

use crate::index::PendingTxIndex;
use crate::provider::{MempoolProvider, PendingTx};

#[derive(Clone)]
pub struct MempoolStream {
    pub tx: broadcast::Sender<PendingTx>,
    pub index: Arc<PendingTxIndex>,
}

impl MempoolStream {
    pub fn new(index: Arc<PendingTxIndex>) -> Self {
        Self { tx: broadcast::channel(4096).0, index }
    }
}

/// Spawn a tokio task that subscribes via `provider`, reconnects on
/// disconnect (1s → 30s exponential backoff), and broadcasts every
/// observed PendingTx.
pub fn spawn(
    chain_name: String,
    provider: Arc<dyn MempoolProvider>,
    stream: MempoolStream,
) -> tokio::sync::oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                connect = provider.subscribe() => {
                    match connect {
                        Ok(mut s) => {
                            backoff = Duration::from_secs(1);
                            tracing::info!(chain = %chain_name, provider = provider.id(), "mempool.subscribed");
                            loop {
                                tokio::select! {
                                    _ = &mut shutdown_rx => return,
                                    next = s.next() => match next {
                                        Some(tx) => {
                                            stream.index.insert(tx.clone());
                                            let _ = stream.tx.send(tx);
                                        }
                                        None => {
                                            tracing::warn!(chain = %chain_name, "mempool.disconnected");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(chain = %chain_name, error = %e, "mempool.subscribe_failed");
                        }
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    });
    shutdown_tx
}
```

- [ ] **Step 2: Write a test using `MockMempoolProvider`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{MockMempoolProvider, PendingTx, TxFees};
    use alloy::primitives::{Address, B256, Bytes, U256};
    use std::time::SystemTime;

    fn fx(b: u8) -> PendingTx {
        let mut h = [0u8; 32]; h[0] = b;
        PendingTx {
            hash: B256::from(h), from: Address::ZERO, to: None, nonce: 0,
            value: U256::ZERO, gas_limit: 21_000, fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(), observed_at: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn stream_inserts_provider_items_into_index_and_broadcasts() {
        let provider: Arc<dyn MempoolProvider> = Arc::new(MockMempoolProvider::new("mock", vec![fx(1), fx(2)]));
        let index = PendingTxIndex::new(8);
        let stream = MempoolStream::new(index.clone());
        let mut rx = stream.tx.subscribe();
        let _shutdown = spawn("ethereum".into(), provider, stream);
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(first.hash, B256::from({ let mut a = [0u8; 32]; a[0] = 1; a }));
    }
}
```

- [ ] **Step 3: Run + commit**

```bash
cargo test -p bloom-mempool --lib stream::tests
cargo fmt --all && cargo clippy -p bloom-mempool --all-targets -- -D warnings
git add crates/bloom-mempool/src/stream.rs
git commit -m "feat(bloom-mempool): MempoolStream task with reconnect/backoff"
```

---

### Task 4.6: Daemon wiring — build provider maps from config

**Files:**
- Modify: `crates/bloom-daemon/src/...` (find the startup module)
- Modify: `crates/bloom-proto/src/config.rs` (add mempool + private_rpc config sections)

- [ ] **Step 1: Add config sections**

Find the `Config` struct in `bloom-proto`:

```bash
grep -rn "pub struct Config" crates/bloom-proto/src/
```

Add fields:

```rust
    #[serde(default)]
    pub mempool: std::collections::BTreeMap<String, MempoolChainConfig>,
    #[serde(default)]
    pub private_rpc: std::collections::BTreeMap<String, PrivateRpcChainConfig>,
```

```rust
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MempoolChainConfig {
    pub provider: String,                 // "alchemy" | "generic_eth_subscribe"
    pub ws_url: String,
    #[serde(default = "default_max_index_size")]
    pub max_index_size: usize,
}
fn default_max_index_size() -> usize { 50_000 }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PrivateRpcChainConfig {
    #[serde(default)]
    pub mev_blocker_url: Option<String>,
    #[serde(default)]
    pub flashbots_url: Option<String>,
}
```

Tests: round-trip via `toml::from_str`. Mirror the existing config tests in the same file.

- [ ] **Step 2: Wire builders in the daemon**

In `bloom-daemon`, find where `Daemon::new` (or similar) wires up handlers + tx engine. Add:

```rust
use std::sync::Arc;
use bloom_mempool::{PendingTxIndex, MempoolStream, PrivateRpcProvider};

// Build mempool indexes and streams per configured chain.
let mut mempool_indexes: std::collections::BTreeMap<String, Arc<PendingTxIndex>> = Default::default();
let mut mempool_handlers: std::collections::BTreeMap<String, Arc<bloom_vfs::handlers::chains_mempool::MempoolHandler>> = Default::default();
let mut shutdown_tx: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();

for (chain, mc) in &config.mempool {
    let idx = PendingTxIndex::new(mc.max_index_size);
    mempool_indexes.insert(chain.clone(), idx.clone());
    let handler = Arc::new(bloom_vfs::handlers::chains_mempool::MempoolHandler::new(
        chain.clone(), mc.provider.clone(), idx.clone(),
    ));
    mempool_handlers.insert(chain.clone(), handler.clone());

    let provider: Arc<dyn bloom_mempool::MempoolProvider> = match mc.provider.as_str() {
        #[cfg(feature = "mempool-alchemy")]
        "alchemy" => Arc::new(bloom_mempool::providers::alchemy::AlchemyProvider::new(&mc.ws_url)),
        #[cfg(feature = "mempool-generic")]
        "generic_eth_subscribe" => Arc::new(bloom_mempool::providers::generic_eth_subscribe::GenericEthSubscribeProvider::new(&mc.ws_url)),
        other => return Err(anyhow::anyhow!("unknown mempool provider: {other}")),
    };
    let stream = bloom_mempool::MempoolStream::new(idx);
    shutdown_tx.push(bloom_mempool::stream::spawn(chain.clone(), provider, stream));
}

// Build private RPC providers per configured chain.
let mut private_rpcs: Vec<(u64, Arc<dyn PrivateRpcProvider>)> = Vec::new();
for (chain, rc) in &config.private_rpc {
    let chain_id = lookup_chain_id_from_name(chain)?;  // existing helper in bloom-daemon
    if let Some(url) = &rc.mev_blocker_url {
        private_rpcs.push((chain_id, Arc::new(bloom_mempool::providers::mev_blocker::MevBlockerProvider::new(url)?)));
    }
    if let Some(url) = &rc.flashbots_url {
        private_rpcs.push((chain_id, Arc::new(bloom_mempool::providers::flashbots::FlashbotsProvider::new(url)?)));
    }
}

// Register with the tx engine.
for (chain_name, idx) in &mempool_indexes {
    tx_engine.set_mempool_index(chain_name.clone(), idx.clone());
}
for (chain_id, p) in private_rpcs {
    tx_engine.register_private_rpc(chain_id, p);
}

// Register handlers with the VFS router.
for (chain_name, handler) in &mempool_handlers {
    vfs.register_handler(&format!("chains/{chain_name}/mempool"), handler.clone());
}
```

Adapt the function/method names to whatever `bloom-daemon` actually exposes (search the file).

Also enable the new Cargo features in `crates/bloom-daemon/Cargo.toml`:

```toml
bloom-mempool = { workspace = true, features = ["alchemy", "generic_eth_subscribe", "mev_blocker", "flashbots"] }
```

(Use the feature names as declared in Task 1.1, not the placeholder `mempool-alchemy` shown above — fix the cfg attributes to match.)

- [ ] **Step 3: Tests**

Add a smoke test in `bloom-daemon` that exercises a daemon with a `[mempool.anvil]` config pointed at a generic eth_subscribe provider (using the existing anvil test fixture if one exists). If the daemon doesn't have direct test scaffolding for this, skip the test and rely on Phase 5's Docker integration.

- [ ] **Step 4: Run + commit**

```bash
cargo build --workspace
cargo test --workspace --lib
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/bloom-proto/ crates/bloom-daemon/
git commit -m "feat(bloom-daemon): wire mempool indexes + streams + private RPCs from config"
```

---

### Task 4.7: Live-providers smoke tests (opt-in)

**Files:**
- Create: `crates/bloom-mempool/tests/it_alchemy_smoke.rs`
- Create: `crates/bloom-mempool/tests/it_private_rpc_health.rs`

- [ ] **Step 1: Write the gated tests**

Create `crates/bloom-mempool/tests/it_alchemy_smoke.rs`:

```rust
#![cfg(feature = "live-providers")]

use bloom_mempool::providers::alchemy::AlchemyProvider;
use bloom_mempool::provider::MempoolProvider;
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn alchemy_yields_at_least_one_pending_tx_in_30s() {
    let key = std::env::var("ALCHEMY_API_KEY").expect("set ALCHEMY_API_KEY to run this test");
    let url = format!("wss://eth-mainnet.g.alchemy.com/v2/{key}");
    let provider = AlchemyProvider::new(url);
    let mut stream = provider.subscribe().await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("no pending tx within 30s")
        .expect("stream ended");
    assert_ne!(first.hash, alloy::primitives::B256::ZERO);
}
```

Create `crates/bloom-mempool/tests/it_private_rpc_health.rs`:

```rust
#![cfg(feature = "live-providers")]

use bloom_mempool::providers::{flashbots::FlashbotsProvider, mev_blocker::MevBlockerProvider};
use bloom_mempool::private::{HealthStatus, PrivateRpcProvider};

#[tokio::test]
async fn mev_blocker_health_returns_healthy() {
    if std::env::var("RUN_PRIVATE_RPC_HEALTH").is_err() {
        eprintln!("skipping: set RUN_PRIVATE_RPC_HEALTH=1 to run");
        return;
    }
    let p = MevBlockerProvider::default_endpoint().unwrap();
    let h = p.health().await.unwrap();
    assert!(matches!(h, HealthStatus::Healthy | HealthStatus::Degraded));
}

#[tokio::test]
async fn flashbots_health_returns_healthy() {
    if std::env::var("RUN_PRIVATE_RPC_HEALTH").is_err() {
        eprintln!("skipping: set RUN_PRIVATE_RPC_HEALTH=1 to run");
        return;
    }
    let p = FlashbotsProvider::new(bloom_mempool::providers::flashbots::DEFAULT_URL).unwrap();
    let h = p.health().await.unwrap();
    assert!(matches!(h, HealthStatus::Healthy | HealthStatus::Degraded));
}
```

- [ ] **Step 2: Verify they compile under the feature**

Run: `cargo check -p bloom-mempool --features live-providers --tests`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add crates/bloom-mempool/tests/
git commit -m "test(bloom-mempool): opt-in live-providers smoke tests"
```

---

# Phase 5 — Docker fork-mode + docs

End-to-end validation on the existing Docker test harness, plus all the documentation updates the spec requires.

---

### Task 5.1: In-Docker WS mock that emulates `alchemy_pendingTransactions`

**Files:**
- Create: `tests/docker/mempool_mock_ws/main.rs` (or whichever language the harness uses)
- Modify: `tests/docker/Dockerfile.test`
- Modify: `tests/docker/run.sh`

- [ ] **Step 1: Read the existing Docker harness**

```bash
ls tests/docker/
cat tests/docker/run.sh
```

Identify how anvil is launched and how the test image is built. The mock WS server should run as a sidecar listening on a fixed port (e.g., `9551`).

- [ ] **Step 2: Implement the mock**

Use a small Rust binary (a new bin crate or a `tests/docker/mempool_mock_ws/` subdir using `tokio-tungstenite` directly) that:

1. Listens on `ws://0.0.0.0:9551`.
2. On receiving the `eth_subscribe(alchemy_pendingTransactions)` request, responds with a subscription id `"0x1"`.
3. Periodically (every 200 ms) emits a `eth_subscription` notification with a hand-crafted pending tx body — the body is parameterised via a `MOCK_FIXTURE_PATH` env var pointing to a JSON file with an array of pending txs to cycle through.

- [ ] **Step 3: Add `--mempool-mock` flag to `tests/docker/run.sh`**

Wire the flag so it:
1. Starts the mock WS sidecar.
2. Configures the daemon's `[mempool.anvil]` section to point at `ws://mempool-mock:9551`.
3. Runs the existing fork-mode harness with an additional assertion step: the test client reads `/eth/chains/anvil/mempool/live` and expects to see the same hashes the mock fixture emitted.

The new assertion can be a one-shot CLI invocation: `bloom vfs cat chains/anvil/mempool/live | head -n 3` and grep for at least one expected hash prefix.

- [ ] **Step 4: Run the harness locally**

```bash
tests/docker/run.sh --mempool-mock
```

Expected: harness passes, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add tests/docker/
git commit -m "test(docker): --mempool-mock fork-mode integration with WS emulator"
```

---

### Task 5.2: README + AUDIT updates

**Files:**
- Modify: `README.md`
- Modify: `docs/AUDIT.md`

- [ ] **Step 1: Update README's "Filesystem layout" section**

Add `chains/<chain>/mempool/...` to the filesystem layout description (in the `chains/<chain>/` bullet). Add a brief mention of `private = true` in the security defaults section.

- [ ] **Step 2: Update README's "Limitations" section**

Remove the bullet starting "Mempool surface not implemented." Replace with:

```markdown
- **Private orderflow is mainnet-only.** `private = true` in a
  wallet's policy routes broadcast through MEV-Blocker (default) or
  Flashbots Protect. On other chains the broadcast returns a
  PrivateNotSupportedOnChain error rather than silently falling back
  to public.
- **MEV heuristic is stage-time, heuristic-only.** No post-broadcast
  detection in v1. See
  [`docs/specs/2026-05-12-mempool-and-private-orderflow-design.md`](./docs/specs/2026-05-12-mempool-and-private-orderflow-design.md).
```

- [ ] **Step 3: Update AUDIT.md**

Add a new section under the per-surface map:

```markdown
### Mempool, private orderflow, gas-bump, MEV warnings

| Surface | Backend | Implementation |
|---|---|---|
| `chains/<c>/mempool/status.json` | rpc (alchemy / generic) | `bloom-vfs/src/handlers/chains_mempool.rs` |
| `chains/<c>/mempool/live` | rpc | `chains_mempool::live` |
| `chains/<c>/mempool/recent.jsonl` | rpc | `chains_mempool::recent_jsonl` |
| `chains/<c>/mempool/by_address/<a>/...` | rpc | `chains_mempool::by_address` |
| `chains/<c>/mempool/by_pool/<a>/recent.jsonl` | rpc | `chains_mempool::by_pool` |
| `chains/<c>/mempool/<hash>/{tx,decoded,status}` | rpc | `chains_mempool::tx_hash_subtree` |
| `wallets/<w>/chains/<c>/pending_external.jsonl` | rpc | `bloom-vfs/src/handlers/wallets.rs` |
| `wallets/<w>/outbox/sent/<h>/{bump.tx,cancel.tx,bump_advice.json}` | local | `bloom-tx::bump_scanner` |
| `wallets/<w>/outbox/pending/<id>/{mev_risk.json,nonce_conflict.json}` | local | `bloom-tx::tx_engine::stage` |
| `status/backends/{mempool,private_rpc}` | local | `bloom-vfs/src/handlers/status.rs` |

Verified end-to-end via `tests/docker/run.sh --mempool-mock`.
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/AUDIT.md
git commit -m "docs: mempool + private orderflow surfaces in README and AUDIT"
```

---

### Task 5.3: QUICKSTART addition

**Files:**
- Modify: `QUICKSTART.md`

- [ ] **Step 1: Append a "Watch the mempool" subsection**

Add at the end of QUICKSTART.md (or alongside the existing wallet/outbox section):

```markdown
## Watch the mempool

If you have a WebSocket-capable RPC configured for a chain (Alchemy
key or any Geth/Erigon node with WS enabled), add a `[mempool.<chain>]`
section to `~/.bloom-eth/config.toml`:

```toml
[mempool.ethereum]
provider = "alchemy"
ws_url = "wss://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
```

Restart the daemon, then tail the live mempool:

```sh
bloom vfs cat /eth/chains/ethereum/mempool/live    # blocks until next pending tx
bloom vfs cat /eth/chains/ethereum/mempool/recent.jsonl | head
bloom vfs cat /eth/chains/ethereum/mempool/by_address/0xYourAddress/pending.jsonl
```

To opt a wallet into private orderflow (mainnet only):

```toml
# wallets/<name>/policy.toml
[private]
enabled = true
provider = "mev_blocker"
```

Future broadcasts from that wallet on chain id 1 will route through
the configured private RPC. Non-mainnet chains return an explicit
PrivateNotSupportedOnChain error rather than silently broadcasting
publicly.
```

- [ ] **Step 2: Commit**

```bash
git add QUICKSTART.md
git commit -m "docs(quickstart): mempool tail and private orderflow walkthrough"
```

---

# Self-Review Notes (planner)

**Spec coverage:** Every section of the spec has at least one task.

- Goal 1 (mempool observability) → Tasks 1.4, 1.5, 2.1–2.6, 4.1, 4.2, 4.5, 4.6.
- Goal 2 (nonce-conflict detection) → Tasks 1.3, 2.7, 3.2.
- Goal 3 (gas-bump suggestions) → Tasks 1.9, 3.5.
- Goal 4 (private orderflow) → Tasks 1.6, 1.7, 3.1, 3.4, 4.3, 4.4, 4.6, 4.7.
- Goal 5 (MEV heuristic) → Tasks 1.8, 3.3.
- VFS surface §5 → Tasks 2.1–2.8.
- Provider abstractions §6 → Tasks 1.4, 1.6, 4.1–4.4.
- Tx-engine integration §7 → Tasks 3.1–3.5.
- Streaming §8 → Tasks 2.3, 4.5.
- Policy & config §9 → Tasks 3.1, 4.6.
- Testing §10 (CI matrix) → Task 5.1 + each task's commit gate.
- Phasing §11 → Phase 1–5 map 1:1.

**Type consistency:** `MempoolProvider`, `PrivateRpcProvider`, `PendingTx`, `TxFees`, `PendingTxIndex`, `MevRiskReport`, `BumpScanner` are used consistently across tasks. `policy.private.enabled` vs `policy.private.provider` consistent. `chain_name: String` (not `&str`) used uniformly when stored in maps. Provider id strings `"mev_blocker"`, `"flashbots"`, `"alchemy"`, `"generic_eth_subscribe"` used identically throughout.

**Known approximations the engineer must resolve:**

- Several tasks reference "the existing helper `make_engine_for_test()` / `make_send_eth_intent` analogue" — the engineer must find the analogous helper by reading the file and adapt. The plan explicitly says where to search (`grep` commands provided).
- The `EthCallQuoteOracle` is a stub returning `None`; a follow-up task in a separate spec wires a real quoter.
- A few alloy types (`AddressError`, `FromHexError`) may differ across alloy minor versions; the plan calls out the fallback to `String`-based mapping where this is likely.

If any of these blocks progress, the engineer should leave a `// TODO(plan):` comment and continue rather than spinning.
