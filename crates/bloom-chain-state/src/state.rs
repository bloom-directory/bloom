//! Top-level `State` struct and snapshot/commit semantics.
//!
//! # State root (spec §6.1, widened by §16.3)
//!
//! The state_root payload is 192 bytes:
//!
//! ```text
//! state_root = blake3_tagged(
//!     "state_root:",
//!     accounts_root || code_root || object_root || ownership_index_root ||
//!     vfs_root || key_registry_root
//! )
//! ```
//!
//! `object_root`, `ownership_index_root`, `vfs_root`, and `key_registry_root`
//! commit to the in-memory Object / OwnershipIndex / VFS / key-registry maps using deterministic
//! sorted-entry encodings. Roots are zero when their underlying map is empty
//! (the workspace's empty-trie convention). They are computed on demand from
//! [`State::objects`] / [`State::ownership`] / [`State::vfs`] / [`State::key_registry`] — there is no
//! cached field, so the roots are always live.
//!
//! Receipts are NOT included in the state root — they are in the block header's
//! separate `receipts_root` field (spec §6.1 note).
//!
//! # Snapshot / commit pattern (spec §6.4, prior-art §2)
//!
//! ```ignore
//! let snap = state.snapshot();
//! snap.set_account(addr, acct);
//! snap.storage_write(addr, key, value);
//! let write_set = snap.commit();   // extract changes
//! state.apply(write_set);          // atomically mutate live state
//! // — OR —
//! snap.revert();                   // discard (no-op drop)
//! ```
//!
//! A `StateSnapshot` tracks a generation counter from its parent `State`.
//! `State::apply` rejects a `WriteSet` whose generation does not match the
//! current state generation, preventing two snapshots from being applied out
//! of order.

use std::collections::BTreeMap;

use bloom_chain_types::{
    Hash32,
    digest::{blake3_tagged, tags},
    types::{Address, PubKeyBytes},
};
use bloom_objects::{
    Object, ObjectId, OwnershipIndexKey,
    store::{encode_object_trie_value, encode_ownership_value, object_trie_key},
};

use crate::{
    account::Account,
    accounts::AccountsTrie,
    code_store::CodeStore,
    error::StateError,
    storage::StorageTrie,
    trie::{Trie, TrieKind},
};

const VFS_ROOT_TAG: &str = "bloom-chain.v0.vfs_root:";
const VFS_LEAF_TAG: &str = "bloom-chain.v0.vfs_leaf:";
const KEY_REGISTRY_ROOT_TAG: &str = "bloom-chain.v0.key_registry_root:";
const KEY_REGISTRY_LEAF_TAG: &str = "bloom-chain.v0.key_registry_leaf:";

// ---------------------------------------------------------------------------
// Write-set types
// ---------------------------------------------------------------------------

/// An account delta: either an update or a removal.
#[derive(Clone, Debug)]
pub enum AccountDelta {
    Set(Account),
    Remove,
}

/// A storage slot delta.
#[derive(Clone, Debug)]
pub enum StorageDelta {
    Write([u8; 32]),
    Delete,
}

/// An object trie delta (spec §16.3): insertion / update with the full
/// canonical `Object` payload, or an explicit deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectDelta {
    /// Insert or update the object record.
    Set(Object),
    /// Delete the object from the trie.
    Remove,
}

/// An ownership-index trie delta (spec §16.3): a re-keyed list of
/// `ObjectId`s for a given `OwnershipIndexKey`, or a deletion of the
/// row (empty list ⇒ delete to keep the trie sparse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipDelta {
    /// Replace the row with this sorted list of owned `ObjectId`s.
    Set(Vec<ObjectId>),
    /// Drop the row entirely.
    Remove,
}

/// A set of mutations produced by committing a `StateSnapshot`.
///
/// Apply to a `State` via [`State::apply`].
///
/// PTB-specific fields (spec §16.3):
/// - `object_writes` / `object_deletes` — `Object` trie diffs.
/// - `ownership_changes` — `OwnershipIndex` trie diffs.
///
/// The Object and OwnershipIndex roots are computed on demand from
/// the underlying `State` maps by [`State::object_root`] /
/// [`State::ownership_index_root`]; this struct just carries the diffs.
#[derive(Clone, Debug, Default)]
pub struct WriteSet {
    /// Generation of the state this write set was produced from.
    pub(crate) generation: u64,
    /// Account-level changes.
    pub(crate) accounts: BTreeMap<Address, AccountDelta>,
    /// Per-contract storage changes: `(address, slot) -> delta`.
    pub(crate) storage: BTreeMap<Address, BTreeMap<[u8; 32], StorageDelta>>,
    /// Newly inserted wasm blobs, keyed by petal hash for in-tx lookup.
    ///
    /// Stored as a map (rather than the legacy `Vec<Vec<u8>>`) so that
    /// `StateSnapshot::get_code` can consult staged code before falling back
    /// to the committed base state. This is required to support same-tx
    /// patterns like "deploy then call" or an `init` that self-calls — the
    /// staged code must be visible within the snapshot that staged it.
    pub(crate) code: BTreeMap<Hash32, Vec<u8>>,
    /// VFS path bindings staged by deploy/publish flows.
    pub(crate) vfs: BTreeMap<String, Hash32>,
    /// Object trie diffs keyed by `ObjectId` (spec §16.3).
    pub(crate) objects: BTreeMap<ObjectId, ObjectDelta>,
    /// OwnershipIndex trie diffs keyed by `OwnershipIndexKey`.
    pub(crate) ownership: BTreeMap<OwnershipIndexKey, OwnershipDelta>,
}

impl WriteSet {
    /// All `Object` records being inserted or updated in this write set.
    ///
    /// Convenience accessor for the PTB executor's commit step (and for
    /// tests). Order is `BTreeMap` iteration order over `ObjectId`.
    pub fn object_writes(&self) -> Vec<&Object> {
        self.objects
            .values()
            .filter_map(|d| match d {
                ObjectDelta::Set(o) => Some(o),
                ObjectDelta::Remove => None,
            })
            .collect()
    }

    /// All `ObjectId`s being removed from the object trie.
    pub fn object_deletes(&self) -> Vec<ObjectId> {
        self.objects
            .iter()
            .filter_map(|(id, d)| match d {
                ObjectDelta::Remove => Some(*id),
                ObjectDelta::Set(_) => None,
            })
            .collect()
    }

    /// All ownership rows being rewritten in this write set
    /// (`(key, new sorted-list)`). `Remove` deltas are surfaced as
    /// empty lists.
    pub fn ownership_changes(&self) -> Vec<(OwnershipIndexKey, Vec<ObjectId>)> {
        self.ownership
            .iter()
            .map(|(k, d)| match d {
                OwnershipDelta::Set(ids) => (*k, ids.clone()),
                OwnershipDelta::Remove => (*k, Vec::new()),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The full chain state: accounts trie + per-contract storage + code store.
///
/// Mutate directly for block-level bookkeeping (emission credits, genesis
/// setup).  For transaction execution, use the snapshot/commit pattern to
/// enable atomic revert on failure.
#[derive(Clone, Debug)]
pub struct State {
    /// Monotonically increasing counter; incremented on every successful `apply`.
    generation: u64,
    pub(crate) accounts: AccountsTrie,
    pub(crate) storage: BTreeMap<Address, StorageTrie>,
    pub(crate) code: CodeStore,
    /// In-memory Object table backing the `Object` trie (spec §16.3).
    ///
    /// Populated by `WriteSet::object_writes` / `object_deletes`. The
    /// commitment root is computed on demand by [`State::object_root`]
    /// using the standard `TrieKind::Object` commitment scheme.
    pub(crate) objects: BTreeMap<ObjectId, Object>,
    /// In-memory OwnershipIndex backing the `OwnershipIndex` trie.
    ///
    /// Populated by `WriteSet::ownership_changes`. Empty lists evict the
    /// row to keep the table sparse. Root is computed on demand by
    /// [`State::ownership_index_root`].
    pub(crate) ownership: BTreeMap<OwnershipIndexKey, Vec<ObjectId>>,
    /// VFS path → petal content hash bindings (spec §7.2 path/hash
    /// pinning, §11.1 module_path).
    ///
    /// Populated by genesis and petal-publishing flows that decode the wasm's
    /// `bloom_petal_manifest_v0` custom section to read the declared
    /// `module_path`.
    ///
    /// VFS bindings are consensus-relevant because validators use them
    /// while checking path/hash petal references, so they are committed by
    /// [`State::vfs_root`] and included in [`State::state_root`].
    pub(crate) vfs: BTreeMap<String, Hash32>,
    /// Address → full xDSA composite public key registry.
    ///
    /// PTB signer slots carry 32-byte addresses; the production PTB verifier
    /// resolves those addresses through this registry to verify full xDSA
    /// composite signatures. Entries are registered from authenticated outer
    /// transaction envelopes and from genesis validator keys.
    pub(crate) key_registry: BTreeMap<Address, PubKeyBytes>,
}

impl State {
    /// Create an empty genesis state.
    pub fn new() -> Self {
        Self {
            generation: 0,
            accounts: AccountsTrie::new(),
            storage: BTreeMap::new(),
            code: CodeStore::new(),
            objects: BTreeMap::new(),
            ownership: BTreeMap::new(),
            vfs: BTreeMap::new(),
            key_registry: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Account access
    // -----------------------------------------------------------------------

    /// Get an account (returns `None` for non-existent accounts).
    pub fn get_account(&self, addr: &Address) -> Option<Account> {
        self.accounts.get(addr)
    }

    /// Set an account.  Empty accounts are pruned automatically.
    pub fn set_account(&mut self, addr: Address, account: Account) {
        self.accounts.set(addr, account);
    }

    /// Remove an account.
    pub fn remove_account(&mut self, addr: &Address) {
        self.accounts.remove(addr);
    }

    // -----------------------------------------------------------------------
    // Storage access
    // -----------------------------------------------------------------------

    /// Read a storage slot for `addr`.  Returns zero for absent slots.
    pub fn storage_read(&self, addr: &Address, key: &[u8; 32]) -> [u8; 32] {
        self.storage
            .get(addr)
            .map(|t| t.read(key))
            .unwrap_or([0u8; 32])
    }

    /// Write a storage slot for `addr`.
    pub fn storage_write(&mut self, addr: Address, key: [u8; 32], value: [u8; 32]) {
        let trie = self.storage.entry(addr).or_default();
        trie.write(key, value);
        // Prune empty tries
        if self
            .storage
            .get(&addr)
            .map(|t| t.is_empty())
            .unwrap_or(false)
        {
            self.storage.remove(&addr);
        }
    }

    /// Delete a storage slot for `addr`.
    pub fn storage_delete(&mut self, addr: &Address, key: &[u8; 32]) {
        if let Some(trie) = self.storage.get_mut(addr) {
            trie.delete(key);
        }
        if self
            .storage
            .get(addr)
            .map(|t| t.is_empty())
            .unwrap_or(false)
        {
            self.storage.remove(addr);
        }
    }

    /// Get the storage root for an address (zero if no storage).
    pub fn storage_root(&self, addr: &Address) -> Hash32 {
        self.storage
            .get(addr)
            .map(|t| t.root())
            .unwrap_or(Hash32([0u8; 32]))
    }

    // -----------------------------------------------------------------------
    // Code store
    // -----------------------------------------------------------------------

    /// Insert wasm bytes.  Returns the petal hash.
    pub fn insert_code(&mut self, wasm: &[u8]) -> Hash32 {
        self.code.insert(wasm)
    }

    /// Get wasm bytes by petal hash.
    pub fn get_code(&self, hash: &Hash32) -> Option<&[u8]> {
        self.code.get(hash)
    }

    // -----------------------------------------------------------------------
    // Object trie access (spec §16.3, Phase 1 in-memory)
    // -----------------------------------------------------------------------

    /// Read an object by id (returns `None` if not present).
    pub fn get_object(&self, id: &ObjectId) -> Option<Object> {
        self.objects.get(id).cloned()
    }

    /// Insert / overwrite an object.
    ///
    /// Real PTB code paths land here only through `State::apply`
    /// (a committed `WriteSet`). Direct invocation is reserved for
    /// genesis fixtures and tests.
    pub fn set_object(&mut self, obj: Object) {
        self.objects.insert(obj.id, obj);
    }

    /// Remove an object by id.
    pub fn remove_object(&mut self, id: &ObjectId) {
        self.objects.remove(id);
    }

    /// Iterate every object currently stored, in `ObjectId` order.
    pub fn iter_objects(&self) -> impl Iterator<Item = (&ObjectId, &Object)> {
        self.objects.iter()
    }

    // -----------------------------------------------------------------------
    // OwnershipIndex trie access (spec §16.3, Phase 1 in-memory)
    // -----------------------------------------------------------------------

    /// Read the sorted list of `ObjectId`s for an owner key.
    pub fn get_ownership(&self, key: &OwnershipIndexKey) -> Option<Vec<ObjectId>> {
        self.ownership.get(key).cloned()
    }

    /// Set the ownership row for `key` to `ids`. An empty list deletes
    /// the row to keep the table sparse.
    pub fn set_ownership(&mut self, key: OwnershipIndexKey, ids: Vec<ObjectId>) {
        if ids.is_empty() {
            self.ownership.remove(&key);
        } else {
            self.ownership.insert(key, ids);
        }
    }

    // -----------------------------------------------------------------------
    // VFS path → petal-hash index (spec §7.2 / §11.1, Phase 1 in-memory)
    // -----------------------------------------------------------------------

    /// Bind `path` to `hash`. Replaces any prior binding for the path.
    ///
    /// Called by genesis and petal-publishing flows after decoding the wasm's
    /// manifest custom section. Not state-root-committed — see the `vfs`
    /// field docs.
    pub fn set_vfs_binding(&mut self, path: String, hash: Hash32) {
        if path.is_empty() {
            return;
        }
        self.vfs.insert(path, hash);
    }

    /// Look up the petal hash bound to `path`, if any.
    ///
    /// The PTB validator uses this to verify that a `PetalRef`'s
    /// `(path, hash)` pair agrees with the on-chain VFS binding
    /// (spec §7.2 step 3). An unbound path returns `None`, which the
    /// validator treats permissively (pure-hash PetalRefs still
    /// validate).
    pub fn vfs_lookup(&self, path: &str) -> Option<Hash32> {
        self.vfs.get(path).copied()
    }

    /// Iterate every VFS binding in path-sorted order. Useful for
    /// snapshot tooling.
    pub fn iter_vfs(&self) -> impl Iterator<Item = (&String, &Hash32)> {
        self.vfs.iter()
    }

    /// Iterate every ownership-index row in key-sorted order.
    pub fn iter_ownership(&self) -> impl Iterator<Item = (&OwnershipIndexKey, &Vec<ObjectId>)> {
        self.ownership.iter()
    }

    // -----------------------------------------------------------------------
    // xDSA key registry
    // -----------------------------------------------------------------------

    /// Register or replace the full xDSA public key for `addr`.
    pub fn register_pubkey(&mut self, addr: Address, pubkey: PubKeyBytes) {
        self.key_registry.insert(addr, pubkey);
    }

    /// Resolve the full xDSA public key for `addr`.
    pub fn get_pubkey(&self, addr: &Address) -> Option<PubKeyBytes> {
        self.key_registry.get(addr).cloned()
    }

    /// Iterate key-registry entries in address order.
    pub fn iter_key_registry(&self) -> impl Iterator<Item = (&Address, &PubKeyBytes)> {
        self.key_registry.iter()
    }

    // -----------------------------------------------------------------------
    // Roots
    // -----------------------------------------------------------------------

    /// The accounts root.
    pub fn accounts_root(&self) -> Hash32 {
        self.accounts.root()
    }

    /// The code root.
    pub fn code_root(&self) -> Hash32 {
        self.code.root()
    }

    /// The Object trie root (spec §16.3).
    ///
    /// Computed on demand from [`State::objects`] using the standard
    /// `TrieKind::Object` BLAKE3-tagged-sorted-leaf commitment. Returns
    /// `Hash32([0u8; 32])` when the underlying map is empty (the
    /// workspace's empty-trie convention).
    pub fn object_root(&self) -> Hash32 {
        if self.objects.is_empty() {
            return Hash32([0u8; 32]);
        }
        let mut trie = Trie::new(TrieKind::Object);
        for (id, obj) in &self.objects {
            let value = encode_object_trie_value(obj)
                .expect("Object canonical encoding is infallible for in-state records");
            trie.insert(object_trie_key(id), value);
        }
        trie.root()
    }

    /// The OwnershipIndex trie root (spec §16.3).
    ///
    /// Computed on demand from [`State::ownership`] using the standard
    /// `TrieKind::OwnershipIndex` commitment. Returns
    /// `Hash32([0u8; 32])` when the underlying map is empty.
    ///
    /// Each row's `Vec<ObjectId>` is sorted before being passed to
    /// `encode_ownership_value` (which enforces canonical ascending
    /// order). Callers that store ownership rows via
    /// [`State::set_ownership`] / [`State::apply`] are not required to
    /// pre-sort the list — sorting happens here, at root-computation
    /// time, so the commitment is canonical regardless of caller order.
    ///
    /// The logical key is `(owner_kind, owner_id)` (33 bytes); the trie
    /// requires 32-byte keys, so we derive the trie key by hashing the
    /// canonical 33-byte encoding with BLAKE3. The hash is uniformly
    /// distributed and collision-resistant, and `TrieKind::OwnershipIndex`
    /// supplies outer domain separation via its root/value tags.
    pub fn ownership_index_root(&self) -> Hash32 {
        if self.ownership.is_empty() {
            return Hash32([0u8; 32]);
        }
        let mut trie = Trie::new(TrieKind::OwnershipIndex);
        for (key, ids) in &self.ownership {
            // Sort + dedup defensively so the canonical encoder (which
            // requires strict ascending order) never sees a malformed
            // row. Duplicates would be a bug in upstream code; we
            // tolerate them here to keep the root computation total.
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted.dedup();
            let value = encode_ownership_value(&sorted)
                .expect("ownership_value encoding is infallible for sorted+deduped input");
            // Derive a 32-byte trie key from the 33-byte canonical
            // ownership key by hashing with BLAKE3. The trie kind's
            // domain tags already separate this from other tries.
            let trie_key: [u8; 32] = blake3::hash(&key.encode()).into();
            trie.insert(trie_key, value);
        }
        trie.root()
    }

    /// The VFS root.
    ///
    /// Commits to path → petal-hash bindings in path-sorted order. The path
    /// bytes are hashed into 32-byte trie keys; the value is the bound petal
    /// hash. Empty VFS returns the all-zero sentinel.
    pub fn vfs_root(&self) -> Hash32 {
        if self.vfs.is_empty() {
            return Hash32([0u8; 32]);
        }

        let count = self.vfs.len() as u64;
        let mut payload = Vec::with_capacity(8 + self.vfs.len() * 64);
        payload.extend_from_slice(&count.to_le_bytes());
        for (path, hash) in &self.vfs {
            let key = blake3_tagged(VFS_LEAF_TAG, path.as_bytes());
            payload.extend_from_slice(&key.0);
            payload.extend_from_slice(&hash.0);
        }
        blake3_tagged(VFS_ROOT_TAG, &payload)
    }

    /// The xDSA key-registry root.
    ///
    /// Commits to address → full composite public-key bindings in address order.
    /// Empty registry returns the all-zero sentinel.
    pub fn key_registry_root(&self) -> Hash32 {
        if self.key_registry.is_empty() {
            return Hash32([0u8; 32]);
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&(self.key_registry.len() as u64).to_le_bytes());
        for (addr, pubkey) in &self.key_registry {
            let key = blake3_tagged(KEY_REGISTRY_LEAF_TAG, &addr.0);
            payload.extend_from_slice(&key.0);
            payload.extend_from_slice(&(pubkey.0.len() as u32).to_be_bytes());
            payload.extend_from_slice(&pubkey.0);
        }
        blake3_tagged(KEY_REGISTRY_ROOT_TAG, &payload)
    }

    /// Compute the `state_root` per spec §6.1, widened by §16.3 and the xDSA
    /// key registry:
    ///
    /// ```text
    /// state_root = blake3_tagged(
    ///     "state_root:",
    ///     accounts_root || code_root || object_root || ownership_index_root ||
    ///     vfs_root || key_registry_root
    /// )
    /// ```
    ///
    /// All six roots are live: changing any underlying trie data
    /// changes the corresponding root, which changes `state_root`.
    pub fn state_root(&self) -> Hash32 {
        let mut payload = [0u8; 192];
        payload[0..32].copy_from_slice(&self.accounts_root().0);
        payload[32..64].copy_from_slice(&self.code_root().0);
        payload[64..96].copy_from_slice(&self.object_root().0);
        payload[96..128].copy_from_slice(&self.ownership_index_root().0);
        payload[128..160].copy_from_slice(&self.vfs_root().0);
        payload[160..192].copy_from_slice(&self.key_registry_root().0);
        blake3_tagged(tags::STATE_ROOT, &payload)
    }

    // -----------------------------------------------------------------------
    // Snapshot / commit
    // -----------------------------------------------------------------------

    /// Take a cheap snapshot for tx-scoped scratch work.
    ///
    /// The snapshot holds the current generation.  After `State::apply` the
    /// generation advances, and subsequent `apply` calls with the old
    /// generation will fail.
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            generation: self.generation,
            base: self.clone(),
            write_set: WriteSet {
                generation: self.generation,
                ..WriteSet::default()
            },
        }
    }

    /// Apply a write set produced by `StateSnapshot::commit`.
    ///
    /// Fails with [`StateError::StaleSnapshot`] if the write set's generation
    /// does not match the current state generation (i.e., another write set
    /// was applied since this snapshot was taken).
    pub fn apply(&mut self, ws: WriteSet) -> Result<(), StateError> {
        if ws.generation != self.generation {
            return Err(StateError::StaleSnapshot);
        }

        for (addr, delta) in ws.accounts {
            match delta {
                AccountDelta::Set(acct) => self.accounts.set(addr, acct),
                AccountDelta::Remove => self.accounts.remove(&addr),
            }
        }

        for (addr, slots) in ws.storage {
            for (key, delta) in slots {
                match delta {
                    StorageDelta::Write(val) => self.storage_write(addr, key, val),
                    StorageDelta::Delete => self.storage_delete(&addr, &key),
                }
            }
        }

        for (_hash, wasm) in ws.code {
            self.code.insert(&wasm);
        }

        for (path, hash) in ws.vfs {
            self.set_vfs_binding(path, hash);
        }

        // PTB extensions (spec §16.3) — Phase 1 in-memory storage.
        for (id, delta) in ws.objects {
            match delta {
                ObjectDelta::Set(obj) => {
                    self.objects.insert(id, obj);
                }
                ObjectDelta::Remove => {
                    self.objects.remove(&id);
                }
            }
        }
        for (key, delta) in ws.ownership {
            match delta {
                OwnershipDelta::Set(ids) => {
                    if ids.is_empty() {
                        self.ownership.remove(&key);
                    } else {
                        self.ownership.insert(key, ids);
                    }
                }
                OwnershipDelta::Remove => {
                    self.ownership.remove(&key);
                }
            }
        }
        self.generation += 1;
        Ok(())
    }

    /// Current generation counter (for testing / debugging).
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StateSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of `State` used for tx-scoped scratch work.
///
/// Writes accumulate in the embedded `WriteSet`.  Call `commit()` to extract
/// them for `State::apply`, or `revert()` to discard.
///
/// `Clone` is provided so callers can checkpoint a snapshot before speculative
/// execution and roll back to the unmodified copy if the work reverts or traps.
/// The base `State` and `WriteSet` are both deeply cloned; this is acceptable
/// for v0 because per-call WriteSets are small.
#[derive(Clone)]
pub struct StateSnapshot {
    generation: u64,
    /// A full clone of the base state at snapshot time (read-through).
    base: State,
    write_set: WriteSet,
}

impl StateSnapshot {
    /// Read an account, respecting any pending writes in this snapshot.
    ///
    /// The order is: account Set/Remove delta wins (if present), else base.
    pub fn get_account(&self, addr: &Address) -> Option<Account> {
        match self.write_set.accounts.get(addr) {
            Some(AccountDelta::Set(a)) => Some(a.clone()),
            Some(AccountDelta::Remove) => None,
            None => self.base.accounts.get(addr),
        }
    }

    /// Stage an account write.
    pub fn set_account(&mut self, addr: Address, account: Account) {
        if account.is_empty() {
            self.write_set.accounts.insert(addr, AccountDelta::Remove);
        } else {
            self.write_set
                .accounts
                .insert(addr, AccountDelta::Set(account));
        }
    }

    /// Stage an account removal.
    pub fn remove_account(&mut self, addr: Address) {
        self.write_set.accounts.insert(addr, AccountDelta::Remove);
    }

    /// Read a storage slot, respecting pending writes.
    pub fn storage_read(&self, addr: &Address, key: &[u8; 32]) -> [u8; 32] {
        if let Some(slots) = self.write_set.storage.get(addr)
            && let Some(delta) = slots.get(key)
        {
            return match delta {
                StorageDelta::Write(v) => *v,
                StorageDelta::Delete => [0u8; 32],
            };
        }
        self.base.storage_read(addr, key)
    }

    /// Stage a storage write.
    pub fn storage_write(&mut self, addr: Address, key: [u8; 32], value: [u8; 32]) {
        let slots = self.write_set.storage.entry(addr).or_default();
        if value == [0u8; 32] {
            slots.insert(key, StorageDelta::Delete);
        } else {
            slots.insert(key, StorageDelta::Write(value));
        }
    }

    /// Stage a storage deletion.
    pub fn storage_delete(&mut self, addr: Address, key: [u8; 32]) {
        let slots = self.write_set.storage.entry(addr).or_default();
        slots.insert(key, StorageDelta::Delete);
    }

    /// Stage a code insertion.  Returns the petal hash.
    pub fn insert_code(&mut self, wasm: Vec<u8>) -> Hash32 {
        // Compute hash immediately (same formula as CodeStore::insert)
        let hash = bloom_chain_types::digest::blake3_tagged(tags::PETAL, &wasm);
        self.write_set.code.insert(hash, wasm);
        hash
    }

    /// Stage a VFS path binding to a petal hash.
    pub fn set_vfs_binding(&mut self, path: String, hash: Hash32) {
        if path.is_empty() {
            return;
        }
        self.write_set.vfs.insert(path, hash);
    }

    /// Look up a VFS binding, respecting staged snapshot updates before the
    /// committed base state.
    pub fn vfs_lookup(&self, path: &str) -> Option<Hash32> {
        self.write_set
            .vfs
            .get(path)
            .copied()
            .or_else(|| self.base.vfs_lookup(path))
    }

    /// Read code, consulting staged inserts before the committed base state.
    ///
    /// The snapshot invariant is preserved: staged code is only visible to
    /// observers that hold (or share) this snapshot's `write_set`. A snapshot
    /// taken at height N never sees code staged by a different snapshot — each
    /// `State::snapshot()` call produces an independent `WriteSet`, so pending
    /// deploys from a *future* tx cannot leak into a snapshot taken now.
    pub fn get_code(&self, hash: &Hash32) -> Option<&[u8]> {
        if let Some(bytes) = self.write_set.code.get(hash) {
            return Some(bytes.as_slice());
        }
        self.base.get_code(hash)
    }

    // ----------------------------------------------------------------
    // Object trie access (PTB executor / chain VM use this)
    // ----------------------------------------------------------------

    /// Read an object, respecting any pending writes/deletes in this snapshot.
    pub fn get_object(&self, id: &ObjectId) -> Option<Object> {
        match self.write_set.objects.get(id) {
            Some(ObjectDelta::Set(o)) => Some(o.clone()),
            Some(ObjectDelta::Remove) => None,
            None => self.base.get_object(id),
        }
    }

    /// Stage an object insert / update.
    pub fn insert_object(&mut self, obj: Object) {
        self.write_set.objects.insert(obj.id, ObjectDelta::Set(obj));
    }

    /// Stage an object delete.
    pub fn delete_object(&mut self, id: ObjectId) {
        self.write_set.objects.insert(id, ObjectDelta::Remove);
    }

    // ----------------------------------------------------------------
    // OwnershipIndex access
    // ----------------------------------------------------------------

    /// Read an ownership row, respecting any pending writes/deletes
    /// in this snapshot.
    pub fn get_ownership(&self, key: &OwnershipIndexKey) -> Option<Vec<ObjectId>> {
        match self.write_set.ownership.get(key) {
            Some(OwnershipDelta::Set(ids)) => Some(ids.clone()),
            Some(OwnershipDelta::Remove) => None,
            None => self.base.get_ownership(key),
        }
    }

    /// Stage an ownership-row rewrite. Empty `ids` deletes the row.
    pub fn set_ownership(&mut self, key: OwnershipIndexKey, ids: Vec<ObjectId>) {
        if ids.is_empty() {
            self.write_set.ownership.insert(key, OwnershipDelta::Remove);
        } else {
            self.write_set
                .ownership
                .insert(key, OwnershipDelta::Set(ids));
        }
    }

    /// Extract the accumulated write set for application to the parent state.
    ///
    /// Consumes the snapshot.
    pub fn commit(self) -> WriteSet {
        self.write_set
    }

    /// Discard the snapshot and all staged writes.
    ///
    /// Consumes the snapshot.  Nothing is applied.
    pub fn revert(self) {
        // Drop is sufficient — no other side-effects.
        drop(self);
    }

    /// The generation this snapshot was taken at.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::{Object, ObjectId, Owner, OwnershipIndexKey, TypeTag};

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn acct(nonce: u64) -> Account {
        Account {
            nonce,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        }
    }

    fn sample_object(id_byte: u8, owner: Owner, version: u64) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "Coin".to_string(),
                type_args: vec![],
            },
            owner,
            version,
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn state_root_is_deterministic() {
        let mut s1 = State::new();
        s1.set_account(addr(1), acct(100));

        let mut s2 = State::new();
        s2.set_account(addr(1), acct(100));

        assert_eq!(s1.state_root(), s2.state_root());
    }

    #[test]
    fn snapshot_commit_applies() {
        let mut state = State::new();
        let snap = state.snapshot();
        // snap.commit() produces an empty write set but increments generation
        state.apply(snap.commit()).unwrap();
        assert_eq!(state.generation(), 1);
    }

    #[test]
    fn snapshot_revert_discards() {
        let state = State::new();
        let mut snap = state.snapshot();
        snap.set_account(addr(1), acct(999));
        snap.revert();
        assert_eq!(state.get_account(&addr(1)), None);
        assert_eq!(state.generation(), 0);
    }

    #[test]
    fn stale_snapshot_rejected() {
        let mut state = State::new();
        let snap1 = state.snapshot();
        let snap2 = state.snapshot();
        state.apply(snap1.commit()).unwrap(); // generation → 1
        // snap2 was taken at generation 0, but state is now at 1
        assert!(matches!(
            state.apply(snap2.commit()),
            Err(StateError::StaleSnapshot)
        ));
    }

    #[test]
    fn empty_state_object_and_ownership_roots_are_zero() {
        // Spec §16.3 + workspace empty-trie convention: a fresh state
        // has no objects and no ownership rows, so both roots return
        // the all-zeros sentinel.
        let s = State::new();
        assert_eq!(s.object_root(), Hash32([0u8; 32]));
        assert_eq!(s.ownership_index_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn state_root_payload_is_192_bytes() {
        // Recompute the expected commitment over the canonical 192-byte
        // payload and verify it matches `State::state_root` exactly.
        let s = State::new();
        let mut payload = [0u8; 192];
        payload[0..32].copy_from_slice(&s.accounts_root().0);
        payload[32..64].copy_from_slice(&s.code_root().0);
        payload[64..96].copy_from_slice(&s.object_root().0);
        payload[96..128].copy_from_slice(&s.ownership_index_root().0);
        payload[128..160].copy_from_slice(&s.vfs_root().0);
        payload[160..192].copy_from_slice(&s.key_registry_root().0);
        let expected = blake3_tagged(tags::STATE_ROOT, &payload);
        assert_eq!(s.state_root(), expected);
    }

    #[test]
    fn state_root_changes_when_object_data_changes() {
        // Two states identical in accounts+code+storage but with
        // different object content must produce different state_roots
        // (the object_root is now live and part of the preimage).
        let mut s = State::new();
        s.set_account(addr(1), acct(100));
        let baseline = s.state_root();

        let mut s2 = State::new();
        s2.set_account(addr(1), acct(100));
        s2.set_object(sample_object(0xC0, Owner::Shared, 1));
        assert_ne!(baseline, s2.state_root());
    }

    #[test]
    fn state_root_changes_when_vfs_binding_changes() {
        let mut s = State::new();
        s.set_account(addr(1), acct(100));
        let baseline = s.state_root();

        s.set_vfs_binding("/bloom/test".to_string(), Hash32([0xAB; 32]));
        assert_ne!(baseline, s.state_root());
        assert_ne!(s.vfs_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn state_root_changes_when_key_registry_changes() {
        let mut s = State::new();
        let baseline = s.state_root();

        s.register_pubkey(addr(7), PubKeyBytes(vec![0xAB; 1984]));
        assert_ne!(baseline, s.state_root());
        assert_ne!(s.key_registry_root(), Hash32([0u8; 32]));
        assert_eq!(s.get_pubkey(&addr(7)), Some(PubKeyBytes(vec![0xAB; 1984])));
    }

    #[test]
    fn snapshot_write_through() {
        let mut state = State::new();
        state.set_account(addr(1), acct(100));

        let mut snap = state.snapshot();
        // Should read base account
        assert_eq!(snap.get_account(&addr(1)).unwrap().nonce, 100);

        snap.set_account(addr(1), acct(200));
        // Should see staged value
        assert_eq!(snap.get_account(&addr(1)).unwrap().nonce, 200);

        state.apply(snap.commit()).unwrap();
        // Live state should reflect the committed write
        assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 200);
    }

    // ------------------------------------------------------------------
    // PTB extensions (spec §16.3): object writes, object deletes,
    // ownership re-keys, Loom deltas. The Object and OwnershipIndex
    // roots are live: changing the underlying maps changes the roots
    // (and therefore the state_root). The dedicated root tests below
    // exercise that behaviour directly.
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_insert_object_round_trips_via_state() {
        let mut state = State::new();
        let mut snap = state.snapshot();
        let obj = sample_object(0xA1, Owner::Address([0x11u8; 32]), 1);
        let id = obj.id;
        snap.insert_object(obj.clone());
        // Snapshot read sees staged write before commit.
        assert_eq!(snap.get_object(&id).as_ref(), Some(&obj));
        state.apply(snap.commit()).unwrap();
        assert_eq!(state.get_object(&id).as_ref(), Some(&obj));
    }

    #[test]
    fn snapshot_delete_object_removes_from_state() {
        let mut state = State::new();
        let obj = sample_object(0xA2, Owner::Address([0x11u8; 32]), 1);
        let id = obj.id;
        // Seed the base state with the object via an initial commit.
        let mut snap = state.snapshot();
        snap.insert_object(obj.clone());
        state.apply(snap.commit()).unwrap();
        assert!(state.get_object(&id).is_some());

        let mut snap2 = state.snapshot();
        snap2.delete_object(id);
        // Snapshot read sees deletion.
        assert!(snap2.get_object(&id).is_none());
        state.apply(snap2.commit()).unwrap();
        assert!(state.get_object(&id).is_none());
    }

    #[test]
    fn snapshot_set_ownership_round_trips_via_state() {
        let mut state = State::new();
        let key = OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
            owner_id: [0x22u8; 32],
        };
        let id_a = ObjectId([1u8; 32]);
        let id_b = ObjectId([2u8; 32]);
        let mut snap = state.snapshot();
        snap.set_ownership(key, vec![id_a, id_b]);
        // Snapshot read.
        let v = snap.get_ownership(&key).expect("staged ownership entry");
        assert_eq!(v, vec![id_a, id_b]);
        state.apply(snap.commit()).unwrap();
        assert_eq!(state.get_ownership(&key), Some(vec![id_a, id_b]));

        // Clearing via empty list deletes.
        let mut snap2 = state.snapshot();
        snap2.set_ownership(key, vec![]);
        state.apply(snap2.commit()).unwrap();
        assert!(state.get_ownership(&key).is_none());
    }

    #[test]
    fn object_root_changes_when_object_inserted() {
        // Spec §16.3: object_root commits to the Object map. Inserting
        // an object must change the root from the empty-trie sentinel.
        let mut state = State::new();
        assert_eq!(state.object_root(), Hash32([0u8; 32]));
        let mut snap = state.snapshot();
        snap.insert_object(sample_object(0xA1, Owner::Shared, 1));
        state.apply(snap.commit()).unwrap();
        assert_ne!(state.object_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn object_root_is_insertion_order_independent() {
        // Build two states with the same set of objects inserted in
        // different orders and assert their object_roots match.
        let obj_a = sample_object(0x01, Owner::Shared, 1);
        let obj_b = sample_object(0x02, Owner::Address([0x22u8; 32]), 1);
        let obj_c = sample_object(0x03, Owner::Immutable, 1);

        let mut s1 = State::new();
        let mut snap1 = s1.snapshot();
        snap1.insert_object(obj_a.clone());
        snap1.insert_object(obj_b.clone());
        snap1.insert_object(obj_c.clone());
        s1.apply(snap1.commit()).unwrap();

        let mut s2 = State::new();
        let mut snap2 = s2.snapshot();
        // Reverse insertion order.
        snap2.insert_object(obj_c);
        snap2.insert_object(obj_b);
        snap2.insert_object(obj_a);
        s2.apply(snap2.commit()).unwrap();

        assert_eq!(s1.object_root(), s2.object_root());
        // And, by transitivity, state_root (other tries empty).
        assert_eq!(s1.state_root(), s2.state_root());
    }

    #[test]
    fn object_root_differs_when_payloads_differ() {
        // Two objects identical except for payload must produce
        // different object_roots.
        let mut obj1 = sample_object(0xA1, Owner::Shared, 1);
        let mut obj2 = obj1.clone();
        obj1.payload = vec![1u8, 2, 3];
        obj2.payload = vec![9u8, 9, 9];

        let mut s1 = State::new();
        s1.set_object(obj1);
        let mut s2 = State::new();
        s2.set_object(obj2);

        assert_ne!(s1.object_root(), s2.object_root());
    }

    #[test]
    fn object_root_returns_to_zero_after_removal() {
        // Insert then remove; the root must collapse back to the
        // empty-trie sentinel.
        let mut state = State::new();
        let obj = sample_object(0xA1, Owner::Shared, 1);
        let id = obj.id;
        state.set_object(obj);
        assert_ne!(state.object_root(), Hash32([0u8; 32]));
        state.remove_object(&id);
        assert_eq!(state.object_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn ownership_index_root_changes_when_row_inserted() {
        // Setting an ownership row must change the root from zero.
        let mut state = State::new();
        assert_eq!(state.ownership_index_root(), Hash32([0u8; 32]));
        let key = OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
            owner_id: [0x55u8; 32],
        };
        state.set_ownership(key, vec![ObjectId([1u8; 32])]);
        assert_ne!(state.ownership_index_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn ownership_index_root_is_insertion_order_independent() {
        let key_a = OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
            owner_id: [0x01u8; 32],
        };
        let key_b = OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
            owner_id: [0x02u8; 32],
        };
        let ids_a = vec![ObjectId([0xA1u8; 32]), ObjectId([0xA2u8; 32])];
        let ids_b = vec![ObjectId([0xB1u8; 32])];

        let mut s1 = State::new();
        s1.set_ownership(key_a, ids_a.clone());
        s1.set_ownership(key_b, ids_b.clone());

        let mut s2 = State::new();
        // Reverse insertion order across rows. The per-row list is
        // also reversed; root() sorts defensively, so the canonical
        // commitment must still match.
        let mut ids_a_rev = ids_a.clone();
        ids_a_rev.reverse();
        s2.set_ownership(key_b, ids_b);
        s2.set_ownership(key_a, ids_a_rev);

        assert_eq!(s1.ownership_index_root(), s2.ownership_index_root());
    }

    #[test]
    fn ownership_index_root_differs_for_distinct_keys() {
        // Two states with rows under different owner_ids must produce
        // distinct roots — keys are part of the commitment preimage.
        let ids = vec![ObjectId([0xA1u8; 32])];
        let mut s1 = State::new();
        s1.set_ownership(
            OwnershipIndexKey {
                owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
                owner_id: [0x01u8; 32],
            },
            ids.clone(),
        );
        let mut s2 = State::new();
        s2.set_ownership(
            OwnershipIndexKey {
                owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
                owner_id: [0x02u8; 32],
            },
            ids,
        );
        assert_ne!(s1.ownership_index_root(), s2.ownership_index_root());
    }

    #[test]
    fn ownership_index_root_returns_to_zero_after_removal() {
        let mut state = State::new();
        let key = OwnershipIndexKey {
            owner_kind: bloom_objects::OWNER_KIND_ADDRESS,
            owner_id: [0x77u8; 32],
        };
        state.set_ownership(key, vec![ObjectId([1u8; 32])]);
        assert_ne!(state.ownership_index_root(), Hash32([0u8; 32]));
        // Passing an empty vec to set_ownership evicts the row.
        state.set_ownership(key, vec![]);
        assert_eq!(state.ownership_index_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn write_set_carries_object_writes_and_deletes() {
        let state = State::new();
        let mut snap = state.snapshot();
        let obj = sample_object(0xA1, Owner::Shared, 1);
        snap.insert_object(obj.clone());
        snap.delete_object(ObjectId([0xBB; 32]));
        let ws = snap.commit();
        assert!(ws.object_writes().iter().any(|o| o.id == obj.id));
        assert!(ws.object_deletes().contains(&ObjectId([0xBB; 32])));
    }
}
