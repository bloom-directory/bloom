//! Top-level `State` struct and snapshot/commit semantics.
//!
//! # State root (spec §6.1, widened by §16.3)
//!
//! Phase 1 widens the state_root payload to 128 bytes so that the
//! commitment is forward-compatible with the Bloom-native contracts
//! framework before any PTBs run:
//!
//! ```text
//! state_root = blake3_tagged(
//!     "state_root:",
//!     accounts_root || code_root || object_root || ownership_index_root
//! )
//! ```
//!
//! In Phase 1 the Object and OwnershipIndex tries are empty
//! (`object_root == ownership_index_root == 0`), so the new commitment
//! differs from the legacy 64-byte one for the same content. This is
//! the one intentional break called out by spec §16.3.
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
    Address, Hash32,
    digest::{blake3_tagged, tags},
};

use crate::{
    account::Account,
    accounts::AccountsTrie,
    code_store::CodeStore,
    error::StateError,
    storage::StorageTrie,
};

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

/// A set of mutations produced by committing a `StateSnapshot`.
///
/// Apply to a `State` via [`State::apply`].
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
    /// Object trie root (spec §16.3, Phase 1).
    ///
    /// Always `Hash32([0u8; 32])` in Phase 1 because no PTBs execute
    /// yet. The field exists so the state-root commitment is stable
    /// across the Phase 1 → Phase 2 cutover. Phase 2 will populate
    /// this from a live `bloom_objects::store::ObjectTrie`.
    pub(crate) object_root: Hash32,
    /// OwnershipIndex trie root (spec §16.3, Phase 1).
    ///
    /// Always `Hash32([0u8; 32])` in Phase 1; see `object_root` above.
    pub(crate) ownership_index_root: Hash32,
}

impl State {
    /// Create an empty genesis state.
    pub fn new() -> Self {
        Self {
            generation: 0,
            accounts: AccountsTrie::new(),
            storage: BTreeMap::new(),
            code: CodeStore::new(),
            object_root: Hash32([0u8; 32]),
            ownership_index_root: Hash32([0u8; 32]),
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
        if self.storage.get(&addr).map(|t| t.is_empty()).unwrap_or(false) {
            self.storage.remove(&addr);
        }
    }

    /// Delete a storage slot for `addr`.
    pub fn storage_delete(&mut self, addr: &Address, key: &[u8; 32]) {
        if let Some(trie) = self.storage.get_mut(addr) {
            trie.delete(key);
        }
        if self.storage.get(addr).map(|t| t.is_empty()).unwrap_or(false) {
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
    /// Always zero in Phase 1; populated by the executor in Phase 2.
    pub fn object_root(&self) -> Hash32 {
        self.object_root
    }

    /// The OwnershipIndex trie root (spec §16.3).
    ///
    /// Always zero in Phase 1; populated by the executor in Phase 2.
    pub fn ownership_index_root(&self) -> Hash32 {
        self.ownership_index_root
    }

    /// Compute the `state_root` per spec §6.1, widened by §16.3:
    ///
    /// ```text
    /// state_root = blake3_tagged(
    ///     "state_root:",
    ///     accounts_root || code_root || object_root || ownership_index_root
    /// )
    /// ```
    ///
    /// In Phase 1 the last two roots are zero, but they are still
    /// included in the preimage so the commitment is stable across
    /// the Phase 1 → Phase 2 activation.
    pub fn state_root(&self) -> Hash32 {
        let mut payload = [0u8; 128];
        payload[0..32].copy_from_slice(&self.accounts_root().0);
        payload[32..64].copy_from_slice(&self.code_root().0);
        payload[64..96].copy_from_slice(&self.object_root.0);
        payload[96..128].copy_from_slice(&self.ownership_index_root.0);
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
/// `Clone` is provided so callers (e.g. the chain VM's nested `petal.call`
/// path) can checkpoint a snapshot before handing it to a sub-call and roll
/// back to the unmodified copy if the sub-call reverts or traps. The base
/// `State` and `WriteSet` are both deeply cloned; this is acceptable for v0
/// because per-call WriteSets are small.
#[derive(Clone)]
pub struct StateSnapshot {
    generation: u64,
    /// A full clone of the base state at snapshot time (read-through).
    base: State,
    write_set: WriteSet,
}

impl StateSnapshot {
    /// Read an account, respecting any pending writes in this snapshot.
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
            self.write_set.accounts.insert(addr, AccountDelta::Set(account));
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

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn acct(loom: u128) -> Account {
        Account {
            nonce: 1,
            loom,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
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
    fn phase1_object_and_ownership_roots_are_zero() {
        // Spec §16.3: Phase 1 keeps both new tries empty.
        let s = State::new();
        assert_eq!(s.object_root(), Hash32([0u8; 32]));
        assert_eq!(s.ownership_index_root(), Hash32([0u8; 32]));
    }

    #[test]
    fn state_root_payload_is_128_bytes() {
        // Recompute the expected commitment over the canonical 128-byte
        // payload and verify it matches `State::state_root` exactly.
        let s = State::new();
        let mut payload = [0u8; 128];
        payload[0..32].copy_from_slice(&s.accounts_root().0);
        payload[32..64].copy_from_slice(&s.code_root().0);
        payload[64..96].copy_from_slice(&s.object_root().0);
        payload[96..128].copy_from_slice(&s.ownership_index_root().0);
        let expected = blake3_tagged(tags::STATE_ROOT, &payload);
        assert_eq!(s.state_root(), expected);
    }

    #[test]
    fn state_root_changes_when_new_roots_change() {
        // Two states identical in accounts+code+storage but with
        // different `object_root` values must produce different
        // state_roots (the new roots are actually in the preimage).
        let mut s = State::new();
        s.set_account(addr(1), acct(100));
        let baseline = s.state_root();

        let mut s2 = State::new();
        s2.set_account(addr(1), acct(100));
        // Forcibly set a non-zero object_root via the crate-internal
        // field. (Phase 1 never does this in real execution.)
        s2.object_root = Hash32([0x11u8; 32]);
        assert_ne!(baseline, s2.state_root());
    }

    #[test]
    fn snapshot_write_through() {
        let mut state = State::new();
        state.set_account(addr(1), acct(100));

        let mut snap = state.snapshot();
        // Should read base account
        assert_eq!(snap.get_account(&addr(1)).unwrap().loom, 100);

        snap.set_account(addr(1), acct(200));
        // Should see staged value
        assert_eq!(snap.get_account(&addr(1)).unwrap().loom, 200);

        state.apply(snap.commit()).unwrap();
        // Live state should reflect the committed write
        assert_eq!(state.get_account(&addr(1)).unwrap().loom, 200);
    }
}
