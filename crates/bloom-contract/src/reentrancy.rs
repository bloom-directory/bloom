//! Framework-side reentrancy lock used by `#[nonreentrant]` handlers.
//!
//! A handler annotated `#[nonreentrant]` is wrapped in dispatcher code that
//! calls [`Guard::acquire`] on entry and (on the success path)
//! [`Guard::release`] just before `petal.return_data`. On the error path no
//! release is needed — the chain's snapshot semantics roll back every state
//! mutation when the call reverts, so the acquire write is undone for free.
//!
//! ## Slot derivation
//!
//! The lock lives at `blake3("bloom::reentrancy")[..32]`. It is scoped to the
//! current petal instance (storage is already per-instance), so two distinct
//! contracts never share a lock. The slot is recomputed on each acquire —
//! blake3 of a sixteen-byte literal is negligible next to the surrounding
//! storage I/O.
//!
//! ## Semantics
//!
//! - `acquire`: read the lock slot. If it's non-zero, revert with
//!   `"reentrancy"`. Otherwise write a single `0x01` byte so re-entrant calls
//!   trip the check.
//! - `release`: clear the slot.
//!
//! Both operations are storage I/O, so they panic when invoked off-wasm. The
//! type is `#[must_use]` to surface accidental drops at call sites that forget
//! the explicit `release`.

use bloom_petal_sdk::{petal, state};

/// Canonical label hashed to derive the lock slot.
const LOCK_LABEL: &[u8] = b"bloom::reentrancy";

fn lock_slot() -> [u8; 32] {
    *blake3::hash(LOCK_LABEL).as_bytes()
}

/// RAII-style handle around the reentrancy lock.
///
/// The struct is a marker only — the actual lock state lives in chain
/// storage. The macro pairs every [`acquire`](Self::acquire) with a manual
/// [`release`](Self::release) on the Ok path and relies on the chain's revert
/// rollback to undo the lock on the Err path.
#[must_use = "the reentrancy guard must be released or dropped via revert"]
pub struct Guard {
    _private: (),
}

impl Guard {
    /// Acquire the reentrancy lock. Reverts with reason `"reentrancy"` if
    /// the lock is already held.
    pub fn acquire() -> Self {
        let slot = lock_slot();
        if let Some(v) = state::read(&slot)
            && v != [0u8; 32] {
                petal::revert("reentrancy");
            }
        let mut held = [0u8; 32];
        held[31] = 1;
        state::write(&slot, &held);
        Self { _private: () }
    }

    /// Clear the reentrancy lock on the success path. Must be called
    /// explicitly — a diverging `petal.return_data` would otherwise skip the
    /// destructor.
    pub fn release(self) {
        let slot = lock_slot();
        state::delete(&slot);
    }
}
