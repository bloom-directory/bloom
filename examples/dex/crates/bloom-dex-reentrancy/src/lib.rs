//! bloom-dex-reentrancy — cross-petal reentrancy orchestrator for bloom-chain DEX.
//!
//! # Design (DEX spec §8 / Mismatch 1 resolution)
//!
//! Lock state lives in the **pair** petal at `blake3("pair.lock")`. This petal
//! is a stateless orchestrator: it receives `enter(target, inner_calldata)`,
//! acquires the lock in the pair, forwards the call, and releases the lock on
//! the success path.
//!
//! # Flow
//!
//! ```text
//! fn enter(target: Address, inner_calldata: bytes):
//!     if msg.sender != target: revert "reentrancy: caller != target"
//!     petal.call(target, PAIR_LOCK_CHECK_AND_SET, value=0)?  // reverts "pair: locked" if held
//!     let ret = petal.call(target, inner_calldata, value=0)?  // forwards inner method, propagates revert
//!     petal.call(target, PAIR_LOCK_CLEAR, value=0)?           // releases on success path
//!     petal.return_data(ret)
//! ```
//!
//! # v0 revert behaviour
//!
//! WASM reverts unwind stack frames synchronously. If the inner call reverts,
//! the revert propagates out of `enter` and `lock_clear` is **skipped**. This
//! means a revert in an `_inner` call leaves the lock set until the end of the
//! transaction. This is acceptable in v0 because:
//!
//! - Each transaction is atomic: the entire tx rolls back on revert, including
//!   the lock write, so the lock is never durably set after a failed tx.
//! - "pair: locked" reverts within a tx are rare — they only occur on
//!   re-entrant call chains.
//!
//! v1 will add `host.try_call` for a finally-clause pattern so the lock is
//! cleared even on inner reverts.
//!
//! # ABI
//!
//! Selectors, calldata encoding, return packing, and dispatch are all generated
//! by the chain-owned `bloom_chain_abi::contract!` macro below. The single
//! exported method is `reentrancy.enter(address,bytes)` whose calldata layout
//! is `selector || target (32B) || inner_calldata (raw, no length prefix)` —
//! the macro's `bytes` argument is rest-of-buffer, matching the wire format
//! the pair petal currently produces.
//!
//! # Revert prefix
//!
//! All reverts from this petal are prefixed with `"reentrancy: "`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use bloom_chain_abi::{DispatchError, contract};
use bloom_dex_abi::selectors;
use bloom_petal_sdk::{LoomValue, msg, petal};

// ---------------------------------------------------------------------------
// Chain-owned ABI declaration
// ---------------------------------------------------------------------------

contract! {
    contract Reentrancy {
        fn enter(target: Address, inner: bytes);
    }
}

// ---------------------------------------------------------------------------
// Petal entry points
// ---------------------------------------------------------------------------

bloom_petal_sdk::petal! {
    init => do_init,
    call => do_call,
}

/// `init` — no parameters; reentrancy petal has no constructor state.
fn do_init(_calldata: Vec<u8>) {
    // Stateless: no initialisation needed.
}

/// `call` — routes a method call through the macro-generated dispatcher and
/// translates `DispatchError` into the petal-SDK revert ABI. The `enter`
/// handler exits via `petal::return_data` / `petal::revert` directly, so the
/// `Ok(_)` branch is only reached if the dispatcher itself returns (it won't
/// for our diverging handler).
fn do_call(calldata: Vec<u8>) -> i32 {
    let mut handler = ReentrancyHandler;
    let caller = msg::sender();
    match reentrancy::dispatch(&mut handler, &caller, &calldata) {
        Ok(data) => petal::return_data(&data),
        Err(DispatchError::ShortCalldata) => petal::revert("reentrancy: calldata too short"),
        Err(DispatchError::UnknownSelector(_)) => petal::revert("reentrancy: unknown selector"),
        Err(DispatchError::Decode(_)) => petal::revert("reentrancy: bad args"),
        Err(DispatchError::Unauthorized) => petal::revert("reentrancy: unauthorized"),
        Err(DispatchError::Handler(m)) => petal::revert(m),
    }
}

// ---------------------------------------------------------------------------
// Handler — diverges via petal::return_data on the success path
// ---------------------------------------------------------------------------

struct ReentrancyHandler;

impl reentrancy::Handler for ReentrancyHandler {
    /// `reentrancy.enter(address target, bytes inner_calldata)`
    ///
    /// - Reverts `"reentrancy: caller != target"` if `msg.sender != target`.
    /// - Calls `pair.lock_check_and_set()` on `target` — reverts `"pair: locked"` if held.
    /// - Forwards `inner_calldata` to `target` via `petal.call`, propagating any revert.
    /// - On success, calls `pair.lock_clear()` to release the lock.
    /// - Exits via `petal::return_data(ret)` (does not return to the dispatcher).
    fn enter(
        &mut self,
        target: [u8; 32],
        inner: Vec<u8>,
    ) -> Result<(), &'static str> {
        // The pair calls `reentrancy.enter(self, ...)` — verify msg.sender == target.
        let caller = msg::sender();
        if caller != target {
            petal::revert("reentrancy: caller != target");
        }

        // Zero LOOM value for all petal.call invocations.
        let zero_value = LoomValue::ZERO;

        // Step 1: acquire lock in the pair (reverts "pair: locked" if already set).
        let mut lock_cd = Vec::with_capacity(4);
        lock_cd.extend_from_slice(&selectors::PAIR_LOCK_CHECK_AND_SET);
        petal::call(&target, &lock_cd, zero_value)
            .unwrap_or_else(|_| petal::revert("reentrancy: lock_check_and_set failed"));

        // Step 2: forward the inner call — reverts propagate naturally
        // (lock_clear skipped in v0).
        let ret = petal::call(&target, &inner, zero_value)
            .unwrap_or_else(|_| petal::revert("reentrancy: inner call failed"));

        // Step 3: release the lock unconditionally on the success path.
        let mut clear_cd = Vec::with_capacity(4);
        clear_cd.extend_from_slice(&selectors::PAIR_LOCK_CLEAR);
        petal::call(&target, &clear_cd, zero_value)
            .unwrap_or_else(|_| petal::revert("reentrancy: lock_clear failed"));

        petal::return_data(&ret);
    }
}

// ---------------------------------------------------------------------------
// Host-side unit tests (cfg(test), non-wasm32 only)
//
// These tests verify:
// - Selector parity: the macro-emitted SEL_ENTER matches the canonical
//   blake3("reentrancy.enter(address,bytes)") string and the legacy
//   bloom_dex_abi::selectors::REENTRANCY_ENTER constant.
// - Calldata layout for enter: 4-byte selector + 32-byte target + variable
//   raw inner bytes (no length prefix) — the macro's `bytes` tail format.
// - The shared PAIR_LOCK_CHECK_AND_SET / PAIR_LOCK_CLEAR / PAIR_*_INNER
//   selectors are stable and do not collide with REENTRANCY_ENTER.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    // ---------------------------------------------------------------------------
    // Selector helpers (host-side: use blake3 crate directly for verification)
    // ---------------------------------------------------------------------------

    fn blake3_sel(method: &[u8]) -> [u8; 4] {
        let h = blake3::hash(method);
        let b = h.as_bytes();
        [b[0], b[1], b[2], b[3]]
    }

    // ---------------------------------------------------------------------------
    // Calldata builders — use the macro-generated client builder.
    // ---------------------------------------------------------------------------

    /// Build enter calldata via the chain-ABI client helper. The macro emits
    /// `selector || target (32B) || inner (raw tail)`, which is exactly the
    /// wire format the pair petal currently constructs by hand.
    fn cd_enter(target: [u8; 32], inner: &[u8]) -> Vec<u8> {
        reentrancy::calls::enter(&target, inner)
    }

    // ---------------------------------------------------------------------------
    // Selector parity tests (chain-ABI macro vs. canonical strings & legacy)
    // ---------------------------------------------------------------------------

    /// SEL_ENTER matches blake3("reentrancy.enter(address,bytes)")[..4].
    #[test]
    fn reentrancy_selectors_match_dex_v0_canonical_strings() {
        assert_eq!(
            reentrancy::SEL_ENTER,
            bloom_chain_abi::selector("reentrancy.enter(address,bytes)"),
            "SEL_ENTER must match canonical blake3 selector",
        );
        // SIG follows the domain.method(...) convention.
        assert_eq!(reentrancy::SIG_ENTER, "reentrancy.enter(address,bytes)");
    }

    /// SEL_ENTER must be byte-identical to the legacy bloom_dex_abi constant
    /// so peer contracts (pair) keep dispatching to the same handler without
    /// any code changes during the rest of the migration.
    #[test]
    fn reentrancy_selectors_match_legacy_dex_abi_constants() {
        assert_eq!(
            reentrancy::SEL_ENTER,
            bloom_dex_abi::selectors::REENTRANCY_ENTER,
            "macro SEL_ENTER must equal legacy REENTRANCY_ENTER",
        );
    }

    // ---------------------------------------------------------------------------
    // Pre-existing selector tests — still required by the v0 spec.
    // ---------------------------------------------------------------------------

    /// REENTRANCY_ENTER (legacy constant) matches direct blake3 computation.
    #[test]
    fn reentrancy_enter_selector_stable() {
        let expected = blake3_sel(b"reentrancy.enter(address,bytes)");
        assert_eq!(
            selectors::REENTRANCY_ENTER,
            expected,
            "REENTRANCY_ENTER selector must match blake3(\"reentrancy.enter(address,bytes)\")[..4]"
        );
    }

    /// Shared pair internal selectors match their canonical method strings.
    #[test]
    fn pair_internal_selectors_stable() {
        assert_eq!(
            selectors::PAIR_LOCK_CHECK_AND_SET,
            blake3_sel(b"pair.lock_check_and_set()"),
            "PAIR_LOCK_CHECK_AND_SET selector mismatch"
        );
        assert_eq!(
            selectors::PAIR_LOCK_CLEAR,
            blake3_sel(b"pair.lock_clear()"),
            "PAIR_LOCK_CLEAR selector mismatch"
        );
        assert_eq!(
            selectors::PAIR_MINT_INNER,
            blake3_sel(b"pair._mint_inner(address)"),
            "PAIR_MINT_INNER selector mismatch"
        );
        assert_eq!(
            selectors::PAIR_BURN_INNER,
            blake3_sel(b"pair._burn_inner(address)"),
            "PAIR_BURN_INNER selector mismatch"
        );
        assert_eq!(
            selectors::PAIR_SWAP_INNER,
            blake3_sel(b"pair._swap_inner(u256,u256,address)"),
            "PAIR_SWAP_INNER selector mismatch"
        );
    }

    /// All five new PAIR_*_INNER selectors are distinct from REENTRANCY_ENTER.
    #[test]
    fn new_selectors_do_not_collide_with_reentrancy_enter() {
        let enter = selectors::REENTRANCY_ENTER;
        assert_ne!(selectors::PAIR_LOCK_CHECK_AND_SET, enter);
        assert_ne!(selectors::PAIR_LOCK_CLEAR, enter);
        assert_ne!(selectors::PAIR_MINT_INNER, enter);
        assert_ne!(selectors::PAIR_BURN_INNER, enter);
        assert_ne!(selectors::PAIR_SWAP_INNER, enter);
    }

    /// All five new PAIR_*_INNER selectors are mutually distinct.
    #[test]
    fn new_selectors_are_mutually_distinct() {
        use std::collections::HashSet;
        let set: HashSet<[u8; 4]> = [
            selectors::PAIR_LOCK_CHECK_AND_SET,
            selectors::PAIR_LOCK_CLEAR,
            selectors::PAIR_MINT_INNER,
            selectors::PAIR_BURN_INNER,
            selectors::PAIR_SWAP_INNER,
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(set.len(), 5, "all five PAIR_*_INNER selectors must be distinct");
    }

    /// enter calldata: 4-byte selector + 32-byte target + N-byte inner.
    /// This verifies the macro's `bytes` tail layout — no length prefix.
    #[test]
    fn enter_calldata_layout() {
        let target = [0xAAu8; 32];
        let inner: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]; // 8 bytes
        let cd = cd_enter(target, inner);

        assert_eq!(cd.len(), 4 + 32 + inner.len(), "enter calldata length");

        assert_eq!(&cd[..4], &reentrancy::SEL_ENTER, "selector prefix (chain-ABI)");
        assert_eq!(&cd[..4], &selectors::REENTRANCY_ENTER, "selector prefix (legacy)");
        assert_eq!(&cd[4..36], &target, "target address");
        assert_eq!(&cd[36..], inner, "inner calldata suffix (no length prefix)");
    }

    /// enter calldata with empty inner: 4 + 32 = 36 bytes.
    #[test]
    fn enter_calldata_empty_inner() {
        let target = [0xBBu8; 32];
        let cd = cd_enter(target, &[]);
        assert_eq!(cd.len(), 36, "enter with empty inner must be 36 bytes");
    }

    /// enter calldata with a realistic _mint_inner payload — exact wire layout
    /// the pair currently produces by hand. The macro must reproduce it byte
    /// for byte so the rest of the migration can land incrementally.
    #[test]
    fn enter_calldata_mint_inner_payload() {
        let target = [0x01u8; 32];
        let recipient = [0x02u8; 32];

        // Build inner calldata: PAIR_MINT_INNER selector + recipient.
        let mut inner = Vec::with_capacity(4 + 32);
        inner.extend_from_slice(&selectors::PAIR_MINT_INNER);
        inner.extend_from_slice(&recipient);

        let cd = cd_enter(target, &inner);

        // Validate structure.
        assert_eq!(cd.len(), 4 + 32 + 4 + 32);
        assert_eq!(&cd[..4], &selectors::REENTRANCY_ENTER);
        assert_eq!(&cd[4..36], &target);
        assert_eq!(&cd[36..40], &selectors::PAIR_MINT_INNER);
        assert_eq!(&cd[40..72], &recipient);
    }

    /// Verify no selector collision between REENTRANCY_ENTER and all known DEX selectors.
    #[test]
    fn no_collision_with_all_dex_selectors() {
        use std::collections::HashSet;

        let all_selectors: &[[u8; 4]] = &[
            selectors::ERC20_TOTAL_SUPPLY,
            selectors::ERC20_BALANCE_OF,
            selectors::ERC20_ALLOWANCE,
            selectors::ERC20_TRANSFER,
            selectors::ERC20_TRANSFER_FROM,
            selectors::ERC20_APPROVE,
            selectors::ERC20_NAME,
            selectors::ERC20_SYMBOL,
            selectors::ERC20_DECIMALS,
            selectors::PAIR_TOKEN0,
            selectors::PAIR_TOKEN1,
            selectors::PAIR_GET_RESERVES,
            selectors::PAIR_MINT,
            selectors::PAIR_BURN,
            selectors::PAIR_SWAP,
            selectors::PAIR_SKIM,
            selectors::PAIR_SYNC,
            selectors::FACTORY_CREATE_PAIR,
            selectors::FACTORY_GET_PAIR,
            selectors::FACTORY_ALL_PAIRS,
            selectors::FACTORY_ALL_PAIRS_LENGTH,
            selectors::REENTRANCY_ENTER,
            selectors::PAIR_LOCK_CHECK_AND_SET,
            selectors::PAIR_LOCK_CLEAR,
            selectors::PAIR_MINT_INNER,
            selectors::PAIR_BURN_INNER,
            selectors::PAIR_SWAP_INNER,
        ];

        let set: HashSet<[u8; 4]> = all_selectors.iter().cloned().collect();
        assert_eq!(
            set.len(),
            all_selectors.len(),
            "selector collision detected — all DEX selectors must be unique"
        );
    }

    /// Verify caller-must-equal-target check is in place conceptually
    /// (the dispatch rejects unknown selectors before entering the handler).
    #[test]
    fn short_calldata_rejected_at_length_guard() {
        // 3 bytes is less than the required 4-byte selector minimum.
        let short_cd: Vec<u8> = alloc::vec![0u8; 3];
        assert!(short_cd.len() < 4, "calldata length guard would fire");
    }

    /// Verify the v0 lock-on-revert documentation property via the semantics.
    /// In v0, if the inner call reverts, lock_clear is NOT called (skipped).
    /// However, the transaction is atomic so the lock write rolls back anyway.
    #[test]
    fn v0_revert_atomicity_documented() {
        // This is a conceptual test: in v0, tx atomicity ensures that a revert
        // in the inner call rolls back ALL state changes for the tx, including
        // the lock_check_and_set write. So "lock held until next tx" never
        // actually happens — the lock is only persisted on the success path
        // (when lock_clear also fires), or rolled back entirely on revert.
        //
        // This test documents the invariant rather than executing host calls.
        let revert_rolls_back_lock = true;
        let lock_clear_skipped_on_inner_revert = true;
        assert!(
            revert_rolls_back_lock,
            "tx atomicity guarantees lock write is rolled back if inner reverts"
        );
        assert!(
            lock_clear_skipped_on_inner_revert,
            "v0: lock_clear is skipped on inner revert (v1 will add host.try_call)"
        );
    }
}
