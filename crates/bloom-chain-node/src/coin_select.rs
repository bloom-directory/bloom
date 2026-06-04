//! `select_coin_loom` — snapshot-level helper for picking and splitting
//! `Coin<LOOM>` objects owned by a sender.
//!
//! Used by fee settlement and PTB helper paths that need deterministic
//! Coin<LOOM> debits.
//!
//! # Selection strategy
//!
//! Coins are sorted **ascending** by value (smallest-first) before picking,
//! so that dust coalesces over time rather than fragmenting large coins.
//! The function returns a [`CoinSelection`] that separates fully-consumed
//! objects from any partially-consumed "remainder" coin that must be kept
//! with a reduced payload.

use bloom_chain_state::StateSnapshot;
use bloom_chain_types::types::Address;
use bloom_objects::{OWNER_KIND_ADDRESS, ObjectId, OwnershipIndexKey, TypeTag};
use bloom_petal_fungible::ops::decode_coin_value;
use thiserror::Error;

/// The result of a `Coin<LOOM>` selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinSelection {
    /// Objects to delete entirely (their full value is consumed).
    pub consumed: Vec<ObjectId>,
    /// If the last coin was larger than needed: its id and the new
    /// (reduced) value to write back. The object itself is NOT deleted —
    /// only its payload changes.
    pub split_remainder: Option<(ObjectId, u128)>,
}

/// Errors from [`select_coin_loom`].
#[derive(Debug, Error)]
pub enum SelectCoinError {
    /// The sender does not own enough `Coin<LOOM>` to cover `need`.
    #[error("insufficient Coin<LOOM>: have {have}, need {need}")]
    Insufficient { have: u128, need: u128 },
}

/// Find `Coin<LOOM>` object(s) owned by `sender` whose total value >=
/// `amount`, possibly splitting the last coin to extract exactly `amount`.
///
/// Returns a [`CoinSelection`] describing:
/// - `consumed`: object ids to delete in their entirety.
/// - `split_remainder`: if the last selected coin had excess value, the
///   (id, new_value) pair that should be written back with a reduced
///   payload. The object itself stays alive; only the payload changes.
///
/// Errors with [`SelectCoinError::Insufficient`] if the sender's total
/// `Coin<LOOM>` is less than `amount`.
///
/// # Selection strategy
///
/// Coins are sorted ascending by value (smallest-first / dust-first).
/// This coalesces small coins over time rather than fragmenting large ones.
pub fn select_coin_loom(
    snap: &StateSnapshot,
    sender: Address,
    amount: u128,
    loom_tag: &TypeTag,
) -> Result<CoinSelection, SelectCoinError> {
    if amount == 0 {
        return Ok(CoinSelection {
            consumed: vec![],
            split_remainder: None,
        });
    }

    // 1. Collect all Coin<LOOM> objects owned by sender.
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: sender.0,
    };
    let owned_ids = snap.get_ownership(&okey).unwrap_or_default();

    let mut coins: Vec<(ObjectId, u128)> = owned_ids
        .into_iter()
        .filter_map(|id| {
            let obj = snap.get_object(&id)?;
            if obj.type_tag != *loom_tag {
                return None;
            }
            // Only Address-owned coins (not shared/immutable/object-owned).
            match &obj.owner {
                bloom_objects::Owner::Address(a) if *a == sender.0 => {}
                _ => return None,
            }
            let value = decode_coin_value(&obj.payload).ok()?;
            Some((id, value))
        })
        .collect();

    // 2. Sort ascending (smallest first).
    coins.sort_by_key(|&(_, v)| v);

    // 3. Greedily pick coins until running total >= amount.
    let total_available = coins.iter().map(|(_, v)| *v).fold(0u128, |acc, value| {
        acc.checked_add(value)
            .map(|sum| sum.min(amount))
            .unwrap_or(amount)
    });
    if total_available < amount {
        return Err(SelectCoinError::Insufficient {
            have: total_available,
            need: amount,
        });
    }

    let mut running = 0u128;
    let mut consumed: Vec<ObjectId> = Vec::new();
    let mut split_remainder: Option<(ObjectId, u128)> = None;

    for (id, value) in coins {
        let remaining_need = amount - running;
        if value <= remaining_need {
            // Fully consumed.
            consumed.push(id);
            running += value;
            if running == amount {
                break;
            }
        } else {
            // This coin covers the remainder — split it.
            let leftover = value - remaining_need;
            split_remainder = Some((id, leftover));
            // running would be += remaining_need, reaching `amount`; loop ends.
            break;
        }
    }

    Ok(CoinSelection {
        consumed,
        split_remainder,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_state::State;
    use bloom_chain_types::types::Hash32;
    use bloom_objects::{Object, Owner};
    use bloom_petal_fungible::ops::coin_payload;
    use bloom_script::{DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn make_coin_object(id_byte: u8, owner: Address, value: u128) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address(owner.0),
            version: 0,
            payload: coin_payload(value),
        }
    }

    /// Seed `state` with coins for `owner`, returns the state (with ownership index wired).
    fn seed_coins(state: &mut State, owner: Address, coins: &[(u8, u128)]) {
        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: owner.0,
        };
        let mut owned = state.get_ownership(&okey).unwrap_or_default();
        for &(id_byte, value) in coins {
            let obj = make_coin_object(id_byte, owner, value);
            let id = obj.id;
            state.set_object(obj);
            if !owned.contains(&id) {
                owned.push(id);
            }
        }
        owned.sort();
        state.set_ownership(okey, owned);
    }

    #[test]
    fn single_coin_exact_match() {
        let mut state = State::new();
        let alice = addr(0x01);
        seed_coins(&mut state, alice, &[(0xA0, 500)]);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 500, &loom_tag).unwrap();
        assert_eq!(sel.consumed, vec![ObjectId([0xA0; 32])]);
        assert_eq!(sel.split_remainder, None);
    }

    #[test]
    fn two_coins_exact_sum() {
        let mut state = State::new();
        let alice = addr(0x01);
        seed_coins(&mut state, alice, &[(0xA0, 300), (0xA1, 200)]);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 500, &loom_tag).unwrap();
        // Both coins consumed (sorted ascending: 200 first, then 300).
        assert_eq!(sel.consumed.len(), 2);
        assert!(sel.consumed.contains(&ObjectId([0xA0; 32])));
        assert!(sel.consumed.contains(&ObjectId([0xA1; 32])));
        assert_eq!(sel.split_remainder, None);
    }

    #[test]
    fn single_coin_oversized_splits_remainder() {
        let mut state = State::new();
        let alice = addr(0x01);
        seed_coins(&mut state, alice, &[(0xA0, 1000)]);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 300, &loom_tag).unwrap();
        // No fully-consumed coins — the one coin is split.
        assert_eq!(sel.consumed, vec![]);
        assert_eq!(sel.split_remainder, Some((ObjectId([0xA0; 32]), 700)));
    }

    #[test]
    fn multiple_coins_last_one_split() {
        let mut state = State::new();
        let alice = addr(0x01);
        // Three coins: values 100, 200, 500 — sorted ascending.
        seed_coins(&mut state, alice, &[(0xA0, 100), (0xA1, 200), (0xA2, 500)]);
        let snap = state.snapshot();

        // Need 350: 100 + 200 = 300, then split 50 from 500 → remainder 450.
        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 350, &loom_tag).unwrap();
        assert!(sel.consumed.contains(&ObjectId([0xA0; 32])));
        assert!(sel.consumed.contains(&ObjectId([0xA1; 32])));
        assert!(!sel.consumed.contains(&ObjectId([0xA2; 32])));
        assert_eq!(sel.split_remainder, Some((ObjectId([0xA2; 32]), 450)));
    }

    #[test]
    fn insufficient_balance_returns_error() {
        let mut state = State::new();
        let alice = addr(0x01);
        seed_coins(&mut state, alice, &[(0xA0, 100), (0xA1, 50)]);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let err = select_coin_loom(&snap, alice, 500, &loom_tag).unwrap_err();
        assert!(matches!(
            err,
            SelectCoinError::Insufficient {
                have: 150,
                need: 500
            }
        ));
    }

    #[test]
    fn selection_total_caps_at_need_without_overflowing() {
        let mut state = State::new();
        let alice = addr(0x01);
        seed_coins(&mut state, alice, &[(0xA0, u128::MAX), (0xA1, 1)]);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, u128::MAX, &loom_tag).unwrap();
        assert_eq!(sel.consumed, vec![ObjectId([0xA1; 32])]);
        assert_eq!(sel.split_remainder, Some((ObjectId([0xA0; 32]), 1)));
    }

    #[test]
    fn no_coins_at_all_returns_insufficient() {
        let state = State::new();
        let alice = addr(0x01);
        let snap = state.snapshot();

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let err = select_coin_loom(&snap, alice, 1, &loom_tag).unwrap_err();
        assert!(matches!(
            err,
            SelectCoinError::Insufficient { have: 0, need: 1 }
        ));
    }

    #[test]
    fn zero_amount_returns_empty_selection() {
        let state = State::new();
        let alice = addr(0x01);
        let snap = state.snapshot();
        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 0, &loom_tag).unwrap();
        assert_eq!(sel.consumed, vec![]);
        assert_eq!(sel.split_remainder, None);
    }

    #[test]
    fn non_loom_coins_ignored() {
        // Seed a non-LOOM coin with a different type_tag — should not be counted.
        let mut state = State::new();
        let alice = addr(0x01);

        // Insert a "wrong type" object in the ownership index.
        let wrong_obj = Object {
            id: ObjectId([0xBB; 32]),
            type_tag: bloom_objects::TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "Coin".to_string(),
                // WLOOM, not LOOM
                type_args: vec![bloom_objects::TypeTag::Concrete {
                    petal_hash: [0u8; 32],
                    type_name: "WLOOM".to_string(),
                    type_args: vec![],
                }],
            },
            owner: Owner::Address(alice.0),
            version: 0,
            payload: coin_payload(9999),
        };
        state.set_object(wrong_obj);
        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: alice.0,
        };
        state.set_ownership(okey, vec![ObjectId([0xBB; 32])]);

        let snap = state.snapshot();
        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let err = select_coin_loom(&snap, alice, 1, &loom_tag).unwrap_err();
        assert!(matches!(
            err,
            SelectCoinError::Insufficient { have: 0, need: 1 }
        ));
    }

    /// StateSnapshot must be used (not base State), so test against a snapshot
    /// that has pending (not yet committed) objects.
    #[test]
    fn select_works_on_snapshot_pending_writes() {
        let state = State::new();
        let alice = addr(0x01);

        // Don't seed into committed state — seed via a snapshot write only.
        let mut snap = state.snapshot();
        let obj = make_coin_object(0xC0, alice, 200);
        let id = obj.id;
        snap.insert_object(obj);
        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: alice.0,
        };
        snap.set_ownership(okey, vec![id]);

        let loom_tag = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let sel = select_coin_loom(&snap, alice, 200, &loom_tag).unwrap();
        assert_eq!(sel.consumed, vec![ObjectId([0xC0; 32])]);
        assert_eq!(sel.split_remainder, None);

        // Also verify the base state sees nothing (confirms snapshot isolation).
        let base_snap = state.snapshot();
        let err = select_coin_loom(&base_snap, alice, 1, &loom_tag).unwrap_err();
        assert!(matches!(err, SelectCoinError::Insufficient { .. }));

        // Suppress unused variable warning
        let _hash32: Hash32 = Hash32([0u8; 32]);
    }
}
