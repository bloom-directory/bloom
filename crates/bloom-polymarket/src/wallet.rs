//! Deposit-wallet on-chain call builders — the V2 approval set.
//!
//! These produce the [`Call`]s bundled into a relayer `WALLET` batch to grant
//! the trading contracts spending rights *from the deposit wallet* (an EOA
//! `approve()` does nothing for it). Spender membership is byte-exact with
//! `rs-builder-relayer-client/src/operations/approve.rs` V2 set — getting a
//! spender wrong is a fund-loss vector, so it is asserted in tests.

use alloy::primitives::{Address, B256, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

use crate::eip712::{
    CTF, CTF_COLLATERAL_ADAPTER, CTF_EXCHANGE_V2, Call, NEG_RISK_CTF_COLLATERAL_ADAPTER,
    NEG_RISK_EXCHANGE_V2, PUSD,
};

sol! {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function setApprovalForAll(address operator, bool approved) external;
    function redeemPositions(address collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] indexSets) external;
}

pub const REDEEM_POSITIONS_SELECTOR: [u8; 4] = [0x01, 0xb7, 0x03, 0x7c];

/// ERC-20 `approve(spender, amount)` from the deposit wallet on `token`.
pub fn approve_amount_call(token: Address, spender: Address, amount: U256) -> Call {
    Call {
        target: token,
        value: U256::ZERO,
        data: approveCall { spender, amount }.abi_encode().into(),
    }
}

/// ERC-20 `approve(spender, MAX)` from the deposit wallet on `token`.
pub fn approve_call(token: Address, spender: Address) -> Call {
    approve_amount_call(token, spender, U256::MAX)
}

/// ERC-20 `transfer(to, amount)` from the deposit wallet on `token`.
pub fn transfer_amount_call(token: Address, to: Address, amount: U256) -> Call {
    Call {
        target: token,
        value: U256::ZERO,
        data: transferCall { to, amount }.abi_encode().into(),
    }
}

/// ERC-1155 `setApprovalForAll(operator, approved)` from the deposit wallet.
pub fn set_approval_for_all_value_call(token: Address, operator: Address, approved: bool) -> Call {
    Call {
        target: token,
        value: U256::ZERO,
        data: setApprovalForAllCall { operator, approved }
            .abi_encode()
            .into(),
    }
}

/// ERC-1155 `setApprovalForAll(operator, true)` from the deposit wallet on `token`.
pub fn set_approval_for_all_call(token: Address, operator: Address) -> Call {
    set_approval_for_all_value_call(token, operator, true)
}

/// Human-readable labels for the eight [`v2_approval_calls`], in order. Single
/// source of truth for the onboarding approval preview and the passkey review
/// page so the displayed grants never drift from what is signed.
pub const V2_APPROVAL_LABELS: [&str; 8] = [
    "pUSD approve(MAX) -> CTF Exchange V2",
    "pUSD approve(MAX) -> Neg-Risk CTF Exchange V2",
    "pUSD approve(MAX) -> CTF Collateral Adapter",
    "pUSD approve(MAX) -> Neg-Risk CTF Collateral Adapter",
    "CTF setApprovalForAll(true) -> CTF Exchange V2",
    "CTF setApprovalForAll(true) -> Neg-Risk CTF Exchange V2",
    "CTF setApprovalForAll(true) -> CTF Collateral Adapter",
    "CTF setApprovalForAll(true) -> Neg-Risk CTF Collateral Adapter",
];

/// The full V2 deposit-wallet approval batch (Polygon mainnet): pUSD `approve`
/// for the two V2 exchanges + the two collateral adapters, and CTF (ERC-1155)
/// `setApprovalForAll` for the same four. Eight calls, submitted together.
pub fn v2_approval_calls() -> Vec<Call> {
    vec![
        approve_call(PUSD, CTF_EXCHANGE_V2),
        approve_call(PUSD, NEG_RISK_EXCHANGE_V2),
        approve_call(PUSD, CTF_COLLATERAL_ADAPTER),
        approve_call(PUSD, NEG_RISK_CTF_COLLATERAL_ADAPTER),
        set_approval_for_all_call(CTF, CTF_EXCHANGE_V2),
        set_approval_for_all_call(CTF, NEG_RISK_EXCHANGE_V2),
        set_approval_for_all_call(CTF, CTF_COLLATERAL_ADAPTER),
        set_approval_for_all_call(CTF, NEG_RISK_CTF_COLLATERAL_ADAPTER),
    ]
}

/// The inverse of [`v2_approval_calls`]: revoke every grant onboarding made —
/// pUSD `approve(0)` for the four spenders + CTF `setApprovalForAll(false)` for
/// the same four, in the same order. Submitted as a relayer `WALLET` batch from
/// the deposit wallet so a user can withdraw the trading contracts' spending
/// authority over their collateral and positions.
pub fn v2_revoke_calls() -> Vec<Call> {
    vec![
        approve_amount_call(PUSD, CTF_EXCHANGE_V2, U256::ZERO),
        approve_amount_call(PUSD, NEG_RISK_EXCHANGE_V2, U256::ZERO),
        approve_amount_call(PUSD, CTF_COLLATERAL_ADAPTER, U256::ZERO),
        approve_amount_call(PUSD, NEG_RISK_CTF_COLLATERAL_ADAPTER, U256::ZERO),
        set_approval_for_all_value_call(CTF, CTF_EXCHANGE_V2, false),
        set_approval_for_all_value_call(CTF, NEG_RISK_EXCHANGE_V2, false),
        set_approval_for_all_value_call(CTF, CTF_COLLATERAL_ADAPTER, false),
        set_approval_for_all_value_call(CTF, NEG_RISK_CTF_COLLATERAL_ADAPTER, false),
    ]
}

/// Redeem a resolved binary condition through the pUSD collateral adapter.
///
/// The V2 adapters expose the same call shape as the underlying CTF
/// `redeemPositions`: pUSD collateral, zero parent collection, condition id,
/// and index sets `[1, 2]`. The losing side burns for zero; the winning side
/// pays one pUSD per share. The target is selected by market class.
pub fn redeem_positions_call(condition_id: B256, neg_risk: bool) -> Call {
    Call {
        target: if neg_risk {
            NEG_RISK_CTF_COLLATERAL_ADAPTER
        } else {
            CTF_COLLATERAL_ADAPTER
        },
        value: U256::ZERO,
        data: redeemPositionsCall {
            collateralToken: PUSD,
            parentCollectionId: B256::ZERO,
            conditionId: condition_id,
            indexSets: vec![U256::from(1), U256::from(2)],
        }
        .abi_encode()
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
    const SET_APPROVAL_SELECTOR: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];
    const REDEEM_POSITIONS_SELECTOR: [u8; 4] = [0x01, 0xb7, 0x03, 0x7c];

    #[test]
    fn v2_set_has_exact_targets_spenders_and_selectors() {
        let calls = v2_approval_calls();
        assert_eq!(calls.len(), 8);

        // First 4: pUSD approve(spender, MAX) to the V2 exchanges + adapters.
        let approve_spenders = [
            CTF_EXCHANGE_V2,
            NEG_RISK_EXCHANGE_V2,
            CTF_COLLATERAL_ADAPTER,
            NEG_RISK_CTF_COLLATERAL_ADAPTER,
        ];
        for (i, spender) in approve_spenders.iter().enumerate() {
            let c = &calls[i];
            assert_eq!(c.target, PUSD, "approve[{i}] must target pUSD");
            assert_eq!(c.value, U256::ZERO);
            assert_eq!(&c.data[..4], &APPROVE_SELECTOR);
            let decoded = approveCall::abi_decode(&c.data).unwrap();
            assert_eq!(decoded.spender, *spender, "approve[{i}] wrong spender");
            assert_eq!(decoded.amount, U256::MAX);
        }

        // Last 4: CTF setApprovalForAll(operator, true) to the same four.
        for (i, operator) in approve_spenders.iter().enumerate() {
            let c = &calls[4 + i];
            assert_eq!(c.target, CTF, "setApprovalForAll[{i}] must target CTF");
            assert_eq!(&c.data[..4], &SET_APPROVAL_SELECTOR);
            let decoded = setApprovalForAllCall::abi_decode(&c.data).unwrap();
            assert_eq!(
                decoded.operator, *operator,
                "setApprovalForAll[{i}] wrong operator"
            );
            assert!(decoded.approved);
        }
    }

    #[test]
    fn v2_revoke_set_zeroes_the_same_spenders_and_operators() {
        let calls = v2_revoke_calls();
        assert_eq!(calls.len(), 8);
        let spenders = [
            CTF_EXCHANGE_V2,
            NEG_RISK_EXCHANGE_V2,
            CTF_COLLATERAL_ADAPTER,
            NEG_RISK_CTF_COLLATERAL_ADAPTER,
        ];
        // First 4: pUSD approve(spender, 0).
        for (i, spender) in spenders.iter().enumerate() {
            let c = &calls[i];
            assert_eq!(c.target, PUSD, "revoke approve[{i}] must target pUSD");
            assert_eq!(&c.data[..4], &APPROVE_SELECTOR);
            let decoded = approveCall::abi_decode(&c.data).unwrap();
            assert_eq!(
                decoded.spender, *spender,
                "revoke approve[{i}] wrong spender"
            );
            assert_eq!(decoded.amount, U256::ZERO, "revoke must approve ZERO");
        }
        // Last 4: CTF setApprovalForAll(operator, false), same four, same order.
        for (i, operator) in spenders.iter().enumerate() {
            let c = &calls[4 + i];
            assert_eq!(
                c.target, CTF,
                "revoke setApprovalForAll[{i}] must target CTF"
            );
            assert_eq!(&c.data[..4], &SET_APPROVAL_SELECTOR);
            let decoded = setApprovalForAllCall::abi_decode(&c.data).unwrap();
            assert_eq!(decoded.operator, *operator);
            assert!(!decoded.approved, "revoke must set approved = false");
        }
        // Mirrors v2_approval_calls target/spender ordering exactly.
        let approvals = v2_approval_calls();
        for (rev, app) in calls.iter().zip(&approvals) {
            assert_eq!(rev.target, app.target);
        }
    }

    #[test]
    fn redeem_call_targets_pusd_adapter_and_redeems_both_outcomes() {
        let condition_id = B256::repeat_byte(0x42);

        for (neg_risk, target) in [
            (false, CTF_COLLATERAL_ADAPTER),
            (true, NEG_RISK_CTF_COLLATERAL_ADAPTER),
        ] {
            let c = redeem_positions_call(condition_id, neg_risk);
            assert_eq!(c.target, target);
            assert_eq!(c.value, U256::ZERO);
            assert_eq!(&c.data[..4], &REDEEM_POSITIONS_SELECTOR);

            let decoded = redeemPositionsCall::abi_decode(&c.data).unwrap();
            assert_eq!(decoded.collateralToken, PUSD);
            assert_eq!(decoded.parentCollectionId, B256::ZERO);
            assert_eq!(decoded.conditionId, condition_id);
            assert_eq!(decoded.indexSets, vec![U256::from(1), U256::from(2)]);
        }
    }
}
