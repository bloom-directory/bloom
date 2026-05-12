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
        TxFees::Legacy { gas_price } => TxFees::Legacy {
            gas_price: bump_125(gas_price),
        },
        TxFees::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => TxFees::Eip1559 {
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
            max_fee_per_gas: 50_000_000_000,         // 50 gwei
            max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        });
        match f {
            TxFees::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                assert_eq!(max_fee_per_gas, 56_250_000_000); // 50*9/8 = 56.25 gwei
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
        let f = compute_replacement_fees(TxFees::Legacy {
            gas_price: near_max,
        });
        match f {
            TxFees::Legacy { gas_price } => assert!(gas_price > near_max),
            _ => panic!("expected legacy"),
        }
    }
}
