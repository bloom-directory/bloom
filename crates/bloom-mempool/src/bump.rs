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
///
/// Post-condition: the returned value is strictly greater than `v` for
/// any `v < u128::MAX`. When `v == u128::MAX` (or when `v * 9` would
/// overflow `u128`), we saturate at `u128::MAX` — still `>= v`, which is
/// the best we can do without a wider integer type.
fn bump_125(v: u128) -> u128 {
    match v.checked_mul(9) {
        Some(nine_v) => {
            // Normal path: ceil(nine_v / 8)
            let bumped = nine_v / 8;
            let rem = nine_v % 8;
            let result = if rem > 0 { bumped + 1 } else { bumped };
            // EIP-1559 requires strictly greater than v. For v > 0, 9v/8 > v
            // always holds; for v == 0, return 1 so we still increase.
            if v == 0 { 1 } else { result }
        }
        // Overflow — saturate at u128::MAX (still >= v). Using saturating
        // arithmetic here previously produced `u128::MAX / 8 ≈ 2^125`,
        // which is actually smaller than `v` when `v > 2^125`.
        None => u128::MAX,
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

    #[test]
    fn very_large_overflow_saturates_to_max_and_does_not_decrease() {
        let v = u128::MAX / 2; // v * 9 overflows
        let f = compute_replacement_fees(TxFees::Legacy { gas_price: v });
        match f {
            TxFees::Legacy { gas_price } => {
                assert!(gas_price >= v, "bumped result must not be less than input");
                assert_eq!(gas_price, u128::MAX, "expected saturation at u128::MAX");
            }
            _ => panic!("expected legacy"),
        }
    }
}
