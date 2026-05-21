//! Integer square root (floor) using the Babylonian / Newton's method.

/// Compute floor(sqrt(n)) for any `u128` using the Babylonian method.
///
/// Returns 0 for input 0. The result `s` satisfies `s*s <= n < (s+1)*(s+1)`
/// (with the upper bound checked in a wrapping-safe way for `n == u128::MAX`).
pub fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    // Initial estimate: bit-length based upper bound.
    // For n < 2^k, sqrt(n) < 2^(k/2 + 1).
    let bits = u128::BITS - n.leading_zeros();
    let mut x: u128 = 1u128 << bits.div_ceil(2);

    // Babylonian iteration: x_{n+1} = (x_n + n/x_n) / 2
    loop {
        let x_next = (x + n / x) / 2;
        if x_next >= x {
            return x;
        }
        x = x_next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqrt_contract_holds_for_range() {
        // For all n in a sample set, verify s*s <= n and (s+1)*(s+1) > n
        let cases: &[u128] = &[
            0,
            1,
            2,
            3,
            4,
            5,
            8,
            9,
            15,
            16,
            17,
            99,
            100,
            101,
            999_999,
            1_000_000,
            1_000_001,
            u64::MAX as u128,
            u128::MAX / 2,
        ];
        for &n in cases {
            let s = integer_sqrt(n);
            assert!(s * s <= n, "s*s > n for n={n}, s={s}");
            let (sq1, ov) = (s + 1).overflowing_mul(s + 1);
            assert!(ov || sq1 > n, "(s+1)^2 <= n for n={n}, s={s}");
        }
    }
}
