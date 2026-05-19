//! 256-bit unsigned integer — big-endian `[u8; 32]` newtype.
//!
//! Operations are checked (returning `None` on overflow / underflow / divide-
//! by-zero). No `std`, no proc-macros, no derives that require `std`.

#[cfg(not(feature = "std"))]
use core::cmp::Ordering;
#[cfg(feature = "std")]
use std::cmp::Ordering;

/// A 256-bit unsigned integer stored as 32 big-endian bytes.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct U256(pub [u8; 32]);

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl U256 {
    /// Zero.
    pub const ZERO: U256 = U256([0u8; 32]);

    /// Construct from a `u64`.
    pub fn from_u64(v: u64) -> Self {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&v.to_be_bytes());
        U256(b)
    }

    /// Construct from a `u128`.
    pub fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        b[16..32].copy_from_slice(&v.to_be_bytes());
        U256(b)
    }

    /// Return `true` iff this value is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Attempt to convert to `u128`, returning `None` if the value exceeds
    /// `u128::MAX` (i.e. the upper 16 bytes are non-zero).
    pub fn to_u128_checked(&self) -> Option<u128> {
        if self.0[..16] != [0u8; 16] {
            return None;
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[16..32]);
        Some(u128::from_be_bytes(buf))
    }

    /// Raw bytes (big-endian).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Byte-wise big-endian comparison is correct for unsigned ints.
        self.0.cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic helpers
// ---------------------------------------------------------------------------

/// Add two 32-byte big-endian values. Returns `None` on overflow.
fn add_be(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        result[i] = s as u8;
        carry = s >> 8;
    }
    if carry != 0 { None } else { Some(result) }
}

/// Subtract two 32-byte big-endian values (a - b). Returns `None` if a < b.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as i16 - b[i] as i16 - borrow;
        if s < 0 {
            result[i] = (s + 256) as u8;
            borrow = 1;
        } else {
            result[i] = s as u8;
            borrow = 0;
        }
    }
    if borrow != 0 { None } else { Some(result) }
}

/// Multiply two 32-byte big-endian values. Returns `None` on overflow
/// (any non-zero digit in the high half of the schoolbook product).
fn mul_be(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    // Schoolbook multiplication with 64 limbs of 8 bits each.
    // Product is 64 bytes; we need the upper 32 to be zero.
    let mut product = [0u32; 64];
    for i in 0..32 {
        for j in 0..32 {
            product[i + j + 1] += a[i] as u32 * b[j] as u32;
        }
    }
    // Propagate carries (from the end).
    for k in (1..64).rev() {
        product[k - 1] += product[k] >> 8;
        product[k] &= 0xff;
    }
    // Upper 32 bytes must be zero.
    for &d in &product[..32] {
        if d != 0 {
            return None;
        }
    }
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = product[32 + i] as u8;
    }
    Some(result)
}

/// Divide a 32-byte big-endian value by another using bit-by-bit long division.
/// Returns `None` if `b` is zero. Returns `(quotient, remainder)`.
fn divmod_be(a: &[u8; 32], b: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    if b == &[0u8; 32] {
        return None;
    }
    let mut remainder = [0u8; 32];
    let mut quotient = [0u8; 32];

    for byte_idx in 0..32 {
        for bit in (0..8).rev() {
            // Shift remainder left by 1.
            let mut carry = (a[byte_idx] >> bit) & 1;
            for k in (0..32).rev() {
                let new_carry = (remainder[k] >> 7) & 1;
                remainder[k] = (remainder[k] << 1) | carry;
                carry = new_carry;
            }
            // If remainder >= b, subtract.
            if remainder >= *b {
                // remainder -= b
                let mut borrow: i16 = 0;
                for k in (0..32).rev() {
                    let s = remainder[k] as i16 - b[k] as i16 - borrow;
                    if s < 0 {
                        remainder[k] = (s + 256) as u8;
                        borrow = 1;
                    } else {
                        remainder[k] = s as u8;
                        borrow = 0;
                    }
                }
                // Set corresponding quotient bit.
                let q_byte = byte_idx;
                let q_bit = bit;
                quotient[q_byte] |= 1 << q_bit;
            }
        }
    }
    Some((quotient, remainder))
}

// ---------------------------------------------------------------------------
// U256 arithmetic methods
// ---------------------------------------------------------------------------

impl U256 {
    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        add_be(&self.0, &rhs.0).map(U256)
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        sub_be(&self.0, &rhs.0).map(U256)
    }

    /// Checked multiplication. Returns `None` on overflow.
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        mul_be(&self.0, &rhs.0).map(U256)
    }

    /// Checked integer division. Returns `None` if `rhs` is zero.
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        divmod_be(&self.0, &rhs.0).map(|(q, _)| U256(q))
    }

    /// Checked remainder. Returns `None` if `rhs` is zero.
    pub fn checked_rem(self, rhs: Self) -> Option<Self> {
        divmod_be(&self.0, &rhs.0).map(|(_, r)| U256(r))
    }

    /// Integer square root via Babylonian iteration. Always succeeds (returns
    /// 0 for 0). Result satisfies `sqrt^2 <= self < (sqrt+1)^2`.
    pub fn sqrt(self) -> Self {
        if self.is_zero() {
            return U256::ZERO;
        }

        // Initial estimate: shift self right by half its bit-length.
        // Find the highest set bit position.
        let mut highest = 0usize;
        'outer: for i in 0..32 {
            for b in (0..8).rev() {
                if (self.0[i] >> b) & 1 == 1 {
                    highest = (31 - i) * 8 + b;
                    break 'outer;
                }
            }
        }
        // Initial estimate: 2^((highest/2)+1)
        let shift = (highest / 2) + 1;
        let mut x = {
            let byte_pos = 31usize.saturating_sub(shift / 8);
            let bit_pos = shift % 8;
            let mut b = [0u8; 32];
            if byte_pos < 32 {
                b[byte_pos] = 1u8 << bit_pos;
            }
            U256(b)
        };

        // Newton-Raphson / Babylonian: x_{n+1} = (x_n + self/x_n) / 2
        loop {
            let div = self.checked_div(x).unwrap_or(U256::ZERO);
            let sum = match x.checked_add(div) {
                Some(s) => s,
                None => {
                    // Overflow in intermediate sum; halve x and retry.
                    // Shift x right by 1.
                    let mut b = x.0;
                    let mut carry = 0u8;
                    for i in 0..32 {
                        let new_carry = b[i] & 1;
                        b[i] = (b[i] >> 1) | (carry << 7);
                        carry = new_carry;
                    }
                    x = U256(b);
                    continue;
                }
            };
            // Halve: shift sum right by 1.
            let mut b = sum.0;
            let mut carry = 0u8;
            for i in 0..32 {
                let new_carry = b[i] & 1;
                b[i] = (b[i] >> 1) | (carry << 7);
                carry = new_carry;
            }
            let x1 = U256(b);
            if x1 >= x {
                break;
            }
            x = x1;
        }
        // Correct for off-by-one (ensure x^2 <= self).
        loop {
            match x.checked_mul(x) {
                Some(sq) if sq <= self => {
                    // Check (x+1)^2 > self.
                    let x1 = match x.checked_add(U256::from_u64(1)) {
                        Some(v) => v,
                        None => break, // x is at max, so x is the sqrt
                    };
                    match x1.checked_mul(x1) {
                        Some(sq1) if sq1 <= self => {
                            x = x1;
                        }
                        _ => break,
                    }
                }
                _ => {
                    // x^2 > self, decrement.
                    x = match x.checked_sub(U256::from_u64(1)) {
                        Some(v) => v,
                        None => return U256::ZERO,
                    };
                }
            }
        }
        x
    }
}

// ---------------------------------------------------------------------------
// Debug / Display (std-only, but with no_std fallback)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
impl core::fmt::Debug for U256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "U256(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Debug for U256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "U256([...])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u64_roundtrip() {
        let v = U256::from_u64(12345);
        assert_eq!(v.to_u128_checked(), Some(12345u128));
    }

    #[test]
    fn from_u128_roundtrip() {
        let big = u128::MAX - 7;
        let v = U256::from_u128(big);
        assert_eq!(v.to_u128_checked(), Some(big));
    }

    #[test]
    fn add_overflow() {
        let max = U256([0xff; 32]);
        let one = U256::from_u64(1);
        assert!(max.checked_add(one).is_none());
    }

    #[test]
    fn sub_underflow() {
        let zero = U256::ZERO;
        let one = U256::from_u64(1);
        assert!(zero.checked_sub(one).is_none());
    }

    #[test]
    fn mul_overflow() {
        // (2^128) * (2^128) = 2^256 — overflows.
        let hi = {
            let mut b = [0u8; 32];
            b[15] = 1; // 2^128
            U256(b)
        };
        assert!(hi.checked_mul(hi).is_none());
    }

    #[test]
    fn div_by_zero() {
        let one = U256::from_u64(1);
        assert!(one.checked_div(U256::ZERO).is_none());
    }

    #[test]
    fn sqrt_perfect_squares() {
        for n in [0u64, 1, 4, 9, 16, 25, 100, 10000, u64::MAX / 2] {
            let sq = U256::from_u128(n as u128 * n as u128);
            let root = sq.sqrt();
            assert_eq!(root, U256::from_u64(n), "sqrt({n}^2) failed");
        }
    }

    #[test]
    fn sqrt_non_perfect() {
        // sqrt(10) = 3
        let v = U256::from_u64(10);
        let r = v.sqrt();
        assert_eq!(r, U256::from_u64(3));
    }

    #[test]
    fn ordering() {
        let a = U256::from_u64(1);
        let b = U256::from_u64(2);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, a);
    }
}
