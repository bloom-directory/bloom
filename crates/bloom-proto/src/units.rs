//! Unit parsing and formatting helpers.
//!
//! Accepts:
//! - "1.5 eth", "1.5eth", "1.5 ether"
//! - "10 gwei"
//! - "100" (raw integer; assume native wei)
//! - "10 usdc" — *symbolic* token amounts; resolved later by the tx
//!   engine using token decimals.

use alloy::primitives::U256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnitError {
    #[error("empty amount")]
    Empty,
    #[error("could not parse amount '{0}'")]
    Parse(String),
    #[error("unknown unit '{0}'")]
    UnknownUnit(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAmount {
    /// Either a numeric raw value (`raw`) when `unit` is a known native
    /// metric (eth/gwei/wei) — pre-applied to wei, OR `None` when the
    /// caller must resolve `symbol` against ERC-20 decimals.
    pub raw: Option<U256>,
    /// Lowercased unit/token symbol, e.g. "eth", "gwei", "usdc".
    pub unit: String,
    /// The original numeric portion as a string (for downstream decimal
    /// resolution against a token's `decimals`).
    pub number: String,
}

impl ParsedAmount {
    pub fn is_native(&self) -> bool {
        matches!(self.unit.as_str(), "wei" | "gwei" | "eth" | "ether")
    }
}

/// Parse "1.5 eth" / "10 usdc" / "100 wei" / "100" into a [`ParsedAmount`].
pub fn parse_amount(s: &str) -> Result<ParsedAmount, UnitError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(UnitError::Empty);
    }
    // Split on first non-numeric character. Allow "1.5eth" as well as
    // "1.5 eth".
    let first_alpha = s
        .char_indices()
        .find(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i);
    let (num_part, unit_part) = match first_alpha {
        Some(i) => (s[..i].trim(), s[i..].trim().to_ascii_lowercase()),
        None => (s, "wei".to_string()),
    };
    if num_part.is_empty() {
        return Err(UnitError::Parse(s.into()));
    }

    let unit = unit_part;
    let raw = match unit.as_str() {
        "wei" => Some(parse_decimal(num_part, 0)?),
        "gwei" => Some(parse_decimal(num_part, 9)?),
        "eth" | "ether" => Some(parse_decimal(num_part, 18)?),
        _ => None,
    };
    Ok(ParsedAmount {
        raw,
        unit,
        number: num_part.to_string(),
    })
}

/// Parse a decimal string with up to `decimals` digits after the point.
pub fn parse_units(s: &str, decimals: u8) -> Result<U256, UnitError> {
    parse_decimal(s.trim(), decimals)
}

/// Parse "1.5 eth" -> wei.
pub fn parse_eth(s: &str) -> Result<U256, UnitError> {
    let p = parse_amount(s)?;
    p.raw.ok_or(UnitError::UnknownUnit(p.unit))
}

/// Render `wei` as a decimal with `decimals` places, trimming trailing
/// zeros after the point.
pub fn format_units(value: U256, decimals: u8) -> String {
    if decimals == 0 {
        return value.to_string();
    }
    let s = value.to_string();
    let dec = decimals as usize;
    if s.len() <= dec {
        let pad = dec - s.len();
        let mut out = String::from("0.");
        for _ in 0..pad {
            out.push('0');
        }
        out.push_str(&s);
        return trim_trailing(&out);
    }
    let (whole, frac) = s.split_at(s.len() - dec);
    let raw = format!("{}.{}", whole, frac);
    trim_trailing(&raw)
}

fn trim_trailing(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let trimmed = s.trim_end_matches('0');
    let trimmed = trimmed.trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_decimal(s: &str, decimals: u8) -> Result<U256, UnitError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(UnitError::Parse(s.into()));
    }
    let neg = s.starts_with('-');
    if neg {
        return Err(UnitError::Parse(s.into()));
    }
    let body = s.strip_prefix('+').unwrap_or(s);

    let (whole_str, frac_str) = match body.split_once('.') {
        Some((a, b)) => (a, b),
        None => (body, ""),
    };
    if whole_str.chars().any(|c| !c.is_ascii_digit()) && !whole_str.is_empty() {
        return Err(UnitError::Parse(s.into()));
    }
    if frac_str.chars().any(|c| !c.is_ascii_digit()) {
        return Err(UnitError::Parse(s.into()));
    }
    if frac_str.len() > decimals as usize {
        return Err(UnitError::Parse(format!(
            "{} has more than {} fractional digits",
            s, decimals
        )));
    }
    let mut padded_frac = frac_str.to_string();
    while padded_frac.len() < decimals as usize {
        padded_frac.push('0');
    }
    let combined = if whole_str.is_empty() && padded_frac.is_empty() {
        "0".to_string()
    } else if whole_str.is_empty() {
        padded_frac
    } else {
        format!("{}{}", whole_str, padded_frac)
    };
    U256::from_str_radix(&combined, 10).map_err(|_| UnitError::Parse(s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eth_amounts() {
        assert_eq!(
            parse_eth("1 eth").unwrap(),
            U256::from(1_000_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_eth("1.5 eth").unwrap(),
            U256::from(1_500_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_eth("0.000000001 eth").unwrap(),
            U256::from(1_000_000_000u64)
        );
        assert_eq!(parse_eth("10 gwei").unwrap(), U256::from(10_000_000_000u64));
        assert_eq!(parse_eth("100 wei").unwrap(), U256::from(100u64));
    }

    #[test]
    fn parse_token_amounts_unresolved() {
        let p = parse_amount("10 usdc").unwrap();
        assert!(p.raw.is_none());
        assert_eq!(p.unit, "usdc");
        assert_eq!(p.number, "10");
    }

    #[test]
    fn format_round_trip() {
        let wei = parse_eth("1.5 eth").unwrap();
        assert_eq!(format_units(wei, 18), "1.5");
        assert_eq!(format_units(U256::from(0u64), 18), "0");
        assert_eq!(format_units(U256::from(1u64), 18), "0.000000000000000001");
    }

    #[test]
    fn rejects_extra_decimals() {
        assert!(parse_eth("1.0000000001 gwei").is_err()); // 10 frac > 9
    }
}
