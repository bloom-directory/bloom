//! Shared serde helpers for micro-USD `Option<u64>` fields used across all
//! venue policy modules. Accepts decimal strings (preferred) and integers /
//! floats (converted via their shortest decimal representation so no
//! binary-float dust leaks into policy). Serializes back as a decimal string.

use alloy::primitives::U256;

/// One USD in micro-USD (6 decimal places).
pub const MICRO_USD: u64 = 1_000_000;

/// Parse a decimal USD string into micro-USD (`u64`).
pub fn parse_decimal_micro(s: &str) -> Result<u64, String> {
    let v =
        crate::units::parse_units(s.trim(), 6).map_err(|e| format!("bad USD amount '{s}': {e}"))?;
    u64::try_from(v).map_err(|_| format!("USD amount '{s}' too large"))
}

/// Format micro-USD as a human-readable decimal string (e.g. `12.5`).
pub fn fmt_usd(micro: u64) -> String {
    crate::units::format_units(U256::from(micro), 6)
}

// ── serde for `Option<u64>` micro-USD ───────────────────────────────────

pub fn serialize<S: serde::Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        None => s.serialize_none(),
        Some(micro) => s.serialize_some(&crate::units::format_units(U256::from(*micro), 6)),
    }
}

pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    use serde::Deserialize as _;
    use serde::de::Error as _;

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Raw {
        S(String),
        I(i64),
        F(f64),
    }
    match Option::<Raw>::deserialize(d)? {
        None => Ok(None),
        Some(Raw::S(s)) => parse_decimal_micro(&s).map(Some).map_err(D::Error::custom),
        Some(Raw::I(i)) => {
            if i < 0 {
                return Err(D::Error::custom("USD amount cannot be negative"));
            }
            (i as u64)
                .checked_mul(MICRO_USD)
                .map(Some)
                .ok_or_else(|| D::Error::custom("USD amount too large"))
        }
        // Shortest decimal repr round-trips the intended value ("0.1" not
        // "0.1000000000000000055…").
        Some(Raw::F(f)) => parse_decimal_micro(&format!("{f}"))
            .map(Some)
            .map_err(D::Error::custom),
    }
}
