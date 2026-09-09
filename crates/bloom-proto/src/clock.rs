//! Wall-clock milliseconds since the Unix epoch, shared so every caller
//! fails loudly on a broken system clock instead of quietly recording a
//! fabricated epoch-0 timestamp.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. `Err` when the system clock is set
/// before 1970, or the elapsed time doesn't fit in a `u64` millisecond
/// count — callers should propagate either as a hard failure rather than
/// defaulting to `0`, which would silently corrupt whatever timestamp,
/// expiry check, or audit record depends on it.
pub fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system time overflow".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_a_plausible_current_timestamp() {
        // Sanity bound, not a precise check: after this module's own
        // addition (2026) and comfortably before any real overflow.
        let ms = now_ms().unwrap();
        assert!(ms > 1_700_000_000_000);
        assert!(ms < 4_000_000_000_000);
    }
}
