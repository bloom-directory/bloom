//! Wall-clock milliseconds since the Unix epoch, shared so the several
//! copies of this logic can't drift apart, and so a broken system clock is
//! reported to the caller rather than silently folded into a timestamp.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. `Err` when the system clock is set
/// before 1970, or the elapsed time doesn't fit in a `u64` millisecond
/// count.
///
/// Returning `Result` makes the failure visible at each call site; it does
/// not by itself make every caller strict, and today they differ:
///
/// - The audit journal (`bloom-proto::audit`) and exact-payload signing
///   (`bloom-vfs::exact_signing`) propagate the error, because a fabricated
///   timestamp there would corrupt a signed or tamper-evident record.
/// - Several VFS/store/watch callers still degrade to `0` via
///   `unwrap_or(0)`, preserving the behaviour they had before this module
///   existed. That is a real weakness where a timestamp gates something —
///   `handlers::wallets` can read a ceremony expiry as not-yet-expired, and
///   `handlers::simulate` can stamp `created_ms = 0` — and it is kept only
///   because tightening those paths is a behavioural change, not a
///   refactor. Prefer propagating in new callers.
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
