//! `Cap<T>` payload-layer round-trip tests.
//!
//! `Cap<T>` is encoded on the wire as 10 bytes: `inner_kind (u8) ||
//! expires_at_block (u64 BE) || revoked (bool)`. We re-encode the
//! payload from outside the petal (mirroring what `bloom-script`'s PTB
//! executor will do when materializing the object) and check the bytes
//! are stable, deterministic, and decode losslessly.

use bloom_resource::{ArgReader, RetWriter};

/// Re-encode a payload manually, exactly as the petal body does.
fn encode(inner_kind: u8, expires_at_block: u64, revoked: bool) -> Vec<u8> {
    let mut w = RetWriter::new();
    w.write_u8(inner_kind);
    w.write_u64(expires_at_block);
    w.write_bool(revoked);
    w.finish()
}

fn decode(buf: &[u8]) -> (u8, u64, bool) {
    let mut r = ArgReader::new(buf);
    let k = r.read_u8().unwrap();
    let e = r.read_u64().unwrap();
    let rev = r.read_bool().unwrap();
    r.expect_eof().unwrap();
    (k, e, rev)
}

#[test]
fn payload_open_round_trip() {
    let bytes = encode(0, 0, false);
    assert_eq!(bytes.len(), 10);
    assert_eq!(decode(&bytes), (0u8, 0u64, false));
}

#[test]
fn payload_locked_round_trip() {
    let bytes = encode(1, 0, false);
    assert_eq!(decode(&bytes), (1u8, 0u64, false));
}

#[test]
fn payload_expire_at_round_trip() {
    let bytes = encode(2, 1_234_567u64, false);
    assert_eq!(decode(&bytes), (2u8, 1_234_567u64, false));
}

#[test]
fn payload_revoked_open_round_trip() {
    let bytes = encode(0, 0, true);
    assert_eq!(decode(&bytes), (0u8, 0u64, true));
}

#[test]
fn payload_is_exactly_ten_bytes() {
    // Sanity: the wire size is fixed (no length prefixes on a u8 or a
    // u64; one byte on the trailing bool). This is the canonical
    // CAP_PAYLOAD_LEN.
    assert_eq!(bloom_petal_cap::CAP_PAYLOAD_LEN, 10);
    for k in [0u8, 1, 2] {
        for r in [false, true] {
            assert_eq!(encode(k, u64::MAX, r).len(), 10);
        }
    }
}

#[test]
fn payload_byte_layout_open() {
    // inner_kind=0 || 0u64 BE || revoked=0 → ten zero bytes.
    assert_eq!(encode(0, 0, false), vec![0u8; 10]);
}

#[test]
fn payload_byte_layout_expire_at_max() {
    let bytes = encode(2, u64::MAX, true);
    assert_eq!(bytes[0], 2);
    assert_eq!(&bytes[1..9], &[0xFFu8; 8]);
    assert_eq!(bytes[9], 1);
}
