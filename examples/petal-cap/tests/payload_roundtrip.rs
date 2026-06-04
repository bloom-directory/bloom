//! `Cap<T>` payload-layer round-trip tests.
//!
//! `Cap<T>` is encoded on the wire as `id (UID) || inner_kind (u8) ||
//! expires_at_block (u64 BE) || revoked (bool)`. We re-encode the payload
//! from outside the petal and check the bytes are stable, deterministic,
//! and decode losslessly.

use bloom_objects::ObjectId;
use bloom_objects::TypeTag;
use bloom_resource::{ArgReader, RetWriter};
use bloom_value::{CodecLimits, validate_value_bytes};

/// Re-encode a payload manually, exactly as the petal body does.
fn encode(inner_kind: u8, expires_at_block: u64, revoked: bool) -> Vec<u8> {
    let mut w = RetWriter::with_capacity(bloom_petal_cap::CAP_PAYLOAD_LEN);
    w.write_object_id(&ObjectId([0u8; 32]));
    w.write_u8(inner_kind);
    w.write_u64(expires_at_block);
    w.write_bool(revoked);
    w.finish()
}

fn decode(buf: &[u8]) -> (u8, u64, bool) {
    let mut r = ArgReader::new(buf);
    let _id = r.read_object_id().unwrap();
    let k = r.read_u8().unwrap();
    let e = r.read_u64().unwrap();
    let rev = r.read_bool().unwrap();
    r.expect_eof().unwrap();
    (k, e, rev)
}

fn self_type(name: &str, type_args: Vec<TypeTag>) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: name.to_string(),
        type_args,
    }
}

#[test]
fn payload_open_round_trip() {
    let bytes = encode(0, 0, false);
    assert_eq!(bytes.len(), 42);
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
fn payload_is_exactly_forty_two_bytes() {
    // Sanity: the wire size is fixed (no length prefixes on a u8 or a
    // u64; one byte on the trailing bool). This is the canonical
    // CAP_PAYLOAD_LEN.
    assert_eq!(bloom_petal_cap::CAP_PAYLOAD_LEN, 42);
    for k in [0u8, 1, 2] {
        for r in [false, true] {
            assert_eq!(encode(k, u64::MAX, r).len(), 42);
        }
    }
}

#[test]
fn payload_byte_layout_open() {
    // id=0 || inner_kind=0 || 0u64 BE || revoked=0.
    assert_eq!(encode(0, 0, false), vec![0u8; 42]);
}

#[test]
fn payload_byte_layout_expire_at_max() {
    let bytes = encode(2, u64::MAX, true);
    assert_eq!(&bytes[..32], &[0u8; 32]);
    assert_eq!(bytes[32], 2);
    assert_eq!(&bytes[33..41], &[0xFFu8; 8]);
    assert_eq!(bytes[41], 1);
}

#[test]
fn payloads_validate_against_declared_manifest_layouts() {
    let manifest =
        bloom_petal_manifest::codec::decode(bloom_petal_cap::cap::__bloom_manifest_bytes())
            .unwrap();
    let resolver = bloom_petal_manifest::ManifestResolver::new(&manifest);
    let limits = CodecLimits::default();
    let marker = self_type("Marker", vec![]);

    let cap_tag = self_type("Cap", vec![marker.clone()]);
    validate_value_bytes(&resolver, &cap_tag, &encode(2, 99, true), &limits).unwrap();
    assert!(
        validate_value_bytes(&resolver, &cap_tag, &[0u8; 10], &limits).is_err(),
        "old body-only Cap<T> payloads must not validate"
    );

    let revoke_cap_tag = self_type("RevokeCap", vec![marker]);
    validate_value_bytes(&resolver, &revoke_cap_tag, &[0u8; 32], &limits).unwrap();
    assert!(
        validate_value_bytes(&resolver, &revoke_cap_tag, &[], &limits).is_err(),
        "old empty RevokeCap<T> payloads must not validate"
    );
}
