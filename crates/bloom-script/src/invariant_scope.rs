//! Canonical "flat field-table" scope buffer for invariant evaluation
//! (plan §5, ADR-008).
//!
//! The host extracts the named `u128` fields an invariant cares about
//! (e.g. `before.reserve_a`, `after.k_last`) from a borrow row's
//! baseline/current payloads, and lays them out as a flat
//! name → value table. The compiled `__inv_<idx>` wasm export receives a
//! pointer to this buffer and looks fields up by name, so the guest never
//! needs to know the type-defining petal's struct layout.
//!
//! Wire format (deterministic, big-endian):
//! ```text
//! off  size  field
//! 0    1     scope_kind        (0x00 = FunctionExit, 0x01 = ObjectType)
//! 1    2     target_name_len   (u16 BE)
//! 3    n     target_name       (UTF-8)
//! 3+n  4     petal_version     (u32 BE)
//! 7+n  2     field_count       (u16 BE)
//! --- per field ---
//!      2     name_len          (u16 BE)
//!      m     name              (UTF-8)
//!      16    value             (u128 BE)
//! ```

use bloom_objects::codec::{
    CodecError, expect_eof, read_string, read_u8, read_u16_be, read_u32_be, write_string, write_u8,
    write_u16_be, write_u32_be,
};

/// `scope_kind` byte for a function-exit invariant.
pub const SCOPE_KIND_FUNCTION_EXIT: u8 = 0x00;
/// `scope_kind` byte for an object-type invariant.
pub const SCOPE_KIND_OBJECT_TYPE: u8 = 0x01;

/// Build a flat field-table scope buffer (see module docs).
pub fn build_invariant_scope(
    scope_kind: u8,
    target_name: &str,
    petal_version: u32,
    fields: &[(String, u128)],
) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    write_u8(&mut buf, scope_kind);
    write_string(&mut buf, target_name)?;
    write_u32_be(&mut buf, petal_version);
    let count =
        u16::try_from(fields.len()).map_err(|_| CodecError::LengthOverflow(fields.len() as u64))?;
    write_u16_be(&mut buf, count);
    for (name, value) in fields {
        write_string(&mut buf, name)?;
        buf.extend_from_slice(&value.to_be_bytes());
    }
    Ok(buf)
}

/// A decoded scope buffer. Used by the round-trip gate and the host-side
/// trusted interpreter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedScope {
    /// `SCOPE_KIND_*` discriminant.
    pub scope_kind: u8,
    /// Target object-type / function name.
    pub target_name: String,
    /// Petal version the scope was built against.
    pub petal_version: u32,
    /// Field name → value pairs, in encoding order.
    pub fields: Vec<(String, u128)>,
}

/// Decode a scope buffer built by [`build_invariant_scope`].
pub fn decode_invariant_scope(buf: &[u8]) -> Result<DecodedScope, CodecError> {
    let mut rdr = buf;
    let scope_kind = read_u8(&mut rdr)?;
    let target_name = read_string(&mut rdr)?;
    let petal_version = read_u32_be(&mut rdr)?;
    let count = read_u16_be(&mut rdr)? as usize;
    let mut fields = Vec::new();
    for _ in 0..count {
        let name = read_string(&mut rdr)?;
        let value = read_u128_be(&mut rdr)?;
        fields.push((name, value));
    }
    expect_eof(rdr)?;
    Ok(DecodedScope {
        scope_kind,
        target_name,
        petal_version,
        fields,
    })
}

/// Look up a named field's `u128` value directly from an encoded scope
/// buffer, without fully decoding it. Returns `None` if the name is
/// absent or the buffer is malformed. This is the host-side mirror of
/// the lookup the generated `__inv_<idx>` export performs in the guest.
pub fn lookup_field(buf: &[u8], name: &str) -> Option<u128> {
    let mut rdr = buf;
    let _scope_kind = read_u8(&mut rdr).ok()?;
    let _target = read_string(&mut rdr).ok()?;
    let _version = read_u32_be(&mut rdr).ok()?;
    let count = read_u16_be(&mut rdr).ok()?;
    for _ in 0..count {
        let entry = read_string(&mut rdr).ok()?;
        let value = read_u128_be(&mut rdr).ok()?;
        if entry == name {
            return Some(value);
        }
    }
    None
}

fn read_u128_be(rdr: &mut &[u8]) -> Result<u128, CodecError> {
    if rdr.len() < 16 {
        return Err(CodecError::UnexpectedEof {
            needed: 16,
            available: rdr.len(),
        });
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&rdr[..16]);
    *rdr = &rdr[16..];
    Ok(u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_round_trip_and_idempotent() {
        let fields = vec![
            ("before.reserve_a".to_string(), 1_000u128),
            ("before.reserve_b".to_string(), 2_000u128),
            ("before.k_last".to_string(), 2_000_000u128),
            ("after.reserve_a".to_string(), 1_500u128),
            ("after.reserve_b".to_string(), u128::MAX),
        ];
        let scope = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, "Pool", 7, &fields).unwrap();

        let decoded = decode_invariant_scope(&scope).unwrap();
        assert_eq!(decoded.scope_kind, SCOPE_KIND_OBJECT_TYPE);
        assert_eq!(decoded.target_name, "Pool");
        assert_eq!(decoded.petal_version, 7);
        assert_eq!(decoded.fields, fields);

        // Field lookup matches.
        assert_eq!(lookup_field(&scope, "before.k_last"), Some(2_000_000));
        assert_eq!(lookup_field(&scope, "after.reserve_b"), Some(u128::MAX));
        assert_eq!(lookup_field(&scope, "missing"), None);

        // Encoding is idempotent.
        let scope2 = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, "Pool", 7, &fields).unwrap();
        assert_eq!(scope, scope2);

        // decode → re-encode round-trip (catches trailing-byte leaks).
        let scope3 = build_invariant_scope(
            decoded.scope_kind,
            &decoded.target_name,
            decoded.petal_version,
            &decoded.fields,
        )
        .unwrap();
        assert_eq!(scope, scope3);
    }

    #[test]
    fn scope_zero_fields_round_trips() {
        let scope = build_invariant_scope(SCOPE_KIND_FUNCTION_EXIT, "enter_pool", 0, &[]).unwrap();

        let decoded = decode_invariant_scope(&scope).unwrap();
        assert_eq!(decoded.scope_kind, SCOPE_KIND_FUNCTION_EXIT);
        assert_eq!(decoded.target_name, "enter_pool");
        assert_eq!(decoded.petal_version, 0);
        assert_eq!(decoded.fields, vec![]);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let scope = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, "Pool", 1, &[]).unwrap();
        let mut corrupted = scope.clone();
        corrupted.push(0xFF);
        assert!(
            decode_invariant_scope(&corrupted).is_err(),
            "trailing bytes must be rejected"
        );
    }

    #[test]
    fn lookup_field_on_truncated_buffer_returns_none() {
        let fields = vec![("before.x".to_string(), 42u128)];

        let scope = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, "Pool", 0, &fields).unwrap();

        // Truncate partway through the last field value (cut ⟦16 bytes).
        let truncated = &scope[..scope.len() - 8];
        assert_eq!(lookup_field(truncated, "before.x"), None);
    }
}
