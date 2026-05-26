//! `Packet` — the canonical typed value crossing a pipe boundary.
//!
//! A [`Packet`] is the value that travels along a pipe edge in the
//! front-door composition layer (spec §4, §6). Crucially, a packet is a
//! **reference within a transaction plan**, never bearer bytes:
//!
//! ```text
//! Packet    { type_tag: TypeTag, ref: PacketRef }
//! PacketRef = Use{ cmd_idx, ret_idx }    // intermediate: resolves only inside THIS plan
//!           | Object{ id, version }       // a persisted object the signer has access to
//! ```
//!
//! Encoding mirrors [`crate::object::Object`] / [`crate::object::Owner`]:
//! a 1-byte variant discriminant followed by a canonical, deterministic,
//! big-endian, no-float payload, with trailing bytes rejected on decode.
//!
//! # Anti-duplication is the executor, not this module
//!
//! This module enforces **nothing** at runtime — it is purely a codec and
//! value type. The "no double-spend / no cross-plan smuggling" guarantee
//! already exists in the chain executor and is independently tested:
//!
//! - A [`PacketRef::Use`] carries only `(cmd_idx, ret_idx)` — an *intra-plan*
//!   coordinate with **no plan identity**. It resolves only inside the
//!   atomic plan that produced it (against that plan's
//!   `ExecutionReport.command_outputs`). Copying its bytes (tee / temp
//!   file) into a *different* plan resolves to nothing: there is no
//!   command at that index, or it has an incompatible return type. The
//!   bytes carry no token that another plan could honor.
//! - A [`PacketRef::Object`] is gated by optimistic version + signer
//!   authority (`check_access_mode`, `validator.rs:587-621`). Spending
//!   always requires the chain's borrow-table row, enforced by
//!   `BorrowTable::linearity_check` (`borrow_table.rs:260-263`) plus
//!   `validate_ptb`.
//!
//! The envelope here is just the *serialization*. The linearity /
//! anti-duplication invariants live in `bloom-script`'s executor and
//! validator and are not (and must not be) re-implemented here.

use crate::codec::{
    self, CodecError, read_bytes32, read_u8, read_u16_be, read_u64_be, write_bytes32, write_u8,
    write_u16_be, write_u64_be,
};
use crate::id::ObjectId;
use crate::type_tag::TypeTag;

/// Variant tag byte for [`PacketRef::Use`].
pub const PACKET_REF_USE: u8 = 0;
/// Variant tag byte for [`PacketRef::Object`].
pub const PACKET_REF_OBJECT: u8 = 1;

/// A reference to the value carried on a pipe edge.
///
/// A packet never carries bearer bytes; it carries a *reference* that the
/// chain resolves at execution time. See the [module docs](self) for why
/// duplication is impossible despite the bytes being copyable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PacketRef {
    /// An **intermediate** value: the `ret_idx`-th return slot of the
    /// `cmd_idx`-th command of *this* plan. Resolves only inside the
    /// atomic plan that produced it — it carries no plan identity, so it
    /// is meaningless in any other plan. Mirrors `bloom-script`'s
    /// `Arg::Use{cmd_idx, ret_idx}` pipe edge.
    Use {
        /// Zero-based index of the producing command within the plan.
        cmd_idx: u16,
        /// Zero-based return-slot index of that command.
        ret_idx: u16,
    },
    /// A **persisted** object the signer has access to, pinned at a
    /// specific optimistic version.
    Object {
        /// Identifier of the persisted object.
        id: ObjectId,
        /// Optimistic version the reference is pinned to.
        version: u64,
    },
}

impl PacketRef {
    /// 1-byte variant discriminant.
    pub fn kind_byte(&self) -> u8 {
        match self {
            PacketRef::Use { .. } => PACKET_REF_USE,
            PacketRef::Object { .. } => PACKET_REF_OBJECT,
        }
    }

    /// Canonical-encode this reference into `buf`: kind byte then payload.
    ///
    /// - `Use`  → 2-byte BE `cmd_idx` + 2-byte BE `ret_idx`.
    /// - `Object` → 32-byte id + 8-byte BE `version`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        write_u8(buf, self.kind_byte());
        match self {
            PacketRef::Use { cmd_idx, ret_idx } => {
                write_u16_be(buf, *cmd_idx);
                write_u16_be(buf, *ret_idx);
            }
            PacketRef::Object { id, version } => {
                write_bytes32(buf, &id.0);
                write_u64_be(buf, *version);
            }
        }
    }

    /// Canonical-decode a reference from a cursor (no trailing-bytes check).
    pub fn decode_from(rdr: &mut &[u8]) -> Result<Self, CodecError> {
        let kind = read_u8(rdr)?;
        match kind {
            PACKET_REF_USE => {
                let cmd_idx = read_u16_be(rdr)?;
                let ret_idx = read_u16_be(rdr)?;
                Ok(PacketRef::Use { cmd_idx, ret_idx })
            }
            PACKET_REF_OBJECT => {
                let id = ObjectId(read_bytes32(rdr)?);
                let version = read_u64_be(rdr)?;
                Ok(PacketRef::Object { id, version })
            }
            other => Err(CodecError::InvalidDiscriminant(other)),
        }
    }

    /// Canonical-encode into a fresh buffer.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(41);
        self.encode_into(&mut buf);
        buf
    }

    /// Canonical-decode a reference, rejecting trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut rdr = bytes;
        let r = Self::decode_from(&mut rdr)?;
        codec::expect_eof(rdr)?;
        Ok(r)
    }
}

/// The typed value on a pipe edge.
///
/// Canonical encoding (deterministic, no floats):
/// 1. `type_tag` — recursive canonical encoding (see [`TypeTag`]).
/// 2. `ref_` — [`PacketRef`] kind byte + payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Packet {
    /// The declared type of the value crossing the pipe.
    pub type_tag: TypeTag,
    /// The in-plan / persisted reference the chain resolves at execution.
    ///
    /// Named `ref_` to avoid the `ref` keyword.
    pub ref_: PacketRef,
}

impl Packet {
    /// Build a packet referencing the `ret_idx`-th return slot of the
    /// `cmd_idx`-th command of the enclosing plan (a pipe edge).
    pub fn from_use(type_tag: TypeTag, cmd_idx: u16, ret_idx: u16) -> Self {
        Packet {
            type_tag,
            ref_: PacketRef::Use { cmd_idx, ret_idx },
        }
    }

    /// Build a packet referencing a persisted object at a pinned version.
    pub fn from_object(type_tag: TypeTag, id: ObjectId, version: u64) -> Self {
        Packet {
            type_tag,
            ref_: PacketRef::Object { id, version },
        }
    }

    /// Canonical-encode this packet into `buf`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<(), CodecError> {
        self.type_tag.encode_into(buf)?;
        self.ref_.encode_into(buf);
        Ok(())
    }

    /// Canonical-encode this packet into a fresh buffer.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Canonical-decode a packet, rejecting trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut rdr = bytes;
        let type_tag = TypeTag::decode_from(&mut rdr, 0)?;
        let ref_ = PacketRef::decode_from(&mut rdr)?;
        codec::expect_eof(rdr)?;
        Ok(Packet { type_tag, ref_ })
    }

    /// A **non-authoritative** human/debug projection for `cat` /
    /// introspection.
    ///
    /// This is *not* round-trippable and is *never* used for decoding:
    /// the canonical bytes from [`encode_canonical`](Self::encode_canonical)
    /// are the sole source of truth. The string here exists only so the
    /// front-door VFS can surface a readable affordance; do not parse it.
    pub fn debug_projection(&self) -> String {
        let ref_str = match &self.ref_ {
            PacketRef::Use { cmd_idx, ret_idx } => {
                format!("use @{cmd_idx}.{ret_idx}")
            }
            PacketRef::Object { id, version } => {
                format!("object {id}@v{version}")
            }
        };
        format!("packet<{}> {ref_str}", type_tag_label(&self.type_tag))
    }
}

/// Best-effort, **non-authoritative** type label for the debug projection.
/// Mirrors only the human-facing surface; never used for (de)serialization.
fn type_tag_label(t: &TypeTag) -> String {
    match t {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => {
            if type_args.is_empty() {
                type_name.clone()
            } else {
                let args: Vec<String> = type_args.iter().map(type_tag_label).collect();
                format!("{type_name}<{}>", args.join(", "))
            }
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("ext#{ref_idx}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concrete(name: &str, args: Vec<TypeTag>) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0xAB; 32],
            type_name: name.to_string(),
            type_args: args,
        }
    }

    fn rt(p: &Packet) {
        let bytes = p.encode_canonical().unwrap();
        let back = Packet::decode_canonical(&bytes).unwrap();
        assert_eq!(*p, back);
    }

    #[test]
    fn use_ref_roundtrip() {
        let r = PacketRef::Use {
            cmd_idx: 3,
            ret_idx: 7,
        };
        let bytes = r.encode_canonical();
        assert_eq!(bytes[0], PACKET_REF_USE);
        assert_eq!(PacketRef::decode_canonical(&bytes).unwrap(), r);
    }

    #[test]
    fn object_ref_roundtrip() {
        let r = PacketRef::Object {
            id: ObjectId([0x42; 32]),
            version: u64::MAX,
        };
        let bytes = r.encode_canonical();
        assert_eq!(bytes[0], PACKET_REF_OBJECT);
        assert_eq!(PacketRef::decode_canonical(&bytes).unwrap(), r);
    }

    #[test]
    fn packet_use_concrete_nested_roundtrip() {
        // Packet<Coin<USDC>> referencing a command return slot.
        let ty = concrete("Coin", vec![concrete("USDC", vec![])]);
        rt(&Packet::from_use(ty, 0, 0));
    }

    #[test]
    fn packet_use_deeply_nested_roundtrip() {
        // Coin<Pool<USDC, LOOM, ConstantProduct>> as a pipe edge.
        let pool = concrete(
            "Pool",
            vec![
                concrete("USDC", vec![]),
                concrete("LOOM", vec![]),
                concrete("ConstantProduct", vec![]),
            ],
        );
        let coin = concrete("Coin", vec![pool]);
        rt(&Packet::from_use(coin, u16::MAX, u16::MAX));
    }

    #[test]
    fn packet_object_generic_roundtrip() {
        rt(&Packet::from_object(
            TypeTag::Generic { idx: 4 },
            ObjectId([0x11; 32]),
            42,
        ));
    }

    #[test]
    fn packet_object_external_roundtrip() {
        rt(&Packet::from_object(
            TypeTag::External { ref_idx: 9 },
            ObjectId([0x99; 32]),
            0,
        ));
    }

    #[test]
    fn packet_decode_rejects_trailing_bytes() {
        let p = Packet::from_object(TypeTag::Generic { idx: 0 }, ObjectId([0; 32]), 1);
        let mut bytes = p.encode_canonical().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            Packet::decode_canonical(&bytes),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn packet_ref_decode_rejects_trailing_bytes() {
        let mut bytes = PacketRef::Use {
            cmd_idx: 1,
            ret_idx: 2,
        }
        .encode_canonical();
        bytes.push(0x00);
        assert!(matches!(
            PacketRef::decode_canonical(&bytes),
            Err(CodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn packet_ref_decode_rejects_invalid_discriminant() {
        // A discriminant byte outside {0, 1} must be rejected.
        let bad = [9u8, 0, 0, 0, 0];
        assert_eq!(
            PacketRef::decode_canonical(&bad),
            Err(CodecError::InvalidDiscriminant(9))
        );
    }

    #[test]
    fn packet_decode_rejects_invalid_ref_discriminant() {
        // Valid TypeTag prefix, then a bad PacketRef discriminant.
        let mut bytes = TypeTag::Generic { idx: 0 }.encode_canonical().unwrap();
        bytes.push(7); // not PACKET_REF_USE (0) or PACKET_REF_OBJECT (1)
        assert_eq!(
            Packet::decode_canonical(&bytes),
            Err(CodecError::InvalidDiscriminant(7))
        );
    }

    /// Spec §4 / §6: "a `Use`-packet from plan A is rejected in plan B."
    ///
    /// We assert this at the *type / serialization* level: a `Use` packet
    /// carries only `(cmd_idx, ret_idx)` and *no plan identity*. Two
    /// conceptually distinct plans ("A" and "B") that happen to reference
    /// the same `(cmd_idx, ret_idx)` produce byte-identical envelopes —
    /// proving the envelope cannot smuggle cross-plan identity. It is a
    /// pure intra-plan coordinate; resolving it is the executor's job,
    /// against *that* plan's command outputs.
    ///
    /// The runtime rejection ("plan B has no such command, or an
    /// incompatible return type") lives in `bloom-script`'s executor /
    /// `BorrowTable::linearity_check` + `validate_ptb`, not here. This
    /// module deliberately enforces nothing at runtime.
    #[test]
    fn use_packet_carries_no_plan_identity() {
        let ty = concrete("Coin", vec![concrete("USDC", vec![])]);
        // "Built in plan A" and "built in plan B" — same coordinate.
        let from_plan_a = Packet::from_use(ty.clone(), 2, 1);
        let from_plan_b = Packet::from_use(ty, 2, 1);

        // The serialized envelopes are identical: no field distinguishes
        // the plan. Copying plan A's bytes into plan B yields exactly what
        // plan B would have built itself — i.e. a coordinate, not a claim.
        assert_eq!(
            from_plan_a.encode_canonical().unwrap(),
            from_plan_b.encode_canonical().unwrap(),
        );

        // And the reference is purely a coordinate: nothing in it can be
        // mistaken for a bearer token or an object the signer holds.
        match from_plan_a.ref_ {
            PacketRef::Use { cmd_idx, ret_idx } => {
                assert_eq!((cmd_idx, ret_idx), (2, 1));
            }
            PacketRef::Object { .. } => panic!("expected a Use reference"),
        }
    }

    #[test]
    fn debug_projection_is_non_authoritative() {
        let ty = concrete("Coin", vec![concrete("USDC", vec![])]);
        let p = Packet::from_use(ty, 1, 0);

        let projection = p.debug_projection();
        let canonical = p.encode_canonical().unwrap();

        // The human projection is a distinct, readable string — not the
        // canonical bytes.
        assert!(projection.contains("Coin<USDC>"));
        assert!(projection.contains("use @1.0"));
        assert_ne!(projection.as_bytes(), canonical.as_slice());

        // It is NOT a decode source: feeding the projection bytes to the
        // canonical decoder does not reconstruct the packet (it fails or
        // produces something unequal). The canonical bytes are the only
        // source of truth.
        match Packet::decode_canonical(projection.as_bytes()) {
            Ok(decoded) => assert_ne!(decoded, p),
            Err(_) => { /* expected: not valid canonical input */ }
        }
    }

    #[test]
    fn debug_projection_object_variant() {
        let p = Packet::from_object(TypeTag::Generic { idx: 0 }, ObjectId([0xAB; 32]), 5);
        let s = p.debug_projection();
        assert!(s.contains("object"));
        assert!(s.contains("@v5"));
        assert!(s.contains(&"ab".repeat(32)));
    }
}
