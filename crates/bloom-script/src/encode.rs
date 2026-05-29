//! Canonical encoder / decoder for the PTB wire types
//! ([`crate::types`]).
//!
//! All primitives use the same widths as `bloom_objects::codec` so the
//! two crates share one canonicalisation contract:
//!
//! - `u8`  / `u16` / `u32` / `u64` / `u128` — big-endian, fixed width.
//! - `bytes` — `u32 BE` length prefix + bytes.
//! - `string` — `u16 BE` length prefix + UTF-8.
//! - `Vec<T>` — `u32 BE` count + N encoded items.
//! - `Option<T>` — 1-byte presence (0 / 1) + encoded T if present.
//! - `enum` — 1-byte discriminant + variant payload.
//!
//! Determinism: a given struct produces identical bytes on every host,
//! every time. The decoder rejects trailing bytes.

use bloom_chain_types::Hash32;
use bloom_objects::{
    AccessMode, ObjectId, Owner, TypeTag,
    codec::{
        self, CodecError, read_bytes32, read_string, read_u8, read_u16_be, read_u32_be,
        read_u64_be, write_bytes, write_bytes32, write_string, write_u8, write_u16_be,
        write_u32_be, write_u64_be,
    },
};

use crate::types::{
    Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, PublishCmd,
    TAG_ARG_CONST, TAG_ARG_OBJECT, TAG_ARG_SIGNER, TAG_ARG_TYPEARG, TAG_ARG_USE, TAG_CMD_MAKE_VEC,
    TAG_CMD_MERGE, TAG_CMD_MOVE, TAG_CMD_PUBLISH, TAG_CMD_SPLIT, TAG_CMD_TRANSFER, TAG_CMD_UPGRADE,
    UpgradeCmd, UseRef,
};

/// Maximum canonical PTB byte length accepted by the decoder.
pub const MAX_PTB_BYTES: usize = 1 << 20;
/// Maximum signer public keys/signatures per PTB.
pub const MAX_PTB_SIGNERS: usize = 16;
/// Maximum commands per PTB.
pub const MAX_PTB_COMMANDS: usize = 256;
/// Maximum args per Move command.
pub const MAX_PTB_ARGS: usize = 256;
/// Maximum `UseRef`s in a single built-in command.
pub const MAX_PTB_USES: usize = 256;
/// Maximum function type args.
pub const MAX_PTB_TYPE_ARGS: usize = 32;
/// Maximum split amounts in a single command.
pub const MAX_PTB_SPLIT_AMOUNTS: usize = 256;
/// Maximum byte-buffer field length inside a PTB.
pub const MAX_PTB_BYTE_BUF: usize = 2 << 20;
/// Maximum publish/upgrade wasm payload length.
pub const MAX_PTB_WASM_BYTES: usize = 2 << 20;

// ---------------------------------------------------------------------------
// Low-level helpers not in bloom-objects::codec
// ---------------------------------------------------------------------------

/// Write a big-endian `u128`.
pub fn write_u128_be(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian `u128`.
pub fn read_u128_be(rdr: &mut &[u8]) -> Result<u128, CodecError> {
    if rdr.len() < 16 {
        return Err(CodecError::UnexpectedEof {
            needed: 16,
            available: rdr.len(),
        });
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&rdr[..16]);
    *rdr = &rdr[16..];
    Ok(u128::from_be_bytes(a))
}

/// Write a 32-byte `Hash32`.
fn write_hash32(buf: &mut Vec<u8>, h: &Hash32) {
    write_bytes32(buf, &h.0);
}

/// Read a 32-byte `Hash32`.
fn read_hash32(rdr: &mut &[u8]) -> Result<Hash32, CodecError> {
    read_bytes32(rdr).map(Hash32)
}

/// Write `Option<Hash32>` as 1-byte presence flag + 32 bytes if present.
fn write_opt_hash32(buf: &mut Vec<u8>, opt: &Option<Hash32>) {
    match opt {
        None => write_u8(buf, 0),
        Some(h) => {
            write_u8(buf, 1);
            write_hash32(buf, h);
        }
    }
}

fn read_opt_hash32(rdr: &mut &[u8]) -> Result<Option<Hash32>, CodecError> {
    match read_u8(rdr)? {
        0 => Ok(None),
        1 => Ok(Some(read_hash32(rdr)?)),
        other => Err(CodecError::InvalidDiscriminant(other)),
    }
}

/// Write a `Vec<T>` count prefix (`u32 BE`).
fn write_vec_count<T>(buf: &mut Vec<u8>, items: &[T]) -> Result<(), CodecError> {
    let count: u32 = items
        .len()
        .try_into()
        .map_err(|_| CodecError::LengthOverflow(items.len() as u64))?;
    write_u32_be(buf, count);
    Ok(())
}

fn read_vec_count(rdr: &mut &[u8]) -> Result<usize, CodecError> {
    Ok(read_u32_be(rdr)? as usize)
}

fn read_vec_count_capped(rdr: &mut &[u8], cap: usize) -> Result<usize, CodecError> {
    let count = read_vec_count(rdr)?;
    if count > cap {
        return Err(CodecError::InvalidLength(count as u64));
    }
    Ok(count)
}

fn read_bytes_capped(rdr: &mut &[u8], cap: usize) -> Result<Vec<u8>, CodecError> {
    let len = read_u32_be(rdr)? as usize;
    if len > cap {
        return Err(CodecError::InvalidLength(len as u64));
    }
    let slice = codec::read_slice(rdr, len)?;
    Ok(slice.to_vec())
}

// ---------------------------------------------------------------------------
// PetalRef
// ---------------------------------------------------------------------------

/// Canonical-encode a [`PetalRef`].
pub fn encode_petal_ref(buf: &mut Vec<u8>, p: &PetalRef) -> Result<(), CodecError> {
    write_string(buf, &p.path)?;
    write_opt_hash32(buf, &p.hash);
    Ok(())
}

/// Canonical-decode a [`PetalRef`].
pub fn decode_petal_ref(rdr: &mut &[u8]) -> Result<PetalRef, CodecError> {
    let path = read_string(rdr)?;
    let hash = read_opt_hash32(rdr)?;
    Ok(PetalRef { path, hash })
}

// ---------------------------------------------------------------------------
// UseRef
// ---------------------------------------------------------------------------

/// Canonical-encode a [`UseRef`] (two `u16` BE).
pub fn encode_use_ref(buf: &mut Vec<u8>, u: &UseRef) {
    write_u16_be(buf, u.cmd_idx);
    write_u16_be(buf, u.ret_idx);
}

/// Canonical-decode a [`UseRef`].
pub fn decode_use_ref(rdr: &mut &[u8]) -> Result<UseRef, CodecError> {
    let cmd_idx = read_u16_be(rdr)?;
    let ret_idx = read_u16_be(rdr)?;
    Ok(UseRef { cmd_idx, ret_idx })
}

// ---------------------------------------------------------------------------
// TypeTag list
// ---------------------------------------------------------------------------

/// Encode `Vec<TypeTag>` with a `u32 BE` count prefix (uses bloom-objects
/// canonical TypeTag encoder for each entry).
pub fn encode_type_tag_vec(buf: &mut Vec<u8>, tags: &[TypeTag]) -> Result<(), CodecError> {
    write_vec_count(buf, tags)?;
    for t in tags {
        t.encode_into(buf)?;
    }
    Ok(())
}

/// Decode `Vec<TypeTag>` with a `u32 BE` count prefix.
pub fn decode_type_tag_vec(rdr: &mut &[u8]) -> Result<Vec<TypeTag>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_TYPE_ARGS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(TypeTag::decode_from(rdr, 0)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Arg
// ---------------------------------------------------------------------------

/// Canonical-encode a single [`Arg`].
pub fn encode_arg(buf: &mut Vec<u8>, arg: &Arg) -> Result<(), CodecError> {
    match arg {
        Arg::Signer(idx) => {
            write_u8(buf, TAG_ARG_SIGNER);
            write_u16_be(buf, *idx);
        }
        Arg::Const(bytes) => {
            write_u8(buf, TAG_ARG_CONST);
            write_bytes(buf, bytes);
        }
        Arg::Object {
            id,
            expected_version,
            access_mode,
        } => {
            write_u8(buf, TAG_ARG_OBJECT);
            write_bytes32(buf, &id.0);
            write_u64_be(buf, expected_version.0);
            write_u8(buf, access_mode.as_byte());
        }
        Arg::Use { cmd_idx, ret_idx } => {
            write_u8(buf, TAG_ARG_USE);
            write_u16_be(buf, *cmd_idx);
            write_u16_be(buf, *ret_idx);
        }
        Arg::TypeArg(t) => {
            write_u8(buf, TAG_ARG_TYPEARG);
            t.encode_into(buf)?;
        }
    }
    Ok(())
}

/// Canonical-decode a single [`Arg`].
pub fn decode_arg(rdr: &mut &[u8]) -> Result<Arg, CodecError> {
    let tag = read_u8(rdr)?;
    match tag {
        TAG_ARG_SIGNER => Ok(Arg::Signer(read_u16_be(rdr)?)),
        TAG_ARG_CONST => Ok(Arg::Const(read_bytes_capped(rdr, MAX_PTB_BYTE_BUF)?)),
        TAG_ARG_OBJECT => {
            let id = ObjectId(read_bytes32(rdr)?);
            let expected_version = ExpectedVersion(read_u64_be(rdr)?);
            let access_mode = AccessMode::from_byte(read_u8(rdr)?)?;
            Ok(Arg::Object {
                id,
                expected_version,
                access_mode,
            })
        }
        TAG_ARG_USE => {
            let cmd_idx = read_u16_be(rdr)?;
            let ret_idx = read_u16_be(rdr)?;
            Ok(Arg::Use { cmd_idx, ret_idx })
        }
        TAG_ARG_TYPEARG => Ok(Arg::TypeArg(TypeTag::decode_from(rdr, 0)?)),
        other => Err(CodecError::InvalidDiscriminant(other)),
    }
}

/// Encode `Vec<Arg>` with a `u32 BE` count prefix.
pub fn encode_arg_vec(buf: &mut Vec<u8>, args: &[Arg]) -> Result<(), CodecError> {
    write_vec_count(buf, args)?;
    for a in args {
        encode_arg(buf, a)?;
    }
    Ok(())
}

/// Decode `Vec<Arg>` with a `u32 BE` count prefix.
pub fn decode_arg_vec(rdr: &mut &[u8]) -> Result<Vec<Arg>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_ARGS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_arg(rdr)?);
    }
    Ok(out)
}

/// Encode `Vec<UseRef>` with a `u32 BE` count prefix.
pub fn encode_use_ref_vec(buf: &mut Vec<u8>, uses: &[UseRef]) -> Result<(), CodecError> {
    write_vec_count(buf, uses)?;
    for u in uses {
        encode_use_ref(buf, u);
    }
    Ok(())
}

/// Decode `Vec<UseRef>` with a `u32 BE` count prefix.
pub fn decode_use_ref_vec(rdr: &mut &[u8]) -> Result<Vec<UseRef>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_USES)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_use_ref(rdr)?);
    }
    Ok(out)
}

/// Encode `Vec<u128>` amount list with a `u32 BE` count prefix.
pub fn encode_u128_vec(buf: &mut Vec<u8>, amounts: &[u128]) -> Result<(), CodecError> {
    write_vec_count(buf, amounts)?;
    for a in amounts {
        write_u128_be(buf, *a);
    }
    Ok(())
}

/// Decode `Vec<u128>` amount list with a `u32 BE` count prefix.
pub fn decode_u128_vec(rdr: &mut &[u8]) -> Result<Vec<u128>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_SPLIT_AMOUNTS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_u128_be(rdr)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Owner (reuse bloom-objects)
// ---------------------------------------------------------------------------

/// Encode an [`Owner`] using bloom-objects' canonical layout.
pub fn encode_owner(buf: &mut Vec<u8>, o: &Owner) {
    o.encode_into(buf);
}

/// Decode an [`Owner`] from a cursor.
pub fn decode_owner(rdr: &mut &[u8]) -> Result<Owner, CodecError> {
    Owner::decode_from(rdr)
}

// ---------------------------------------------------------------------------
// MoveCmd / PublishCmd / UpgradeCmd
// ---------------------------------------------------------------------------

/// Encode a [`MoveCmd`].
pub fn encode_move_cmd(buf: &mut Vec<u8>, m: &MoveCmd) -> Result<(), CodecError> {
    encode_petal_ref(buf, &m.petal)?;
    write_string(buf, &m.function)?;
    encode_type_tag_vec(buf, &m.type_args)?;
    encode_arg_vec(buf, &m.args)?;
    Ok(())
}

/// Decode a [`MoveCmd`].
pub fn decode_move_cmd(rdr: &mut &[u8]) -> Result<MoveCmd, CodecError> {
    let petal = decode_petal_ref(rdr)?;
    let function = read_string(rdr)?;
    let type_args = decode_type_tag_vec(rdr)?;
    let args = decode_arg_vec(rdr)?;
    Ok(MoveCmd {
        petal,
        function,
        type_args,
        args,
    })
}

/// Encode a [`PublishCmd`].
pub fn encode_publish_cmd(buf: &mut Vec<u8>, p: &PublishCmd) -> Result<(), CodecError> {
    write_bytes(buf, &p.wasm_bytes);
    write_string(buf, &p.module_path)?;
    match &p.publisher_cap {
        None => write_u8(buf, 0),
        Some(u) => {
            write_u8(buf, 1);
            encode_use_ref(buf, u);
        }
    }
    Ok(())
}

/// Decode a [`PublishCmd`].
pub fn decode_publish_cmd(rdr: &mut &[u8]) -> Result<PublishCmd, CodecError> {
    let wasm_bytes = read_bytes_capped(rdr, MAX_PTB_WASM_BYTES)?;
    let module_path = read_string(rdr)?;
    let publisher_cap = match read_u8(rdr)? {
        0 => None,
        1 => Some(decode_use_ref(rdr)?),
        other => return Err(CodecError::InvalidDiscriminant(other)),
    };
    Ok(PublishCmd {
        wasm_bytes,
        module_path,
        publisher_cap,
    })
}

/// Encode an [`UpgradeCmd`].
pub fn encode_upgrade_cmd(buf: &mut Vec<u8>, u: &UpgradeCmd) -> Result<(), CodecError> {
    write_bytes(buf, &u.wasm_bytes);
    write_string(buf, &u.module_path)?;
    encode_use_ref(buf, &u.publisher_cap);
    Ok(())
}

/// Decode an [`UpgradeCmd`].
pub fn decode_upgrade_cmd(rdr: &mut &[u8]) -> Result<UpgradeCmd, CodecError> {
    let wasm_bytes = read_bytes_capped(rdr, MAX_PTB_WASM_BYTES)?;
    let module_path = read_string(rdr)?;
    let publisher_cap = decode_use_ref(rdr)?;
    Ok(UpgradeCmd {
        wasm_bytes,
        module_path,
        publisher_cap,
    })
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Canonical-encode a [`Command`].
pub fn encode_command(buf: &mut Vec<u8>, c: &Command) -> Result<(), CodecError> {
    match c {
        Command::Move(m) => {
            write_u8(buf, TAG_CMD_MOVE);
            encode_move_cmd(buf, m)?;
        }
        Command::Publish(p) => {
            write_u8(buf, TAG_CMD_PUBLISH);
            encode_publish_cmd(buf, p)?;
        }
        Command::TransferObjects { uses, owner } => {
            write_u8(buf, TAG_CMD_TRANSFER);
            encode_use_ref_vec(buf, uses)?;
            encode_owner(buf, owner);
        }
        Command::MergeCoins(uses) => {
            write_u8(buf, TAG_CMD_MERGE);
            encode_use_ref_vec(buf, uses)?;
        }
        Command::SplitCoins { src, amounts } => {
            write_u8(buf, TAG_CMD_SPLIT);
            encode_use_ref(buf, src);
            encode_u128_vec(buf, amounts)?;
        }
        Command::MakeMoveVec { ty, uses } => {
            write_u8(buf, TAG_CMD_MAKE_VEC);
            ty.encode_into(buf)?;
            encode_use_ref_vec(buf, uses)?;
        }
        Command::UpgradePetal(u) => {
            write_u8(buf, TAG_CMD_UPGRADE);
            encode_upgrade_cmd(buf, u)?;
        }
    }
    Ok(())
}

/// Canonical-decode a [`Command`].
pub fn decode_command(rdr: &mut &[u8]) -> Result<Command, CodecError> {
    let tag = read_u8(rdr)?;
    match tag {
        TAG_CMD_MOVE => Ok(Command::Move(decode_move_cmd(rdr)?)),
        TAG_CMD_PUBLISH => Ok(Command::Publish(decode_publish_cmd(rdr)?)),
        TAG_CMD_TRANSFER => {
            let uses = decode_use_ref_vec(rdr)?;
            let owner = decode_owner(rdr)?;
            Ok(Command::TransferObjects { uses, owner })
        }
        TAG_CMD_MERGE => Ok(Command::MergeCoins(decode_use_ref_vec(rdr)?)),
        TAG_CMD_SPLIT => {
            let src = decode_use_ref(rdr)?;
            let amounts = decode_u128_vec(rdr)?;
            Ok(Command::SplitCoins { src, amounts })
        }
        TAG_CMD_MAKE_VEC => {
            let ty = TypeTag::decode_from(rdr, 0)?;
            let uses = decode_use_ref_vec(rdr)?;
            Ok(Command::MakeMoveVec { ty, uses })
        }
        TAG_CMD_UPGRADE => Ok(Command::UpgradePetal(decode_upgrade_cmd(rdr)?)),
        other => Err(CodecError::InvalidDiscriminant(other)),
    }
}

/// Encode `Vec<Command>` with a `u32 BE` count prefix.
pub fn encode_command_vec(buf: &mut Vec<u8>, cmds: &[Command]) -> Result<(), CodecError> {
    write_vec_count(buf, cmds)?;
    for c in cmds {
        encode_command(buf, c)?;
    }
    Ok(())
}

/// Decode `Vec<Command>` with a `u32 BE` count prefix.
pub fn decode_command_vec(rdr: &mut &[u8]) -> Result<Vec<Command>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_COMMANDS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_command(rdr)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Signers / signatures
// ---------------------------------------------------------------------------

/// Encode `Vec<PqPubkey>` with a `u32 BE` count prefix (32 bytes each).
pub fn encode_signers(buf: &mut Vec<u8>, signers: &[[u8; 32]]) -> Result<(), CodecError> {
    write_vec_count(buf, signers)?;
    for s in signers {
        write_bytes32(buf, s);
    }
    Ok(())
}

/// Decode `Vec<PqPubkey>` with a `u32 BE` count prefix.
pub fn decode_signers(rdr: &mut &[u8]) -> Result<Vec<[u8; 32]>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_SIGNERS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_bytes32(rdr)?);
    }
    Ok(out)
}

/// Encode a `Vec<PqSignature>` (each signature is a length-prefixed
/// byte blob, count prefix is `u32 BE`).
pub fn encode_signatures(buf: &mut Vec<u8>, sigs: &[PqSignature]) -> Result<(), CodecError> {
    write_vec_count(buf, sigs)?;
    for s in sigs {
        write_bytes(buf, &s.0);
    }
    Ok(())
}

/// Decode a `Vec<PqSignature>` with a `u32 BE` count prefix.
pub fn decode_signatures(rdr: &mut &[u8]) -> Result<Vec<PqSignature>, CodecError> {
    let count = read_vec_count_capped(rdr, MAX_PTB_SIGNERS)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(PqSignature(read_bytes_capped(rdr, MAX_PTB_BYTE_BUF)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// PtbTx
// ---------------------------------------------------------------------------

/// Canonical-encode every field of a [`PtbTx`] *except* `signatures`.
/// Used by [`crate::hash::ptb_hash`] (the value signers sign).
pub fn encode_ptb_without_sigs(buf: &mut Vec<u8>, tx: &PtbTx) -> Result<(), CodecError> {
    encode_signers(buf, &tx.signers)?;
    encode_command_vec(buf, &tx.commands)?;
    write_bytes32(buf, &tx.gas_payer.0);
    write_u64_be(buf, tx.gas_budget);
    write_u128_be(buf, tx.gas_price);
    write_u64_be(buf, tx.expiry_block);
    Ok(())
}

/// Canonical-encode a full [`PtbTx`] (signatures included).
pub fn encode_ptb(tx: &PtbTx) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    encode_ptb_without_sigs(&mut buf, tx)?;
    encode_signatures(&mut buf, &tx.signatures)?;
    Ok(buf)
}

/// Canonical-decode a [`PtbTx`], rejecting trailing bytes.
pub fn decode_ptb(bytes: &[u8]) -> Result<PtbTx, CodecError> {
    if bytes.len() > MAX_PTB_BYTES {
        return Err(CodecError::InvalidLength(bytes.len() as u64));
    }
    let mut rdr = bytes;
    let signers = decode_signers(&mut rdr)?;
    let commands = decode_command_vec(&mut rdr)?;
    let gas_payer = ObjectId(read_bytes32(&mut rdr)?);
    let gas_budget = read_u64_be(&mut rdr)?;
    let gas_price = read_u128_be(&mut rdr)?;
    let expiry_block = read_u64_be(&mut rdr)?;
    let signatures = decode_signatures(&mut rdr)?;
    codec::expect_eof(rdr)?;
    Ok(PtbTx {
        signers,
        commands,
        gas_payer,
        gas_budget,
        gas_price,
        expiry_block,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::TypeTag;

    /// Lowercase hex-encode (no external `hex` dep).
    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    // --- low-level helpers ---

    #[test]
    fn u128_be_roundtrip() {
        let mut buf = Vec::new();
        write_u128_be(&mut buf, 0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708u128);
        let mut rdr = buf.as_slice();
        assert_eq!(
            read_u128_be(&mut rdr).unwrap(),
            0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708u128
        );
    }

    #[test]
    fn u128_be_eof() {
        let buf = [0u8; 4];
        let mut rdr = buf.as_slice();
        assert!(matches!(
            read_u128_be(&mut rdr),
            Err(CodecError::UnexpectedEof { needed: 16, .. })
        ));
    }

    #[test]
    fn opt_hash32_none_roundtrip() {
        let mut buf = Vec::new();
        write_opt_hash32(&mut buf, &None);
        let mut rdr = buf.as_slice();
        assert_eq!(read_opt_hash32(&mut rdr).unwrap(), None);
    }

    #[test]
    fn opt_hash32_some_roundtrip() {
        let h = Hash32([0xCC; 32]);
        let mut buf = Vec::new();
        write_opt_hash32(&mut buf, &Some(h));
        let mut rdr = buf.as_slice();
        assert_eq!(read_opt_hash32(&mut rdr).unwrap(), Some(h));
    }

    #[test]
    fn opt_hash32_bad_discriminant() {
        let buf = [9u8];
        let mut rdr = buf.as_slice();
        assert!(matches!(
            read_opt_hash32(&mut rdr),
            Err(CodecError::InvalidDiscriminant(9))
        ));
    }

    // --- PetalRef ---

    #[test]
    fn petal_ref_roundtrip_pinned() {
        let p = PetalRef {
            path: "/bloom/petals/dex/pool".to_string(),
            hash: Some(Hash32([0xEF; 32])),
        };
        let mut buf = Vec::new();
        encode_petal_ref(&mut buf, &p).unwrap();
        let mut rdr = buf.as_slice();
        assert_eq!(decode_petal_ref(&mut rdr).unwrap(), p);
    }

    #[test]
    fn petal_ref_roundtrip_unpinned() {
        let p = PetalRef {
            path: "/bloom/petals/core/fungible".to_string(),
            hash: None,
        };
        let mut buf = Vec::new();
        encode_petal_ref(&mut buf, &p).unwrap();
        let mut rdr = buf.as_slice();
        assert_eq!(decode_petal_ref(&mut rdr).unwrap(), p);
    }

    // --- UseRef ---

    #[test]
    fn use_ref_roundtrip() {
        let u = UseRef {
            cmd_idx: 7,
            ret_idx: 3,
        };
        let mut buf = Vec::new();
        encode_use_ref(&mut buf, &u);
        assert_eq!(buf.len(), 4);
        let mut rdr = buf.as_slice();
        assert_eq!(decode_use_ref(&mut rdr).unwrap(), u);
    }

    // --- Arg ---

    fn arg_rt(arg: &Arg) {
        let mut buf = Vec::new();
        encode_arg(&mut buf, arg).unwrap();
        let mut rdr = buf.as_slice();
        let back = decode_arg(&mut rdr).unwrap();
        assert_eq!(*arg, back, "arg round-trip");
        assert!(rdr.is_empty(), "arg decode should consume entire payload");
    }

    #[test]
    fn arg_signer_rt() {
        arg_rt(&Arg::Signer(0));
        arg_rt(&Arg::Signer(0xBEEF));
    }

    #[test]
    fn arg_const_rt() {
        arg_rt(&Arg::Const(vec![]));
        arg_rt(&Arg::Const(vec![1, 2, 3, 4, 5]));
        arg_rt(&Arg::Const(vec![0xFFu8; 1024]));
    }

    #[test]
    fn arg_object_rt() {
        arg_rt(&Arg::Object {
            id: ObjectId([0x42; 32]),
            expected_version: ExpectedVersion(99),
            access_mode: AccessMode::Mutable,
        });
        arg_rt(&Arg::Object {
            id: ObjectId([0; 32]),
            expected_version: ExpectedVersion(0),
            access_mode: AccessMode::ReadOnly,
        });
        arg_rt(&Arg::Object {
            id: ObjectId([0xFF; 32]),
            expected_version: ExpectedVersion(u64::MAX),
            access_mode: AccessMode::Consume,
        });
    }

    #[test]
    fn arg_use_rt() {
        arg_rt(&Arg::Use {
            cmd_idx: 2,
            ret_idx: 0,
        });
    }

    #[test]
    fn arg_typearg_rt() {
        arg_rt(&Arg::TypeArg(concrete("USDC")));
    }

    #[test]
    fn arg_bad_discriminant() {
        let buf = [99u8];
        let mut rdr = buf.as_slice();
        assert!(matches!(
            decode_arg(&mut rdr),
            Err(CodecError::InvalidDiscriminant(99))
        ));
    }

    // --- Commands ---

    fn cmd_rt(c: &Command) {
        let mut buf = Vec::new();
        encode_command(&mut buf, c).unwrap();
        let mut rdr = buf.as_slice();
        let back = decode_command(&mut rdr).unwrap();
        assert_eq!(*c, back, "command round-trip");
        assert!(rdr.is_empty());
    }

    #[test]
    fn cmd_move_rt() {
        cmd_rt(&Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/petals/dex/pool".to_string(),
                hash: Some(Hash32([0x01; 32])),
            },
            function: "swap_a_for_b".to_string(),
            type_args: vec![concrete("USDC"), concrete("LOOM")],
            args: vec![
                Arg::Signer(0),
                Arg::Object {
                    id: ObjectId([0x11; 32]),
                    expected_version: ExpectedVersion(5),
                    access_mode: AccessMode::Mutable,
                },
                Arg::Use {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                Arg::Const(vec![1, 2, 3]),
            ],
        }));
    }

    #[test]
    fn cmd_publish_rt() {
        cmd_rt(&Command::Publish(PublishCmd {
            wasm_bytes: vec![0x00, 0x61, 0x73, 0x6d],
            module_path: "/bloom/petals/dex/strategy/cpmm".to_string(),
            publisher_cap: None,
        }));
        cmd_rt(&Command::Publish(PublishCmd {
            wasm_bytes: vec![0xAA; 64],
            module_path: "/bloom/x".to_string(),
            publisher_cap: Some(UseRef {
                cmd_idx: 1,
                ret_idx: 2,
            }),
        }));
    }

    #[test]
    fn cmd_transfer_rt() {
        cmd_rt(&Command::TransferObjects {
            uses: vec![
                UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                },
            ],
            owner: Owner::Address([0xAB; 32]),
        });
        cmd_rt(&Command::TransferObjects {
            uses: vec![],
            owner: Owner::Shared,
        });
    }

    #[test]
    fn cmd_merge_rt() {
        cmd_rt(&Command::MergeCoins(vec![
            UseRef {
                cmd_idx: 1,
                ret_idx: 0,
            },
            UseRef {
                cmd_idx: 2,
                ret_idx: 0,
            },
        ]));
    }

    #[test]
    fn cmd_split_rt() {
        cmd_rt(&Command::SplitCoins {
            src: UseRef {
                cmd_idx: 0,
                ret_idx: 0,
            },
            amounts: vec![100, 200, 300],
        });
    }

    #[test]
    fn cmd_makemovevec_rt() {
        cmd_rt(&Command::MakeMoveVec {
            ty: concrete("Coin"),
            uses: vec![UseRef {
                cmd_idx: 0,
                ret_idx: 0,
            }],
        });
    }

    #[test]
    fn cmd_upgrade_rt() {
        cmd_rt(&Command::UpgradePetal(UpgradeCmd {
            wasm_bytes: vec![1, 2, 3, 4],
            module_path: "/bloom/petals/dex/strategy/cpmm".to_string(),
            publisher_cap: UseRef {
                cmd_idx: 0,
                ret_idx: 0,
            },
        }));
    }

    #[test]
    fn cmd_bad_discriminant() {
        let buf = [99u8];
        let mut rdr = buf.as_slice();
        assert!(matches!(
            decode_command(&mut rdr),
            Err(CodecError::InvalidDiscriminant(99))
        ));
    }

    // --- PtbTx ---

    fn sample_ptb() -> PtbTx {
        PtbTx {
            signers: vec![[0xAA; 32], [0xBB; 32]],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0x01; 32])),
                    },
                    function: "swap".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Signer(0)],
                }),
                Command::TransferObjects {
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                    owner: Owner::Address([0x99; 32]),
                },
            ],
            gas_payer: ObjectId([0x77; 32]),
            gas_budget: 1_000_000,
            gas_price: 7,
            expiry_block: 12345,
            signatures: vec![PqSignature(vec![1, 2, 3]), PqSignature(vec![4, 5, 6])],
        }
    }

    #[test]
    fn ptb_full_roundtrip() {
        let tx = sample_ptb();
        let bytes = encode_ptb(&tx).unwrap();
        let back = decode_ptb(&bytes).unwrap();
        assert_eq!(tx, back);
    }

    #[test]
    fn ptb_empty_signatures_for_signing_digest() {
        let tx = sample_ptb();
        let mut buf = Vec::new();
        encode_ptb_without_sigs(&mut buf, &tx).unwrap();
        // The "without_sigs" encoding must be a strict prefix of the
        // full encoding plus zero-count sig vector encoding.
        let mut tx_no_sigs = tx.clone();
        tx_no_sigs.signatures.clear();
        let full = encode_ptb(&tx_no_sigs).unwrap();
        // full = without_sigs || u32_be(0)
        assert_eq!(&full[..buf.len()], &buf[..]);
        assert_eq!(&full[buf.len()..], &[0u8; 4]);
    }

    #[test]
    fn ptb_rejects_trailing_bytes() {
        let tx = sample_ptb();
        let mut bytes = encode_ptb(&tx).unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            decode_ptb(&bytes),
            Err(CodecError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn decode_rejects_huge_command_count_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // signers
        bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // commands
        let err = decode_ptb(&bytes).unwrap_err();
        assert_eq!(err, CodecError::InvalidLength(u32::MAX as u64));
    }

    #[test]
    fn decode_rejects_oversized_ptb_bytes() {
        let bytes = vec![0u8; MAX_PTB_BYTES + 1];
        let err = decode_ptb(&bytes).unwrap_err();
        assert_eq!(err, CodecError::InvalidLength((MAX_PTB_BYTES + 1) as u64));
    }

    // --- determinism / hex snapshot ---

    #[test]
    fn use_ref_hex_snapshot() {
        let mut buf = Vec::new();
        encode_use_ref(
            &mut buf,
            &UseRef {
                cmd_idx: 0x1234,
                ret_idx: 0x5678,
            },
        );
        assert_eq!(hex_encode(&buf), "12345678");
    }

    #[test]
    fn arg_signer_hex_snapshot() {
        let mut buf = Vec::new();
        encode_arg(&mut buf, &Arg::Signer(0x00FF)).unwrap();
        // tag(0) || u16(0x00FF)
        assert_eq!(hex_encode(&buf), "0000ff");
    }

    #[test]
    fn petal_ref_unpinned_hex_snapshot() {
        let mut buf = Vec::new();
        encode_petal_ref(
            &mut buf,
            &PetalRef {
                path: "/a".to_string(),
                hash: None,
            },
        )
        .unwrap();
        // u16(2) || "/a" || u8(0)
        assert_eq!(hex_encode(&buf), "00022f6100");
    }

    #[test]
    fn encoding_is_deterministic() {
        let tx = sample_ptb();
        let a = encode_ptb(&tx).unwrap();
        let b = encode_ptb(&tx).unwrap();
        assert_eq!(a, b);
    }
}
