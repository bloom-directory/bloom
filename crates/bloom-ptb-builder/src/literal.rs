//! Canonical literal encoding for `Arg::Const`.
//!
//! The cmd-line grammar (§3.4) lowers a bare `key=value` / positional
//! literal to an [`Arg::Const`] whose bytes are the **canonical
//! encoding** of the value under the declared
//! [`ArgDeclStub::Const(TypeTag)`] type. We encode using the same widths
//! `bloom-resource`' canonical [`BloomType`] implementations emit, so
//! the resulting `Const` bytes match the schema-driven value codec.
//!
//! Supported primitive type names: `u8`..`u128`, `i8`..`i128`, `bool`,
//! `Address`/`address`/`ObjectId`/`Hash32`/`UID` (32-byte hex), `bytes`,
//! `String`/`string`.
//! Anything else (petal-defined structs, generics, externals, and
//! parameterized values) must be lowered through a manifest-aware front door.

use bloom_objects::TypeTag;
use bloom_resource::{BloomType, Bytes as BloomBytes};

use crate::error::BuildError;

/// Encode the textual `value` into canonical `Arg::Const` bytes for the
/// declared (already type-arg-substituted) `TypeTag`.
pub fn encode_const_literal(declared: &TypeTag, value: &str) -> Result<Vec<u8>, BuildError> {
    match declared {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } if type_args.is_empty() => encode_primitive(type_name, value),
        _ => Err(BuildError::Parse(format!(
            "declared const type {} requires manifest-aware typed lowering",
            type_tag_label(declared)
        ))),
    }
}

fn encode_primitive(type_name: &str, value: &str) -> Result<Vec<u8>, BuildError> {
    match type_name {
        "u8" => parse_uint(value, 8).map(|v| vec![v as u8]),
        "u16" => parse_uint(value, 16).map(|v| (v as u16).to_be_bytes().to_vec()),
        "u32" => parse_uint(value, 32).map(|v| (v as u32).to_be_bytes().to_vec()),
        "u64" => parse_uint(value, 64).map(|v| (v as u64).canonical_encode()),
        "u128" => parse_u128(value).map(|v| v.to_be_bytes().to_vec()),
        "i8" => parse_int(value, 8).map(|v| (v as i8).to_be_bytes().to_vec()),
        "i16" => parse_int(value, 16).map(|v| (v as i16).to_be_bytes().to_vec()),
        "i32" => parse_int(value, 32).map(|v| (v as i32).to_be_bytes().to_vec()),
        "i64" => parse_int(value, 64).map(|v| (v as i64).to_be_bytes().to_vec()),
        "i128" => parse_i128(value).map(|v| v.to_be_bytes().to_vec()),
        "bool" => match value {
            "true" | "1" => Ok(vec![1u8]),
            "false" | "0" => Ok(vec![0u8]),
            other => Err(BuildError::Parse(format!(
                "expected bool (true/false/0/1), got {other:?}"
            ))),
        },
        "Address" | "address" | "ObjectId" | "Hash32" | "UID" => {
            let bytes = parse_hex_bytes(value)?;
            if bytes.len() != 32 {
                return Err(BuildError::Parse(format!(
                    "{type_name} literal must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        "bytes" => parse_hex_bytes(value).map(|bytes| BloomBytes(bytes).canonical_encode()),
        "String" | "string" => Ok(value.to_string().canonical_encode()),
        _ => Err(BuildError::Parse(format!(
            "declared const type {type_name} requires manifest-aware typed lowering"
        ))),
    }
}

fn type_tag_label(tag: &TypeTag) -> String {
    match tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => {
            let mut out = type_name.clone();
            if *petal_hash != [0u8; 32] && *petal_hash != bloom_objects::BUILTIN_TYPE_HASH {
                out.push('@');
                push_hex(petal_hash, &mut out);
            }
            if !type_args.is_empty() {
                out.push('<');
                out.push_str(
                    &type_args
                        .iter()
                        .map(type_tag_label)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                out.push('>');
            }
            out
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("$external_{ref_idx}"),
    }
}

fn push_hex(bytes: &[u8], out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

/// Parse a possibly-`0x`-prefixed hex string into raw bytes. A bare
/// (non-hex) value with no `0x` prefix is rejected so typos surface.
pub(crate) fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, BuildError> {
    let s = value.strip_prefix("0x").unwrap_or(value);
    if s.is_empty() {
        return Ok(vec![]);
    }
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BuildError::Parse(format!(
            "expected hex literal (optionally 0x-prefixed) with even length, got {value:?}"
        )));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, BuildError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(BuildError::Parse(format!(
            "invalid hex digit {:?}",
            b as char
        ))),
    }
}

fn parse_uint(value: &str, bits: u32) -> Result<u128, BuildError> {
    let v = parse_u128(value)?;
    if bits < 128 && v > (1u128 << bits) - 1 {
        return Err(BuildError::Parse(format!(
            "value {value} does not fit in u{bits}"
        )));
    }
    Ok(v)
}

fn parse_u128(value: &str) -> Result<u128, BuildError> {
    value
        .parse::<u128>()
        .map_err(|e| BuildError::Parse(format!("invalid unsigned integer {value:?}: {e}")))
}

fn parse_int(value: &str, bits: u32) -> Result<i128, BuildError> {
    let v = parse_i128(value)?;
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    if bits < 128 && (v > max || v < min) {
        return Err(BuildError::Parse(format!(
            "value {value} does not fit in i{bits}"
        )));
    }
    Ok(v)
}

fn parse_i128(value: &str) -> Result<i128, BuildError> {
    value
        .parse::<i128>()
        .map_err(|e| BuildError::Parse(format!("invalid signed integer {value:?}: {e}")))
}

/// Parse a 32-byte object/hash id from a possibly-`0x`-prefixed hex
/// string. Used by both `obj:` and `signer/type` literal handling.
pub fn parse_id32(value: &str) -> Result<[u8; 32], BuildError> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != 32 {
        return Err(BuildError::Parse(format!(
            "expected 32-byte id (64 hex chars), got {} bytes from {value:?}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a type-tag literal for `type:<tag>`.
///
/// Grammar (kept deliberately small for v0):
/// - `T<n>` / `$generic<n>` → `TypeTag::Generic { idx: n }`
/// - `$external_<n>` → `TypeTag::External { ref_idx: n }`
/// - `Name` or `Name@<hex-petal-hash>` or `Name<Inner,...>` →
///   `TypeTag::Concrete`. `petal_hash` defaults to `[0u8;32]` (self) if
///   no `@hash` is given; nested type-args parsed recursively.
pub fn parse_type_tag(text: &str) -> Result<TypeTag, BuildError> {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("$external_") {
        let idx = rest
            .parse::<u16>()
            .map_err(|e| BuildError::Parse(format!("bad external ref idx {rest:?}: {e}")))?;
        return Ok(TypeTag::External { ref_idx: idx });
    }
    if let Some(rest) = t.strip_prefix("$generic") {
        let idx = rest
            .parse::<u16>()
            .map_err(|e| BuildError::Parse(format!("bad generic idx {rest:?}: {e}")))?;
        return Ok(TypeTag::Generic { idx });
    }
    if let Some(rest) = t.strip_prefix('T')
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        let idx = rest
            .parse::<u16>()
            .map_err(|e| BuildError::Parse(format!("bad generic idx {rest:?}: {e}")))?;
        return Ok(TypeTag::Generic { idx });
    }

    // Concrete: split off optional `<...>` args and optional `@hash`.
    let (head, args_str) = match t.split_once('<') {
        Some((h, rest)) => {
            let inner = rest.strip_suffix('>').ok_or_else(|| {
                BuildError::Parse(format!("unbalanced `<...>` in type tag {text:?}"))
            })?;
            (h, Some(inner))
        }
        None => (t, None),
    };
    let (name, petal_hash) = match head.split_once('@') {
        Some((n, hash_hex)) => (n, parse_id32(hash_hex)?),
        None => (head, [0u8; 32]),
    };
    if name.is_empty() {
        return Err(BuildError::Parse(format!("empty type name in {text:?}")));
    }
    let type_args = match args_str {
        None => vec![],
        Some("") => vec![],
        Some(inner) => split_top_level(inner, ',')
            .iter()
            .map(|s| parse_type_tag(s))
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(TypeTag::Concrete {
        petal_hash,
        type_name: name.trim().to_string(),
        type_args,
    })
}

/// Replace each `TypeTag::Generic { idx }` with `type_args[idx]`,
/// recursing into concrete type-arg vectors. Mirrors the (private)
/// `bloom_script::validator::substitute_type_args` so lowered `Const`
/// literals are encoded against the same concrete type the validator
/// will later check them against. Total: out-of-range generics are
/// left unchanged.
pub fn substitute_type_args(t: &TypeTag, type_args: &[TypeTag]) -> TypeTag {
    match t {
        TypeTag::Generic { idx } => type_args
            .get(*idx as usize)
            .cloned()
            .unwrap_or_else(|| t.clone()),
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args: inner,
        } => TypeTag::Concrete {
            petal_hash: *petal_hash,
            type_name: type_name.clone(),
            type_args: inner
                .iter()
                .map(|x| substitute_type_args(x, type_args))
                .collect(),
        },
        TypeTag::External { .. } => t.clone(),
    }
}

/// Split `s` on `sep`, but only at the top `<...>` nesting level.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '<' => {
                depth += 1;
                cur.push(c);
            }
            '>' => {
                depth -= 1;
                cur.push(c);
            }
            c if c == sep && depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}
