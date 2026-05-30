//! Command-line grammar (§3.4) and arg lowering.
//!
//! One line per command:
//!
//! ```text
//! <endpoint-path> [arg …] [as <label>]
//! ```
//!
//! Each arg token self-identifies and lowers to a `bloom_script::Arg`:
//!
//! | token form              | lowers to                                  |
//! |-------------------------|--------------------------------------------|
//! | `signer:<i>`            | `Arg::Signer(i)`                           |
//! | `obj:<id>[@<ver>]`      | `Arg::Object{ id, version, access_mode }`  |
//! | `@<cmd>.<ret>` / `@lbl` | `Arg::Use{ cmd_idx, ret_idx }`             |
//! | `type:<type-tag>`       | generic call type arg or `Arg::TypeArg`     |
//! | `key=value` / literal   | `Arg::Const(canonical bytes)`              |
//!
//! Lowering is **positional against the resolved function signature**:
//! the i-th token lowers against the i-th declared `ArgDeclStub` (so a
//! bare literal learns its canonical type, and an `obj:` learns its
//! declared access mode). `type:` tokens are an exception: for current
//! manifests they populate the call's `type_args` vector without consuming a
//! positional arg; legacy manifests that still declare `TypeArg` positional
//! slots continue to accept them there.

use bloom_objects::{AccessMode, ObjectId, TypeTag};
use bloom_script::{Arg, ArgDeclStub, ExpectedVersion, FunctionDeclStub};

use crate::error::BuildError;
use crate::literal::{encode_const_literal, parse_id32, parse_type_tag};

/// A parsed command line before resolution / lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedLine {
    /// The endpoint path (first token).
    pub path: String,
    /// Raw argument tokens (everything between the path and `as`).
    pub arg_tokens: Vec<String>,
    /// Optional `as <label>` binding for this command's primary output.
    pub label: Option<String>,
}

/// How a `@`-reference token resolves: either an explicit
/// `@<cmd>.<ret>` pair or a named `@<label>` to be resolved against the
/// session's label table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UseToken {
    /// Explicit `@<cmd>.<ret>`.
    Explicit {
        /// Producing command index.
        cmd_idx: u16,
        /// Return slot index.
        ret_idx: u16,
    },
    /// Named label `@<label>` → primary output (`ret 0`) of the labelled
    /// command.
    Label(String),
}

/// One lowered argument token. `Use` is kept symbolic until the session
/// resolves labels (the grammar layer has no label table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoweredArg {
    /// A concrete `Arg` (Signer / Const / Object / TypeArg).
    Concrete(Arg),
    /// A type argument for the generic Move call, not a value argument.
    CallTypeArg(TypeTag),
    /// A use-reference still to be resolved against the label table.
    Use(UseToken),
}

/// Split a raw command line into tokens, separating the trailing
/// `as <label>` clause.
pub fn parse_line(line: &str) -> Result<ParsedLine, BuildError> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(BuildError::Parse("empty command line".to_string()));
    }
    let path = tokens[0].to_string();

    // Detect a trailing `as <label>`.
    let mut label = None;
    let mut end = tokens.len();
    if tokens.len() >= 3 && tokens[tokens.len() - 2] == "as" {
        label = Some(tokens[tokens.len() - 1].to_string());
        end = tokens.len() - 2;
    } else if tokens.len() >= 2 && tokens[tokens.len() - 1] == "as" {
        return Err(BuildError::Parse("`as` with no label name".to_string()));
    }

    let arg_tokens = tokens[1..end].iter().map(|s| s.to_string()).collect();
    Ok(ParsedLine {
        path,
        arg_tokens,
        label,
    })
}

/// Lower the parsed arg tokens against the resolved function signature.
///
/// `type_args` is the running list of `TypeTag`s collected from
/// `type:` tokens so far (used to substitute generic `Const` slots so
/// the literal is encoded against the concrete type the caller chose).
///
/// Returns the lowered args in order. `Use` tokens stay symbolic
/// ([`LoweredArg::Use`]); the caller resolves labels and bounds-checks
/// the resulting `cmd_idx`.
pub fn lower_args(
    arg_tokens: &[String],
    signature: &FunctionDeclStub,
) -> Result<Vec<LoweredArg>, BuildError> {
    let mut out = Vec::with_capacity(arg_tokens.len());
    // Collect type args as we encounter `type:` tokens, so that a later
    // generic `Const` slot can be encoded against the concrete type.
    let mut type_args: Vec<TypeTag> = Vec::new();
    // Walk the declared arg positions in step with the tokens.
    let mut value_pos = 0usize;
    for tok in arg_tokens {
        let decl = signature.args.get(value_pos);
        if let Some(rest) = tok.strip_prefix("type:") {
            let tt = parse_type_tag(rest)?;
            type_args.push(tt.clone());
            if matches!(decl, Some(ArgDeclStub::TypeArg(_))) {
                out.push(LoweredArg::Concrete(Arg::TypeArg(tt)));
                value_pos += 1;
            } else if type_args.len() <= signature.type_params.len() {
                out.push(LoweredArg::CallTypeArg(tt));
            } else if let Some(other) = decl {
                return Err(BuildError::Parse(format!(
                    "`type:` token at position {value_pos} but signature expects {}",
                    decl_label(other)
                )));
            } else {
                return Err(BuildError::Parse(format!(
                    "too many arguments: `type:` token has no declared slot (function takes {})",
                    signature.args.len()
                )));
            }
            continue;
        }

        let lowered = lower_one(tok, decl, value_pos, &type_args)?;
        out.push(lowered);
        value_pos += 1;
    }

    if value_pos != signature.args.len() {
        return Err(BuildError::Parse(format!(
            "arg count mismatch: function declares {} arg(s), got {}",
            signature.args.len(),
            value_pos
        )));
    }
    Ok(out)
}

fn lower_one(
    tok: &str,
    decl: Option<&ArgDeclStub>,
    pos: usize,
    subst: &[TypeTag],
) -> Result<LoweredArg, BuildError> {
    // `@` use-reference, optionally written as `key=@ref` (the named-input
    // form the pipe lowering emits).
    if let Some(rest) = tok.strip_prefix('@') {
        return Ok(LoweredArg::Use(parse_use_token(rest)?));
    }
    if let Some((_key, value)) = tok.split_once('=')
        && let Some(rest) = value.strip_prefix('@')
    {
        return Ok(LoweredArg::Use(parse_use_token(rest)?));
    }
    // `signer:<i>`.
    if let Some(rest) = tok.strip_prefix("signer:") {
        let idx = rest
            .parse::<u16>()
            .map_err(|e| BuildError::Parse(format!("bad signer index {rest:?}: {e}")))?;
        return Ok(LoweredArg::Concrete(Arg::Signer(idx)));
    }
    // `const:<hex>`: raw canonical bytes. This is primarily for front doors
    // that already accepted ABI JSON and must preserve exact const bytes.
    if let Some(rest) = tok.strip_prefix("const:") {
        let bytes = crate::literal::parse_hex_bytes(rest)?;
        return Ok(LoweredArg::Concrete(Arg::Const(bytes)));
    }
    // `obj:<id>[@<ver>]`.
    if let Some(rest) = tok.strip_prefix("obj:") {
        let (id_str, ver) = match rest.split_once('@') {
            Some((id, v)) => (
                id,
                v.parse::<u64>()
                    .map_err(|e| BuildError::Parse(format!("bad object version {v:?}: {e}")))?,
            ),
            None => (rest, 0u64),
        };
        let id = ObjectId(parse_id32(id_str)?);
        // Access mode comes from the declared Object arg; default to
        // Mutable if the slot is not an Object decl (the validator will
        // then reject the kind mismatch with a clear message).
        let access_mode = match decl {
            Some(ArgDeclStub::Object { mode, .. }) => *mode,
            _ => AccessMode::Mutable,
        };
        return Ok(LoweredArg::Concrete(Arg::Object {
            id,
            expected_version: ExpectedVersion(ver),
            access_mode,
        }));
    }

    // Otherwise: a `key=value` or positional literal → Const, encoded
    // per the declared type.
    let value = match tok.split_once('=') {
        Some((_key, v)) => v,
        None => tok,
    };
    let declared_ty = match decl {
        Some(ArgDeclStub::Const(ty)) => ty.clone(),
        Some(other) => {
            return Err(BuildError::Parse(format!(
                "literal {tok:?} at position {pos} but signature expects {}",
                decl_label(other)
            )));
        }
        None => {
            return Err(BuildError::Parse(format!(
                "too many arguments: literal {tok:?} has no declared slot"
            )));
        }
    };
    // Apply the caller's type-arg substitution so a generic `Const T`
    // slot is encoded against the concrete `T` (mirrors the validator's
    // `substitute_type_args`).
    let concrete_ty = crate::literal::substitute_type_args(&declared_ty, subst);
    let bytes = encode_const_literal(&concrete_ty, value)?;
    Ok(LoweredArg::Concrete(Arg::Const(bytes)))
}

/// Parse the body of a `@...` token into a [`UseToken`].
pub fn parse_use_token(rest: &str) -> Result<UseToken, BuildError> {
    if rest.is_empty() {
        return Err(BuildError::Parse("empty `@` reference".to_string()));
    }
    match rest.split_once('.') {
        Some((cmd, ret)) => {
            let cmd_idx = cmd
                .parse::<u16>()
                .map_err(|e| BuildError::Parse(format!("bad use cmd index {cmd:?}: {e}")))?;
            let ret_idx = ret
                .parse::<u16>()
                .map_err(|e| BuildError::Parse(format!("bad use ret index {ret:?}: {e}")))?;
            Ok(UseToken::Explicit { cmd_idx, ret_idx })
        }
        None => {
            // `@<n>` (no `.ret`) is shorthand for `@<n>.0` if `n` parses
            // as an index; otherwise it is a label.
            if let Ok(cmd_idx) = rest.parse::<u16>() {
                Ok(UseToken::Explicit {
                    cmd_idx,
                    ret_idx: 0,
                })
            } else {
                Ok(UseToken::Label(rest.to_string()))
            }
        }
    }
}

fn decl_label(d: &ArgDeclStub) -> &'static str {
    match d {
        ArgDeclStub::Signer => "Signer",
        ArgDeclStub::Const(_) => "Const literal",
        ArgDeclStub::Object { .. } => "Object",
        ArgDeclStub::TypeArg(_) => "TypeArg",
    }
}
