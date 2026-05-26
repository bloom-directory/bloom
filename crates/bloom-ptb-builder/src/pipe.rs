//! Pipe-expression lowering (§3.5).
//!
//! Lowers a `bloom pipe '<expr>'` expression into an ordered list of
//! command lines (the same lines the §3.4 grammar / tx-session `cmd`
//! file accept), with `@<cmd>.<ret>` use-edges materialised. Feeding
//! the resulting lines into a [`crate::PtbSession`] in order produces the
//! validated `PtbTx`.
//!
//! Two composition forms:
//!
//! - **Linear** `A | B | C`: a stage's primary output auto-binds to the
//!   next stage's primary input as `@<prev>.0`.
//! - **Named / DAG** `endpoint --a <(<sub-expr>)> --b <(<sub-expr>)>`:
//!   each `--name <(...)>` sub-expression is lowered to its own
//!   command(s) first, and the `--name` slot binds to that sub-pipe's
//!   **final** output ref. This is the add-liquidity case (litmus 5.3).
//!
//! Lowering is purely syntactic: it does not resolve endpoints or
//! typecheck. The `PtbSession` does that as each emitted line is
//! appended.

use crate::error::BuildError;

/// Lower a pipe expression into ordered command lines. Each line is
/// ready to feed to [`crate::PtbSession::append_command`] in order.
///
/// The returned lines reference upstream outputs with explicit
/// `@<cmd_idx>.0` use-edges, so the indices are stable regardless of how
/// the caller drives the session.
pub fn lower_pipe_expr(expr: &str) -> Result<Vec<String>, BuildError> {
    let mut out: Vec<String> = Vec::new();
    lower_into(expr, &mut out)?;
    Ok(out)
}

/// Lower `expr` into `out`, returning the command index of the
/// expression's **final** (primary output) command.
fn lower_into(expr: &str, out: &mut Vec<String>) -> Result<u16, BuildError> {
    let stages = split_pipe_stages(expr)?;
    if stages.is_empty() {
        return Err(BuildError::Parse("empty pipe expression".to_string()));
    }

    let mut prev_output: Option<u16> = None;
    for stage in stages {
        let stage = stage.trim();
        if stage.is_empty() {
            return Err(BuildError::Parse(
                "empty stage in pipe expression".to_string(),
            ));
        }
        // Split the stage into its head tokens and any `--name <(...)>`
        // named sub-expressions.
        let (head, named) = split_named_inputs(stage)?;

        // Lower each named sub-expression first; record its final output
        // command index so we can bind the `--name` slot to it.
        let mut named_refs: Vec<(String, u16)> = Vec::new();
        for (name, sub_expr) in &named {
            let sub_final = lower_into(sub_expr, out)?;
            named_refs.push((name.clone(), sub_final));
        }
        named_refs.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Build this stage's command line.
        let mut line = head.trim().to_string();

        // A linear upstream output auto-binds as the next primary input.
        // It is appended as the first positional arg (so it lands in the
        // function's leading object/value slot).
        if let Some(prev) = prev_output {
            line = splice_primary_input(&line, prev);
        }

        // Named inputs lower to `<name>=@<idx>.0` key=value-style
        // use-edges (the endpoint declares the matching arg name; the
        // grammar treats `key=value` positionally, and the `@` makes it a
        // Use). They are appended after the head tokens, in order.
        for (name, idx) in &named_refs {
            line.push(' ');
            line.push_str(&format!("{name}=@{idx}.0"));
        }

        out.push(line);
        let this_idx = (out.len() - 1) as u16;
        prev_output = Some(this_idx);
    }

    Ok(prev_output.expect("at least one stage lowered"))
}

/// Insert the linear upstream output as the primary (first) positional
/// argument of `line`. We splice it directly after the endpoint path so
/// it occupies the leading arg slot.
fn splice_primary_input(line: &str, prev: u16) -> String {
    let mut tokens = line.split_whitespace();
    let path = tokens.next().unwrap_or("");
    let rest: Vec<&str> = tokens.collect();
    let mut result = String::from(path);
    result.push(' ');
    result.push_str(&format!("@{prev}.0"));
    for t in rest {
        result.push(' ');
        result.push_str(t);
    }
    result.trim().to_string()
}

/// Split a pipe expression into stages on top-level `|` (not inside
/// `<(...)>` sub-expressions).
fn split_pipe_stages(expr: &str) -> Result<Vec<String>, BuildError> {
    let mut stages = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' if chars.peek() == Some(&'(') => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                // `)` closes a `<(...)>`; the `>` follows.
                if depth > 0 {
                    depth -= 1;
                }
                cur.push(c);
            }
            '|' if depth == 0 => {
                stages.push(cur.clone());
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    stages.push(cur);
    if depth != 0 {
        return Err(BuildError::Parse(
            "unbalanced `<( … )>` in pipe expression".to_string(),
        ));
    }
    Ok(stages)
}

/// Split a single stage into its head (endpoint path + plain args, in
/// source order) and the list of `--name <(<sub-expr>)>` named
/// sub-expression inputs.
///
/// Plain tokens may appear before *and* after the named inputs (e.g.
/// `endpoint --a <(…)> min-lp=10`); both are folded into the head so the
/// stage's positional args are preserved.
fn split_named_inputs(stage: &str) -> Result<(String, Vec<(String, String)>), BuildError> {
    let tokens = split_stage_tokens(stage)?;
    let mut head_tokens = Vec::new();
    let mut named = Vec::new();
    let mut i = 0usize;
    while i < tokens.len() {
        let tok = &tokens[i];
        let Some(name) = tok.strip_prefix("--") else {
            head_tokens.push(tok.clone());
            i += 1;
            continue;
        };
        if name.is_empty() {
            return Err(BuildError::Parse(
                "named input `--` with no name".to_string(),
            ));
        }

        let Some(next) = tokens.get(i + 1) else {
            head_tokens.push(format!("{name}=true"));
            i += 1;
            continue;
        };

        if next.starts_with("<(") {
            let (sub, after) = extract_subexpr(next)?;
            if !after.trim().is_empty() {
                return Err(BuildError::Parse(format!(
                    "named input --{name} has trailing text after `<( … )>`"
                )));
            }
            named.push((name.to_string(), sub));
            i += 2;
        } else if next.starts_with("--") {
            head_tokens.push(format!("{name}=true"));
            i += 1;
        } else {
            head_tokens.push(format!("{name}={next}"));
            i += 2;
        }
    }

    Ok((head_tokens.join(" "), named))
}

fn split_stage_tokens(stage: &str) -> Result<Vec<String>, BuildError> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut chars = stage.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' if chars.peek() == Some(&'(') => {
                depth += 1;
                cur.push(c);
            }
            ')' if depth > 0 => {
                depth -= 1;
                cur.push(c);
            }
            c if c.is_whitespace() && depth == 0 => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if depth != 0 {
        return Err(BuildError::Parse(
            "unbalanced `<( … )>` in pipe expression".to_string(),
        ));
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Extract a `<( … )>` sub-expression from the front of `s`, returning
/// the inner text and the remainder after the closing `)>`.
fn extract_subexpr(s: &str) -> Result<(String, &str), BuildError> {
    // s starts with "<(".
    let inner_start = 2;
    let bytes = s.as_bytes();
    let mut depth = 1i32;
    let mut i = inner_start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // Expect a closing `>` after `)`.
                    let inner = s[inner_start..i].trim().to_string();
                    let rest = &s[i + 1..];
                    let rest = rest.strip_prefix('>').ok_or_else(|| {
                        BuildError::Parse("`<( … )` missing closing `>`".to_string())
                    })?;
                    return Ok((inner, rest));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(BuildError::Parse(
        "unterminated `<( … )>` sub-expression".to_string(),
    ))
}
