# Implementation Plan — First Real Invariant End to End

> **Status: IMPLEMENTED (2026-05-30).** This plan has been built. See
> [`08-implementation-status.md`](08-implementation-status.md) for what actually landed, the
> deviations from this spec (notably the calldata/`petal.return` ABI, which this plan got wrong),
> and the remaining gaps. The text below is the original spec, kept as written.

**Date:** 2026-05-29  
**Status:** Concrete implementation spec — bridges the architecture in
[`02-architecture.md`](02-architecture.md) to the codebase.  
**Audience:** The implementing agent.  
**Prerequisites:** ADR-001 through ADR-010 (all research-accepted); code anchors in
[`02` Appendix A](02-architecture.md#appendix-a--codebase-anchors).

---

## Contents

1. [What this is and is not](#1-what-this-is-and-is-not)
2. [InvariantScope wire format](#2-invariantscope-wire-format)
3. [InvariantResult tri-state](#3-invariantresult-tri-state)
4. [Scope builder — replacing the argspec-only buffer](#4-scope-builder--replacing-the-argspec-only-buffer)
5. [AST→Wasm lowering — replacing `return 1`](#5-astwasm-lowering--replacing-return-1)
6. [pool_k_non_decreasing end to end](#6-pool_k_non_decreasing-end-to-end)
7. [BoundedArith — the arithmetic predicate node](#7-boundedarith--the-arithmetic-predicate-node)
8. [Code change plan](#8-code-change-plan)
9. [Test plan — standing gates](#9-test-plan--standing-gates)

---

## 1. What this is and is not

**This is:** a concrete specification of the *first* real invariant pipeline — the `InvariantScope`
wire format, the `InvariantResult` tri-state, the AST→Wasm lowering interface, and the end-to-end
implementation of `pool_k_non_decreasing`. It tells the implementing agent exactly what to change,
in which files, in what order, and what tests must pass.

**This is not:** a rehash of the architecture (`02`), the open questions (`03`), the ADRs (`04`),
or the market design (`06`). It assumes those are read. Trigger granularity is resolved (ADR-010):
invariants fire at function-exit / borrow-release boundary for both `FunctionExit` and
`ObjectType` targets. Per-`object.mutate` checking is a v1+ opt-in.

**Single highest-leverage move:** replace the `return 1` stub at `codegen.rs:787` with a real
AST→Wasm lowering that reads a properly-encoded scope buffer and evaluates the predicate. The
scope encoding (ADR-008) and numeric domain (ADR-009) decisions are captured below.

---

## 2. InvariantScope wire format

Per ADR-008: composed from the same canonical primitives as `Object::encode_canonical`
(`crates/bloom-objects/src/object.rs:113`). All integers big-endian. No floats. No padding.
Length-prefixed variable fields.

```
InvariantScope canonical encoding (byte order: top to bottom):

Offset  Size    Field                   Encoding
──────  ────    ─────                   ────────
0       1       scope_kind              u8:  0x00 = FunctionExit, 0x01 = ObjectType
1       2       target_name_len         u16 BE
3       n       target_name             UTF-8 bytes (n = target_name_len)
3+n     4       petal_version           u32 BE
7+n     2       before_count            u16 BE (0 or 1 for v1; future: multi-object invariants)

--- for each of before_count objects: ---
9+n     1       type_tag_variant        u8:  0 = Concrete, 1 = Generic, 2 = External
        ⋮                              TypeTag canonical encoding (recursive; see type_tag.rs:61)
        ⋮       version                 u64 BE
        ⋮       payload_len             u32 BE
        ⋮       payload                 raw bytes (payload_len bytes)
--- end objects ---

--- after_count objects: same layout as before ---

        ⋮       args_count              u16 BE
--- for each arg: ---
        ⋮       arg_len                 u32 BE
        ⋮       arg_bytes               canonical-encoded Arg (see encode.rs)
--- end args ---

        ⋮       ret_count               u16 BE
--- for each ret: ---
        ⋮       ret_len                 u32 BE
        ⋮       ret_bytes               raw bytes
--- end rets ---

Total size: variable, dominated by payload lengths.
```

### Encoding primitives used (all from `crates/bloom-objects/src/codec.rs`)

| Primitive | Signature | Use |
|-----------|-----------|-----|
| `write_u8` | `buf, u8` | scope_kind, type_tag_variant |
| `write_u16_be` | `buf, u16` | target_name_len, before/after/args/ret counts |
| `write_u32_be` | `buf, u32` | petal_version, payload_len, arg_len, ret_len |
| `write_u64_be` | `buf, u64` | object version |
| `write_bytes` | `buf, &[u8]` | payload, arg/ret bytes (u32 BE len prefix + data) |
| `write_bytes32` | `buf, &[u8; 32]` | (inherited from Object::encode_canonical; not used in scope directly) |

### Wasm-side decoding contract

The `__inv_<idx>` export receives `(scope_ptr: i32, scope_len: i32)` and must:

1. Read `scope_kind` at offset 0 — if not 0x00 or 0x01, the scope is malformed.
2. Read `target_name_len` (u16 BE), skip that many bytes.
3. Read `petal_version` (u32 BE) — can be ignored or validated.
4. Read `before_count` (u16 BE). Read each before-object: skip `type_tag` (its variant byte
   tells you the encoded size; or parse it fully), read `version` (u64 BE), read `payload_len`
   (u32 BE), extract `payload` into a slice. The payload slice is the decoded scope field.
5. Repeat for after-objects.
6. Read `args_count` (u16 BE). Read each arg: `arg_len` (u32 BE), skip bytes.
7. Read `ret_count` (u16 BE). Read each ret: `ret_len` (u32 BE), skip bytes.
8. Evaluate the predicate AST nodes against decoded field values.
9. Return `1` (satisfied), `0` (violated), or trap (out-of-fuel → host interprets as
   `indeterminate` via the tri-state `InvariantResult`).

**Fuel trap → indeterminate.** The Wasm export does not return `-1` for out-of-fuel. It traps
(host catches `wasmtime::Trap`). The host-side `call_invariant` catches the trap and sets
`InvariantResult { ok: false, fuel_used: budget, indeterminate: true }`.

---

## 3. InvariantResult tri-state

Per ADR-002 and ADR-008: the result channel must distinguish satisfied, violated, and
indeterminate (out-of-fuel).

### Current state

```rust
// crates/bloom-script/src/executor.rs:71-78
#[derive(Debug, Clone, Default)]
pub struct InvariantResult {
    pub ok: bool,           // true = satisfied, false = violated
    pub fuel_used: u64,
}
```

### Target state

```rust
#[derive(Debug, Clone)]
pub struct InvariantResult {
    pub ok: bool,           // true = predicate returned 1 (satisfied)
                            // false = predicate returned 0 (violated)
                            //     OR trap/out-of-fuel (indeterminate is true in that case)
    pub fuel_used: u64,
    pub indeterminate: bool, // true when the evaluation trapped (out-of-fuel);
                             // ok is always false when indeterminate is true
}
```

### Call site change (`run_invariant`, executor.rs:1243-1304)

**Before (current):** checks `res.fuel_used > *fuel_remaining`, then `if !res.ok` → revert.

**After:** same fuel check. Then:
- `res.indeterminate` → record verdict as `Indeterminate` in receipt, do NOT revert. The
  invariant was not violated; it was too expensive.
- `!res.ok && !res.indeterminate` → revert with `PtbError::InvariantFailed` (predicate
  evaluated false).
- `res.ok` → satisfied.

### Host-side dispatch (`chain_petal_runner.rs:298-317` or equivalent)

```rust
fn call_invariant(…) -> Result<InvariantResult, PtbError> {
    let result = match self.dispatch(petal_hash, export_name, scope_buf, fuel_budget) {
        Ok(result) => InvariantResult {
            ok: result.ret_buf.first().copied() == Some(1),
            fuel_used: result.fuel_used,
            indeterminate: false,
        },
        Err(e) if is_out_of_fuel_trap(&e) => InvariantResult {
            ok: false,
            fuel_used: fuel_budget,
            indeterminate: true,
        },
        Err(e) => return Err(e),
    };
    Ok(result)
}
```

---

## 4. Scope builder — replacing the argspec-only buffer

### Current state (`executor.rs:1253-1286`)

The scope buffer is built from `inv.argspec` — a `Vec<u16>` of indices into `args` and `outputs`.
Each entry is encoded as `(u32 BE len ‖ canonical Arg bytes)`. No before/after payloads. No
version. No type_tag.

### Target state

The scope builder replaces the simple argspec-based loop with the full canonical encoding from §2.
It receives additional context from the borrow table.

```rust
fn build_invariant_scope(
    inv:        &InvariantDeclStub,
    target:     &InvariantTarget,
    petal_hash: &Hash32,
    petal_version: u32,
    before_rows: &[&BorrowRow],   // rows whose baseline_payload is the "before"
    after_rows:  &[&BorrowRow],   // rows whose payload_bytes is the "after"  
    args:        &[Arg],
    rets:        &[Vec<u8>],
) -> Result<Vec<u8>, PtbError> {
    let mut buf = Vec::new();

    // scope_kind
    let kind: u8 = match target {
        InvariantTarget::ObjectType { .. } => 0x01,
        InvariantTarget::FunctionExit { .. } => 0x00,
    };
    write_u8(&mut buf, kind);

    // target_name
    let name = match target {
        InvariantTarget::ObjectType { name } => name,
        InvariantTarget::FunctionExit { name } => name,
    };
    let name_bytes = name.as_bytes();
    write_u16_be(&mut buf, name_bytes.len() as u16);
    buf.extend_from_slice(name_bytes);

    // petal_version
    write_u32_be(&mut buf, petal_version);

    // before objects
    write_u16_be(&mut buf, before_rows.len() as u16);
    for row in before_rows {
        row.type_tag.encode_into(&mut buf)?;
        write_u64_be(&mut buf, row.version);
        write_bytes(&mut buf, &row.baseline_payload);
    }

    // after objects
    write_u16_be(&mut buf, after_rows.len() as u16);
    for row in after_rows {
        row.type_tag.encode_into(&mut buf)?;
        write_u64_be(&mut buf, row.version);
        write_bytes(&mut buf, &row.payload_bytes);
    }

    // args
    write_u16_be(&mut buf, args.len() as u16);
    for arg in args {
        let arg_bytes = encode_arg_for_scope(arg)?;
        write_bytes(&mut buf, &arg_bytes);
    }

    // rets
    write_u16_be(&mut buf, rets.len() as u16);
    for ret in rets {
        write_bytes(&mut buf, ret);
    }

    Ok(buf)
}
```

### Where the before/after rows come from

Per ADR-010, invariants fire at function-exit / borrow-release boundary inside `exec_move`
(`executor.rs:558`). The caller has access to `&self.borrow_table`. After the petal call
returns and function-attached invariants are evaluated, iterate over borrow rows whose
`dirty` flag is set (i.e., rows touched by this command). For each touched row, look up
`ObjectType` invariants from the petal manifest that target that row's `type_tag`. Build
the scope with `before` = `baseline_payload`, `after` = `payload_bytes`. For
`FunctionExit` invariants, the scope uses `args`/`rets` only (no object before/after).

**Implication:** the `run_invariant` function signature gains `before_rows` and
`after_rows` parameters. The call site at `executor.rs:558` is updated to pass
borrow-table rows for both function-attached and object-type invariants.

---

## 5. AST→Wasm lowering — replacing `return 1`

### Current state (`codegen.rs:787-808`)

```rust
pub(crate) fn emit_invariant_shim(idx: u16) -> TokenStream {
    // emits: pub extern "C" fn __bloom_inv_N(_scope_ptr: i32, _scope_len: i32) -> i32 { 1 }
}
```

### Target: per-AST-node compilation to Wasm instructions

The shim is now a code generator. For each AST node in the predicate, it emits Wasm opcodes (via
`walrus` or raw `wasm-encoder` at the crate level, or via inline `#[cfg(target_arch = "wasm32")]`
Rust with `unsafe` Wasm memory access). The lowering walks the `PredicateAst` tree recursively.

**Lowering rules:**

```
FieldGe { lhs: "reserve_a", rhs: "k_last" }:
  → load field lhs from after.payload at its struct offset
  → compute rhs value (see below)
  → emit i64.ge_u / i64.lt_u → return 1 or 0

FieldLe { lhs, rhs }:
  → same, with i64.le_u

FieldEq { lhs, rhs }:
  → same, with i64.eq

StrategyKNonDecreasing { strategy_param: "S", pool_field: "p" }:
  → load pool.p.reserve_a, pool.p.reserve_b
  → checked_mul(reserve_a, reserve_b) → U512 → widen
  → load pool.p.k_last
  → compare: U512(k_after) >= U512(k_before)
  → return 1 or 0

And(lhs @ box, rhs @ box):
  → evaluate lhs, if 0 return 0
  → evaluate rhs, return result

Or(lhs, rhs):
  → evaluate lhs, if 1 return 1
  → evaluate rhs, return result

Not(inner):
  → evaluate inner, return 1 - result

BoundedArith { op: Mul, lhs, rhs, widening: U512, on_overflow: Indeterminate }:
  → load lhs, load rhs
  → convert to U512 (zero-extend)
  → mul (U512)
  → if overflow saturates U512 → trap (out-of-fuel path)
  → downcast to u128, check fits → if not, trap
  → store result as an intermediate for comparison nodes to reference
```

### Field layout knowledge

The Wasm export needs to know struct field offsets to decode named fields from the payload. The
invariant macro (`invariant.rs`) already parses field names from the closure's AST. The lowering
step must consult the petal manifest's type registry (or the codegen's own field layout info) to
emit the correct `i32.load offset=N` instruction for each named field.

**For `pool_k_non_decreasing` on the DEX pool:**
- `reserve_a` is at a known offset within the pool's payload
- `reserve_b` is at a known offset
- `k_last` is at a known offset
- All three are `u128` (16 bytes, little-endian or big-endian per the encoding convention)

The encoding convention for `u128` fields within an object payload is determined by the
type-defining petal's serialization. The invariant lowering must match.

### Simplified v1 approach: interpret scope as a flat key-value map

Rather than teaching the Wasm export struct layouts (which couples it to the petal's
serialization format), define the scope buffer to carry pre-extracted field values as
length-prefixed name-value pairs. The scope builder on the host side (Rust) does the field
extraction from the borrow table's `baseline_payload`/`payload_bytes` using the type-defining
petal's canonical decoder. The Wasm export receives a flat scope and does simple comparisons.

**Scope extension for v1 — add field entries:**

After the ret_count block in §2, append:

```
        ⋮       field_count             u16 BE
--- for each field: ---
        ⋮       name_len                u16 BE
        ⋮       name_bytes              UTF-8
        ⋮       value_before            u128 LE  (or 16 zero bytes if N/A)
        ⋮       value_after             u128 LE  (or 16 zero bytes if N/A)
```

Each `PredicateAst` leaf node references fields by name. The Wasm export scans the field table
for a matching name and loads the corresponding `value_before`/`value_after`. This keeps the Wasm
export simple, deterministic, and decoupled from struct layouts — the host-side scope builder
does the field extraction using the canonical codec for each type.

**Recommendation: use the flat field-table scope for v1.** It is simpler to lower, easier to test
(AST interpreter becomes a trivial match over the field table), and avoids coupling the invariant
Wasm to the petal's serialization format. The per-field extraction is done once per scope build
on the Rust host, not once per comparison.

> **S7 field-resolution model — RESOLVED per ADR-011 (ACCEPTED 2026-05-29).** The host extracts
> named fields (`reserve_a`, `k_last`) from an object's payload to populate the flat field table via
> the host-side schema-driven design (option b), now settled in
> [`04-decision-log.md`](04-decision-log.md) ADR-011; all five sub-questions S7a–S7e are resolved
> ([`03-open-questions.md`](03-open-questions.md) §S7). The concrete design Steps 6/7 implement:
>
> - **Field-offset computation** (S7a–S7d): `FieldDecl` gains `offset: Option<u32>`/`width:
>   Option<u32>`, computed by `#[object]` using `canonical_byte_width` (promoted from
>   `primitive_size_hint`). Width model: `ObjectId`/`Address`/`Hash32` are *already* 32B — add `UID`
>   (32B) and the `Coin<T>`/`Resource<T>` wrapper case (32B). **Fixed-prefix rule:** a field's
>   `offset` is `Some` only while every preceding field has a known fixed width; fields past the
>   first variable-width field are `None` and not invariant-addressable in v1 (the pool's
>   `reserve_*`/`k_last` are in the fixed 32/48/64/80 prefix, so unaffected).
> - **Validator stub projection** (S7e): `ObjectTypeDeclStub` carries a minimal
>   `field_layout: Vec<FieldLayoutStub { name, offset, width }>` so the scope builder has layout at
>   runtime without the full manifest.
> - **Manifest schema change**: adding `offset`/`width` to `FieldDecl` is the **sanctioned override**
>   of Appendix B's "no manifest schema changes" (ADR-011) — the implementation-gating prerequisite.
> - **Trust/red-team**: extraction is *not* covered by the ADR-002 differential test (S7b); a wrong
>   or malicious offset is caught by auditable `scope_def` offsets + the ADR-003 deploy-time gate over
>   concrete vectors (RT-011), plus a standing scope-builder round-trip unit test.

---

## 6. pool_k_non_decreasing end to end

### What it evaluates

The invariant `pool_k_non_decreasing` attached to `ObjectType("Pool")`:

1. Scope builder extracts from the borrow table:
   - `before`: `baseline_payload` of the Pool row → decode → extract `reserve_a`, `reserve_b`, `k_last`
   - `after`: `payload_bytes` of the Pool row → decode → extract `reserve_a`, `reserve_b`, `k_last`
2. Populates the field table with before/after field values.
3. Calls `__inv_0(scope_ptr, scope_len)`.
4. The Wasm export:
   - Loads `after.reserve_a`, `after.reserve_b`, `before.k_last` from the field table.
   - Computes `k_after = after.reserve_a * after.reserve_b` (using wide U512 to avoid overflow).
   - Compares `k_after >= before.k_last`.
   - Returns `1` if satisfied, `0` if violated.

### Predicate AST for this invariant

```rust
PredicateAst::And(
    Box::new(PredicateAst::And(
        Box::new(PredicateAst::BoundedArith {
            op: BoundedArithOp::Mul,
            lhs: ArithField::Field("after.reserve_a".into()),
            rhs: ArithField::Field("after.reserve_b".into()),
            widening: Widening::U512,
            on_overflow: OverflowPolicy::Indeterminate,
        }),
        Box::new(PredicateAst::FieldGe {
            lhs: "k_after".into(),
            rhs: "k_before".into(),
        }),
    )),
    Box::new(PredicateAst::FieldGe {
        lhs: "k_after".into(),
        rhs: "k_before".into(),
    }),
)
```

Wait — the `And` nodes aren't needed for the simple comparison. A cleaner AST for the current
PredicateAst vocabulary (extended with BoundedArith):

The invariant is: `after.reserve_a * after.reserve_b >= before.k_last`. With the flat field-table
scope (§5), the Wasm export:
1. Finds field `"after.reserve_a"` in field table → loads 16-byte u128 LE
2. Finds field `"after.reserve_b"` → loads 16-byte u128 LE
3. Finds field `"before.k_last"` → loads 16-byte u128 LE
4. Computes `k_after_u512 = u512(after.reserve_a) * u512(after.reserve_b)`
5. Computes `k_before_u512 = u512(before.k_last)`
6. Returns `u64(k_after_u512 >= k_before_u512)`

The AST doesn't need `And` for this — it's a single `FieldGe` with a computed LHS. But the
current `FieldGe` takes `String` field names, not expressions. The `BoundedArith` node computes
the LHS as an intermediate.

### Concrete field table for this scope

For a Pool object before a swap:
```
field_count    = 6 (u16 BE)

name="before.reserve_a"  value_before=<rA_old>  value_after=<zero>
name="before.reserve_b"  value_before=<rB_old>  value_after=<zero>
name="before.k_last"     value_before=<k_old>   value_after=<zero>
name="after.reserve_a"   value_before=<zero>    value_after=<rA_new>
name="after.reserve_b"   value_before=<zero>    value_after=<rB_new>
name="after.k_last"      value_before=<zero>    value_after=<k_new>
```

---

## 7. BoundedArith — the arithmetic predicate node

### PredicateAst extension (`types.rs:203`)

Add to the `PredicateAst` enum:

```rust
/// Checked arithmetic expression evaluated within the predicate.
/// All operands are u128; intermediates widen to U256 or U512.
/// Overflow ⇒ indeterminate (never failed).
BoundedArith {
    /// Operation.
    op: BoundedArithOp,
    /// Left operand (field reference or literal).
    lhs: ArithExpr,
    /// Right operand (N/A for Sqrt).
    rhs: ArithExpr,
    /// Intermediate widening domain.
    widening: Widening,
    /// What to do on overflow.
    on_overflow: OverflowPolicy,
},
```

Supporting enums:

```rust
pub enum BoundedArithOp {
    Add,        // checked_add → Option<u128>
    Sub,        // checked_sub
    Mul,        // checked_mul → with widening
    DivFloor,   // floor division
    DivCeil,    // ceil division
    Sqrt,       // integer floor sqrt
}

pub enum ArithExpr {
    /// Reference to a named field in the scope (e.g., "after.reserve_a").
    Field(String),
    /// A literal u128 value.
    Literal(u128),
}

pub enum Widening {
    None,   // u128 operands, no widening (overflow ⇒ Indeterminate)
    U256,   // widen intermediates to 256 bits
    U512,   // widen intermediates to 512 bits
}

pub enum OverflowPolicy {
    Indeterminate,  // overflow ⇒ predicate result is indeterminate
    Saturate,       // overflow ⇒ saturate at u128::MAX (rarely correct)
}
```

### SMT-encodability

`BoundedArith` stays in the integer domain (ADR-009). The SMT encoding for Z3 (used by Rung 3's
seed generation) is:
- `Add(a, b)`: `result = a + b; assert result <= u128::MAX` (if overflow → UNSAT)
- `Mul(a, b, U512)`: `result = ZeroExt(a, 384) * ZeroExt(b, 384); assert result <= u128::MAX`
- `Sqrt(n)`: `assert result * result <= n < (result + 1) * (result + 1)` (nonlinear, slow but
  tractable for u128)

The Kani harness (§5.1 of `02-architecture.md`) uses the same Rust checked arithmetic that the
production code (`bloom-dex-math`) uses — no SMT encoding needed for the Kani path; Kani
translates Rust checked arithmetic to CBMC natively.

---

## 8. Code change plan

Ordered by dependency. Each step is a standalone PR-able change with its own tests.

| Step | File(s) | What changes | ~LOC | Depends on |
|------|---------|-------------|------|-----------|
| 1 | `executor.rs:71-78` | Add `indeterminate: bool` to `InvariantResult` | 3 | — |
| 2 | `chain_petal_runner.rs:298-317` (or equivalent dispatch) | Trap-catch → set `indeterminate = true` | 15 | Step 1 |
| 3 | `executor.rs:1243-1311` | Replace argspec-only scope builder with canonical encoding (§4) | 60 | Step 1 |
| 4 | `types.rs:203-236` | Add `BoundedArith` variant + supporting enums (§7) | 40 | — |
| 5 | `invariant.rs:128` (`predicate_ast_of`) | Lower closures to `BoundedArith` nodes | 40 | Step 4 |
| 6 | `codegen.rs:787-808` (`emit_invariant_shim`) | Replace `return 1` with flat-field-table scope decoding + node evaluation (§5) | 250 | Steps 2, 4 |
| 7 | New: `invariant_scope.rs` (in `bloom-script`) | Canonical `build_invariant_scope` function + field-table construction | 120 | Steps 1, 4 |
| 8 | `chain_vm.rs:225` (`validate_chain_wasm`) | Add float-opcode rejection (per ADR-004) | 30 | — |
| 9 | `executor.rs:557-577` | Wire borrow-table rows into invariant calls | 20 | Steps 3, 7 |
| 10 | `borrow_table.rs` | (No changes needed — rows already provide `type_tag`, `version`, `baseline_payload`, `payload_bytes`) | 0 | — |
| 11 | `petal-dex` pool manifest / macro usage | Declare `pool_k_non_decreasing` with real predicate | 15 | Steps 5, 6 |

**Total estimated LOC: ~590** (net, across existing and new files).

### Step dependencies visual

```
Step 1 ──→ Step 2 ──→ Step 3 ──→ Step 9
  │                    │
  │                    └──→ Step 7 ──→ Step 9
  │
Step 4 ──→ Step 5 ──→ Step 6 ──→ Step 9
                        │
                        └──→ Step 11

Step 8 (independent)
```

Steps 1+2+3+7+9 form the scope-encoding track. Steps 4+5+6+9 form the predicate-evaluation track.
Step 8 (float rejection) and Step 10 (no change) are independent. Step 11 (petal-dex integration)
requires both tracks.

---

## 9. Test plan — standing gates

Each gate is a test that must pass in CI before the change is accepted.

### 9.1 Scope encoding round-trip (Step 7)

```rust
#[test]
fn invariant_scope_round_trip() {
    // Build a scope with known values, encode, decode, assert equality.
    let scope = build_invariant_scope(…);
    let decoded = decode_invariant_scope(&scope).unwrap();
    assert_eq!(decoded.before_payloads[0], expected_before);
    assert_eq!(decoded.after_payloads[0], expected_after);
    // Encode again, assert idempotent.
    let scope2 = build_invariant_scope(…);
    assert_eq!(scope, scope2);
}
```

### 9.2 InvariantResult tri-state (Step 2)

```rust
#[test]
fn invariant_result_indeterminate_on_trap() {
    // Mock a petal runner that traps on call_invariant.
    // Assert InvariantResult { ok: false, indeterminate: true, fuel_used: budget }.
}

#[test]
fn invariant_result_satisfied() {
    // Normal return of 1 → ok: true, indeterminate: false.
}
```

### 9.3 AST-interpreter vs. __inv Wasm differential test (Steps 6+7)

A standing gate that replaces today's `return 1`: given the same scope buffer,
evaluate the predicate AST via a trusted Rust interpreter AND via `call_invariant`
on the compiled Wasm export. Results must match bit-identically.

```rust
#[test]
fn ast_interpreter_matches_wasm_export() {
    for scope in fuzz_corpus() {
        let ast_result = interpret_predicate_ast(&predicate_ast, &scope);
        let wasm_result = runner.call_invariant(petal_hash, "__inv_0", &scope, budget).unwrap();
        assert_eq!(ast_result.ok, wasm_result.ok);
        // indeterminate can differ: AST interpreter doesn't trap on fuel
    }
}
```

### 9.4 pool_k_non_decreasing integration test (Step 11)

```rust
#[test]
fn pool_k_non_decreasing_holds_after_valid_swap() {
    // Deploy pool petal with pool_k_non_decreasing invariant.
    // Execute a valid swap (k increases due to fee).
    // Assert invariant passes (no revert).
}

#[test]
fn pool_k_non_decreasing_reverts_on_k_decrease() {
    // Execute a swap that would cause k to decrease (malicious).
    // Assert PTB reverts with InvariantFailed(pool_k_non_decreasing).
    // Assert invariant result recorded in receipt (even on failure).
}
```

### 9.5 Invariant receipt emission (Step 9)

```rust
#[test]
fn invariant_verdict_in_receipt_on_success() {
    // Execute a petal function with attached invariants.
    // Assert the receipt contains {invariant_id, verdict: satisfied}.
    // Per ADR-002: result is recorded EVEN ON SUCCESS.
}
```

### 9.6 Gas metering regression (Step 6)

```rust
#[test]
fn invariant_fuel_cost_is_bounded() {
    // Run pool_k_non_decreasing with extreme reserve values (u128::MAX).
    // Assert fuel_used < MAX_INVARIANT_FUEL_BUDGET.
    // Assert fuel_used is deterministic (same scope → same fuel).
}
```

### 9.7 Float opcode rejection (Step 8 per ADR-004)

```rust
#[test]
fn chain_wasm_rejects_float_opcodes() {
    // Build a .wasm with f32.add or f64.mul.
    // Assert validate_chain_wasm returns Err.
    // Mirror the existing tail-call rejection pattern.
}
```

### 9.8 Kani harness on bloom-dex-math (Step 11, per 02 §5.1)

The Kani harnesses from `02-architecture.md` §5.1 — `integer_sqrt`, bounded `quote`/`apply_swap`
safety, and k-non-decreasing — become a CI gate. These are **independent** of the invariant
implementation (they prove properties of the math kernel, not the invariant runtime). But they
provide the first calibration point for the trust scoring model (`06` §4.2).

---

## Appendix A: field enumeration for pool_k_non_decreasing

The scope builder (Step 7) needs to extract named fields from the pool object payload. The pool
serialization (`petal-dex/crates/pool/src/lib.rs`) uses a canonical binary format. For the v1
flat-field-table scope, the scope builder calls the pool's canonical decoder to extract:

| Field | Payload offset (example) | Type | Scope name |
|-------|-------------------------|------|------------|
| `reserve_a` | depends on pool encoding | u128 LE | `"before.reserve_a"`, `"after.reserve_a"` |
| `reserve_b` | depends on pool encoding | u128 LE | `"before.reserve_b"`, `"after.reserve_b"` |
| `k_last` | depends on pool encoding | u128 LE | `"before.k_last"`, `"after.k_last"` |

The scope builder uses the type-defining petal's canonical decoder for the pool type to extract
these. The invariant doesn't need to know the offsets — the host does the extraction once.

---

## Appendix B: what NOT to change in v1

- **No new borrow-table fields.** The existing `BorrowRow` already carries `type_tag`, `version`,
  `baseline_payload`, `payload_bytes` — everything the scope builder needs.
- **No manifest schema changes** — *except the one sanctioned by ADR-011*: `FieldDecl` gains
  `offset: Option<u32>` / `width: Option<u32>` (the field-resolution prerequisite, §5). The
  `InvariantDecl` schema otherwise stays as-is for v1. The `VerificationClaim` schema (`06`) is
  additive and lands later.
- **No on-chain scoring.** The trust scoring model (`06` §4) is specified but not implemented in
  this plan. The first invariant (`pool_k_non_decreasing`) operates at Rung 2 (runtime) and
  scores at L1 per the model.
- **No fuzzing rung in v1.** The Rung 3 pre-deploy fuzz pipeline
  ([`rung3-fuzzing-state-of-art.md`](rung3-fuzzing-state-of-art.md)) is designed but lands after
  the runtime path works end to end. The first invariant ships with manual testing.
- **No cross-petal claims.** The `pool_k_non_decreasing` invariant is attached to the pool petal
  itself, not to the router. Cross-petal claims (`06` §6 #4) are v1+.
