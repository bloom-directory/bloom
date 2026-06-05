# Authoring invariants in a petal

An **invariant** is a safety property the chain enforces every time an object is
mutated: if it doesn't hold after a command, the whole PTB reverts. This guide
shows how to add one to your petal. For the design rationale see
[`../research/formal-verification/02-architecture.md`](../research/formal-verification/02-architecture.md);
for what's actually built see
[`../research/formal-verification/08-implementation-status.md`](../research/formal-verification/08-implementation-status.md).

## The shape

Put `#[invariant(...)]` on a `pub fn` inside your `#[bloom::petal]` module:

```rust
#[invariant(
    name   = "pool_k_non_decreasing",
    target = "Pool",   // base object-type name (no generics)
    pred   = |before, after| after.reserve_a * after.reserve_b >= before.k_last,
    text   = "the pool constant-product k never decreases across a swap", // optional
)]
pub fn swap_exact_in<A, B>(coin_in: Coin<A>, pool: &mut Resource<Pool>, min_out: u128) -> Coin<B> {
    /* ... */
}
```

- **`name`** — human-readable id; appears in the receipt verdict.
- **`target`** — the **base** object-type name (`"Pool"`, not `"Pool<A, B>"`).
  The invariant fires after *every* command that mutates a row of that type,
  not just this function (it guards the type, not the fn). Attaching it to a
  representative mutating function is enough.
- **`pred`** — a closure comparing the object's `before` and `after` state.
- **`text`** *(optional)* — a plain-language statement of what the predicate is
  meant to guarantee. Stored alongside the predicate (`InvariantDecl.human_text`)
  and surfaced for tooling/arbitration; it does **not** affect evaluation. The
  authoritative rule is always the `pred` math — `text` is the human-readable
  claim paired with it (ADR-003 spec↔intent).

## Writing the predicate

Reference fields as **`before.<field>`** and **`after.<field>`** — the
qualifier is required (it matches how the host lays out the evaluation scope).
`after.reserve_a` reads the post-mutation value; `before.k_last` the
pre-mutation value.

**Supported shapes:**

| Form | Example | Lowers to |
|------|---------|-----------|
| Field comparison | `after.x >= before.x` | `FieldGe` / `FieldLe` / `FieldEq` |
| Arithmetic comparison | `after.reserve_a * after.reserve_b >= before.k_last` | `ArithCmp` |
| Boolean composition | `a >= b && after.kind <= 2`, `k_ok \|\| !(after.lp == before.lp)` | `And` / `Or` / `Not` |

- Comparison operators: `>=`, `<=`, `==`.
- Arithmetic: `*`, `+`, and `u128` literals. Multiplication widens to 256
  bits, so a product of two `u128`s never overflows. Subtraction (`-`) is
  **rejected at deploy** for now — on underflow the on-chain evaluator fails
  closed (reverts) while the reference interpreter treats it as indeterminate,
  and that divergence isn't yet covered by the differential gate. Rephrase
  using `+`/`*` (e.g. `a >= b + c` instead of `a - c >= b`).
- Boolean: `&&`, `||`, `!` compose any of the above (short-circuit at runtime).

**Field rules (important):** only **fixed-prefix, ≤16-byte unsigned integer fields** are
addressable — i.e. `u8/u16/u32/u64/u128` fields that appear *before* the first
variable-width field in the struct. `bool` is fixed-width but not addressable as
a numeric invariant field. Once a `Vec<u8>`, `String`, or `TypeTag` field
appears, it and everything after it are **not** addressable. (Reserves and
`k_last` sit in the pool's fixed prefix, so they're fine.)

## The golden rule: it must hold after *every* mutation of the target

An `ObjectType("Foo")` invariant fires after **every** command that mutates a
`Foo` — not just the function you wrote it on. So the predicate must be true for
*all* of them, or it will wrongly revert legitimate operations.

Cautionary tale: `pool_k_non_decreasing` was first written as just
`after.reserve_a * after.reserve_b >= before.k_last`. That holds for swaps, but
`remove_liquidity` legitimately shrinks both reserves (so `k` drops) — and since
the invariant fires on *that* mutation too, every withdrawal reverted. The fix
uses boolean composition to exempt liquidity events:

```rust
pred = |before, after| after.reserve_a * after.reserve_b >= before.k_last
    || !(after.lp_supply == before.lp_supply)   // a liquidity event: k may move
```

When in doubt, enumerate every function that mutates the target and check the
predicate against each. An object-type invariant (`target = "T"`) fires on
**every** mutation of `T` — per-function *filtering* (e.g. "only on `swap`, not
on `remove_liquidity`") is future work. Function-exit invariants (those without a
`target`) already fire on their attached function's exit, but v1 does not extract
args/returns into the field table (so field-referencing predicates on
function-exit invariants are rejected at deploy).

## What is NOT supported (and will be rejected at deploy)

Deploy-time validation (`validate_chain_wasm`) **rejects** a petal whose
invariant predicate it can't enforce — fail-closed, so an unenforceable
invariant can never silently pass:

- `Div` / `Sqrt`;
- strategy-call forms like `S::k(p) >= p.k_last`;
- anything that doesn't lower to a supported shape (an opaque closure);
- predicates on function arguments/returns (function-exit invariants don't have
  field extraction yet — use an object `target`);
- a field name not present in the target's addressable layout (a typo would
  otherwise silently fail-open under `!`);
- **vacuous predicates** — anything statically always-true or always-false
  (`after.x >= after.x`, `P || !P`, `2 <= 1`). A predicate that enforces nothing
  is a false promise, so it's refused (ADR-003 intent-conformance).
- **semantically vacuous predicates** — structurally non-trivial but always-true
  or always-false because of field domain constraints. Examples: `after.x >= 0`
  on a `u128` field (every u128 is ≥ 0); `after.x >= 1000` on a `u8` field (max
  value is 255). A boundary-test generator at deploy time catches these (ADR-003
  Tier 1a).

If you hit a rejection, the error names the offending invariant; rewrite the
predicate into a supported shape or open an issue to grow the vocabulary.

## What happens at runtime

After a command mutates a `target` row, the invariant is evaluated:

- **satisfied** → the PTB commits;
- **violated** → the PTB reverts with `InvariantFailed`;
- **indeterminate** (the evaluation ran out of fuel) → *not* a violation; the
  PTB is **not** reverted on that basis.

Every evaluation is recorded in the transaction **receipt** (`invariant_outcomes`,
each `{name, cmd_idx, verdict}`), readable over RPC — including on success.

## Testing your invariant

- **Unit / host:** the macro lowers your closure to a `PredicateAst`; a trusted
  host interpreter (`bloom_petal_manifest::interpret_predicate`) and the
  macro-generated host evaluator (`<petal>::<mod>::__bloom_inv_<n>_eval`) can be
  driven directly over a scope built with
  `bloom_script::invariant_scope::build_invariant_scope`. The DEX suite's
  `pool_k_invariant.rs` is the worked example (incl. a 2000-case randomized
  differential).
- **Real wasm (`--ignored`):** compile the petal to `wasm32-unknown-unknown` and
  drive the real `__inv_<n>` export via `PetalVm::run_chain_call` — see
  `examples/petal-dex/tests/bloom-petal-dex-it/tests/real_inv_wasm.rs`. This is
  the only layer that exercises the calldata/`petal.return` ABI end-to-end.

## Worked example

The canonical example is `pool_k_non_decreasing` on the DEX pool:
`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs` (search `#[invariant`).
It asserts the constant-product `k = reserve_a · reserve_b` never decreases
across a swap, and is exercised end-to-end in `real_wasm_pool.rs`.
