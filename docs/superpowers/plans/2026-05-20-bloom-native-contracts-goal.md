# Bloom-native contracts — /goal prompt (Phases 1 & 2)

**Date:** 2026-05-20
**Branch:** `feat/bloom-like-petals`
**Spec:** [`docs/specs/2026-05-20-bloom-native-contracts-design.md`](../../specs/2026-05-20-bloom-native-contracts-design.md)

This file is a self-contained `/goal` prompt to drive Claude Code through
the first two phases of the Bloom-native contracts framework.
Phases 3 (DEX rewrite), 4 (parity), and 5 (deprecation) are explicit
follow-up `/goal` invocations.

---

## Prompt

```
Implement Phases 1 and 2 of the Bloom-native contracts framework as
specified in `docs/specs/2026-05-20-bloom-native-contracts-design.md`.

You are on the branch `feat/bloom-like-petals`. The current contract
framework (`bloom-contract*`, `examples/dex/*`, `examples/wloom`) MUST
stay fully operational throughout — the four-validator docker DEX
acceptance test (`examples/dex/tests/bloom-dex-it/tests/docker_dex_multi_user.rs`)
and the chain DEX demo (`examples/dex/tests/bloom-dex-it/tests/chain_dex_demo.rs`)
must pass at every commit. The new framework lives alongside the old one.

## Read first (in order)

1. `docs/specs/2026-05-20-bloom-native-contracts-design.md` — the spec
   you are implementing. THIS IS THE CANONICAL SOURCE OF TRUTH for
   every design decision. If something is ambiguous, prefer the
   spec's stated intent and flag the ambiguity in a TODO comment + a
   note at the end of your final report. Do not re-litigate decided
   design questions.
2. `docs/specs/2026-05-18-bloom-chain-design.md` — to understand the
   existing chain surface you are extending (esp. §6 state, §7 host
   imports, §7.1 tx kinds, §7.10 ABI codec).
3. `docs/specs/2026-05-19-contract-macro-v2.md` — the framework you
   are adding ALONGSIDE (not replacing). Useful for understanding
   how macros currently emit manifests.
4. `crates/bloom-contract-macros/src/lib.rs` and
   `crates/bloom-contract/src/lib.rs` — to understand the current
   macro entry points so the new ones can coexist.
5. `crates/bloom-chain-abi/src/lib.rs` — the canonical codec. The new
   framework REUSES this codec for object payload encoding; do not
   fork it.

## Phase 1 deliverables (foundation — must complete)

Create these new crates under `crates/`:

- **`bloom-objects`** — Object types (`ObjectId`, `Object`, `Owner`,
  `TypeTag`, `Ability`), the object-store data model, and the new
  host-import function signatures (declarations only; the actual
  implementations land in `bloom-chain-state` / `bloom-chain-node`).
  Codec extensions for object payload encoding using the existing
  `bloom-chain-abi` primitives.

- **`bloom-resource`** — Runtime support library used by all
  type-module petals: `Coin<T>` primitives, `Capability<T>`
  primitives, linearity bookkeeping helpers, the `Signer` argument
  type, the wasm-side host-import wrappers (analogous to
  `bloom-petal-sdk` but for the new imports).

- **`bloom-resource-macros`** — The new proc-macro crate:
  - `#[bloom::petal(path = "...")]` — module-level attribute
  - `#[object(abilities = "...")]` — struct attribute
  - `#[capability]` — sugar for capability objects
  - `#[invariant(name, target, pred)]` — invariant declaration
  Emits: wasm function exports, manifest entries, invariant closures.
  Generic type-arg handling per spec §11. The macros may share
  internals with `bloom-contract-macros` but live in a separate
  crate so the old framework stays untouched.

- **`bloom-script`** — PTB types (`PtbTx`, `Command`, `MoveCmd`,
  `Arg`, `PetalRef`, etc. per spec §7.1), canonical
  encode/decode using `bloom-chain-abi`, the PTB validator
  (signature check, expiry, petal resolution, function-signature
  typecheck, version + access check), and the PTB executor
  (sequential command execution, value-flow tracking, invariant
  checking, linearity check). In Phase 1 the executor is a library;
  in Phase 2 it gets wired into the chain.

Add the new tx kind: extend `crates/bloom-chain-types` with
`TxKind::SubmitPtb(PtbTx)` per spec §16.1. In Phase 1 the chain
rejects this tx kind with a clear "not yet activated" error — the
goal is just to make the surface visible.

Add the new host imports per spec §16.2 to the chain VM's linker as
declarations only (returning "not yet activated" trap). Existing
host imports remain unchanged and fully functional for legacy petals.

For each crate, add unit tests covering: type roundtrips through the
codec, macro expansion (use `trybuild` or equivalent), PTB encode/decode,
PTB validation rejecting malformed inputs.

## Phase 2 deliverables (first working PTB end-to-end)

Once Phase 1 lands and the workspace is green:

- **`bloom-petal-fungible`** — Implements `/bloom/core/fungible` per
  spec §14.1 / §9. `Coin<phantom T>` with split, merge, transfer.
  `MintCap<T>`, `BurnCap<T>`, `Supply<T>`. The currency-creation flow
  returns `(MintCap, BurnCap, Supply)`. Uses `bloom-resource-macros`.

- **`bloom-petal-cap`** — `/bloom/core/cap`. Generic capability
  primitives (transferable, lockable, scoped-by-expiry).

- **Activate `TxKind::SubmitPtb`** in the chain executor: wire the
  Phase 1 `bloom-script` executor into `bloom-chain-node` /
  `bloom-petals` so PTBs actually execute. Activate the new host
  imports.

- **Genesis LOOM migration**: at chain bootstrap, convert each
  account's `loom: u128` into a `Coin<LOOM>` object owned by that
  address. Implement the read-side compatibility shim that
  re-aggregates `Coin<LOOM>` for legacy `account.loom` reads (used
  by the existing `Transfer` and `Call` tx kinds).

- **First integration test**: under a new crate `crates/bloom-petal-it`
  (NOT `examples/dex/tests/bloom-dex-it/` — keep the old test crate
  untouched), write a test that:
  1. Spins up a single-node chain
  2. Submits a PTB that creates a new currency `Coin<TestToken>`
  3. Submits a PTB that mints 1000, splits into two coins, transfers
     one to Bob, merges Bob's other holdings, and burns 100
  4. Asserts the resulting object store state matches expected
  5. Submits a PTB that violates linearity (orphan object) and
     asserts revert
  6. Submits a PTB with a missing capability and asserts revert

## What you MUST NOT do

- Do NOT modify `crates/bloom-contract*` source. The old framework
  stays untouched.
- Do NOT modify `examples/dex/*` or `examples/wloom`. They are
  untouched.
- Do NOT change `crates/bloom-chain-abi` semantics. You may add new
  encoder/decoder helpers, but the canonical encoding rules in chain
  spec §7.10 are frozen.
- Do NOT remove or rename existing host imports.
- Do NOT touch the consensus engine (`bloom-chain-consensus`).
- Do NOT implement Phases 3-5 (DEX rewrite, parity, deprecation).
  Those are separate /goals.
- Do NOT implement the optional `Publish` / `UpgradePetal` PTB
  commands in Phase 1. Stub them — they land later.
- Do NOT implement parallel execution, resolution policies, or
  zkVM proofs (all v1+ per spec §2).

## Working method

- Use TDD per the superpowers:test-driven-development skill. Every
  new module should have unit tests written first or alongside.
- After Phase 1 completes, run the full workspace test suite plus
  the docker DEX e2e (`scripts/test-docker-dex.sh`) and confirm
  green BEFORE starting Phase 2.
- Commit per-crate or per-logical-unit. Don't bundle the whole
  framework into one commit.
- Use the systematic-debugging skill if you hit unexpected failures;
  do not work around symptoms.
- Use the subagent-driven-development skill if Phase 1 deliverables
  are independent enough to parallelize (e.g. `bloom-objects` /
  `bloom-resource` / `bloom-script` are largely independent).

## Definition of done

- All Phase 1 crates compile, pass clippy, pass their own unit tests.
- All Phase 2 crates compile, pass clippy, pass their own unit tests.
- The new integration test (`crates/bloom-petal-it`) passes.
- `cargo test --workspace` is green.
- `scripts/test-docker-dex.sh` is green (old DEX still works).
- v0 acceptance items 1-5 and 7-10 from spec §19 are demonstrably
  satisfied. (Items 6 and 7 about multi-validator docker tests for
  the new framework are for Phase 3.)
- A short report in the final message describing what landed, what
  ambiguities you flagged, and what's queued for the next /goal
  (Phase 3 — DEX rewrite).

Spec is the source of truth. When in doubt, re-read the relevant
spec section. When the spec is genuinely silent, prefer simplicity
and bloom-paper alignment (linear, content-addressed, capability-based,
no EVM idioms), and flag the choice in your final report.
```

---

## Follow-up goals (not part of this prompt)

- **Phase 3** — DEX rewrite (`bloom-petal-dex-pool`,
  `bloom-petal-dex-cpmm`, new docker multi-validator e2e under
  `bloom-petal-dex-it`).
- **Phase 4** — Parity: all current docker DEX scenarios pass under
  the new framework; mark `bloom-contract*` and `examples/dex/*`
  and `examples/wloom` as `#[deprecated]`.
- **Phase 5** — Removal of the old framework (separate decision
  after a soak period).
