# Bloom-native contracts — /goal prompt (full implementation)

**Date:** 2026-05-20
**Branch:** `feat/bloom-like-petals`
**Spec:** [`docs/specs/2026-05-20-bloom-native-contracts-design.md`](../../specs/2026-05-20-bloom-native-contracts-design.md)
**Supersedes:** [`2026-05-20-bloom-native-contracts-goal.md`](2026-05-20-bloom-native-contracts-goal.md) (which only covered Phases 1–2)

A single self-contained `/goal` prompt that drives Claude Code through
the entire Bloom-native contracts implementation: Phases 1, 2, 3, and
the bookkeeping pieces of Phase 4. Phase 5 (old-framework removal) is
explicitly deferred to a separate decision after soak.

---

## Prompt

```
Implement the Bloom-native contracts framework end-to-end as specified
in `docs/specs/2026-05-20-bloom-native-contracts-design.md`. Cover
Phases 1, 2, 3, and the deprecation-flag portion of Phase 4 from
spec §17. Do NOT remove the old framework — that is Phase 5, deferred.

You are on branch `feat/bloom-like-petals`. Stay on this branch. The
current contract framework (`crates/bloom-contract*`, `examples/dex/*`,
`examples/wloom`) MUST remain fully operational throughout. The
four-validator docker DEX acceptance test
(`examples/dex/tests/bloom-dex-it/tests/docker_dex_multi_user.rs`) and
the chain DEX demo
(`examples/dex/tests/bloom-dex-it/tests/chain_dex_demo.rs`) must pass
at every commit. The new framework lives alongside the old until
parity is demonstrated.

Do not stop until the Definition of Done at the bottom of this prompt
is fully satisfied. If you hit a blocker, do not silently shrink
scope — diagnose the root cause, document the obstacle in your final
report, and either resolve it or leave a precisely-described handoff.

## Read first (in order)

1. `docs/specs/2026-05-20-bloom-native-contracts-design.md` — the
   canonical source of truth for every design decision. If something
   feels ambiguous, prefer the spec's stated intent; flag the
   ambiguity in a TODO comment and your final report. Do not
   re-litigate decided design questions.
2. `docs/specs/2026-05-18-bloom-chain-design.md` — the existing chain
   surface you are extending (esp. §6 state, §7 host imports,
   §7.1 tx kinds, §7.10 ABI codec).
3. `docs/specs/2026-05-19-contract-macro-v2.md` — the older framework
   you are adding ALONGSIDE (not replacing).
4. `crates/bloom-chain-abi/src/lib.rs` — the canonical codec.
   REUSE this codec for object payload encoding and PTB encoding;
   do not fork it.
5. `crates/bloom-chain-state/src/trie.rs` — the placeholder trie
   commitment; the new `Object` / `OwnershipIndex` TrieKind variants
   reuse the same algorithm (spec §16.3).
6. `crates/bloom-chain-state/src/account.rs` — the 122-byte SSZ
   `Account` whose `loom` field becomes a denormalized cache (spec §9.2).
7. `crates/bloom-contract-macros/src/lib.rs` +
   `crates/bloom-contract/src/lib.rs` — how the existing macro crate is
   organized; useful for siting the new macros so the old ones stay
   untouched.

## Sub-agent strategy

The implementation has enough independent surface area to benefit from
the `superpowers:subagent-driven-development` skill. Recommended
parallelization:

Phase 1 — foundation, after the shared `bloom-objects` type crate is
in place, dispatch in parallel:
  - bloom-resource (runtime library)
  - bloom-resource-macros (proc-macros; uses bloom-resource API
    contracts agreed up front)
  - bloom-script (PTB types + executor library)
The merge step wires them together and adds chain-side stubs.

Phase 2 — after the foundation merges, in parallel:
  - bloom-petal-fungible
  - bloom-petal-cap
Then a sequential merge step for chain activation, genesis migration,
legacy compat shim, and the bloom-petal-it integration test.

Phase 3 — after Phase 2 lands, in parallel:
  - bloom-dex-math (workspace crate, no petal)
  - bloom-petal-dex-pool (the Pool<A, B, S> petal)
  - bloom-petal-dex-cpmm (the ConstantProduct strategy)
  - bloom-petal-dex-router (router petal — depends on bloom-dex-math)
Then sequential: integration tests in bloom-petal-dex-it, multi-validator
docker test.

Use the `Plan` agent type for design micro-decisions inside a phase
when the spec is silent on a detail (e.g. exact buffer-layout choices
inside a wasm export). Use `Explore` for "where is X?" lookups across
the workspace. Use `general-purpose` for parallel implementation
streams as above. Use `superpowers:code-reviewer` after each phase
completes to catch deviations from the spec.

## Phase 1 — Foundation

Create these new crates under `crates/`:

- **`bloom-objects`** — Object types per spec §4: `ObjectId`, `Object`,
  `Owner` (Address/Object/Shared/Immutable), `TypeTag` (recursive:
  Concrete/Generic/External), `Ability` bitfield, `AccessMode`, the
  object-store data model, and the new host-import function-signature
  declarations. Payload codec extensions over `bloom-chain-abi`.

- **`bloom-resource`** — Runtime support library used by every new
  petal: `Coin<T>` / `Capability<T>` primitives, `Signer`,
  `Resource<T>` wrapper for non-phantom generics (spec §11.2), the
  wasm-side host-import wrappers, linearity bookkeeping helpers
  (transient/persistent borrow-table client side), and the standard
  arg/ret canonical-codec buffer protocol (spec §11.1).

- **`bloom-resource-macros`** — The proc-macro crate emitting:
  - `#[bloom::petal(path = "...")]` — module attribute
  - `#[object(abilities = "...")]` — struct attribute (phantom vs
    non-phantom T detection per §11.2; reject plain T in fields/args)
  - `#[capability]` — sugar for capability objects
  - `#[invariant(name, target, pred)]` — invariant declaration
  Emits: one wasm export per `pub fn` named `__petal_<name>` with the
  uniform signature `(args_ptr, args_len, ret_ptr, ret_cap) -> i32`
  (spec §11.1); one `__inv_<idx>` per invariant; the
  `bloom_petal_manifest_v0` custom section as canonical-codec bytes
  (spec §8); the derived `<petal>.petal.json` sidecar via the
  build pipeline. Macros MAY share lower-level helpers with
  `bloom-contract-macros` but live in their own crate so the old
  framework stays untouched.

- **`bloom-script`** — PTB types (`PtbTx`, `Command`, `MoveCmd`,
  `Arg`, `PetalRef`, etc. per spec §7.1), canonical encode/decode,
  the PTB validator (spec §7.2 steps 1–6, 8, the function-signature
  typecheck against the new manifest), the PTB executor (steps 7–10:
  sequential command dispatch, borrow-table management, command-end
  diff-check + invariant check, tx-end linearity + Account.loom
  reconciliation + commit). In Phase 1 the executor is a library;
  Phase 2 wires it into the chain.

Chain-side stubs (do NOT activate yet):

- Add `TxKind::SubmitPtb(PtbTx)` to `crates/bloom-chain-types` per
  spec §16.1; selector 3 (after Transfer=0, Deploy=1, Call=2).
  Chain initially rejects this kind with a clear
  `NotYetActivated` receipt.
- Add the new host imports per spec §16.2 to the VM linker as
  declarations only — each traps `NotYetActivated`. Existing host
  imports stay untouched and fully functional.
- Add the two new `TrieKind` variants (`Object`, `OwnershipIndex`)
  to `bloom-chain-state` reusing the existing BLAKE3-tagged-sorted-leaf
  placeholder commitment; extend `state_root` to the 128-byte payload
  per spec §16.3. The accounts + code tries remain untouched.
- Add `petals.lock` plumbing in `bloom-contract-build` (or a new
  `bloom-petal-build` crate if cleaner): read `petals.lock` from the
  workspace root, resolve `external_type_refs` placeholders, embed
  the final manifest into the wasm `bloom_petal_manifest_v0` custom
  section (spec §8.3).

Tests for Phase 1: codec round-trips, macro expansion (use `trybuild`
or equivalent), PTB encode/decode, PTB validator unit tests rejecting
malformed inputs, new-TrieKind commitment round-trips, manifest custom
section round-trips per spec §19 item 12.

## Phase 2 — Fungible petal + first working PTB

After Phase 1 merges and the workspace is green:

- **`bloom-petal-fungible`** — `/bloom/core/fungible` per spec §9 +
  §14.1. Implements `Coin<phantom T>` with split/merge/transfer,
  `MintCap<T>`, `BurnCap<T>`, `Supply<T>`. The `LOOM` marker type
  lives in this crate (spec §9.1). `mint_genesis` is gated by an
  `EpochZero` capability whose lifecycle is consumed at end of
  genesis flow. The currency-creation flow returns `(MintCap,
  BurnCap, Supply)`. Uses `bloom-resource-macros`.

- **`bloom-petal-cap`** — `/bloom/core/cap`. Generic capability
  primitives (transferable, lockable, scoped-by-expiry, optional
  revocation bit per spec §18 capability-revocation resolution).

- **Activate `TxKind::SubmitPtb`** in `bloom-chain-node` /
  `bloom-petals`: wire Phase 1's `bloom-script` executor into the
  chain VM. Activate the new host imports. The PTB validator runs
  before any wasm executes. The gas-payer model per spec §9.4 is
  fully active.

- **Genesis LOOM allocation** (spec §9.3): at chain bootstrap, mint
  one `Coin<LOOM>` per allocated address via
  `fungible::mint_genesis`, set `Owner::Address(holder)`, write
  `accounts[holder].loom = amount`. Consume the `EpochZero`
  capability at end of genesis.

- **`Account.loom` denormalized cache + end-of-block invariant** per
  spec §9.2: every PTB that creates / splits / merges / transfers /
  destroys a `Coin<LOOM>` owned by an `Owner::Address(addr)` updates
  `accounts[addr].loom` in lockstep inside the same command's
  diff-check. At end-of-block in tests, run the full reconciliation
  invariant; in steady state, sample.

- **Legacy `TxKind::Transfer` / `TxKind::Call` compat shim** per
  spec §9.5: the chain translates these into synthetic PTBs using the
  `select_coin(addr, T, min_amount)` deterministic chain helper
  (largest-coin-first, ObjectId tiebreak, merge-large-coins fallback).

- **First integration test** under a new crate `crates/bloom-petal-it`
  (NOT under `examples/dex/tests/bloom-dex-it/`):
  1. Spin up a single-node chain.
  2. Submit a PTB that creates a currency `Coin<TestToken>`.
  3. Submit a PTB that mints 1000, splits into two coins, transfers
     one to Bob, merges Bob's other holdings, burns 100.
  4. Assert resulting object-store state matches expected.
  5. Submit a PTB that violates linearity (orphan object) — assert revert
     with `LinearityViolation`.
  6. Submit a PTB missing the required `&MintCap` — assert revert.
  7. Run a `TxKind::Transfer` and an equivalent `Coin<LOOM>` PTB;
     assert identical state roots (spec §19 item 5).

## Phase 3 — DEX rewrite

After Phase 2 lands and the new integration test is green:

- **`bloom-dex-math`** — workspace crate (NOT a petal). Defines the
  `SwapStrategy` trait and pure math (`quote`, `apply_swap`,
  `add_liquidity`, `remove_liquidity`, `k`). Implements `ConstantProduct`
  (CPMM) in this crate so multiple petals can link it at compile time
  per spec §14.1.

- **`bloom-petal-dex-pool`** — `/bloom/dex/pool` per spec §14.2.
  `Pool<phantom A, phantom B, phantom S: SwapStrategy>` with
  `reserve_a`, `reserve_b`, `lp_supply`, `params: S::Params`,
  `k_last`. `LpPosition<phantom A, phantom B>`.
  Functions: `new`, `swap_a_for_b`, `swap_b_for_a`, `add_liquidity`,
  `remove_liquidity`. Function-attached `reserve_product_non_decreasing`
  invariant per spec §12.1 (using `S::k(p) >= p.k_last`).
  Links `bloom-dex-math` at compile time.

- **`bloom-petal-dex-cpmm`** — `/bloom/dex/strategy/cpmm`. Wraps the
  shared `bloom-dex-math::ConstantProduct` impl as the wire-visible
  strategy marker type, so PTB type_args can reference
  `TypeTag::ConstantProduct`. Tests assert the type_args round-trip
  through the codec.

- **`bloom-petal-dex-router`** — `/bloom/dex/router` per spec §14.3.
  Functions: `quote_1hop`, `swap_1hop`, `quote_2hop`, `swap_2hop`,
  `quote_3hop`, `swap_3hop`. Each takes fixed-arity tuples of
  `&mut Pool<...>` references with linear-typed coin threading;
  intermediate min_outs are zero, outer min_out is the user's
  slippage bound. Function-attached `all_pools_k_non_decreasing`
  invariant for multi-hop swaps. Links `bloom-dex-math` at compile
  time; NO `petal.call` host import.

- **Integration tests under `crates/bloom-petal-dex-it`** (a new
  crate, NOT replacing `examples/dex/tests/bloom-dex-it/`):
  1. Single-node: create CPMM pool, add liquidity, swap, remove,
     assert k non-decreasing across many swaps.
  2. Single-node: 2-hop swap A→B→C via the router; assert
     all_pools_k_non_decreasing holds; assert atomicity (if step 2
     reverts, step 1 rolls back per spec §19 item 11).
  3. Single-node: capability auth — mint without `&MintCap` reverts;
     transfer a `MintCap`, new holder mints, old holder cannot.
  4. Single-node: invariant violation — synthetically craft a pool
     state that would break `reserve_product_non_decreasing`, assert
     revert with `InvariantViolation { ... }`.

- **Multi-validator docker e2e** under `crates/bloom-petal-dex-it`
  (filename `docker_dex_new_framework.rs`), mirroring the structure
  of the existing `docker_dex_multi_user.rs` but driving the new
  framework:
  - Spin up four validators.
  - Alice creates `TestUSDC` currency.
  - Bob creates `Pool<TestUSDC, LOOM, ConstantProduct>` and seeds
    liquidity.
  - Carol executes a `router::swap_1hop` PTB.
  - All four validators agree on the resulting state root.
  - Assert `Account.loom` cache invariants per spec §19 item 4.
  - Assert no wallet-side multi-hop logic exists: the test driver
    submits only PTBs that reference `/bloom/dex/router`; no
    CLI/wallet code constructs a swap chain locally.

## Phase 4 bookkeeping (deprecation flags)

After Phase 3 is fully green:

- Mark with `#[deprecated(since = "...", note = "use bloom-resource
  framework — see docs/specs/2026-05-20-bloom-native-contracts-design.md")]`:
  - `crates/bloom-contract` (top-level re-exports)
  - `crates/bloom-contract-macros` (the entry-point attribute macros)
  - `examples/dex/contracts/*` and `examples/wloom`
  Do NOT remove anything. Do NOT change their behaviour. Just attach
  the deprecation attribute on the public surface.
- Update top-level `README.md` (if any) and any "getting started"
  docs to point new contracts at the new framework.

## What you MUST NOT do

- Do NOT modify `crates/bloom-contract*` runtime behaviour. The old
  framework remains operational; only the top-level deprecation
  attributes get added in Phase 4 bookkeeping.
- Do NOT modify `examples/dex/*` or `examples/wloom` semantics. The
  existing docker DEX test must continue passing throughout.
- Do NOT change `crates/bloom-chain-abi` semantics. You may add new
  encoder/decoder helpers (specifically for PTB / TypeTag /
  manifest), but the canonical encoding rules in chain spec §7.10
  are frozen.
- Do NOT remove or rename existing host imports. The new ones are
  added alongside.
- Do NOT touch the consensus engine (`bloom-chain-consensus`) beyond
  what's strictly required by the new `state_root` payload extension.
- Do NOT implement Phase 5 (old-framework removal). That is a
  separate decision after soak.
- Do NOT implement v1+ items from spec §2 / §18.1: parallel PTB
  scheduling, resolution policies, zkVM proofs, concentrated
  liquidity, cross-chain bridging.
- Do NOT implement `petal.call` host import. Multi-petal composition
  in v0 is via PTB-level chaining and compile-time math linking.
- Do NOT add a third on-chain trie kind for type-indexing. Type
  queries are off-chain (spec §16.3).

## Working method

- Use `superpowers:test-driven-development` per crate. Every new
  module gets unit tests written first or alongside, not bolted on
  at the end.
- Use `superpowers:subagent-driven-development` for the parallel
  streams identified above. Brief each sub-agent with the relevant
  spec section, the API contract it shares with siblings, and the
  test signatures it must produce.
- After each phase completes, run `cargo test --workspace`, then
  `scripts/test-docker-dex.sh` (the legacy docker test), and confirm
  green BEFORE starting the next phase. If either is red, stop and
  fix the root cause.
- Use `superpowers:systematic-debugging` for unexpected failures.
  Do not work around symptoms.
- Commit per-crate or per-logical-unit. Don't bundle the whole
  framework into one mega-commit.
- After each phase merges, invoke `superpowers:code-reviewer` with
  the spec section as context and apply the review's fixes before
  starting the next phase.
- Track in-flight work with `TaskCreate` so progress is visible.

## Definition of done

Every item below must hold before declaring the goal complete.

Phase 1:
- All Phase 1 crates compile, pass clippy, pass their own unit tests.
- New `TrieKind` variants commit to expected hashes on known fixtures.
- Manifest custom section round-trip is byte-identical (spec §19 #12).
- `petals.lock` resolution passes (presence) / fails closed (absence)
  per spec §19 #13.

Phase 2:
- Fungible + cap petals compile and pass unit tests.
- The chain accepts `TxKind::SubmitPtb` and executes per the
  validation pipeline (spec §7.2).
- Genesis emits one `Coin<LOOM>` per allocated address;
  `EpochZero` is consumed.
- `Account.loom == sum(Coin<LOOM> owned by addr)` end-of-block
  invariant holds in tests (spec §19 #4).
- Legacy `TxKind::Transfer` and an equivalent PTB produce identical
  state roots (spec §19 #5).
- `crates/bloom-petal-it` integration test passes.

Phase 3:
- DEX petals + bloom-dex-math compile and pass unit tests.
- `Pool<USDC, LOOM, ConstantProduct>` create / add / swap / remove
  works; `k` is non-decreasing across many swaps (spec §19 #6).
- Router `swap_2hop` passes the `all_pools_k_non_decreasing`
  invariant on a U→A→B chain (spec §19 #7).
- The new multi-validator docker test
  (`docker_dex_new_framework.rs`) is green; all four validators
  agree on state root (spec §19 #10).
- Wallet-enshrinement audit passes: the new test driver constructs
  no multi-hop math locally (spec §19 #8).
- Atomicity test: a PTB whose second swap reverts rolls back the
  first swap (spec §19 #11).

Phase 4 bookkeeping:
- Deprecation attributes attached as listed above.
- Legacy `bloom-contract*` workspace tests still pass.
- Legacy `scripts/test-docker-dex.sh` still passes.

Cross-cutting:
- `cargo test --workspace` is green.
- `cargo clippy --workspace --all-targets -- -D warnings` is green.
- Grep audit: zero `msg.sender` / `msg::sender` in new-framework
  crates (spec §19 #14).
- Grep audit: zero `U256` / `u256` in new-framework crates except
  where explicitly bridging legacy types (spec §19 #15).
- Determinism: same PTB sequence on same initial state produces
  same state root on two independent runs (spec §19 #16).
- A final report in your last message describing:
  * Per-phase: what landed, file paths, test outputs.
  * Every TODO / ambiguity flag you placed and why.
  * Any spec sections you found genuinely silent and the choice you
    made.
  * The exact `git log --oneline` range of commits produced.
  * What's queued for the next /goal (Phase 5 — old-framework removal
    decision).

Spec is the source of truth. When in doubt, re-read the relevant
spec section. When the spec is genuinely silent, prefer simplicity
and bloom-paper alignment (linear, content-addressed, capability-based,
no EVM idioms), and flag the choice in the final report.

DO NOT STOP until every item above is satisfied or you have a
precisely-described, root-caused obstacle that requires user
direction. Partial progress without a clear obstacle is not
acceptable.
```

---

## Notes for future iterations

- **Phase 5** — Removal of the old framework. Separate decision after
  a soak period on Phases 1–4. Not part of this prompt.
- If Phase 3 takes too long, split off the multi-validator docker test
  into its own follow-up /goal — but keep the unit-test acceptance
  criteria in this run.
