# Bloom Rust Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote Bloom's smart-contract surface from the hand-rolled `bloom_chain_abi::contract!` DSL to an Anchor/Solana-style Rust framework (`#[bloom::contract]`, derives, explicit storage loading, typed interfaces, manifest emission, optional on-chain anchor) — while preserving byte-for-byte compatibility with the existing DEX example selectors, storage slots, and event topics.

**Architecture:** Add four new workspace crates (`bloom-contract`, `bloom-contract-macros`, `bloom-contract-metadata`, `bloom-contract-build`) that layer on top of the existing `bloom-chain-abi` codec. The new attribute macros generate the same wasm-side artifacts the legacy `contract!` macro does (init/call exports, dispatcher, selector table, storage accessors, event emitters, reentrancy lock) but with richer types (ABI derives), explicit storage loading (`State::load(ctx)`), typed `Result<T, E>` returns, and a metadata schema that backs both `bloom contract build` (manifest emission) and an on-chain manifest anchor stored alongside `code_hash` in state. The legacy `contract!` macro stays in place as a compatibility surface and is removed only after every example migrates.

**Tech Stack:** Rust 2024, `wasm32-unknown-unknown`, `wasmtime 26`, `blake3`, `serde` for manifest JSON, `clap` for CLI subcommands.

---

## Spec Source

All architectural decisions trace to `docs/specs/2026-05-20-bloom-rust-contracts.md`. Open Questions resolved in that doc:

- **Q1** Dynamic ABI values: self-describing schema (length-prefixed + type-tag header).
- **Q2** Event topics: 32-byte topics under metadata version 2 for new contracts; legacy 4-byte-padded topics under metadata version 1 stay decodable. Default for migrations is v1 (parity); switching to v2 is opt-in per `#[event(version = 2)]`.
- **Q3** Floating point: disallowed by `bloom contract build` lint (deterministic profile). Wasm module validation rejects any `f32`/`f64` opcodes.
- **Q4** Source/manifest verification: minimal on-chain anchor in v1 (`code_hash → manifest_hash`); off-chain tooling does full source/manifest verification.
- **Q5** Storage loading: explicit, Solana-account-style. `State::load(ctx)` returns a typed handle; fields are `Map<K, V>`, `StorageValue<T>`, etc. with explicit `load()`/`save()` semantics.

## File Structure

### New crates

```
crates/bloom-contract/
  Cargo.toml
  src/
    lib.rs               — re-exports + prelude
    prelude.rs           — Address, Hash32, U256, Map, Result, Context, contract attrs
    types.rs             — Address, Hash32, U256 re-exports + StringN/BytesN bounded types
    abi.rs               — AbiEncode/AbiDecode/AbiType traits + impls
    storage.rs           — StorageValue trait, Map<K,V>, VecStore<T>, slot derivation
    context.rs           — Context struct, ctx.sender()/ctx.value()/ctx.call/ctx.deploy
    interface.rs         — ContractRef<I>, InterfaceCall trait
    error.rs             — Error trait, ContractError encoding
    panic.rs             — Bloom-flavoured panic→revert handler

crates/bloom-contract-macros/
  Cargo.toml
  src/
    lib.rs               — proc-macro entry points
    contract.rs          — #[bloom::contract] attribute on `mod`
    storage_attr.rs      — #[storage] struct → StorageLayout
    event_attr.rs        — #[event] struct → AbiEncode + topic
    error_attr.rs        — #[error] enum → ErrorEncode + selectors
    init_attr.rs         — #[init] fn → init export
    interface_attr.rs    — #[bloom::interface] trait → ContractRef
    derives.rs           — #[derive(AbiEncode/AbiDecode/AbiType)] (struct + enum)
    abi_type.rs          — TypeSchema generation
    util.rs              — shared helpers (selector hashing, snake/camel case)

crates/bloom-contract-metadata/
  Cargo.toml
  src/
    lib.rs               — manifest schema versions
    manifest.rs          — Manifest struct (serde), schema_version, contract block
    schema.rs            — TypeSchema, AbiSchema, StorageSchema, EventSchema, ErrorSchema
    imports.rs           — host-import allowlist
    limits.rs            — max_memory_pages, max_wasm_bytes constants

crates/bloom-contract-build/
  Cargo.toml
  src/
    lib.rs               — public build API
    builder.rs           — orchestrates cargo build, wasm post-processing
    validator.rs         — PetalVm::validate_for_chain wrapper, floating-point reject
    optimizer.rs         — optional wasm-opt-style pass
    manifest_writer.rs   — emits manifest JSON next to .wasm
    verifier.rs          — verify a deployed wasm matches a published manifest
```

### Touched crates

- `crates/bloom-chain-abi` — extend with `AbiEncode/AbiDecode/AbiType` blanket impls so the low-level codec serves both `contract!` and `#[bloom::contract]`. Add length-prefixed dynamic ABI helpers (string, bytes, vec generic). No breaking changes to existing call sites.
- `crates/bloom-chain-abi-macros` — leave alone (legacy `contract!`). Phase D would delete it after every example migrates; spec lets us keep it as a compat layer.
- `crates/bloom-chain-state` — add `manifest_hash: Option<Hash32>` field to `Account` (sibling of `code_hash`), plus a serialized-state migration.
- `crates/bloom-chain-types/src/tx.rs` — extend `TxKind::Deploy` with optional `manifest_hash` field (encoded with a version byte so older blocks decode unchanged).
- `crates/bloom-chain-node/src/petal_executor.rs` — propagate `manifest_hash` from `Deploy` tx into the snapshot's `Account.manifest_hash`.
- `crates/bloom-petals/src/chain_vm.rs` — new host import `chain.code.manifest_hash(addr_ptr, out_ptr)` that reads the manifest_hash for any address.
- `crates/bloom-petal-sdk` — wrapper `code::manifest_hash(&Address) -> Option<Hash32>`.
- `crates/bloom/src/commands/contract.rs` — new `bloom contract build|verify` subcommand.
- `examples/dex/crates/bloom-dex-{erc20,factory,pair,router}` and `examples/wloom` — migrate from `contract!` to `#[bloom::contract]`.
- `examples/dex/tests/bloom-dex-it/*` — assertions stay valid; selectors/slots/topics unchanged.

## Compatibility Invariants

These invariants are the spec's acceptance bar; every phase must keep them green.

- Method selectors derived from `blake3("<domain>.<method>(<types>)")[..4]` — unchanged.
- Storage slots derived from `blake3("<domain>.<field>")` (scalar) / `blake3("<tag>" || encoded_key)` (mapping) — unchanged for migrated examples.
- Event topic-0 prefix `blake3("<EventName>(<types>)")[..4]` — unchanged under metadata version 1.
- Reentrancy lock slot `blake3("__macro.nonreentrant.<domain>")` — unchanged.
- Wasm module imports limited to `"chain"` namespace; bloom-petals chain_vm validation rules unchanged.

## Phase-by-Phase Plan

Each phase ends in a green `cargo test --workspace` and a commit. Phases 7a-e migrate examples one at a time so the DEX integration tests cap each migration's blast radius.

---

### Phase 1: Foundation crates scaffold

**Files:**
- Create: `crates/bloom-contract/Cargo.toml`, `crates/bloom-contract/src/lib.rs`, `crates/bloom-contract/src/prelude.rs`, `crates/bloom-contract/src/types.rs`, `crates/bloom-contract/src/abi.rs`, `crates/bloom-contract/src/storage.rs`, `crates/bloom-contract/src/context.rs`, `crates/bloom-contract/src/interface.rs`, `crates/bloom-contract/src/error.rs`, `crates/bloom-contract/src/panic.rs`
- Create: `crates/bloom-contract-macros/{Cargo.toml,src/lib.rs}` (stub proc-macro entry points only)
- Create: `crates/bloom-contract-metadata/{Cargo.toml,src/lib.rs}` (stub with placeholder schema)
- Create: `crates/bloom-contract-build/{Cargo.toml,src/lib.rs}` (stub)
- Modify: `Cargo.toml` (workspace members + workspace-deps entries)

- [ ] Write skeleton `lib.rs` for each crate that re-exports the canonical low-level types (`U256`, `Address` newtype around `[u8;32]`, `Hash32`).
- [ ] `bloom-contract::prelude` re-exports `Address, Hash32, U256, Result, Context, Map, VecStore, AbiEncode, AbiDecode, AbiType, contract, storage, event, error, init, interface, view, payable, nonreentrant, internal`.
- [ ] Add four workspace members + four workspace-deps lines to root `Cargo.toml`.
- [ ] `cargo build -p bloom-contract -p bloom-contract-macros -p bloom-contract-metadata -p bloom-contract-build` passes.
- [ ] Run: `cargo test --workspace -- --skip docker` (Docker tests are integration-only and skipped during the framework build phase).

  Expected: PASS — no examples migrated yet, everything compiles untouched.

- [ ] **Commit** as `feat(contract): scaffold bloom-contract framework crates`.

---

### Phase 2: AbiEncode/AbiDecode/AbiType + self-describing schema

The new framework's runtime ABI surface. Built so the legacy `bloom-chain-abi::Encoder`/`Buf` keeps emitting/parsing fixed-width primitives, and the new derives sit on top with length-prefixed dynamic shapes (strings, vecs, structs) plus a versioned self-describing schema header.

**Files:**
- Modify: `crates/bloom-chain-abi/src/lib.rs` — add `pub use bloom_contract_abi::*;`-style re-exports
- Create: `crates/bloom-chain-abi/src/dyn_codec.rs` — dynamic codec: length-prefixed string/bytes/vec
- Create: `crates/bloom-contract/src/abi.rs` — `AbiEncode`, `AbiDecode`, `AbiType` traits + impls for primitives, tuples, arrays, `Option<T>`, `Result<T, E>`
- Create: `crates/bloom-contract-macros/src/derives.rs` — `#[derive(AbiEncode, AbiDecode, AbiType)]` proc macros
- Create: `crates/bloom-contract-metadata/src/schema.rs` — `TypeSchema` enum (Scalar/Tuple/Struct/Enum/Array/Vec/Map/Option/Result/Address/Hash32/U256/String/Bytes/BoundedString/BoundedBytes/Custom), plus serde Serialize.
- Tests: per-trait roundtrip tests + a `schema_is_stable` test that pins `TypeSchema` serialization for the core primitives.

- [ ] Add `AbiType` trait with `const ABI_TYPE: &'static str` and `fn schema() -> TypeSchema` for compile-time + runtime metadata.
- [ ] Add `AbiEncode`/`AbiDecode` traits in `bloom-contract::abi` with blanket impls in terms of `Encoder`/`Buf` for the existing primitives so the legacy `contract!`-emitted code keeps working unchanged.
- [ ] Implement `#[derive(AbiEncode, AbiDecode, AbiType)]` for structs (sequential field encoding), C-like enums (single-byte discriminant), and payload enums (discriminant + variant fields). Add a `#[abi(transparent)]` attribute for newtype wrappers.
- [ ] Add dynamic encoding helpers in `bloom-chain-abi::dyn_codec`: `push_string` (u16 length + utf-8 bytes), `push_bytes_var` (u16 length + bytes), `push_vec<T: AbiEncode>` (u16 length + T-encodings), all matched by symmetric `read_*` helpers. Length prefix is u16 — overflow returns `AbiEncodeError::TooLong`.
- [ ] Add `StringN<const N: usize>` and `BytesN<const N: usize>` bounded types with `AbiType` impls that report the max length in the schema.
- [ ] Add tuple impls for arities 0..=12.
- [ ] Add `(T0, T1, T2)` multi-return encoding (sequential concatenation, no header) used by router phases.
- [ ] Add a `SchemaVersion = 1` constant + `Manifest::abi_version` field, so future header-prefixed encoding (v2) is forward-extensible.
- [ ] Test every impl with a round-trip + a `TypeSchema::serialize` golden assertion.

- [ ] **Commit** as `feat(contract): AbiEncode/Decode/Type traits + derives + dynamic codec`.

---

### Phase 3: Storage derives + explicit-loading model

The spec's Q5 answer is "explicit storage loading" — Solana-style. Each contract declares one `#[storage] pub struct State { ... }` and accesses everything via `let mut state = State::load(ctx)?;`. `Map<K, V>` and `VecStore<T>` are zero-sized descriptor handles tied to a `Slot` derived from the field name.

**Files:**
- Create: `crates/bloom-contract/src/storage.rs` — `Slot` newtype, `StorageValue<T>` trait, `Map<K, V>`, `VecStore<T>`, `slot_for_field` helper using `blake3("storage:<domain>:<field>")`
- Create: `crates/bloom-contract-macros/src/storage_attr.rs` — `#[storage]` macro
- Create: `crates/bloom-contract-metadata/src/schema.rs` (extend) — `StorageSchema`, `FieldSchema`
- Tests: parity tests asserting slot equality for ERC-20 / pair / factory tags via a `#[storage(compat = "...")]` attribute that opts into the legacy slot derivation rule.

- [ ] Define `Slot = [u8; 32]`. `slot_for_field(domain, field)` derives `blake3("storage:" || domain || ":" || field)` (new derivation rule; matches Anchor's `[seeds]` style).
- [ ] Add `#[storage(compat_tag = "erc20.balance:")]` field attribute to opt fields into the legacy slot rule (`blake3(tag || key)` for mappings, `blake3(tag)` for scalars). Migrations use it to preserve byte parity.
- [ ] `Map<K, V>`: zero-sized, methods `get(&self, ctx, k: K) -> Result<V>` and `set(&mut self, ctx, k: K, v: V)`. Key encoding via `AbiEncode`.
- [ ] `VecStore<T>`: zero-sized, length stored at `slot`, items at `blake3(slot || u64_be(index))`. Methods `len(&self, ctx)`, `get(&self, ctx, i)`, `push(&mut self, ctx, v)`.
- [ ] `StorageValue<T>` for typed scalar slots: `load(ctx) -> Result<T>`, `store(&mut self, ctx, v) -> Result<()>`. Implemented via `AbiEncode`/`AbiDecode`.
- [ ] `#[storage]` macro: expands to a public struct with field-wise zero-sized `Map<...>` / `StorageValue<T>` / `VecStore<T>` members, a `load(ctx) -> Result<Self>` constructor, and a `StorageSchema` constant. Per-field `#[storage(compat_tag = "...")]` attribute generates the legacy slot derivation for that field.
- [ ] Add a `#[storage(domain = "...")]` struct-level attribute that pins the slot-derivation contract domain (defaults to the enclosing `mod` name).
- [ ] Tests: scalar load/store round-trip via an in-memory `MockHost`, parity asserts that match the legacy `erc20.balance:` / `factory.pair:` / `pair.k_last` slot bytes when `compat_tag` is set.

- [ ] **Commit** as `feat(contract): #[storage] derive + Map/VecStore + explicit State::load`.

---

### Phase 4: `#[bloom::contract]` attribute macro + Context + revert encoding

The headline feature. The attribute macro wraps a `mod` containing the `#[storage]` struct, `#[init]` fn, `#[event]` structs, `#[error]` enum, and ordinary handler functions. It generates the `init` and `call` wasm exports, the selector table, the dispatcher, return encoding, reentrancy lock setup+cleanup (auto-cleared at function exit even on `Result::Err`), and the metadata constants.

**Files:**
- Create: `crates/bloom-contract-macros/src/contract.rs` — top-level `#[bloom::contract]` attribute
- Create: `crates/bloom-contract-macros/src/event_attr.rs` — `#[event]`
- Create: `crates/bloom-contract-macros/src/error_attr.rs` — `#[error]`
- Create: `crates/bloom-contract-macros/src/init_attr.rs` — `#[init]`
- Create: `crates/bloom-contract/src/context.rs` — `Context` with `sender`, `value`, `block_number`, `block_timestamp`, `call<C: ContractInterface>`, `deploy<C: ContractInterface>`, helpers for emitting events / reading storage.
- Create: `crates/bloom-contract/src/error.rs` — `Error` trait, `ContractError` enum, automatic `Result<T, E>` → revert-bytes encoding (4-byte selector + payload).

- [ ] `Context` is zero-sized; methods call into `bloom-petal-sdk` (`msg`, `block`, `state`, `petal`, `log`). On wasm32 these compile away; off-target they panic.
- [ ] `#[event] struct EventName { #[indexed] pub from: Address, ... }` derives `AbiEncode` + a `topic0() -> [u8; 32]` (or `[u8; 4]` under v1) constant + `emit(ctx, &self)` method.
- [ ] `#[error] pub enum Error { InsufficientBalance, Overflow(U256), ... }` derives selectors `blake3("Error::Variant(<types>)")[..4]` and `encode_revert(&self) -> Vec<u8>` (selector + payload).
- [ ] `#[init] pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()>` produces a `pub extern "C" fn init` wasm export that decodes `cfg: InitConfig` (any `AbiDecode`) from calldata, calls the user fn, and on `Err(e)` calls `petal.revert(e.encode_revert())`.
- [ ] `#[bloom::contract] mod my { ... }` expands to: selector table over methods; dispatcher pattern-match calling each handler; for `#[nonreentrant]` methods, lock acquire on entry + lock clear at any exit path via `core::panic::catch_unwind`-free RAII guard struct; for `#[internal]` methods, caller equality check against `ctx.contract_address()` or a declared authorized list; for `#[view]` no `&mut Context` mutability; for `#[payable]` allow `ctx.value() > 0`; non-payable methods revert on `value > 0`.
- [ ] Generate `pub mod __manifest { pub const ABI_JSON: &str = "..."; }` so the build tool can lift a manifest out of any wasm by reading a known data segment.
- [ ] `Result<T, E>` returns automatically encode `Ok(T)` via `AbiEncode` and `Err(E)` via the error selector + payload. Macro consumes whatever the user fn signature returns; failure path goes through `petal.revert`.
- [ ] Tests: A `tests/erc20_smoke.rs` integration test in the macro crate compiles a stub ERC-20 contract (host-mode, not wasm32) and verifies the dispatch table, selectors, and error encoding.

- [ ] **Commit** as `feat(contract): #[bloom::contract] attribute + Context + typed errors`.

---

### Phase 5: `#[bloom::interface]` traits + `ContractRef<I>`

Lets contracts expose multiple ABI domains (e.g. WLOOM has `wloom.*` plus `erc20.*` selectors) without hand-rolling selector dispatch. Lets cross-contract calls be typed: `let bal = Erc20::balance_of(ctx, token_addr, owner)?;` builds calldata, calls `ctx.petal_call`, decodes the return.

**Files:**
- Create: `crates/bloom-contract-macros/src/interface_attr.rs`
- Create: `crates/bloom-contract/src/interface.rs` — `ContractInterface`, `ContractRef<I>`, blanket `Erc20Ref`/`Erc20RefExt`-style helper.

- [ ] `#[bloom::interface(domain = "erc20")] pub trait Erc20 { fn balance_of(owner: Address) -> Result<U256>; ... }` emits: `Erc20::SEL_BALANCE_OF` const; `Erc20::balance_of_calldata(owner: Address) -> Vec<u8>` builder; `Erc20Ref` newtype wrapping `Address` with `fn balance_of(self, ctx) -> Result<U256>` methods.
- [ ] An attribute `#[interface(Erc20)]` placed on a `#[bloom::contract]` module declares that the contract implements the `Erc20` interface — the macro then adds the `erc20.*` selectors to the dispatcher and routes each to a handler with the matching name.
- [ ] Compile-time check: implementing handlers must match the interface signature.
- [ ] Tests: a contract module that implements `Erc20` + a custom `Foo` interface; assert both dispatchers route the right selectors, and assert `Erc20Ref::transfer` produces the same calldata as `contract::Foo::abi::call::transfer` in the legacy DEX.

- [ ] **Commit** as `feat(contract): #[bloom::interface] traits + ContractRef`.

---

### Phase 6: `bloom contract build|verify` + manifest emission

The CLI subcommand that compiles a contract crate to chain-valid wasm and emits the manifest JSON. Lives inside the existing `bloom` binary so the user doesn't need a separate cargo subcommand install.

**Files:**
- Create: `crates/bloom/src/commands/contract.rs` — `Build`, `Verify` subcommands.
- Create: `crates/bloom-contract-build/src/builder.rs` — `Builder::build(spec) -> ArtifactSet { wasm: Vec<u8>, manifest: Manifest, source_hash: Hash32 }`
- Create: `crates/bloom-contract-build/src/manifest_writer.rs` — emits `{contract}.wasm` + `{contract}.manifest.json`
- Create: `crates/bloom-contract-build/src/verifier.rs` — given a wasm + manifest, asserts wasm_hash + manifest internal consistency
- Modify: `crates/bloom/src/main.rs` — wire in the new subcommand
- Tests: golden test that builds the migrated ERC-20 example end-to-end and pins manifest JSON.

- [ ] Shell out to `cargo build -p <crate> --release --target wasm32-unknown-unknown` with a pinned toolchain (the workspace already uses `rust-toolchain.toml`).
- [ ] Locate output wasm in `target/wasm32-unknown-unknown/release/<crate>.wasm`.
- [ ] Run `bloom_petals::PetalVm::validate_for_chain(&wasm)`; reject on error.
- [ ] Walk module imports, reject anything not under `"chain"` (already enforced by `validate_for_chain`, but recapture for manifest emission).
- [ ] Walk module types/exports, reject any `f32`/`f64` opcodes (deterministic profile Q3) — implement via `wasmparser::Validator`-driven walk over function bodies, scanning instructions for `F32*`/`F64*` ops.
- [ ] Enforce limits from the spec: `max_memory_pages = 256`, `max_wasm_bytes = 262144` (configurable via a `[package.metadata.bloom-contract] limits = { ... }` block).
- [ ] Locate the embedded manifest data segment (Phase 4 wrote it as a static `pub const ABI_JSON: &str`), parse it, and merge with build-time computed `wasm_hash` (blake3) and `source_hash` (blake3 over the contract's `src/**/*.rs`).
- [ ] Emit alongside the .wasm a `<crate>.manifest.json` matching the schema in spec §10.
- [ ] `bloom contract verify <wasm> <manifest>` asserts wasm_hash equality and re-parses imports/limits.
- [ ] Test: build & verify the migrated ERC-20 in a `tempfile::TempDir`-rooted cargo workspace; assert manifest fields match expected.

- [ ] **Commit** as `feat(contract): bloom contract build/verify + manifest schema v1`.

---

### Phase 7a: Migrate ERC-20

Rewrite `examples/dex/crates/bloom-dex-erc20/src/lib.rs` to use `#[bloom::contract]`. Use `#[storage(compat_tag = "erc20.balance:")]` style attributes so the slot bytes match the legacy contract bit-for-bit.

**Files:**
- Modify: `examples/dex/crates/bloom-dex-erc20/src/lib.rs` (full rewrite)
- Modify: `examples/dex/crates/bloom-dex-erc20/Cargo.toml` (depend on `bloom-contract`, drop `bloom-chain-abi`+`bloom-chain-abi-macros` direct deps)
- Keep: existing host-side tests intact — they assert selector / slot / event parity; they should keep passing unchanged because the macro maps `compat_tag` to the same slot bytes.

- [ ] Convert `contract! { contract Erc20 { ... } }` to `#[bloom::contract] mod erc20 { use bloom_contract::prelude::*; #[storage] struct State { ... }; #[event] struct Transfer { ... }; #[error] enum Error { ... }; #[init] fn init(ctx, cfg: InitConfig) -> Result<()> { ... }; pub fn transfer(...) -> Result<bool, Error> { ... } }`.
- [ ] Use `InitConfig` derived from `#[derive(AbiDecode)]` so the hand-rolled `parse_length_prefixed` / `str_to_bytes32` helpers disappear in favour of bounded `StringN<32>` fields.
- [ ] Replace the special-cased `decimals()` runtime selector (legacy comment: "macro can't model u8 return") — the new ABI derives model `u8` natively.
- [ ] Run `cargo test -p bloom-dex-erc20`. Selector parity, storage slot parity, init-payload, all tests pass.
- [ ] Run the DEX integration test that exercises only ERC-20 routes — should still pass.

- [ ] **Commit** as `feat(dex): migrate ERC-20 to #[bloom::contract]`.

---

### Phase 7b: Migrate WLOOM

WLOOM exposes BOTH `wloom.deposit/withdraw` and the full `erc20.*` surface. Currently the latter is hand-dispatched. With Phase 5 the contract can declare `#[interface(Erc20)]` and the dispatcher picks up both domains automatically.

**Files:**
- Modify: `examples/wloom/src/lib.rs` (full rewrite)
- Modify: `examples/wloom/Cargo.toml`
- Keep: existing tests intact.

- [ ] Declare `#[bloom::contract] mod wloom { ... }` with `#[interface(Erc20)]` so the macro emits `erc20.*` selectors alongside `wloom.deposit/withdraw`. The hand-rolled selector-cascade in `do_call` disappears.
- [ ] Implement the `Erc20` trait methods inside the module — the macro routes `erc20.balance_of` to `Erc20::balance_of`, etc.
- [ ] Run `cargo test -p bloom-dex-wloom`. Tests stay green.

- [ ] **Commit** as `feat(dex): migrate WLOOM to #[bloom::contract] + #[interface(Erc20)]`.

---

### Phase 7c: Migrate factory

The factory has one peculiar case — `Mapping<u64, V>` for `all_pairs_at`, which the legacy macro didn't support. Phase 3's `Map<u64, V>` does support arbitrary `AbiEncode` keys, so the hand-rolled `all_pairs_at_slot` helper goes away.

**Files:**
- Modify: `examples/dex/crates/bloom-dex-factory/src/lib.rs`
- Modify: `examples/dex/crates/bloom-dex-factory/Cargo.toml`

- [ ] Replace `slot_mapping("factory.all_pairs:", &i.to_be_bytes())` with `state.all_pairs_at.get(&mut ctx, i)?` — under `#[storage(compat_tag = "factory.all_pairs:")]` the slot bytes are identical.
- [ ] Wire `Address`, `Hash32` to the new types module.
- [ ] Run `cargo test -p bloom-dex-factory`. Tests stay green.

- [ ] **Commit** as `feat(dex): migrate factory to #[bloom::contract]`.

---

### Phase 7d: Migrate pair

The pair is the macro's hardest stress test: nonreentrant, ERC-20 surface inlined, multiple events, multi-return.

**Files:**
- Modify: `examples/dex/crates/bloom-dex-pair/src/lib.rs`
- Modify: `examples/dex/crates/bloom-dex-pair/Cargo.toml`

- [ ] `#[bloom::contract] mod pair { #[interface(Erc20)] ... #[nonreentrant] pub fn mint(...) -> Result<U256, Error> { ... } }`. With Phase 4's auto-clearing lock guard the hand-rolled `pair::abi::nonreentrant_lock_clear()` calls before divergent returns disappear.
- [ ] `get_reserves()` becomes `pub fn get_reserves(ctx) -> Result<(u128, u128, u64), Error>` — tuple return via Phase 2 multi-return derives.
- [ ] Run `cargo test -p bloom-dex-pair`. All tests stay green.

- [ ] **Commit** as `feat(dex): migrate pair to #[bloom::contract] + auto-cleared #[nonreentrant]`.

---

### Phase 7e: Migrate router

Router exercises `Vec<U256>` returns and (U256, U256, U256) multi-returns. Spec acceptance: "A new router method can return `(U256, U256, U256)` without manual `petal::return_data`."

**Files:**
- Modify: `examples/dex/crates/bloom-dex-router/src/lib.rs`
- Modify: `examples/dex/crates/bloom-dex-router/Cargo.toml`

- [ ] Convert `add_liquidity` etc. to `pub fn add_liquidity(ctx, ...) -> Result<(U256, U256, U256), Error>`. The macro picks up tuple-return encoding from Phase 2.
- [ ] Convert `get_amounts_out` etc. to `pub fn get_amounts_out(ctx, amount_in: U256, path: Vec<Address>) -> Result<Vec<U256>, Error>`. `Vec<T>` ABI encoding from Phase 2.
- [ ] Use `Erc20Ref::from(token_addr).balance_of(ctx)?` for cross-contract calls — typed, no hand-rolled selector encoding.
- [ ] Run `cargo test -p bloom-dex-router`. Tests stay green.
- [ ] Run `cargo test -p bloom-dex-it` (host-side DEX integration smoke).

- [ ] **Commit** as `feat(dex): migrate router with typed multi-return + Vec<U256>`.

---

### Phase 8: Minimal on-chain manifest anchor

Spec answer to Q4: source/manifest verification should eventually be on-chain. The minimal v1: at deploy time the deployer commits to a manifest hash; the chain stores it in `Account.manifest_hash`; contracts can read any deployed contract's manifest hash via a new host import.

**Files:**
- Modify: `crates/bloom-chain-state/src/account.rs` — add `manifest_hash: Option<Hash32>` field
- Modify: `crates/bloom-chain-types/src/tx.rs` — `TxKind::Deploy { ..., manifest_hash: Option<Hash32> }` (versioned encoding: a leading version byte so old txs decode unchanged)
- Modify: `crates/bloom-chain-node/src/petal_executor.rs` — write `manifest_hash` to `acct.manifest_hash` during deploy
- Modify: `crates/bloom-petals/src/chain_vm.rs` — add `chain.code.manifest_hash(addr_ptr, out_ptr)` host import
- Modify: `crates/bloom-petal-sdk/src/{imports.rs,code.rs}` — wrapper
- Modify: `crates/bloom/src/commands/contract.rs` — `bloom contract build` prints the computed manifest_hash to anchor at deploy time; `bloom contract verify` re-derives + compares
- Tests: deploy a contract with a manifest_hash, query it back, assert byte equality

- [ ] Add the `manifest_hash` field. Migrate existing `Account` codec with a forward-compat version byte.
- [ ] On `TxKind::Deploy` decode, accept both the old (no manifest_hash) and new (with) wire forms.
- [ ] Petal executor stores manifest_hash alongside code_hash when present.
- [ ] New host import returns `Option<Hash32>` (encoded as `0x00` for None or `0x01 || hash` for Some).
- [ ] Petal SDK exposes `code::manifest_hash(&Address) -> Option<Hash32>`.
- [ ] Integration test: deploy with manifest_hash via `bloom-chain-node`; query via a tiny WAT-only petal that calls the new import.
- [ ] Confirm DEX integration tests still pass with manifest_hash = None throughout.

- [ ] **Commit** as `feat(chain): on-chain manifest_hash anchor in Account`.

---

### Phase 9: Final acceptance run

- [ ] `cargo build --workspace --release` — all crates build.
- [ ] `cargo test --workspace` — all tests green.
- [ ] `bloom contract build -p bloom-dex-erc20` succeeds and emits a manifest.
- [ ] Repeat for wloom, factory, pair, router.
- [ ] Run the DEX integration tests (`cargo test -p bloom-dex-it`) and assert byte-level parity for selectors, storage slots, and event topics against pre-migration golden files.
- [ ] Walk the spec's Acceptance Criteria list one by one and tick each off.

- [ ] **Final commit** as `feat(contract): bloom-rust-contracts v1 complete — all examples migrated`.

---

## Risk Notes

- **Macro complexity.** `#[bloom::contract]` does a lot. Build it incrementally with focused tests rather than a single mega-expand. Reuse the existing `bloom-chain-abi-macros::contract!` patterns where they're already proven (selector hashing, slot derivation, reentrancy lock).
- **Slot byte parity.** The single biggest correctness risk. Every migrated field must have a `compat_tag` test that asserts byte equality with the pre-migration slot. Don't skip these.
- **Toolchain pin.** `bloom contract build` shells out to cargo; pin via the workspace's `rust-toolchain.toml` so manifest determinism survives toolchain bumps.
- **Wasm size budget.** The new macros may bloat the wasm. Watch `max_wasm_bytes = 262144` and tighten the macro output if any example exceeds it.
- **Schema versioning.** Reserve `schema_version = 1` for the initial manifest. Anything new (32-byte event topics, on-chain manifest verification expansion) goes to `schema_version = 2`.
