# 2026-05-20 - Bloom Rust contracts

## Summary

Bloom should evolve its current petal smart-contract surface into a
Solana/Anchor-style Rust framework rather than inventing a new source
language.

The chain should keep verifying the same deterministic artifact it verifies
today: a `wasm32-unknown-unknown` module with only `chain.*` imports, fuel
metering, bounded memory, synchronous calls, and state-root-producing writes.
Developer expressiveness should move into a higher-level Rust SDK, proc
macros, derives, and build tooling that compile down to that narrow VM
contract.

In short:

```text
Rust contract source
  -> bloom-contract macros + derives
  -> typed ABI/storage/event metadata
  -> deterministic wasm + manifest
  -> existing bloom VM execution and chain verification
```

## Current Baseline

The repo already has the right lower layer:

- `bloom-petal-sdk` exposes safe guest wrappers over deterministic chain
  imports: `state.*`, `petal.*`, `msg.*`, `block.*`, `log.emit`,
  `crypto.blake3`, and `host.deploy`.
- `bloom-petals::chain_vm` validates chain WASM, links only the `"chain"`
  import module, enables fuel, bounds memory/table growth, disables threads
  and relaxed SIMD, and distinguishes return/revert/trap.
- `bloom-chain-node::petal_executor` commits VM snapshots only on success and
  drops them on revert/trap.
- `bloom-chain-abi` provides fixed-width ABI encoding/decoding, selector
  derivation, storage-slot helpers, and dispatch errors.
- `bloom-chain-abi-macros::contract!` generates selectors, dispatchers,
  storage accessors, event emitters, init codecs, and a basic nonreentrant
  guard.
- The DEX and WLOOM examples prove the model is usable, but also expose the
  pain: manual init parsing, manual multi-return packing, limited storage
  mappings, one ABI domain per macro declaration, and manual cleanup before
  divergent returns.

## Goals

1. Make Rust the first-class smart contract language for Bloom.
2. Preserve WASM as the only consensus execution artifact.
3. Preserve the existing deterministic host-import and state-root model.
4. Remove hand-rolled selector dispatch, byte packing, storage-key derivation,
   and divergent `petal::return_data` patterns from ordinary contract code.
5. Support expressive contract data: structs, enums, tuples, arrays, vectors,
   strings/bytes, maps, nested maps, custom errors, and multi-return values.
6. Emit enough metadata for clients, explorers, auditors, and build tooling to
   reason about the generated contract artifact.
7. Migrate current examples incrementally without breaking the VM boundary.

## Non-Goals

- A new non-Rust source syntax.
- EVM/Solidity ABI compatibility.
- Runtime reflection inside contracts.
- Dynamic imports, WASI, filesystem, clocks, random, threads, or network I/O.
- Proving high-level source equivalence on-chain in v0. The chain verifies
  WASM execution; source/manifest verification is off-chain tooling.

## Target Developer Model

Contracts should look like ordinary constrained Rust:

```rust
#![no_std]

use bloom_contract::prelude::*;

#[bloom::contract]
mod erc20 {
    use super::*;

    #[storage]
    pub struct State {
        pub name: String32,
        pub symbol: String32,
        pub decimals: u8,
        pub total_supply: U256,
        pub balances: Map<Address, U256>,
        pub allowances: Map<(Address, Address), U256>,
    }

    #[event]
    pub struct Transfer {
        #[indexed]
        pub from: Address,
        #[indexed]
        pub to: Address,
        pub value: U256,
    }

    #[error]
    pub enum Error {
        InsufficientBalance,
        InsufficientAllowance,
        Overflow,
    }

    #[init]
    pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()> {
        let mut state = State::load(ctx)?;
        state.name.set(cfg.name)?;
        state.symbol.set(cfg.symbol)?;
        state.decimals.set(cfg.decimals)?;
        mint(ctx, cfg.initial_holder, cfg.initial_supply)?;
        Ok(())
    }

    pub fn transfer(ctx: &mut Context, to: Address, amount: U256) -> Result<bool> {
        let from = ctx.sender();
        debit(ctx, from, amount)?;
        credit(ctx, to, amount)?;
        emit!(ctx, Transfer { from, to, value: amount });
        Ok(true)
    }
}
```

The macro owns the entry points, dispatch, return encoding, error encoding,
ABI metadata, and cleanup. Contract authors write `Result<T, E>`, not
`petal::return_data`.

## Architecture

### 1. Consensus Kernel Stays Small

The consensus-critical kernel remains:

- WASM module bytes.
- Deploy/call transaction payloads.
- The `"chain"` import ABI.
- Fuel accounting.
- Snapshot commit/revert semantics.
- Storage root and state root computation.
- Log receipt computation.

Language features compile to this kernel. Adding a Rust SDK feature must not
require adding a new host import unless the feature genuinely needs new
consensus behavior.

### 2. New Crates

Add:

| Crate | Role |
|---|---|
| `bloom-contract` | Guest-facing high-level SDK: prelude, `Context`, types, storage wrappers, call/deploy wrappers, error/result types. |
| `bloom-contract-macros` | Attribute/derive macros: `#[contract]`, `#[storage]`, `#[event]`, `#[error]`, ABI/storage derives. |
| `bloom-contract-metadata` | Shared host/guest metadata schema for ABI, storage, events, errors, imports, compiler versions, and source hashes. |
| `bloom-contract-build` | Build/validation support used by `cargo bloom build`. |

Keep `bloom-chain-abi` as the low-level canonical codec. The new framework
may extend it, but it should not fork ABI rules into application crates.

### 3. Attribute Macros Replace `contract!`

`contract!` remains as the compatibility layer. New code uses Rust-native
attributes:

- `#[bloom::contract] mod name { ... }`
- `#[storage] struct State { ... }`
- `#[event] struct EventName { ... }`
- `#[error] enum Error { ... }`
- `#[init] fn init(...) -> Result<()>`
- `#[payable]`
- `#[view]`
- `#[nonreentrant]`
- `#[internal]`
- `#[interface(...)]` for exposing additional ABI domains such as ERC-20.

The macro expands to:

- `init` and `call` exports.
- A selector table.
- Strict calldata decoding.
- Typed handler calls.
- Typed return encoding.
- Revert/error encoding.
- Reentrancy setup and cleanup.
- Metadata constants or custom sections.
- Client call builders.

### 4. Rich ABI Derives

Introduce traits:

```rust
pub trait AbiEncode {
    fn abi_encode(&self, out: &mut Encoder) -> Result<()>;
}

pub trait AbiDecode: Sized {
    fn abi_decode(input: &mut Buf) -> Result<Self>;
}

pub trait AbiType {
    const ABI_TYPE: &'static str;
    fn schema() -> TypeSchema;
}
```

Support, in phases:

- Scalars: `bool`, `u8`, `u16`, `u32`, `u64`, `u128`, `U256`, `Address`,
  `Hash32`.
- Fixed bytes and arrays: `[u8; N]`, `[T; N]` for bounded `N`.
- Tuples and multi-return values.
- `Vec<T>` with bounded length metadata.
- `StringN` / `BytesN` bounded types first; dynamic `String` / `Bytes`
  only when a max length is declared.
- Structs.
- C-like and payload enums.
- `Option<T>` and `Result<T, E>` as ABI data where useful.

All dynamic ABI shapes must be length-prefixed and bounded by metadata so
clients and tooling can estimate decode cost and memory pressure.

### 5. Storage Compiler

Introduce storage traits:

```rust
pub trait StorageValue {
    fn load(slot: Slot) -> Result<Self>;
    fn store(&self, slot: Slot) -> Result<()>;
}

pub struct Map<K, V> { /* zero-sized descriptor */ }
pub struct VecStore<T> { /* slot-prefix descriptor */ }
```

`#[storage]` compiles each field to deterministic slot namespaces:

```text
root slot = blake3("storage:" || contract_domain || ":" || field_name)
map slot  = blake3(root_slot || StorageKey::encode(key))
```

The compiler emits a storage schema:

- Contract domain.
- Field names and types.
- Slot derivation algorithm version.
- Explicit compatibility tags, if any.
- Reserved macro slots, such as reentrancy locks.

Manual `@ "tag"`-style overrides should stay available for migration and
shared-layout compatibility, but normal contracts should never need them.

### 6. Context and Effects

Replace free host calls in user code with `Context`:

```rust
pub struct Context { /* zero-sized guest handle */ }

impl Context {
    pub fn sender(&self) -> Address;
    pub fn value(&self) -> LoomValue;
    pub fn block_number(&self) -> u64;
    pub fn block_timestamp(&self) -> u64;
    pub fn call<C: ContractInterface>(&mut self, to: Address, args: C::Call) -> Result<C::Return>;
    pub fn deploy<C: ContractInterface>(&mut self, hash: Hash32, salt: Hash32, init: C::Init) -> Result<Address>;
}
```

Effects should be visible to tooling. Function attributes define expected
capabilities:

- `#[view]` means no state writes, no value transfer, no deploy.
- `#[payable]` allows nonzero `ctx.value()`.
- `#[nonreentrant]` uses framework-managed lock cleanup.
- `#[internal]` limits callers to framework-declared authorized addresses.

Static enforcement can start conservative. The first version may enforce
effects by hiding mutating APIs behind `&mut Context` and validating macro
expansion metadata, then grow into stricter linting.

### 7. Interfaces and Cross-Contract Calls

Add typed interfaces:

```rust
#[bloom::interface(domain = "erc20")]
pub trait Erc20 {
    fn balance_of(owner: Address) -> Result<U256>;
    fn transfer(to: Address, amount: U256) -> Result<bool>;
}
```

The macro emits:

- Selector constants.
- Client call builders.
- `ContractRef<Erc20>` typed call helpers.
- Optional implementation checks for contracts that claim `impl Erc20`.

This removes the current hand-dispatch problem in pair and WLOOM. A contract
can expose multiple interfaces while still having one implementation module.

### 8. Errors and Reverts

Move from `&'static str` as the main handler error channel to typed errors:

```rust
#[error]
pub enum Error {
    #[message("insufficient balance")]
    InsufficientBalance,
    Overflow,
}
```

Encoding:

- Stable 4-byte error selector derived from `ErrorName(...)`.
- Optional encoded fields for payload variants.
- Human-readable messages live in metadata, not necessarily in revert data.

The VM still sees `petal.revert(bytes)`. The framework chooses the bytes.

### 9. Events

Events become Rust structs with derived schemas. Indexed fields remain part
of event metadata and log encoding. The framework should align SDK behavior
with the host, which already accepts 32-byte topics; current 4-byte event
prefixes can stay compatibility-padded to 32 bytes or be replaced by full
32-byte topics under a versioned event encoding.

Acceptance requirement: old DEX event topics/data remain decodable through a
compatibility metadata version.

### 10. Build and Verification Artifacts

Add `cargo bloom build`:

```text
cargo bloom build -p bloom-dex-erc20
```

It should:

1. Compile with pinned Rust toolchain to `wasm32-unknown-unknown`.
2. Run `PetalVm::validate_for_chain`.
3. Reject disallowed imports and exports.
4. Enforce memory limits and WASM size limits.
5. Emit optimized WASM.
6. Emit a manifest:

```json
{
  "schema_version": 1,
  "contract": "erc20",
  "wasm_hash": "b3...",
  "source_hash": "b3...",
  "compiler": {
    "rustc": "...",
    "bloom_contract": "...",
    "wasmtime_epoch": "..."
  },
  "abi": {},
  "storage": {},
  "events": {},
  "errors": {},
  "imports": ["chain.state.read", "chain.state.write"],
  "limits": {
    "max_memory_pages": 256,
    "max_wasm_bytes": 262144
  }
}
```

The chain does not need to trust the manifest for execution, but tools can
verify that a deployed `wasm_hash` matches a published manifest and source.

### 11. Determinism Profile

Document and lint a Bloom Rust profile:

- `#![no_std]`.
- `wasm32-unknown-unknown`.
- No WASI.
- No threads.
- No randomness except future chain-provided deterministic randomness.
- No system time; use `ctx.block_timestamp()`.
- Prefer no floating point. If allowed, rely on chain VM NaN
  canonicalization and document the exact semantics.
- Bounded allocation patterns where possible.
- Bounded dynamic ABI and storage collections.
- Panic maps to revert.

### 12. Migration Plan

Phase 1: Foundation

- Add `bloom-contract`, `bloom-contract-macros`,
  `bloom-contract-metadata`, and `bloom-contract-build`.
- Re-export low-level `bloom-chain-abi` types.
- Implement `Address`, `Hash32`, bounded string/bytes helpers, typed
  `Result`, and `Context`.
- Keep current `contract!` unchanged.

Phase 2: ABI derives

- Add `AbiEncode`, `AbiDecode`, `AbiType`.
- Support scalars, structs, tuples, arrays, bounded vecs, and multi-return.
- Update `bloom-chain-abi` so low-level codec can serve both old macro and
  new derives.

Phase 3: Storage derives

- Add `#[storage]`, `StorageValue`, `Map<K, V>`, and deterministic schema
  emission.
- Support compatibility tags so ERC-20/pair storage can keep current slots.
- Add host-side tests proving slot parity for migrated examples.

Phase 4: Contract attributes

- Implement `#[bloom::contract]`, `#[init]`, `#[event]`, `#[error]`,
  `#[nonreentrant]`, `#[payable]`, and `#[view]`.
- Generate `init`/`call` exports directly.
- Ensure user handlers return normally through `Result<T, E>`; the macro
  owns `petal.return` and `petal.revert`.

Phase 5: Interfaces

- Implement `#[interface]` traits and `ContractRef<I>`.
- Migrate WLOOM and pair LP-token ERC-20 surfaces away from manual selector
  dispatch.

Phase 6: Tooling

- Add `cargo bloom build`.
- Emit manifest JSON.
- Add manifest verification command.
- Integrate with deploy-suite CLI.

Phase 7: Example migration

- Migrate ERC-20 first.
- Migrate WLOOM.
- Migrate factory.
- Migrate pair.
- Migrate router last, because it exercises multi-return and vector returns.
- Keep selector, storage, event, and end-to-end DEX parity tests throughout.

## Compatibility

The old `contract!` macro remains supported until all examples migrate.
Generated selectors, storage slots, event topics, and calldata for migrated
contracts must match existing contracts when a compatibility tag or interface
domain requests it.

Breaking improvements, such as full 32-byte event topics or a new ABI dynamic
layout, must be versioned in metadata and unavailable by default for migrated
v0 examples.

## Acceptance Criteria

- Existing `cargo test` and DEX integration tests remain green.
- A new ERC-20 written with `#[bloom::contract]` compiles to chain-valid WASM.
- The new ERC-20 has selector, storage, event, and behavior parity with the
  current `examples/dex/crates/bloom-dex-erc20` contract.
- A new router method can return `(U256, U256, U256)` without manual
  `petal::return_data`.
- A contract can expose both its own domain and an `erc20` interface without
  hand-written selector dispatch.
- `#[nonreentrant]` requires no user-authored lock clear.
- `cargo bloom build` emits WASM plus a manifest and rejects disallowed
  imports.
- The chain still verifies and executes only WASM plus the existing
  consensus state-transition rules.

## Open Questions

1. Should dynamic ABI values use simple length-prefix encoding or a
   self-describing schema format for future compatibility?
   User answer: self-describing schema.
2. Should event topics stay as 4-byte Bloom prefixes padded to 32 bytes, or
   should new contracts move to full 32-byte topics under metadata version 2?
   User answer: whatever is most future proof but not over-engineered.
3. How strict should the first Bloom Rust profile be about floating point?
   User answer: use your best judgement.
4. Should source/manifest verification eventually be recorded on-chain, or
   remain explorer/tooling infrastructure?
   User answer: on-chain.
5. Do we want account-style explicit storage loading, like Solana accounts,
   or the current contract-owned storage model with typed accessors? The
   current chain state favors contract-owned storage; the framework should
   not fight that unless the state model changes.
   User answer: explicit storage loading.
