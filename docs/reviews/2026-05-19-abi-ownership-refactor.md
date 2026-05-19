# Chain-owned ABI refactor (2026-05-19)

## Background

The 2026-05-19 architectural review concluded that `bloom-dex-abi` sits in
the wrong ownership layer. Every DEX contract (pair, router, factory)
hand-rolls selector dispatch, slicing, return packing, and init layouts.
SDK-level u256 silently ignores top 16 bytes. Revert fuel accounting is
wrong. Pair internal selectors have no `msg.sender` guard.

Chain VM must remain a raw-byte boundary, but ABI semantics must be
chain-owned. DEX shrinks to interface declarations and business logic.

## Deliverables

### 1. Chain-owned ABI crate

Create `crates/bloom-chain-abi`. Canonical encoders / decoders for:

- `Address`
- `Hash32` / `bytes32`
- `u256`, `u128`, `u64`
- `bool`
- fixed-length arrays
- variable-length arrays
- raw bytes
- method selectors (BLAKE3-tagged)
- event topics
- return values
- init calldata

Selector derivation tag and width specified in the v0 spec.

### 2. Migrate from `bloom-dex-abi`

Move encoding / decoding mechanics from
`examples/dex/crates/bloom-dex-abi` (`Encoder`, `Buf`, u256 ops,
selector hashing, `push_*` and `read_*` helpers) into `bloom-chain-abi`.
DEX may keep type declarations and domain enums but must not own
primitive byte packing or selector hashing.

### 3. Strict decoding by default

Every generated decoder rejects trailing bytes via `expect_eof` unless
the method explicitly opts into variable trailing data. Sweep
`examples/dex/crates/bloom-dex-pair`, `bloom-dex-router`,
`bloom-dex-factory` to remove `len >= N` partial-decode paths.
Factory init at `examples/dex/crates/bloom-dex-factory/src/lib.rs:257`
must enforce exactly 128 bytes.

### 4. Generated dispatch (`contract!` macro)

```rust
bloom_chain_abi::contract! {
    contract Factory {
        fn create_pair(token_a: Address, token_b: Address) -> Address;
        // ...
    }
}
```

Macro emits:

- client-side call-builder (selector + arg encode)
- guest-side dispatcher with selector match + strict arg decode + return
  encode
- init wrappers for `host.deploy`

DEX contracts switch from hand-rolled `Buf::new(args).read_address()`
to typed handler signatures.

### 5. SDK consumes the chain ABI

Move `bloom-petal-sdk` value-call surface from u256-with-silent-truncation
(`crates/bloom-petal-sdk/src/petal.rs:19`) to `LoomValue(u128)` or
explicit reject on nonzero high bytes. No silent narrowing.

### 6. Fix revert fuel accounting

VM bug at `crates/bloom-petals/src/chain_vm.rs:1212` vs `:1298`.
`run_chain_call` must propagate the real `fuel_used` on revert paths
instead of zeroing. Reverting contracts must not look free. Regression
test under `crates/bloom-petals/tests/`.

### 7. Pair internal-selector authorization

`examples/dex/crates/bloom-dex-pair/src/lib.rs:1000` area must reject
internal selectors when `msg.sender != stored reentrancy_addr`. Move
this into the macro-generated internal-method wrapper so other contracts
can opt in.

### 8. Spec update

`docs/specs/2026-05-18-bloom-chain-design.md`: new section describing
the canonical ABI:

- selector tag + derivation
- primitive width / encoding per type
- strict-decoding requirement
- init-calldata layout rules
- dispatch protocol
- revert fuel rules

## Acceptance gates (must remain green)

- `scripts/test-docker-dex.sh`
- `examples/dex/tests/bloom-dex-it/tests/chain_dex_demo.rs`
  (`dex_v0_acceptance_end_to_end`)
- full `cargo test` workspace

## Adversarial test additions

- (a) trailing-bytes rejection on every migrated method
- (b) factory init with wrong length rejected
- (c) pair internal selector called by a non-reentrancy sender rejected
- (d) revert from a contract that burned fuel correctly bills the sender
- (e) u128 boundary tests on petal-sdk value-call: high bytes nonzero
  must either reject or carry through, never silently truncate

## Working style

- Keep DEX under `examples/`.
- Default `RUST_LOG=warn`.
- Do not invoke any `superpowers:*` skills.
- Dispatch parallel agents on independent file groups where the change
  set is genuinely parallelizable (one agent per migrated DEX contract
  once the chain-abi surface is stable). The macro / codegen design and
  chain-abi crate scaffold must be done serially before any contract
  migration starts.

## Migration order

1. Scaffold `bloom-chain-abi`.
2. Port primitives and selector hashing.
3. Design and land `contract!` macro.
4. Migrate one DEX contract end-to-end as the canary.
5. Migrate remaining DEX contracts in parallel.
6. Delete the obsolete portions of `bloom-dex-abi`.
7. Fix revert fuel + internal-selector auth + petal-sdk value handling.
8. Spec update.
