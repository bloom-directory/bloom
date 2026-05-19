# bloom-dex — a Uniswap-v2-style DEX as bloom-chain petals

**Status:** draft
**Date:** 2026-05-18 (revised 2026-05-19 for contract-macro v2)
**Owners:** —
**Addresses:** The v0 application layer on top of [bloom-chain]
([2026-05-18-bloom-chain-design.md](2026-05-18-bloom-chain-design.md)).
A constant-product AMM expressed as a small set of wasm petals: an
ERC-20-shaped token petal, a pair petal, a factory petal, a router
petal, and a wrapped-LOOM petal. Reentrancy protection is now a
language-level concern provided by the `#[nonreentrant]` attribute on
`bloom_chain_abi::contract!` (see
[2026-05-19-contract-macro-v2.md](2026-05-19-contract-macro-v2.md) §C);
the separate reentrancy-guard helper petal is gone. No flash swaps,
no fee-to, no on-chain governance, no oracles — that is all v1+.

## 1. Goals

1. **Reproduce the Uniswap-v2 surface** (`Factory`, `Pair`, `Router`,
   `ERC20`-shaped token, LP token, wrapped-native token) as a set of
   bloom-chain petals.
2. **Constant-product AMM with 0.30 % LP fee.** `x * y ≥ k` enforced
   on every swap after fees. No protocol fee in v0 (`feeTo = 0` and
   the slot is omitted).
3. **Deterministic pair address derivation** so the router can locate
   any pair without onchain registry lookups.
4. **Petal-only.** All DEX state lives in per-instance petal storage
   (§6 of the chain spec). No bespoke node-side modules, no
   precompiles. The chain treats DEX petals exactly like any other
   onchain petal.
5. **Demo-ready.** `tests/chain/dex_demo.rs` can deploy the factory +
   two ERC-20 petals + a pair, add liquidity, swap, remove liquidity,
   and assert `x*y=k` (up to fees) and LP-share accounting against
   the chain spec's v0 acceptance criteria (§15 there).

## 2. Non-goals (v0)

- **Flash swaps.** The pair's `swap` entry point does not call back
  into the recipient before checking `k`. Removed from the v2 ABI.
- **`feeTo` / protocol fee.** All swap fees stay with LPs. The
  `setFeeTo` / `setFeeToSetter` surface is omitted entirely.
- **TWAP / cumulative-price oracles.** No `price0CumulativeLast` /
  `price1CumulativeLast` slots; no `blockTimestampLast`.
- **Permit / EIP-2612.** Approvals are direct `approve` calls only.
- **ERC-165 / on-chain introspection.** Selectors are 4-byte BLAKE3
  prefixes (§4) — there's no `supportsInterface` registry.
- **Re-orderable txs / private orderflow integration.** Sequencing
  is whatever the proposer picks. v0 trusts the honest-majority
  assumption.
- **Multi-hop router quoting beyond a single pair.** v0 router does
  exact-in / exact-out across an explicit path array, but quoting is
  client-side. No on-chain `getAmountsOut` view.
- **Fee-on-transfer tokens.** Pair assumes balance deltas equal
  transfer amounts. Documented limitation; tests use plain ERC-20s.

## 3. Petal inventory

Five wasm petals total. Each is content-addressed by its BLAKE3 hash;
deploying instantiates `(petal_hash, instance_address)` per the
chain spec's `Deploy` tx kind.

| Petal | Crate | Role |
|-------|-------|------|
| `bloom-dex-erc20` | `examples/dex/crates/bloom-dex-erc20` | Generic ERC-20-shaped fungible token. Used for both test tokens and as the **base class** of `bloom-dex-pair`'s LP token (the LP token is the pair instance itself). |
| `bloom-dex-pair` | `examples/dex/crates/bloom-dex-pair` | Single-pair AMM. Holds reserves, exposes `mint` / `burn` / `swap` / `skim` / `sync`. Also acts as its own LP token (ERC-20 surface inlined). `mint` / `burn` / `swap` carry `#[nonreentrant]` (see §8). |
| `bloom-dex-factory` | `examples/dex/crates/bloom-dex-factory` | Deploys pairs deterministically. Registers `pair_address(tokenA, tokenB)`. Owns the canonical `pair` petal hash. |
| `bloom-dex-router` | `examples/dex/crates/bloom-dex-router` | Stateless. `addLiquidity` / `removeLiquidity` / `swapExactTokensForTokens` / `swapTokensForExactTokens`, plus their `*LOOM` variants over wrapped LOOM. |
| `bloom-dex-wloom` | `examples/wloom` | Wrapped native LOOM. `deposit` (payable, mints), `withdraw` (burns, sends native). Mirrors WETH9 semantics. Lives at the workspace top level — independent of the DEX. |

Each petal compiles to one `*.wasm` artifact under
`target/wasm32-unknown-unknown/release/`. The `init` entry point
(per chain spec §7.8) writes constructor parameters into storage.
The `call(calldata_ptr, calldata_len) -> i32` entry point dispatches
on a 4-byte selector (§4).

## 4. Calldata encoding

The DEX does NOT define its own calldata encoding. Encoding,
selector hashing, strict decoding, and dispatcher generation all
live in the chain-owned `bloom-chain-abi` crate; see **chain spec
§7.10 (Canonical ABI for petal calldata)** for the full
specification. Every DEX petal declares its ABI via the
`bloom_chain_abi::contract!` macro, which emits client-side
call builders, a typed `Handler` trait, and a strict dispatcher
from a single declaration.

The remainder of this section enumerates the canonical method
strings the DEX uses — i.e. the inputs to `blake3(...)[..4]` selector
derivation defined in chain spec §7.10.2. The chain governs HOW;
the DEX only chooses the per-petal method list.

Width and type conventions (recapped from chain spec §7.10.1 for
reference):
- `Address` = 32 bytes (chain spec §4.3).
- `u256` = 32 bytes big-endian. (LOOM and token balances are
  `u256` for ERC-20 compatibility, even though native LOOM
  balances at the chain level are `u128` — pair / LP / router
  math operates on `u256` to avoid overflow on intermediate
  products. Conversion at the wLOOM boundary clamps to `u128`
  via `LoomValue::try_from_be_u256_bytes`, which reverts on
  overflow rather than silently truncating.)
- `u128` = 16 bytes big-endian.
- `u64` = 8 bytes big-endian.
- `bool` = 1 byte (0 / 1).
- `bytes32` = 32 bytes.
- `Vec<Address>` (paths only) = `u16` big-endian length + `length * 32` bytes.
- `bytes` (variable-length tail) = raw remainder of calldata, no
  length prefix; chain spec §7.10.1 restricts it to the LAST
  positional argument of a method. Currently unused in v0 — the
  reentrancy.enter callsite that used it has been removed (see §8).

Strict decoding (chain spec §7.10.4) means every dispatcher
rejects trailing bytes, unknown selectors, short calldata, and
out-of-range typed values. The DEX inherits this behaviour
automatically through `contract!`.

Return data:
- ERC-20 read methods return their natural width (e.g.
  `balanceOf -> u256` → 32 bytes raw).
- Write methods return either 1 byte `1` for `true` or 32-byte
  `u256` for amounts (see per-method tables below).
- Multi-value returns (`pair.burn → (u256,u256)`,
  `router.add_liquidity → (u256,u256,u256)`, `router.swap_* →
  Vec<u256>`) are NOT expressible in `contract!`'s return slot
  (chain spec §7.10.6); those methods declare a void macro
  return and emit `petal.return` from the handler with a manually
  constructed payload via `bloom_chain_abi::Encoder`. The
  canonical signature string for selector hashing still reflects
  only the argument list, never the return.
- Revert reason strings are UTF-8 bytes passed to `petal.revert`.

### 4.1 Method strings (canonical, hashed for selectors)

All strings hashed via `blake3(...)[..4]`. Stored verbatim in the
test crate; the runtime never re-derives selectors.

**ERC-20 / LP token** (`bloom-dex-erc20`, also exposed by pair):
- `erc20.total_supply()`
- `erc20.balance_of(address)`
- `erc20.allowance(address,address)`
- `erc20.transfer(address,u256)`
- `erc20.transfer_from(address,address,u256)`
- `erc20.approve(address,u256)`
- `erc20.name()` (returns `bytes32`, ASCII left-padded with NULs)
- `erc20.symbol()`
- `erc20.decimals()`

**Pair** (`bloom-dex-pair`, plus the ERC-20 surface above as the LP):
- `pair.token0()`
- `pair.token1()`
- `pair.get_reserves()` → returns `(u128 reserve0, u128 reserve1,
  u64 block_timestamp_last)` packed into 32 bytes (see §6).
- `pair.mint(address to)` → returns `u256 liquidity`.
- `pair.burn(address to)` → returns `(u256 amount0, u256 amount1)`.
- `pair.swap(u256 amount0_out, u256 amount1_out, address to)`.
- `pair.skim(address to)`.
- `pair.sync()`.

(No `pair.initialize` method: the pair's chain-level `init` entry
point — chain spec §7.8 — handles one-time setup using the
`init_calldata` supplied to `host.deploy`. The `init_calldata`
encoding is two `Address`es: `t0 || t1`.)

**Factory** (`bloom-dex-factory`):
- `factory.create_pair(address tokenA, address tokenB)` →
  returns `address pair`.
- `factory.get_pair(address tokenA, address tokenB)` →
  returns `address pair` (zero if none).
- `factory.all_pairs(u64 index)` → returns `address`.
- `factory.all_pairs_length()` → returns `u64`.

**Router** (`bloom-dex-router`):
- `router.add_liquidity(address tokenA, address tokenB,
                        u256 amount_a_desired, u256 amount_b_desired,
                        u256 amount_a_min, u256 amount_b_min,
                        address to, u64 deadline)`
  → returns `(u256 amount_a, u256 amount_b, u256 liquidity)`.
- `router.remove_liquidity(address tokenA, address tokenB,
                           u256 liquidity,
                           u256 amount_a_min, u256 amount_b_min,
                           address to, u64 deadline)`
  → returns `(u256 amount_a, u256 amount_b)`.
- `router.swap_exact_tokens_for_tokens(u256 amount_in,
                                       u256 amount_out_min,
                                       Vec<Address> path,
                                       address to, u64 deadline)`
  → returns `Vec<u256> amounts` (encoded as `u16` length + 32-byte
  entries).
- `router.swap_tokens_for_exact_tokens(u256 amount_out,
                                       u256 amount_in_max,
                                       Vec<Address> path,
                                       address to, u64 deadline)`
  → returns `Vec<u256> amounts`.
- LOOM variants (`*_loom`) operate over native LOOM and wrap /
  unwrap through `bloom-dex-wloom` internally. The router instance
  is constructed with `(factory_address, wloom_address)`.

**Wrapped LOOM** (`bloom-dex-wloom`, also exposes ERC-20):
- `wloom.deposit()` — `msg.value` LOOM credited as wLOOM to
  `msg.sender`.
- `wloom.withdraw(u256 amount)` — burns wLOOM, transfers native
  LOOM to `msg.sender` via the chain's value-transfer mechanism
  (see §7).

**Reentrancy.** No dedicated petal. The pair's `mint` / `burn` /
`swap` carry the `#[nonreentrant]` attribute, which makes the
chain-ABI macro wrap each method with a check-and-set of a contract-
wide auto-managed lock slot (see §8 and contract-macro v2 spec §C).

## 5. Address derivation

The factory uses CREATE2-style determinism on top of the chain's
deploy-address formula (chain spec §7.7) so any client can compute
a pair address from `(factory, tokenA, tokenB)` alone.

### 5.1 Pair salt

```
(t0, t1) = sort([tokenA, tokenB])   // lexicographic by 32-byte address
salt     = blake3("dex.pair.salt:" || t0 || t1)
```

### 5.2 Pair deploy

`factory.create_pair(tokenA, tokenB)`:
1. Sort `(t0, t1)` lexicographically.
2. Compute `salt = blake3("dex.pair.salt:" || t0 || t1)`.
3. Compute `init_calldata = encode_pair_init(t0, t1)` (per §6.2).
4. Invoke `host.deploy(pair_petal_hash, salt, init_calldata)`
   (chain spec §7.6). The chain runtime deploys at
   `pair_address = blake3("bloom-chain.v0.addr:deploy:" || factory
                          || ":" || salt || ":" || pair_petal_hash)` because the
   calling petal — the factory — is the deployer-of-record under the
   chain's `host.deploy` semantics (chain spec §7.7).
5. Record `(t0, t1) -> pair_address` in factory storage and append
   to `all_pairs`.
6. Return `pair_address`.

`pair_petal_hash` is a constant baked into the factory at deploy
(see §7). Re-deployment of an already-existing pair reverts at the
chain level (chain spec §7.7's `code_hash != None` collision rule).
Clients can pre-compute `pair_address` from `(factory, tokenA,
tokenB, pair_petal_hash)` alone.

### 5.3 Router and wLOOM addresses

Plain deploys with operator-chosen salts. Their addresses are
captured in `genesis.toml` or the demo's setup script and
referenced by clients as fixed constants for the duration of v0.

### 5.4 Petal-initiated deploys (resolved)

The chain spec adds a `host.deploy(hash, salt, init_calldata) ->
address` import (chain spec §7.6) for v0. The factory uses it
directly in `create_pair`; no separate `pair.initialize` method is
needed because the chain calls the deployed petal's standard `init`
entry point (chain spec §7.8) with the supplied `init_calldata`.

Pre-requirement: the pair wasm must already exist in the chain's
`code_root`. Operators upload it once during chain bootstrap via a
single tx-level `Deploy` whose `init_args` is exactly 96 bytes of
zero (`token0 = token1 = self = 0x00..`). Pair `init` tolerates a
zero-only payload — it writes zero slots to the bootstrap instance,
leaves reserves at zero, and never gets called again because
`create_pair` derives a different address for every real
(tokenA, tokenB) deployment. The resulting bootstrap instance
address is therefore inert; only the `petal_hash` registration in
`code_root` is what matters. The factory is constructed with
`pair_petal_hash` baked in as a constant.

> v1+: introduce `TxKind::UploadCode { wasm }` so wasm registration
> doesn't require committing a dead instance. Tracked as project
> task #16. Until then the zero-init bootstrap above is the
> sanctioned v0 mechanism.

This collapses what was a two-tx workflow into a single
`factory.create_pair(...)` call.

## 6. Per-petal storage layout

State keys are 32-byte BLAKE3 digests of a domain-tagged tuple, and
values are 32-byte slots (chain spec §6.2 / §7.6). Multi-field
records pack into multiple slots with a `field` discriminator.

### 6.1 ERC-20 / LP token (`bloom-dex-erc20`, `bloom-dex-pair` LP surface)

| Slot | Key | Value |
|------|-----|-------|
| `total_supply` | `blake3("erc20.total_supply")` | u256 |
| `balance_of(a)` | `blake3("erc20.balance:" \|\| a)` | u256 |
| `allowance(o,s)` | `blake3("erc20.allowance:" \|\| o \|\| s)` | u256 |
| `name` | `blake3("erc20.name")` | bytes32 (NUL-padded ASCII) |
| `symbol` | `blake3("erc20.symbol")` | bytes32 |
| `decimals` | `blake3("erc20.decimals")` | u8 in low byte, rest zero |

Pair re-uses these keys verbatim for its LP token; the keyspace
does not collide with pair-AMM keys below because the domain tags
differ.

### 6.2 Pair AMM (`bloom-dex-pair`)

**init calldata:** `token0 (32B) || token1 (32B) || pair_self_addr (32B)` — 96 bytes, no fallback.
The factory pre-computes `pair_self_addr` via chain spec §7.7 before calling `host.deploy`.
The pair stores `pair_self_addr` in the `self_addr` slot so it can call `token.balanceOf(self)`
(the chain has no `msg.self` host import).

Storage is declared inline in the pair's `contract!` block; slot keys
below are the canonical derivations the chain-ABI storage runtime
produces from each `@ "tag"` (scalar) or `@ "tag:"` (mapping) override
plus the auto-tagged fields `pair.<field>`.

| Slot | Key | Value |
|------|-----|-------|
| `token0` | `blake3("pair.token0")` | Address (32 bytes) |
| `token1` | `blake3("pair.token1")` | Address |
| `self_addr` | `blake3("pair.self")` | Address — this petal's own address |
| `reserve0` | `blake3("pair.reserve0")` | u128 (left-padded to 32) |
| `reserve1` | `blake3("pair.reserve1")` | u128 |
| `k_last` | `blake3("pair.k_last")` | u256 (kept for future feeTo; always written but read-only in v0) |

Plus the ERC-20 / LP token slots from §6.1 (`total_supply`,
`balances:`, `allowances:`) which the pair re-uses verbatim.

**Reentrancy lock.** The pair no longer stores a `lock` slot under
its own namespace. The `#[nonreentrant]` attribute on
`mint` / `burn` / `swap` makes the macro auto-manage a
reserved slot at `blake3("__macro.nonreentrant.pair")` — opaque to
user code, but invariant across deploys of the same petal hash. See §8.

`get_reserves` packs `reserve0` (u128, 16 bytes), `reserve1` (u128,
16 bytes), and the current `block.timestamp` low 64 bits into one
return slot for cheaper reads.

### 6.3 Factory (`bloom-dex-factory`)

**init calldata:** `pair_petal_hash (32B) || fee_to_setter (32B) || factory_self_addr (32B)` — 96 bytes, no fallback.
`factory_self_addr` is the factory's own pre-computed CREATE2 address, stored in the `self_addr` slot.
The factory uses `self_addr` in `createPair` to pre-compute the pair address via chain spec §7.7
before calling `host.deploy`, so the pair's 96B init calldata can include `pair_self_addr`.

`createPair` builds 96B pair init: `t0 || t1 || pair_address` where
`pair_address = blake3("bloom-chain.v0.addr:deploy:" || factory_self || ":" || salt || ":" || pair_petal_hash)`.

| Slot | Key | Value |
|------|-----|-------|
| `pair_petal_hash` | `blake3("factory.pair_petal_hash")` | bytes32 |
| `fee_to` | `blake3("factory.fee_to")` | Address (zero in v0) |
| `fee_to_setter` | `blake3("factory.fee_to_setter")` | Address |
| `self_addr` | `blake3("factory.self")` | Address — factory's own address |
| `get_pair(t0,t1)` | `blake3("factory.pair_of:" \|\| t0 \|\| t1)` | Address (zero if unset) — stored for both orderings |
| `all_pairs_length` | `blake3("factory.all_pairs.len")` | u64 |
| `all_pairs[i]` | `blake3("factory.all_pairs:" \|\| u64_be(i))` | Address |

The factory no longer stores a `reentrancy` address; the cross-petal
reentrancy guard is gone (§8).

### 6.4 Wrapped LOOM (`bloom-dex-wloom`)

Same as ERC-20 §6.1, with `name = "Wrapped LOOM"`, `symbol =
"wLOOM"`, `decimals = 18`. `deposit` increments
`balance_of(msg.sender)` and `total_supply` by `msg.value`.
`withdraw` does the reverse and triggers a native LOOM transfer
(see §7).

### 6.5 Router (`bloom-dex-router`)

**init calldata for router (`bloom-dex-router`):**
`factory_addr (32B) || wloom_addr (32B) || router_self_addr (32B)` — 96 bytes, no fallback.
The 64-byte form is rejected with `"router: bad init"`. The `deploy-suite` CLI MUST
pass 96 bytes with the router's CREATE2-precomputed address as the third field.
`router_self_addr` is required for LOOM-output swaps which temporarily receive
wLOOM into the router before unwrapping it to native LOOM.

## 7. Native LOOM ↔ wrapped LOOM bridge

The chain spec keeps LOOM native in the accounts trie; petals
cannot mint native LOOM. To let the AMM trade LOOM, the
`bloom-dex-wloom` petal wraps it:

- `wloom.deposit()` is invoked with `msg.value = N` LOOM via a
  `Call` tx (chain spec §7.1). The chain runtime debits `N` from
  `sender.loom` and credits `N` to the wLOOM petal's account
  balance (this is the existing native-value-transfer semantics
  in `petal.call`). The petal then `state.write`s
  `balance_of(sender) += N` and `total_supply += N`.
- `wloom.withdraw(amount)` does the reverse. To send native LOOM
  back, the petal calls `petal.call(target=msg.sender,
  calldata=[], value_loom=amount)` — an empty calldata transfer.
  Plain accounts (no `code_hash`) accept value transfers without
  invoking any wasm.

The router's `*_loom` variants wrap on entry and unwrap on exit,
so end users hold native LOOM and never see wLOOM unless they
choose to.

## 8. Reentrancy and locking

v2 pair contracts in Solidity use a `lock` modifier around `mint`,
`burn`, and `swap`. The chain-ABI macro provides the equivalent as a
function-level attribute. The DEX uses it directly; there is no
dedicated reentrancy petal and no cross-petal `enter` indirection.

### 8.1 The `#[nonreentrant]` attribute

```rust
contract! {
    contract Pair {
        // …storage, events…

        #[nonreentrant]
        fn mint(to: Address);

        #[nonreentrant]
        fn burn(to: Address);

        #[nonreentrant]
        fn swap(amount0_out: U256, amount1_out: U256, to: Address);
    }
}
```

The macro wraps each `#[nonreentrant]` method with a contract-wide
lock check-and-set at the dispatcher boundary. The lock slot is a
single auto-managed key derived as
`blake3("__macro.nonreentrant.<contract_snake>")` — for the pair
that is `blake3("__macro.nonreentrant.pair")`. The reserved
`__macro.` tag prefix is enforced by the macro parser; user code
cannot declare any storage under it (contract-macro v2 spec §B).

### 8.2 Enter / exit semantics

On entry to a `#[nonreentrant]` method the macro-generated
dispatcher:

1. Reads the lock slot. If `slot[31] == 1`, the dispatcher reverts
   `"pair: reentrant call"` immediately.
2. Writes `slot[31] = 1` (set the lock).
3. Invokes the user handler.
4. **Success path:** writes `slot[31] = 0` (clear the lock).

The pair handlers terminate via the divergent `petal::return_data`
SDK call, which never returns control to the dispatcher. For those
methods the user code calls `pair::abi::nonreentrant_lock_clear()`
(emitted by the macro inside the contract's `abi` module)
immediately before `petal::return_data(...)`. The divergent-return
contract is documented in the contract-macro v2 spec §C.

### 8.3 Revert behaviour

If a `#[nonreentrant]` handler reverts (via `petal::revert(...)` or
any host trap), the surrounding transaction is rolled back at the
chain level — including the lock-set write. The lock is never
durably observable after a failed transaction. This matches the
behaviour of the prior cross-petal guard and removes the need for
`host.try_call` / a finally-clause primitive in v0.

The `petal.call` depth cap of 16 (chain spec §16) remains as a
backstop.

## 9. AMM math

All math is integer, replicating Uniswap v2 verbatim.

### 9.1 Swap formula

Given input reserves `(r_in, r_out)`, swap amount `a_in`, and 30 bp
fee:

```
a_in_with_fee = a_in * 997
numerator     = a_in_with_fee * r_out
denominator   = r_in * 1000 + a_in_with_fee
a_out         = numerator / denominator
```

`pair.swap` performs the invariant check directly:

```
let balance0_adj = balance0 * 1000 - amount0_in * 3
let balance1_adj = balance1 * 1000 - amount1_in * 3
require(balance0_adj * balance1_adj >= reserve0 * reserve1 * 1_000_000)
```

Intermediates are `u256`; final reserves clamp to `u128` and revert
on overflow.

### 9.2 Liquidity math

- **First mint:** `liquidity = sqrt(amount0 * amount1) -
  MIN_LIQUIDITY`, with `MIN_LIQUIDITY = 1000` locked permanently
  by minting to the zero address.
- **Subsequent mints:** `liquidity = min(amount0 * total_supply /
  reserve0, amount1 * total_supply / reserve1)`.
- **Burn:** for `liquidity_in` LP tokens, return
  `(liquidity_in * balance0 / total_supply,
    liquidity_in * balance1 / total_supply)`.

Integer `sqrt` uses Babylonian iteration over `u256`.

### 9.3 Quoting (router-side, in-petal)

- `quote(amount_a, reserve_a, reserve_b) = amount_a * reserve_b /
  reserve_a`. Used by `add_liquidity` to decide which side to
  match.
- `get_amount_out`, `get_amount_in` replicate the v2 helpers
  using the formula above.

All paths revert on division-by-zero or overflow rather than
returning silent zeros.

## 10. Events / logs

Each petal declares its events inline in its `contract!` block; the
chain-ABI macro emits per-event topic constants (`<EVENT>_TOPIC`,
4 bytes) and an `emit_<event>(...)` function inside the contract's
`abi::events` module. Topics are 4-byte BLAKE3 selectors of the
canonical event signature (chain spec §7.10.2; identical derivation
to method selectors).

Indexed fields are tagged with `#[indexed]` in the declaration. In
v0 the underlying `log.emit` host import accepts a single 4-byte
topic, so indexed field values are encoded as 32-byte chunks at the
head of the log's data blob (the topic remains the event-signature
prefix). Downstream consumers read indexed values by position. This
matches the pre-migration wire format and a future v1+ chain
upgrade can promote them to multi-topic logs without changing the
DSL.

ERC-20:
- `Transfer(#[indexed] from: Address, #[indexed] to: Address, value: U256)`
- `Approval(#[indexed] owner: Address, #[indexed] spender: Address, value: U256)`

Pair:
- `Mint(#[indexed] sender: Address, amount0: U256, amount1: U256)`
- `Burn(#[indexed] sender: Address, amount0: U256, amount1: U256, #[indexed] to: Address)`
- `Swap(#[indexed] sender: Address, a0_in: U256, a1_in: U256, a0_out: U256, a1_out: U256, #[indexed] to: Address)`
- `Sync(reserve0: u128, reserve1: u128)`

Factory:
- `PairCreated(#[indexed] token0: Address, #[indexed] token1: Address, pair: Address, all_pairs_length: u64)`

## 11. CLI surface (DEX-specific)

The chain CLI (chain spec §10) already covers `deploy`, `call`,
`query`, `submit`. The DEX adds a thin convenience subcommand
tree under `bloom dex` for the demo:

```
bloom dex deploy-suite [--genesis-keys K1,K2,...]
    # Deploys wloom, factory (with pair_petal_hash baked in),
    # and router. Writes addresses to <bloom_home>/chain/dex.toml.

bloom dex deploy-token --name N --symbol S --decimals 18
                       --supply <u256> --to <addr>
    # Deploys a fresh ERC-20 petal.

bloom dex create-pair --token-a <addr> --token-b <addr>
    # Submits a Call tx invoking factory.create_pair, which uses
    # host.deploy internally (per §5.2) to deploy the pair instance
    # at the deterministic CREATE2 address.

bloom dex add-liquidity --token-a <addr> --token-b <addr>
                        --amount-a <u256> --amount-b <u256>
                        --to <addr> --deadline <u64>

bloom dex swap --in <addr> --out <addr>
               --amount-in <u256> --min-out <u256>
               --to <addr> --deadline <u64>

bloom dex remove-liquidity --token-a <addr> --token-b <addr>
                           --liquidity <u256>
                           --to <addr> --deadline <u64>
```

All commands compile their calldata via each target petal's
`abi::call::*` module (emitted by the `contract!` macro in the petal
crate) and submit `Call` txs via the existing chain RPC. The
historical `bloom-dex-abi` aggregation crate has been deleted in
favour of importing directly from `bloom-dex-factory`,
`bloom-dex-pair`, `bloom-dex-router`, `bloom-dex-erc20`, and
`bloom-dex-wloom`.

## 12. Interaction with bloom-chain

The DEX touches **no** chain-internal modules. It only relies on:

- `Deploy` and `Call` tx kinds (chain spec §7.1).
- Address derivation (§7.7).
- The chain-mode host imports surface (§7.6) — specifically
  `state.read`, `state.write`, `petal.call` (with `value_loom`),
  `petal.return`, `petal.revert`, `block.number`,
  `block.timestamp`, `msg.sender`, `msg.value`, `msg.calldata.*`,
  `log.emit`, `crypto.blake3`.
- Fuel pricing (§7.9). The pair's `swap` is the hot path; it
  performs ≤ 7 `state.read` + 4 `state.write` ops plus the
  arithmetic, well under the 30M-fuel block cap.

The DEX additionally relies on `host.deploy` (chain spec §7.6) for
the factory's pair deployment path. That import is now part of the
v0 chain surface; see §5.2 / §5.4.

## 13. Storage layout under bloom_home

DEX-specific artefacts (kept separate from chain state, which
lives in `<bloom_home>/chain/`):

```
<bloom_home>/chain/dex.toml
  factory     = "blm1..."
  router      = "blm1..."
  wloom       = "blm1..."
  pair_petal  = "blake3-hex"
  erc20_petal = "blake3-hex"
```

This file is produced by `bloom dex deploy-suite` and consumed by
all other `bloom dex …` subcommands. v0 keeps it user-local; v1
will publish it via the chain itself.

## 14. v0 acceptance

Drives the chain spec's §15 acceptance test
(`tests/chain/dex_demo.rs`):

1. **Suite deploy.** `bloom dex deploy-suite` succeeds, writing
   `dex.toml`. `factory.all_pairs_length() == 0` initially.
2. **Token deploy.** Two ERC-20 petals `A` and `B` deployed with
   `total_supply = 1_000_000 * 10^18` each, sent to a test
   account `U0`.
3. **Pair creation.** `bloom dex create-pair --token-a A --token-b
   B` results in `factory.get_pair(A, B) == factory.get_pair(B, A)
   == P`. `pair.token0() < pair.token1()` (sorted).
   `pair.factory() == factory`. `pair.get_reserves() == (0, 0, _)`.
4. **Initial liquidity.** `add_liquidity(A, B, 1e21, 1e21, 0, 0,
   U0, deadline)` returns `liquidity > 0`. LP balance of `U0` is
   `sqrt(1e21 * 1e21) - 1000 = 1e21 - 1000`. The 1000 lockup is
   held by the zero address.
5. **Swap.** `swap_exact_tokens_for_tokens(1e18, 0, [A, B], U0,
   deadline)` returns the v2 formula output `≈ 9.96e17` (after
   0.3 % fee). Post-swap reserves satisfy
   `r_a' * r_b' ≥ r_a * r_b` (CPMM invariant up to fee).
6. **Remove liquidity.** `remove_liquidity(A, B, lp_balance / 2,
   0, 0, U0, deadline)` returns roughly half of each reserve
   (within rounding). Total supply of LP token drops accordingly.
7. **LOOM accounting.** Per chain spec §15.5,
   `sum(account.loom) + sum(pending_fees) =
   sum(genesis allocations) + 10 LOOM * blocks_produced`. The
   wLOOM wrap/unwrap path is exercised by an additional pair
   `(A, wLOOM)` in the same test and must preserve this identity.
8. **Reentrancy.** A malicious test token that re-enters
   `pair.swap` from inside its `transfer` callback **reverts** the
   outer swap. (Test-only; the standard `bloom-dex-erc20` never
   does this.)
9. **Determinism across validators.** All four validators agree
   on the post-test `state_root` at the final block.

## 15. Open questions / future work

- **~~Petal-initiated deploys (§5.4, option B).~~** Resolved: v0
  ships `host.deploy` (chain spec §7.6), and the factory uses it
  directly in `create_pair`. See §5.2 / §5.4.
- **`feeTo` reactivation.** When score-weighted LOOM emission
  lands (chain v1+), routing a slice of swap fees to the petal-
  scoring system is the natural fit. v0 leaves `k_last` written
  so the migration is non-disruptive.
- **TWAP oracle.** Re-enabling `price0CumulativeLast` /
  `price1CumulativeLast` is one extra `state.write` per swap;
  cheap, but no consumer yet.
- **Router multi-hop.** v0 supports an N-hop path but expects the
  caller to assemble it; on-chain `get_amounts_out` is omitted to
  keep router stateless. Trivial to add later.
- **Fee-on-transfer compatibility.** Pair's reserve accounting
  assumes balance deltas match transfer amounts. Supporting
  rebasing or fee-on-transfer tokens requires the v2 `swap`
  "balance after / before transferFrom" pattern; out for v0.
- **Selector collisions.** 4-byte BLAKE3 prefixes have ~1-in-4-
  billion collision chance per pair of selectors. v0 enumerates
  all selectors at build time and asserts uniqueness; if a
  collision appears we either rename or widen to 8 bytes (would
  require updating §4).
