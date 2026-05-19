# bloom-dex — a Uniswap-v2-style DEX as bloom-chain petals

**Status:** draft
**Date:** 2026-05-18
**Owners:** —
**Addresses:** The v0 application layer on top of [bloom-chain]
([2026-05-18-bloom-chain-design.md](2026-05-18-bloom-chain-design.md)).
A constant-product AMM expressed as a small set of wasm petals: an
ERC-20-shaped token petal, a pair petal, a factory petal, a router
petal, a wrapped-LOOM petal, and a reentrancy-guard helper petal. No
flash swaps, no fee-to, no on-chain governance, no oracles — that is
all v1+.

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

Six wasm petals total. Each is content-addressed by its BLAKE3 hash;
deploying instantiates `(petal_hash, instance_address)` per the
chain spec's `Deploy` tx kind.

| Petal | Crate | Role |
|-------|-------|------|
| `bloom-dex-erc20` | `crates/bloom-dex-erc20` | Generic ERC-20-shaped fungible token. Used for both test tokens and as the **base class** of `bloom-dex-pair`'s LP token (the LP token is the pair instance itself). |
| `bloom-dex-pair` | `crates/bloom-dex-pair` | Single-pair AMM. Holds reserves, exposes `mint` / `burn` / `swap` / `skim` / `sync`. Also acts as its own LP token (ERC-20 surface inlined). |
| `bloom-dex-factory` | `crates/bloom-dex-factory` | Deploys pairs deterministically. Registers `pair_address(tokenA, tokenB)`. Owns the canonical `pair` petal hash. |
| `bloom-dex-router` | `crates/bloom-dex-router` | Stateless. `addLiquidity` / `removeLiquidity` / `swapExactTokensForTokens` / `swapTokensForExactTokens`, plus their `*ETH` variants over wrapped LOOM. |
| `bloom-dex-wloom` | `crates/bloom-dex-wloom` | Wrapped native LOOM. `deposit` (payable, mints), `withdraw` (burns, sends native). Mirrors WETH9 semantics. |
| `bloom-dex-reentrancy` | `crates/bloom-dex-reentrancy` | Library petal with a single guarded-call helper. The pair's `mint` / `burn` / `swap` route through it. (See §8.) |

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
- `bytes` (variable-length tail, used only by
  `reentrancy.enter`) = raw remainder of calldata, no length
  prefix; chain spec §7.10.1 restricts it to the LAST
  positional argument of a method.

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

**Reentrancy** (`bloom-dex-reentrancy`):
- `reentrancy.enter(address callee, bytes calldata)` — sets a
  lock slot, forwards via `petal.call`, clears the lock on
  return. Reverts if already locked. (See §8.)

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
single tx-level `Deploy` whose `init_args` is exactly 128 bytes of
zero (`token0 = token1 = reentrancy = self = 0x00..`). Pair `init`
tolerates a zero-only payload — it writes zero slots to the
bootstrap instance, leaves reserves at zero, and never gets called
again because `create_pair` derives a different address for every
real (tokenA, tokenB) deployment. The resulting bootstrap instance
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

**init calldata:** `token0 (32B) || token1 (32B) || reentrancy_addr (32B) || pair_self_addr (32B)` — 128 bytes, no fallback.
The factory pre-computes `pair_self_addr` via chain spec §7.7 before calling `host.deploy`.
The pair stores `pair_self_addr` in `K_SELF` so it can call `token.balanceOf(self)`
(the chain has no `msg.self` host import).

| Slot | Key | Value |
|------|-----|-------|
| `token0` | `blake3("pair.token0")` | Address (32 bytes) |
| `token1` | `blake3("pair.token1")` | Address |
| `reentrancy` | `blake3("pair.reentrancy")` | Address |
| `self` | `blake3("pair.self")` | Address — this petal's own address |
| `reserve0` | `blake3("pair.reserve0")` | u128 (left-padded to 32) |
| `reserve1` | `blake3("pair.reserve1")` | u128 |
| `k_last` | `blake3("pair.k_last")` | u256 (kept for future feeTo; always written but read-only in v0) |
| `lock` | `blake3("pair.lock")` | u8 (0/1) — reentrancy guard; set/cleared by `bloom-dex-reentrancy` via internal selectors |

**Internal selectors** (callable only by the reentrancy petal, registered in `bloom-dex-abi`):
- `pair.lock_check_and_set()` — reverts `"pair: locked"` if lock==1, otherwise sets lock=1.
- `pair.lock_clear()` — unconditionally clears lock=0.
- `pair._mint_inner(address)` — mint inner logic (LP issuance).
- `pair._burn_inner(address)` — burn inner logic (LP redemption).
- `pair._swap_inner(u256,u256,address)` — swap inner logic (k-invariant check).

`get_reserves` packs `reserve0` (u128, 16 bytes), `reserve1` (u128,
16 bytes), and the current `block.timestamp` low 64 bits into one
return slot for cheaper reads.

### 6.3 Factory (`bloom-dex-factory`)

**init calldata:** `pair_petal_hash (32B) || reentrancy_addr (32B) || fee_to_setter (32B) || factory_self_addr (32B)` — 128 bytes, no fallback.
`factory_self_addr` is the factory's own pre-computed CREATE2 address, stored in `K_SELF`.
The factory uses `K_SELF` in `createPair` to pre-compute the pair address via chain spec §7.7
before calling `host.deploy`, so the pair's 128B init calldata can include `pair_self_addr`.

`createPair` builds 128B pair init: `t0 || t1 || reentrancy_addr || pair_address` where
`pair_address = blake3("bloom-chain.v0.addr:deploy:" || factory_self || ":" || salt || ":" || pair_petal_hash)`.

| Slot | Key | Value |
|------|-----|-------|
| `pair_petal_hash` | `blake3("factory.pair_petal_hash")` | bytes32 |
| `reentrancy` | `blake3("factory.reentrancy")` | Address |
| `fee_to` | `blake3("factory.fee_to")` | Address (zero in v0) |
| `fee_to_setter` | `blake3("factory.fee_to_setter")` | Address |
| `self` | `blake3("factory.self")` | Address — factory's own address |
| `get_pair(t0,t1)` | `blake3("factory.pair:" \|\| t0 \|\| t1)` | Address (zero if unset) — stored for both orderings |
| `all_pairs_length` | `blake3("factory.all_pairs.len")` | u64 |
| `all_pairs[i]` | `blake3("factory.all_pairs:" \|\| u64_be(i))` | Address |

### 6.4 Wrapped LOOM (`bloom-dex-wloom`)

Same as ERC-20 §6.1, with `name = "Wrapped LOOM"`, `symbol =
"wLOOM"`, `decimals = 18`. `deposit` increments
`balance_of(msg.sender)` and `total_supply` by `msg.value`.
`withdraw` does the reverse and triggers a native LOOM transfer
(see §7).

### 6.5 Reentrancy guard (`bloom-dex-reentrancy`)

**init calldata:** none — stateless petal, no constructor parameters.

**init calldata for router (`bloom-dex-router`):**
`factory_addr (32B) || wloom_addr (32B) || router_self_addr (32B)` — 96 bytes, no fallback.
The 64-byte form is rejected with `"router: bad init"`. The `deploy-suite` CLI MUST
pass 96 bytes with the router's CREATE2-precomputed address as the third field.
`router_self_addr` is required for LOOM-output swaps which temporarily receive
wLOOM into the router before unwrapping it to native LOOM.

The lock slot is held by the **pair** at `blake3("pair.lock")`. The reentrancy
petal is a stateless orchestrator — it owns no storage. It acquires and releases
the lock by calling back into the pair's internal selectors:
- `pair.lock_check_and_set()` — first call on entry; reverts if lock already set.
- `pair.lock_clear()` — called on the success path to release.

This keeps the lock per-pair without cross-pair contention and avoids state in
the reentrancy petal itself.

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
`burn`, and `swap`. We replicate this without a modifier system.

**Lock state lives in the pair** (`blake3("pair.lock")`). The
reentrancy petal is a stateless orchestrator — all lock reads/writes
happen inside the pair via internal selectors registered in `bloom-dex-abi`.

### 8.1 Enter flow

1. On entry to `pair.mint` / `pair.burn` / `pair.swap`, the pair
   re-encodes the request as an inner selector (e.g. `pair._mint_inner`)
   and calls `reentrancy.enter(self_addr, inner_calldata)` via `petal.call`.
2. The reentrancy petal (`bloom-dex-reentrancy`):
   a. Verifies `msg.sender == target` — only the pair may call `enter` for itself.
   b. Calls `pair.lock_check_and_set()` on the pair. That internal selector
      reverts `"pair: locked"` if `lock == 1`, otherwise atomically sets
      `lock = 1`.
   c. Calls `target` with `inner_calldata` — forwarding to `pair._mint_inner`,
      `pair._burn_inner`, or `pair._swap_inner`. Any revert from the inner
      call propagates out of `enter`.
   d. On success, calls `pair.lock_clear()` to set `lock = 0`.
3. Any reentrant `petal.call` chain back into the same pair's public
   entry point that calls `enter` again will hit `lock_check_and_set`
   and revert `"pair: locked"`.

### 8.2 v0 revert behaviour (known limitation)

WASM reverts unwind stack frames synchronously. If the inner call in
step 2c reverts, control propagates out of `enter` and `lock_clear`
(step 2d) is **skipped**. However, this is safe in v0 because each
transaction is atomic: a revert rolls back ALL state changes for the
tx, including the `lock_check_and_set` write. So the lock is never
durably persisted after a failed transaction.

The `petal.call` depth cap of 16 (chain spec §16) is a backstop;
the per-pair lock is the primary defence.

v1 will add `host.try_call` for a finally-clause pattern so that
`lock_clear` fires even on inner reverts, making lock-release
unconditional regardless of tx revert semantics.

### 8.3 Internal selector registry

The five internal selectors live in `bloom-dex-abi::selectors` (registered
in `bloom-dex-abi/build.rs`) so both the pair and the reentrancy petal
reference the same compiled constants:

| Constant | Method string |
|----------|---------------|
| `PAIR_LOCK_CHECK_AND_SET` | `pair.lock_check_and_set()` |
| `PAIR_LOCK_CLEAR` | `pair.lock_clear()` |
| `PAIR_MINT_INNER` | `pair._mint_inner(address)` |
| `PAIR_BURN_INNER` | `pair._burn_inner(address)` |
| `PAIR_SWAP_INNER` | `pair._swap_inner(u256,u256,address)` |

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

Each petal emits logs via `log.emit` (chain spec §7.6). Topics are
4-byte BLAKE3 selectors of the event signature; topic and data
encoding mirror Solidity logs at the surface level so a client SDK
can decode them with the existing eth log shape.

ERC-20:
- `Transfer(address from, address to, u256 value)`
- `Approval(address owner, address spender, u256 value)`

Pair:
- `Mint(address sender, u256 amount0, u256 amount1)`
- `Burn(address sender, u256 amount0, u256 amount1, address to)`
- `Swap(address sender, u256 a0in, u256 a1in, u256 a0out, u256 a1out, address to)`
- `Sync(u128 reserve0, u128 reserve1)`

Factory:
- `PairCreated(address token0, address token1, address pair, u64 index)`

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

All commands compile their calldata via `bloom-dex-abi` (a small
crate that mirrors §4 in Rust) and submit `Call` txs via the
existing chain RPC.

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
