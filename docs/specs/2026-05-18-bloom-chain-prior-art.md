# bloom-chain prior-art notes

**Status:** memo
**Date:** 2026-05-18
**Source:** `/Users/joshua/code/bloom` (sibling worktree)
**Addresses:** Inputs for the implementation of the bloom-chain v0
specs ([chain](2026-05-18-bloom-chain-design.md),
[DEX](2026-05-18-bloom-dex-design.md)). Distilled from four
parallel read-only audits of the sibling codebase. **The specs are
canonical**; this memo records what is worth lifting and what is
not. If a memo claim and a spec claim disagree, the spec wins.

## 1. Identity / xDSA / keystore (`crates/bloom-identity`)

**Adopt:**
- `darkbio-crypto` (v0.15, with `xdsa` feature) as the composite
  ML-DSA-65 + Ed25519 signer. Pinned to `ml-dsa = 0.1.0-rc.7`.
  The crate gives `SecretKey::generate`, `SecretKey::sign(&[u8])`,
  `PublicKey::verify(&[u8], &Signature)`, plus `to_bytes` /
  `from_bytes` round-trips for both keys and signatures.
- The `Identity` wrapper (gen → sign → verify) shape is a clean
  facade — mirror it in `bloom-keystore`.
- Encrypted keystore on disk: **CBOR envelope with Argon2id
  (m_cost = 65536, t_cost = 3, p_cost = 4) + XChaCha20Poly1305**.
  Format:
  ```
  Envelope { version, kdf: { alg, m_cost, t_cost, p_cost, salt },
             cipher: { alg, nonce, ciphertext }, pubkey }
  ```
  Plaintext = `secret_bytes || public_bytes`. Pubkey kept
  unencrypted for fast reads.
- BLAKE3-based fingerprint: `fp = blake3(pubkey_bytes)[..32]`,
  displayed via z-base-32 (52 chars). bloom-eth address derivation
  (chain spec §4.3) is the same shape — same constant.

**Pass:**
- The sibling's bloom-specific `Domain` enum (File, Tombstone,
  Handshake, Block, Tx, Genesis). The chain spec uses its own
  domain-tagged BLAKE3 (`addr:`, `tx:`, `block_header:`,
  `state_blob:`, …). Use the **pattern**, not the enum.
- `Zeroize` is **not** implemented on `darkbio-crypto::SecretKey`.
  Wrap secrets in our own owned-bytes type with manual `Drop`, or
  file an upstream PR. Spec says: keystore must zeroize on drop.
- Opaque `PUBLIC_KEY_SIZE` / `SECRET_KEY_SIZE` / `SIGNATURE_SIZE`
  constants. Re-export as `bloom_keystore::xdsa::{PK_LEN, SK_LEN,
  SIG_LEN}` so callers don't depend on the upstream crate path.

**Source files of interest:**
- `crates/bloom-identity/src/identity_impl.rs`
- `crates/bloom-identity/src/fingerprint.rs`
- `crates/bloom-identity/src/keyfile.rs`
- `crates/bloom-identity/src/digest.rs`

## 2. Chain consensus + state (`crates/bloom-chain`)

**Adopt:**
- `SignedTx` envelope shape: `(Tx, author_fingerprint, pubkey,
  sig)` — clean separation, encoding-agnostic. We change the
  encoding (SSZ instead of CBOR) but keep the structure.
- Domain-separated digest pattern for tx hashes and block hashes.
- Block pre-sign / post-sign digest distinction: `signing_digest`
  vs. `block_hash`. The chain spec already does this (`block_hash
  = blake3("block_header:" || ssz_encode(header))`) — mirror the
  helper layout.
- **Snapshot-and-commit** state application: clone the live state,
  apply all txs in a block to the scratch copy, swap atomically
  on success. (sibling: `ledger.rs:124–136`.) Maps cleanly onto
  the chain spec's `apply_block(state) -> NewState` shape.
- Validator seal-loop knobs: `max_batch` (1000 txs) and
  `seal_window` (500 ms) as proposer-level batching parameters.
  Reuse the defaults; tune later.

**Pass:**
- Single-validator architecture; no propose / prevote / precommit
  rounds; no locking. Tendermint-style BFT must be written fresh.
- CBOR (`ciborium`) encoding. Spec mandates SSZ.
- Flat `BTreeMap` state. The chain spec uses sparse-Merkle tries
  over BLAKE3 with a separate state-blob store.
- File-per-block persistence. v0 chain uses RocksDB or sled under
  `<bloom_home>/chain/` (see chain spec §14).
- The sibling's `Tx` variants (Mint, RegisterFile, Stake, Use,
  PublishPetal, StakePetal, UsePetal, ChallengePetal). Replaced
  by chain spec §7.1's `Transfer` / `Deploy` / `Call`.

**Source files of interest:**
- `crates/bloom-chain/src/{block,tx,signed_tx,state,ledger,genesis}.rs`
- `crates/bloom-chain-net/src/validator.rs` (seal loop, lines ~92+)

## 3. Networking (`crates/bloom-net` + `crates/bloom-chain-net`)

**Adopt:**
- **Length-prefixed framed codec.** 4-byte big-endian `u32`
  length + payload, max 16 MiB. Encoding-agnostic — swap CBOR
  for SSZ on the body. (sibling: `proto/codec.rs`.)
- **`WireMessage` trait** with `tag()` + `is_known_tag()` for
  forward-compatible unknown-tag handling (sibling silently
  skips unknown tags rather than erroring). Use the same shape
  in `bloom-chain-types`.
- **`ChainMsg` enum.** The sibling already enumerates the right
  set: `ChainHello`, `GetTip` / `Tip`, `GetBlocks` / `Block` /
  `BlocksErr`, `BlockAnnounce`, `SubmitTx` / `Ack` / `Err`,
  `GetPetalBytes` / `PetalBytes` / `NotAvailable`, `Bye`. The
  state-blob fetch in chain spec §6.3 maps onto
  `GetPetalBytes`/`PetalBytes` with the name changed.
- **xDSA handshake state machine.** Hello / HelloChallenge /
  HelloResponse, signature over `blake3("handshake:" ||
  nonce_c || nonce_s)`. Identity-only, no TLS coupling — reuse
  verbatim once the underlying transport is TCP not QUIC.
- **peers.toml static config**: `{ fingerprint, address,
  optional pubkey_path }` per peer. Suffices for v0 validator
  set; future bootstrap discovery is additive.
- **Chunked content-addressed fetch**: `GetPetalBytes` → ≤ 4 MiB
  reply, BLAKE3-verified on receipt, retried with exponential
  backoff on `NotAvailable`. Direct fit for chain spec §6.3
  state-blob fetch.
- **Validator broadcast pattern**: maintain a session map,
  fire-and-forget `BlockAnnounce` to every entry. (sibling:
  `chain-net/src/validator.rs`.) For BFT we'll also need
  proposal + vote broadcast, but the session-map plumbing
  carries over.
- **Follower catch-up loop**: chunked `GetBlocks` (1000 at a
  time) on `BlockAnnounce` notification.

**Pass:**
- **Quinn / QUIC.** Strip out the QUIC endpoint, `AcceptAnyCert`
  shim, and ALPN handling. v0 chain spec mandates plain TCP with
  the same framing pattern (so the codec stays, the socket
  changes).
- TLS cert generation — gone with QUIC.
- ALPN version negotiation — replace with a 4-byte magic + 4-byte
  protocol-version prefix at the start of each TCP stream.

**Source files of interest:**
- `crates/bloom-net/src/{proto/codec.rs,handshake.rs,peers/config.rs}`
- `crates/bloom-chain-net/src/{proto.rs,session.rs,validator.rs,
  follower.rs,bytes_fetch.rs}`

## 4. Petal runtime + content store (`crates/bloom-petal`, `crates/bloom-store`)

**Adopt:**
- **Wasmtime v25** with this deterministic config:
  ```
  consume_fuel = true
  wasm_simd = false
  wasm_relaxed_simd = false
  wasm_multi_memory = false
  wasm_bulk_memory = true
  // no WASI, no epoch interruption, no async
  ```
  Pin the version workspace-wide in `Cargo.toml`. Matches chain
  spec §7.5 pinning requirement.
- **ABI pattern**: input buffer at `in_ptr` of length `in_len`,
  output buffer at `out_ptr` of capacity `out_cap`, return value
  `i32` = bytes written or negative error. Lifts directly into
  the chain spec's `call(calldata_ptr, calldata_len) -> i32` +
  the host-side `msg.calldata.*` imports.
- **`abi.rs` helpers**: `write_guest(mem, store, ptr, bytes)`
  and `read_guest(mem, store, ptr, len)` for safe linear-memory
  copies. Reuse as the building blocks for every chain-mode
  host import.
- **Empty `Linker<...>` as the base.** The chain mode's
  `link_chain_imports()` adds host functions on top of the same
  empty starting point used here. (Sibling uses an empty linker
  for adjudication; we'll diverge by adding imports.)
- **Single global fuel cap per instantiation.** `store.set_fuel(N)`
  before `call`, then read `store.get_fuel()` after for actual
  consumption. The per-import fuel surcharge (chain spec §7.9)
  is layered on top — subtract the surcharge from `get_fuel`
  inside each import callback before doing native work.
- **BLAKE3** as the hash function everywhere — already a
  dependency in the sibling (`blake3 = "1"`).
- The **adjudicate dual-module pattern** (code + check wasm,
  separate fuel pools) is a useful future shape for v1+ challenge
  / invariant verification. v0 does not use it.

**Pass:**
- The sibling's hard limits (`PETAL_FUEL = 10M`, `CHECK_FUEL =
  1M`, `MAX_LINEAR_MEMORY_BYTES = 16 MiB`, input/output 64 KiB)
  are useful **defaults** but the chain spec sets its own
  per-tx caps (`fuel_limit = 30M` per block, calldata size is
  encoded inside the SSZ tx and bounded only by the block fuel
  budget). Keep memory + linear-memory caps as a baseline.
- **`bloom-store`'s file/namespace layout** (per-fingerprint
  directories, `.sig` / `.tomb` / `.pubkey` sidecars, mtime TTL
  GC). bloom-chain state goes into a separate Merkle-trie KV
  store plus the state-blob store. The signed sidecar pattern is
  not needed because chain state is authenticated by the state
  root in each block.
- The sibling's no-imports invariant. Chain mode breaks it by
  design — that's the entire point of `state.read/write`,
  `petal.call`, etc.
- Sibling's lack of nested calls. Chain mode needs synchronous
  nested `petal.call`s with a depth cap of 16 (chain spec §16).

**Source files of interest:**
- `crates/bloom-petal/src/{host,execute,adjudicate,validate,abi,limits}.rs`
- `crates/bloom-store/src/store/{layout,sig,local}.rs`

## 5. Net effect on the implementation tasks

| Task | What this memo unblocks |
|------|--------------------------|
| `bloom-keystore` xDSA port | Dep choice (`darkbio-crypto`), keystore envelope shape, fingerprint formula, zeroize follow-up. |
| `bloom-chain-types` | `SignedTx` shape, framed-codec wire format, `WireMessage` trait pattern, `ChainMsg`-style top-level enum. |
| `bloom-chain-state` | Snapshot-and-commit shape; no trie code to lift — that part is net-new. |
| `bloom-chain-consensus` | **Net-new code.** Sibling is single-validator; locking rule + 2f+1 quorum + proposer rotation must be written fresh. Seal loop's batch/window knobs survive. |
| `bloom-petals` chain-mode imports | Wasmtime config, linker scaffolding, ABI helpers (`abi.rs`), fuel-meter integration point. |
| `bloom-chain-node` networking | Framed codec, xDSA handshake, peers.toml, validator broadcast and follower catch-up patterns. Strip Quinn/QUIC; substitute plain TCP. |

## 6. Watch-list (deferred follow-ups)

- **Wasmtime v25 longevity.** If upstream drops support before
  bloom-chain mainnet, we trigger the epoch upgrade reserved in
  chain spec §7.5. Track wasmtime release notes.
- **`darkbio-crypto` upstream Zeroize PR.** File it; until then,
  bloom-keystore handles secret zeroization in our wrapper.
- **Sibling's `ChallengePetal` workflow** is the seed of the
  invariant/pruning system listed in chain spec §16 follow-ups.
  Not for v0, but worth knowing it exists.

## 7. Implementation notes (post-build addenda)

Addenda recorded after the v0 crates landed. Each entry is a
deviation from §1–§5 above that future readers should be aware of.

- **xDSA crate choice landed on direct deps, not `darkbio-crypto`.**
  `darkbio-crypto 0.15` resolves to `ml-dsa = 0.1.0` on crates.io
  but fails to compile because it calls `SigningKey::to_expanded()`
  and `sign_deterministic()`, which were renamed/removed before
  `ml-dsa 0.1.0`'s final release. Fell back to
  `ml-dsa = "0.1.0"` + `ed25519-dalek = "2"` directly.
  Composite layout: pk = 1984 B (1952 ML-DSA + 32 Ed25519),
  sig = 3373 B (3309 ML-DSA + 64 Ed25519).
- **No separate `SignedTx` type.** `bloom-chain-types::tx::Tx` is
  itself the signed envelope (it contains `pubkey` + `sig`).
  `Tx::signing_digest()` excludes the `sig` field; that is what
  the xDSA key signs. The prior-art memo's "envelope shape (Tx,
  fingerprint, pubkey, sig)" is implemented inline in `Tx`.
- **v0 trie is a sorted-entry BLAKE3 commitment, not a 256-ary
  SMT.** `bloom-chain-state::trie::Trie` uses a `BTreeMap`-backed
  sparse store and computes `root() = blake3_tagged(domain,
  count_u64_le || (key || blake3(value))*)` over sorted entries.
  Documented as a v1 swap-in behind the same `Trie::root()` API.
  The spec language ("sparse Merkle tree") stays — v0 just
  satisfies the determinism/diffability properties without the
  full SMT depth.
- **`validator_set:` BLAKE3 tag lives in `bloom-chain-consensus`,
  not `bloom-chain-types`.** The chain-types crate kept only the
  tags used in §4.4 of the chain spec; the consensus crate defines
  `TAG_VALIDATOR_SET = "bloom-chain.v0.validator_set:"` locally.
- **`STATE_BLOB` BLAKE3 tag is also not in chain-types.**
  `bloom-chain-state::blob::*` uses the `PETAL` tag as a content-
  addressed opaque-bytes hash. Cleaner would be to add a
  `STATE_BLOB` tag to chain-types in a follow-up; spec language
  doesn't require it.
- **`Action::Commit` boxes the `Block`.** `bloom-chain-consensus`
  represents the commit action as `Action::Commit(Box<Block>,
  Commit)` to satisfy Clippy's `large_enum_variant` lint without
  pessimising the steady-state. Transparent at pattern-match
  sites.
- **`host.deploy` is in v0 (added 2026-05-18).** Original chain
  spec deferred petal-initiated deploys to v1; the DEX spec
  needed deterministic CREATE2-style addressing without a two-tx
  workflow, so chain spec §7.6/§7.7/§7.9 grew a `host.deploy`
  import and the DEX spec §5.4 collapsed to a single
  `factory.create_pair` call. Pair init data is plumbed via the
  chain's standard `init` entry point (§7.8) — there is no
  separate `pair.initialize` method.
