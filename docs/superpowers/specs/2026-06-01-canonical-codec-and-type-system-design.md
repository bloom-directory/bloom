# Canonical Value Codec & Rich Type System — Design

**Date:** 2026-06-01
**Status:** Approved design (pre-implementation; amended after codebase validation)
**Scope:** Bloom-native value/object serialization and the petal type-description language. Does **not** touch the SSZ transaction/block envelope or the EVM-side crates. Consensus-adjacent PTB admission/execution code **is in scope** where it validates or interprets Bloom-native value bytes.

---

## 1. Problem

Bloom currently has **five divergent, hand-written byte codecs** for its own value/object data, and they only interoperate by author discipline:

1. `bloom-objects/src/codec.rs` + `type_tag.rs` — "type system" codec (manifest, `TypeTag`). Strings = **2-byte** BE length prefix.
2. `bloom-resource/src/abi.rs` (`ArgReader`/`RetWriter`, `CallArgsWriter`/`Reader`) — function args/returns + framed PTB calldata. Strings/bytes = **4-byte** BE length prefix.
3. `bloom-script/src/abi_json.rs` — JSON ⇄ canonical bytes for RPC/CLI/views. Strings = 2-byte; vectors only fixed-width elements; its own `fixed_width` table.
4. `bloom-vfs/src/petals_handler.rs` — bespoke manifest-driven payload walker for display. Strings = 2-byte; `Coin` hardcoded as 48 bytes; vectors fixed-width only; **does not know `UID`**; silently falls back to `{"hex": ...}` on any mismatch.
5. Petals hand-roll their own payload codec (e.g. `bloombook` `StateWriter`/`StateReader` at 2-byte to match the VFS; `bloom-petal-fungible` `coin_payload` via `RetWriter`).

### Root cause
Encoding is **defined five times and enforced zero times**. The schema (manifest / `TypeTag`) exists but does not *drive* a single codec. `#[object]` records field name+type into the manifest but generates **no** encode/decode; `object_create(type_tag, payload)` takes opaque bytes that nothing checks against the manifest.

### Concrete defects this produces
- **String/bytes width disagreement** (2-byte/raw vs 4-byte) is a *live latent bug*: `validate_canonical_bytes` validates `String` as 2-byte, `ArgReader::read_string`/`read_bytes` decode 4-byte, while `abi_json` treats `bytes` and lowercase `string` as raw/unframed and `String` as 2-byte-prefixed. A petal with a `String`, `string`, or `bytes` argument can break today; it only has not bitten because shipped petals avoid this path or hand-roll payload codecs. `bloombook` sidesteps it with a bespoke 2-byte codec.
- **No payload↔manifest guarantee.** The FS "just works" only if the author serializes in exactly the order/width the VFS guesses.
- **`UID` is a blind spot.** `id: UID` lowers to `TypeTag::Concrete { type_name: "UID" }`, but no `fixed_width` table recognizes `UID` — only `ObjectId`/`Address`/`Hash32`/`address`.
- **`Coin` is special-cased** as 48 bytes (`ObjectId(32) || u128(16)`) with a redundant zero id prefix.
- **Partial + silent decoders.** No `vector<String>`, no variable-width vector elements; decode failures degrade to `{"hex": ...}` so a real layout bug is indistinguishable from "data we chose not to decode," and one bad field poisons all later fields in the same struct.
- **Massive duplication** of derived helpers: `substitute_type_args` ×4, `fixed_width`/`primitive_size_hint` ×3, `type_tag_label` ×4, and `marshal_args`/`unmarshal_outputs` is a full reimplementation of `CallArgsWriter`/`Reader`.

### The north star
Make encode/decode work *at least* as well as Ethereum ABI / ethers / alloy — given a type schema and bytes, mechanically produce human-readable values and the exact inverse — but **without ABI's mistakes**, and supporting a rich, deterministic, arbitrary type system.

---

## 2. Goals & non-goals

### Goals
- **One canonical value codec**, driven by the type schema, used by: object payloads, function args/returns, JSON lowering, and VFS display.
- A **rich algebraic type system** petals can use to declare arbitrary *deterministic* data structures.
- **`#[object]` (and `#[capability]`) generate payload encode/decode** so payloads match the manifest *by construction*; petals stop hand-rolling codecs.
- **Validate payloads at the chain boundary** (`object_create` / `object.mutate`) — reject bytes that don't cleanly decode against the declared schema.
- **Collapse the duplicated helpers** into the one codec / one type-resolution module.
- Decode failures are **hard errors**, not silent hex.

### Non-goals
- No backward compatibility / migration. **Bloom has never been deployed; there is no persistent state to preserve** (see memory `bloom-predeployment-clean-break`). We clean-break: pick the best design, regenerate genesis, delete legacy paths.
- Do **not** change the SSZ transaction/block envelope (`bloom-chain-types/src/tx.rs`, block serialization). `TxKind::SubmitPtb` continues to wrap opaque PTB bytes.
- Do **not** change the PTB structural envelope unless explicitly called out by a follow-up spec. `bloom-script/src/encode.rs` `encode_ptb`/`decode_ptb`, the per-arg `CallArgs` envelope, and return-slot framing may keep their outer counts/tags/lengths; the **value bytes inside** `Const`/`Use`/return slots change to the new codec.
- Do **not** touch the EVM-side crates (`bloom-defi`, `bloom-ens`, `bloom-etherscan`, `bloom-prices`, `bloom-watch`) — they use `alloy`/`bloom-chain-abi` and have zero dependency on these codecs.
- No new self-describing/standalone-decodable wire format (see §4 rationale).

---

## 3. The type system (data model)

Petals can declare arbitrary **deterministic algebraic data types**, all delivered in this effort (full system, not phased):

**Scalars:** `bool`, `u8`, `u16`, `u32`, `u64`, `u128`; `Address`, `ObjectId`, `Hash32` (all 32-byte); `UID` (alias of the 32-byte object id — see §6).
**Byte/text:** `bytes`, `String` (UTF-8).
**Product types:** structs (named, via declarations) and tuples `(A, B, …)`; freely **nested** up to bounded value/schema depth.
**Sum types:** `enum` with named variants, each carrying zero or more fields (unit / tuple / struct variants); `Option<T>` and `Result<T, E>` are ordinary enums.
**Collections:** `vector<T>` for **any** `T` (variable-width elements allowed); `map<K, V>` and `set<T>` with **canonically sorted keys** and duplicate rejection.

Recursive type declarations are **not generally allowed** in this version. Because the value codec is inline and has no pointer/box/indirection type, direct cycles such as `struct Node { next: Node }` are unencodable. The manifest validator rejects structural declaration cycles unless a future explicit indirection type is introduced. The decoder still enforces bounded value nesting for acyclic but deeply nested values such as `vector<vector<...>>`.

### 3.1 How types are represented

`TypeTag` stays the **type *identity*** (content-addressed name), unchanged in spirit: `Concrete { petal_hash, type_name, type_args }`, `Generic { idx }`, `External { ref_idx }`. We do **not** bloat `TypeTag` with structural bodies, because its canonical hash feeds `ObjectId` derivation and cross-petal identity.

The **structural definition** of a type lives in its **declaration** in the manifest:
- `ObjectTypeDecl` (existing) and a new `EnumTypeDecl` / `DataTypeDecl` carry the field/variant lists (`FieldDecl { name, ty: TypeTag }`, plus a variant list for enums).
- **Built-in container & primitive types** (`vector`, `map`, `set`, `tuple`, `Option`, `Result`, the scalars, `String`, `bytes`) are recognized by the codec as well-known `TypeTag::Concrete` names with `type_args` — exactly how `vector<T>` already works. These need no per-petal declaration.

So the codec resolves a `TypeTag` to a structural shape via: (a) the fixed built-in set, then (b) the manifest's declarations (`tag_hash == petal_hash` → look up the named decl). This keeps `TypeTag` small while making the type language rich.

Built-in representation is now locked: all built-ins are `TypeTag::Concrete { petal_hash: BUILTIN_TYPE_HASH, type_name, type_args }`, where `BUILTIN_TYPE_HASH` is a single reserved 32-byte constant documented in code. `petal_hash == [0; 32]` remains only a macro-time "self petal" sentinel and must be stamped/resolved before stored values or validator-visible manifests depend on it. User-defined declarations may not use reserved built-in names. `External { ref_idx }` must be resolved through the full manifest's `external_type_refs` table before structural decoding.

Built-in arities:
- `vector<T>`: one type arg.
- `map<K, V>`: two type args.
- `set<T>`: one type arg.
- `tuple<T0, ... Tn>`: `n` type args; `tuple<>` is the unit tuple.
- `Option<T>`: one type arg; equivalent to built-in enum variants `None`, `Some(T)`.
- `Result<T, E>`: two type args; equivalent to built-in enum variants `Ok(T)`, `Err(E)`.
- Scalars, `String`, `bytes`, `UID`, `Address`, `ObjectId`, `Hash32`: zero type args.

### 3.2 Manifest schema changes
- Add variant/field structural data for enums (`EnumTypeDecl` or an extended `ObjectTypeDecl` kind).
- `CapabilityDecl` currently has **no `fields`** — add `fields: Vec<FieldDecl>` so capabilities get a derived codec like objects.
- Add plain data declarations for `#[derive(BloomType)]` structs/enums that are not on-chain objects. The macro/type classifier must distinguish these from `#[object]` types; today uppercase path types are treated as object arguments, which would misclassify data structs.
- Bump `SCHEMA_VERSION` (currently 2; codec also accepts v1). Because of the clean break we may **drop the v1 path entirely** and set a single current version.
- Golden manifest byte tests (`snapshot_minimal_first_bytes`, the legacy-v1 fixture in `view_function_manifest.rs`) will be regenerated.
- The validator-facing `PetalManifestStub` is not enough for payload validation because it drops field/variant structure. Chain-boundary validation must receive or be able to fetch the **full decoded manifest** and resolve external refs/generics against it.

---

## 4. The wire format (the canonical value codec)

**Model:** schema-driven, **non-self-describing**, bijective — BCS (Sui/Aptos) / Borsh (Solana) class, *not* Ethereum ABI's flavor.

**Why not self-describing (CBOR/protobuf):** consensus hashes payloads into the state root, so the encoding must be **bijective** (exactly one byte string per logical value). Self-describing formats admit multiple valid encodings and force a bolted-on "deterministic mode." On a content-addressed chain the schema is always available — the `Object` already stores its `TypeTag` next to the payload — so standalone decodability buys little.

**What we keep from ABI:** the schema *is* the decoder; no per-value type tags.

**Ethereum mistakes we explicitly avoid:**
1. **32-byte word padding** → we pack tightly, no alignment padding.
2. **Head/tail relative offsets for dynamic types** → **inline length prefixes**, self-delimiting, no relative pointers.
3. **Decoder leniency** → **strict & bijective** (see rules).
4. **No sum types / Option / maps** → first-class here.

### 4.1 Encoding rules
- **Typed integers:** fixed-width, **big-endian** (matches existing `TypeTag`/manifest codecs and the `TypeTag` canonical hash; endianness is low-stakes, BE is the incumbent).
- **All lengths, sequence counts, and enum/Option/Result discriminants:** **ULEB128, minimal-form-enforced**, decoded into `u64` with a hard maximum of **10 encoded bytes**. Values that exceed the context's max (`usize`, configured sequence cap, or variant count) are rejected. This dissolves the 2-vs-4-byte string-width war — there is one length encoding everywhere, and "reject non-minimal" keeps it canonical.
- **Structs / tuples:** fields in declaration order, concatenated, no padding, no framing.
- **`vector<T>`:** ULEB128 count, then each element encoded recursively (any `T`, including variable-width).
- **`map<K,V>` / `set<T>`:** ULEB128 count, then entries with **keys sorted by their canonical encoded-key bytes**; duplicate keys rejected.
- **`enum` (incl. `Option`/`Result`):** ULEB128 variant index, then the variant's fields encoded in declaration order. `Option`: `0=None`, `1=Some(T)`.
- **`String`:** ULEB128 byte length + validated UTF-8.
- **`bytes`:** ULEB128 byte length + raw bytes.
- **Scalars 32-byte (`Address`/`ObjectId`/`Hash32`/`UID`):** raw 32 bytes.

Normative resource bounds:
- Maximum ULEB128 bytes: `10`.
- Maximum value nesting depth: `64` recursive value nodes.
- Maximum schema-resolution depth: `64` type expansions.
- Maximum vector/map/set element count: `1_000_000` unless a stricter call-site cap applies.
- Maximum value byte length for a single value slot: the existing PTB/object payload cap at the call site; the codec must accept a cap argument and reject before allocating.
- Zero-sized values are legal only as struct/tuple/enum fields. Collections of zero-sized values are rejected unless their count is `0`, preventing huge logical vectors from consuming no bytes.

### 4.2 Strict decode (bijectivity guarantees)
Decoding **rejects**: trailing bytes; non-minimal ULEB128; ULEB128 values wider than 10 bytes; counts above caps; unsorted or duplicate map/set keys; invalid UTF-8; out-of-range enum discriminants; schema cycles; recursion beyond bounded depth; lengths/counts exceeding remaining buffer; allocations above the caller-supplied byte cap.

For `map`/`set`, the decoder must strictly decode each key, re-encode the logical key with the canonical encoder, and compare adjacent re-encoded key bytes. Order is strict increasing (`prev < curr`); equality rejects duplicates. Do not compare raw consumed byte slices, because doing so can hide nested non-canonical encodings.

### 4.3 No per-object type-hash prefix
We do **not** embed a type hash in each payload. The `Object` already carries its authoritative `TypeTag` (with `canonical_hash`). Instead we **validate at the boundary** (§5.3): decode-and-reject on `object_create`/`object.mutate`. This closes the "wrong-but-same-width schema → silent garbage" hole at zero per-object storage cost and supplies the chain-side enforcement `validate_canonical_bytes` lacks today.

### 4.4 Relationship to the PTB calldata envelope
The framed PTB calldata envelope (count + per-arg tag: Signer/Const/Object/Use/TypeArg) stays as a thin **outer** layer. The **value bytes inside** each `Const`/`Use`/return slot use this one codec. Unifying string/bytes width therefore fixes the args/returns value path. `marshal_args`/`unmarshal_outputs` in `bloom-script/src/executor.rs` collapse onto the shared `CallArgs` implementation (no more duplicate reimplementation), but this effort must preserve the existing outer envelope unless a separate migration explicitly changes it.

Function returns keep the current "multiple return slots" semantics. Rust tuple returns from functions continue to flatten into multiple manifest return slots for ABI compatibility. A tuple **value** is encoded only when a declared argument, object field, enum payload, vector element, map key/value, or single return slot has a tuple `TypeTag`.

---

## 5. Components & where the code lives

### 5.1 Canonical codec crate/module (single source of truth)
A single low-level codec providing the primitives (ULEB128, fixed-width BE ints, 32-byte, length-prefixed bytes/UTF-8) and the recursive **schema-driven** encode/decode that walks a resolved type. Natural home: a dedicated `bloom-codec`/`bloom-value` crate, or a new module with dependency direction equivalent to:

`bloom-objects` type identities → `bloom-petal-manifest` declarations → value codec resolver/projection → `bloom-script`/`bloom-resource`/`bloom-vfs`/`bloom-petals`.

Do **not** put manifest-driven reflective decoding directly in `bloom-objects` if that requires `bloom-objects -> bloom-petal-manifest`; today `bloom-petal-manifest` already depends on `bloom-objects`, so that would create a cycle.

`bloom-script/src/abi_json.rs` is **not** a near-complete codec; it is a primitive/fixed-vector JSON projection layer with divergent framing. It should become a thin JSON projection over the new codec rather than the implementation base.

Two cooperating layers that **must agree** (enforced by round-trip tests):
- **Derive-generated (compile-time)** encode/decode for petal Rust types — Borsh-style. Lives in/emitted by `bloom-resource-macros`.
- **Reflective (runtime, schema-driven)** encode/decode driven purely by the manifest — for the host/VFS/JSON side, which has the manifest but not the Rust types.

### 5.2 Authoring surface (macros)
- **New `#[derive(BloomType)]`** (with enum support) for plain data structs/enums that aren't on-chain objects.
- `#[object]` and `#[capability]` **build on the same machinery** — an object is a `BloomType` that additionally has identity (`UID`) and abilities. `#[object]::expand` (which already computes full field info via `build_decl`) gains a call that emits the payload codec.
- Generics: `Resource<T>` and non-phantom generics require a `BloomType` bound on `T` so generated code can call `<T as BloomType>::encode/decode`. Phantom params remain manifest-only. The `reject_plain_generic_in_payload` rule is revisited so `Option<T>`/`vector<T>` fields are legal.
- `lower()` in `bloom-resource-macros/src/type_tag.rs` must stop flatly rejecting tuples and must lower built-ins to `BUILTIN_TYPE_HASH`, not the `[0;32]` self sentinel.
- The petal macro must discover enum items and `#[derive(BloomType)]` data structs/enums, not only `Item::Struct` objects and functions.
- Function argument classification must use manifest/type metadata rather than the current "uppercase path means object" heuristic, so plain data structs become `ArgKind::Const` and objects/resources remain object args.
- Implement generic `BloomType` support for `Option<T>`, `Result<T,E>`, `Vec<T>`/`vector<T>`, tuples, maps, and sets. Today runtime `BloomType` only covers a small primitive set.
- Capability semantics are in scope: adding capability payload fields is not enough. PTB validation must stop blanket-rejecting non-empty `required_capabilities` and must define how capability requirements are satisfied.

### 5.3 Chain boundary enforcement
- `object_create` and `object.mutate` (`bloom-petals/src/chain_vm.rs`) **decode the payload against the declared schema and reject** on failure. Replaces the `validate_canonical_bytes`-returns-`Unknown`-for-structs gap.
- This requires access to the full manifest/type-resolution context for the object-defining petal. The current host import path only has a `TypeTag` and raw bytes, and the `PetalManifestStub` drops field structure; both are insufficient.
- Genesis/core bootstrapping must ensure `/bloom/petals/core/fungible` has a real manifest/code available before `Coin<LOOM>` payloads need schema validation. Do not rely on `DEFAULT_FUNGIBLE_PETAL_HASH` with no manifest, unless `Coin` is explicitly modeled as a built-in schema during genesis.

### 5.4 VFS / JSON display
- Delete the bespoke decoder in `bloom-vfs/src/petals_handler.rs` (`decode_field_json`, `fixed_width`, `static_field_width`, the `Coin` special-case) and route through the reflective codec + JSON projection.
- **Decode failure → hard error** (EIO at the VFS), logged. No `{"hex": ...}` fallback.
- **Preserve the user-facing scalar JSON contract** exactly: `u64`/`u128` as decimal strings; `u8`/`u16`/`u32` as JSON numbers; addresses/hashes as bare lowercase hex (no `0x`); `bytes` as bare lowercase hex; the `{"concrete": {...}}` TypeTag JSON shape. These are stable API asserted by tests.
- Rich JSON projection shapes:
  - structs and struct variants: JSON object by field name.
  - tuples and tuple variants: JSON array in declaration order.
  - unit enum variants: string variant name.
  - enum tuple/struct variants: single-key object `{ "Variant": payload }`.
  - `Option<T>`: `null` for `None`, projected `T` for `Some`.
  - `Result<T,E>`: `{ "Ok": value }` / `{ "Err": value }`.
  - `vector<T>`/`set<T>`: JSON arrays.
  - `map<K,V>`: JSON array of two-element `[key, value]` entries, preserving canonical order. Do not use JSON objects for arbitrary maps because non-string keys, duplicate keys, and property order are not safe.

### 5.5 Deduplication (mandatory, not optional)
Collapse into the shared codec / one type-resolution module: `substitute_type_args` (×4: executor, rpc, vfs, ptb-builder), `fixed_width`/`primitive_size_hint` (×3: abi_json, vfs, primitive), `type_tag_label` (×4), and `marshal_args`/`unmarshal_outputs` ↔ `CallArgsWriter`/`Reader`.

---

## 6. `UID` and `Coin` / `ObjectId` changes (bundled)

- **`UID` alias:** the type system treats `UID` as the 32-byte object-id scalar for both encode and decode/display. Added to the built-in scalar set (replacing the scattered `fixed_width` tables).
- **`Coin` becomes a normal derived struct.** Drop the redundant 32-byte zero id prefix; `Coin` is just `{ value: u128 }` (id lives on the `Object`, not in the payload). Remove the VFS `Coin` special-case and the `resolve_self_type_refs` Coin carve-out.
  - **Blast radius (runtime + chain-node + petals):** `decode_coin_value`/`rewrite_value`; PTB built-ins in `bloom-script/src/executor.rs` (`SplitCoins`/`MergeCoins`); gas validation in `bloom-script/src/validator.rs`; consensus admission; the ~12 sites in `petal_executor.rs`; `gas_select.rs`, `coin_select.rs`, `genesis.rs`; `bloom-petal-fungible`; DeX faucet/pool/router petals; and inline duplicates in tests all assume `bytes[32..48]` and/or `len()==48`. All must move to the new layout/codec.
- **`ObjectId` derivation reconciliation:** unify the four divergent formulas (`id.rs` spec, `chain_vm.rs::derive_create_id`, `genesis.rs`, `mint_coin_loom_to`) onto one canonical, documented formula; ensure ids are reproducible from stored state (today `derive_create_id` hashes the pre-stamp tag, not the persisted post-stamp tag).

---

## 7. State-root impact (why clean break is required)

Object payloads are serialized into the state root: `object_root()` → `encode_object_trie_value(obj)` → `obj.encode_canonical()` (incl. raw payload) → blake3 → state root → block header (`bloom-chain-state/src/state.rs:456`, `bloom-objects/src/store.rs:43`). Any wire-format change therefore changes every object's hash. Because Bloom has no deployed state, we **regenerate genesis** and do not add a version byte or dual-read path.

Clean break also means deleting/regenerating local persisted state blobs and gas-payer/object-id fixtures. Blob loading verifies roots against canonical object bytes, so old `state_blobs` are invalid after this change even if genesis is regenerated.

---

## 8. Testing strategy

- **Codec round-trip property tests** for every type form (scalars, String/bytes, structs, tuples, vectors of variable-width elems, enums/Option/Result, maps/sets with ordering), including **canonical/bijective** assertions: re-encode(decode(x)) == x and decode rejects non-canonical inputs (non-minimal ULEB128, trailing bytes, unsorted/dup keys, bad discriminants, bad UTF-8).
- **Derive ↔ reflective agreement:** for representative types, the macro-derived (Rust) encoding must byte-match the reflective (manifest-driven) encoding, and each must decode the other.
- **Boundary enforcement:** `object_create`/`object.mutate` reject malformed payloads.
- **VFS:** field reads and `_object.json` projection produce the correct values; decode failure returns a hard error; listing/pagination remain decoupled from decode success. `bloombook/tests/docker_vfs.rs` is the end-to-end gate (`String` fields decode correctly through the mounted VFS).
- **Docker/integration gates:** the current docker integration tests must still pass after intentional fixture/layout updates. They may be mechanically updated for new payload sizes, object ids, genesis hashes, and JSON shapes, but the **spirit of every assertion must remain true**: atomicity stays atomic, gas accounting remains correct, adversarial/malformed PTBs still fail, VFS projections remain inspectable, pipe composition behavior is preserved, and no assertion may be weakened merely to accommodate the refactor.
- **Migrate canaries:** `bloom-petal-fungible/tests/it_fungible.rs` (hardcoded `[32..48]`, `len()==48`), `ptb_submit_e2e.rs` inline `coin_payload`, `petals_handler.rs` test fixtures, DeX docker/integration fixtures, gas-reservation/signature/ownership tests, and the manifest golden-byte tests are updated/regenerated for the new layout.
- **Delete** `bloombook`'s bespoke `StateWriter`/`StateReader` and `bloom-petal-fungible`'s hand-rolled `coin_payload`/`supply_payload`/`cap_payload` in favor of derived codecs (verify the `bytes[96]` offset assumption in bloombook's vote test is replaced by symbolic field access).

---

## 9. Blast-radius file map (for planning)

**Codec / type system:** `bloom-objects/{codec.rs,type_tag.rs,primitive.rs,object.rs,id.rs,store.rs}`; new codec module.
**Macros:** `bloom-resource-macros/src/{object.rs,capability.rs,codegen.rs,petal.rs,type_tag.rs,ast.rs,lib.rs}`; new `BloomType` derive.
**Manifest:** `bloom-petal-manifest/src/{types.rs,codec.rs,stub.rs,extract.rs}` (+ `EnumTypeDecl`, `CapabilityDecl.fields`, `SCHEMA_VERSION`).
**ABI/args/returns:** `bloom-resource/src/abi.rs` (string width, share `CallArgs`); `bloom-script/src/executor.rs` (`marshal_args`/`unmarshal_outputs` dedup).
**JSON/RPC/CLI:** `bloom-script/src/abi_json.rs` (becomes projection layer; preserve JSON contract); `bloom-chain-node/src/rpc.rs`; `bloom/src/commands/chain.rs`; `bloom-ptb-builder/src/literal.rs`.
**PTB builder/session/labels:** `bloom-ptb-builder/src/{literal.rs,session.rs}`; `bloom/src/commands/{chain.rs,pipe.rs}`; `bloom-vfs/src/tx_handler.rs` (`type_tag_label`/literal grammar dedup).
**VFS:** `bloom-vfs/src/petals_handler.rs` (replace decoder; hard-error); `bloom-vfs/src/tx_handler.rs`.
**Chain boundary / Coin / ObjectId:** `bloom-petals/src/chain_vm.rs` (validate-on-create/mutate; id derivation); `bloom-script/src/{executor.rs,validator.rs}` (Coin built-ins/gas validation); `bloom-chain-consensus/src/tx_admission.rs` if PTB admission semantics change; `bloom-chain-node/src/{petal_executor.rs,consensus_driver.rs,gas_select.rs,coin_select.rs,genesis.rs}` (Coin layout); `bloom-chain-state/src/{state.rs,blob.rs}` (regen genesis/state blobs).
**Petals/tests/fixtures:** `bloom-petal-fungible/{src/lib.rs,tests/it_fungible.rs}`; `bloom-petal-it/src/harness.rs`; `examples/petal-dex/**` (faucet/pool/router codecs and integration harness); `bloom-chain-node/tests/{ptb_submit_e2e.rs,ptb_gas_reservation.rs,ptb_signature_rejection.rs,ptb_ownership_index_rebuild.rs}`; docker integration tests/fixtures; `bloom-resource-macros/tests/fixtures/*`; `bloombook/{src/lib.rs,tests/docker_vfs.rs}`.
**Out of scope:** SSZ tx/block envelope; EVM-side crates `bloom-defi`/`bloom-ens`/`bloom-etherscan`/`bloom-prices`/`bloom-watch`.

---

## 10. Decisions (locked)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Migration | **Clean break** — no compat, regenerate genesis (no deployed state) |
| 2 | Type richness in v1 | **Full algebraic system now** (scalars, struct, tuple, vector, Option/Result, enum, map/set) |
| 3 | Wire format | **Schema-driven, non-self-describing, BCS/Borsh-class**; BE ints; ULEB128 minimal lengths/counts/discriminants; strict bijective |
| 4 | Mis-decode protection | **Validate-on-write** at the chain boundary; no per-object hash prefix |
| 5 | VFS decode failure | **Hard error** (no hex fallback) |
| 6 | Coin / ObjectId | **Bundle both** — Coin loses redundant id prefix, becomes derived struct; ObjectId formulas reconciled |
| 7 | Authoring surface | **New `#[derive(BloomType)]`** (+ enums); `#[object]`/`#[capability]` build on it |
| 8 | Built-in identity | **Reserved `BUILTIN_TYPE_HASH`**; `[0;32]` is only a macro-time self sentinel |
| 9 | Test compatibility | **Docker/integration behavior preserved** — fixtures may change, assertion meaning may not |
