# Stage 4 — State Projection

**Status:** design, approved for planning
**Date:** 2026-05-31
**Surface:** bloom's **own sovereign chain** (petals / PTBs / objects) — *not* the external-EVM client mounts (`chains/`, `wallets/`, `defi/`-Enso)
**Vision:** `2026-05-29-petal-vfs-namespace-vision.md` (Stage 4 of 4)
**Builds on:**
- `2026-05-29-petal-vfs-stage1-design.md` — the namespace, the `PetalsEndpointHandler`, the `iter_vfs` enumeration-hook pattern, the `/bloom/petals/` admission invariant
- `2026-05-30-petal-vfs-stage3-design.md` — the `.pipe` reserved node and the dot-prefixed admission reservation this stage generalizes
- The read engine — `chain_query_object` / `chain_ls_objects`, `State::iter_objects`, and the typed-value decoder (`decode_return_json` / `decode_json_type_tag`) that `view-call` already uses

**Dependency:** Stage 1 only (the namespace + handler). Runs parallel to Stages 2–3 per the vision; specced last by sequence.

---

## 1. Goal

Render a petal's committed object state as a navigable, **read-only** filesystem under its path, so results are read back the same way they were invoked — closing the loop with Stages 1–3.

```
/bloom/petals/dex/pool/
  quote  swap  …                 # endpoints (Stages 1–3)
  .state/
    Pool/                        # a declared object type
      <object-id>/
        reserve_x                # decoded field value
        reserve_y
        _object.json             # whole object + metadata (owner, version, type)
    LP/<object-id>/…
```

- `ls .state` → the petal's declared object types, straight from `manifest.object_types` (no scan).
- `ls .state/Pool` → live object ids of that `(petal_hash, type_name)`, paginated.
- `ls .state/Pool/<id>` → one file per declared field, plus `_object.json`.
- `cat .state/Pool/<id>/reserve_x` → the decoded field value; `cat …/_object.json` → the whole decoded object + metadata.

### The load-bearing constraint

Objects are stored globally by id and indexed only **by owner** (address or parent-object) — there is **no petal→objects or type→objects index**. The *type* level is free (declared in the manifest); only the *id* level requires a full object-trie scan filtered by `petal_hash`+`type_name`. Single objects are addressed cheaply by id. Shared/immutable objects have no owner index but still appear in a type scan (the scan visits all objects regardless of owner). Reads reflect the **latest committed snapshot**, read-only. The projection is a new front door over existing state — no chain, consensus, or manifest-schema change.

## 2. Settled decisions

| Decision | Choice |
|---|---|
| **Projection shape** | Type-indexed tree: `.state/<TypeName>/<id>/<field>`. Browsable; the by-id leaf decodes fields. |
| **Leaf representation** | A directory of per-field files (`<id>/<field>` → value) plus `<id>/_object.json` (whole decoded object + metadata). |
| **Placement & protection** | A reserved `.state` dir under each bound petal dir. Admission generalized from Stage 3's "reject `.pipe`" to "reject any **dot-prefixed segment** under `/bloom/petals/`," protecting `.state`, `.pipe`, and future control/projection nodes. |
| **Snapshot & mutability** | Latest committed snapshot only; strictly read-only. |
| **Enumeration** | A new `iter_objects` hook on `ChainStateIface` (default-empty, mirroring `iter_vfs`), filtered by `(petal_hash, type_name)`; output bounded by the existing `paginate` primitive. The full scan is accepted for v0 and `log`-noted. |

## 3. The `.state` tree and the units it needs

Four pieces, mostly mirroring how Stage 1 added `iter_vfs`:

1. **Object-enumeration hook on `ChainStateIface`.** Add `iter_objects()` with a default-empty impl (like `iter_vfs`), implemented on `PtbChainAdapter` via the existing `State::iter_objects`. The handler filters it by `(petal_hash, type_name)` to list a type's live ids. This is the only way to enumerate without an index; the scan is bounded on output by `paginate`.

2. **A payload→fields decoder.** A new helper that takes an object's `payload` bytes + the type's `ObjectTypeDecl.fields` and produces named JSON values, reusing the typed-value decoder `view-call` already uses for returns (`decode_return_json` / `decode_json_type_tag`). Scalars render as plain values; nested structs / `Coin<T>` / vectors render as JSON; anything undecodable (e.g. fields behind unresolved generics) falls back to hex. This is the one genuinely new bit of logic.

3. **Handler navigation in `PetalsEndpointHandler`.** The `.state` segment under a bound petal path is special-cased (like `.pipe`):
   - `list .state` → manifest object-type names.
   - `list .state/<Type>` → paginated object ids whose `(petal_hash, type_name)` match (scan + filter); excludes other petals' same-named types.
   - `list .state/<Type>/<id>` → one file per declared field, plus `_object.json`.
   - `read` of a field → its decoded value; `read _object.json` → the whole decoded object + metadata (id, type, owner, version).
   - Unknown type / id / field → 404.

4. **Admission generalization.** Replace Stage 3's `.pipe`-specific reservation in `validate_chain_petal_module_path` with "reject any dot-prefixed first segment under `/bloom/petals/`," covering `.state`, `.pipe`, and future control nodes in one rule.

No daemon wiring, no manifest schema, no consensus change.

## 4. Testing strategy

- **Decoder (unit):** an object payload with scalar + complex (nested struct / `Coin<T>` / vector) fields decodes to the expected named JSON values; an undecodable/generic field falls back to hex; field count/order matches the manifest.
- **Handler (unit, in-process):** with a bound petal exposing two object types and several live objects, `ls .state` lists the declared type names; `ls .state/<Type>` lists exactly the ids whose `(petal_hash, type_name)` match, paginated, excluding other petals' same-named types; `ls .state/<Type>/<id>` shows one file per field plus `_object.json`; `read` of a field returns its decoded value and `_object.json` returns the whole object; unknown type/id/field 404s; `.state` does not perturb endpoint listing or the `.pipe` node.
- **Admission (unit):** a petal binding any dot-prefixed segment (`/bloom/petals/dex/.state`, `…/.pipe`, `…/.foo`) is rejected without writes; a normal petal still deploys — generalizes `deploy_reserved_pipe_path_fails`.
- **End-to-end (Docker — the headline proof):** extend `exercise_live_petal_vfs_mount`. After the existing mutations leave the counter at 99, read it back through the projection — `cat …/.state/<CounterType>/<id>/<field>` and `_object.json` — and assert it equals the value the `view` endpoint returns. This is the "read state back the same way you invoked" proof, closing the loop with Stages 1–3. Reuses the `docker-petal-vfs` CI job.
- **Migration guard:** existing DEX / handler / admission suites still pass.

## 5. Out of scope (deferred)

- **Owner-scoped projection** (`.state/by-owner/<addr>/…` via the ownership index) — the efficient "my objects under this petal" view; layers on later.
- **Dynamic collections / parent→child objects** (`Owner::Object` enumeration — e.g. a Pool's child LP positions) — the richer "collection" mapping; v0 projects declared top-level object types only.
- **Historical / at-block state** — projection reads the latest committed snapshot only.
- **Writing through the projection** — `.state` is strictly read-only; mutation stays at the endpoints (Stages 2–3).
- **Indexing to avoid the full scan** — a real type/petal index is a chain-state change; out of scope. The full-scan cost is `log`-noted at current scale.
- **Generic-field deep decoding** — fields behind unresolved generics fall back to hex rather than a full structural decode.
- **Self-contained endpoint binaries** (no client-side `bloom` CLI dependency) — carried over from Stages 1–3.
- Anything on the external-EVM surface.
