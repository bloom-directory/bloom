# Authoring Petals

This guide is for developers and coding agents building local/off-chain Petal
applications. A package contains exactly one filesystem-shaped route tree and
builds to content-addressed WebAssembly component artifacts.

## Package layout

The minimum source package is:

```text
my-petal/
  petal.toml
  README.md
  AGENTS.md
  petal/
    example/
      $index.wasm
      status.json.wasm
```

`README.md` is developer/contributor documentation. `AGENTS.md` is the
operating contract for users and agents: document paths, input bodies,
side effects, approval steps, idempotency, and how to recognize completion.

The `name` in `petal.toml` must equal the sole directory under `petal/`. It may
contain ASCII letters, digits, `-`, and `_`; it may not contain dots or Unicode.
Bloom mounts `petal/example/` at `/petals/example/`.

## Manifest

A representative manifest is:

```toml
schema = "bloom.petal.package.v1"
name = "example"

[consent]
summary = "Read an API and store package-local state."

[caps]
allowed = ["bloom:http", "bloom:store"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/v1/*"]

[store]
namespaces = ["cache"]
secret_namespaces = ["credentials"]
```

Policy structures reject unknown fields. Network paths must be explicit; use
`"/*"` deliberately for all paths rather than relying on an empty list.
`[[net.allow]]` may also name a configured endpoint with `binding = "..."`.

Supported component imports map to manifest capabilities as follows:

| WIT import | Manifest capability or policy |
|---|---|
| `bloom:http/fetch@0.1.0` | `bloom:http` plus `[[net.allow]]` |
| `bloom:store/kv@0.1.0` | `bloom:store` plus `[store]` namespaces |
| `bloom:sign/signing@0.2.0` | `bloom:sign` plus `[sign].allowed_intents`; exact payload, optional Signer-owned Petal KeyRef selector, and atomic ordered batches |
| `bloom:key/derive@0.1.0` | `bloom:key.derive`; routes delegating child-key operation classes must also use `[[key.derive]]` |
| `bloom:tx/outbox@0.1.0` | `bloom:tx.outbox` |
| `bloom:chain/read@0.1.0` | `bloom:chain` |
| `bloom:vfs/readwrite@0.1.0` | `bloom:vfs.read` and/or `bloom:vfs.write`, according to used exports |
| `bloom:env/runtime@0.1.0` | no additional capability |

Imports, route metadata, and the top-level manifest must agree. Metadata may
narrow installed authority at runtime but may not widen it. A package declaring
`bloom:sign` must list allowed intents, and each signing route's metadata must
select one of them. The retired `bloom:sign/signing@0.1.0` hash-only import is
incompatible with production signing and fails closed.

Child-key operation classes are distinct from the signing intent used
immediately by the route that requests the key. Declare each delegated class on
the exact route pattern that imports `bloom:key/derive@0.1.0`:

```toml
[[key.derive]]
route = "[network]/agent_sessions/[wallet]/new.json"
operation_classes = ["venue.agent_action"]
```

Every listed class must also appear in `[sign].allowed_intents`. Bloom rejects
unknown or duplicate routes, empty or duplicate class lists, invalid class
tokens, and declarations on routes without the key-derivation import. The
installer records only the route's immediate signing intent and these explicit
delegated classes; other package-level signing intents are not inherited.

## Routes and ABI

Every route artifact is a WebAssembly component implementing
`bloom:route@0.1.0`; raw core Wasm is rejected. The complete contract is in
The canonical [`route.wit`](https://github.com/bloom-directory/petal/blob/main/wit/route/route.wit). The route world exports
`metadata`, `lookup`, `list`, `read`, and `write`; return
`route-error.unsupported` for operations the route does not implement.

The route tree is the public VFS declaration:

- `status.json.wasm` creates the file `/petals/example/status.json`;
- `$index.wasm` handles the containing directory;
- `$lookup.wasm` refines lookup for dynamic entries;
- `[wallet]/balance.json.wasm` binds a dynamic `wallet` parameter; and
- static segments take precedence over dynamic segments.

Reserved `$...` names are only valid as recognized special route leaves. A
normal file route is readable by default. A route that advertises write access
must export `write`.

### Writable routes

Bloom waits for the component's `write` export to complete and propagates its
error to the VFS caller. Authors can therefore rely on a returned write error
being visible to a mounted filesystem or `bloom vfs write` client. A successful
return means the route handler completed; it does not imply that a transaction
the handler staged has been approved, broadcast, or confirmed. Represent those
states explicitly through inspectable routes and receipts.

The WIT `route-meta` record retains `write-async` for serialized-format
compatibility. Generated metadata and installation consent may call the same
field `write_async`. It is reserved metadata in this iteration: Bloom does not
detach writes when it is `true`, and authors must not document it as a
background-job guarantee. Set it deliberately for compatibility with existing
components, but design and test every write against synchronous execution.

For composition, a route may have a sibling `.route.toml` sidecar which points
to a primary component under `modules/` or `components/` and dependencies under
`components/`. See the
[file-driven package design](../superpowers/specs/2026-06-23-petals-v1.md)
for route precedence, sidecar composition, metadata narrowing, and archive
normalization rules.

## Build and validate

Validate the directory and generate route artifacts:

```sh
bloom petals build path/to/my-petal
```

Emit a deterministic uncompressed package archive at the same time:

```sh
bloom petals build path/to/my-petal --out my-petal.petal.tar
```

The build regenerates `artifacts/routes/` and
`artifacts/build-manifest.json`. Do not hand-edit generated artifacts or treat
stale artifacts as source. Install the directory and archive through the same
validation pipeline used for GitHub sources:

```sh
bloom petals install path/to/my-petal
bloom petals install my-petal.petal.tar
```

Before publishing, test both direct VFS fallback and a mounted daemon. Cover
lookup, list, read, invalid input, backend failure, and every writable route.
For a staged transaction workflow, verify that documentation and route output
distinguish staging, approval, confirmation, broadcast, and receipt states.

## GitHub source packages

Source repositories under `bloom-directory` may add:

```toml
[source]
kind = "github"
repository = "bloom-directory/bloom-petal-example"

[build]
command = "./scripts/build-package"
outputs = ["artifacts/routes"]
```

Bloom executes the build command natively with the installing user's
privileges. Publishing under the trusted owner is therefore an assertion about
the repository's source, build script, and dependencies—not only the resulting
Wasm. Keep builds non-interactive and reproducible, minimize dependencies, and
test installation by tag and immutable commit. Bloom records the resolved
commit but intentionally does not sandbox the source build in this iteration.

## Author checklist

- Keep `petal.toml`, `README.md`, and operational `AGENTS.md` current.
- Declare only host capabilities the component actually imports.
- Make network paths, store namespaces, and signing intents explicit.
- Make writes idempotent where retry is possible and expose inspectable status.
- Never imply that a staged or approval-required action has completed.
- Build from a clean tree and install the resulting directory and archive.
- Exercise failure paths and confirm errors are actionable for both people and
  agents.
