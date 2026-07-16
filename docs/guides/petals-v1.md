# Petals v1

Petals are content-addressed packages whose `petal/<name>/` tree defines
the `/petals/<name>/` VFS surface.

Required files:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- at least one `petal/<name>/**/*.wasm` route

Petals run only `bloom:route@0.1.0` component routes. Component route imports
are validated against Bloom-owned WIT at build/install time; direct component
exports are invoked by the component runner. Each normal file route must export
the full `route-file` world: `metadata`, `lookup`, `list`, `read`, and `write`.
Unsupported operations should return `route-error.unsupported`. Component routes
can call mediated `bloom:http/fetch@0.1.0`, `bloom:store/kv@0.1.0`, and
`bloom:vfs/readwrite@0.1.0`, and `bloom:sign/signing@0.1.0` imports when the
package manifest grants the matching capability. Signing routes must also
declare `[sign].allowed_intents`, and runtime host calls are denied unless the
requested intent is in that allow-list. `bloom:store/kv@0.1.0` includes atomic
`put-new` and `delete-if-value` operations for route locks/idempotency.
`bloom:chain/read@0.1.0` is linked
through the component runner for future host support, but install validation
currently rejects it until the daemon mediates production chain reads. Its WIT
shape is one generic JSON call: `call({ chain, method, params-json }) ->
{ result-json }`. `bloom:env/runtime@0.1.0` provides mediated runtime utilities
(`now-ms` and `random-bytes`). Package-local shared component imports land with
composition support.

Useful commands:

```sh
bloom petals build path/to/package --out app.petal.tar
bloom petals install path/to/package
bloom petals install app.petal.tar
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket --ref v0.1.0
bloom petals ls
```

`bloom petals build` validates the package, writes generated route artifacts
under `artifacts/`, and emits a deterministic `.petal.tar` when `--out` is set.

`bloom petals install <trusted-github-url>` accepts source repositories under
`bloom-directory`. By default it installs the latest SemVer-like tag; pass
`--ref <tag-or-sha>` to pin a tag, branch, or commit explicitly. GitHub source
repos must declare `[build] command = "..."` in `petal.toml`; Bloom runs that
trusted command locally, validates the generated Petal package through the same
package pipeline as local directories and `.petal.tar` archives, then records
the source URL, selected tag/ref, resolved commit, and package hash in install
metadata. Raw remote `.wasm` URLs and unsupported GitHub owners are rejected.

Route artifacts must be WebAssembly components; raw core-WASM route artifacts
are rejected.
