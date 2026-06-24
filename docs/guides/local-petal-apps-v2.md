# Local Petal Apps v2

v2 local apps are content-addressed packages whose `app/<name>/` tree defines
the `/apps/<name>/` VFS surface.

Required files:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- at least one `app/<name>/**/*.wasm` route

v2 apps run only `bloom:route@0.1.0` component routes. Component route imports
are validated against Bloom-owned WIT at build/install time; direct component
exports are invoked by the component runner. Component routes can call mediated
`bloom:http/fetch@0.1.0`, `bloom:store/kv@0.1.0`, and
`bloom:vfs/readwrite@0.1.0`, and `bloom:sign/signing@0.1.0` imports when the
package manifest grants the matching capability. Signing routes must also
declare `[sign].allowed_intents`, and runtime host calls are denied unless the
requested intent is in that allow-list. `bloom:chain/read@0.1.0` is linked
through a mediated host adapter and defaults to denied unless the embedding
host provides chain read support. Package-local shared component imports land
with composition support.

Useful commands:

```sh
bloom petal app build path/to/package --out app.petal.tar
bloom petals install path/to/package
bloom petals install app.petal.tar
bloom petals ls
```

`bloom petal app build` validates the package, writes generated route artifacts
under `artifacts/`, and emits a deterministic `.petal.tar` when `--out` is set.

Route artifacts must be WebAssembly components; raw core-WASM route artifacts
are rejected.
