# Local Petal Apps v2

v2 local apps are content-addressed packages whose `app/<name>/` tree defines
the `/apps/<name>/` VFS surface.

Required files:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- at least one `app/<name>/**/*.wasm` route

Current bootstrap support runs compatibility `petal_dispatch` core-WASM routes
and direct `bloom:route@0.1.0` component routes. Component route imports are
validated against Bloom-owned WIT at build/install time; direct component
exports are invoked by the component runner. Component routes can call mediated
`bloom:http/fetch@0.1.0`, `bloom:store/kv@0.1.0`, and
`bloom:vfs/readwrite@0.1.0`, and `bloom:sign/signing@0.1.0` imports when the
package manifest grants the matching capability. Signing routes must also
declare `[sign].allowed_intents`, and runtime host calls are denied unless the
requested intent is in that allow-list. `bloom:chain/read@0.1.0` currently
returns an unsupported error, and package-local shared component imports land
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

Example demos live under `examples/local-petal-apps`. Build their WAT sources
into installable package directories with:

```sh
./examples/local-petal-apps/build-demo-apps.sh
```

Then install one:

```sh
cargo run -p bloom -- petals install examples/local-petal-apps/build/echo
```
