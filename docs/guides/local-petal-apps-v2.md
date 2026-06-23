# Local Petal Apps v2

v2 local apps are content-addressed packages whose `app/<name>/` tree defines
the `/apps/<name>/` VFS surface.

Required files:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- at least one `app/<name>/**/*.wasm` route

Current bootstrap support accepts compatibility `petal_dispatch` core-WASM
routes. Component routes are rejected until `bloom:route@0.1.0` WIT validation
and execution are implemented.

Useful commands:

```sh
bloom petal app build path/to/package --out app.petal.tar
bloom petals install path/to/package
bloom petals install app.petal.tar
bloom petals ls
```

Example demos live under `examples/local-petal-apps`. Build their WAT sources
into installable package directories with:

```sh
./examples/local-petal-apps/build-demo-apps.sh
```

Then install one:

```sh
cargo run -p bloom -- petals install examples/local-petal-apps/build/echo
```
