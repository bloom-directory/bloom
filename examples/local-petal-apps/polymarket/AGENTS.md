# Polymarket v2 Petal

- Keep this package on `bloom:route@0.1.0`; do not add legacy or compat route
  artifacts.
- The route component owns the Polymarket behavior. It may use v2 HTTP, store,
  signing, and mediated wallet/chain VFS imports, but it must not delegate to
  the legacy native `polymarket/...` VFS handler.
- After changing `../polymarket-route/src/lib.rs` or the route list, run
  `examples/local-petal-apps/build-polymarket-v2.sh` and commit the regenerated
  `.wasm` artifacts.
