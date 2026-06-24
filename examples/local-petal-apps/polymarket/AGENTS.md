# Polymarket v2 Petal

- Keep this package on `bloom:route@0.1.0`; do not add v1 or compat route
  artifacts.
- The proxy is intentionally thin. Feature behavior lives in the native
  `polymarket/...` VFS handler and is exposed here through mediated v2 VFS
  imports.
- After changing `../polymarket-route-proxy/src/lib.rs` or the route list, run
  `examples/local-petal-apps/build-polymarket-v2.sh` and commit the regenerated
  `.wasm` artifacts.
