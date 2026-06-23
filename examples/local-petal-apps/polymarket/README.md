# Polymarket v2 Local App Package

This package wraps the existing `bloom-local-petal-polymarket` compatibility
petal in the v2 file-driven app layout. It is intended as the parity package
for exercising `/apps/polymarket/...` through the v2 installer, route index,
artifact store, and app router.

Build it with:

```sh
./examples/local-petal-apps/build-demo-apps.sh polymarket
```

The build script compiles the existing Polymarket petal to `wasm32-wasip1` and
copies that compat route artifact across the v2 Polymarket route tree.
