# Bloom WIT contracts

The `route` package is the Petal route ABI. Its `deps/` directory checks
in the Bloom-owned host capability packages that route components may import.

Validate the contracts with:

```sh
wasm-tools component wit wit/bloom/route
for package in wit/bloom/route/deps/*; do wasm-tools component wit "$package" >/dev/null; done
```
