# Polymarket v2 Petal

This package mounts the native `polymarket/...` VFS tree under
`apps/polymarket/...` using the `bloom:route@0.1.0` component ABI.

The route component source lives in `../polymarket-route-proxy`. It is a VFS
proxy: it imports `bloom:vfs/readwrite@0.1.0`, maps the mounted app path to the
matching native Polymarket path, and delegates lookup, list, read, and write.
It does not use the removed v1 dispatch ABI.

Regenerate the checked-in route components with:

```sh
examples/local-petal-apps/build-polymarket-v2.sh
```
