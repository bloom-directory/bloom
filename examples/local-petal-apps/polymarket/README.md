# Polymarket v2 Petal

This package implements the Polymarket app at `apps/polymarket/...` using the
`bloom:route@0.1.0` component ABI.

The route component source lives in `../polymarket-route`. It performs
Polymarket HTTP calls directly through the v2 HTTP import, persists petal-owned
state through the v2 private store import, uses v2 signing intents for CLOB and
relayer signatures, and reads mediated wallet/chain state through the host VFS
imports. It uses only the v2 route ABI and does not delegate to the legacy
native `polymarket/...` VFS handler.

Regenerate the checked-in route components with:

```sh
examples/local-petal-apps/build-polymarket-v2.sh
```
