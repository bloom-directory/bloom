# Working with bloom

bloom exposes Ethereum workflows as a virtual filesystem. Prefer inspecting the
tree with normal filesystem tools when it is mounted, or with `bloom vfs` when it
is not mounted.

To mount the tree, run a mount-enabled build as `bloom serve --mount`. With no
path argument, the mount point is `/bloom` on Linux and `/Volumes/bloom` on
macOS; pass `bloom serve --mount <path>` to choose another existing directory.
Mounting uses the platform NFS client and may require elevated privileges.

Useful commands:

- `bloom vfs ls /` lists the VFS root.
- `bloom vfs ls /docs` lists the embedded documentation.
- `bloom vfs cat /docs/README.md` reads the VFS overview.
- `bloom vfs cat /docs/examples.md` reads workflow examples.

For more information, start in the `/docs` folder. It contains the canonical
VFS usage notes and examples exposed by the mounted tree.

Most paths are read-only views over chain, wallet, status, pricing, ENS, and
tooling data. Treat writable paths as actions: writes may stage transactions,
create watched resources, or update local bloom state. Read the nearby docs and
directory contents before writing.

## Polymarket

Prediction-market trading lives under `/polymarket` and is driven by the
`bloom polymarket ...` commands. It is **opt-in and human-gated**: a wallet
trades only after `[polymarket] enabled = true` is set in its `policy.toml`, and
value-moving steps open a passkey review ceremony that needs a human present —
or unlock a **local** (passphrase) wallet via `BLOOM_PASSPHRASE` for headless
runs. Start at `/docs/examples.md` (the Polymarket section: prerequisites + the
onboard → fund → order → confirm happy path) and read `docs/polymarket-integration.md`
in the repo for the full spec and caveats. Funds move only through the CLI
(`fund`, `fund --request`, `onboard --target-pusd`); the VFS surface stages and
reviews, it never signs.
