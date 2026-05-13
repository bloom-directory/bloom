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
