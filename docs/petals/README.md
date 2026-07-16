# Petals

Petals are content-addressed WebAssembly component packages that add a
filesystem-shaped application under `/petals/<name>/` in Bloom's VFS. Bloom
validates the package at install time and mediates the component's access to
networking, storage, signing, transactions, and the rest of the VFS.

Start with the guide for your role:

- [Using Petals](using-petals.md) explains how a person or agent installs,
  inspects, operates, and removes a Petal.
- [Authoring Petals](authoring-petals.md) explains the package layout, route
  ABI, manifest policy, build, and validation workflow for developers and
  coding agents.

## Detailed references

These guides are the concise operational entry point. The following documents
remain authoritative for lower-level detail:

- [Canonical Bloom route and host WIT](https://github.com/bloom-directory/petal/tree/main/wit/route)
- [File-driven package design](../superpowers/specs/2026-06-23-petals-v1.md)
- [External repositories and GitHub source installs](../superpowers/specs/2026-06-24-external-petal-repos-and-github-source-installs.md)
- [Petal platform/native parity](../specs/2026-07-10-petal-platform-native-parity.md)
- [Sealed Approval](../specs/2026-07-02-sealed-approval.md)
