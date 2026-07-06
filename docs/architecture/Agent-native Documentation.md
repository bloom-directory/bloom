# Agent-native Documentation

**Status:** architecture overview
**Audience:** Bloom engineers, Petal authors, and implementation agents

Bloom's VFS is self-documenting. An agent pointed at a Bloom mount must be
able to discover how to use it by reading files inside the mount, without
prior knowledge of Bloom. This document describes the surfaces that provide
that, how they are kept honest, and what must be added to them as the
platform evolves.

## Mount-Root Guidance: `/AGENTS.md` and `/CLAUDE.md`

The primary surface is a single guidance document served at the mount root
under two aliases, `AGENTS.md` and `CLAUDE.md`, so that both generic agents
and Claude-family tooling find it by convention.

How it works today:

- The content is a vendored markdown file,
  `crates/bloom-vfs/src/docs/agent-guidance.md`, embedded into the binary at
  compile time via `include_bytes!` in the VFS router
  (`crates/bloom-vfs/src/router.rs`).
- The root `Vfs` router itself — not a Petal handler — serves it: root
  listings include both filenames, lookups return a read-only file entry
  (mode `0o444`), and reads return the embedded bytes verbatim. Writes are
  not routable to these paths.
- The same content is also readable at `/docs/agent-guidance.md` through the
  docs handler, alongside `/docs/README.md` and `/docs/examples.md`.

Because the content is compiled into the Bloom Machine, the documentation an agent
reads is always the documentation of the exact binary serving the mount.
There is no runtime templating and no way for the served guidance to drift
from the release it ships with.

## What the Guidance Covers

`agent-guidance.md` ("Working with bloom") currently documents:

- mounting and the `bloom vfs ls`/`bloom vfs cat` facade;
- the capability security model: reads are always safe; direct value-moving
  writes cross an owner-approval gate; automated action flows through bounded
  sessions/capabilities; the owner key is never handed to an agent;
- the outbox stage/confirm flow;
- paid HTTP under `/requests` (staging, `plan.md`, `confirm`, spend caps);
- the mounted Sealed Approval lifecycle for the EVM slice: permission-denied
  confirm writes, `approval_challenge.json`, `ceremony_url`, grant / grant +
  execute, and retrying after a grant-only approval;
- Hyperliquid session-first trading and Polymarket opt-in gating;
- passkey policy signing and `under_policy` semantics.

As additional Petals adopt the mounted Sealed Approval flow described in
[`Interaction Modes.md`](./Interaction%20Modes.md), the guidance must stay the
discovery mechanism for that contract: the permission-denied signal on a confirm
write, reading `approval_challenge.json` from the same pending directory,
forwarding or opening `ceremony_url`, the grant / grant + execute choice, and
retrying the confirm write after a grant-only approval. There is no per-action
hint file and no per-directory README duplication of global contracts.

## Per-Petal READMEs

Petal handlers embed their own read-only, Petal-local documentation the same
way (compile-time constants served as `README.md` inside the Petal's
subtree): `/hyperliquid/README.md` (plus `asset_ids.md`),
`/polymarket/README.md`, `/defi/README.md`, ENS, and the per-address
`tokens/README.md` under chain handlers. Per-request `plan.md` files under
`/requests` are per-instance previews rather than static docs.

The division of labor:

- the root guidance documents cross-cutting contracts: the security model,
  the action lifecycle, approvals, and where things live;
- a Petal README documents only Petal-local paths and semantics, and links
  back to the shared contracts rather than restating them.

## Keeping It Honest

Two mechanisms keep the served documentation truthful:

**Tests pin the surface.** The router tests assert that the root lists both
`AGENTS.md` and `CLAUDE.md` as read-only files, that the served bytes are
byte-identical to the vendored source file, and that the content passes
sanity checks. Petal handlers carry similar tests for their READMEs (for
example, that the Hyperliquid README documents safe reads and API-wallet
risk).

**The PR checklist enforces updates.** The repository's pull request
template includes a mandatory "Agent Documentation updated" item, enforced
by a required status check (see `.github/pull_request_template.md` and
`.github/workflows/pr-checklist.yml`). Any change that alters agent-visible
behavior — new paths, changed lifecycles, new approval semantics — must
update `agent-guidance.md` and/or the affected Petal READMEs in the same PR,
or explicitly justify why no update is needed.

## Extension Points

- The router exposes a `root_dynamic` registration mechanism for dynamic
  root-level files. The Bloom Machine uses it for `/next.md`, a Bloom Machine-rendered "what
  needs my attention" aggregator for agent workflows.
- New global agent-facing documents belong at the mount root or under
  `/docs`, embedded at compile time and covered by byte-identity tests, not
  generated at runtime and not scattered per-directory.

## Requirements Summary

- Every Bloom mount must serve `AGENTS.md` and `CLAUDE.md` at the root,
  read-only, byte-identical to the vendored source, versioned with the
  binary.
- Global contracts (security model, action lifecycle, Sealed Approval
  discovery) live in the root guidance; Petal READMEs stay Petal-local.
- Documentation changes ship in the same PR as the behavior they describe,
  enforced by the PR checklist.
