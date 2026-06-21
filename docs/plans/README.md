# Active Plans

Tracked plans here must describe open work or unresolved regressions. Completed
or superseded plans belong in `docs/archive/plans/`; scratch notes belong in
ignored `docs/.scratch/`.

## Current PR / Next Work

- `2026-06-13-scoped-agent-run-capabilities-roadmap.md` — signed scoped task
  capabilities, Polymarket authorization, settlement gates, and verified
  funding routes.
- `2026-06-13-enso-simulation-verification.md` — Enso route verification.
  WP0/WP1 and same-chain receiver calldata check have landed; simulation
  min-output and settlement remain before unattended use.
- `2026-06-13-policy-browser-editor.md` — separate validated policy editor;
  fuzzy search belongs there, not as a separate active plan.
- `2026-06-16-wallet-agenda-entanglement-scan.md` — live-first wallet agenda
  and cross-protocol entanglement scan design; Phase 0 not yet built.
- `2026-06-17-next-priorities-mcp-first.md` — prioritization note for building
  a read-only MCP interface before larger agent-facing surfaces.
- `2026-06-19-hyperliquid-integration-hardening.md` — correctness,
  durability, testing, and maintainability plan for Hyperliquid bounded
  sessions and trading paths.
- `2026-06-20-agent-obvious-capability-model.md` — make capabilities the
  default agent path across all venues: read-only `/wallets/<w>/capabilities/`
  roll-up, `/next.md` aggregator, auto-lock-on-expiry for
  owner-signing capabilities, and a Polymarket capability primitive.

## Removed From Active Set

Live-run notes and superseded drafts for passkey review pages, Polymarket
funding/auth UX, VFS exit UX, agent-friendly IPC, deposit QR export, native
balance display, Polymarket account workflow clarity, and broad policy autonomy
are implemented, stale, or covered by the active plans above.

## Older Open Work

- `2026-05-12-mempool-and-private-orderflow.md`
- `2026-05-26-contract-stack-consolidation.md`
- `2026-05-26-system-petals-todo.md`
- `2026-06-02-dex-coin-mint-regression.md`
