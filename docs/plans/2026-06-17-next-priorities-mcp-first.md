# Next Priorities: MCP Interface First

**Status:** Recommendation. Prioritization after a design/review session.
**Date:** 2026-06-17.

## Context

bloom is an agent-guided EVM wallet: the user opens their agent, the agent drives
bloom to read state and move funds within policy. This doc records *what to build
next* and why, after a session that produced more analysis than code. It is a
prioritization decision, not an implementation spec.

## Framing: three layers of "guiding an agent"

Don't conflate these — work on the one that's actually the bottleneck.

1. **Orientation** — *what bloom is, the rules.* `AGENTS.md` + the session-start
   hook. **Done.** More prose does not make an agent more capable.
2. **Interface** — *the agent's hands.* Today: CLI/VFS text-scraping. Robust
   version: an **MCP server** over the `Vfs` router. **Missing. This is the
   bottleneck.**
3. **Situation** — *what you hold, what's at risk, what you did.* The wallet
   agenda / entanglement scan (`2026-06-16-wallet-agenda-entanglement-scan.md`).
   Sits *on top of* the interface; deferred (below).

## Recommendation: read-only MCP server next

Build a minimal, **read-only** MCP server (`bloom-mcp`) over the existing `Vfs`
router, speaking MCP over stdio.

Why this, over the alternatives:
- **Highest leverage on the product thesis.** "Agent uses bloom" today means
  scraping CLI text — works for a strong model, fragile otherwise. MCP gives
  agents *typed tools* instead. It is the one piece `DIRECTION.md` named as step
  one that was never built.
- **Bounded, shippable, not a research project.** v0 is read tools only — chain
  state, balances, `simulate`, prices — wrapping the same router the daemon's
  `IpcServer` already wraps (the JSON-RPC-over-transport template to mirror). No
  signing path, no policy surface, no money risk in v0.
- **Unblocks everything downstream.** The agenda and any future surface are
  better consumed through a typed contract than scraped. Build the contract
  first; the agenda gets better for free once agents consume MCP.

### v0 scope
- New `bloom-mcp` transport mirroring `bloom-daemon/src/ipc.rs` (`IpcServer`),
  wrapping `crates/bloom-vfs` `Vfs`.
- Expose **read tools** onto existing VFS paths: chain reads, balances,
  `simulate`, prices.
- Stdio transport so any MCP client (Claude Desktop, Cursor, Inspector) connects
  with no SDK.
- No write tools in v0.

## Sequencing

1. **Now (~minutes):** land the deposit-QR + `wallet address` change as its own
   small PR; clear the working tree. (Pending a green `cargo build` +
   `cargo test -p bloom`.)
2. **Next (the real build):** read-only `bloom-mcp` over the Vfs router.
3. **Then:** guarded **write** tools (DeFi intent + wallet outbox), routed
   through the existing `bloom-tx` policy / outbox / audit path — *and* harden
   the audit log alongside them (below). Exposing write tools is the forcing
   function for the audit work.

## Deferred — and why (named, not buried)

- **Wallet agenda / entanglement scan.** Good design (keep the doc), but building
  ahead of demand: for today's Polymarket-centric usage, `polymarket obligations`
  already covers the one protocol in use, and the scan's payoff (cross-protocol
  risk) needs multi-protocol positions that aren't in evidence yet. It also sits
  on top of the interface. **Trigger to revisit:** evidence that real users hold
  positions across protocols and get burned by not being reminded.

## Supporting assessments (from this session)

- **Trust model is decent.** Value-moving actions route through
  `evaluate_action_authorization` (`bloom-proto/src/policy.rs`): a layered,
  fail-closed authorization state machine (deny is absolute; reviewed-hash path;
  `under_policy` autonomy bounded by verified calldata + USD budget). Credit it.
- **Audit log is the weak spot, and it's where money-safety lives.** It is
  hash-chained and verifiable, but (a) **fail-open** — append errors are dropped
  and the action proceeds; (b) integrity is scoped to *error*, not a local
  adversary (no external anchor); (c) it logs path + sha, **not the authorization
  decision** (autonomous vs reviewed, subject hash, USD debit). For an autonomous
  money-mover, value-moving actions should fail **closed** on audit and record
  the decision. Do this with the MCP write-tools phase.
- **Interface fragility is the bottleneck**, which is why MCP leads.

## Risk / open question

The real safety surface appears when MCP exposes **write** tools. Those must go
through the existing outbox/policy/audit path with no shortcut — and that is the
moment to make the audit log fail-closed and decision-recording. v0 stays
read-only precisely to keep that surface out of the first, fast shippable slice.
