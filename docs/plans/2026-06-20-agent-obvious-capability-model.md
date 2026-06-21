# Agent-Obvious Capability Model

**Status:** Active plan.
**Date:** 2026-06-20.

## Context

Bloom should be obvious for agents. Today it is not. The core architecture is
right — passkeys approve durable bounded capabilities; agents operate inside
those capabilities; the owner key never leaves the daemon process — but the
agent-facing surfaces, the naming, and the cross-venue consistency do not yet
express that model. A cold-start agent must read `AGENTS.md`, `/docs/README.md`,
`/hyperliquid/README.md`, the wallet `policy.toml`, `addresses.json`, the
per-venue session paths, and the CLI help, and then infer what to do.

This plan consolidates a strategic direction (make capabilities the default
trading path across all web3 operations) with the concrete read-only surfaces
and doc work that unblock agents immediately, plus the one missing primitive
(a Polymarket capability).

Three findings from the codebase shape the plan:

1. **Hyperliquid already realizes the model.** An ephemeral agent key signs
   trades inside a bounded session after one owner-signed `approveAgent`
   ceremony. The locked-wallet remediation text, the in-VFS README, and the
   "ADVANCED" labeling on direct writes are already shipped.

2. **EVM and Polymarket do not.** EVM `policy-session` is a batch-authorization
   envelope that still signs every tx with the owner key; the owner key lives
   in the keystore's unlocked cache with an unbounded lifetime
   (`crates/bloom-tx/src/session.rs:9-12`). Polymarket has no capability
   primitive at all — every trade re-crosses the owner gate with a fresh
   passkey ceremony.

3. **The three existing authority primitives use two different signing
   architectures.** Hyperliquid mints and holds an ephemeral key
   (`HoldsDelegatedKey`); EVM `policy-session` only suppresses per-tx ceremony
   while the owner key still signs (`AuthorizesOwnerSigning`); Polymarket
   builder-keys are relayer HMAC submission auth only and never move funds
   (`ServiceAuthOnly`). A unified capability model must surface this
   `signing_model` as load-bearing security truth, not hide it.

Related plans (do not duplicate):

- `2026-06-13-scoped-agent-run-capabilities-roadmap.md` — single-action signed
  Polymarket capability with canonical scope, spend ledger, and revocation
  mechanics. The Polymarket workstream in this plan builds on that design; it
  does not re-derive the scope/ledger/approval signature model.
- `2026-06-19-hyperliquid-integration-hardening.md` — Hyperliquid session
  correctness and durability. Must land together with the read surfaces here,
  because `tradable` is currently a derived flag that sometimes lies.
- `2026-06-17-next-priorities-mcp-first.md` — read-only MCP interface. The
  capability surfaces in this plan are VFS surfaces; an MCP projection of them
  is a later concern.

## Goals

1. Make "create capability → agent operates inside it → capability expires" the
   default mental model and the default documented path, across all venues.
2. Give agents a single read that answers "what can I do with this wallet
   without a human?" — today this requires reading five files and inferring.
3. Close the unbounded-cache gap: owner-key RAM residency for
   `AuthorizesOwnerSigning` capabilities must be bounded by the capability TTL
   and auto-lock on expiry/revocation.
4. Build the Polymarket capability primitive (scoped approve, TTL, caps, live
   risk evaluator) so Polymarket is no longer the venue where every trade
   re-prompts.
5. Stop showing raw internal concepts (`approveAgent`, `ephemeral key`,
   `policy-session`, `wallet_unlock`) to agents in prose, paths, or errors.

## Non-Goals For This Plan

- A writable unified `/capabilities/{new,revoke}` namespace. Reads first; the
  writable namespace is a refactor disguised as UX polish until the conceptual
  model is validated.
- Migrating existing writes off `/wallets/<w>/policy-session/` and
  `/hyperliquid/<net>/agent_sessions/`. Writes stay where they are.
- ERC-4337 / funded hot-wallet for EVM true key delegation. That is a separate
  security project.
- `/dryrun/` capability simulation. Valuable but separable.
- MCP projection of capability surfaces. Tracked under
  `2026-06-17-next-priorities-mcp-first.md`.
- Hyperliquid withdrawals or transfers (gated on the policy model and tracked
  under the hardening plan).

## The Capability Read Model

### Subtree shape

Read-only projection mounted under each wallet. Data is not moved; this subtree
renders from existing per-venue stores via a common trait.

```text
/wallets/<wallet>/capabilities/
  README.md                          orientation: reads safe / caps bound agents
  active.json                        machine-readable roll-up of all capabilities
  active.md                          human/agent-readable narrative of the same
  hyperliquid/
    mainnet/
      <session-id>.json              mirror of the HL session truth
  policy/
    active.json                      mirror of EVM policy-session truth
  polymarket/                         once the Polymarket capability exists
    <capability-id>.json
```

### The seven questions every entry answers

These are required fields in the JSON and rendered sections in the `.md`. An
agent reading any capability entry must learn all seven without crossing to
another file.

| Question | Field(s) |
|---|---|
| What capabilities exist? | the list itself in `active.json` |
| Who/what can act? | `wallet`, `signing_model`, `agent_address` (HL) |
| What can it do? | `allowed`: assets / slugs / pending_ids, caps |
| What can it NOT do? | `denied`: action kinds excluded, assets not allowlisted, withdraw/transfer excluded |
| When does it expire? | `expires_ms`, `expires_in` |
| How do I stop it? | `revoke_path` (the existing per-venue write path) |
| What path should an agent use next? | `next_write_path` (concrete VFS path) |

`signing_model` (`HoldsDelegatedKey` | `AuthorizesOwnerSigning` |
`ServiceAuthOnly`) is always rendered. Agents and humans must know whether the
owner key is still in the loop.

### Truth sources (unchanged)

The subtree is a projection. Raw truth stays where it lives today:

- Hyperliquid: `/hyperliquid/<net>/agent_sessions/<w>/<id>/session.json`
  (`crates/bloom-vfs/src/handlers/hyperliquid.rs:2574-2608`,
  `session_status_json_with_orphaned`).
- EVM: `/wallets/<w>/policy-session/active.json`
  (`crates/bloom-vfs/src/handlers/wallets.rs:163-185`).
- Polymarket (new): `<bloom home>/polymarket/<wallet>/capabilities/<id>.json`.

### Implementation seam

A `CapabilityView` trait in `bloom-proto` with one impl per venue:
`HlCapabilityView`, `EvmPolicyCapabilityView`, `PolymarketCapabilityView`.
The wallets handler renders the roll-up by iterating registered views. No
per-venue code moves; only a read adapter is added per venue.

### Do not headline the derived `tradable` flag

`session_is_tradable` is computed from six fields
(`crates/bloom-vfs/src/handlers/hyperliquid.rs:2561-2572`) and the hardening
plan documents it sometimes lies
(`docs/plans/2026-06-19-hyperliquid-integration-hardening.md:71-77`). The
capability view surfaces the raw fields (`status`, `orphaned`, `stale`,
`last_snapshot_ok_ms`) and lets the agent judge. `tradable` may be rendered as
a hint but never as the headline.

## Auto-Lock-On-Expiry (the security keystone)

Today the keystore's unlocked cache has an unbounded lifetime
(`crates/bloom-keystore/src/lib.rs:758-807`). This is acceptable for
`HoldsDelegatedKey` capabilities (HL), where the owner key is only needed for
the one `approveAgent` signature and not thereafter. It is not acceptable for
`AuthorizesOwnerSigning` capabilities (EVM, Polymarket), where the owner key
must be resident for the duration and the current design lets it stay resident
indefinitely after one unlock.

The refinement:

1. When an `AuthorizesOwnerSigning` capability is minted, register a
   `KeyResidencyLease` against `(wallet, capability_id, expires_ms)` on the
   keystore.
2. The lease enforces: when `now > expires_ms` OR the capability is revoked,
   AND no other active capability still needs the same wallet's key, the
   keystore calls `keystore.lock(wallet)`.
3. The session monitor (`crates/bloom-vfs/src/handlers/hyperliquid.rs:1316-1419`)
   ticks existing HL leases; a new EVM/Polymarket equivalent ticks the new ones.

This makes EVM/Polymarket capabilities safe-by-construction: the human opts
into a bounded headless window, not an indefinite one. A locked key is never
resurrected by a capability (existing invariant at
`crates/bloom-tx/src/session.rs:9-12` is preserved).

## Polymarket Capability Primitive

The largest single piece of new work. Today Polymarket onboarding grants
`approve(MAX)` to four V2 contracts from the deposit wallet
(`crates/bloom/src/commands/polymarket.rs:1101-1107`), unbounded in time and
notional, and every order requires a fresh owner POLY_1271 ceremony
(`crates/bloom-polymarket/src/builder_creds.rs:1-12`). There is no continuous
risk evaluator for resting CTF positions.

### Design

- **Scoped approve:** the capability carries TTL + `max_notional_usd`
  cumulative + `max_order_usd` per order + `allowed_slugs` / `denied_slugs` +
  `max_loss_usd`. On-chain approvals remain as they are; the capability is the
  bloom-side authority that scopes what the agent may do without a fresh
  ceremony.
- **Signing model:** `AuthorizesOwnerSigning`. Polymarket's protocol requires
  an owner POLY_1271 signature on every order; there is no `approveAgent`
  analog. The owner key is RAM-resident for the window, governed by the
  `KeyResidencyLease` above.
- **Continuous risk evaluator:** mirror `HyperliquidSession::evaluate`
  (`crates/bloom-proto/src/hyperliquid_session.rs:126-139`) — track open CTF
  position notional and drawdown against `max_loss_usd`. On breach: halt the
  capability and trigger flatten/revoke cleanup. Polymarket has no such
  evaluator today.
- **Ceremony kind:** `CeremonyIntentKind::CapabilityGrant` (promote and reuse
  the existing `RunCapability` slot at `crates/bloom-proto/src/ceremony.rs:19`,
  currently EVM-only; also lifts the HL grant out of `Other` per
  `crates/bloom-proto/src/hyperliquid_review.rs:35`).
- **Signature / scope / ledger mechanics:** build on the design in
  `docs/plans/2026-06-13-scoped-agent-run-capabilities-roadmap.md` (PR C).
  That plan specifies canonical scope, approval signature, spend ledger,
  revocation state, and exact-action matching for single-action capabilities.
  This plan extends that primitive to a multi-order bounded window with
  continuous risk evaluation.
- **Mint path (write stays on the existing-style path, not `/capabilities/`):**
  `/polymarket/<w>/capabilities/new` → produces `<capability-id>`. Subsequent
  orders write to `/polymarket/<w>/capabilities/<id>/order` and are auto-signed
  while the window is open.
- **Disk:** `<bloom home>/polymarket/<wallet>/capabilities/<id>.json`,
  alongside the existing `builder_creds.json`
  (`crates/bloom-polymarket/src/order_store.rs:8-11`).
- **VFS README:** add `/polymarket/README.md` as a vendored constant mirroring
  `/hyperliquid/README.md` (`crates/bloom-vfs/src/handlers/hyperliquid.rs:70-121`).
  Polymarket has no orientation doc today.

### Relationship to builder keys

Builder API keys are relayer submission auth only; they cannot move funds and
every wallet operation still carries the owner signature
(`crates/bloom-polymarket/src/builder_creds.rs:1-12`). They are correctly
classified `ServiceAuthOnly` and are NOT promoted to trading authority by this
plan.

## Tier 0 — Docs And Microcopy (no architecture)

Most of this is propagation of framing that already exists for Hyperliquid.
Today `EXAMPLES.md`, `QUICKSTART.md`, and
`crates/bloom-vfs/src/docs/agent-guidance.md` (the root `AGENTS.md` /
`CLAUDE.md`) contain zero mentions of `hyperliquid`, `agent_sessions`, or
capabilities.

1. Propagate the capability-first triad into all three docs: "reads are safe /
   direct writes need owner approval / automated action uses a capability."
2. Replicate the HL locked-wallet remediation text
   (`crates/bloom-vfs/src/handlers/hyperliquid.rs:1402-1433`) to the EVM and
   Polymarket deny paths. Every deny answers "what would I change to make this
   allowed?" — not just "what failed?"
3. Add `unlocked: bool` to `/wallets/<w>/addresses.json`
   (`crates/bloom-vfs/src/handlers/wallets.rs:137-148`). Currently exposes
   `policy_status` but not whether the signer is cached. One-line change; lets
   an agent cheaply decide `unlock` vs `create capability`.
4. Add `/polymarket/README.md` and `/defi/README.md` vendored constants
   (mirror `crates/bloom-vfs/src/handlers/hyperliquid.rs:70-121`).
5. Write the security rules into `DIRECTION.md`:
   - Passkeys approve durable, bounded capabilities; agents operate inside them.
   - The owner key is never handed to agents. Keeping the owner key confined
     to a single trusted process (the daemon) is the target invariant; today
     some CLI flows unlock inside the CLI process.
   - `HoldsDelegatedKey` is preferred where the venue protocol allows it.
   - `AuthorizesOwnerSigning` is acceptable only with a `KeyResidencyLease`
     that auto-locks on expiry/revocation.
   - `ServiceAuthOnly` credentials never move funds and are not trading
     authority.

## Tier 1 — Read-Only Capability Surfaces

1. `CapabilityView` trait in `crates/bloom-proto/src/capability.rs` (new) +
   `HlCapabilityView` and `EvmPolicyCapabilityView` impls.
2. `/wallets/<w>/capabilities/` subtree rendered by iterating registered views
   (shape above). Read-only.
3. `/next.md` at the VFS root — the "what do I do next" aggregator. Generalizes
   the only existing next-action pattern
   (`crates/bloom/src/commands/polymarket.rs:2221-2324`) into a VFS-wide
   surface. Aggregates:
   - unsigned-policy wallets;
   - pending outbox confirms awaiting review;
   - orphaned HL sessions needing owner cleanup;
   - expiring capabilities;
   - stale snapshots.
4. `/status/audit/recent.md` — render the existing hash-chained audit log
   (`crates/bloom-vfs/src/router.rs:104-140`) as plain-English narrative.
   Data already exists; agents cannot currently read it as a story.
5. Per-capability `status.md` rendering alongside the existing `.json`. Honest
   fields, not the derived `tradable` headline.
6. Promote `hyperliquid_agent_session_grant` from `CeremonyIntentKind::Other`
   to first-class `CapabilityGrant`
   (`crates/bloom-proto/src/ceremony.rs:19`,
   `crates/bloom-proto/src/hyperliquid_review.rs:35`).

## Tier 2 — Polymarket Capability + Auto-Lock

1. `KeyResidencyLease` on the keystore + auto-lock on expiry/revocation.
2. Polymarket capability primitive (scoped approve, TTL, caps, drawdown
   evaluator, mint/store/lifecycle).
3. `PolymarketCapabilityView` wired into the roll-up.

## Sequencing And Dependencies

```text
Tier 0 (parallel, independent) ─────────────────────────────────────► ship

Tier 1.1 (CapabilityView trait) ──► Tier 1.2 (capabilities subtree)
                                  ► Tier 1.3 (/next.md)
                                  ► Tier 1.5 (status.md)              ► ship
[Tier 1.4 audit narrative, 1.6 ceremony kind — parallel with above]

Tier 2.1 (KeyResidencyLease) ──► Tier 2.2 (Polymarket capability) ──► Tier 2.3 (view wiring)
```

- Tier 0 has no dependencies and unblocks agents immediately.
- Tier 1.1 (`CapabilityView` trait) unblocks Tier 1.2 and Tier 2.3.
- Tier 2.1 (auto-lock) must land before Tier 2.2 (Polymarket capability),
  because the capability's safety claim depends on the lease.

## Definition Of Done

A cold-start agent with a bloom wallet can, by reading three files
(`/wallets/<w>/capabilities/active.md`, `/next.md`, `/docs/README.md`), answer:

- What can I do with this wallet without a human?
- Which venue should I act on, and what is the exact path to write to?
- What is already in flight that needs my attention?

And on Polymarket specifically, the agent can:

```text
create a capability that lets me place up to $50 of YES orders
on markets X and Y, max price 0.70, expires in 30 minutes,
max drawdown $10
```

…with one owner ceremony, and place matching orders inside that window without
re-prompting. The owner key auto-locks when the window ends. No ceremony per
trade.

## Explicitly Deferred

- Writable unified `/capabilities/{new,revoke}` namespace — wait until the read
  model is validated.
- `/dryrun/` capability simulation.
- ERC-4337 / funded hot-wallet for EVM true key delegation.
- Migrating existing writes off `/policy-session/` and `/agent_sessions/`.
- MCP projection of capability surfaces.
