# Hyperliquid Integration Hardening Plan

**Status:** Active plan.
**Date:** 2026-06-19.

## Context

Bloom's Hyperliquid integration is real and useful, but it is not yet reliable
enough for unattended bounded trading. The core architecture is mostly right:

- `bloom-hyperliquid` isolates signing and client behavior.
- `hyperliquid_policy.rs` is pure, fail-closed, and default-deny.
- Ephemeral trade-only agent keys are the right authority model.
- The VFS surface is broad enough to support real reads, writes, and session
  workflows.

The gaps are now mostly operational and correctness issues:

- the named-agent slot model is not durable under repeated session creation;
- session status can wobble between `tradable` / `orphaned` states;
- session order mutation and repricing need stricter verification;
- some safety-critical paths are only structurally tested;
- the main VFS handler has grown too large to maintain comfortably.

One important correction: preserving the current restart-as-kill-switch property
is part of the security model. Any move toward at-rest persistence of
Hyperliquid trading authority is a separate security design, not a routine
reliability hardening task.

This plan turns those findings into a concrete sequence.

## Goals

1. Make "one signature, then bounded session trading" dependable during a
   single daemon lifetime.
2. Preserve the trade-only agent security model; do not fall back to a cached
   owner signer for routine trading.
3. Preserve the current restart-as-kill-switch property unless and until a
   separate approved design changes it.
4. Close the highest-risk correctness gaps before adding major new features.
5. Raise test confidence on network-touching and safety-critical paths.
6. Split the Hyperliquid handler into maintainable submodules without changing
   behavior.

## Non-Goals For This Plan

- Full WebSocket support.
- Hyperliquid withdrawals or transfers unless the policy model lands first.
- Strategy sophistication beyond bounded test trading.
- Broad product/UX redesign beyond targeted Hyperliquid operator clarity.

## Current Assessment

### What is fundamentally sound

- Dedicated Hyperliquid crate and signing/client separation.
- Policy evaluator design and per-wallet policy enforcement.
- Session-scoped agent model with venue-enforced trade-only keys.
- Read-only VFS surfaces: books, candles, funding, user/account state, fills,
  rate limit, contexts, and extra agents.
- Manual owner-signed orphan recovery path.

### What is still not reliable enough

1. **Agent-slot exhaustion**
   - Default session creation burns named agent slots.
   - Hyperliquid only allows one unnamed agent and up to three named agents.
   - The headline "one signature, then session trading" flow is not durable
     until Bloom reuses names intentionally.

2. **Session state inconsistency**
   - Live use exposed inconsistent `tradable` / `orphaned` / active-session
     state.
   - A session that still accepted writes could also report itself as not
     tradable or orphaned.
   - This undermines operator trust and makes automation brittle.

3. **Session order correctness**
   - Live repricing behavior needs tighter validation.
   - We need stronger guarantees that caller-supplied order parameters survive
     normalization and replacement as intended.

4. **Daemon/session durability**
   - Memory-only agent keys are an intentional security choice today.
   - Restart behavior currently kills live session authority and may require
     manual cleanup.
   - That is acceptable as a security boundary for now, but Bloom needs to make
     the consequence explicit and operationally clean.

5. **Thin integration-boundary tests**
   - Important paths still lack fault-injected or mocked transport tests:
     approveAgent vector checks, retry behavior, forced cleanup, orphan
     recovery, and session recovery.

6. **Oversized VFS handler**
   - `crates/bloom-vfs/src/handlers/hyperliquid.rs` is large enough to slow
     review and increase regression risk.

## Workstreams

### Workstream 1: Session Reliability

This is the immediate priority. Bloom should not promise unattended bounded
trading until these items are done.

#### 1.1 Agent-slot lifecycle

Build a durable named-agent policy for Bloom-managed sessions.

Concrete decision for this plan:

- **Default concurrency model: serial single-session reuse.**
- Bloom manages **one reusable named agent slot by default** for bounded session
  trading.
- Bloom does **not** use the unnamed slot by default.
- Bounded concurrent named sessions are deferred until Bloom has an explicit
  multi-slot lifecycle design.

Required behavior:

- Stop generating effectively unique names by default.
- Set the default bounded-session concurrency to **1 active session per
  `(network, wallet)`**.
- Route default session creation through a single stable named slot such as
  `bloom-session` (or one configured replacement name).
- Reuse names only under rules that cannot clobber active sessions.
- Exclude any slot currently backing an active Bloom session from reuse.
- If all reusable slots are occupied by active sessions or foreign names, fail
  with an explicit operator-facing error and guidance.
- Keep supporting explicit `agent_name` overrides for manual rotation.

Implementation notes:

- Reuse existing `extra_agents.json` visibility.
- Session creation should surface current slot pressure in errors and review
  context.
- Reuse the Hyperliquid venue rule that re-approving an existing name rotates
  the address in that slot.
- The single-slot default means a new session create must fail if another Bloom
  session for that wallet/network is active. No silent rotation of a live slot.
- Under the fixed-name model, **re-approving the same stable name is the slot
  reuse mechanism**. Bloom does not need a separate venue deregister call to
  make the next session possible; the next `approveAgent` for `bloom-session`
  replaces the prior agent address in that slot.
- The one remaining lifecycle seam is the stop -> next-create gap:
  - stopping a session is local and does not immediately invalidate the venue
    agent;
  - until the next create re-approves `bloom-session`, the last agent for that
    name may remain venue-live;
  - for this plan, Bloom should document that behavior explicitly rather than
    attempting an implicit post-stop rotation.
- Durable "Bloom owns this name" state is satisfied by convention under the
  fixed-name model: Bloom always treats the stable configured slot name (for
  example `bloom-session`) as its own reusable bounded-session slot.
- Account for the three already-live named agents during migration by choosing a
  single Bloom-owned stable name and standardizing on it.

Rationale for the chosen default:

- It matches today's actual safety model: in-memory agent key, restart kills
  authority, owner can recover.
- It avoids the hardest correctness problem: re-approving a named slot that is
  still backing a live session.
- It respects Hyperliquid's signer/nonce guidance that each trading process
  should use its own API wallet. Name reuse does **not** imply key reuse:
  every new session still mints a fresh ephemeral agent key and only reuses the
  stable slot name.
- It keeps the headline UX simple: one passkey ceremony authorizes one bounded
  trading process.
- It avoids burning the unnamed slot, which is lower-observability and more
  likely to collide with unrelated tooling.

Why not bounded concurrent named sessions in this plan:

- Bloom currently has no durable ownership model for multiple names.
- `stop_session` is local-only; it does not truly free venue-side capacity.
- Restart/orphan behavior is still being hardened.
- A safe multi-slot design needs explicit rules for active-slot exclusion,
  venue expiry, operator overrides, and migration of already-existing agents.

Why not use the unnamed slot by default:

- The current VFS create path always supplies a name, so unnamed usage is not
  presently exposed.
- The unnamed slot is less diagnosable in `extraAgents` and easier to collide
  with if other tools also rely on the account's unnamed agent.
- Named reuse gives Bloom and the operator a stable identifier to reason about
  during review and recovery.

Definition of done:

- Only one bounded Hyperliquid session can be active per wallet/network under
  the default flow.
- Bloom cannot accidentally re-approve the name of an active session.
- Session create must consult both in-memory active state and persisted/orphaned
  session state so a daemon restart cannot silently permit a second bounded
  session while the prior slot may still be venue-live.
- Bloom can explain, for every named slot it sees, whether it is active,
  reusable, foreign, or unknown.
- A user can create, stop, and recreate sessions without hidden slot leaks under
  the chosen concurrency model.

Future expansion, deliberately deferred:

- Opt-in concurrent named sessions with an explicit configured cap.
- Explicit support for the unnamed slot as an expert/manual path if a real use
  case emerges.

#### 1.2 Session truth model

Pin the source of truth for:

- `tradable`
- `orphaned`
- `status`
- active daemon registration
- ephemeral key presence
- expiry/stopped flags

Required behavior:

- `tradable` is derived from stable invariants only.
- `orphaned=true` means the daemon has definitely lost the agent key needed to
  continue trading.
- Read-time refresh must not transiently flip session authority state.
- Status should be internally coherent even under concurrent reads and monitor
  updates.

Known live symptom to root-cause:

- A session that still accepted writes also intermittently reported
  `tradable=false` and/or `orphaned=true`.

Likely code path to confirm or falsify:

- `session_status_value` appears able to fall back to orphaned-session handling
  when active-session lookup fails transiently. The fix should target the real
  invariant break, not merely add more retries or smoothing.

Definition of done:

- The same live session does not oscillate between tradable and orphaned states
  without a real lifecycle change.

#### 1.3 Ephemeral key retention

Do not put sealed agent-key persistence on the merge bar.

Current position:

- Restart-as-kill-switch is a meaningful security property.
- There is currently no daemon KEK design, provenance, derivation, storage, or
  threat model in the codebase.
- "Sealed at rest" is not acceptable as a casual implementation detail if the
  same machine can recover both blob and KEK without user involvement.

What this workstream should do now:

- Make restart behavior explicit in status, docs, and operator recovery paths.
- Improve orphan cleanup and diagnostics.
- Separate a future "persistent session authority" design into its own plan.

Future design questions, if this is ever pursued:

- Where does the KEK come from?
- What attacker is it meant to resist?
- Can filesystem access recover live trading authority?
- How is nonce continuity handled across restart?
- How does persisted state interact with venue-side agent expiry?
- How does persisted state interact with name rotation and slot reuse?

Definition of done for this plan:

- Restart consequences are explicit and safe.
- Operators have a clear recovery path after restart.
- No at-rest Hyperliquid trading secret is added as part of merge hardening.

#### 1.4 Session order semantics

Harden the session order path so the signed exchange payload is inspectable and
predictable.

Required behavior:

- The requested action, normalized action, and final exchange payload are all
  auditable.
- Cancel/replace and repricing must preserve caller intent.
- Order-path normalization should be deterministic and explicitly tested.

Known live symptom to root-cause:

- During live trading, attempts to tighten a resting reduce-only exit appeared
  to continue producing the same effective exit price/order shape rather than
  the newly requested one.

This must be treated first as a correctness bug, not merely a testing gap.

Definition of done:

- A live or mocked replace/reprice sequence produces the exact intended price,
  side, reduce-only flag, and tif.

### Workstream 2: Safety and Cleanup

#### 2.1 Monitor behavior

Current state:

- Expiry cleanup works.
- Risk snapshot staleness is visible.
- The monitor is still fail-stale on read errors.

Plan:

- Keep current visibility fields:
  - `stale`
  - `last_snapshot_ok_ms`
  - `stale_since_ms`
- Do not add automatic flatten-on-blindness as part of this hardening plan.
- If stale-risk escalation is revisited later, it must explicitly confront the
  contradiction that blind flattening also acts without trusted market reads.
- Ensure cleanup actions remain risk-reducing and cannot be blocked by later
  policy edits.

Definition of done:

- Monitor behavior on read failure is explicit in status/docs, and expiry
  cleanup remains reliable.

#### 2.2 Orphan recovery

Keep the current owner-signed orphan cleanup model, but make it easier to
operate and audit.

Required behavior:

- Clear distinction between:
  - live session cleanup via agent key;
  - orphan recovery via owner key.
- Explicit audit events for owner-signed cleanup.
- Status fields that expose recoverability and next actions.

Definition of done:

- An operator can tell immediately whether a session is active, orphaned, or
  recoverable, and can invoke the appropriate action without ambiguity.

#### 2.3 Direct-write safety cleanup

The VFS Hyperliquid write path is already gated by configured policy. Do not
re-decide that.

Actual follow-up items:

- Verify and close any remaining expert or CLI paths that can bypass the
  intended Hyperliquid trading boundary.
- Re-check `raw_signed.json` and any owner-unlock direct-trade helpers.

Definition of done:

- There is no residual signed trading path that escapes the intended
  Hyperliquid policy boundary by accident.

### Workstream 3: Transport and Integration Testing

The next bugs should be caught locally, not after live trading.

#### 3.1 Mockable Hyperliquid transport

Add an injectable HTTP transport layer or equivalent test seam in
`bloom-hyperliquid`.

Use it to test:

- `/info` retry logic
- non-retry rules for exchange writes
- approveAgent payload shape
- cleanup flows
- session startup/recovery exchange interactions

#### 3.2 External truth vectors

Tests that verify signing must check against external truth, not only Bloom's
own implementation.

Required coverage:

- official Hyperliquid docs
- vendored approveAgent fixture produced once by the official SDK and committed
  into the repo
- recovered signer validation
- final exchange payload shape

This specifically prevents another self-referential `signatureChainId` trap.

#### 3.3 Safety-path integration tests

Add at least one mocked integration-style test for each:

- named-agent slot rotation
- foreign-slot exhaustion failure
- forced cleanup bypass
- orphan cleanup
- session restart recovery
- session status coherence
- session repricing / replace semantics

Definition of done:

- Safety-critical Hyperliquid behaviors are covered by more than pure unit logic
  and more than live manual testing.

### Workstream 4: Code Structure

Refactor the VFS handler after the top correctness bugs are closed.

Suggested split:

- `read_paths`
- `exchange_writes`
- `sessions`
- `monitor`
- `orphan_recovery`
- `status_and_hints`
- `tests`

Rules:

- No behavior change in the split itself.
- Move with focused verification after each extraction.
- Keep one thin facade that wires the route table together.

Definition of done:

- Hyperliquid VFS behavior is easier to review and isolated changes no longer
  require editing a single ~3k-line file.

### Workstream 5: Product Surface and Docs

#### 5.1 Hyperliquid session review UX

Every Hyperliquid session approval should clearly show:

- session id
- agent name
- duration
- allowed assets
- max notional
- max position
- max loss
- leverage cap
- whether the session can survive daemon restart

The passkey ceremony itself cannot carry this information, so Bloom's review
surface must.

#### 5.2 Operator diagnostics

Expose enough state to operate the system without reading code:

- active session count
- slot usage
- daemon monitor state
- key loaded vs orphaned
- last exchange error
- last info/read error

#### 5.3 Hyperliquid docs

Keep docs current for:

- read-only paths
- signed exchange paths
- session lifecycle
- orphan recovery
- API-wallet risk model
- known limitations

### Workstream 6: Deferred Feature Expansion

Do not start these until Workstreams 1-3 are substantially done.

#### 6.1 Withdrawals and transfers

Prerequisite:

- policy model for withdrawal/transfer/class-transfer actions
- explicit caps and allowlists
- tests before public write surfaces

#### 6.2 WebSocket surface

Scope later:

- subscriptions for books, trades, orders, fills, account updates
- daemon/event integration
- policy-neutral read/event surface first

#### 6.3 Strategy layer

Only after session reliability is proven:

- bounded automated strategies
- better maker/taker logic
- higher-level session templates

## Priority Order

### Merge / immediate bar

1. Fix agent-slot exhaustion.
2. Fix session state coherence.
3. Make restart/orphan behavior explicit and operationally clean without adding
   at-rest trading-key persistence.
4. Fix session order/reprice correctness.
5. Add mocked coverage for the above.

### Near-term after merge bar

6. Improve orphan recovery diagnostics.
7. Close any residual direct-write/CLI boundary leaks.
8. Split the VFS handler.

### Later expansion

9. Separate design for persisted session authority, if ever wanted.
10. Withdrawals/transfers design and implementation.
11. WebSocket surface.
12. Strategy layer.

## Suggested Ownership Split

To reduce collisions:

- `bloom-hyperliquid`: transport seam, signing vectors, retry behavior.
- `bloom-proto`: policy/session semantics, status model, durable session state.
- `bloom-keystore`: deferred only, if a future separate plan introduces
  persisted session authority with an approved KEK model.
- `bloom-vfs`: session routing, monitor/orphan recovery, diagnostics, docs.
- `bloom` / daemon: approval UX, daemon lifecycle, startup session resume.

## Acceptance Criteria

This Hyperliquid work is in good shape when all of the following are true:

1. A bounded session can be created repeatedly without exhausting agent slots.
2. A daemon restart does not silently surprise the operator; the resulting
   cleanup/recovery path is explicit and auditable.
3. Session status is coherent and stable under concurrent reads/writes.
4. Session order replacement is deterministic and auditable.
5. Safety cleanup paths are tested with mocked transport, not only live/manual
   verification.
6. Operators can understand Hyperliquid session authority and risk bounds before
   signing.
7. The large VFS handler is split enough that future review does not require
   reading one monolithic file.

## Immediate Next Steps

1. Specify the named-agent concurrency model and slot reuse rules.
2. Reproduce and fix the live `tradable` / `orphaned` inconsistency.
3. Diagnose the live session order/reprice mismatch as a concrete bug.
4. Add mocked regression coverage for session status, slot reuse, and order
   repricing before relying on more live trading.
