# Hyperliquid Integration

**Status (2026-06-19): implemented and live-exercised in small size.**
This document is the reviewer-facing map of Bloom's Hyperliquid surface. It
describes what exists today, which paths are read-only vs signed, where the
safety boundary lives, and which gaps are still deferred.

## Code map

- VFS handler: `crates/bloom-vfs/src/handlers/hyperliquid.rs`
- Exchange client and signing: `crates/bloom-hyperliquid/src/lib.rs`
- Policy model: `crates/bloom-proto/src/hyperliquid_policy.rs`
- Session model: `crates/bloom-proto/src/hyperliquid_session.rs`
- Ephemeral API-wallet key storage: `crates/bloom-keystore/src/ephemeral.rs`
- CLI entrypoints: `crates/bloom/src/main.rs`

## Implemented read surface

All read paths are available under `/hyperliquid/<network>/...` for
`mainnet` and `testnet`.

Network and market data:

- `status.json`
- `mids.json`
- `perp_meta.json`
- `perp_contexts.json`
- `predicted_fundings.json`
- `spot_meta.json`
- `spot_contexts.json`
- `books/<coin>.json`
- `candles/<coin>/<interval>.json`
- `recent_trades/<coin>.json`
- `asset_contexts/<coin>.json`
- `funding_history/<coin>.json`

User/account data:

- `users/<account>/clearinghouse.json`
- `users/<account>/spot_state.json`
- `users/<account>/open_orders.json`
- `users/<account>/frontend_open_orders.json`
- `users/<account>/fills.json`
- `users/<account>/portfolio.json`
- `users/<account>/rate_limit.json`
- `users/<account>/funding/<coin>.json`

These reads are best-effort. The client now retries transport failures with
bounded jittered backoff, but there is still no stale-cache layer for `/info`.

## Implemented signed direct writes

Direct exchange writes live at `/hyperliquid/<network>/exchange/<wallet>/...`.
They sign and submit immediately after policy checks.

- `order.json`
- `cancel.json`
- `schedule_cancel.json`
- `update_leverage.json`
- `raw_signed.json`

Readback:

- `last_response.json`

Current action coverage behind those paths:

- place perp or spot orders
- cancel by order id
- set or clear the venue dead-man switch (`scheduleCancel`)
- update leverage
- submit a caller-provided fully signed payload after Bloom validates the
  request shape and applies the policy gate; malformed payloads are rejected
  before policy evaluation because no typed action exists to inspect

## Implemented agent-session surface

Session paths live at `/hyperliquid/<network>/agent_sessions/<wallet>/...`.

Create:

- `new.json`

Per-session:

- `status.json`
- `session.json`
- `audit.jsonl`
- `order.json`
- `cancel.json`
- `schedule_cancel.json`
- `stop`
- `cancel_all`
- `close_all`
- `orphan_cancel_all`
- `orphan_close_all`

The intent is:

1. the owner wallet signs `approveAgent` once;
2. Bloom mints an ephemeral Hyperliquid API wallet;
3. the daemon keeps only the ephemeral agent key in memory;
4. session writes use the agent key, but every action still passes the wallet's
   verified `[hyperliquid]` policy and the session lifecycle gate.

## Policy boundary

The hard safety boundary for Hyperliquid writes is the per-wallet
`[hyperliquid]` policy plus the session lifecycle checks.

What the current evaluator can enforce:

- trading must be explicitly enabled for the wallet
- allowed assets
- allowed order types
- max leverage
- max order notional
- max position size
- max loss
- allow/deny trigger orders
- allow/deny TWAP orders
- allow/deny builder orders
- allow/deny vault or subaccount writes
- max session duration

Important behavior:

- direct exchange writes are now opt-in; an unconfigured `[hyperliquid]` policy
  denies trading
- allowlists fail closed when asset resolution is unavailable
- `max_loss_usd` in the pure per-action policy gate currently keys off the live
  snapshot's unrealized loss estimate only; session-level realized drawdown
  belongs to the Hyperliquid session monitor / lifecycle layer
- unknown action kinds default-deny
- forced cleanup paths for expired or breached sessions bypass the normal
  trading-policy gate so a later policy edit cannot block flattening

## API-wallet risk model

Hyperliquid API wallets are not "just another order signature." `approveAgent`
creates standing venue authority until it expires or is replaced.

Bloom's model is:

- owner signs `approveAgent`
- daemon holds the ephemeral API-wallet key only in memory by default
- session lifecycle enforces TTL and cumulative session state
- the session monitor can trigger `cancel_all` or `close_all`
- audit records are persisted for session creation, writes, policy decisions,
  and cleanup actions

This is intentionally stronger than repeated passkey prompts per order, but it
also means the daemon is temporarily trusted with live trading authority inside
the policy envelope.

The owner passkey review must be plain-language first. It should answer:

- what Bloom can do: trade on Hyperliquid inside the listed limits
- for how long: the configured session TTL
- how large: max order, max position, max loss, and max leverage
- what Bloom cannot do: withdrawals and third-party transfers

Internal ceremony fields such as intent hashes, path names, and raw canonical
subjects are audit/debug details and belong behind advanced details, not in the
main user decision.

## Cleanup expectations

Normal lifecycle:

- active session cleanup is automatic via the in-memory agent key
- expiry or breach can trigger `cancel_all` or `close_all`

Restart/crash lifecycle:

- if the daemon restarts, the session becomes orphaned because the ephemeral
  agent key lived in memory
- orphaned sessions report `tradable: false`
- recovery is explicit and owner-signed through `orphan_cancel_all` or
  `orphan_close_all`

This is a deliberate authority boundary: Bloom does not auto-take owner-key
cleanup actions on startup.

## Known limitations

Still missing:

- Hyperliquid withdrawals
- Hyperliquid transfers or class transfers
- WebSocket surface

Implemented but not fully hardened:

- `/info` reads still have no stale-cache layer
- the session monitor is fail-stale on snapshot read failure: it keeps
  last-known risk and will not auto-flatten on a transient read error
- live retry behavior for `/info` is structurally tested, not fault-injection
  tested with a mock HTTP server

## Reviewer checklist

Good review targets for this PR:

- direct writes cannot bypass the `[hyperliquid]` policy gate
- session writes pass both policy and lifecycle checks
- forced cleanup can still flatten after a later policy change
- orphaned-session cleanup uses the owner key, not the missing agent key
- `approveAgent` signing matches Hyperliquid's documented EIP-712 shape
- operator-facing docs and VFS hints match the real exported paths
