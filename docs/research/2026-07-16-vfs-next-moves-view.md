# Issue 114: VFS Next Moves view

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Treat Next Moves as a small priority inbox, not a dashboard or an investment
recommendation engine:

```text
/next.json                         canonical cross-wallet signals for agents
/next.md                           universal human-readable fallback
/next.html                         optional rich, self-contained view
/wallets/<wallet>/next.{json,md,html}  filtered views of the same signals
```

Keep the existing `/next.md` path and add JSON as the source of truth. Markdown and
HTML are Bloom-owned renderers over one typed snapshot; the agent does not populate
these files. The agent may explain or combine the signals with the
[portfolio snapshot](./2026-07-16-vfs-portfolio-views.md), but Bloom should produce the
underlying facts deterministically.

The UI should have only two lanes in V0:

- **Needs attention** — safety risks, blocked workflows, and approvals with a real
  deadline or consequence.
- **Available now** — concrete follow-ups such as redeeming a resolved position.

A future opt-in **Explore** lane may contain speculative opportunities. Keeping it
separate prevents an airdrop lead from looking as trustworthy or urgent as liquidation
risk. The inbox model also fits persistent conditions better than a chronological feed;
GitHub's notification inbox similarly groups unresolved items and supports later triage
without making time order the main hierarchy
([GitHub notification inbox](https://docs.github.com/en/subscriptions-and-notifications/how-tos/viewing-and-triaging-notifications/managing-notifications-from-your-inbox)).

## V0 signals

| Signal | Emit when | Do not emit when |
|---|---|---|
| Approval required | A canonical action is staged or challenged and still awaits the user | Merely because an owner-signing session exists |
| Stuck EVM transaction | It is unmined and the bump scanner has produced current advice | It has since mined, even if old advice files remain |
| Polymarket onboarding | Persisted onboarding is awaiting funding, failed, or past its in-flight deadline | It never started, is actively in flight, or is complete |
| Polymarket redemption | A position is explicitly `redeemable` | A market merely approaches its end date |
| Hyperliquid margin risk | An account-mode-correct margin ratio crosses an explicit warning threshold | Leverage alone is high |
| Hyperliquid monitoring failure | Risk data is stale beyond a grace period while exposure remains | The account has no open exposure or a single refresh failed |
| Hyperliquid cleanup/recovery | Cleanup failed, or an orphaned session still has open exposure | A session simply expired and cleaned up successfully |
| Policy setup | A real workflow is blocked by an unsigned or stale policy | A passkey wallet exists but no requested workflow needs the policy |

For Hyperliquid, use the venue's account state and account mode. Cross positions share
collateral, and the displayed liquidation price can change with funding and PnL in other
positions, so a naive per-position distance is not a sufficient risk score
([Hyperliquid margining](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/margining),
[liquidations](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/liquidations)). Show the
actual ratio and use two named, configurable bands such as `warning` and `critical`;
do not hide the decision behind an opaque 0–100 ranking score.

V0 should deliberately exclude:

- Generic airdrop discovery. There is no universal safe claim registry; eligibility and
  proofs are often off-chain. Add rewards only through an explicit trusted provider,
  never from unsolicited tokens or embedded URLs
  ([MetaMask airdrop-scam guidance](https://support.metamask.io/stay-safe/protect-yourself/nfts/nft-airdrop-scams/)).
- Generic low-gas nags. Surface gas only when it blocks a known action or violates a
  user-configured reserve.
- Price predictions, trade ideas, and “sell before this market ends” suggestions. Those
  are agent interpretation over portfolio facts, not canonical Bloom signals.
- Durable Done/Snooze state. Stable item identities make this possible later, but V0 can
  derive completion when the underlying condition clears.

## Data contract

Every format should carry the same `snapshot_id` and `as_of_ms`. A minimal JSON shape is
enough:

```json
{
  "schema": "bloom.next_moves.v1",
  "snapshot_id": "...",
  "as_of_ms": 1784217600000,
  "items": [
    {
      "id": "stuck_tx:alice:ethereum:0001",
      "wallet": "alice",
      "lane": "needs_attention",
      "kind": "stuck_transaction",
      "urgency": "soon",
      "title": "Transaction is still pending",
      "why_now": "Pending for 143 seconds; replacement advice is available",
      "deadline_ms": null,
      "estimated_value_usd": null,
      "evidence": [
        {
          "path": "/wallets/alice/chains/ethereum/outbox/sent/0001/bump_advice.json",
          "as_of_ms": 1784217600000
        }
      ],
      "next_steps": [
        {
          "label": "Review replacement advice",
          "operation": "read",
          "path": "/wallets/alice/chains/ethereum/outbox/sent/0001/bump_advice.json",
          "requires_approval": false
        }
      ]
    }
  ],
  "coverage": [],
  "errors": []
}
```

Use stable item IDs derived from `rule_id + wallet + subject + condition version`.
Order deterministically by lane, urgency, deadline, then ID. Each item must say what was
observed, why it matters now, where the evidence lives, and which supported next steps
exist. Use decimal strings for monetary values in the real schema.

`coverage` and `errors` are required even when `items` is empty. “Nothing needs
attention” must not be indistinguishable from “Hyperliquid and Polymarket both failed to
load.”

## Safety and interaction

Next Moves is discovery, not authorization. A next step may point to a plan, staging
path, or ceremony, but the existing policy and passkey flow remains the authority for
value movement. HTML should not contain forms that bypass that boundary. It should be
script-free, read-only, self-contained, escape provider text, and make no network
requests. Markdown remains the reliable cross-client view because Codex, Claude,
OpenCode, and other chat hosts cannot be assumed to render arbitrary VFS HTML.

Risk items should present options rather than a prescriptive trade. For example, a
margin warning can identify “reduce exposure,” “add collateral,” and “leave unchanged”
as possibilities while requiring the agent to prepare any selected action through the
normal review path.

Never advertise a path as an action unless it works. If Bloom detects an orphaned
Hyperliquid session while owner recovery is unsupported, the item should say that Bloom
cannot perform recovery and direct the user to an established manual recovery route; it
must not render a broken Bloom button.

## What exists and what is missing

The repository already has `/next.md`, but it is a synchronous closure in
[`bloom-daemon`](../../crates/bloom-daemon/src/lib.rs). It currently:

- treats active owner-signing sessions as “pending outbox confirms,” which is not the
  canonical pending-action state;
- reports only part of the Hyperliquid capability lifecycle;
- advertises orphan recovery paths that currently fail closed as unsupported;
- can render a blank page when Hyperliquid is mounted but there are no signals; and
- has no focused tests.

The supporting state also needs small typed accessors:

- [`CentralOutbox`](../../crates/bloom-vfs/src/handlers/outbox.rs) has no public typed
  listing API, and today only EVM actions are fully projected into it. Add an explicit
  summary API and temporary venue adapters; do not crawl the VFS internally. Longer
  term, all sealed flows should project into the central lifecycle.
- [`RootContentRenderer`](../../crates/bloom-vfs/src/router.rs) is synchronous,
  infallible, and outside the path cache. Portfolio-derived signals need an async,
  fallible root renderer or a dedicated handler backed by the shared snapshot cache.
- Polymarket's [`Position`](../../crates/bloom-polymarket/src/types.rs) drops `slug`,
  `currentValue`, PnL, and `endDate`, although the upstream response supplies them. The
  redeem signal needs at least `slug`, `conditionId`, `redeemable`, and current value
  ([Polymarket positions API](https://docs.polymarket.com/api-reference/core/get-current-positions-for-a-user)).
- The Polymarket rules should consume the typed `OnboardState` and its terminal
  `Complete` stage; existing rendered account status has inconsistent tradeable-stage
  logic.
- Hyperliquid's capability roll-up lacks the exposure, stale-age, and cleanup-error data
  needed to decide whether a session state is actually actionable.
- `bump.tx` and `cancel.tx` are advisory today, not directly stageable. Surface them as
  evidence until the normal intent parser can safely accept explicit replacement fees.

## Suggested implementation sequence

1. Add a versioned `NextMovesSnapshot` model and a testable `NextMovesService` in the
   VFS layer. Inject the existing local stores plus the planned shared
   `PortfolioSnapshotService`.
2. Replace the current `/next.md` closure with async, fallible JSON/Markdown/HTML
   renderers over one cached snapshot. Root is the cross-wallet view; wallet paths are
   filters over the same item model.
3. Implement only the V0 rules above with source timeouts, stable IDs, explicit
   evidence, and honest coverage. Query independent wallet/venue sources concurrently.
4. Add fixture tests for each rule and its clearing condition, partial provider failure,
   deterministic ordering, supported action paths, empty-state coverage, and matching
   snapshot IDs across formats.
5. Add opt-in reward providers, user triage state, and an Explore lane only after the
   deterministic inbox has proven useful.

V0 is ready when `/next.json` never invents a recommendation, every surfaced action is
supported, safety signals survive partial provider failure, and the Markdown/HTML views
are pure presentations of the same evidence-backed snapshot.
