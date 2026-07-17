# Issue 114: VFS Activity view

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Build Activity as a user-centered timeline of wallet outcomes, not a merged transaction
explorer or a rendering of Bloom's audit log:

```text
/wallets/<wallet>/activity.json                    latest canonical snapshot
/wallets/<wallet>/activity.md                      universal readable timeline
/wallets/<wallet>/activity.html                    optional rich timeline
/wallets/<wallet>/activity/events/<event_id>.json  exact detail and evidence
```

One card should answer **what changed, where, when, and with what status**. A swap may
involve an approval, router call, several transfers, and an indexer row, but it is still
one user action. Those implementation steps and asset effects belong inside the card.

Keep two visual layers:

```text
In progress
┌ Awaiting approval ───────────────────────────────┐
│ Swap 100 USDC → ETH                             │
│ Base · prepared 2 minutes ago · Review →        │
└─────────────────────────────────────────────────┘

Today
  Sent 25 USDC to alice.eth
  Base · Finalized · 14:32
  −25 USDC · fee 0.00003 ETH

  Bought 40 YES on “Will …?”
  Polymarket · Filled · 12:06
  −24.80 USDC · +40 YES
```

- **In progress** pins actions that are awaiting approval, submitted, partially filled,
  or included but not yet sufficiently final.
- **Timeline** groups settled outcomes by local calendar day, newest first.
- **Details** disclose full addresses, hashes, order IDs, blocks, finality, sources,
  warnings, and conflicts without making raw identifiers the primary interface.

Activity is history and current lifecycle. [Next Moves](./2026-07-16-vfs-next-moves-view.md)
remains the priority inbox for what the user might do next. A pending Activity card may
link to an existing read-only review path, but Activity never adds a confirm button or
bypasses policy, passkeys, or Sealed Approval.

## What counts as one activity

Create an item when Bloom stages a canonical action, submits an order or transaction,
or discovers a verified external wallet effect. Exclude pure reads, simulations,
unsubmitted drafts, and individual signature ceremonies.

Use exact identifiers to group evidence:

- Bloom `action_id` for one lifecycle and a new `workflow_id` for related steps such as
  approve-then-swap.
- EVM chain ID plus transaction hash; link the local outbox by its persisted hash.
- Hyperliquid trade ID (`tid`) for a fill and order ID (`oid`) for its parent order.
- Polymarket CLOB trade ID and order ID; use the Data API transaction hash and typed
  event fields only for activity outside the order lifecycle.

Never group merely because amounts and timestamps are close. When exact linkage is not
available, preserve separate events rather than manufacture certainty. Merge overlapping
feeds into one item while retaining every source as evidence and surfacing conflicts.

A Bloom-originated item keeps an ID derived from its `workflow_id` or `action_id` from
staging through settlement; it does not acquire a new URL when a transaction hash or
order ID appears. An externally discovered item derives its ID from the source's stable
canonical identity. In both cases, expose a bounded path-safe digest such as `evt_<base32>`
and retain the exact identifiers as evidence. Never place an unbounded provider string
directly into a VFS path.

Examples of grouping:

| Evidence | User-visible result |
|---|---|
| Local outbox + EVM normal tx + ERC-20 transfer with one hash | One token-send card |
| Explicit approval dependency + swap route | One swap card with two transaction steps |
| Polymarket local receipt + authenticated trades for its order ID | One order card with partial fills |
| Hyperliquid fills sharing an order ID | One order outcome; individual trade IDs remain evidence |
| Failed EVM receipt | One failed card showing the fee, but no successful transfer effect |
| Replacement or cancellation chain | One lifecycle, not several successful-looking transactions |

Authority changes such as approvals, revocations, sessions, and wallet-policy updates
belong in Activity when they have a canonical action and user-visible effect. Routine
VFS reads, passkey implementation events, and raw audit entries do not.

## Data contract

All formats are pure renderings of one cached `ActivitySnapshot` and share its
`snapshot_id` and `as_of_ms`. A compact shape is enough:

```json
{
  "schema": "bloom.activity.v1",
  "snapshot_id": "...",
  "wallet": "alice",
  "as_of_ms": 1784217600000,
  "display_timezone": "America/Argentina/Cordoba",
  "in_progress": [],
  "events": [
    {
      "id": "evt_7K4M...",
      "kind": "token_transfer",
      "origin": "bloom",
      "status": "succeeded",
      "finality": "finalized",
      "effective_at_ms": 1784212320000,
      "title": "Sent 25 USDC to alice.eth",
      "action_id": "...",
      "workflow_id": null,
      "account": "eip155:8453:0x1234...",
      "effects": [],
      "steps": [],
      "fees": [],
      "counterparties": [],
      "warnings": [],
      "evidence": []
    }
  ],
  "next_cursor": null,
  "coverage": [],
  "errors": []
}
```

Amounts and money use decimal strings. Effects are typed, signed asset or authority
changes with chain-qualified identity, provenance, and evidence. Trust attaches to each
fact: bytes and independently checked receipts may be `host-verified`, indexer and venue
responses are `provider-reported`, and a Petal's protocol label remains `app-claimed`.
Conflicting evidence stays visible rather than being silently resolved by source order.

Use absolute timestamps as the canonical value and primary display; relative time is
only supplementary. Render in the configured display timezone or UTC when none is set.
An in-progress item uses its latest lifecycle time; once settled, it uses the outcome
time without changing ID. Order equal timestamps by stable item ID. Keep execution
status (`awaiting_approval`, `submitted`, `partially_filled`, `succeeded`, `failed`, or
`cancelled`) separate from chain finality (`included`, `safe`, `finalized`, `reorged`, or
`unknown`). Historical USD appears only when captured at execution time or supplied as
a timestamped venue cash leg. Never apply today's price to an old event, and never invent
PnL; show only venue-provided realized PnL with provenance.

## Sources and current gaps

| Source | What Bloom already has | Gap for Activity |
|---|---|---|
| Local and central outboxes | Intent, plan, action ID, policy, pending/sent/failed state, transaction hash | Consistent venue projection, shared workflow IDs, and a typed listing service |
| EVM RPC | Broadcast and basic mined receipt reconciliation | Persist block hash, block time, gas, logs, replacement relation, and finality/reorg state |
| EVM address history | Normal, internal, ERC-20, ERC-721, and ERC-1155 paginated feeds | Query the source directly, merge overlapping feeds by hash, and state recent-only coverage |
| Hyperliquid | Recent fills, open orders, clearinghouse and spot state | Add by-time fills, historical orders, funding, and non-funding ledger updates |
| Polymarket | Public activity/trades and local order drafts/receipts | Add authenticated CLOB trades to link order IDs, partial fills, and settlement exactly |
| Audit log | Hash-chained implementation records | Keep as provenance only; its free-form reads/signatures/paths are not a product timeline |

Relevant code is in
[`outbox.rs`](../../crates/bloom-vfs/src/handlers/outbox.rs),
[`chains_history.rs`](../../crates/bloom-vfs/src/handlers/chains_history.rs),
[`hyperliquid.rs`](../../crates/bloom-vfs/src/handlers/hyperliquid.rs),
[`polymarket.rs`](../../crates/bloom-vfs/src/handlers/polymarket.rs), and
[`audit.rs`](../../crates/bloom-proto/src/audit.rs).

The upstream semantics support this split:

- Ethereum receipts expose inclusion and block identity; the `safe` and `finalized`
  block tags support finality tracking
  ([Ethereum JSON-RPC](https://ethereum.org/developers/docs/apis/json-rpc/)).
- Hyperliquid exposes by-time fills, historical orders, funding, and non-funding ledger
  updates; its recent-history limits mean coverage must be explicit
  ([Info endpoint](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/perpetuals),
  [WebSocket subscriptions](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/websocket/subscriptions)).
- Polymarket's public Activity API covers trades, splits, merges, redemptions, rewards,
  deposits, and withdrawals, while authenticated CLOB trades provide stable trade and
  order linkage
  ([Activity](https://docs.polymarket.com/api-reference/core/get-user-activity),
  [CLOB trades](https://docs.polymarket.com/api-reference/trade/get-trades)).

An event marked successful after EVM inclusion is not permanently final. Persist its
block hash and verify canonicality until `safe`, `finalized`, or a configured
confirmation threshold. If a receipt disappears or changes, mark it reorged and
re-resolve it instead of retaining stale success.

## Account scope, coverage, and pagination

Build Activity for one Bloom wallet over an explicit account graph: owner accounts per
chain plus configured Polymarket proxy/deposit and Hyperliquid account/subaccount roles.
Never infer ownership because two addresses look related.

V0 should return the latest roughly 50 semantic items and label every adapter `ok`,
`partial`, or `unavailable`, including its time/range limits. “No activity” must remain
distinguishable from “the provider failed.” The Etherscan-style feeds are limited and
offset-paginated, so Bloom must not call this complete history
([normal transactions](https://docs.etherscan.io/api-reference/endpoint/txlist),
[ERC-20 transfers](https://docs.etherscan.io/api-reference/endpoint/tokentx)).

When older pages are added, use an opaque keyset cursor over
`(effective_at_ms, stable_id)` with a frozen upper bound. Bind the cursor to the wallet,
filters, schema, and snapshot; validate its size and version. Offset pages shift as new
events arrive and should not become the authoritative history contract.

## Safety and presentation rules

- Incoming history is attacker-controlled. Never turn an incoming sender into a copy
  target, default recipient, or contact suggestion. Address-poisoning attacks
  deliberately seed lookalike history entries
  ([MetaMask guidance](https://support.metamask.io/stay-safe/protect-yourself/wallet-and-hardware/address-poisoning-scams/)).
- Preserve unsolicited and unverified assets in JSON/evidence, but collapse them in the
  human timeline, for example “4 unverified incoming assets.” Never fetch their image
  URLs or promote untrusted token names.
- HTML is semantic, single-column, script-free, escaped, and makes no network requests.
  Use `<section>`, `<ol>`, `<article>`, `<time>`, `<dl>`, and `<details>` rather than a
  wide transaction table.
- Status is text, not color alone. The page must reflow without horizontal scrolling at
  320 CSS pixels and remain understandable at zoom
  ([WCAG reflow](https://www.w3.org/WAI/WCAG21/Understanding/reflow),
  [use of color](https://www.w3.org/WAI/WCAG21/Understanding/use-of-color.html)).
- Keep the content column near 760 pixels, use the system font, and reserve badges for
  short noninteractive status adjectives
  ([GOV.UK status tags](https://design-system.service.gov.uk/components/tag/)).
- Full addresses and identifiers remain one disclosure away. Shortened identifiers are
  never the only representation, and saved names show their resolution provenance.

The view is visually ready when the first screen exposes outstanding work plus several
recent outcomes without raw hashes dominating; hierarchy survives Markdown; status is
clear in grayscale; and the same fixture is legible at 320 pixels and at 200%/400% zoom.

## V0 event kinds and implementation

Include native/token/NFT transfers, swaps, approvals/revocations, arbitrary contract
calls, failures/replacements/cancellations, Polymarket orders/fills/redemptions/funding,
Hyperliquid fills/funding/transfers/liquidations, and canonical policy/session changes.
Do not attempt social labels, heuristic workflow grouping, a global cross-wallet feed,
current-price historical charts, or a full block explorer in V0.

Suggested sequence:

1. Add versioned `ActivitySnapshot`/`ActivityItem` models, an explicit wallet account
   graph, and a cached `ActivitySnapshotService`.
2. Project all sealed actions and venue outcomes consistently; add `workflow_id` and
   enrich EVM receipts with canonical block, fee, effect, finality, and replacement data.
3. Add typed adapters for outboxes, `AddressHistorySource`, Hyperliquid history/ledger,
   and Polymarket authenticated trades plus public activity. Query independent sources
   concurrently with bounded timeouts.
4. Normalize, group only by exact identifiers, retain evidence/conflicts, and report
   honest recent-only coverage.
5. Render the latest JSON, Markdown, and HTML plus per-event detail. Add keyset history
   pages only after the latest view is useful.

Fixtures must prove that overlapping ERC-20 feeds render once; approve-then-swap is one
workflow; replacements, partial fills, failures, and reorgs do not double-count; a failed
transaction shows only its fee; venue funding and liquidation appear; poisoning and
untrusted asset text cannot create contacts or script HTML; equal timestamps sort
deterministically; provider failure remains visible; and every format shares one
snapshot ID.

V0 is ready when a user can understand the lifecycle and net effects of recent actions
without reading hashes, while an agent can open exact evidence for every claim and no
renderer changes the existing signing boundary.
