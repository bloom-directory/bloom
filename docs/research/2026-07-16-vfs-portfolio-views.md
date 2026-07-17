# Issue 114: VFS portfolio views

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Build one server-owned, read-only portfolio snapshot and render it three ways:

```text
/wallets/<wallet>/portfolio.json  canonical facts for agents
/wallets/<wallet>/portfolio.md    universal human-readable fallback
/wallets/<wallet>/portfolio.html  optional rich, self-contained view
```

Here, a "template" means a Bloom-owned renderer over typed snapshot data. The agent
does not populate or edit these files. All three files must share a `snapshot_id` and
`as_of_ms`, so they cannot disagree because they were fetched separately.

This is a small extension of what Bloom already has. The hard part is honestly
describing discovery and valuation coverage, not producing attractive HTML.

## V0 scope

The snapshot should query independent sources concurrently, tolerate partial failure,
and cache the result briefly per wallet (roughly 10–30 seconds):

- Native balances on every configured EVM chain.
- ERC-20 balances for Bloom's curated tokens plus tokens discovered from available
  address history.
- Hyperliquid spot balances, account equity, and leveraged positions when configured.
- Polymarket cash and current positions when configured.
- USD prices in one batched price request where possible.

The renderers should be pure functions over that cached snapshot. The HTML should be
semantic, responsive, script-free, read-only, and self-contained; it must escape every
provider-supplied string and make no network requests. Markdown remains the reliable
cross-client presentation because Codex, Claude, OpenCode, and other hosts cannot be
assumed to render a VFS HTML file.

A minimal JSON shape is enough:

```json
{
  "schema": "bloom.portfolio.v1",
  "snapshot_id": "...",
  "wallet": "alice",
  "as_of_ms": 1784217600000,
  "summary": {
    "priced_net_value_usd": "1234.56",
    "unpriced_items": 2
  },
  "items": [],
  "coverage": [],
  "errors": []
}
```

Use decimal strings for amounts and money. Items should have typed kinds such as
`native_token`, `erc20`, `spot_balance`, `perp_position`, and `prediction_position`.
Use chain-qualified account and asset identifiers rather than symbols as identity;
[CAIP-10](https://standards.chainagnostic.org/CAIPs/caip-10) and
[CAIP-19](https://standards.chainagnostic.org/CAIPs/caip-19) are useful shapes.

## What exists and what is missing

| Area | Already present | V0 gap |
|---|---|---|
| EVM | Native/token balance readers, configured-chain registry, curated and history-discovered token lists | Aggregate them and report that token discovery is partial |
| Prices | `PricesClient::current_many` with timestamp and confidence | Apply it once to normalized items |
| Hyperliquid | Raw clearinghouse, spot-state, and order data | Normalize equity, spot balances, leverage, entry/liquidation price, notional, and PnL |
| Polymarket | The preinstalled Petal exposes positions and buying power, but its `Position` DTO omits current value, PnL, slug, and end date | Preserve those fields in the Petal and expose them through a versioned portfolio-provider boundary without double-counting cash or cost basis |
| VFS | Byte reads and filename-based discovery | No MIME/presentation metadata; keep Markdown as the fallback |
| Cache | Per-path byte cache | Add one shared snapshot cache so JSON/Markdown/HTML agree |
| Petals | Generic VFS routes and manifests plus the preinstalled Polymarket Petal | No semantic portfolio-provider contract; one is required before core can aggregate Petal data without crawling arbitrary paths |

Relevant implementation points are
[`balances.rs`](../../crates/bloom-vfs/src/handlers/balances.rs),
[`chains.rs`](../../crates/bloom-vfs/src/handlers/chains.rs),
[`wallets.rs`](../../crates/bloom-vfs/src/handlers/wallets.rs),
[`hyperliquid.rs`](../../crates/bloom-vfs/src/handlers/hyperliquid.rs),
[`bloom-prices`](../../crates/bloom-prices/src/lib.rs).
Polymarket now lives in the external preinstalled Petal described by the
[native-removal specification](../specs/2026-07-20-preinstalled-polymarket-petal.md).

## Correctness rules

- Never label the result "complete" unless a source can prove completeness. Standard
  ERC-20 exposes `balanceOf(owner)` but no owner-to-token enumeration, so RPC calls
  alone cannot find every token ([ERC-20](https://eips.ethereum.org/EIPS/eip-20)).
- Show source-level `ok`, `partial`, or `unavailable` coverage, freshness, and errors.
  A failed venue should not make the whole portfolio unreadable.
- Call the summary `priced_net_value_usd`, not "total value", whenever assets are
  unpriced or discovery is partial.
- Count Hyperliquid account equity once. Position notional is exposure, not additional
  wealth. Account modes also affect which balance endpoint is authoritative
  ([Hyperliquid clearinghouse state](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/perpetuals)).
- Count Polymarket position `currentValue` and uncommitted cash separately; do not add
  cost basis again. The upstream API already exposes value, realized/unrealized PnL,
  redeemability, and end date
  ([Polymarket positions](https://docs.polymarket.com/api-reference/core/get-current-positions-for-a-user)).
- Deduplicate by chain-qualified account, asset, and venue identity when two adapters
  observe the same balance.

## Alternatives considered

- **Agent-populated `portfolio.json`: reject.** It would vary by client, duplicate
  network work, become stale, and blur trusted facts with agent interpretation.
- **Multicall first: defer.** Multicall reduces RPC round trips only after token
  discovery; it does not discover assets. If added later, verify deployed bytecode per
  chain and retain individual-call fallback because the Multicall3 deployer key was
  compromised ([Multicall3](https://github.com/mds1/multicall3)).
- **Hosted portfolio indexer: optional later.** An indexer can materially improve token
  coverage across chains, but introduces API keys, privacy leakage, vendor trust, and
  chain limits. Alchemy's
  [Portfolio API](https://www.alchemy.com/docs/reference/portfolio-apis) is one viable
  opt-in provider, not a V0 dependency.
- **Generic multi-Petal portfolio interface: later.** V0 can define a narrow,
  versioned Polymarket provider boundary; generalize it after a second external
  portfolio source proves the abstraction. Do not crawl arbitrary Petal trees looking
  for balances.
- **MCP Apps/A2UI component protocol: later.** These can enable interactive host-native
  UI, but host support is not universal. Plain HTML plus Markdown solves the immediate
  problem without defining a new component system
  ([MCP Apps](https://modelcontextprotocol.io/extensions/apps/overview),
  [A2UI](https://github.com/a2ui-project/a2ui)).

## Suggested implementation sequence

1. Add a versioned `PortfolioSnapshot` model and a shared, short-lived
   `PortfolioSnapshotService` injected into the wallets handler.
2. Add direct adapters for configured EVM chains and Hyperliquid plus the versioned
   Polymarket Petal provider. Run them concurrently with timeouts and per-source errors.
3. Normalize and deduplicate items, batch prices, then calculate the conservative
   priced summary.
4. Add JSON, Markdown, and HTML renderers and expose the three synthetic VFS files.
5. Test leveraged Hyperliquid positions, Polymarket bets, duplicate assets, unpriced
   tokens, stale data, one failed provider, and identical snapshot IDs across formats.

V0 is ready when these reads require no agent-authored data or approvals, partial
coverage is visible, values are not double-counted, and every format is generated from
the same snapshot. "Next moves," prices, and chain-status pages can then consume the
same snapshot and renderer pattern without blocking this first useful page.
