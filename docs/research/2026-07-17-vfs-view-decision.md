# Bloom views: understand the market, your wallet, and what comes next

Research for #114. Revised 5 September 2026. **Design and working offline
prototypes; no new runtime VFS routes.** This replaces the six July specifications.
The decision is made here; there is no questionnaire or approval prerequisite.

Open [Today](vfs-view-mockups/index.html) in a browser. Follow Markets → Chains →
Wallet → Next moves → transfer review → Activity. Every page explicitly uses
fictional data. [Failure and empty states](vfs-view-mockups/states.html) are part
of the prototype, not an implementation footnote.

## Product decision

Start with **Today**, a short briefing with three answers:

1. What is happening? Token price movement and trading activity, with a visible
   source, period, universe, and a plain explanation of what each metric means.
2. How does it affect me? Holdings, chain exposure, and incomplete observations.
3. What needs me? Pending owner decisions and concrete workflow failures first;
   optional research comes after them. Doing nothing is a valid outcome.

Markets and Chains are separate drilldowns, not a carousel of buy suggestions.
Wallet combines balances and positions. Receive, transfer review, Activity, and
Access are supporting views. Define unfamiliar terms where they first appear;
keep raw paths, identifiers, and provider detail behind expandable evidence.
A beginner should not need to learn the VFS to read their wallet.

Use the existing Bloom ceremony language: paper `#f4efe6`, surface `#faf7f1`,
burgundy `#8a2a3a`, leaf `#526f51`, italic serif titles, system sans body, and
monospace metadata. Reuse the Bloom mark, not a new logo or icon package. These
are read-only information pages. Matching the brand does **not** make them a
trusted authorization surface. Passkeys and private input stay in Broker's page.

## Rebase and source authority

The branch is rebased directly onto **#214 `da7f179`**, the latest 0xdewy
wallet-policy/ceremony and Robinhood stack at inspection. Review this PR against
`feat/robinhood-chain-support`; it does not merge other people's feature branches.
The newer master release and parallel Solana/usage stack were inspected separately.
Being researched here does not mean those unmerged capabilities ship on this base.

| Source inspected | What changes this design |
| --- | --- |
| [#214](https://github.com/bloom-directory/bloom/pull/214), `da7f179` | Per-chain policy, approval-required ceremony details, wallet export, refused/ambiguous signing lifecycle, Robinhood assets |
| [master `e190a1b`](https://github.com/bloom-directory/bloom/commit/e190a1bee2428a3da0919cf79c075e3706f5ab8d) | 0.2.0 release/default Petals and newer Petal eligibility/provenance; installation is distinct from wallet permission |
| [#169 / #170](https://github.com/bloom-directory/bloom/pull/170), `19c042f` | BIP-39 derived accounts, native SOL balances/transfers, exact account selection; no implied SPL transfer support |
| [#196](https://github.com/bloom-directory/bloom/pull/196) | Real workflows wait for receipts, recover expired approvals, and distinguish a possible broadcast from success; mainnet canary support is conditional |
| [#200](https://github.com/bloom-directory/bloom/pull/200), `022ad9f` | Agent guidance: discover mounted capabilities, respect process ownership, verify terminal outcomes |
| [Broker ceremony assets](https://github.com/bloom-directory/bloom-broker/tree/5625297/crates/bloom-broker/src/ceremony_assets) | Existing visual system and trusted approval/private-input boundary |

Local source anchors: [prices](../../crates/bloom-vfs/src/handlers/prices.rs),
[chain health](../../crates/bloom-vfs/src/handlers/status.rs),
[wallet/policy reads](../../crates/bloom-vfs/src/handlers/wallets.rs),
[outbox](../../crates/bloom-vfs/src/handlers/outbox.rs), and
[daemon next-actions renderer](../../crates/bloom-daemon/src/lib.rs).
The old claim that `/next.md` needs an asynchronous renderer is obsolete.
The old native Hyperliquid/keystore references no longer describe Machine.

## What “hot” means

Never combine price change, search popularity, volume, and RPC health into one
score. They answer different questions, and none predicts returns.

**Tokens:** start with a bounded liquid-market universe from one market provider.
Show price, signed 24-hour change, and 24-hour USD volume. Default ordering is
volume descending; an explicit price-movers view orders signed change descending.
Show the universe and eligible/total count. Stablecoins remain in volume rankings;
identify them so low price movement is understandable. Do not rank symbols:
use provider ID plus chain-qualified contract/mint where relevant. Separate native
ETH from wrapped ETH and chain-specific USDC balances. A wallet holding can be
highlighted without changing the ranking.

A candidate source is [CoinGecko coins/markets](https://docs.coingecko.com/reference/coins-markets).
Its volume is provider-reported aggregate market volume, not necessarily on-chain
volume or available liquidity. [Trending search](https://docs.coingecko.com/reference/trending-search)
is search attention over 24 hours; if added later, label it separately. Neither
endpoint exists in Bloom's current `prices` handler. Account for the chosen API
plan's authentication, rate limits, and attribution when implementing the adapter;
no key or direct browser fetch belongs in these snapshots.

**Chains:** show decentralized-exchange (DEX) spot trading volume for a common
completed UTC day, previous-day change, and the same provider's covered chains.
Use descending USD volume, then canonical chain ID as a deterministic tie-break.
Do not sum aggregator volume on top of DEX volume. A candidate source is the
[DefiLlama chain DEX overview](https://github.com/DefiLlama/api-docs/blob/main/llms-pro.txt);
[its methodology](https://docs.llama.fi/list-your-project/other-dashboards) distinguishes
DEXs, aggregators, and derivatives. Updates can differ by protocol, so use a
completed daily window and record its boundary rather than calling it live.

Beside this market context, show **your balance**, **connection health**, and
**whether a supported action can be prepared**. A healthy RPC does not mean a
chain is popular, a popular chain need not be configured, and a configured chain
need not be permitted for this wallet. Robinhood with no comparable volume is
“Not covered”, never a fabricated zero or a ranked loser.

Exclude stale/missing rows from the ranking; retain them in the coverage panel.
Use null for unavailable values. Display a movement of zero as zero. Timestamps
come from the source where available; fetch time alone cannot prove freshness.
Compare only the same metric, source, currency, and window. No made-up sparklines,
market causality, social sentiment, yield guarantees, or “best chain” badges.

## Wallet and Petal coverage

Use installed Petals' existing read contracts, after discovering their manifest,
route tree, wallet eligibility, and account scope. A repo on GitHub is not proof
that an installed version supports a route. Do not invent a new Petal ABI or a
universal portfolio plugin as a prerequisite. Start with narrow adapters for
actual outputs. Cross-source claims remain labeled with provenance.

| Surface / inspected repository | Useful view | Honest limitation |
| --- | --- | --- |
| Native EVM balances + `prices/spot`, `prices/change_24h` | Native/known-token balances, spot valuation | Price coverage is not complete token discovery; 24h token change is not wallet P&L |
| Native Solana (#170) | SOL by full account fingerprint; account-specific Receive; transfer lifecycle | Conditional on that stack; multiple children require explicit selection; no fabricated SPL inventory |
| [Hyperliquid `26678dd`](https://github.com/bloom-directory/bloom-petal-hyperliquid/tree/26678dd) | Account equity, positions, fills, bounded-agent state | Master/subaccount is distinct from the agent key; local stop is not proof of venue revocation |
| [Polymarket `c057e6d`](https://github.com/bloom-directory/bloom-petal-polymarket/tree/c057e6d) | Account cash, positions, trade and funding status | Current DTO has `redeemable` but does not preserve all valuation/deadline fields; normalize only available facts |
| [Morpho `859aba5`](https://github.com/bloom-directory/bloom-petal-morpho/tree/859aba5/route/files) | `[chain]/positions/[wallet].json`, vault data, deposit/withdraw action status | Indexed claims need their observation time; do not invent borrower health or a guaranteed APY |
| [Robinhood `38f96b1`](https://github.com/bloom-directory/bloom-petal-robinhood/tree/38f96b1/route/files) | `portfolio/[wallet].json`, issuer prices, corporate actions, transfer status | Stock tokens are issuer products, not interchangeable with brokerage shares; missing quote stays unpriced |
| [Enso](https://github.com/bloom-directory/bloom-petal-enso) | Route quote, minimum received, approval then swap lifecycle | Quoted destination value is not a received asset; a cross-chain balance increase alone is not settlement proof |
| [Gasless](https://github.com/bloom-directory/bloom-petal-gasless) | Quote, fee, destination and settlement status | Gas sponsorship does not mean no fee or no authorization |
| [Privacy Pools](https://github.com/bloom-directory/bloom-petal-privacy-pools) | Public workflow phase, owner-input-needed signal | No note, private recipient, witness, or recovery secret in a view; do not expose private balances via aggregation |
| [Venice x402](https://github.com/bloom-directory/bloom-petal-venice-x402) | Service credit and last-known top-up status | Service credit is separate from spendable wallet cash; stale cached balance is labeled |
| [Pump.fun](https://github.com/bloom-directory/bloom-petal-pumpfun) | Optional token detail when installed and supported | No default discovery/trading promise; a token feed needs provenance, liquidity context, and spam treatment |

The prototype exercises EVM, conditional native SOL, Morpho, Hyperliquid,
Polymarket, Robinhood, Enso, and private-input states. It is deliberately broader
than today's installed release. Unsupported adapters show “Not available” without
blocking native balances. Check exact installed routes before offering preparation.

**Accounting:** sum wallet assets and independently owned position equity once.
If Morpho shares already appear as a wallet token, suppress that token's priced
contribution when using the underlying claim value. Hyperliquid equity already
contains its position P&L; never add notional, margin collateral, and equity again.
Polymarket cash and current positions may be summed if their scopes do not overlap;
redeemable value is part of positions, not extra wealth. Unknown prices stay null.
Service credits and privacy-sensitive pool value are outside this total. Never
label a mixed-time or incomplete observation “total net worth”.

## Next moves and lifecycle

Use two lanes: **Needs you** and **Worth a look**. Only the former contributes to
the attention count. A market mover is not an urgent task. Order Needs you by
source-proven urgency, then actual expiry, then stable action ID. Do not generate
fake time pressure from an expired or missing clock.

| Observed state | User-facing behavior |
| --- | --- |
| Pending current approval | Show amount, network, next step and expiry; open the existing Broker ceremony only from the current trusted request |
| Approval expired / definite refusal with no signature | Say nothing was sent if the lifecycle proves it; offer the existing refresh/retry path and a new exact review |
| Signing/broadcast outcome ambiguous | “Checking outcome”; no resend or cancel suggestion until canonical reconciliation resolves it |
| Enso/Morpho approval succeeded, next step pending | One workflow card: approval done, swap/deposit not done; never “deposit complete” |
| Policy blocks selected chain or Petal | Explain the specific block; prepare the existing policy update ceremony; reading policy never authorizes a transaction |
| Polymarket outcome marked redeemable | Optional follow-up only if current holdings and a supported redemption route are verified; refresh before staging |
| Owner private input required | Direct the owner to the Broker ceremony; do not ask for it in chat |
| Provider stale/unavailable | State what cannot be assessed; never “nothing needs attention” across the failed scope |
| No issues in checked sources | “Nothing needs you in the sources checked”; list missing coverage separately |

Read operation state after a successful write. HTTP success, `sent/`, a signature,
or a passkey success is not proof of final settlement. Group only by durable
workflow/action/transaction/order identifiers; proximity in time cannot merge two
payments. Keep failed attempts and replacements within the known lifecycle.
The first implementation can show recent local operations without requiring an
external universal activity index. Imported history is labeled separately.

## Receive, transfer review, and access

Receive starts with network and account, then shows the full destination. The
same EVM address on Base and Ethereum is two routes. Multiple Solana children
need a selected full fingerprint. A venue deposit wallet is shown only if its
current account state proves that route accepts the selected asset/network;
otherwise explain the missing setup. Shared bridges are funding workflows, not
personal receive addresses. The prototype intentionally has no scannable QR or
copy button for its fictional addresses. A production QR is optional and must
encode exactly the displayed chain-qualified route.

Transfer review summarizes the staged operation and simulation: amount, full
recipient, selected account/network, estimated fees, and any approval scope. It
links to the existing exact Broker review; it does not embed passkey code, accept
private input, infer an authorization from a UI label, or create another outbox.
A contact label is context, never proof of the address. Omit automatic contact
suggestions and arbitrary “second send” thresholds. AddressBook consistency is a
separate implementation concern to verify when changing that path, not an
unconditional blocker for market/portfolio views.

Access shows current public policy, wallet/Petal eligibility, known venue access,
and the existing export/recovery entry points. It does not promise a universal
on-chain approval inventory or a security score. Unknown remote revocation stays
unknown. Export/recovery format and trusted private-input UX belong to Signer and
Broker; this PR does not design a new keystore export, backup checker, or raw-key
viewer. Agent-readable HTML never includes secret material or ceremony tokens in
shared/exported snapshots.

## Minimal implementation contract (proposed, not mounted today)

| Candidate view | Proposed location | Existing inputs to reuse |
| --- | --- | --- |
| Today | `/wallets/<wallet>/overview.{json,md,html}` | Wallet, next actions, bounded market observations |
| Markets | `/markets/overview.{json,md,html}` | New market read adapter; existing prices for wallet valuation |
| Chains | `/markets/chains.{json,md,html}` | New DEX-volume adapter + existing chain-health reads |
| Wallet | `/wallets/<wallet>/portfolio.{json,md,html}` | Native balances and supported Petal reads |
| Next moves | Existing `/next.md` first; wallet-scoped JSON/HTML as needed | Current Broker projections, outbox, supported Petal state |

Supporting Receive, Activity, Access, and review pages can be sections/links
around those existing routes. Do not promise a new endpoint for every mockup.
One typed observation should feed JSON and Markdown first; optional HTML must
render those same facts. A host unable to display HTML gets Markdown and an
explicit local-file link, never the claim that a hidden widget was displayed.
Do not silently write exports to shared disk.

Keep the shared envelope small: `schema_version`, `snapshot_id`, `observed_at`,
`scope`, `sources` (status, source time/window, fetch time, error, covered scope),
and view rows. Observations are not globally atomic chain snapshots. Missing
values are null, quantities use decimal strings, asset IDs are chain-qualified,
and local action IDs are stable. If a new render observes new data, give it a new
snapshot ID; cached sibling formats must not silently disagree. Reuse current
bounded client caches and timeout behavior rather than adding a new cache service.
Freshness eligibility belongs to each source's documented update cadence; don't
add user-facing timeout knobs to this design.

Render escaped text, semantic tables/headings, accessible status labels, and
native details/summary. Read-only HTML needs no script, remote fonts, tracking,
provider image URLs, or browser API fetches. The offline prototype uses a shared
local CSS file; a host that only accepts one file may inline that same CSS at
export time. Validate href schemes/targets separately from text escaping.
Never turn provider descriptions into HTML, commands, or ceremony URLs. No private
key, mnemonic, credential, note, or secret belongs in any format.

## Delivery slices and acceptance

1. Ship a small wallet/next-actions snapshot over existing public reads, JSON and
   Markdown with the shared HTML skin. Partial Petal coverage is explicit.
2. Add Markets and Chains adapters with a fixed observable ranking definition;
   add wallet relevance without changing the market order. No signal without data.
3. Add Petal adapters in actual usage order, plus local Activity and Receive.
   Reuse supported lifecycle and ceremony paths throughout.

No custom dashboard builder, strategy recommender, price alert engine, universal
indexer, Petal ABI extension, backup redesign, or complete approval inventory is a
prerequisite. No real funds are needed to validate this research PR.

Acceptance for implementation: missing provider != zero; stale rows cannot rank;
all formats agree; overlapping claims count once; two Solana accounts stay distinct;
expired approvals never reuse a dead link; uncertain broadcast never invites resend;
incoming dust never becomes a contact; private-input content never reaches the
renderer. HTML works at 320 px, at 200% text size, with keyboard navigation and
without scripts/network. Unsupported and empty states remain useful.

## Prototype verification

`vfs-view-mockups/build.py` renders the fixture-backed market, chain, wallet, and
supporting pages using only the Python standard library. `snapshot.json` is
fictional and deterministic. Regenerate with `python3 build.py` in that directory;
use `python3 build.py --check` to verify committed output and accounting/ranking
invariants without writing. `snapshot.md` is the same fixture's readable fallback.
Serve locally with `python3 -m http.server 8118 --bind 127.0.0.1` or open `index.html`.
The committed HTML is directly reviewable without running a build.

Browser verification and any limitations are recorded in the PR description.
Runtime adapter acceptance above remains future work, not a claim that research
fixtures exercise live RPCs, production signing, or actual provider availability.
