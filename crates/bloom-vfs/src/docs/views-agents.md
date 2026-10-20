# Bloom views

This directory holds read-only pages meant for a person to open in a
browser, plus one Markdown briefing for chat. They render the same facts the
surrounding VFS exposes as JSON and Markdown; they never introduce a new
authority surface.

In an MCP client, prefer the matching `show_bloom_*` tool. A host that
advertises MCP Apps support renders the page inline; other hosts return the
browser path below as a fallback.

Open one from the mount, for example:

```sh
xdg-open ~/bloom/views/index.html    # Linux
open /Volumes/bloom/views/index.html # macOS
```

For chat, quote `briefing.md` — the Today briefing as pasteable Markdown,
drawn from the same data as `index.html`.

## Pages

- `briefing.md` — Today for chat: holdings, what needs you, app positions,
  and recent activity as Markdown to quote into a transcript.
- `index.html` — Today: what you hold, what needs you, what happened recently.
- `wallets.html` — every wallet in the current Broker listing, organized by
  projected wallet/account identity. Native balances and Petal positions stay
  under the identity their records name. Activity-only addresses are compact
  historical observations and never become controlled wallets.
- `activity.html` — central-outbox operations, newest first, with recorded
  transaction hashes. Separate Solana outboxes are not included.
- `chains.html` — Networks: every configured network in one sortable list —
  cumulative fee totals, 24h fees and DEX volume, and what your wallets hold
  on it. Opening a row discloses the older fee periods and the 30-day daily
  history. Solana is included from the same public source without inventing an
  EVM chain id; public network availability is independent of Solana wallet
  account projection. Fee totals are network-wide public data (DefiLlama),
  never a quote for a personal transaction.
- `fees.html` — an alias of the Networks page, kept so old bookmarks keep
  working. It serves exactly the same bytes as `chains.html`.
- `markets.html` — what a public provider reports is moving, and the sample it
  was drawn from. No row here is a holding of yours.
- `next-moves.html` — staged operations awaiting review, with the policy
  denial that explains why each will not proceed as staged.
- `contacts.html` — saved address-book names and recipients identified from
  recorded transfers. Repeated unnamed recipients are suggestions; contract
  targets and unclassified targets are never promoted to contacts.
- `receive.html` — receiving addresses grouped by wallet and address family,
  with self-contained QR artwork encoding the displayed address. EVM addresses
  must parse as EVM addresses. Solana addresses come from the numbered-account
  inventory (derivation path shown on each card); projections cached from
  before that inventory still contribute explicit `solana:` CAIP-10 addresses
  from Ed25519 keys, and a bare Ed25519 key never qualifies. Absent Solana
  data gets an unavailable card, never a guessed destination.
- `policy.html` — where each wallet may send, which package fingerprints may
  request it, and how long approval may last, from its signed policy.
- `bloom.css`, `bloom.js`, and `icons/` — the stylesheet, the small local
  Networks sorter, and the bundled artwork the pages
  reference. Icons are matched on canonical identity (chain id, then asset
  symbol); an unknown name keeps an initials fallback. Provenance is
  documented in the icon sources beside the handler.
- `skin.css` — the person's own styles. See below.

## Skins

Every page loads `bloom.css` (the base Bloom design) and then `skin.css`.
`skin.css` is whatever the file `~/.bloom/skin.css` holds, re-read on every
access, and empty when that file does not exist, so with no skin the pages
are the base design.

To restyle the pages, write CSS to `~/.bloom/skin.css` and reload. Every
color, font, and radius in `bloom.css` is a custom property on `:root`, so a
skin that only redefines tokens restyles every page at once:

```css
:root { --accent: #1f5fbf; --serif: Georgia, serif; }
```

A skin may also override any rule.

A skin is trusted presentation code: CSS can hide warnings or alter apparent
meaning. The Content-Security-Policy blocks remote assets and permits only the
bundled same-origin scripts; it does not isolate the page from its stylesheet.

When a person asks for a different look, edit `~/.bloom/skin.css` on the
host; the mount itself is read-only.

## What to tell a person

Prefer the matching `show_bloom_*` MCP tool so a capable desktop host can
render the view inline. A host that cannot render MCP Apps receives that
page's own text in the tool result, plus the browser path. `briefing.md` is
only the Today briefing. Do not quote it for Receive, Activity, Contacts,
Policy, Networks, or Markets. Do not paste the HTML into a transcript, and do
not re-render these pages yourself: the canonical values live in the sibling
JSON leaves
(`wallets/<wallet>/addresses.json`, `wallets/<wallet>/chains/<chain>/balance.json`,
`outbox/<state>/<action>/intent.json` and `result.json`).

## What the words mean

These pages are deliberately narrow about what they claim:

- **Broadcast** means Bloom submitted the transaction and kept the hash. It is
  not a claim of settlement. The Activity page looks up receipts for up to 64
  recent records to show execution gas fees; these exclude additional L1-data
  and blob fees and do not establish finality. Missing receipts show no fee.
- **No broadcast recorded** means no transaction hash was retained. It does
  not prove no transaction reached a chain. An approval challenge alone does
  not prove whether the owner approved. Stopped operations with hashes retain
  their explorer links; settlement must be checked on chain.
- **Holds nothing** means the network answered and reported an empty balance.
  It is listed rather than dropped, so that holding nothing stays
  distinguishable from a network that was never read.
- A native balance without a configured market price is shown in its own
  table and excluded from dollar totals. This is a valuation limitation, not
  a claim that the network is a testnet or that its native asset has no value.
- **App coverage incomplete** means a read failed, returned invalid data,
  exceeded a discovery limit, or supplied no sufficiently recent timestamp.
  The same warning appears in the briefing. Missing rows are not zero balances.
- Hyperliquid shows default perpetuals-market equity in USD, not a USDC token
  balance or the full spot/unified trading account. Only source timestamps no
  more than five minutes old qualify for app totals; future, missing and stale
  timestamps leave an unvalued observation. The source time is in the evidence.
- Privacy-pool notes are local observations, never dollar-valued without
  verified network identity and spend status. Amounts are summed in exact
  integer base units. Other apps expose account-record metadata only: unknown
  file contents are neither read nor treated as balances.
- App collection has a five-second total deadline, 1 MiB supported-leaf limit,
  256 entries per listing, and generic discovery limited to depth two,
  24 listings and 12 records per app. Truncation is disclosed, not completeness.
  A Petal route that marks its read as side-effecting is skipped and named.
- Balance reads for projected accounts and historical senders share one
  ten-second budget and eight in-flight reads. A read that does not finish is
  omitted and named. Activity opens at most 256 operations in each state;
  older records are omitted and the page says coverage is incomplete.

## Boundaries

- These pages are **observations**. Nothing here approves, stages, or executes
  an action. A page that matches Bloom's visual language is still not a trusted
  authorization surface — passkeys and private input belong to Broker's own page.
- They make no automatic network requests. The stylesheet, sorter, and images
  are served from this same mount. Following an explicit block-explorer link is
  the reader's choice.
- Address, transaction, market, app-account, and network-source links are
  emitted only from known chain ids or provider identities and use no referrer.
- An address shown here is the wallet's current projected receiving address. A
  network label never changes what an address-only QR code encodes; the sender
  must select the matching network in their own wallet.
- Receive lists configured EVM networks, not every EVM chain. Account-inventory
  failures are disclosed rather than treated as proof that no Solana account
  exists. Solana receiving addresses must decode to 32 bytes.
- Receive starts with every wallet collapsed, including a single-wallet page.
  Selecting a wallet reveals its codes and closes the previous wallet. Native
  disclosure controls work without JavaScript; explicit wallet deep links open
  the named wallet. Arc mainnet (5042) uses native USDC with 18 decimals and a
  fresh USDC market quote; Arc Testnet is not valued as mainnet USDC.
- Test networks are listed separately. Test funds are not main-network funds.
