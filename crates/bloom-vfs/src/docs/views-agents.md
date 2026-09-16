# Bloom views

This directory holds read-only pages meant for a person to open in a
browser, plus one Markdown briefing for chat. They render the same facts the
surrounding VFS exposes as JSON and Markdown; they never introduce a new
authority surface.

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
- `activity.html` — every operation Bloom staged, broadcast, or never sent,
  newest first, with the transaction hash where one exists.
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
  must parse as EVM addresses; Solana requires an explicit `solana:` CAIP-10
  address on an Ed25519 key. The current key projection does not expose the
  newer account-list API; absent Solana data gets an unavailable card, never a
  guessed destination. Full Solana account discovery still needs that API.
- `policy.html` — where each wallet may send, which package fingerprints may
  request it, and how long approval may last, from its signed policy.
- `bloom.css`, `bloom.js`, and `icons/` — the stylesheet, the small local
  Networks sorter, and the bundled artwork the pages
  reference. Icons are matched on canonical identity (chain id, then asset
  symbol); an unknown name keeps an initials fallback. Provenance is
  documented in the icon sources beside the handler.
- `skin.css` and `skins/` — the person's own styles and the bundled
  alternatives. See below.

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

A skin may also override any rule. To start from a bundled skin, import it
and add your own rules after the import:

```css
@import "skins/winamp.css";
```

A skin is styling only. The pages' Content-Security-Policy still forbids
every remote fetch and every script, whatever the stylesheet asks for, and a
skin cannot change what a page says. Bundled skins under `skins/` follow the
same rule as `bloom.css`: no images, fonts, or imports from anywhere.

When a person asks for a different look, edit `~/.bloom/skin.css` on the
host; the mount itself is read-only.

## What to tell a person

Point them at the file path and let the browser render it. For anything that
must be said inside the chat itself, quote `briefing.md` rather than
summarizing from memory. Do not paste the HTML into a chat transcript, and do
not re-render these pages yourself: the canonical values live in the sibling
JSON leaves
(`wallets/<wallet>/addresses.json`, `wallets/<wallet>/chains/<chain>/balance.json`,
`outbox/<state>/<action>/intent.json` and `result.json`).

## What the words mean

These pages are deliberately narrow about what they claim:

- **Broadcast** means Bloom submitted the transaction and kept the hash. It is
  not a claim that the chain accepted it. No receipt is read here.
- **Never broadcast** means the record carries no result and no transaction
  hash, so nothing reached any chain. It is not the same as reverted — these
  pages never claim a revert, because they hold no evidence of one.
- **Holds nothing** means the network answered and reported an empty balance.
  It is listed rather than dropped, so that holding nothing stays
  distinguishable from a network that was never read.
- A balance on a chain with no market for its native unit (a faucet or
  development chain) is shown in its own table and never priced. Its quantity
  is real; it is not money.

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
- Test networks are listed separately. Test funds are not main-network funds.
