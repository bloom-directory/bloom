# Bloom views

This directory holds read-only pages meant for a person to open in a
browser. They render the same facts the surrounding VFS exposes as JSON and
Markdown; they never introduce a new authority surface.

Open one from the mount, for example:

```sh
xdg-open ~/bloom/views/wallets.html    # Linux
open /Volumes/bloom/views/wallets.html # macOS
```

## Pages

- `wallets.html` — every wallet in the current Broker listing with its native
  balance on each configured network, valued where a fresh price exists.
- `receive.html` — receiving addresses grouped by wallet and address family,
  with self-contained QR artwork encoding the displayed address. EVM addresses
  must parse as EVM addresses. Solana addresses come from the numbered-account
  inventory (derivation path shown on each card); projections cached from
  before that inventory still contribute explicit `solana:` CAIP-10 addresses
  from Ed25519 keys, and a bare Ed25519 key never qualifies. Absent Solana
  data gets an unavailable card, never a guessed destination.
- `activity.html` — central-outbox operations, newest first, with recorded
  transaction hashes. Separate Solana outboxes are not included.
- `bloom.css` and `bloom.js` — the stylesheet and the small local script that
  opens the Receive wallet a link points at.

## What to tell a person

Give them the file path and let the browser render it. Do not paste the HTML
into a transcript, and do not re-render these pages yourself: the canonical
values live in the sibling JSON leaves
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
- **Empty** means the network answered and reported an empty balance. It is
  counted rather than dropped, so that holding nothing stays distinguishable
  from a network that was never read.
- A native balance without a configured market price is shown in its own
  table and excluded from dollar totals. This is a valuation limitation, not
  a claim that the network is a testnet or that its native asset has no value.
- Balances cover native coins only; token holdings are not scanned. Chains
  without a native token (Tempo) are skipped.
- Balance reads for projected accounts share one ten-second budget and eight
  in-flight reads. A read that does not finish is omitted and named. A recent
  successful read (at most five minutes old) stands in for a failed one and is
  disclosed. Activity opens at most 256 operations in each state; older
  records are omitted and the page says coverage is incomplete.

## Boundaries

- These pages are **observations**. Nothing here approves, stages, or executes
  an action. A page that matches Bloom's visual language is still not a trusted
  authorization surface — passkeys and private input belong to Broker's own page.
- They make no automatic network requests. The stylesheet and script are
  served from this same mount. Following an explicit block-explorer link is
  the reader's choice.
- Address and transaction links are emitted only from known chain ids and use
  no referrer.
- An address shown here is the wallet's current projected receiving address. A
  network label never changes what an address-only QR code encodes; the sender
  must select the matching network in their own wallet.
- Receive lists configured EVM networks, not every EVM chain. Account-inventory
  failures are disclosed rather than treated as proof that no Solana account
  exists. Solana receiving addresses must decode to 32 bytes.
- Receive starts with every wallet collapsed. Native disclosure controls work
  without JavaScript; explicit wallet deep links open the named wallet.
- Test networks are listed separately. Test funds are not main-network funds.
