# Bloom views

This directory holds read-only HTML pages meant for a person to open in a
browser. They render the same facts the surrounding VFS exposes as JSON and
Markdown; they never introduce a new authority surface.

Open one from the mount, for example:

```sh
xdg-open ~/bloom/views/index.html    # Linux
open /Volumes/bloom/views/index.html # macOS
```

## Pages

- `index.html` — Today: what is held, what is waiting, what never sent.
- `markets.html` — what a public provider reports is moving, and the sample it
  was drawn from. No row here is a holding of yours.
- `chains.html` — each configured network: whether it answered your daemon,
  its provider-reported trading activity, and what you hold priced on it.
- `fees.html` — daily fees paid by everyone using a network, over the last
  completed UTC days. This is paid network usage, not a quote for your next
  transaction.
- `wallets.html` — native balances per wallet on every network that answered,
  with the wallet's address, kind, and policy version.
- `receive.html` — receiving addresses grouped by wallet and address family,
  each with a scannable QR code and the networks that address serves.
- `next-moves.html` — staged operations awaiting review, with the policy
  denial that explains why each will not proceed as staged.
- `activity.html` — every operation Bloom staged, broadcast, or never sent,
  newest first, with the transaction hash where one exists.
- `policy.html` — where each wallet may send, from its signed policy.

## What to tell a person

Point them at the file path and let the browser render it. Do not paste the
HTML into a chat transcript, and do not re-render these pages yourself: the
canonical values live in the sibling JSON leaves
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
- They carry no script and make no network requests. The stylesheet and images
  are served from this same mount, and no block explorer is ever contacted.
- An address shown here is the wallet's current projected receiving address. A
  network label never changes what an address-only QR code encodes; the sender
  must select the matching network in their own wallet.
- Test networks are listed separately. Test funds are not main-network funds.
