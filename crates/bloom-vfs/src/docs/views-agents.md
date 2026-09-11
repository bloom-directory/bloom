# Bloom views

This directory holds read-only HTML pages meant for a person to open in a
browser. They render the same facts the surrounding VFS exposes as JSON and
Markdown; they never introduce a new authority surface.

Open one from the mount, for example:

```sh
xdg-open ~/bloom/views/receive.html    # Linux
open /Volumes/bloom/views/receive.html # macOS
```

## Pages

- `receive.html` — receiving addresses grouped by wallet and address family,
  each with a scannable QR code and the networks that address serves.

## What to tell a person

Point them at the file path and let the browser render it. Do not paste the
HTML into a chat transcript, and do not re-render these pages yourself: the
canonical values live in the sibling JSON leaves
(`wallets/<wallet>/addresses.json`, `wallets/<wallet>/chains/<chain>/balance.json`).

## Boundaries

- These pages are **observations**. Nothing here approves, stages, or executes
  an action. A page that matches Bloom's visual language is still not a trusted
  authorization surface — passkeys and private input belong to Broker's own page.
- They carry no script and make no network requests. The stylesheet and images
  are served from this same mount.
- An address shown here is the wallet's current projected receiving address. A
  network label never changes what an address-only QR code encodes; the sender
  must select the matching network in their own wallet.
- Test networks are listed separately. Test funds are not main-network funds.
