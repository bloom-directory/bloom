# Card Checkout

**Status:** architecture overview; implemented behind the Triad
**Audience:** Bloom engineers and reviewers

Card checkout lets an agent shop on ordinary websites and pay once the human
approves the purchase with a passkey. The agent never sees card numbers, CVCs,
the approval page, or the human's private view of the browser.

## Authority ownership

- **Machine** exposes `cards/` and `checkout/` in VFS. It forwards closed
  requests to Broker (cards) and to `bloom-checkout` (shopping), and re-parses
  every response into a closed public type before it reaches VFS.
- **`bloom-checkout`** is its own principal. It owns a headless Chromium over a
  CDP pipe or, when configured, one allowlisted tab in the person's browser.
  It accepts Machine requests only from the Machine UID, reads checkout facts,
  fills a released card and clicks the pay button. Its operation store is a
  private SQLite file.
- **Broker** turns a checkout intake into a card ceremony, shows the approval
  page and relays ciphertext. It never holds card plaintext.
- **Signer** stores cards encrypted, binds each approval to its facts, and
  releases a card only HPKE-encrypted to the recipient key `bloom-checkout`
  generated for that one operation.

## Card lifecycle

Adding or deleting a card is a custody ceremony (`cards/add.json`,
`cards/delete.json`). The human types card details on the Broker page; they
are encrypted to Signer. The first card also enrolls the card passkey that
every later checkout approval uses. Signer never persists a CVC.

## Checkout modes

An agent writes `checkout/requests/<operation_id>/in.json`.

| Request | Mode | What the approval binds | After approval |
|---|---|---|---|
| `card_id` | Card | origin, payment-frame origins, total, currency, installments, recurring, card | Signer releases card + CVC to the recipient key; checkout rechecks the facts, fills provider fields, submits once |
| no `card_id` | Site | the same facts with no payment frames | checkout rechecks the facts and clicks the merchant's pay button once; the merchant charges the method saved in the buyer's account |
| `take_over: true` | Take-over | the agent's description only | the human works in the private view and hands back; nothing is bought |

Facts come from `facts.js`: exactly one visible pay button and one labelled
total in a supported language and number format, or processor data for
Stripe-hosted pages. If facts are unclear, the request falls back to a manual
ceremony that releases no card, and the human finishes in the private view.
A card is filled only into fields hosted by a known payment provider
(`PROVIDER_FIELD_ORIGINS`); other pages go to the private view.

The approval page also shows the entered fields and, when checkout owns the
browser, a screenshot of the order. These are human aids and are not bound to
the approval.

## User browser extension

The extension's manifest, background worker, content-script dispatcher and
bundle assembly live in `bloom-directory/bloom-browser-extension`. Checkout
pins that crate at an exact Git revision and supplies its generic DOM scripts
to the bundler. The native messaging host and socket adapter remain here.
There is no runtime source download or sibling-checkout dependency. The
installed version hashes both extension assets and supplied DOM scripts.

Flight search, itinerary selection, airline navigation instructions and the
seller handoff live in `bloom-directory/bloom-petal-flights`. Its booking route
uses the existing checkout VFS with declared read/write capabilities. Petals
can orchestrate that public surface; they do not receive saved card/traveler
plaintext or authorize disclosure. Merchant/provider origin allowlists stay
with the components enforcing disclosure and extension permissions.

The extension payment path currently inspects only the top document. Its
JetSMART browsing permission does not prove Yuno iframe card support; the
verified JetSMART purchase used checkout's own browser.

A fresh Chromium profile fails Aerolíneas' passenger check even when it is
headed and not marked as automated. The person's long-lived profile passes.
Chrome refuses remote debugging of that default profile, so checkout reaches
it only through this extension. Desktop clicks are not a checkout path.

A Manifest V3 content-script extension connects to checkout through Chrome
native messaging; it uses neither the debugger API nor a localhost web port.
The extension creates and controls one tab, accepts only the Aerolíneas and
JetSMART origins, and never reads other tabs. Flybondi is omitted: its origin
no longer resolves to a server that can take a booking.

Machine keeps the same browse and checkout API. Named, bundled page functions
replace arbitrary script evaluation. Traveler and card values still cross the
Broker and Signer ceremonies, are released for the approved origin, and are
redacted from snapshots. The extension does not weaken payment discovery,
fact rechecks, the single-submit rule or restart recovery.

## Private view

The private view is an HTTP page on `localhost` served by `bloom-checkout`,
opened from the approval page with a one-use capability. It streams
screenshots and forwards clicks and keys to the held tab and its popups (bank
challenges). While it is open, Machine's browse requests are refused. The URL
and screenshots never appear in VFS. It is not reachable from another device.

Takeover is for login, verification or an unsupported field, not routine
passenger entry. On handback, checkout navigates the human-selected tab through
`about:blank` into a fresh document at the selected URL, closes all other
pages, and clears navigation history before enabling shopping. This retains
the site's tab-scoped booking/session storage without handing the private DOM,
form values or execution contexts to Machine. Storage is not exported through
the VFS. Failure to replace the document leaves shopping paused.

Card and site-payment completion still close every private page and resume
shopping in a fresh blank tab. Takeover buys nothing and releases no card;
saved-card payment needs its separate approval for the exact merchant/total.

The extension tab is already visible in the person's browser, so it is not
mirrored into the private view. Approval follow-up instead tells the person to
return to the Bloom tab for a bank check or correction.

### Journey selection and installed-extension limit

An explicit shopping `open` selects the extension only for origins in its
pinned permissions, otherwise checkout's browser. Connecting an extension does
not take over an existing journey. That journey retains its original connection
through private execution; a disconnect or replacement fails rather than
switching browsers or replaying payment. Completion closes only the extension's
recorded tab before returning public control. Unsupported extension takeover
resumption remains paused instead of exposing the private document.

Every explicit open starts a new traveler-unlock context, even on the same
origin. An approval returned for an earlier context is discarded. Private
traveler actions recheck context and origin while holding the browsing lock.

The native host registers in Linux Chrome/Chromium config directories or macOS
Application Support directories. Its relay uses bounded JSON frames and queues;
malformed/truncated/oversized input and lost connections fail closed. Platform
registration follows [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

This is still a development connection, not installed extension acceptance.
Checkout currently accepts only its own UID on the extension socket; the
installed browser uses the login UID, not the isolated checkout UID. Do not
remove this check or open the socket to the login UID as a packaging shortcut.
A login-UID check alone cannot distinguish Chrome's native host from Machine
or another process running under that same login. A normal-profile browser is
therefore a different trust boundary from checkout's isolated browser. Private
installed-extension support needs a protected bridge or an explicit product
decision accepting the trusted-login-browser limitation, with accurate claims
and acceptance tests. Neither this change nor green fixture tests grants it.

## Durable states and recovery

The operation store is written before every irreversible step:

- `release_started` is committed before card plaintext exists; `submitted`
  before the site-mode click. A lost response never causes a second fill or
  click.
- On restart, operations that may have disclosed or submitted become
  `disclosure_unknown`; operations still waiting become
  `failed_before_release`. Neither is retried automatically.
- Outcomes (`paid`, `declined`, `uncertain`) are what the merchant page showed,
  not a bank confirmation.

`checkout/history.json` lists the 50 latest requests with mode, shop origin,
the approved total and the current status, so an agent can avoid buying twice.

## Sealed Approval relationship

Card checkout is a custody ceremony, not a signing approval. Each card
ceremony consumes one passkey approval for one operation; the release is bound
to the operation ID and the recipient key, and the recipient key is discarded
after one use. Nothing persists a PRF output, CVC, or reusable grant.

## Limits

- Card ceremonies share Broker's anonymous quota of four per five minutes.
- Take-over and site payment need the card passkey, so one card must be saved.
- The private view is local; phone take-over needs a remote surface.
- Sites that block a fresh browser need an allowlisted origin in the person's
  existing profile. The extension does not make a refused connection or a dead
  airline bookable. New origins stay off until a rehearsal in that profile
  reaches payment and stops before Pay. The caller supplies the booking link.
