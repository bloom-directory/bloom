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
  CDP pipe, using Chromium's normal browser identity.
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
Amounts use ISO 4217 minor units. Checkout conversion and Broker's approval
display use those exponents, not the browser's currency display precision:
for example, HUF28,826.50 is 2882650 minor units even when CLDR normally
displays forints without fractions.
A card is filled only into fields hosted by a known payment provider
(`PROVIDER_FIELD_ORIGINS`); other pages go to the private view.

The approval page also shows the entered fields and, when checkout owns the
browser, a screenshot of the order. These are human aids and are not bound to
the approval.

## Saved booking party

Checkout retains up to twelve independently approved traveler records within
one origin/journey (nine passengers and separate payer/billing/contact roles).
Private values remain in checkout. `fill_traveler` and `type_traveler` accept
`traveler_id`; it is mandatory when multiple records are unlocked and must
name an already approved record. Existing single-person JSON remains valid.

Duplicate passenger forms are not filled by guessing DOM order. The agent uses
public field references and the exact approved person's ID for each passenger
or payer/contact field. No raw saved values are accepted from or returned to
Machine. A new explicit open and private completion/handback clear the cache;
expired records are refused synchronously and erased by a one-second sweep.
Cancellation discards an outstanding recipient key or removes the unlocked
record, durably marks the operation cancelled and cannot be reversed by a late
release/poll result. Broker cancellation is best effort after local revocation;
an unavailable Broker cannot preserve local fill access. Already disclosed
page values cannot be recalled.
Snapshot-redaction patterns use zeroizing storage and remain until the browser
context is safely discarded, so expiry cannot expose values already in a DOM.
Filled controls also carry private annotations in an isolated-world WeakMap;
their public values become saved-field placeholders. This protects short date
parts without replacing the same digits in prices or flight dates. Select
values use this projection rather than duplicated accessibility-tree text.
Known numeric and English full-date renderings are redacted in review text.
Before payment approval, verify the itinerary, party, extras and final total.

## Booking sites that reject Bloom's browser

When an airline rejects Bloom's browser, the agent tries an agency selling
the selected itinerary on Google's booking page. It reports the agency's
price and booking terms before approval. If no listed seller works, it may
search a known agency's normal website for the same flights, verifying actual
airports, local dates/times, cabin and party before unlocking travelers. If
no matching offer works, it gives the person the booking link. No fingerprint spoofing, automated CAPTCHA
solving or cookie import is used.

Seller observations are dated evidence of a particular step and itinerary.
A homepage loading does not prove checkout support; payment review does not
prove a charge or ticket issuance. Earlier purchases do not verify a changed
service combination. Current operator guidance lives in `docs/checkout.md`
inside the VFS.

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

Every explicit open starts a new traveler-unlock context, even on the same
origin. An approval returned for an earlier context is discarded. Private
traveler actions recheck context and origin while holding the browsing lock.

## Durable states and recovery

The operation store is written before every irreversible step:

- `release_started` is committed before card plaintext exists; `submitted`
  before the site-mode click. A lost response never causes a second fill or
  click.
- On restart, interrupted disclosure becomes `disclosure_unknown`; submission
  and form-error states become `uncertain`. Earlier `not_submitted` records
  also become `uncertain`, since older code inferred them from form errors.
  Operations still awaiting release become `failed_before_release`. None is
  retried automatically.
- Form errors, timeout and closing the private view do not establish that no
  charge occurred. The UI asks the person to check the merchant and bank before
  another attempt; it never promises that nothing was charged.
- A reservation reference alone is not a successful purchase. `booked` needs
  the reference plus a merchant-reported purchase/payment confirmation or
  issued-ticket evidence. This remains page-derived evidence, not independent
  bank settlement. Durable per-booking reconciliation and protection against
  retrying an unresolved purchase under a new operation ID remain unfinished.

`checkout/history.json` lists the 50 latest requests with mode, shop origin,
the approved total and the current status, so an agent can avoid buying twice.

## Sealed Approval relationship

Card checkout is a custody ceremony, not a signing approval. Each card
ceremony consumes one passkey approval for one operation; the release is bound
to the operation ID and the recipient key. Signer permits one release per
operation ID. Checkout generates a fresh recipient key for each operation and
discards it after one use; Signer does not prevent recipient-key reuse across
different operation IDs. Nothing persists a PRF output, CVC, or reusable grant.

## Limits

- Card ceremonies share Broker's anonymous quota of four per five minutes.
- Take-over and site payment need the card passkey, so one card must be saved.
- The private view is local; phone take-over needs a remote surface.
- Direct airline booking depends on the site's browser acceptance. Agency
  fallback depends on a listed seller offering the selected itinerary; it
  does not guarantee coverage for every airline or fare.
