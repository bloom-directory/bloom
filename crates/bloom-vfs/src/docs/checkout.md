# Checkout

When `cards/` and `checkout/` are present, shop inside Bloom's browser. Never
ask for card number, expiry, cardholder name, or CVC in chat, shell, or VFS.
Those go only in the human's Broker ceremony page. Do not use another browser
tool for this checkout.

- Read `cards/index.json` for card IDs, labels, brands, and last four digits.
- Write `cards/add.json` with `operation_id` (64 hex characters), `card_id`,
  and `label`. Read `cards/operations/<operation_id>/ceremony.json` and forward
  its ceremony URL. The human enters and saves the card privately.
- To delete, write `cards/delete.json` with `operation_id` and `card_id`, then
  forward the ceremony URL in the same way.
- For passenger details, read `travelers/index.json`: IDs, labels and available
  field categories only. Never ask for or save legal names, birth dates,
  documents or contact details in chat, shell, or `checkout/profile.json`.
- Save a person through `travelers/save.json` with `operation_id`, `traveler_id`
  and a public `label`. Forward the URL in
  `travelers/operations/<operation_id>/ceremony.json`. The human enters details
  privately and approves saving them. Reuse an ID to replace that person's
  record; `travelers/delete.json` accepts `operation_id` and `traveler_id`.
- On the booking website, before the passenger form, write
  `checkout/requests/<new-64-hex-id>/in.json` with `traveler_id` and
  `agent_description`. Forward the status ceremony URL. One approval unlocks
  that person for this website for 30 minutes; `status.json` then says
  `unlocked`. It authorizes no payment.
- Unlock each passenger, payer or contact separately once. Approved records
  remain available across this journey's pages; do not repeat the ceremony on
  every page. With multiple people unlocked, `fill_traveler` and
  `type_traveler` require the exact `traveler_id`. Omitting it is allowed only
  when one record is unlocked. An unapproved ID is refused.
- On each page asking for that person's details, send the browse action
  `fill_traveler`. It fills the empty fields it recognizes and returns only
  their names; card-holder fields are left for the payer. For a field it
  missed, send `type_traveler` with `element_ref` and `field`: a saved field,
  `phone_national` (no country code, when the page shows the prefix
  separately), `phone_area` and `phone_local` (area code and number, split by
  the country's numbering plan), `born_on_day`, `born_on_month`,
  `born_on_year` or `born_on_dmy`.
  Snapshots show unlocked values as `[saved <field>]`; check each field holds
  the right placeholder, and never try to recover the values.
  One `fill_traveler` person per booking. The same person may be filled again
  on a later step. A different person is refused; use `type_traveler` with
  that person's id for each field. When a page contains multiple passenger
  blocks, use `type_traveler` with the person's ID and fresh references to
  that person's specific fields. Automatic filling of duplicate or ambiguous
  fields stays blocked. Use the payer or contact's own approved ID for those
  fields.
  A new explicit open, private completion/handback or expiry ends the unlock.
  To cancel an outstanding unlock or revoke future fills from an unlocked
  record, write to its original `checkout/requests/<operation_id>/cancel`.
  The file ignores the body. Values already sent to the site
  cannot be retracted; cancellation prevents future private fills.
- Write a browse request to `checkout/browse/<64-hex-slot>/in.json`; read
  `out.json`. Reuse a slot. Results expire after five minutes. Requests use
  `action`: `open` plus `url`, `snapshot`, `click` plus `element_ref`, `type`
  plus `element_ref` and `text`, `select` plus `element_ref` and `value`,
  `back`, `fill_traveler`, or `type_traveler` plus `element_ref` and `field`.
- A snapshot element may carry `context`, the short text around it. Use it
  to tell repeated controls apart, such as identical fare buttons on
  different flight cards or the same day number in two calendar months.
  Large pages may report that text is limited to the listed controls;
  those controls, including on-page filters, remain usable.
- Use fresh snapshot refs after every action. The browser rejects direct
  card entry and recognizable payment submission through shopping controls.
- Shops load controls in stages. If a control is missing or the document
  changed, request another snapshot before concluding it is unavailable.
  Check each product's required size, format and purchase frequency; radio
  buttons and their labels report `checked`. After Add to cart, confirm the
  cart updated before navigating away, so the shop can finish adding the item.
- A payment request is refused while the page shows form errors; take a
  snapshot, fix what it marks, and request again.
- For a saved-card payment, select the shop's debit/credit-card option so
  its card fields are visible before requesting payment approval.
- Once checkout is ready, write `checkout/requests/<new-64-hex-id>/in.json`
  with `card_id` and `agent_description`. That description is shown as agent
  text, not verified purchase facts. Read `status.json`, forward its ceremony
  URL, and wait. Shopping access stays paused through private checkout.
  Complete contact, delivery and billing details and choose shipping first.
  If billing matches delivery, select that option instead of leaving a
  separate billing form empty. Blank shipping-choice labels are still loading;
  wait for named rates and a selected method before requesting approval.
  A total beside “Enter shipping address” can omit delivery and destination
  taxes; it is not a final quote. Visible card boxes alone do not prove that
  a checkout is ready to submit.
- If the human is logged in to the shop with a saved payment method there,
  omit `card_id`: after approval Bloom clicks the shop's pay button once and
  the shop charges its saved method.
- When a login, verification code, captcha or bot check blocks you, write a
  request with `"take_over": true` and an `agent_description` saying what the
  human must do. Forward the ceremony URL. The human approves, works in
  Bloom's browser, and clicks Done; `status.json` then says `returned` and
  shopping continues on the page the human left. Logins persist in Bloom's
  browser, so a take-over is needed once per site, not per purchase.
  Approvals use the passkey set up with the first saved card; if
  `cards/index.json` is empty, ask the human to add a card first.
- Cancellation is a write to the request's `cancel` file, only before release.
- If the person loses an approved private-view tab, read `status.json` and
  forward `view_url`. It reopens the view in the browser that claimed it;
  access still requires that browser's private cookie. It carries no access
  token. The original approval-page link can also be reopened in that browser.
  Do not request another payment just to recover a lost tab.
- Read `checkout/history.json` for the 50 latest requests: time, kind, shop,
  total read from the page and request status. A failed or cancelled request
  can have a total without any approval or payment. Check it before buying again at the same
  shop so nothing is ordered twice. A subscription also carries the terms the
  page stated, `renewal_minor`, `renewal_period` and `renewal_starts_on`,
  so this is where to answer what they are still paying for and when it next
  charges. A renewal the person approved elsewhere is not here, and no entry
  proves the shop has not changed its price since.

The human approves website, total, currency, installments, recurring status,
and card, then enters CVC privately; the approval also lists entered fields
and shows a screenshot when checkout owns the browser. Bloom fills and submits
once. Bloom fills a saved card into fields hosted by a known payment
provider (Stripe, Shopify, Adyen, Braintree, Yuno and others) or into the own
checkout page of a listed merchant. A bank challenge,
card fields anywhere else, or
an unclear total goes to the human's private view; its access token and screenshots
never appear in VFS. The cookie-protected `view_url` is only an entry point for
the already authorized browser. A manual
fallback releases no saved card.

For a subscription, the approval states the ongoing price, how often it
recurs and the day it starts, whenever the page says them plainly. Tell the
person what those terms are before asking for approval: a trial price is not
what the subscription costs. To stop one, cancel it on the shop's own site in
this browser, with a take-over if it needs a login; Bloom holds no
subscription of its own and cancelling is never a payment request. A page offering several plans states several
ongoing prices, so Bloom claims none of them; say which plan is selected and
what it renews at. Bloom cannot cap what a merchant charges after a card is
on file, and cancelling is done with the merchant, not through Bloom.

Use a requested agency directly; otherwise try the airline first. Open
`google_flights_url` and match the chosen offer's airports, flight numbers,
airport-local dates and times, cabin and party; for round trips match both
outbound and return. Report price changes rather than substituting another
itinerary. Explain the chosen seller's final price and material trade-offs,
including a substantially cheaper alternative.

If the airline blocks, shows an empty page or loses the itinerary, recover
the same flights there or try an agency on Google's booking page. Expand
extra booking options and prioritize dated `known.opened` observations.
If Back in the followed popup does not restore Google, reopen the original
search URL and reselect the same itinerary. A country chooser is not a block.
If no listed seller works, search a known agency's normal website for the
same flights; never invent an agency itinerary URL or bypass a challenge.
Verify the actual offer: partner links and search results can change airports,
cabin or codeshare. Recheck dates/times, party, bags and final total before
unlocking travelers or requesting payment. Conflicting dates or times require
private review or another seller. Hand off when no matching offer works.

Explain agency trade-offs before approval: fees and upsells may raise the
price. Changes and refunds go through the agency. An order confirmation can
precede ticket issuance; expect the e-ticket later by email, and do not call
an order number a paid ticket. Agencies may require stricter fraud checks.
Record the agency as the shop. Reachability observations have dates, not
guarantees; hand off on a block without fingerprint spoofing, CAPTCHA
solving or cookie import. Earlier airline homepage probes do not establish
whether an itinerary can reach checkout today. Aerolíneas reached its passenger
page but stopped at reCAPTCHA; JetSMART had a purchase on an earlier build.
Neither result verifies the current build or another itinerary. Record the
date, itinerary, last completed step and blocker when checking a seller.
Reaching payment review does not prove a charge or an issued ticket.
Do not click or type through the desktop.

`filled` means fields were filled, not that payment succeeded. `booked`,
`paid` and `declined` describe what the merchant reported; Bloom has not
verified the bank charge. For `booked`, `outcome.order_id` holds the booking
code the site showed; a reference alone does not prove payment or ticket issue.
`needs_input` means the page needs attention, not that no payment was submitted.
Do not infer a charge outcome from a form error, timeout or closing the view.
`paused` means checkout could not hand the browser back, so shopping stays paused.
For a `cancelled` or `failed_before_release` request with `paused`, write its
`cancel` file again to retry browser cleanup. This cannot repeat payment.
`reason` says why Bloom left the payment to the person: `facts_unreadable` for
a total or currency it could not read, `fields_unsupported` for card fields in
an unexpected shape, `receiving_origin_unreviewed` for a frame that would
receive the card and is not a reviewed payment host. The first two can change
with the page: reach the real payment step, let it finish loading and request
payment again. The third needs the person, or another seller.
Older `not_submitted` records and interrupted `manual_required` or
`human_control` views become `uncertain` on restart: the person may have paid
privately. A fresh browser clears `paused`, not the uncertain result.
`partially_filled`, `disclosure_unknown`, and `uncertain` require
human inspection; never repeat the purchase automatically. Ask the human to
check the merchant account or confirmation email, then write
`checkout/requests/<operation_id>/resolve`. The file ignores the body. Bloom
refuses another checkout at that shop until that write. After private checkout
closes, shopping resumes on a fresh tab.
