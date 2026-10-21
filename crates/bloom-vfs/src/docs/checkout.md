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
  When a page contains multiple passenger blocks, use `type_traveler` with the
  person's ID and fresh references to that person's specific fields. Automatic
  filling of duplicate/ambiguous fields stays blocked. Use the payer/contact's
  own approved ID for those fields; never substitute a passenger by position.
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
- Use fresh snapshot refs after every action. The browser rejects direct
  card entry and recognizable payment submission through shopping controls.
- A payment request is refused while the page shows form errors; take a
  snapshot, fix what it marks, and request again.
- Once checkout is ready, write `checkout/requests/<new-64-hex-id>/in.json`
  with `card_id` and `agent_description`. That description is shown as agent
  text, not verified purchase facts. Read `status.json`, forward its ceremony
  URL, and wait. Shopping access stays paused through private checkout.
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
- Read `checkout/history.json` for the 50 latest requests: time, kind, shop,
  approved total and final status. Check it before buying again at the same
  shop so nothing is ordered twice.

The human approves website, total, currency, installments, recurring status,
and card, then enters CVC privately; the approval also lists entered fields
and shows a screenshot when checkout owns the browser. Bloom fills and submits
once. Bloom fills a saved card into fields hosted by a known payment
provider (Stripe, Shopify, Adyen, Braintree, Yuno and others) or into the own
checkout page of a listed merchant. A bank challenge,
card fields anywhere else, or
an unclear total goes to the human's private view; its URL and screenshots
never appear in VFS. A manual
fallback releases no saved card.

Airlines that reject a fresh browser are not bookable by Bloom. Give the
person the deep link and stop; they book it themselves. Named cases include
Aerolíneas Argentinas, American, SAS, SWISS, easyJet and United. JetSMART,
Shopify and Stripe-hosted checkouts work in Bloom's own browser. Do not click
or type through the desktop. Open the booking link you were given.

`filled` means fields were filled, not that payment succeeded. `booked`,
`paid` and `declined` describe what the merchant reported; Bloom has not
verified the bank charge. For `booked`, `outcome.order_id` holds the booking
code the site showed; a reference alone does not prove payment or ticket issue.
`needs_input` means the page needs attention, not that no payment was submitted.
Do not infer a charge outcome from a form error, timeout or closing the view.
Older `not_submitted` records are also ambiguous and become `uncertain` on
restart. `partially_filled`, `disclosure_unknown`, and `uncertain` require
human inspection; never repeat the purchase automatically. Ask the human to
check the merchant account or confirmation email. After private checkout
closes, shopping resumes on a fresh tab.
