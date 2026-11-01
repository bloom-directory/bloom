# Checkout

When `cards/` and `checkout/` are present, shop in Bloom's browser through
`checkout/browse`. Do not use another browser tool or the desktop for this.
Never ask for card numbers, expiry, cardholder name, CVC, legal names, birth
dates, documents or contact details in chat, shell or VFS. The person enters
them only on Bloom's private ceremony page. Every ID you create below is a new
64-character lowercase hex string.

## Saved cards and travelers

- `cards/index.json` lists card IDs, labels, brands and last four digits. If
  it is empty, ask the person to add a card first: approvals use the passkey
  set up with the first card.
- Add: write `cards/add.json` with `operation_id`, `card_id` and `label`.
  Delete: write `cards/delete.json` with `operation_id` and `card_id`.
- `travelers/index.json` lists traveler IDs, labels and field categories only.
  Save or replace: `travelers/save.json` with `operation_id`, `traveler_id`
  and a public `label`. Delete: `travelers/delete.json`.
- For each of these, read `<cards|travelers>/operations/<operation_id>/ceremony.json`
  and send the person its URL.

## Browse

Write `checkout/browse/<slot>/in.json`, then read `out.json` (kept five
minutes). Reuse the slot. Actions: `open` + `url`, `snapshot`, `click` +
`element_ref`, `type` + `element_ref` + `text`, `select` + `element_ref` +
`value`, `back`, `fill_traveler`, `type_traveler`.

- Take a fresh snapshot after every action; refs expire. Pages load in
  stages: if a control is missing or the page changed, snapshot again before
  calling it unavailable.
- `type` needs an element whose `role` is `input` or `textarea`; `select`
  needs role `select` and an option `value` from the snapshot. A label or
  button of the same name only focuses the field: click it and snapshot.
- `context` is the text around an element. Use it to tell apart identical
  buttons, such as fares on different flight cards or the same day in two
  months. Radio buttons and labels report `checked`.
- Bloom blocks typing card or password data and clicking pay buttons. That
  is the cue to request payment approval, not to work around it.
- After Add to cart, confirm the cart changed before leaving the page.
- Links carry `href` (no query or fragment): read a document link instead of
  clicking it. If a popup closes or downloads a file, shopping continues on the
  remaining page; take a new snapshot.

## Travelers on a booking

1. Before the passenger form, write `checkout/requests/<id>/in.json` with
   `traveler_id` and `agent_description`, and send the person the ceremony
   URL from `status.json`. One approval unlocks that person on this website
   for 30 minutes (`status.json` says `unlocked`). It pays nothing. Unlock each
   passenger, payer or contact once per journey, not once per page.
2. Send `fill_traveler` (with `traveler_id` when more than one is unlocked).
   It fills the empty fields it recognizes and returns their names in
   `filled_fields`. It fills one person per booking and leaves card-holder
   fields for the payer.
3. For a missed field, a second passenger block or a different person, send
   `type_traveler` with `traveler_id`, a fresh `element_ref` and `field`: a
   saved field, `phone_national` (no country code), `phone_area`,
   `phone_local`, `born_on_day`, `born_on_month`, `born_on_year`, `born_on_dmy`
   or `born_on_mdy`. Use the date order the field states; never guess it from
   the site's language. Choose the phone country before area and number:
   changing it can clear them.
4. Snapshots show filled values as `[saved <field>]`. Check each field holds
   the right placeholder on the seller's review step; never try to read the
   values. While these appear, page text is limited to nearby controls.

A new `open`, a handback or expiry ends the unlock. Writing the request's
`cancel` file stops future fills; values already sent to the site stay there.

## Pay

1. Finish everything first: contact, delivery and billing (choose "same as
   delivery" when it matches), a named shipping rate, and the site's
   credit/debit card option so its card fields show. Fix any form errors the
   snapshot marks. A total beside "Enter shipping address" is not final.
2. Tell the person the shop, total and anything that changes the price. For a
   subscription, say what it costs after any trial and how often.
3. Write `checkout/requests/<id>/in.json` with `card_id` and
   `agent_description`, read `status.json`, send the ceremony URL and wait.
   The person sees the shop, total, currency, installments, renewal terms and
   card read from the page, approves with their passkey and enters the CVC.
   Bloom fills and submits once. Shopping is paused meanwhile.
4. If the person is logged in to the shop with its own saved payment method,
   omit `card_id`; after approval Bloom clicks the pay button once.

Bloom fills cards only into known payment providers (Stripe, Shopify, Adyen,
Braintree, Yuno and others) or a listed merchant's own page. Anything else,
a bank challenge or an unclear total goes to the person's private view; no
card is released to a manual fallback. `agent_description` is shown as your
words, not as verified facts.

An early Buy button before passenger details is still a payment button. Use a
take-over for that step; never bypass the guard.

## Blocks: take-over

For a login, code, captcha or bot check, write a request with
`"take_over": true` and an `agent_description` telling the person what to do.
Send the ceremony URL. They work in Bloom's browser and click Done;
`status.json` says `returned` and you continue on their page. Some sellers
reset bags, seats or extras after handback: recheck them and the total.
Closing a payment checkout clears the site's cookies, so a later purchase may
need another login.

## Results and recovery

`status.json` `state` reports what the merchant showed; Bloom has not seen the
bank charge.

| State | Meaning and next step |
| --- | --- |
| `booked`, `paid` | Merchant reported success. `outcome.order_id` is the code shown; for flights it is not proof of a ticket. |
| `declined` | Merchant declined. Tell the person; do not retry without asking. |
| `filled` | Fields filled; not proof of payment. |
| `needs_input` | The page wants more input; payment may already be submitted. The person finishes in the private view. Optional wallet signup can add fields: complete or decline it there. |
| `partially_filled`, `disclosure_unknown`, `uncertain` | Unknown whether money moved. Ask the person to check the shop account or email, then write `checkout/requests/<id>/resolve`. Bloom refuses another checkout at that shop until then. |
| `paused` | Checkout could not hand the browser back. Check status before anything else; for a request that never released a card, write its `cancel` again to retry cleanup. A restart clears `paused`, not an uncertain result. |

Never buy again after a timeout, form error or closed view. Read
`checkout/history.json` (latest 50 requests, with shop, total and status)
before any repeat purchase at a shop. A failed request can show a total
without any payment.

When preparation falls back to the person, `reason` says why:

- `facts_unreadable`: total, currency or payment step incomplete. Let the
  page finish loading on the real payment step and request once more.
- `fields_unsupported`: card fields in an unexpected shape. Same as above.
- `payment_action_ambiguous`: several payment buttons. The person chooses
  privately; never click Subscribe or Buy to test which one charges.
- `charge_terms_unreadable`: unclear installments. The person reviews privately.
- `receiving_origin_unreviewed`: the card would go to an unreviewed host.
  The person pays privately, or choose another seller.

If the same reason repeats on an unchanged page, use a take-over.

- Cancel before release by writing the request's `cancel` file.
- A lost private tab: read `status.json` and send `view_url`. It reopens only
  in the browser that claimed the view. Never request another payment for it.
- After a restart, interrupted private views become `uncertain`: the person
  may have paid.

## Subscriptions

`history.json` entries carry the stated `renewal_minor`, `renewal_period`
and `renewal_starts_on`; use them to say what the person still pays and
when. With several plans on the page Bloom claims no renewal price, so say
which plan is selected. Bloom cannot cap later charges. To cancel, do it on
the shop's site in this browser (with a take-over for login); it is never a
payment request.

## Flights

Search and seller choice are in `/petals/flights/README.md`. Agencies can add
fees, handle changes and refunds themselves, and may email the e-ticket after
the order: record the agency as the shop, and do not call an order number a
paid ticket.
