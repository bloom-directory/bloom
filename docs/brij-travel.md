# BRIJ flight booking through Bloom

BRIJ exposes flight search and booking at `https://travel.brij.fi`, paid in
Solana-mainnet USDC through x402. Bloom's Solana exact-payment adapter lets an
agent use it through the existing `/requests` surface. This is an experimental
integration, not a dedicated flights Petal or a claim that ticketing is verified.
It requires the Solana x402 adapter introduced in
[Bloom PR #350](https://github.com/bloom-directory/bloom/pull/350); an older
EVM-only client cannot make these payments.

## Verified on October 13, 2026

An installed test candidate crossed the real Machine–Broker–Signer boundary,
with owner passkey approval and Solana settlement:

| Call | Fee | Observed result |
| --- | --- | --- |
| `POST /air/search` | $0.10 | HTTP 200; final flight offers after free polling |
| `POST /air/offer-details` | $0.01 | HTTP 200; refreshed fare and expiry |
| `POST /air/intents` | $0.10 | HTTP 201; response not inspected because it contains private capabilities |
| `POST /air/book` | Full fare | **Not tested; no fare paid or ticket issued** |

The search returned Aerolíneas AR1554, Córdoba to Bariloche, October 25, 2026,
13:20–15:35 local time. The Plus fare was US$166.57 with one carry-on and no
checked bag. This historical quote is not authority for a future purchase.
Search and intent-fee settlements were independently confirmed finalized with
no error on mainnet. Test receipts are evidence of API delivery and payment,
not of an issued airline ticket.

## Search

Read the running Bloom's `/AGENTS.md` and paid-request documentation first.
Use a wallet's authenticated canonical Solana account and fund it with USDC;
never export a key to an x402 SDK. The supported mint is
`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` (six decimals).

An example request to write to `/requests/new`:

```toml
method = "POST"
url = "https://travel.brij.fi/air/search"
wallet = "main"
max_amount_usd = "0.10"
[headers]
content-type = "application/json"
[body]
inline = '{"origin_iata":"COR","destination_iata":"BRC","depart_date":"2026-10-25","adults":1,"cabin_class":"economy","max_stops":0,"cheapest_per_itinerary":true,"limit":10}'
```

Identify the exact new request from the before/after pending-directory
difference. Inspect its plan, merchant, wallet, amount and policy; confirm that
request only. Forward its public `approval_challenge.json` ceremony URL to the
owner immediately, then confirm the same request after approval. Solana's
frozen blockhash has a shorter lifetime than the approval page. An expired
draft needs a new request and fresh approval; never substitute new transaction
bytes under an old exact grant.

Inspect the sent/failed receipt before retrying anything. A timeout does not
prove non-payment. Do not read or expose payment-credential sidecars.

Search can cost $0.10–$5 depending on load; a $0.10 cap must reject a higher
challenge. If the response says `enriching`, poll free
`POST /air/search-updates` with `{"search_id":"<returned search id>"}` until
`complete`. Compare all fare options, baggage, local arrival times and sellers.
Unknown refund/change conditions are not promises or refusals.

## Prepare and buy

1. Revalidate the selected offer through `POST /air/offer-details`, body
   `{"offer_id":"<selected id>"}`, capped at $0.01. Inspect fresh price,
   expiry, included bags and conditions. Additional services are informational
   and cannot be purchased through this API.
2. With approval for the $0.10 call, create `POST /air/intents`, body
   `{"offer_id":"<selected id>","funding_wallet":"<authenticated buyer address>","refund_wallet":"<same buyer address>"}`.
   This creates a booking intent; it does not buy a ticket or fund the fare.
3. The response is **credential-bearing**: `intent_id` and
   `customer_support_code` are private capability tokens. Obtain any required
   exact-path permission before reading it. Keep them out of chat, public
   projections, evidence and logs; retain them in an approved private store
   for booking status and refund recovery.
4. Inspect the exact intent's fare, expiry, passenger count, escrow vault and
   frozen refund destination. Before fare funding, verify the payment challenge
   agrees with that intent and review the vendor/escrow limitations with the
   owner. Program ownership alone is not proof of escrow safety.
5. Collect the required passenger and contact details accurately. Then stage
   `POST /air/book` with the private intent ID and passenger list. Its x402
   payment is the **full fare**, not a $0.10 service fee. Show the exact flight,
   baggage, currency and total and obtain separate owner payment approval.
6. Reconcile settlement and poll free `GET /air/intents/{intent_id}` privately
   for fulfillment. HTTP acceptance or a PNR alone is not proof of an issued
   ticket: verify ticket numbers/status with the airline before declaring the
   purchase complete. An ambiguous result must not trigger another purchase.

## Limits and alternate card route

BRIJ accepts USDC, not Bloom's saved card. Card booking is a separate airline
checkout through Bloom's protected browser, with an independently quoted
total and card ceremony. Browser takeover is for login, verification or a
blocked automation step; API booking itself does not require it.

BRIJ's terms make settled API fees non-refundable, leave post-ticket refunds
subject to airline rules and manual review, and cap contractual liability at
service fees, subject to applicable law. Public settlement/refund activity
exists, but independent customer reviews and unique traveler counts were not
verified. Contract upgrade authority, oracle trust, exact escrow bindings and
real ticket issuance remain unverified by this integration.

Authoritative vendor surfaces: [API guide](https://travel.brij.fi/llms.txt),
[schema](https://travel.brij.fi/openapi.json),
[terms](https://travel.brij.fi/terms),
[escrow description](https://docs.brij.fi/), and
[public order explorer](https://docs.brij.fi/bounties).
Always recheck current prices, schema and terms before a purchase.
