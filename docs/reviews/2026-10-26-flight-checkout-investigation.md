# Flight checkout investigation — 26 October 2026

Flight search and checkout rehearsals work across multiple airlines, but this
does not establish that every airline can be booked. Finish the following
three gaps before expanding coverage further. This report records findings;
it does not implement their fixes.

## Confirmed gaps

1. **Currency parsing and approval display.** Checkout rejects the unambiguous
   `Total IQD 1,250.125`: the local browser regression expected 1250125 minor
   units and received no amount. Exact-function checks also rejected
   `BHD 1.250,125`. Support these formats while preserving refusal of ambiguous
   `KWD 1.234`. This currently causes manual fallback, not an observed wrong
   charge. Separately, Broker #95 formats 1250125 minor IQD as 1,250,125 rather
   than 1,250.125 using host Intl defaults: a 1000-fold approval-display error.
   The existing isolated Broker patch at
   `4dd1b58b7217cdcb0a1238c5ee70febbc1cf95a4` applies cleanly to #95's
   `e33344beb4e15aeef02b80f55a60e105322835ea`, but is not integrated there.
   Integrate it through that PR's owner and test the resulting combination.
2. **Safe preparation reasons.** Checkout logs discovery failures but drops
   their cause from public status. Observed unreadable-total and unreviewed
   receiver fallbacks expose the same status shape. Return a few bounded,
   code-owned reasons for facts, fields and receiving-origin failures through
   the existing API. Never expose raw merchant errors or private values; no
   retry framework or additional approval step is needed.
3. **One complete synthetic flow through real services.** Live airline
   rehearsals fill public fake people and cancel before card release. Stripe
   test-mode fixtures call Discovery directly; existing saved-person and
   Broker tests use injected records or a mock Signer. Join the ordinary
   VFS/tool path through real Machine, Broker, Signer and Checkout with synthetic
   saved travelers, a separate payer, normal test-credential approval and a
   controlled merchant/test processor. Assert success, decline, amount changes,
   restart recovery and no duplicate submission using existing fixtures.

Relevant code: `crates/bloom-checkout/src/facts.js`,
`crates/bloom-checkout/src/service.rs`,
`crates/bloom-checkout-api/src/lib.rs` and the Stripe tests in
`crates/bloom-checkout/src/discovery.rs`.

## What the evidence establishes

At Bloom `79ea2a52b55ccedd7c96c7256b4e30be7bd9e2d8` and Flights
`c41b1982581aa1e1b52a55cccbc4b1af1f108472`, the recent audit found 38 requests,
all cancelled: 33 bound quotes and five manual fallbacks, with no private-field
release or payment outcome. The 33 quotes cover five shop origins but chiefly
two checkout families: 25 Jettzy Malaysia and eight Mytrip/Gotogate (Etraveli).
These are useful itinerary and form variations, not 33 independent payment
integrations. Native airline blocks remain separate from agency successes.

Existing verification at the Bloom revision above passed 89 local checkout
tests (seven network tests excluded), strict Clippy, formatting and builds.
All four explicit Stripe test-mode success/decline/3DS cases passed. CI runs
40263752341 and 40263752345, dry release builds 40263766148, and macOS
conformance 40263770851 passed. Those results do not cover the newly reproduced
three-decimal parser regression. Its temporary failing test was reverted;
the diagnostic patch and log are retained in the workspace evidence directory
`/data/flights-1024/` as `investigate-three-decimal-regression.patch` and
`investigate-three-decimal-browser-red.log`.

The current combination has not issued a real ticket. Earlier purchases do
not prove the current build. The older JetSMART operation `0ebc703d…` still
needs its bank outcome resolved; the safety block applies to that shop origin,
not every airline or agency. Do not retry an uncertain payment.

## Keep the remaining work small

- Keep browser search without an API key. No new SerpApi key, x402 integration,
  bundled credentials or per-airline framework is justified by these failures.
- Remove the optional API Aerolineas route/date booking-URL special case in
  Flights `route/src/lib.rs`; it omits the selected flight number. Use actual
  seller buttons or normal search instead. This cleanup is not implemented.
- Reuse rehearsal helpers and record observed itinerary, party, fare, bags,
  charge, filled field names, stopping reason and cancellation/outcome. Store
  no private values. Prioritize distinct checkout behavior over airline counts.
- Do not buy a real ticket as a development prerequisite. Ticket issuance is
  verified on a genuine authorized trip. Keep normal human approval for funds.
- Two-login macOS GUI isolation remains a release/privacy check, not a
  prerequisite for public fake-passenger rehearsals or Linux iteration.

Signer #65 and Broker #95 remain draft dependencies of Bloom #346. Review,
dependency integration, verification at the resulting revisions and explicit
approval of each specific merge remain outstanding. No merge or live purchase
was performed during this investigation.
