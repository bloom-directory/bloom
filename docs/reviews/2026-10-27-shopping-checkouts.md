# Shopping checkout acceptance, 2026-10-27

Ten different merchants reached their final card checkout through Bloom's
normal `checkout/browse` VFS. Each accepted synthetic contact and billing
details, resolved shipping where applicable, exposed its payment control and
reviewed Shopify card fields, and passed saved-card payment discovery.
No live card was entered and no live order was submitted.

| Merchant | Product | Displayed total (USD) |
|---|---|---:|
| [AeroPress](https://aeropress.com/products/aeropress-coffee-maker) | Original coffee maker | 51.35 |
| [Simply On Purpose](https://shop.simplyonpurpose.org/products/story-starters) | Story Starters digital download | 1.00 |
| [Stumptown](https://www.stumptowncoffee.com/products/holler-mountain) | Holler Mountain, one-time purchase | 26.00 |
| [Craighill](https://craighill.co/products/closed-helix-keyring) | Closed Helix Keyring | 36.59 |
| [Baronfig](https://baronfig.com/products/squire) | Squire pen | 72.95 |
| [Ugmonk](https://ugmonk.com/products/analog-starter-kit) | Analog Starter Kit | 81.38 |
| [Verve](https://www.vervecoffee.com/products/streetlevel) | Streetlevel coffee | 27.00 |
| [Hario](https://www.hario-usa.com/products/v60-plastic-coffee-dripper-02) | V60 plastic dripper, white, size 02 | 24.12 |
| [Death Wish Coffee](https://www.deathwishcoffee.com/products/death-wish-coffee) | Dark roast, whole bean, 1 lb | 32.46 |
| [theory11](https://store.theory11.com/products/monarchs) | Monarchs playing cards, one deck | 21.59 |

These are observed quotes for synthetic US delivery details, not advertised
prices or promises about future tax, shipping, inventory or authorization.
All ten real merchants use Shopify; this is merchant and checkout-layout
coverage, not ten independent processors. Hario and theory11 exercise separate
information, shipping and payment steps. Simply On Purpose needs no shipping.

The test driver invoked the same CLI VFS actions available to a shopper:
open, snapshot, click, type and select. It selected variants, added products,
confirmed the cart, entered synthetic details, selected card payment, and
requested preparation with a deliberately nonexistent card ID. The resulting
`failed_before_release` is expected: Broker cannot release a nonexistent card.
A populated history total with no preparation refusal establishes that card
discovery completed before Broker rejected the card. It does not mean an
approval or payment happened. No approval was bypassed.

Initial quotes with blank shipping-choice labels were excluded and rerun.
For example, Ugmonk first displayed $69.00 before its rates loaded; its final
tested quote was $81.38. Death Wish first displayed $21.71 with shipping still
pending; its completed quote was $32.46. AeroPress was rerun after selecting
the option to use its completed shipping details as billing details.

The run used a reserved example email domain, a clearly synthetic buyer name,
a sample San Francisco address and a reserved fictional US phone number.
No personal saved traveler record or live card was used. Storefront bot checks
were not bypassed. Ridge was blocked by Cloudflare. Fellow's initially
selected region/variants were unavailable; Native Union and Counter Culture
did not complete through the first cart path attempted. Those attempts are
not counted as completed checkouts or claimed fixed.

Changes verified during this run:

- A contact-only block explicitly identifying newsletter or SMS marketing is
  excluded from payment-button selection. Its recurring marketing consent is
  also excluded from charge terms. The actual Death Wish checkout now reads
  as a one-time payment, with four receiving card frames; a separate live
  discovery and recheck passed.
- A non-submit subscription upgrade button outside a uniquely identified
  card form no longer competes with that form's final submit button. Priced
  offers and explicit payment controls retain ambiguity protection. A live
  Stumptown discovery and recheck passed with `recurring=false`.
- Repeated native submit buttons count as one action only when their form,
  destination, method, name/value payload, normalized label and inline handler
  agree. Different payloads, destinations and script buttons remain refused.
  This fixes Hario's two equivalent final payment buttons.
- Stripe's repeated prices are accepted only when every visible amount and
  currency agrees with the bound processor facts. Equal digits with different
  currencies and conflicting prices are refused. Its real public sandbox
  discovery and recheck passed at the localized quote MDL 372.73. A sandbox
  payment with a test card also completed. A test decline was detected, and a
  separate successful 3-D Secure test completed its simulated bank challenge.
  No real funds moved.
- VFS shopping guidance now covers variant state, asynchronous cart updates,
  incomplete shipping quotes, billing details and history semantics. A history
  total can belong to a failed request and is not itself proof of approval.

Validation at runtime commit `023b38134cec57743f79678560e980f57f4f5e53`:

- `cargo test -p bloom-checkout --lib`: 96 passed, 8 opt-in tests ignored.
- The marketing/payment-control regression exercises 19 acceptance/refusal
  scenarios, including actual fixture submission and a changed form before
  submission. The repeated Stripe price regression exercises five cases.
- Live Stripe sandbox discovery, successful test payment, declined test card,
  successful 3-D Secure test, Stumptown discovery/recheck and Death Wish
  discovery/recheck passed.
- `cargo test -p bloom-vfs --lib root_agent_guidance_files_are_identical_to_markdown_source`
  passed. The updated guide was also read through the running VFS.
- `git diff --check` passed.

The isolated triad used ports 28810/28811 and root `/tmp/bc1027/root`;
installed custody on 18734 was untouched. Broker was
`4dd1b58b7217cdcb0a1238c5ee70febbc1cf95a4`, Signer was
`b898d03712309ec1cc5f9027275ba1b6d28b6e53`. Checkout binary SHA-256:
`a7322a659bcb7331439291e08b3c29eb16a44dcd9e4b6810e27815b2aba645c5`.
The machine and checkout were built from the owned candidate checkout; this
was a development installation, not an installed release test.
Final Machine binary SHA-256 after the VFS documentation update:
`f03b8b10ec46da63c1ebbed2e673b86eb8f8570a973f0623dac14c87d224ff50`.

Public snapshots, the VFS driver and operation traces are retained under
`/tmp/bc1027`. A sanitized result ledger and resume notes are linked from
`shared/checkout-takeover-2026-10-27.md` in the development workspace.
No checkout-session URLs or private-view capabilities are published here.

## Full service test and recovery follow-up

At `4af81c33`, `scripts/test-card-checkout.mjs` passed against real Machine,
Broker and Signer services with a software passkey. It enrolled a synthetic
card through custody, approved sealed card release and completed a real Stripe
**test** payment. It also verified manual fallback without card release,
reopening a closed approved private tab, returning an authenticated page after
takeover, one submission using a shop-saved payment method, and custody-backed
card deletion. Ports were 28820/28821. Broker and Signer revisions were the
development revisions recorded above; this was not a release installation or
an OS-principal isolation test.

Private bootstrap URLs are one-use; their values no longer double as session
cookies. A separate random HttpOnly cookie lets the same browser reopen the
approved view through the safe `view_url` in request status. Replaying a used
bootstrap or forging a cookie from it is rejected.

Recovery regressions also cover interrupted human payment remaining uncertain
after restart, stale pause flags clearing on a fresh browser, retrying cleanup
after confirmed pre-release cancellation, and partial browser-context disposal.
A real subprocess test kills checkout's own Chromium and requires checkout to
exit unsuccessfully, allowing the installed service manager to restart it.

Live bank authorization and live merchant settlement remain untested. A test
payment cannot prove that a bank will approve a live purchase. Release builds,
macOS conformance and inherited dependency-pin failures are separate gates.
Nothing was merged.
