# Shopping checkout acceptance, 2026-10-27

Eleven different merchants reached their final card checkout through Bloom's
normal `checkout/browse` VFS. Each accepted synthetic contact and billing
details, resolved shipping where applicable, exposed its payment control and
reviewed Shopify or Stripe card fields, and passed saved-card payment discovery.
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
| [Offerman Woodshop](https://offermanwoodshop.com/store/) | Good Clean Fun, autographed book | 51.23 |

These are observed quotes for synthetic US delivery details, not advertised
prices or promises about future tax, shipping, inventory or authorization.
The first ten merchants use Shopify; Offerman uses WooCommerce with Stripe
secure fields. This is merchant and checkout-layout coverage across two
platforms, not eleven independent processors. Hario and theory11 exercise separate
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
credentials. A second follow-up at `679146b3` replaces the session cookie:
a real two-server Chromium test demonstrated that a localhost cookie is also
sent to other localhost ports. The independent session key now stays in the
human browser's localStorage for the checkout's exact origin and is sent only
in explicit Authorization headers. Screenshots use authenticated fetches.
Another local app receives neither the key nor an authentication cookie.
The safe `view_url` reopens the view in the browser that claimed it. Used
bootstrap replay, cookie-only access and cross-origin mutations are refused.
The private UI retries failed reads after temporary outages and hides its
controls while its image is unavailable; it never retries payment actions.

Recovery regressions also cover interrupted human payment remaining uncertain
after restart, stale pause flags clearing on a fresh browser, retrying cleanup
after confirmed pre-release cancellation, and partial browser-context disposal.
A real subprocess test kills checkout's own Chromium, requires checkout to
exit unsuccessfully, then starts it against the same state and socket. Shopping
works in a fresh browser; the recorded booking survives and its pause clears.
Failed private-browser cleanup also requests supervised restart instead of
leaving shopping permanently paused. This never retries a payment.

Live bank authorization and live merchant settlement remain untested. A test
payment cannot prove that a bank will approve a live purchase. Release builds,
macOS conformance and inherited dependency-pin failures are separate gates.
Nothing was merged.

The existing protocol migration from Bloom #378 is incorporated in this
candidate. Machine speaks Broker API1.8, and every build/release/workflow pin
now names Broker `88604d308412bea3876533adc80904223d334bf2` and Signer
`74e097a566f1bd08f5f43a7e847d3958b6386a3a`. Migration tests use frozen schema-1
JSON instead of compiling an obsolete Broker/runtime dependency. The pin audit
now fails only because the two dependencies have not landed; its inconsistent
revision findings are resolved. No merge or approval requirement was waived.

Baseline runtime verification at `679146b36791450761b4959406b4bf2ae1d92cc4`,
with those exact Broker/Signer revisions:

- All seven real-service checks passed: custody card enrollment, isolation
  from another HTTP localhost app, manual fallback and lost-tab recovery,
  sealed card release and a real Stripe TEST payment, authenticated takeover
  handback, exactly one shop-saved payment submission, and custody deletion.
  The local app received neither private authentication cookies nor an
  Authorization header and could not read the checkout's origin storage.
- Checkout library98 passed (8 opt-in tests ignored); Machine client70,
  protocol182, Solana transactions20, transactions183 (1 ignored), VFS439.
- Linux packaging55 passed (16 macOS tests excluded, as in Linux CI).
  The real browser-death subprocess test also passed under nextest.
- All four public Stripe Elements TEST cases passed: success, card decline,
  successful simulated bank challenge and failed simulated bank challenge.
  The real public test backend explicitly returned `livemode=false`.
- Strict Clippy across affected packages, final VFS source embedding and
  JavaScript syntax checks passed. A real UI regression also verifies read
  reconnection after a temporary server failure and closed-view controls.

The final developer triad used ports28820/28821 and root
`/tmp/checkout-1027-public/origin-triad`; its recorded launcher was stopped
after card deletion. Installed custody on18734 was untouched. Sanitized
results, logs and executable SHA-256 values are retained in the workspace's
`shared/checkout-1027-evidence/full-service-verification.json` and adjacent
artifacts. These are developer-service tests with a software passkey; they
do not replace installed OS-principal conformance.

That baseline's [three-platform release dry run](https://github.com/bloom-directory/bloom/actions/runs/40619324801)
and [single-Mac conformance](https://github.com/bloom-directory/bloom/actions/runs/40619330497)
passed with the explicit sibling revisions above, including installed W0.

## Further shopping and flight use

Runtime `7f67e430` passed all seven real-service checks again. Failed browser
cleanup now enters the existing supervised restart path, preserving the known
payment result instead of leaving shopping permanently paused. A real process
test verifies restart on the same state and socket with the booking intact.

A further real VFS journey selected Aerolíneas COR–AEP, one adult, one-way on
31 October 2026, at the displayed final fare ARS120,484.95. Search, airport
suggestions, calendar and fare selection worked. The early Comprar button
required the existing private take-over; its approval bought nothing. The
synthetic person advanced the fare and baggage warning through the protected
image/click view, then returned control on the passenger form.

Real Broker/Signer ceremonies saved and unlocked a synthetic traveler. The
passenger form filled ten categories privately. This found and fixed two
defects at `6da48d5f`:

- US phone formatting uses hyphens as well as spaces. The former split treated
  the full national number as its area code and produced an empty local number.
  US, UK, Australian and Argentine regressions now verify both parts. The real
  airline accepted the corrected split fields. Choosing its calling-code
  selector first avoids the site's subsequent clearing of the number.
- Custom date/country selectors displayed saved values beside emptied inputs;
  radio checked-state also revealed the selected saved gender. The smallest
  rendered choice wrappers and radio groups are now masked in labels, context
  and selection state. Their page text uses the masked control projection.
  A realistic regression preserves public fare controls with identical digits.
  The repeated real airline snapshot contained none of the synthetic saved
  names, document, email, month/country labels or years.

After the passenger form passed its field checks, the airline redirected to
`/checkout-error`: “No pudimos validar la verificación de seguridad.” This
flight is **not** counted as a completed checkout. No security challenge was
bypassed, ticket ordered or live payment attempted. Both runs deleted the
synthetic card and traveler through custody. Checkout's browser used normal
TLS validation and its sandbox. The earlier strict-TLS Stripe TEST3DS2 run also passed
its enrollment, protected bank challenge and custody deletion checks.

Mac run40633928931 exposed a catalog timeout while serializing its huge AX
outline. Runtime `7fd3ca5aaf73af7b321b182a53eefb01a57e23cf` skips that work
when the document already exceeds the 30,000-character public text budget.
The bounded control projection stays usable; reply-size protection remains.
Its real large-catalog test passed in1.65 seconds locally, all99 checkout
library tests passed (8 opt-in exclusions), and subprocess recovery, strict
Clippy and VFS source embedding passed.

All seven real-service acceptance checks passed again at this final runtime,
using a fresh developer triad and the exact sibling revisions above. The
local synthetic merchant fixtures need the developer TLS exception; they do
not replace strict-TLS or installed-principal verification. The
[release dry run](https://github.com/bloom-directory/bloom/actions/runs/40636365930)
and [Mac conformance](https://github.com/bloom-directory/bloom/actions/runs/40636370662)
passed, including installed W0 isolation. The required two-login macOS runner
and active GUI-login inputs remain unavailable; runner inventory returned403.
Unlanded dependencies, independent review and specific merge approval remain
separate gates. This evidence does not establish universal merchant support
or live-bank authorization.

## WooCommerce follow-up

Runtime `553c5e4891143177bba5f040f227fa3c781ca7ae` also completed Offerman
Woodshop preparation at USD51.23 through the normal VFS, with Chromium's
sandbox and normal TLS validation. Media Mail was selected at $7.13; the $44.10
subtotal included $4.10 tax. The three card fields were served by `js.stripe.com`.
After the fix, history recorded 5123/USD with no preparation refusal before
Broker rejected the deliberately nonexistent card. No card was entered or
order submitted. This is the eleventh completed merchant preparation.

The first attempt exposed another newsletter collision. A text field used as
a bot trap made the newsletter block appear to contain a customer field. A
normal Chromium diagnostic confirmed that it was entirely offscreen, removed
from keyboard navigation and inside an `aria-hidden` block. The classifier now
ignores only that combination for non-private text fields. Visible, focusable,
assistively accessible, card-like and password fields preserve ambiguity.
Making the trap visible after preparation also refuses submission without a
second click. The payment-control regression now covers 25 scenarios. All 99
checkout tests, real process recovery and strict Clippy passed.

The earlier `7fd3ca5a` runtime additionally passed all four real public Stripe
Elements TEST cases and a fresh strict-TLS bank challenge through the protected
image/click view, including custody deletion. Its three-platform release dry
run passed and its Mac candidate passed all checkout/browser/crash checks.
Its installed isolation checks also passed.

The final runtime's seven real-service checks also passed, including an actual
Stripe TEST payment, exactly-once site-saved submission and custody deletion.
The final [release dry run](https://github.com/bloom-directory/bloom/actions/runs/40639701386)
passed on all three platforms, and its Mac candidate passed the full
checkout/browser/crash suite. See the
[Mac conformance record](https://github.com/bloom-directory/bloom/actions/runs/40639706432)
for its installed-isolation result. The two-login runner, unlanded dependencies
and independent review remain separate gates; nothing has been merged or
production-published.

Take-over preserves the current site session. Closing a card or site-payment
checkout discards its cookies and storage, so another purchase may require a
new login. The VFS guide now states that limit rather than promising one login
per site indefinitely. The existing real-browser session-disposal regression
passed in the99-test suite.

## Private input follow-up, 2026-10-28

A real Chromium regression found that a field labelled Card number without
`autocomplete` was masked in snapshots but accepted ordinary shopping typing.
Runtime `31c58316acbaec025e331534efb0a00b525248d3` makes typing use the same
live private-input classifier as the snapshot. Eleven rejection cases cover
names, accessible/slotted labels, numeric placeholders, passwords, autocomplete
and fields changing on focus. No value is inserted in those cases. The existing
payment-word guard and native selection behavior remain intact.

All100 checkout library tests passed (8 opt-in exclusions), as did strict
Clippy. All seven real Machine/Broker/Signer acceptance checks passed again:
the stronger public typing guard permits normal contact entry and the approved
sealed-card path still completes an actual Stripe TEST payment, then deletes
the synthetic card through custody. The corrected session-lifetime guide was
also read back byte-for-byte through the running VFS.

Runtime553 completed its full installed Mac conformance successfully. The
guarded runtime's [three-platform release run](https://github.com/bloom-directory/bloom/actions/runs/40678447250)
passed. Its [Mac conformance](https://github.com/bloom-directory/bloom/actions/runs/40678454797)
passed the candidate tests, then reached the sixty-minute job limit while
compiling installed-test dependencies. This is incomplete installed verification.
The workflow configured a cached build directory but did not pass the existing
`BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR` option across `sudo` to the driver.
It now does, so the test suites share compiled dependencies and the cache can
be saved. Checks and the sixty-minute limit are unchanged. The previously
stated two-login infrastructure, unlanded-pin and independent-review gates remain.
