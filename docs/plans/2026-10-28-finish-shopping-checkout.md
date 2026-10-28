# Finish shopping checkout

## Outcome and limits

A person can select goods or a matching flight through Bloom, review a final
quote, approve privately, and understand the result or safely recover from a
block. The agent must not receive private inputs or guess whether to buy again.

This is a plan, not a declaration of readiness. Continue existing Bloom #346;
do not open a competing PR. Preserve the established custody and approval flow.
Do not require universal merchant support: make the supported experience useful
and state observed limits. No live order or charge is authorized by this plan.

Evidence: [shopping acceptance and lessons](../reviews/2026-10-27-shopping-checkouts.md),
[VFS operator guide](../../crates/bloom-vfs/src/docs/checkout.md), and
[real-service test instructions](../../TESTING.md#shopping-through-the-real-triad).
The workspace's `shared/checkout-1027-evidence/full-service-verification.json`
holds revision-bound results; it needs refreshing before final acceptance.

## Established baseline

Execution update: diagnostics and dropdown recovery are implemented and pushed
on existing #346 (`50b38c92`, `88155b68`, `734e430b`, `e115804e`). The final runtime passed
100 library tests, strict checkout/API Clippy, 12 docs tests, browser-death
recovery and eight real-service checks. Mounted guide bytes match the source. Card selectors without autocomplete now
use the same private-field guard as typing; a failing browser regression proves
the gap and twelve rejection cases verify the fix. A separate strict-TLS
real-service bank challenge passed; no live funds moved.
Additional recurring and non-Shopify journeys, including their limits, are
recorded in the [acceptance report](../reviews/2026-10-27-shopping-checkouts.md#finish-plan-implementation-2026-10-28).
Flight and live-trial readiness remain unverified. Do not mark this plan complete:
the new release/installed runs, two-login infrastructure, independent reviews,
landed dependencies and explicit merge approvals remain outstanding. The old
corrected Mac run has now passed, including cache persistence and all eleven
digest-bound installed criteria. It does not verify the new runtime.

- Eleven merchants reached final preparation: ten Shopify, one WooCommerce/
  Stripe. Shipping, billing and final quotes were checked; no live order was
  submitted. A nonexistent-card refusal after discovery is preparation evidence,
  not proof of approval, submission or authorization.
- Separate real Machine/Broker/Signer tests passed seven custody, private-view,
  sealed-release, site-saved-payment and cleanup checks. Public Stripe TEST
  success, decline and simulated bank challenges have been exercised.
- Runtime `31c58316acbaec025e331534efb0a00b525248d3` passed 100 checkout library
  tests, strict Clippy and the seven-service checks. Eight opt-in exclusions
  are not passes. Browser death and private-input mutation regressions passed.
- The Aerolíneas journey validated private passenger entry but ended at a
  merchant security rejection. It does not establish flight payment readiness.
- The guarded runtime's three-platform release build passed. Its first installed
  Mac run timed out during compilation. Workflow `8d9b1385` forwards the existing
  shared build-directory option through sudo; corrected run40689432767 was still
  active at this investigation. Its candidate passed; installed proof is pending.
- Two-login Mac evidence, landed dependency pins and independent review remain
  outstanding. Master conflicts must be resolved with explicit merge approval.

## 1. Make refusals actionable

Inspect the path from `facts.js` through `discovery.rs` and `service.rs` to
`bloom-checkout-api::Status`, Machine and VFS history. Script-owned refusals
currently reach logs, while different failures collapse to `facts_unreadable`.
Its API comment still describes only total/currency; reconcile that wording.

Expose only the smallest useful set of constant, safe diagnostics: payment
action ambiguity, unreadable/conflicting price or terms, unsupported fields,
and unreviewed receiver. Keep existing broad reasons where compatibility needs
them. Check strict deserializers and persisted records before choosing whether
to refine the reason or add an optional detail. Do not change the approval
protocol, add merchant-text errors or create a general diagnostic framework.

For every new diagnostic, verify a real browser fixture produces the expected
public result without values, capabilities or a submit click. Keep conflicting
amounts/currencies, genuine subscription actions, changed forms and unreviewed
card hosts refused. Update the VFS recovery instruction beside the code change.

Done: an operator can distinguish an incomplete page from an ambiguous charge
without reading server logs or trying competing payment buttons.

## 2. Broaden actual shopping, driven by differences

Use the normal Bloom VFS on an isolated real triad, with normal TLS and browser
sandboxing. Select public merchants by checkout implementation, not by an
arbitrary additional shop count. Inspect what they actually use before counting
a different storefront as new platform coverage.

Prioritize another non-Shopify card integration, then a materially different
processor flow such as Braintree or Adyen if reachable through ordinary shopping.
Existing reviewed origins are not evidence that those flows work. Also exercise
an ordinary recurring purchase, including trial/renewal disclosure, because
marketing Subscribe must remain distinct from a genuine subscription charge.

For each journey, record dated product/variant, quantity, frequency, destination
category, named shipping, billing completion, final total/currency, receiving
hosts, preparation result and last completed step. Use synthetic non-secret
contact fixtures; never enter a live card or create an order to increase coverage.
Do not put personal data or private-view URLs in the public ledger.

On each reproduced defect: preserve the smallest realistic fixture, demonstrate
failure, make the narrow fix, rerun it and the affected regressions, then repeat
the actual journey. Do not add a hostname exception when form semantics solve it.
If blocked, record and hand off normally; no fingerprint spoofing, cookie import
or challenge bypass. A blocked merchant is neither a pass nor proof of a Bloom bug.

Done: each claimed integration has evidence beyond host recognition, and
unreachable/unsupported paths have a clear recovery or honest limitation.

## 3. Complete an airline journey or bound the claim

Find an ordinarily accessible airline or agency through its real search flow.
Match airports, dates, local times, cabin, party, bags and final currency/price;
do not substitute a different itinerary to obtain a pass. Use custody-approved
synthetic traveler data on a disposable triad. Exercise custom selectors and
country-code/area/local phone entry through the private fill path.

Reach the actual final payment step with passenger validation complete and
demonstrate preparation. Inspect snapshots for private-value leakage. A merchant
security rejection calls for private takeover or a matching alternative seller,
not a guard exemption. Record booking references, paid status and ticket issuance
as different outcomes; no ticket or charge is authorized for this investigation.

Done: a dated matching itinerary reaches final preparation, or flight support
remains explicitly unverified with the last step and blocker documented. Do not
describe the shopping product as verified for flight checkout while this remains.

## 4. Verify the resulting service combination

After behavior changes, run the affected browser regressions, checkout library
suite and strict Clippy, then all seven maintained real-service acceptance checks
against exact Machine/Broker/Signer binaries. Repeat public Stripe TEST success,
decline and challenge outcomes when payment discovery/submission changes. Preserve
the strict-TLS result separately from local fixtures needing developer TLS setup.

Exercise lost-tab recovery, focus mutation, browser death during shopping and
interrupted private payment. Confirm no automatic resubmit, known outcomes survive,
uncertain outcomes still require inspection, and cleanup clears browser state.
Verify changed operator Markdown through the mounted VFS, not just the source.

Record commit IDs, binary hashes, flags, results and exclusions once per meaningful
checkpoint. Do not repeat broad tests for prose-only edits. Never treat a software
passkey developer triad as installed principal-isolation proof.

Done: all affected checks pass at the actual resulting revisions and the
acceptance report separates preparation, TEST payment and installed evidence.

## 5. Finish integration and release gates

1. Inspect the corrected Mac run's final result and completed logs when available.
   Verify installed assertions and cache save, not just candidate success. If it
   fails, diagnose the first concrete failure before another dispatch; do not
   remove assertions or simply raise timeouts. No unchanged-status polling loop.
2. Refresh remotes and assess the master conflict. Request explicit approval for
   that specific branch merge immediately before merging, as workspace AGENTS.md
   requires. Preserve checkout dependencies when resolving the known Cargo.lock
   overlap; do not rebase a head with downstream consumers or force-push it.
3. Complete dependency work bottom-up. Broker #95 and Signer #65 need their own
   reviews and specific merge approvals; replace development pins with landed
   full commits everywhere required by the workspace pin checklist. Reassess
   after fetching: old PR states and old test results are not current evidence.
4. Run required Linux release and both macOS conformance workflows against the
   exact resulting compatibility revisions. Two-login testing needs the labeled
   disposable runner and two actual active GUI identities. Existing runner API403
   is an infrastructure access blocker, not permission to fabricate users or
   weaken the test. Obtain that environment through an authorized operator.
5. Retain revision/digest-bound installed subjects and criteria, run the workspace
   pin and readiness helpers, and obtain independent review. Push checkpoints
   through the existing PR owner helper. No merge is authorized by green checks.

Done: current published revisions satisfy checks and required review, pins name
landed dependencies, conflicts are resolved with permission, and installed
evidence covers the shipped combination. Production publication and each merge
still need their applicable explicit authorization.

## Final product acceptance

A fresh operator can follow the mounted guide to choose a product, verify the
cart and final quote, request private approval, recover a lost view, and read
the outcome without repeating a purchase. The tested integrations and limits
are stated plainly. Every refusal directs the person toward a useful next step.

Publish one concise evidence summary with links to the detailed ledger and
revision-bound service/install results. Remove stale readiness claims; retain
older results as dated evidence. Live bank approval remains a separate,
unperformed test. Do not promise that merely supplying a card guarantees success.
