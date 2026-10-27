# Generic EVM/SVM sessions — key decisions

Key decisions · 27 October 2026 · Owner-authorized implementation candidate; not deployed.

## Goal and ownership

An owner approves reusable authority for selected accounts, networks, actions and Petals. Those approvals share one cross-token USD spending budget, including across EVM and SVM accounts within one wallet and one authoritative Broker journal.

- **Broker owns all economics:** asset identity, prices, spending limits, reservations, shared usage and recovery.
- **Signer retains custody and structural authority:** exact keys, approved subjects/classes, signature/operation/rate limits, expiry, revocation and replay. No prices, token amounts or budget ledger in Signer.
- **Machine executes Petals and constructs/submits transactions.** Petals declare their economic effects; Broker decides admission.

Reuse existing **Petal Sealed Approvals**, approval ceremonies and status APIs. Each member is an existing approval bound to the same reviewed budget descriptor. Native transfers use an explicit System identity through the same lifecycle; they do not impersonate a Petal. This needs a minimal structural System selector in Signer.

## Trust boundary

By default, trust the approved immutable Petal and Machine to report complete outflows, costs and continuing permissions. Broker does not need a protocol decoder for every Petal.

**A USD budget enforced against trusted claims does not independently contain a dishonest Petal/Machine.** Signer backstops limit signature volume and duration, not dollars; a compromised Broker is outside the economic protection boundary. Disclose these limits during review.

Preserve stronger existing checks. In particular, Polymarket BUY must retain Broker's signed-order/debit verification; Machine cannot omit its evidence or choose the generic path to bypass it. Native transfer profiles independently check their supported transaction bytes and scope.

## Spending semantics

- Charge **gross authorized outflows plus maximum wallet-paid costs**, including network fees and supported account-creation funding. Incoming funds and swap outputs do not replenish the budget.
- Enforce per-action, lifetime and reviewed rolling-window USD limits atomically across members. Use integer microdollars, exact conversion and upward rounding.
- Asset identity is network plus native/contract/mint identity, never ticker alone. Use approved metadata for decimals. Explicitly allowlist spending and fee assets.
- Native transfers require reviewed recipient allowlists and fixed per-action raw-token ceilings, checked at prepare and use. Petal targets remain declared destinations, not independently verified recipients.
- Onboarding suggests fixed raw-token caps for all priced assets using the review quote. Native caps are mandatory; Petal caps are optional on the wire. Later prices cannot raise these caps automatically.
- New members, packages, wider scope or changed pricing policy require fresh owner review.

## Pricing — selected policy

**Keyless CoinGecko first; keyless DefiLlama as fallback. Maximum quote age: 15 minutes.** No API keys or pricing proxy.

Broker fetches prices using approved chain/address/mint mappings. CoinGecko uses token/native price endpoints and `last_updated_at`; DefiLlama uses current prices and `timestamp`. The provider timestamp determines freshness, rechecked at reservation; fetching or caching never refreshes its age.

Use a valid cached primary quote or fetch it. If unavailable, unsupported, stale, invalid or throttled, try the fallback. Different assets may use different providers; record the selected source and quote for each. Do not average quotes or choose whichever is cheaper. Cache/coalesce requests and respect provider limits. Bound external calls.

Charge `ceil(raw amount × USD price per token × 1,000,000 / 10^decimals)`. Store the accepted valuation with the reservation; retries do not reprice it. The cap measures authorization-time value, not execution-time value or portfolio loss. Prices may lag the market by up to 15 minutes.

**If neither provider supplies an acceptable price, use today's owner-approval flow.** No implicit $1 stablecoin peg, zero-price fallback or unpriced automatic exception. Price pUSD as its distinct asset.

## Initial release and deferrals

Ship the common Petal effects contract and Broker budget/pricing engine first, adapt Polymarket as a reference, then complete native coverage before the general release:

- Generic trusted Petals on EVM and SVM, including declared SVM token spending.
- Native EVM currency/ERC-20 transfers and native SOL transfers, restricted to supported single-transfer formats.
- Polymarket automatic BUY with its existing verifier; SELL retains today's exact approval behavior.

Defer native SPL verification, automatic Polymarket SELL valuation, complex native batches, multi-member co-signing, continuing financial permissions, dynamic asset universes and provider consensus. Allowances, permits, delegates and other continuing authority require separate approval. Unsupported actions retain today's approval path.

## Lifecycle and recovery

Reserve shared capacity durably **before signing**. Reserved, committed and ambiguous operations consume capacity. Release only with authoritative evidence that no usable signature was produced. Canceled, unsubmitted, expired or reverted signed actions remain charged.

Reuse existing operation status, journal and authenticated audit/checkpoint mechanisms. Bind budget identity, quantities, valuation and reservation time into the audit event. Restore/conflict uncertainty fences automatic admission; simultaneous rollback of all witnesses is not promised detectable.

Stop fences the entire pool atomically before revoking members, reconciles in-flight operations and ends owner ceremonies. Already produced signatures are not undone. Signer post-signature failures must preserve ambiguity rather than cause Broker to release capacity.

## Existing PRs: reuse versus change

| Work | Keep | Change |
| --- | --- | --- |
| [Broker #100 → #112](https://github.com/bloom-directory/bloom-broker/pull/112) | Shared ledger, reservations, approvals, EVM verifier, recovery | Generic claims/scope, real USD pricing, two keyless adapters and shared review-bound budget |
| [Bloom #352 → #377](https://github.com/bloom-directory/bloom/pull/377) | Persona UI, onboarding, durable retries and stop; clear-signing foundation | Capability-driven accounts/Petals, generic effects, shared budget and native integration |
| [Polymarket #19 → #26](https://github.com/bloom-directory/bloom-petal-polymarket/pull/26) | Prepared-byte reconstruction, BUY debit verification, exact review and recovery | Common effects/assets; no global Polymarket-only gate |
| [Signer #68](https://github.com/bloom-directory/bloom-signer/pull/68) | Existing approval/counter model | Economic design superseded; separate structural-only System selector |

Reuse Kyle's landed Broker #103 token catalog and review/verifier infrastructure; it supplies metadata, not prices. Reconcile existing Machine recovery work and require Signer #62's ambiguity fix or equivalent before release. Negotiate compatible API versions; retain existing wallet policy and exact approvals.

This proposes the narrow D-065 architecture amendment permitting Broker USD accounting and generic sessions. Implementation remains gated on compatible components, validated mappings/provider behavior, and tests for scope, fallback, concurrent spending, recovery and stop.
