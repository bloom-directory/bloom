# Generic session specification follow-up and re-review request

Please re-review the updated [generic EVM and SVM session specification](../specs/2026-10-26-generic-evm-svm-sessions.md), especially sections 2, 4, 9, 10 and G03/G04/G10–G12. This began as a documentation-only design review. The owner authorized implementation on 2026-10-27; the candidate now includes implementation work across the existing successor PRs and a separate structural-only Signer change. No deployment is implied.

The agreed product remains a Broker-owned cross-token USD budget, trusted Petal claims by default, Broker-controlled prices, native EVM/SVM and Petal actions, and today's approval flow when automatic admission is unavailable. Signer keeps structural authority without economic accounting.

## Follow-up safeguards now specified

1. **Native scope binding:** Prepare and every admission recompute the persisted member-scope digest. G11 rejects a changed recipient list or raw cap even after a successful prepare. Existing recipient/policy intersection and one-transfer rules remain.
2. **BUY check dispatch:** Add a small Broker-owned provenance/class binding alongside the compiled assurance registry. It requires the existing BUY witness helper, independently of a Machine template flag. Its mapping and compiled check identities are review-bound; missing or changed requirements refuse automatic use. G03 covers omission/downgrade. This is data-driven dispatch, not a protocol-name branch in generic admission or a new plugin system.
3. **BUY limits and assets:** Automatic BUY is explicitly single-order/single-payload. Exact-path batch summation remains. Normalize the independently reconstructed asset and claim through the same approved mapping; the literal `pusd` label cannot create another accounting identity.
4. **Counter allocation:** At prepare and use, projected Signer limits must exactly equal descriptor allocations. Reject pool operation/signature ceilings below the member count. Existing counters enforce the fixed allocations without a shared Signer ledger.
5. **Decision and fee scope:** Rename the proposed amendment D-065, following the triad log's D-040–D-064 sequence. Its previous GS001 label is retained only for traceability. Assets absent from permitted scope, including fee assets, remain denied.
6. **Audit binding:** Extend the existing `reservation.created` event with `budget_id` and `valuation_record_digest`. The canonical record includes accepted time, quantities, quotes/policy, rounding and charged USD. Admission/recovery verifies its digest. Reuse current transaction/checkpoint handling; no new audit infrastructure or counter-status RPC.
7. **Undefined ownership field:** Remove `authority_owner_id` from the descriptor. Use existing authenticated journal/edge identity continuity checks. Independent writable Broker journals remain unsupported, without inventing a distributed owner detector.

## Accepted simplifications

- Use three fixed profile disclosures instead of a general field-level assurance engine. Preserve existing stronger policy/verifier contracts.
- Drop the generic execution-domain object and universal purpose taxonomy. Reuse current debits/fees; add purpose labels only where a profile needs extra cost lines.
- For each selected provider, use its published upper bound when present, otherwise its trusted point price. No bound-combination machinery.
- Onboarding now emits fixed raw-unit caps by default for listed priced assets, reusing the compiler model. Petal caps remain optional on the wire; native caps stay mandatory. Later quotes do not raise them. This addresses oracle underquotes for honest declarations without pretending to validate the initial quote or contain dishonest Petals.

## Confirmed scope reduction

The owner has confirmed deferral of Broker-verified SPL transfers. The first release covers native SOL plus EVM native/ERC-20; generic trusted SVM Petals can still declare priced mint spending under approved scope and price mappings. This removes native SPL parsing, token-account ownership/extension verification and token-account setup from the release without removing the generic trusted-Petal path. G01 tests that distinction, and G11 ensures SPL cannot silently enter the native SOL profile.

## Remaining boundaries

The successor PRs remain intentional: #100 → #112, #352 → #377 and #19 → #26; #68's economic Signer design stays superseded. Rollback protection reuses existing witnesses and does not promise detection after every witness is restored together. pUSD pricing is still a real coverage gate; no implicit peg or automatic SELL valuation was added.

Please check the mandatory BUY binding cannot be omitted or downgraded, canonical asset mapping preserves its independent check, allocation equality is tested, and the named audit event binds time as well as USD usage. Separate any remaining essential safety correction from an optional expansion. We want to keep two small keyless pricing adapters with fixed ordered fallback, existing approval APIs plus pool stop, narrow native profiles, and a minimal structural Signer change.

## Existing work reviewed on October 27

Section 12 now maps Kyle's existing Broker work to reuse. #103 is already in #112 and supplies the compiled token metadata/review paths, Hyperliquid use-time witness pattern, and structural Solana/Pump readers. Preserve existing mandatory profile checks; those readers are neither a price feed nor full reusable SPL state verification. Open #113 fixes Petal-destination versus native-recipient wording; open #88 keeps status readable under degradation.

Do not resurrect Broker #74: its closure explains that existing `operation_status` already provides completed results. Reconcile Machine #329's caller recovery and unknown-outcome semantics with the persona journal instead. Also include open Signer #62 or prove equivalent behavior on the release candidate: partial-batch/post-signature failures must report ambiguity so Broker does not release their capacity. Broker's quarantine handling already exists. G07 now names that boundary test; G13 includes real stop/ceremony cleanup and degraded-status coverage. These are reuse/correctness requirements, not a new recovery service or a return to Signer-owned budgets.

## Owner-selected pricing policy, October 27

Section 7 now selects keyless CoinGecko first and keyless DefiLlama only when the primary cannot supply an acceptable quote. Both use provider timestamps, with a maximum age of 15 minutes rechecked at reservation. No API keys, pricing proxy, quote averaging or cheapest-price selection. Fallback may select different providers for different assets, recorded individually in the immutable valuation. If neither provider supplies a valid price, retain today's approval path. G05 covers provider order/failure, cache isolation, age boundaries and bounded calls. This adds a second small HTTP adapter and fixed fallback dispatch; multi-provider consensus and disagreement machinery remain deferred. Please re-review section 7 and G05 against this owner decision.

## Implementation candidate review — October 27

Machine now binds generic effects to exact EVM/SVM accounts, compiles explicit
member/asset selections into one reviewed USD pool, preserves price-denial exact
fallback and frozen retries, and fences pool stop before member revocation.
Manifest effects-v1 opt-in is installer-certified; old immutable packages stay
ineligible. Native supported transfer projections retain System identity.

Local evidence includes the two unrelated EVM/SVM Petal public-adapter test,
fixed-cap arithmetic, interrupted full-pool staging, generic host/account
binding, durable missing-price fallback, native transfer projection negatives,
the manifest opt-in test, and existing Machine/Petal/native suites. These are
repository checks; they do not substitute for the authenticated triad and
installed release gates in the full specification.

Review the final immutable service pins and compatible SDK/Petal artifacts as
part of integration. Publishing/adopting the new immutable Polymarket artifact,
physical-passkey rehearsal and installed Linux/macOS conformance remain release
steps. The currently pinned old package is deliberately not relabeled effects-v1.

Candidate integration pins: Broker `3157b1f25876905b54a70ee6cdf678db60daa088`
(API 1.10), Signer `70a698fb0b122394070c6c2089422fc1461c159f` (API 1.8).
Machine Cargo, lockfile, compatibility matrix and conformance workflows select
these exact commits. Existing ordinary Petal SDK opaque claim transport is
reused; participating packages explicitly certify effects schema v1.

The broad workspace check also exposed two inherited compatibility failures.
The macOS launch-agent assertion now follows the existing user-domain sentinel
and checks GUI availability separately. Exact paid HTTP EIP-712 signatures
retain their existing installer-certified System owner-approval path; the
Petal-only review envelope requirement still applies to arbitrary Petal
messages. Neither change makes opaque System signing eligible for USD sessions.

Earlier candidate validation recorded 2,106 workspace checks with 13
service/artifact-dependent ignores, including 69 release metadata/authority
checks and 93 Machine client cases. That historical run predates the subsequent
local integration fixes; it is not a full-workspace rerun at the pins above.

Local wallet creation now offers **Continue setup** when persona preferences
have not been saved. Machine starts the existing expiring loopback bridge and
carries its connection in the registration URL fragment. The wallet page keeps
it in tab-scoped storage; Broker and Signer receive no new authority or API.
The picker preselects the created wallet and retains its existing authenticated
wallet-discovery and approval checks. Hosted ceremony links are unchanged.

The continuation change passed all 136 Machine CLI tests (2 ignores), including
a live origin-bound bridge regression, Broker's wallet-button and wizard Node
regressions, the focused release compatibility check, and both service builds.
Strict Machine Clippy encounters the pre-existing `result_large_err` warning
on `require_existing_wallet`; with that one lint allowed, it passes. Git fixture
checks ran with signing/editor settings overridden only for the test process.
These checks do not replace physical-passkey walkthrough or installed
principal-isolation conformance before release.
