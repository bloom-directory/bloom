# Generic EVM and SVM sessions with Broker budgets

**Status:** Implementation candidate in PRs, authorized by the owner on 2026-10-27; not deployed.
**Date:** 2026-10-26
**Updated:** 2026-10-27 after reviewing existing Broker work
**Scope:** Reusable native and Petal signing authority, shared USD accounting, pricing, approval integration, and changes to the existing draft PRs.

## 1. Product decisions

An owner can approve a bounded session for selected accounts, networks, native actions, and Petals. Every member grant draws from one Broker-owned dollar budget. Petals use existing Petal Sealed Approvals. Native actions use the same approval lifecycle with an explicit System scope. Signer owns custody and structural signature backstops; it does not interpret prices, assets, spending, or exposure.

The following decisions were selected during design:

| Decision | Required behavior |
| --- | --- |
| Default assurance | Trust the approved immutable Petal and Machine to report economic effects. Independent semantic verification is optional unless existing policy requires it. |
| Initial currency | A shared cross-token USD cap is required in the first general release. Token-unit limits alone do not satisfy this requirement. |
| Native scope | Include EVM native/ERC-20 and native SOL transfers. Defer Broker-verified SPL transfers; retain generic trusted SVM Petal token spending. Native execution must retain a System identity. |
| Price authority | Broker obtains prices through approved providers. Machine and Petals cannot choose the conversion used to debit a budget. |
| Missing or stale prices | Fall back to the current owner-approval flow. Do not create an automatic token-unit exception outside the USD cap. |

This draft chooses gross authorized spending and includes wallet-paid fees and account-creation costs in the same USD cap. This reuses the existing debit-plus-fee accounting path and avoids a second fee ledger. Receipts do not replenish a spending budget. These are proposed accounting semantics, rather than a measure of net loss or portfolio value.

Generic means that any conforming Petal can participate without a protocol decoder being added to Broker. It does not mean that every installed Petal, token, transaction format, or opaque signature automatically receives authority. Missing effects, unsupported authority semantics, incompatible services, and unavailable pricing take the ordinary approval path.

### Architecture amendment D-065

**D-065 — Broker USD session accounting** (previous draft label GS001): The owner's cross-token USD requirement explicitly replaces the no-price-feed/no-fiat restriction in section 10.3 of the July triad specification for the new generic session profile. It also replaces the BUY-only admission restriction in that document's Persona Petal extension. Ordinary token-unit approvals keep their existing meaning. The existing rule that assets absent from the approval are denied, including fee assets, remains mandatory through each pool's `permitted_asset_scope`; pricing a fee asset does not implicitly authorize it. D-065 is recorded in the consolidated architecture following owner authorization on 2026-10-27; release validation remains required and this does not imply deployment. Custody, provenance, economic ownership, and claim-assurance boundaries are unchanged.

## 2. Trust and ownership

| Component | Owns |
| --- | --- |
| Machine | Petal execution, native transaction construction, staging, simulation, dispatch, broadcast, reconciliation, preferences, and public projections. |
| Petal | Application semantics, complete economic declarations, and protocol-specific submission/recovery. |
| Broker | Approval review and policy, provenance verification, accepted claims and assurance, asset identity, approved prices, USD conversion, shared counters, reservations, journal, and budget recovery. |
| Signer | Wallet keys, approved key and structural scope, signature/operation/rate backstops, expiry, revocation, and replay. |
| Approved price provider and asset mapping | Trusted reported USD prices, timestamps and asset/unit mapping. A valid but understated price can undercharge a budget; authentication and freshness do not establish market truth. |
| Approved chain RPC | Trusted cluster/state/fee observations where required by native profiles. Independent byte parsing does not establish the truth of an RPC response. |

For the default `machine_asserted` mode, a dollar limit constrains accounting against accepted declarations. It is not independent protection against a compromised Petal or Machine: a false declaration may authorize an actual outflow larger than the charged amount. Honest pricing cannot repair dishonest quantities or omitted authority. Review and status must state this explicitly and identify the trusted package and runtime.

`proof_verified` and `invariant_attested` remain available under their existing contracts. For this release, render a fixed disclosure table for each of three profiles: generic trusted Petal (declared effects trusted), Polymarket BUY (existing signed-order/debit check required; prices and external execution still trusted), and native transfer (supported bytes/account/recipient checked; prices and RPC facts trusted as stated). Preserve any stronger existing policy. Do not build a general field-level assurance tracking or UI engine; fields outside a verifier's existing contract remain asserted.

A compromised Broker is outside the economic protection boundary in every mode. Signer's independent backstops constrain signature volume and duration, not dollar value. On-chain vault or smart-account containment is a separate project.

## 3. Release scope and sequence

Work is ordered by dependency and follows the previously proposed priorities. The first general release is the completion of P1 through P3, including USD pricing. Pricing moves forward from the earlier later-phase proposal because it is a product requirement for this release.

| Priority | Deliverable | Completion condition |
| --- | --- | --- |
| P1 | Common effects, scope, assurance, asset and pricing contracts; generic Broker accounting | A trusted Petal of any protocol can use supported signing suites and complete claims to share a real USD budget. No application-name allowlist is required. |
| P2 | Adapt Polymarket to the common contracts | BUY sessions retain their existing Broker witness check. SELL declarations, exact review, and login remain intact; automatic SELL valuation is deferred. Polymarket is a reference implementation, not a global admission gate. |
| P3 | EVM native/ERC-20 and native SOL coverage | Reactivate the existing EVM verifier with structural-only Signer scope; add trusted SVM genesis/blockhash/fee observations for native SOL. Retain single-transfer native profiles. Generic trusted SVM Petals can declare priced mint spending without a native SPL verifier. |
| P4 | Continuing permissions and broader protocol assurance | Add reviewed semantics for allowances/delegates, complex batches, account abstraction, bridges, position risk, and selected optional verifiers. Unknown/unbounded permissions continue to require ordinary approval. |
| P5 | Advanced valuation and exposure | Multiple-provider quorum/disagreement policies, dynamic asset universes, richer market liquidity rules, outstanding exposure reconciliation, and separately specified net-spend or portfolio-risk products. |

The general release may support a defined set of transaction formats and token behaviors. It must support arbitrary conforming trusted Petals within those formats. Documentation must publish that distinction and the fallback reason for unsupported cases.

## 4. Shared session descriptor

Introduce a versioned Broker-side `SessionBudgetV2`. The field names below define semantics; final edge-owned wire types belong in `bloom-broker-api`.

```text
SessionBudgetV2 {
  schema_version
  budget_nonce
  wallet_id
  policy_version, policy_digest, wallet_revocation_epoch
  member_keys[]                       // exact KeyRefs, EVM and/or Ed25519
  member_scope_digests[]              // fixed, reviewed grant templates
  accounting_mode = gross_authorized_usd
  usd_limits { per_action, lifetime, rolling_windows[] }
  operation_and_signature_limits
  member_backstop_allocations[]       // fixed per-grant count/rate limits
  optional_asset_unit_limits[]
  permitted_asset_scope
  pricing_policy_digest
  not_before_ms, expires_at_ms
}
```

Implementation wire note: the north-edge API uses an additive `SessionBudget.usd_policy` with `schema_version = 2` and complete `member_templates`, rather than a separate outer Rust type. Existing `nominal_limits`/`nominal_used` field names carry actual USD microdollars only when that reviewed v2 policy is present; older nominal profiles retain their original interpretation. Machine does not use the old nominal converter for v2 admission.

USD amounts are unsigned integer microdollars: USD 1 = 1,000,000. Asset quantities are unsigned integer base units. Floating-point arithmetic is forbidden in approval identity, pricing, conversion, and limit checks. Arithmetic overflow denies admission.

Descriptor sets use sorted unique canonical identities; duplicate member templates, keys, assets or inconsistent repeated limits are rejected. Numeric bounds and collection-size limits must be defined by the receiving API schema and checked before hashing or allocating unbounded buffers.

`budget_id` is a domain-separated hash of canonical descriptor bytes. A fresh `budget_nonce` distinguishes deliberately new authorizations with otherwise identical terms. Repeated activation reconciles the original descriptor and approval IDs instead of minting a fresh budget when an old one is exhausted.

Every member is a separate existing Sealed Approval for one exact key and structural subject/scope. The same descriptor is committed by every member. Member template digests exclude the budget commitment and issuance nonce to avoid a circular hash dependency; they include key, subject, routes/classes, provenance, suites, assurance requirements, and semantic scope. Broker rejects a grant whose template is not a listed member.

At preparation, Broker checks that every member's projected Signer operation/signature/rate limits exactly equal its descriptor allocation; repeat that equality check at use. All members require positive operation/signature allocations, so either pool ceiling below the member count is invalid. Reject the descriptor rather than silently omit members or issue a larger Signer backstop. These are checks over existing limit types, not a new counter subsystem.

The pool is scoped to one wallet and one authoritative Broker journal. Multiple accounts and chain families within that wallet can share it. This version does not aggregate unrelated wallets or independently writable Broker journals. A second Broker cannot spend from the pool without a separately designed single-writer/fencing mechanism.

There is no new `authority_owner_id` hash field. Journal ownership/continuity uses the existing authenticated Broker identity, edge manifest/history and checkpoint checks. Replacing or copying an independent journal is outside the supported single-journal deployment; this specification does not invent a separate authority-owner identity or distributed ownership detector.

Descriptor mutation, new members, changed pricing policy, wider assets, or changed assurance requires fresh owner review. Existing members cannot silently inherit a package or protocol update. Policy/revocation epoch changes invalidate use according to the current approval lifecycle.

Optional asset-unit limits are additional restrictions. They do not exempt an asset from USD pricing. The first release uses an explicit owner-approved asset allowlist; any asset with a supported identity and approved price mapping can be listed. This is an owner scope, not a global hardcoded list of supported tickers. Dynamic priced-asset universes are deferred to P5.

Native member scope additionally requires a non-empty reviewed recipient allowlist (at most 256 entries) and fixed per-action raw-unit ceilings for every outgoing asset, including the fee asset. Broker intersects recipients with current wallet policy. Reuse `SystemSessionScope.destinations`, `validate_use`, and per-asset ceiling checks already present in #100/#112; keep their economic fields in Broker. Persist these member scopes and bind their digests into the descriptor. Recompute and compare the scope digest at preparation and every admission, before pricing/reservation: changing the stored recipient list or raw ceilings must fail even if the grant was previously prepared successfully.

Onboarding emits per-action raw-unit caps by default for all listed priced assets, including trusted-Petal scopes, using the existing ceiling/compiler model. Suggest the base-unit quantity equivalent to the reviewed per-action USD limit at the review quote, rounded downward; the owner sees the fixed quantities and can customize them. Do not recompute these caps from later prices. Native caps are mandatory; trusted-Petal caps remain optional on the wire. A valid later underquote cannot bypass a present raw cap, even for an honest Petal. The tradeoff is that falling prices may require fresh review to raise a raw cap despite remaining USD capacity. This is a guard against later oracle failure, not validation of the first quote or containment of a malicious Petal that lies about quantities.

## 5. Canonical economic effects

Version the existing Petal/System claims and normalize them into the effects object below. Reuse declared debits, destinations and fees rather than introducing a parallel effects language. Keep package, route, class, suite, payload digest, ordered hashes, nonce, and exact-account bindings. Petal claims and System claims remain distinct identities but normalize into one Broker accounting representation. Add only the missing payload/network context and permission classification needed for admission; minimum-receipt/slippage engines and structured continuing-permission evaluation are not first-release requirements.

```text
EconomicEffectsV1 {
  payload_contexts[] { payload_index, network_identity, spending_accounts[] }
  outgoing[] { asset_id, maximum_amount, recipient_or_target }
  permission_effect = none | requires_separate_approval
  effect_assurance                    // existing claim + verifier contracts
}
```

Reuse existing debit/fee separation for display and normalization. Add a cost-purpose label only to profiles needing additional distinct wallet-cost lines; no universal taxonomy or execution-domain object is required for charging. Account-creation funding, where a Petal profile supports it, is charged at its maximum outgoing amount even if later recoverable. Costs already included in another line must not be counted twice. All declared outflows from member-controlled accounts are combined, even if one child uses several assets.

Keep Petal declared destinations distinct from verified transfer recipients. A Petal destination may be a router or program the transaction reaches. Reuse Broker #113's presentation distinction: native transfers can say “To”; Petal claims say “Declared destinations” and “Spend up to”. Do not apply the native recipient semantics to arbitrary Petal target lists.

For ordinary operations, the Petal supplies this declaration and Machine binds it to the actual invocation and payloads. Broker validates complete canonical shape, exact account membership, provenance, scope, fee requirements, allowed targets, assurance, quantities, and pricing. No protocol decoder is mandatory for trusted-Petal mode.

This includes SVM Petals declaring token spending by canonical mint/token-program identity, with an approved price mapping and owner-reviewed scope. Broker enforces their declared usage without verifying SPL transfer instructions or token-account ownership. Deferring native SPL verification does not disable this trusted-Petal path or represent it as independently verified. Missing prices or unsupported claims retain today's approval behavior.

A Petal batch is one admitted action with an ordered payload list, a summed worst-case debit, and a signature count equal to all signatures requested. The same accounting pipeline handles single and batch requests. Scope and budget evaluation covers every child before any child signature can be released. Partial completion remains charged conservatively. Initial native profiles retain one transfer and one signing payload per operation; this generic batch rule does not widen them. Swaps charge gross input and costs; expected or minimum outputs are not subtracted. A supported sale charges the disposed asset, not an invented collateral debit; automatic Polymarket SELL remains deferred.

An admitted operation uses one member grant and exact `KeyRef`. A pool can contain many such keys, but automatic transactions requiring several member keys to co-sign are deferred until a grouped signing identity can charge their common effects exactly once. They retain the current approval path in the first release. Each batch payload must have a complete context; no child may inherit a different child's chain or execution domain by omission.

Zero-debit actions need an explicit, owner-approved non-economic class contract. A missing debit array, unknown message, allowance, or credential-creation action must not become a free operation merely by reporting zero. Authentication remains separately scoped; credentials that permit future financial actions must describe that authority or retain their existing approval path.

Continuing permissions are not ordinary transfers. In the first release, an operation creating an allowance, permit, delegate, session key, owner change, or other continuing financial authority must declare `requires_separate_approval` and use the current owner-approval flow. P4 may introduce separately reviewed bounded-permission adapters and extend the schema. Unlimited permissions and repeatedly reusable quotas cannot be represented as a small immediate debit. This rule is a declaration obligation in trusted mode and independently checked only where the selected verifier establishes it.

Existing permissions and independently executed external actions are not retrospectively contained by this session. The UI must not claim the session budget bounds every possible wallet spend.

## 6. Asset and network identity

Broker maintains a canonical asset record keyed by network identity, asset standard, and native/contract/mint/token identifier. UI aliases such as `polygon:pusd` must resolve through a reviewed mapping; they cannot be alternate accounting identities for the same asset.

Reuse #103's compiled EVM token catalog and `TokenMetadata`/`Catalog::entry` lookup for existing chain/address bindings, decimals, names and review formatting; add only missing canonical aliases, approved price-provider mappings and SVM asset metadata. The current catalog is release-trusted metadata, not a price feed or proof of deployed token behavior. Preserve pUSD's distinct identity and neutral presentation rather than treating it as USDC. Do not recreate the retired signed-catalog publisher/key infrastructure for this feature.

| Family | Required identity |
| --- | --- |
| EVM | Chain ID plus approved network configuration; native asset, token contract, or NFT contract and token ID. |
| SVM | Pinned genesis hash plus approved cluster configuration; native SOL, or mint plus token-program identity. Source token-account ownership is separate from mint identity. |

Case, aliases, decimal representations, and duplicate debit lines must canonicalize before aggregation. Decimals and unit scaling come from approved metadata, not an untrusted display symbol or a Petal-supplied multiplier. Bridged assets and assets on different networks remain distinct even if a provider gives them the same USD price.

Fungible token prices do not establish NFT or position-token value. Such assets need an approved pricing mapping for the exact economic asset, or fall back to the existing approval path. Separate asset identities do not prohibit an explicitly approved valuation relationship, but a bridge/redemption relationship must be established rather than inferred from a shared ticker. The initial release has no fixed-peg valuation mode, default USD 1 stablecoin price, or default zero price. Introducing an owner-approved peg policy would be a separate decision and is not an outage fallback.

## 7. Broker pricing and USD conversion

The Broker owns a `PricingProvider` interface and an approved provider/asset mapping catalog. A deployment must configure at least one usable provider before advertising USD sessions. The first release uses keyless CoinGecko as primary and keyless DefiLlama as fallback, with fixed approved endpoints and no API keys or pricing proxy; a Petal cannot submit a provider URL, override a quote, or label an arbitrary asset as a known ticker.

```text
PricingPolicy {
  ordered_provider_ids, mapping_digest
  maximum_quote_age_ms
  maximum_reservation_delay_ms
  maximum_future_timestamp_skew_ms
  upward_price_margin_bps
}
PriceObservation {
  canonical_asset_id
  provider_id, mapping_digest
  observed_at_ms, fetched_at_ms, expires_at_ms
  usd_per_base_unit_numerator, denominator
  uncertainty_bound
  evidence_digest
}
```

Owner-selected pricing policy: ordered providers `[coingecko, defillama]`, maximum quote age **15 minutes (900,000 ms)**. Retain the proposed at-most-10-second acceptance-to-reservation delay, at-most-5-second future skew and zero blanket upward margin. Freshness is measured from the provider's reported observation timestamp and rechecked at reservation; fetching, caching or falling back never resets it. A quote exactly 15 minutes old is acceptable; an older quote is not. The ordered providers, mappings and age limit are review-bound through the pricing policy digest.

For each aggregated asset, use a valid cached CoinGecko observation, otherwise attempt its keyless lookup; on missing coverage, timeout, throttling, stale/invalid quote or other lookup failure, use a valid cached DefiLlama observation or attempt its keyless lookup. Only if neither supplies an acceptable observation does that asset require today's owner approval. Assets in one action may use different providers; retain each selected provider and observation in the valuation record. Never select the cheaper quote or average providers. An existing reservation retains its original valuation on retry. Multiple-provider quorum and disagreement handling remain deferred to P5; this fixed ordered fallback is included in the first release.

Use CoinGecko `https://api.coingecko.com/api/v3/simple/token_price/{platform}` for approved EVM contract/SVM mint mappings and `/simple/price` for explicitly mapped native asset IDs, with `vs_currencies=usd` and `include_last_updated_at=true`; `last_updated_at` supplies observation time. Use DefiLlama `https://coins.llama.fi/prices/current/{coins}` with approved `{chain}:{address}` or explicit native-asset mappings; its `timestamp` supplies observation time. CoinGecko platform IDs and DefiLlama chain IDs are provider-specific mappings, not asset identity. Preserve case-sensitive SVM mints. Require an exact mapped response entry, positive price and valid timestamp from either provider. DefiLlama's `confidence` is not a USD price-error bound; leave `uncertainty_bound` absent for both point-price adapters. No implicit stablecoin peg is permitted.

Reuse a provider's published upper confidence bound if a future approved adapter supplies one; otherwise its reported point price is a trusted input, not a proven upper market bound. A provider-specific extra margin requires explicit review and display. The 15-minute policy intentionally permits lag relative to the market; raw-unit caps remain independent restrictions.

`uncertainty_bound` records the provider's published upper bound when present and is otherwise absent. Use that upper bound, otherwise the point price; do not combine bounds or infer an independent confidence model.

Broker fetches/caches observations itself, validates identity and freshness, selects the provider's accepted price or published upper confidence bound, and applies any explicitly approved margin. A provider adapter must document what its timestamp and uncertainty mean. Cache entries are keyed by provider, canonical asset and mapping/policy version. Coalesce concurrent lookups, batch where the keyless endpoint permits, and respect throttling/backoff without extending quote expiry. Stale-while-revalidate must not authorize a signature. Native raw-unit ceilings limit damage from a subsequent valid-but-low quote; they do not make the provider trustworthy or independently protect trusted Petal declarations.

For asset quantity `q` and accepted USD price per base unit `n/d`, including any approved upward margin:

```text
charge_usd_micro = ceil(q * n * 1_000_000 / d)
action_charge = sum(charge_usd_micro for each aggregated asset)
```

Apply the margin using exact rational arithmetic and round upward to microdollars when charging. Aggregate quantities for an asset first; sum all charged assets and wallet-paid costs without netting receipts. The journal records quantities, accepted observations, policy/version, rounding results, and total charge. A USD 100 outflow plus USD 2 maximum wallet-paid costs consumes at least USD 102 before the approved price margin.

Valuation occurs when Broker reserves authority. Recorded usage is immutable and is not repriced when prices later change. A changed quote on a retry cannot change an existing reservation. Thus the cap measures dollars authorized at admission prices; it is not a guarantee about execution-time prices, realized losses, or mark-to-market exposure.

Unavailable, stale, invalid, ambiguous, or unsupported prices return a typed `ApprovalRequired` reason and use today's approval flow. A price lookup failure creates no reservation. The separate approval is visibly outside this session; it does not silently bypass a supposedly wallet-wide USD cap or amend the session. Existing wallet policy continues to apply and may still deny it.

The first provider adapter must cover supported EVM/SVM native assets and a documented token-address/mint universe. Before advertising automatic Polymarket BUY, specifically establish a supported price mapping for its actual pUSD collateral; coverage is not assumed. If unavailable, that profile retains today's approval behavior without blocking the rest of the generic system. The providers and order are selected above; exact supported mappings remain release configuration. Live research confirmed keyless pUSD coverage at both providers, but this does not establish continuous availability or freshness. Provider availability and rate limits must be tested before enabling the capability.

### External calls and packaging

Reuse Broker's existing HTTPS/runtime and W0 networking profile, which already supports outbound relay/ACME/DNS. Configure fixed operator-approved price/RPC endpoints; do not accept Petal-selected URLs or cross-origin redirects. The selected pricing endpoints require no credentials. Do not introduce a pricing key, secret store or network proxy; existing RPC configuration remains separate.

Use bounded responses, a five-second deadline per provider request and no in-request retry loop; bound a sequential primary/fallback pricing attempt to ten seconds for the aggregated action, including all asset lookups. Use fresh cache entries where valid; on primary failure try the approved fallback within that deadline. If no valid quote is available for every required asset, perform no reservation and return the existing approval fallback where policy permits. Do not follow untrusted endpoints or redirects. Reuse this client policy for the required SVM observations. Update Linux/macOS service configuration and installed tests for these endpoints; do not broaden Signer egress. A configured RPC is a trusted observation source, not a cryptographic proof. Failure to establish the pinned genesis and fresh context keeps native SVM reuse disabled.

## 8. Native execution requirements

Native EVM and SVM operations normalize into the same effects, prices, and budget ledger as Petals. They retain existing stricter native account, transaction, and network checks; default trust in Petal claims does not downgrade native verification.

For EVM, adapt `system_session::verify_evm` from #100, already retained in #112, without its former economic Signer projection. Preserve canonical legacy/EIP-1559 re-encoding, rejection of trailing bytes/access lists, strict 68-byte ERC-20 transfer calldata with zero native value, the 1/137/31337 chain allowlist, and the unsupported-L2-fee negative test. Bind chain ID, exact key, recipient, native value, token contract, transfer amount, and maximum fee to signed bytes. Preserve exactly one transfer/payload per native operation and the recipient/raw-unit restrictions in section 4. Wider chains/envelopes/batches are explicit later profile extensions. Contract calls through trusted Petals retain their own scopes; a four-byte selector alone does not establish arbitrary contract behavior.

For SVM, the first native reusable profile covers SOL only. Reuse exact-account selection and the existing native transfer verifier. Bind the approved signer/fee payer, full message, recipient, lamports, fee estimate bound, genesis observation, and recent-blockhash validity. Fee observations must be fresh, bound to the exact message/context, and checked against declared maxima. #103 already includes structural SPL/Pump instruction inspection; retain it for current review paths. Extending that reading into a native reusable SPL verifier with independently established token-account ownership, mint-extension state and account creation is deferred. The generic trusted SVM Petal path in section 5 remains in scope.

SVM cluster identity and freshness require Broker-controlled observations from a configured trusted RPC. An additional attestation infrastructure is not required for this release. A Machine claim carrying a genesis string is not sufficient. The recent blockhash must be observed on the configured cluster, and any external state used for accounting must carry a bounded validity interval. Preserve one SOL transfer/payload per initial native SVM operation, reviewed recipients and raw-unit ceilings; no SPL or token-account setup is admitted through this native profile.

The first native release supports explicitly enumerated legacy message/transaction profiles. Versioned messages, lookup tables, durable nonces, additional EVM envelopes, Token-2022 hooks/fees, and arbitrary CPI need explicit support contracts before native automatic use. An unsupported native format follows today's approval behavior where supported, otherwise it is refused. A trusted Petal may declare supported opaque signing payloads under its own scope; this must not be represented as independent native verification.

Broker cannot prove arbitrary future contract/program execution from a simulation. Simulation is useful evidence and a user preview; it does not eliminate state changes between signing and execution or replace the selected trust model.

## 9. Approval and Signer contracts

Reuse Petal `ApprovalSubject`, package hash, route grants, operation classes, exact `KeyRef`, allowed suites, policy/provenance bindings, owner ceremony, activation modes, counters, revocation, and replay. A trusted-Petal session uses the existing `machine_asserted` assurance default unless wallet policy demands more. New session eligibility is versioned in approved provenance metadata with the supported effects schema and fee/permission obligations. A package cannot opt an existing grant into wider semantics by changing a label.

Required profile checks are Broker-owned data alongside the existing compiled assurance registry, keyed by independently validated package/provenance identity and operation class. The released Polymarket BUY binding requires the compiled existing order-witness/debit check. Bind the required-check mapping and compiled check identities/digests into the reviewed member template; changing or removing them requires fresh review. Preparation and every admission resolve and compare that binding themselves; a Machine template flag or `machine_asserted` label cannot omit or disable it. A member missing the required binding/check, or a Broker lacking that compiled check, is refused for automatic use. Keep the small mapping in the trusted release/catalog configuration, not a runtime plugin loader or Petal-provided policy. Generic admission dispatches registered requirements without protocol-name branches; unrelated trusted Petals have no mandatory semantic decoder. The registry adapter receives actual payloads, approved account and evidence needed by the existing helper, without claiming it establishes every economic field.

Adapt existing use-time witness patterns rather than creating another verification framework. #103 already supplies `verify_hyperliquid_agent_use`, and `solana_review` binds Pump messages with a narrowly refreshable recent blockhash. Preserve their mandatory checks, current scope/count limits, and Safe/message exact-review restrictions when generalizing dispatch; they cannot silently enter a weaker generic profile. Hyperliquid action reconstruction does not establish trading-loss or venue-exposure budgets. Pump instruction inspection does not provide native reusable SPL ownership/state/price verification, so native SPL remains deferred.

Automatic Polymarket BUY remains single-order/single-payload in this release because the existing verifier enforces one order and one debit. Preserve batch debit summation for current exact approval; do not infer automatic multi-order support. Adapt the BUY checker to compare normalized canonical asset identities on both the independently reconstructed order and the claim, using the same approved mapping. The raw `pusd` label must not remain an alternate accounting identity; conflicting/unknown mappings fail rather than bypass the witness check.

Broker's grant metadata and signed review contain the complete descriptor, pricing policy, asset scope, trust disclosure, and semantic scope. Preserve the current opaque nonce commitment approach, but extend it to commit a domain-separated digest of the complete versioned Broker scope as well as the budget. No economically meaningful field may sit outside both the review commitment and grant identity. The original request nonce remains random/unique; it is not replaced by a predictable budget alias.

Projection into Signer terms strips Broker-only prices, assets, economic effects, shared USD state, and pricing observations. Ordinary Petal grants continue to use the existing Petal selector. Signer independently enforces its existing structural authority. The compiler allocates fixed operation/signature ceilings to members such that their sums do not exceed the reviewed pool ceilings; rate limits use the same window durations and sum within each pool window. Bind the allocations into the reviewed descriptor and each grant. Display both the pool limits and the sum of independent Signer backstops. Broker still enforces shared usage; Signer needs no cross-grant ledger. Fixed allocation may leave capacity stranded in one member. Dynamic redistribution is deferred; replacing allocations requires fresh review and confirmed revocation of the old grants first.

Native reuse requires a new minimal structural `System` selector in `bloom-signer-api`, because the production 1.6 selector supports only Exact and Petal. It binds component/action identity, allowed operation classes, provenance, exact key/suites, counters and validity through the existing approval model. Any narrower network/action semantics remain Broker-owned and opaque-committed. It must not contain the old draft `SystemSessionScope` asset amounts, prices, destinations, or budget ledger.

Do not revive Signer #68's economic design. Create a separately reviewable structural-only Signer change and matching Broker translation. Allocate fresh negotiated protocol versions for changed wire shapes: do not reuse current draft Machine–Broker 1.9, production Broker–Signer 1.6, or the incompatible Broker–Signer 1.7 shape already defined by #68/#100. Audit other allocated versions before choosing numbers. Petal-only clients may remain compatible where capabilities explicitly permit it.

Missing generic effects, pricing, native scope, or required assurance capabilities must produce an explicit fallback/unsupported result. There is no fallback to local authority, direct Machine-to-Signer RPC, or a weaker unreviewed grant.

## 10. Admission and ledger lifecycle

1. Machine selects a live member grant from authenticated Broker state and supplies exact payloads, provenance, account, operation ID, effects and evidence. Ambiguous matching grants require explicit selection.
2. Completed-result recovery checks the frozen operation identity and returns existing bytes through status without requiring fresh authority, pricing or reservation. New signing admission validates identity, scope, policy/epoch, active lifecycle, canonical effects, required assurance and native checks.
3. Broker resolves canonical assets and obtains acceptable prices outside the database write transaction. The resulting quote set is immutable input to admission.
4. In one authoritative write transaction, Broker rechecks grant/policy state, quote validity and its effective clock; checks USD per-action/lifetime/rolling limits, asset limits, counts and rates; then appends the reservation with all valuation evidence.
5. Broker persists the Signer operation identity before requesting signing. Only after the reservation is durable may signing start. All member keys/classes use this same gate.
6. Signer enforces structural approval and replay, signs, and returns the existing authenticated receipt. Broker marks the reservation committed and stores the recoverable result. Lost replies reconcile against that same operation; they do not create a new charge or signature.

Use existing Broker `operation_status` and frozen Machine operation identity to recover completed signatures. The persona client already uses this path; Machine #329 extends consistent recovery and unknown-outcome handling to the other Petal signing paths. Do not revive closed Broker #74 or require a second result-recovery RPC. Reconcile an uncertain attempt before replacing its payload, grant or operation ID; a status/read failure is not evidence that nothing was signed.

Use the journal's existing reserve/commit/release/quarantine machinery. The required economic states are `RESERVED`, `COMMITTED`, `AMBIGUOUS`, and `RELEASED`. Reserved, committed, and ambiguous uses consume capacity. Append a release only when Broker has authoritative evidence that no usable signature was produced; a timeout, failed broadcast, cancellation request, revocation, or Machine receipt does not establish that.

Correct post-signature error classification is a release prerequisite: include Signer #62's fix or independently demonstrate equivalent behavior on the selected Signer. The current pinned 1.6 production revision can quarantine an operation yet return a refusal code on partial-batch/post-signature failure. Broker's existing `AmbiguousProviderEffect` handling already retains the reservation when correctly informed; it must not release economic capacity for those cases. This is a wire-compatible Signer correctness fix, not economic accounting in Signer.

For the initial gross-authorization budget, even a successfully canceled, expired, reverted or unsubmitted signed action remains charged. Execution receipts and proceeds do not refund the budget. P4 may add a separately defined outstanding-exposure ledger; it must not silently change gross-spend semantics.

USD rolling windows use Broker's effective monotonic/reconciled clock at reservation and intervals `(now - duration, now]`. Lifetime usage never disappears when a rolling window advances. Clock rollback, journal restore, missing valuation evidence or failed existing journal/edge-identity continuity checks fence new automatic admission pending recovery. An old Signer backup cannot reconstruct or reset Broker usage.

Use existing authenticated journal heads, Broker self-checkpoints and Broker–Signer peer-head exchange as rollback witnesses. Every budget mutation must be bound into the existing audit stream with descriptor and valuation-record digests, not just an unauthenticated mutable table. Before automatic admission after restart/restore, compare against surviving checkpoints and reconcile in-flight operations; behind/conflicting heads or missing bound records fence admission. Tests must restore the Broker DB alone, DB plus local checkpoints with a newer Signer witness surviving, and a crash around reservation/signing. A hash chain alone does not detect a fully consistent old snapshot. If all witnesses are rolled back together, automatic detection is not promised; an operator-declared restore disables old pools and requires fresh review. Signer counters/receipts are useful additional evidence where exposed, but equal counts do not prove equal economic history. Do not add a second rollback service or counter API for this release.

Specifically extend the existing `reservation.created` audit payload with `budget_id` and `valuation_record_digest`, in the same transaction as the reservation/session-use row. The canonical valuation record includes reservation time (`accepted_at_ms`), descriptor identity, canonical quantities, accepted price observations/policy, rounding and charged USD. The existing authenticated event/checkpoint then binds both economic history and window timing; an unauthenticated `session_uses` insert alone is insufficient. Recompute/compare that digest when loading records for admission or recovery. This is an extension to the current event, not a new audit stream.

Fresh payloads, blockhashes, fee changes and replacement transactions are new signing identities. Initially charge them separately. Do not deduplicate replacements merely because execution may be mutually exclusive. A future replacement-aware optimization needs an explicit proof and lifecycle contract.

Stop atomically fences the pool in Broker before revoking individual members, so another Machine or a pending price lookup cannot admit new work during partial revocation. It also disables local dispatch, revokes every remotely active member and confirms live Broker state. It is idempotent and reports outstanding revocations. An already reserved/signing operation remains charged and is reconciled rather than presumed canceled. Already produced signatures and on-chain permissions remain valid according to their external semantics. Completed result recovery remains available after expiry/revocation without authorizing another signature.

End live owner ceremonies for revoked members so the wallet can immediately request a normal approval after stop. Closed #76/#79 contain reusable cleanup logic and fixtures, but are not landed dependencies. Treat ceremony cleanup separately from authoritative revocation: report unfinished cleanup without claiming a confirmed revoke failed or reopening the pool. Add dispatch-level coverage for the actual stop/revoke paths; the old standalone helper tests alone were insufficient.

### Broker API additions

Keep existing approval prepare/ceremony/status, capabilities and signing RPCs. Extend them with versioned effects and a pool reference; do not add a parallel session service or five new pool endpoints:

| Operation | Request and required result |
| --- | --- |
| Existing capabilities | Advertise supported effects/pricing schemas, native profiles, assurance contracts and pool-stop support. |
| Existing approval preparation | Include complete reviewed pool/member templates in Broker metadata; register the pending pool idempotently when preparing the first member. Subsequent members must match it. Return existing approval/ceremony references. |
| Existing completion/reconciliation and approval status | Existing activation completion/reconciliation marks the pool active transactionally once all members are confirmed live. Status projects shared usage/lifecycle and readiness; every admission rechecks the complete live set. No separate activation RPC is needed, and Machine need not submit a signing action just to activate the pool. |
| `session.stop` | Pool ID, idempotent operation ID and reason. Persist `STOPPED`, fence admission, revoke members and return confirmed/pending outcomes. Retrying completes revocation without reopening the pool. |

Pool lifecycle is `PENDING → ACTIVE → STOPPED` or `EXPIRED`. Pending/expired/stopped pools never admit new work; revocation reconciliation and completed-result recovery are still allowed. Failed member preparation remains pending until resumed or explicitly stopped. Activation does not create a new descriptor, replenish usage or extend validity. Existing single-approval RPCs cannot bypass the pool-state check for a pool member.

Signing admission returns either the existing signed/pending result, a policy denial, or a typed approval requirement. Distinguish at least `PRICE_UNAVAILABLE`, `PRICE_STALE`, `ASSET_UNSUPPORTED`, `EFFECTS_UNSUPPORTED`, `SESSION_SCOPE_MISMATCH`, `BUDGET_EXHAUSTED`, `POOL_INACTIVE`, and `ASSURANCE_UNAVAILABLE`. The client uses the current approval path only where existing policy permits it; denial must not be converted into a weaker approval automatically.

## 11. Onboarding and status

Persona choices remain suggestions, not authority. Compile proposals from selected wallet/accounts, installed immutable packages, declared session eligibility, supported native profiles, pricing coverage, and current Broker/Signer capabilities. Remove account-0-only and EVM-only assumptions; never infer an account by list position.

The owner reviews the whole shared pool and each member scope. Multiple existing approval ceremonies may be needed. An incomplete bundle is not an active generic session: Machine must keep it pending and avoid automatic dispatch until every intended member is confirmed active. Failed activation must be recoverable without a fresh budget; abandoning it disables/revokes already active members. Broker independently checks the expected member set before admitting pool use. No new multi-grant atomic Signer protocol is required.

A single passkey assertion bound to the budget and complete member-set digest is a deferred UX option, not a first-release requirement. Keep existing per-grant ceremonies until its challenge, replay and partial-completion semantics are separately specified.

Review/status must show USD per-action/lifetime/rolling limits; remaining reserved/committed usage; selected accounts/networks/packages/classes; native recipients/raw caps; priced asset scope; costs included; trust mode by field; price source/freshness policy and any margin; pending/stopped/orphaned state; and the exact reason for fallback. Show the declared principal value, wallet-paid costs and final charged USD separately, so a USD 100 all-in cap is not advertised as USD 100 spendable principal. Trusted claims must be described as an accounting limit, not protection against malicious Petals.

Reuse #88's best-effort ceremony sweep and readable status behavior during clock/journal degradation. Render degraded service state alongside readable last-known status; it must not authorize signing or assert a sweep succeeded. Keep denial reasons available through existing diagnostics rather than adding a parallel session logging service.

Adding a Petal, account, asset universe or new native profile requires review. Ordinary package installation and persona changes cannot silently add a pool member. Existing manual approvals and unrelated authority remain intact.

## 12. Changes to the current draft PRs

This mapping is against the reviewed heads below. It describes future changes; no PR metadata or implementation is changed by this spec.

| Original PR | Current candidate | Preserved or superseded |
| --- | --- | --- |
| [Broker #100](https://github.com/bloom-directory/bloom-broker/pull/100) | [Broker #112](https://github.com/bloom-directory/bloom-broker/pull/112) | Shared ledger, review and typed EVM verifier retained. Economic Signer projection removed; native reuse currently disabled pending structural-only scope. |
| [Bloom #352](https://github.com/bloom-directory/bloom/pull/352) on `feat/default-policy` | [Bloom #377](https://github.com/bloom-directory/bloom/pull/377) on clear-signing [#224](https://github.com/bloom-directory/bloom/pull/224) | Persona/default-policy work retained and reconciled with clear signing; original branches/local changes preserved. |
| [Polymarket #19](https://github.com/bloom-directory/bloom-petal-polymarket/pull/19) | [Polymarket #26](https://github.com/bloom-directory/bloom-petal-polymarket/pull/26), combining #19 and #21 | Order debits and recovery retained alongside current login/clear-signing flow. |
| [Signer #68](https://github.com/bloom-directory/bloom-signer/pull/68) | Economic design superseded | No Signer budget ledger. A separate minimal native structural selector is still required. |

| Candidate | Reviewed head | Role |
| --- | --- | --- |
| [Broker #112](https://github.com/bloom-directory/bloom-broker/pull/112) | `556f6b3966f373a2eb2381355aabf3c619b485b7` | Generic accounting and approval owner. |
| [Bloom #377](https://github.com/bloom-directory/bloom/pull/377) | `a95f3863798004947c3b3916c230d5fdd5a1cdfc` | Machine, CLI and onboarding integration; stacked on clear-signing #224. |
| [Polymarket #26](https://github.com/bloom-directory/bloom-petal-polymarket/pull/26) | `6ba63258f67fefb9cd4d908811dc62200c016028` | First protocol consumer/reference. |

### Broker 112

**Reuse:** Transactional shared journal and idempotent reservations; approval metadata and review manifest; nonce projection into ordinary Signer Petal terms; authenticated RPC; policy, counts/rates, replay and stop/recovery behavior; canonical debit aggregation; existing optional assurance registry and exact-review decoders.

**Change:**

- Replace mandatory `SessionAssetScale`/`SessionNominalLimits` conversion with versioned USD valuation and stored Broker observations. Preserve mandatory native per-asset raw ceilings; trusted-Petal caps stay optional on the wire but onboarding emits them by default. Never relabel nominal micro-units as observed USD.
- Replace the global Polymarket-only budget allowlist with generic scope/effects admission. Dispatch `verify_polymarket_session_use` through the Broker-owned required-check binding for the Polymarket BUY provenance/class, at prepare and use. Preserve single-order automatic BUY, canonical-asset comparisons and existing exact review/batch summation. Do not require protocol decoders for unrelated trusted Petals or claim that this helper verifies every field.
- Extend claims and review with complete outflows/costs and continuing-permission classification; make single/batch paths equivalent. Unknown price/semantics returns typed approval fallback before reservation.
- Add canonical network/asset mapping, CoinGecko/DefiLlama keyless adapters and the ordered pricing policy, immutable quote records, USD checks and fixed profile disclosures. Extend `reservation.created` with budget identity and a valuation digest; reuse current audit/checkpoint infrastructure. Reuse approval APIs for member readiness/status; add only the pool-stop operation. Stop must fence the shared pool before per-member revocation. Check that projected member limits exactly match their allocations without a new Signer ledger.
- Replace the legacy native-session refusal only after the structural Signer extension and native economic/context checks exist. Translate explicit System identity without exporting budgets south.
- Correct stale `SessionAccounting` documentation referring to a Signer economic backstop. All economic accounting and recovery remain Broker-owned.

**Keep separate:** Clear-signing/login changes inherited from production Broker. Do not weaken exact review or existing wallet policy while generalizing reusable authority.

### Bloom 377

**Reuse:** Browser/persona UI and local-server protections; selected-wallet checks; default-policy creation/import flow; durable proposal and retry journals; forwarding evidence; no-local-authority rule; exact fallback; idempotent confirmed stop; Linux/macOS onboarding integration.

**Change:**

- Replace `persona_onboarding.rs` account-0/EVM/pUSD compilation with capability-driven explicit account/member selection and one shared USD descriptor. The suggested USD profile can remain, but it must compile to actual pricing-backed terms.
- Remove the global `polymarket.order.poly1271`/mandatory-witness dispatch gate in `persona_sessions.rs`. Select grants by approved provenance/scope, effects schema and live capability. Supply evidence for mandatory profile checks advertised by Broker; the Machine cannot omit a required check to select the generic trusted path.
- Carry generic effects through the existing opaque SDK claim transport, bind exact accounts in the host, and add native projections; preserve complete effects/evidence in retry identity. A changed claim, price policy, key, payload order or evidence must conflict, not reuse a frozen attempt.
- Stop using local nominal conversion as authority or as a gate that incorrectly excludes a priced asset. Broker decides admission and returns usage/fallback reasons.
- Integrate native EVM/SVM signing, multi-key member activation/reconciliation, cost declarations, price-related status and fallback to today's approval flow.
- Negotiate capabilities and pin exact compatible Broker/Signer/SDK releases in Cargo, CI and packaging. Update architecture/spec wording that currently describes BUY-only scope or Signer 1.6 as sufficient for native reuse.

**Keep separate:** #224 clear-signing work and inherited default-policy work. They are foundations, not reasons to ship incomplete generic sessions.

### Polymarket 26

**Reuse:** Reconstruction of saved prepared signing bytes; gross BUY collateral and SELL CTF-share declarations; batch summation; exact review and separated CLOB authentication; durable prepared-operation recovery.

**Change:** Adopt the versioned effects schema and canonical asset mappings. Retain the existing mandatory BUY witness verification in Broker. Enable BUY automatically only after actual pUSD pricing coverage is established. Preserve SELL's exact share-unit declarations and today's approval behavior; automatic SELL pricing/admission is deferred to a separate product/profile decision rather than requiring a CLOB-price adapter now. Declare every wallet-paid builder/protocol cost when support is added. Relabel documentation around generic shared budgets rather than BUY being a universal rule.

**Do not inherit:** Login, setup, funding, withdrawals or unlimited allowances merely because trading has a session. Each needs its own reviewed scope and complete effects, or the existing approval path. Immutable package publication and installer catalog adoption remain rollout gates.

### Signer and shared Petal tooling

Signer #68 remains superseded as an economic design. A new structural-only Signer candidate is now required for native reuse; ordinary Petal sessions continue to reuse current Petal approvals. Add tests showing prices, assets, fees and shared budget ledgers never enter the new System selector or Signer operation identity.

The candidate reuses the canonical SDK’s existing opaque claim transport: no SDK fork or new WIT signing API is needed. Participating Petals emit the versioned generic effects JSON; Machine binds exact accounts, and installer-certified manifest metadata explicitly enables schema v1. Compatibility fixtures exercise this path. Existing Petals require updates only to participate automatically; old packages continue through existing approval behavior. Native SOL observations remain Broker work. Native SPL verification is not a first-release dependency.

### Kyle's Broker work to reuse

Reviewed on 2026-10-27. PR status is an integration note, not a claim that an open branch is release-ready. #112 already contains the landed #103/#37 foundations, and Machine #377 incorporates #224.

| Work | Status at review | Reuse or integration decision |
| --- | --- | --- |
| [Broker #103](https://github.com/bloom-directory/bloom-broker/pull/103), following [#36](https://github.com/bloom-directory/bloom-broker/pull/36)/[#37](https://github.com/bloom-directory/bloom-broker/pull/37) | Landed and already in #112 | Use compiled token metadata, formatting, exact review and existing message/use-time witness helpers. Keep the existing stronger profile restrictions; add no duplicate catalog or decoder framework. These are not USD prices. |
| [Broker #113](https://github.com/bloom-directory/bloom-broker/pull/113) | Open | Adopt its small native-recipient versus Petal-destination UI fix and regression fixture with the session review integration. |
| [Broker #88](https://github.com/bloom-directory/bloom-broker/pull/88) | Open | Reuse status-under-degradation and denial diagnostics. Preserve read access without weakening mutation/admission checks. |
| [Broker #74](https://github.com/bloom-directory/bloom-broker/pull/74), [Machine #329](https://github.com/bloom-directory/bloom/pull/329) | #74 closed as redundant; #329 open | Reuse `operation_status`; reconcile #329's caller recovery/unknown-outcome handling with existing persona journals rather than add another retry service. |
| [Signer #62](https://github.com/bloom-directory/bloom-signer/pull/62) | Open | Required fix or proven equivalent for truthful post-signature ambiguity. Exercise it through Broker's existing quarantine path and shared budget tests before release. |
| [Broker #76](https://github.com/bloom-directory/bloom-broker/pull/76)/[#79](https://github.com/bloom-directory/bloom-broker/pull/79) | Closed, unmerged | Reuse stop/ceremony cleanup lessons and fixtures where needed; do not revive the canceled funded-session product scope or assume helper coverage proves dispatch behavior. |
| [Broker #97](https://github.com/bloom-directory/bloom-broker/pull/97), [#101](https://github.com/bloom-directory/bloom-broker/pull/101)/[#102](https://github.com/bloom-directory/bloom-broker/pull/102) | Closed; related readings consolidated in #103 | Do not stack obsolete advisory/catalog-policy branches onto the candidate. Use the current compiled-catalog implementation. |

The checkout/card work ([#95](https://github.com/bloom-directory/bloom-broker/pull/95), [#114](https://github.com/bloom-directory/bloom-broker/pull/114)) provides useful disclosure examples for future authority, but is not a dependency of crypto sessions. Do not import checkout storage, delivery protocols or Signer card scope merely to reuse its UI wording. Two small keyless price adapters with fixed ordered fallback and trusted native SOL observations remain new work; none of these PRs supplies the generic USD price service.

## 13. Acceptance criteria

| ID | Required acceptance |
| --- | --- |
| G01 | Two unrelated test Petals on EVM and SVM share one USD budget with no protocol-name branch in generic admission. The SVM fixture declares priced token spending through trusted claims without requiring a native SPL verifier, with the corresponding trust disclosure. |
| G02 | A native EVM action, native SOL action and Petal action compete concurrently for the same pool; only reservations fitting its remaining USD capacity succeed. |
| G03 | Default trusted-Petal claims need no semantic decoder; review uses the fixed profile disclosures. BUY members missing their mandatory registry binding/check are refused at prepare and use even if Machine omits a flag. Missing/changed witness or understated debit fails; automatic multi-order BUY fails while existing exact batches remain available. Canonical mapping preserves witness checks, and generalization cannot downgrade existing Hyperliquid/Pump/Safe/message restrictions. |
| G04 | Duplicate/aliased asset lines, wrong decimals, wrong chain/mint/program, and arithmetic boundaries cannot reduce charged USD. Onboarding emits fixed caps for listed assets; a valid-but-low later quote cannot bypass native or present Petal raw caps. Omitted Petal caps remain wire-compatible, and no independent protection for dishonest declarations is claimed. |
| G05 | Valid CoinGecko quotes take precedence; missing, stale, throttled, invalid or failed primary lookups use valid DefiLlama quotes. Test primary recovery/preference, mixed-provider actions, cache isolation, bounded deadlines, timestamps exactly 900,000 ms old versus older, future skew and freshness recheck at reservation. Missing/invalid quotes from both providers trigger current approval behavior with no leaked reservation. Petal prices are ignored; an unavailable actual pUSD mapping cannot silently become a USD 1 peg. |
| G06 | Fees, account funding and protocol costs are charged once. Missing required fees, under-scoped assets and zero-debit permission grants cannot silently enter the pool. |
| G07 | Partial batches, post-signature errors, lost Signer replies, crash between reserve/sign/commit and repeated recovery preserve charges and do not duplicate signatures. Test Signer #62 behavior or equivalent through Broker: no possibly signed attempt returns a released refusal. Completed recovery uses existing operation status; changed retry content conflicts and an unresolved attempt cannot be replaced. |
| G08 | Gross usage remains charged after canceled/unsubmitted/expired/reverted signed operations; incoming proceeds and clock/window changes cannot reset lifetime usage. |
| G09 | Exact fallback remains available under current policy, is clearly separate from session usage, and does not create broader authority. |
| G10 | Signer receives only existing Petal or minimal System structural scopes. Prepare/use reject projected member limits unequal to descriptor allocations; reject pool operation/signature ceilings below member count. Summed count/rate backstops fit the reviewed pool without a Signer shared ledger. Unknown/incompatible versions fail negotiation; no economic interpretation or direct Machine-to-Signer path is added. |
| G11 | Native EVM/SVM checks reject account/chain/payer/blockhash changes, recipients outside either allowlist, native batches, raw-unit excess and unsupported cost/context models. At admission, reject a stored recipient/raw-cap scope whose recomputed digest differs from the committed member digest, even after successful preparation. Preserve existing EVM verifier negatives; native SOL scope rejects SPL instructions and token-account setup rather than claiming token verification. |
| G12 | Package update, new member/key, changed pricing policy, assurance downgrade or failed existing journal/identity continuity checks cannot reuse an old pool silently. Verify `reservation.created` binds budget ID and the canonical valuation/time digest; reject altered rows. Restore tests cover DB-only rollback, local-checkpoint rollback with surviving peer witness, and reservation/signing crashes. Coordinated rollback of all witnesses is an explicit limitation. |
| G13 | Partial activation, stop/retry, expiry and revocation preserve live Broker truth and completed-result recovery. A stopped member's live ceremony no longer blocks the next ordinary approval; test actual dispatch, including cleanup failure after confirmed revoke. Clock/journal degradation leaves status readable but blocks unsafe admission. Existing signed permissions are not reported as canceled. |
| G14 | Polymarket BUY uses its verified collateral quantity and approved price mapping; SELL retains current approval and exact share-unit declarations. Login/setup cannot borrow trading authority. |

Use unit/property tests for canonicalization, fixed-point valuation and budget arithmetic; authenticated Broker–Signer acceptance for lifecycle, native scope and replay; and Machine/Petal integration for fallback and recovery. Run existing authority-boundary/release checks and installed Linux/macOS conformance with exact immutable revisions. A software-passkey fixture does not replace the physical-passkey/installed release checks.

### Example shared accounting fixture

Use fixed fixture observations rather than live market prices. An owner approves a USD 200 rolling-day pool across one EVM key, one SVM key and two pinned Petals. Use the initial zero extra margin; principal and wallet costs remain separate display lines:

| Action | Declared outflow value | Wallet-paid costs | Charged USD |
| --- | --- | --- | --- |
| EVM token transfer | USD 100 | USD 1 | USD 101 |
| Native SOL transfer | USD 20 | USD 0.10 | USD 20.10 |
| Second Petal trade | USD 30 | USD 0.90 | USD 30.90 |

Usage is USD 152, leaving USD 48 for that rolling window. Later incoming proceeds or a price change leave this recorded usage unchanged. A concurrent action charging USD 49 must require separate approval or be denied by existing policy. An action using a token without a fresh approved price follows current approval behavior before reserving anything. Each native example must also fit its fixed recipient and raw-unit scope.

## 14. Implementation and release gates

The implementation candidate selects Machine–Broker API 1.10 at Broker
`53372d2f979d89538decf21928fb82d312720dc7` and structural Broker–Signer API 1.8
at Signer `70a698fb0b122394070c6c2089422fc1461c159f`. These are PR candidate
pins, not a claim of deployed service or published compatible Petal artifacts.


Implement the contracts and fixtures in P1 before changing onboarding dispatch. Add pricing and versioned ledger records in Broker, then the SDK/reference Petal, then native structural Signer scope and Machine integration. Add migration only if the deployment check below requires it. Keep every intermediate default conservative: unsupported capabilities fall back to existing approvals until the full path is available.

Establish whether any old session profile has actually been deployed or retained before planning migration. Current references to a production Signer mean its released code/API, not evidence that #68/#100/#112 sessions were deployed. If these are unreleased disposable draft profiles, make a clean version break and do not implement a migration engine. If live/retained authority exists, preserve its original restrictions and usage until explicitly stopped/replaced; never reinterpret nominal units as observed USD or reset consumed authority. Rollback protection for the new release remains required regardless of migration needs.

Before first general release: validate both selected keyless pricing adapters, ordered fallback and canonical asset coverage; verify actual pUSD coverage before enabling that profile; verify the owner-selected 15-minute age limit and remaining pricing defaults; publish compatible immutable Petal artifacts using the existing SDK transport; certify provenance/effects/native profiles; pin both API edges and service commits; complete G01–G14 and installed conformance; and independently review the trust disclosure and restore behavior. No mainnet trade is required merely to test these contracts.

### Implementation size and deferrals

| Work | Expected scope relative to the current candidates |
| --- | --- |
| Native recipients/raw caps/single transfer; BUY witness; count allocations | Reuse existing validators, metadata and counters; add explicit wiring/compilation and focused tests. No new economic Signer types. |
| Rollback coverage | Reuse existing checkpoint/head exchange; bind new valuation records and test restore cases. No new witness service or mandatory counter-status API. |
| Shared USD pricing | Material unavoidable addition for the requested feature: two small keyless provider adapters, fixed ordered fallback, canonical mappings, cache/valuation records and failure handling. Establish pUSD coverage before promising automation. |
| Native SVM reuse | Missing path narrowed to trusted genesis/blockhash/fee observations for existing SOL transfer verification. Reuse existing structural Solana/SPL readers for current review; no new native reusable SPL verifier, token-account setup or attestation infrastructure. |
| Native Signer selector and SDK effects | Coordinated API/compatibility work already required by generic native/Petal scope. Keep the Signer change structural only. |

Defer native SPL verification, multiple-provider consensus/disagreement policies, automatic SELL valuation, fixed-peg policy, dynamic counter redistribution, one-assertion bundle ceremonies, dynamic asset universes and unreleased-draft migration machinery. These are not prerequisites for the owner's agreed first-release features. Generic trusted SVM Petal token spending remains supported. Reuse existing approval APIs plus pool stop; do not build a parallel approval orchestration service.

Remaining engineering selections are exact asset mappings, provider-specific keyless limits, and the exact supported native transaction/token profiles. They must be recorded before enabling those profiles. Further product decisions are needed only to change gross-spend semantics, enable unpriced automation, widen continuing permissions, or claim economic containment beyond the selected trust boundary.

## 15. Source contracts

- [Triad process architecture](2026-07-23-triad-process-architecture.md), especially default `machine_asserted` trust, mandatory fee accounting, Broker ownership and compiled assurance contracts.
- [Edge owned protocol migration](2026-08-04-edge-owned-protocol-migration.md).
- [Solana provenance catalog](2026-08-18-solana-provenance-catalog.md).
- [Persona onboarding](../architecture/Persona%20Onboarding.md) and [Sealed Approvals](../architecture/Sealed%20Approvals.md) in the current Machine candidate.
- [ERC-20](https://eips.ethereum.org/EIPS/eip-20): token transfer and allowance are distinct operations.
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712): typed-message hashing does not itself supply application replay protection.
- [Solana transactions](https://solana.com/docs/core/transactions) and [fees](https://solana.com/docs/core/fees): message execution and fee behavior must be accounted for separately.
- [Solana transfer hooks](https://solana.com/docs/tokens/extensions/transfer-hook): some mint behavior invokes additional program logic and needs an explicit support contract.
