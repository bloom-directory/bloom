# Reusable EVM/SVM permissions with recurring token allowances

Status: candidate, not deployed. Updated 2026-10-27 following the owner's decision to remove USD budgets.

This revision supersedes the USD pricing and finite persona-duration requirements in earlier versions of this document. The triad custody, authenticated transport, Sealed Approval, revocation and replay boundaries remain unchanged.

## Product contract

Broker accounts in exact raw token units. There is no price service, quote age, nominal conversion, assumed peg, cross-token dollar pool or on-chain ERC20 `approve` in this feature.

Each default allowance belongs to one wallet, exact account/key and Petal package (or native component). All reviewed routes of that Petal share usage. Chain and token address/mint are part of every asset identity. Different tokens, Petals and accounts have independent capacity; duplicates cannot multiply an allowance. Policy/package/key changes still require owner review.

| Persona | Automatic allowance |
| --- | --- |
| Institutional | None; approve each action |
| Trader | Per-action amounts and a continuously rolling 24-hour allowance per token |
| Degen | Larger per-action amounts and a continuously rolling seven-day allowance per token |

These are standing permissions until revoked. The window does not expire authority. A charge ages out at its exact window boundary; no calendar reset or hidden renewal occurs. Changing the persona or token amounts stops retained authority before requesting replacement consent.

## Initial quantity presets

Numbers are quantities of each token, not dollar equivalents. Grouping does not share limits.

| Token | Trader/action | Trader/24h | Degen/action | Degen/7d |
| --- | ---: | ---: | ---: | ---: |
| USDC, USDT, DAI, USDS, pUSD, EURC, GHO, crvUSD | 100 | 1,000 | 1,000 | 10,000 |
| WETH | 0.025 | 0.25 | 0.25 | 2.5 |
| wstETH, rETH, weETH | 0.02 | 0.2 | 0.2 | 2 |
| WBTC, cbBTC, tBTC | 0.001 | 0.01 | 0.01 | 0.1 |
| WBNB | 0.1 | 1 | 1 | 10 |
| WAVAX, WHYPE | 2 | 20 | 20 | 200 |
| LINK | 5 | 50 | 50 | 500 |
| AAVE | 0.25 | 2.5 | 2.5 | 25 |
| UNI | 10 | 100 | 100 | 1,000 |
| ARB, OP | 100 | 1,000 | 1,000 | 10,000 |

Only exact deployments present in the trusted token catalog may receive a preset. Symbols in a Petal request never choose authority. Polymarket's automatic BUY scope uses the exact six-decimal Polygon pUSD contract. Hyperliquid funding would use USDC; venue orders and agent permissions are separately reviewed and do not become bounded by a funding allowance. Enso/NEAR require supported source-chain routes and explicit selected assets. Feedback needs no spending allowance. An unsupported integration remains on ordinary owner approval; do not manufacture an effects certification.

Native transfer and gas allowances have separate explicit raw-unit amounts; they are not inferred from an ERC20 allowance. Advanced selections may supply `token_allowances` overrides with `asset`, `per_action`, and `per_window` raw decimal strings. Missing presets/explicit limits fail closed.

## Authority and trust

Reuse Sealed Approvals, exact KeyRefs, installer provenance, frozen operation identities, reservations and durable revocation. The v3 token policy binds exact asset metadata and reviewed member templates. Machine compiles one budget per Petal/account; Broker owns the ledger. Signer sees structural signing terms and a commitment to Broker economics, not prices or a token ledger.

The generic path intentionally trusts the pinned Petal and Machine's declared debits, maximum wallet-paid fees and `economic_effects` v1. Broker checks accounts, networks, provenance, permission classification, and arithmetic over those declarations. It does not establish maximum exposure from arbitrary signed bytes. A buggy or malicious Petal can understate spending and exceed these accounting limits. Review must state this plainly.

Supported native EVM/ERC20 and SOL transfer verifiers keep binding the actual supported bytes, exact account, network, recipient, amount and fee facts. Native SPL verification remains deferred. Polymarket BUY keeps its mandatory signed-order maker debit witness; automatic BUY remains single-payload. SELL shares, relayer batches, onboarding, funding and withdrawals retain separate approval. Preserve existing stronger approval profiles.

Continuing approvals/delegations and opaque off-chain permissions do not enter automatic token allowance scopes merely because a Petal calls them zero-cost. Exact owner review remains available. Existing venue collateral, external approvals and already-signed orders are not cancelled by revoking future signing authority.

## Accounting and lifecycle

Aggregate all debits and maximum wallet-paid fees for the same asset before checking its per-action cap. Charge each asset independently against its rolling windows. Incoming transfers do not refund capacity. Reserve atomically before signing; reserved, committed and quarantined outcomes count. Only authenticated proof that no signature escaped releases a reservation. Stable retries reuse the original operation and charge. Ambiguous signatures never get fresh operation IDs or replacement authority.

Standing validity uses the explicitly reviewed `expires_at_ms = u64::MAX` sentinel on reusable selectors only. The signed wallet policy must explicitly permit standing validity (`maximum_approval_lifetime_ms = 9_007_199_254_740_991`). Exact approvals retain finite validity, and finite Signer approvals retain the compiled 90-day ceiling. Local standing grants use the existing durable-local activation mode. Wallet secrets remain boot-activated: a restart/lock can require an owner unlock, but does not grant a fresh allowance or erase usage. Revocation, policy epochs, account retirement and package provenance checks still apply.

Lifetime structural counters use the maximum representable value, with explicit operation/signature rate backstops. No small lifetime count should turn a recurring permission into regular reapproval. Ordinary finite/exact approvals retain their existing counters.

## Delivery and acceptance

Remove the pricing module, pricing RPC/capability, USD policy/valuation records and nominal conversion. Retain authenticated raw-unit reservation evidence. Old unshipped USD grant/config formats are rejected, not silently converted; keep audit/recovery files. Use a fresh isolated dev installation for acceptance.

Verify independent token/Petal/account scopes, shared-route usage, duplicate selection rejection, batch/fee aggregation, integer precision/overflow, exact rolling boundaries, unchanged authority identity after replenishment, stable retries, authenticated releases, ambiguous signatures, restart retention and durable revocation. Exercise real signing through the triad and owner passkey setup. Repeated covered actions must create no additional approval ceremonies; unlisted assets and continuing permissions retain ordinary review.

Do not add simulation, a verifier framework, new on-chain approvals or a parallel legacy pricing engine in this change.

An owner can unlock retained local authority with `bloom wallet persona rearm WALLET` (`--approval ID` selects a specific grant). This reuses the sealed-approval passkey ceremony with the unchanged standing terms and a signed rearm purpose. It preserves both Broker usage and Signer counters, refuses stopped/revoked or changed terms, and retains an operation identity across retries. It does not add a wallet-unlock ceremony kind or silently create replacement authority.

## Degen ERC20 transfers to any recipient

Degen onboarding additionally proposes a native-wallet, ERC20-only standing
transfer scope on configured Ethereum (1) and Polygon (137). Its exact token
contracts come from the reviewed catalog and use Degen's per-action and rolling
seven-day quantities. Each chain's gas allowance is separate: Ethereum 0.005
ETH/action and 0.05 ETH/7d; Polygon 1 POL/action and 10 POL/7d. These quantities
are displayed for owner approval and do not derive from prices. Native-token
transfers are not included. Trader and Institutional defaults are unchanged.

The wallet policy separately signs `erc20:any-recipient` for each chain, and
the immutable system scope signs `any_erc20_recipient: true`. Neither alone
permits signing. Broker reconstructs the recipient, exact token, amount and
maximum gas from the canonical transaction bytes and enforces both opt-ins,
asset caps and rolling windows. Machine's native send staging recognizes this
narrow permission without clearing general allowlists. Petal calls, approve,
transferFrom, opaque calldata and batches gain no exception. Already-created
wallets require an owner-reviewed policy/session change; no existing authority
is widened silently. Other supported native scopes can still select recipients
explicitly. Locking, rearm, retries and revocation retain their existing rules.
