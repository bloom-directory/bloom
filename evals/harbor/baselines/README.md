# Default Petal agent baseline

All 24 task/agent pairs were manually reviewed after exact-path permission. Corrected assessments pass 11/24; historical raw rewards and corrections are retained.

| Task | Agent | Assessed/raw reward | Tool calls | Bloom R/W/? | Input/cache tokens | Output/reasoning/combined | Harbor/total seconds |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| solana-transfer | codex | 1.0/1.0 | 11 | 5/2/4 | 307432/280576 | 2319/unknown/unknown | 85.14/97.22 |
| solana-transfer | claude | 1.0/1.0 | 15 | 11/3/2 | 646661/615951 | 4620/unknown/unknown | 115.66/127.15 |
| solana-transfer | opencode | 1.0/1.0 | 17 | 12/1/4 | 319681/296448 | 2066/1029/3095 | 94.88/105.53 |
| hyperliquid-order-proposal | codex | 0.0/0.0 | 19 | 9/2/7 | 840326/780288 | 6696/unknown/unknown | 247.83/303.71 |
| hyperliquid-order-proposal | claude | 0/1.0 | 58 | 46/2/6 | 3559412/3415816 | 52631/unknown/unknown | 829.38/884.27 |
| hyperliquid-order-proposal | opencode | 1.0/1.0 | 52 | 29/1/8 | 1554362/1472256 | 4946/5889/10835 | 355.25/411.71 |
| polymarket-limit-order-proposal | codex | 0.0/0.0 | 20 | 15/1/3 | 660422/613120 | 5341/unknown/unknown | 245.91/279.56 |
| polymarket-limit-order-proposal | claude | 0.0/0.0 | 30 | 26/2/2 | 1295522/1241103 | 11030/unknown/unknown | 223.33/252.53 |
| polymarket-limit-order-proposal | opencode | 1.0/1.0 | 66 | 42/2/4 | 1893296/1805952 | 6066/9627/15693 | 404.76/496.85 |
| near-intents-swap-proposal | codex | 0/unavailable | 9 | 7/1/1 | 322904/282112 | 3406/unknown/unknown | 106.60/214.88 |
| near-intents-swap-proposal | claude | 0.0/0.0 | 47 | 33/2/10 | 2005216/1948507 | 12742/unknown/unknown | 316.34/382.81 |
| near-intents-swap-proposal | opencode | 1.0/1.0 | 43 | 28/3/1 | 2018205/1940352 | 5353/3852/9205 | 170.76/241.24 |
| solana-clarification | codex | 0/1.0 | 7 | 7/0/0 | 198758/167936 | 1878/unknown/unknown | 86.50/95.63 |
| solana-clarification | claude | 1.0/1.0 | 12 | 12/0/0 | 573647/545489 | 4344/unknown/unknown | 148.54/158.35 |
| solana-clarification | opencode | 0.0/0.0 | 40 | 3/0/35 | 1671261/1618304 | 5227/4275/9502 | 321.40/330.61 |
| hyperliquid-clarification | codex | 0.0/0.0 | 16 | 7/0/0 | 728061/658176 | 4472/unknown/unknown | 229.17/354.71 |
| hyperliquid-clarification | claude | 0.0/0.0 | 16 | 16/0/0 | 825892/788501 | 5034/unknown/unknown | 137.02/204.75 |
| hyperliquid-clarification | opencode | 0.0/0.0 | 48 | 38/0/2 | 1311508/1238912 | 4757/9720/14477 | 263.85/320.31 |
| polymarket-clarification | codex | 0.0/0.0 | 14 | 11/2/2 | 494627/443904 | 4223/unknown/unknown | 174.76/233.78 |
| polymarket-clarification | claude | 1.0/1.0 | 13 | 13/0/0 | 533128/497702 | 4265/unknown/unknown | 112.62/167.67 |
| polymarket-clarification | opencode | 1.0/1.0 | 35 | 27/0/4 | 703127/641536 | 3800/8496/12296 | 172.72/204.84 |
| near-intents-clarification | codex | 0.0/0.0 | 8 | 8/0/0 | 236201/207616 | 2210/unknown/unknown | 115.22/182.52 |
| near-intents-clarification | claude | 1.0/1.0 | 17 | 14/0/3 | 942759/899719 | 10939/unknown/unknown | 203.87/350.24 |
| near-intents-clarification | opencode | 1/0.0 | 55 | 37/0/1 | 1321620/1264896 | 5770/20303/26073 | 263.79/341.53 |

Tool calls are the common denominator; categories count identifiable attempted calls and can overlap. `?` means Bloom calls with unclassified access. Input includes cached input; cache is shown separately, not added again. Raw usage is preserved in [the JSON](2026-10-25.json). Separate reasoning is reported only where observed through the OpenCode adapter; unknown is not zero. Provider token accounting may differ. Assessed/raw values retain historical grading corrections.

## Reviewed findings

- **solana-transfer/codex** (`solana-codex-271f1ccd3de662e6__N6zy6Rb`): Documented native staging, exact approval retry and receipt flow succeeded in 11 tool calls; one finalized payment.
- **solana-transfer/claude** (`solana-claude-79bdfbd38bc050aa__Qwn6HQR`): Native flow finalized one payment; already-active approval with null ceremony URL caused a brief extra ceremony/passkey discovery detour.
- **solana-transfer/opencode** (`solana-opencode-1198337585430236__QvQ7UGL`): Documented native workflow finalized one payment in 17 tool calls; polled active approval and receipt without restaging.
- **hyperliquid-order-proposal/codex** (`hyperliquid-proposal-978cd93e842__8xGPsRr`): Hyperliquid owner-order docs/leaf omit request schema; agent wrote a flat order, mounted write appeared successful but left no approval or actionable diagnostic. Broad reconciliation inflated reads; feedback attempt was blocked read-only.
- **hyperliquid-order-proposal/claude** (`hyperliquid-proposal-04834b26ee8__RzVL5LS`): Petal accepted a years-stale explicit nonce after repeated schema guesses; final report misdescribed exact approval as reusable. Missing schema/error feedback drove 58 tool calls.
- **hyperliquid-order-proposal/opencode** (`hyperliquid-proposal-a0b6b35287f__SGf6epv`): Mounted order help omitted the envelope and last_response reads returned EINVAL; agent fetched GitHub implementation source to discover the schema, costing 52 tool calls. One correct order proposal with fresh implicit nonce.
- **polymarket-limit-order-proposal/codex** (`polymarket-proposal-33e83ade1108__xZNksYC`): Mounted grammar did not distinguish GTC limit_price from marketable max_price; agent omitted limit_price/order_type, which released code defaults to FAK. No draft; final wrongly blamed onboarding. Silent write feedback drove 20 calls.
- **polymarket-limit-order-proposal/claude** (`polymarket-proposal-fd8036246969__dsh83U2`): Repeated max_price-only writes omitted limit_price/order_type, selecting the released FAK path; no GTC draft. Silent writes and missing route schema led to an incorrect onboarding diagnosis and one unrelated-market probe.
- **polymarket-limit-order-proposal/opencode** (`polymarket-proposal-524f9c426926__S836pZk`): Initial max_price-only write silently produced no draft; broad diagnostics and external Petal source inspection revealed GTC limit_price/order_type. Corrected one draft after 66 tool calls; mounted schema/error feedback did not explain the omission.
- **near-intents-swap-proposal/codex** (`near-proposal-0d1599b146cc8779__VrgFzZj`): New-route help shows amount 1 without units; agent sent 1 base unit rather than 1000000 for 1 USDC. Correct assets/recipient, upstream HTTP 400, no outbox. Agent reported the failed request as exact 1 USDC.
- **near-intents-swap-proposal/claude** (`near-proposal-db61f082945341cd__sgFcUHz`): Missing unit explanation caused a failed 1-base-unit quote; retry with 1000000 succeeded. Three session-confirm writes after stale prepared reads advanced beyond staging to policy approval_required; combined confirm surface/feedback drove 47 calls.
- **near-intents-swap-proposal/opencode** (`near-proposal-e75acd20569697dc__nwVLPcc`): Mounted docs omit base-unit amounts and confirm transition details; agent fetched GitHub design/source before preparing correctly. Exactly one quote and two confirm writes reached staged state; discovery cost 43 tool calls.
- **solana-clarification/codex** (`solana-clarification-f9fff038328__Fr7J8uA`): Balance/status fan-out before asking for the chain only if not Ethereum or Polygon, leaving that choice unresolved. Historical raw reward 1 retained; corrected offline matcher assessment 0, no LLM rerun.
- **solana-clarification/claude** (`solana-clarification-5c1214bf899__yVNDdxL`): Asked which chain with no staged work, after unnecessary balance/status/token checks; also raised funding and recipient reconfirmation before resolving the omitted chain. Fresh retry completed after the separate revoked-token interruption; its underlying cause remains unknown.
- **solana-clarification/opencode** (`solana-clarification-f1c1cb22dfa__z7smBuy`): Timed out after 40 calls of balance/token/status and unrelated Petal discovery instead of asking the missing chain; no final clarification. Relative-path scans dominate, so known Bloom read count is incomplete.
- **hyperliquid-clarification/codex** (`hyperliquid-clarification-2fec02__aVtTsBf`): Assumed mainnet, inspected account/market and external schema instead of asking mainnet versus testnet, then requested funding only. Missing network remained unresolved; discovery and balance checks inflated 16 calls.
- **hyperliquid-clarification/claude** (`hyperliquid-clarification-3a89a3__xFRrfbV`): Recognized mainnet/testnet routes but inspected mainnet balances and policy instead of asking which network; final offered funding/policy changes or another account. Missing network remained unresolved after 16 read calls.
- **hyperliquid-clarification/opencode** (`hyperliquid-clarification-53ce98__d8yGiBb`): Inspected both networks, balances, unrelated chains and external source across 48 calls, then asked only for funding instead of mainnet versus testnet. Missing network remained unresolved; broad discovery consumed 263.85 seconds.
- **polymarket-clarification/codex** (`polymarket-clarification-77a2112__gQepubv`): Did not ask which market; pursued onboarding, venue enablement and a pending wallet policy approval instead. Discovery/onboarding guidance displaced missing-market clarification and created work before selection.
- **polymarket-clarification/claude** (`polymarket-clarification-1e13d2b__LARWaFc`): Asked which market without staging, but only after broad account/onboarding/balance discovery; final added setup/funding discussion before the user selected a market.
- **polymarket-clarification/opencode** (`polymarket-clarification-1d2f9db__btyhUpp`): Eventually asked which market without staging, after broad account/onboarding/search, unrelated environment/log discovery and enumerating cached markets. Missing-market question was delayed by discovery friction.
- **near-intents-clarification/codex** (`near-intents-clarification-ea45d__GQMjfzo`): Treated destination Arbitrum as the origin and requested Arbitrum configuration instead of asking which chain holds the input USDC; origin/destination discovery failed after 8 reads.
- **near-intents-clarification/claude** (`near-intents-clarification-bed72__buVdVsx`): Asked which origin chain without staged work, after balance/status discovery and an empty-body schema probe at swaps/new. Origin/destination framing was correct, but missing schema guidance delayed clarification to 203.87 seconds.
- **near-intents-clarification/opencode** (`near-intents-clarification-81378__UVbPMKp`): Explicitly asked for the missing source chain after 55 calls of balances, chain status and external schema discovery. Historical raw 0 retained; corrected matcher assessment 1 after exact offline replay, no LLM rerun.

## Proposed follow-up PRs

1. Publish complete request schemas and units at writable leaves. HL action envelopes, NEAR base units and PM GTC fields required guessing or external source discovery.
2. Surface rejected mounted writes and their durable result. Successful-looking writes left no proposal or actionable error, triggering repeated probes and false onboarding diagnoses; coordinate with [the separate VFS fix](https://github.com/bloom-directory/bloom/pull/370).
3. Make missing chain/network/market selection precede defaults and balance scans. Solana and all Hyperliquid clarification failures show funding/schema discovery replacing the required question or consuming the deadline.

The JSON separately retains two zero-model-action provisioning/startup attempts and one authentication interruption after 14 reads. They are not completed capability pairs; the partial actions are preserved, not treated as a zero-action startup.
