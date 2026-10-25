# Default Petal agent baseline

in progress: 12 of 24 pairs manually reviewed. Every listed trajectory was manually reviewed after exact-path permission.

| Task | Agent | Assessed/raw reward | Tool calls | Bloom R/W/? | Input/cache tokens | Output + separate reasoning | Harbor/total seconds |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| hyperliquid-order-proposal | codex | 0.0/0.0 | 19 | 9/2/7 | 840326/780288 | 6696 + unknown | 247.83/303.71 |
| hyperliquid-order-proposal | claude | 0/1.0 | 58 | 46/2/6 | 3559412/3415816 | 52631 + unknown | 829.38/884.27 |
| hyperliquid-order-proposal | opencode | 1.0/1.0 | 52 | 29/1/8 | 1554362/1472256 | 4946 + 5889 | 355.25/411.71 |
| near-intents-swap-proposal | codex | 0/None | 9 | 7/1/1 | 322904/282112 | 3406 + unknown | 106.60/214.88 |
| near-intents-swap-proposal | claude | 0.0/0.0 | 47 | 33/2/10 | 2005216/1948507 | 12742 + unknown | 316.34/382.81 |
| near-intents-swap-proposal | opencode | 1.0/1.0 | 43 | 28/3/1 | 2018205/1940352 | 5353 + 3852 | 170.76/241.24 |
| solana-transfer | codex | 1.0/1.0 | 11 | 5/2/4 | 307432/280576 | 2319 + unknown | 85.14/97.22 |
| solana-transfer | claude | 1.0/1.0 | 15 | 11/3/2 | 646661/615951 | 4620 + unknown | 115.66/127.15 |
| solana-transfer | opencode | 1.0/1.0 | 17 | 12/1/4 | 319681/296448 | 2066 + 1029 | 94.88/105.53 |
| polymarket-limit-order-proposal | codex | 0.0/0.0 | 20 | 15/1/3 | 660422/613120 | 5341 + unknown | 245.91/279.56 |
| polymarket-limit-order-proposal | claude | 0.0/0.0 | 30 | 26/2/2 | 1295522/1241103 | 11030 + unknown | 223.33/252.53 |
| polymarket-limit-order-proposal | opencode | 1.0/1.0 | 66 | 42/2/4 | 1893296/1805952 | 6066 + 9627 | 404.76/496.85 |

Tool calls are the common denominator; categories count identifiable attempted calls and can overlap. `?` means Bloom calls with unclassified access. Input includes cached input; cache is shown separately, not added again. Raw usage is preserved in [the JSON](2026-10-25.json). Separate reasoning is reported only where observed through the OpenCode adapter; unknown is not zero. Provider token accounting may differ. Assessed/raw values retain historical grading corrections.

## Reviewed findings

- **hyperliquid-order-proposal/codex** (`hyperliquid-proposal-978cd93e842__8xGPsRr`): Hyperliquid owner-order docs/leaf omit request schema; agent wrote a flat order, mounted write appeared successful but left no approval or actionable diagnostic. Broad reconciliation inflated reads; feedback attempt was blocked read-only.
- **hyperliquid-order-proposal/claude** (`hyperliquid-proposal-04834b26ee8__RzVL5LS`): Petal accepted a years-stale explicit nonce after repeated schema guesses; final report misdescribed exact approval as reusable. Missing schema/error feedback drove 58 tool calls.
- **hyperliquid-order-proposal/opencode** (`hyperliquid-proposal-a0b6b35287f__SGf6epv`): Mounted order help omitted the envelope and last_response reads returned EINVAL; agent fetched GitHub implementation source to discover the schema, costing 52 tool calls. One correct order proposal with fresh implicit nonce.
- **near-intents-swap-proposal/codex** (`near-proposal-0d1599b146cc8779__VrgFzZj`): New-route help shows amount 1 without units; agent sent 1 base unit rather than 1000000 for 1 USDC. Correct assets/recipient, upstream HTTP400, no outbox. Agent reported the failed request as exact 1 USDC.
- **near-intents-swap-proposal/claude** (`near-proposal-db61f082945341cd__sgFcUHz`): Missing unit explanation caused a failed 1-base-unit quote; retry with 1000000 succeeded. Three session-confirm writes after stale prepared reads advanced beyond staging to policy approval_required; combined confirm surface/feedback drove 47 calls.
- **near-intents-swap-proposal/opencode** (`near-proposal-e75acd20569697dc__nwVLPcc`): Mounted docs omit base-unit amounts and confirm transition details; agent fetched GitHub design/source before preparing correctly. Exactly one quote and two confirm writes reached staged state; discovery cost 43 tool calls.
- **solana-transfer/codex** (`solana-codex-271f1ccd3de662e6__N6zy6Rb`): Documented native staging, exact approval retry and receipt flow succeeded in 11 tool calls; one finalized payment.
- **solana-transfer/claude** (`solana-claude-79bdfbd38bc050aa__Qwn6HQR`): Native flow finalized one payment; already-active approval with null ceremony URL caused a brief extra ceremony/passkey discovery detour.
- **solana-transfer/opencode** (`solana-opencode-1198337585430236__QvQ7UGL`): Documented native workflow finalized one payment in 17 tool calls; polled active approval and receipt without restaging.
- **polymarket-limit-order-proposal/codex** (`polymarket-proposal-33e83ade1108__xZNksYC`): Mounted grammar did not distinguish GTC limit_price from marketable max_price; agent omitted limit_price/order_type, which released code defaults to FAK. No draft; final wrongly blamed onboarding. Silent write feedback drove20 calls.
- **polymarket-limit-order-proposal/claude** (`polymarket-proposal-fd8036246969__dsh83U2`): Repeated max_price-only writes omitted limit_price/order_type, selecting the released FAK path; no GTC draft. Silent writes and missing route schema led to an incorrect onboarding diagnosis and one unrelated-market probe.
- **polymarket-limit-order-proposal/opencode** (`polymarket-proposal-524f9c426926__S836pZk`): Initial max_price-only write silently produced no draft; broad diagnostics and external Petal source inspection revealed GTC limit_price/order_type. Corrected one draft after 66 tool calls; mounted schema/error feedback did not explain the omission.

Infrastructure attempts before model actions are retained separately in the JSON; they are not additional scored pairs.
