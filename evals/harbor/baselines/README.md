# Default Petal agent baseline

One trial per task and agent on Bloom master 83a94b82 with optimized services, run 2026-10-25 and reviewed by hand. Petals are the pinned releases: Hyperliquid v0.1.7, Polymarket v0.1.6 and NEAR Intents v0.1.4. Input tokens include cached input.

| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| solana-transfer | codex | 1 | 11 | 307,432 / 280,576 | 2,319 | 85 |
| solana-transfer | claude | 1 | 15 | 646,661 / 615,951 | 4,620 | 116 |
| solana-transfer | opencode | 1 | 17 | 319,681 / 296,448 | 2,066 | 95 |
| hyperliquid-order-proposal | codex | 0 | 19 | 840,326 / 780,288 | 6,696 | 248 |
| hyperliquid-order-proposal | claude | 0 | 58 | 3,559,412 / 3,415,816 | 52,631 | 829 |
| hyperliquid-order-proposal | opencode | 1 | 52 | 1,554,362 / 1,472,256 | 4,946 | 355 |
| polymarket-clarification | codex | 0 | 14 | 494,627 / 443,904 | 4,223 | 175 |
| polymarket-clarification | claude | 1 | 13 | 533,128 / 497,702 | 4,265 | 113 |
| polymarket-clarification | opencode | 1 | 35 | 703,127 / 641,536 | 3,800 | 173 |

The Polymarket and NEAR proposal prompts were changed after this run to give only the facts a user would. Their trials will be added when rerun.

## What the trials show

Native Solana took 11 to 17 tool calls. Petal tasks took 43 to 66 when they succeeded, because agents had to work out request formats and failures that Bloom did not show them:

- **Petal write errors never reach the agent.** A rejected write to a mounted Petal file still reports success. Agents retried blind or misdiagnosed the cause; Codex blamed Polymarket onboarding. [bloom#371](https://github.com/bloom-directory/bloom/issues/371)
- **Hyperliquid owner orders have no documented format.** Codex wrote a flat order and stopped. Claude Code guessed for 58 calls. OpenCode read the Petal's source on GitHub. [hyperliquid#28](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/28)
- **Hyperliquid accepts a stale nonce.** Claude Code supplied a 2024 nonce, and the Petal staged an approval the venue would reject, so the trial scores 0. [hyperliquid#29](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/29)
- **Polymarket's `new` help omits `limit_price` and `order_type`.** With the earlier prompt, two of three agents wrote a marketable order instead of a resting one. [polymarket#24](https://github.com/bloom-directory/bloom-petal-polymarket/issues/24)
- **NEAR's help omits base units and the confirm steps.** With the earlier prompt, agents sent 1 base unit instead of 1 USDC, and one confirmed past staging. [near#13](https://github.com/bloom-directory/bloom-petal-near/issues/13)
- **Agents scan balances and status before acting or asking.** Codex never asked which market. The others asked only after 13 to 35 calls. [bloom#372](https://github.com/bloom-directory/bloom/issues/372)
