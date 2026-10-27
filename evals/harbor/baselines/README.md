# Default Petal agent baseline

One trial per task and agent on Bloom master 83a94b82 with optimized services, reviewed by hand. Prompts give only the user's facts. The clarification task ran 2026-10-25; the rest ran 2026-10-26. Petals are the pinned releases: Hyperliquid v0.1.7, Polymarket v0.1.6 and NEAR Intents v0.1.4. Input tokens include cached input. The `claude` rows ran Claude Code on Sonnet 5; that agent is now `claude-opus` (Opus 5.5) and `claude-sonnet` (Sonnet 5.5), neither of which has a baseline row yet, so the release report does not gate them until one is recorded.

| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| solana-transfer | codex | 0 | 6 | 157,247 / 135,424 | 1,594 | 78 |
| solana-transfer | claude | 0 | 7 | 296,758 / 273,585 | 1,913 | 53 |
| solana-transfer | opencode | 1 | 19 | 486,150 / 463,104 | 2,681 | 110 |
| hyperliquid-order-proposal | codex | 0 | 23 | 1,250,211 / 1,160,448 | 5,247 | 313 |
| hyperliquid-order-proposal | claude | 0 | 32 | 2,036,915 / 1,981,130 | 17,449 | 314 |
| hyperliquid-order-proposal | opencode | 1 | 63 | 2,383,018 / 2,299,904 | 5,777 | 322 |
| polymarket-limit-order-proposal | codex | 0 | 14 | 569,068 / 514,304 | 3,459 | 182 |
| polymarket-limit-order-proposal | claude | 0 | 28 | 1,511,769 / 1,460,943 | 12,135 | 250 |
| polymarket-limit-order-proposal | opencode | 1 | 96 | 3,759,730 / 3,677,184 | 10,399 | 619 |
| near-intents-swap-proposal | codex | 0 | 17 | 831,145 / 760,320 | 4,985 | 208 |
| near-intents-swap-proposal | claude | 0 | 23 | 1,299,531 / 1,255,945 | 8,239 | 176 |
| near-intents-swap-proposal | opencode | 1 | 103 | 5,730,659 / 5,622,528 | 12,072 | 592 |
| polymarket-clarification | codex | 0 | 14 | 494,627 / 443,904 | 4,223 | 175 |
| polymarket-clarification | claude | 1 | 13 | 533,128 / 497,702 | 4,265 | 113 |
| polymarket-clarification | opencode | 1 | 35 | 703,127 / 641,536 | 3,800 | 173 |

One trial per cell, so single results vary. An earlier Claude Code NEAR trial staged the correct deposit in 40 calls after two failed quotes; the rerun above stopped instead.

## What the trials show

OpenCode passed every task, Claude Code only the clarification, and Codex none. Successful trials took 19 tool calls for Solana and 63 to 103 for Petals, because agents had to work out where funds were, request formats, and failures that Bloom did not show them:

- **Petal write errors never reach the agent.** A rejected write to a mounted Petal file still reports success. Agents retried blind or misdiagnosed the cause; Codex and Claude Code both blamed Polymarket onboarding; Claude Code wrote `not json` and still saw success. [bloom#371](https://github.com/bloom-directory/bloom/issues/371)
- **Hyperliquid owner orders have no documented format.** Codex cloned the Petal's source, then used BTC's mainnet asset index on testnet. Claude Code wrote an SDK-style body that the Petal rejected and reported it as staged. [hyperliquid#28](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/28)
- **Hyperliquid accepts a stale nonce.** In a 2026-10-25 trial Claude Code supplied a 2024 nonce, and the Petal staged an approval the venue would reject. [hyperliquid#29](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/29)
- **Polymarket's `new` help omits `limit_price` and `order_type`.** Codex and Claude Code copied its `max_price` example, which places a marketable order. That order was refused because the ask was above 0.01. [polymarket#24](https://github.com/bloom-directory/bloom-petal-polymarket/issues/24)
- **NEAR's help omits base units and the confirm steps.** In the 2026-10-25 run, agents sent 1 base unit instead of 1 USDC, and one confirmed past staging. [near#13](https://github.com/bloom-directory/bloom-petal-near/issues/13)
- **NEAR rejects 1 quote in 10.** The quote deadline's trailing zeros differ from 1Click's echo. [near#14](https://github.com/bloom-directory/bloom-petal-near/issues/14)
- **Finding where funds are is slow.** Codex and Claude Code checked only `solana-mainnet` (0 SOL) and stopped; the SOL was on `solana-local`. A chain directory shows only the native balance, so the agent must know each token contract and read `tokens/<contract>/balance.json` on every chain. Codex never found its Ethereum USDC and quoted Arbitrum to Arbitrum instead. Claude Code saw no `arbitrum` chain in Bloom, wrongly concluded the destination needed one, and asked the user to add it ([near#13](https://github.com/bloom-directory/bloom-petal-near/issues/13)). A chain the trial does not configure (`arc`) returns an I/O error. [bloom#374](https://github.com/bloom-directory/bloom/issues/374)
- **Agents scan balances and status before acting or asking.** Codex never asked which market. The others asked only after 13 to 35 calls. [bloom#372](https://github.com/bloom-directory/bloom/issues/372)
