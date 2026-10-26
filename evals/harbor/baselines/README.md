# Default Petal agent baseline

One trial per task and agent on Bloom master 83a94b82 with optimized services, reviewed by hand. The Polymarket and NEAR proposals ran 2026-10-26 at 45c16784; the rest ran 2026-10-25. Petals are the pinned releases: Hyperliquid v0.1.7, Polymarket v0.1.6 and NEAR Intents v0.1.4. Input tokens include cached input.

| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| solana-transfer | codex | 1 | 11 | 307,432 / 280,576 | 2,319 | 85 |
| solana-transfer | claude | 1 | 15 | 646,661 / 615,951 | 4,620 | 116 |
| solana-transfer | opencode | 1 | 17 | 319,681 / 296,448 | 2,066 | 95 |
| hyperliquid-order-proposal | codex | 0 | 19 | 840,326 / 780,288 | 6,696 | 248 |
| hyperliquid-order-proposal | claude | 0 | 58 | 3,559,412 / 3,415,816 | 52,631 | 829 |
| hyperliquid-order-proposal | opencode | 1 | 52 | 1,554,362 / 1,472,256 | 4,946 | 355 |
| polymarket-limit-order-proposal | codex | 0 | 14 | 569,068 / 514,304 | 3,459 | 182 |
| polymarket-limit-order-proposal | claude | 0 | 28 | 1,511,769 / 1,460,943 | 12,135 | 250 |
| polymarket-limit-order-proposal | opencode | 1 | 96 | 3,759,730 / 3,677,184 | 10,399 | 619 |
| near-intents-swap-proposal | codex | 0 | 17 | 831,145 / 760,320 | 4,985 | 208 |
| near-intents-swap-proposal | claude | 1* | 40 | 2,800,900 / 2,726,867 | 23,706 | 391 |
| near-intents-swap-proposal | opencode | 1 | 103 | 5,730,659 / 5,622,528 | 12,072 | 592 |
| polymarket-clarification | codex | 0 | 14 | 494,627 / 443,904 | 4,223 | 175 |
| polymarket-clarification | claude | 1 | 13 | 533,128 / 497,702 | 4,265 | 113 |
| polymarket-clarification | opencode | 1 | 35 | 703,127 / 641,536 | 3,800 | 173 |

\* Scored 0 when run, because the verifier then required a single swap session. Claude's first two quotes failed (one on near#14), so it retried, and its third session staged the correct deposit. The verifier now ignores failed and abandoned sessions. This trial was regraded by hand, not replayed.

## What the trials show

Native Solana took 11 to 17 tool calls. Successful Petal tasks took 40 to 103, because agents had to work out request formats and failures that Bloom did not show them:

- **Petal write errors never reach the agent.** A rejected write to a mounted Petal file still reports success. Agents retried blind or misdiagnosed the cause; Codex and Claude Code both blamed Polymarket onboarding; Claude Code wrote `not json` and still saw success. [bloom#371](https://github.com/bloom-directory/bloom/issues/371)
- **Hyperliquid owner orders have no documented format.** Codex wrote a flat order and stopped. Claude Code guessed for 58 calls. OpenCode read the Petal's source on GitHub. [hyperliquid#28](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/28)
- **Hyperliquid accepts a stale nonce.** Claude Code supplied a 2024 nonce, and the Petal staged an approval the venue would reject, so the trial scores 0. [hyperliquid#29](https://github.com/bloom-directory/bloom-petal-hyperliquid/issues/29)
- **Polymarket's `new` help omits `limit_price` and `order_type`.** Codex and Claude Code copied its `max_price` example, which places a marketable order. That order was refused because the ask was above 0.01. [polymarket#24](https://github.com/bloom-directory/bloom-petal-polymarket/issues/24)
- **NEAR's help omits base units and the confirm steps.** In the 2026-10-25 run, agents sent 1 base unit instead of 1 USDC, and one confirmed past staging. [near#13](https://github.com/bloom-directory/bloom-petal-near/issues/13)
- **NEAR rejects 1 quote in 10.** The quote deadline's trailing zeros differ from 1Click's echo. [near#14](https://github.com/bloom-directory/bloom-petal-near/issues/14)
- **Finding where funds are is slow.** A chain directory shows only the native balance, so the agent must know each token contract and read `tokens/<contract>/balance.json` on every chain. Codex never found its Ethereum USDC and quoted Arbitrum to Arbitrum instead. A chain the trial does not configure (`arc`) returns an I/O error.
- **Agents scan balances and status before acting or asking.** Codex never asked which market. The others asked only after 13 to 35 calls. [bloom#372](https://github.com/bloom-directory/bloom/issues/372)
