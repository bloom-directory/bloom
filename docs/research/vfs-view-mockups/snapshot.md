# Bloom · fictional example snapshot

Snapshot: example-20260905-1700 · 2026-09-05T17:00:00Z

**No wallet connected. No live prices. No actions execute.**

Observed priced wallet value: **$13,303.00**. One unpriced asset is excluded. Mixed observation times; Solana read delayed.

## Needs you

### Review 100 USDC to Sam (needs)
Your Base transfer is prepared. Nothing has been sent. Check the recipient and estimated fee before continuing in Bloom’s approval ceremony.
Evidence: Canonical staged transfer · example approval expires 17:10 UTC
[Context](send.html)

### Your Morpho deposit is paused (needs)
The token approval completed; the 50 USDC deposit did not start. Refresh the deposit review if you still want to continue. Do not repeat the completed approval.
Evidence: Morpho action + outbox · definite no-signature refusal for deposit
[Context](activity.html#morpho)

### A prediction position may be ready to redeem (optional)
The example provider marks an $80 position redeemable. Refresh ownership and the supported redemption route before preparing anything. It is already included in your wallet value.
Evidence: Polymarket fixture · valuation adapter proposed
[Context](portfolio.html#positions)

## Tokens by illustrative 24h market volume

| Token | Price | 24h change | Volume |
| --- | ---: | ---: | ---: |
| Ethereum | $3,000.00 | +4.20% | $12.0B |
| USD Coin | $1.00 | +0.01% | $7.0B |
| Solana | $150.00 | +6.80% | $5.0B |
| Hyperliquid | $25.00 | -2.10% | $1.0B |

## Chains by illustrative completed-day DEX volume

| Chain | Volume | Your assets |
| --- | ---: | ---: |
| Ethereum | $3.0B | $7,050.00 |
| Solana | $2.0B | $1,500.00 |
| Base | $1.0B | $1,003.00 |
| Arbitrum | $0.5B | $250.00 |

Robinhood volume: not covered. Its $1,000 wallet value remains included.

## Holdings

| Asset | Quantity | Scope | Value |
| --- | --- | --- | ---: |
| Ethereum | 2 ETH | Ethereum | $6,000.00 |
| Ethereum | 0.001 ETH | Base | $3.00 |
| USD Coin | 50 USDC | Ethereum | $50.00 |
| USD Coin | 1,000 USDC | Base | $1,000.00 |
| USD Coin | 250 USDC | Arbitrum | $250.00 |
| Solana | 10 SOL | Solana | $1,500.00 |
| Morpho vault | Underlying claim | Ethereum | $1,000.00 |
| Hyperliquid account | Account equity | Hyperliquid | $2,100.00 |
| Prediction account | $150 cash + $250 positions | Polymarket | $400.00 |
| Apple stock token | 5 AAPL tokens | Robinhood | $1,000.00 |
| Unidentified token | 25 units | Base | Not priced |

## Sources and coverage

- Illustrative CoinGecko-style market data: partial. 4 eligible tokens of 5 in this example subset; not a global ranking. Source time 2026-09-05T16:59:00Z; 24 hours ending 2026-09-05T16:59:00Z.
- Illustrative DefiLlama-style DEX data: partial. 4 covered chains of 5 in this example; Robinhood not covered. Source time 2026-09-05T00:00:00Z; 2026-09-04T00:00:00Z to 2026-09-05T00:00:00Z.
- Illustrative native and Petal observations: partial. 10 priced rows; 1 unpriced item; private pool value and Venice credit excluded. Source time 2026-09-05T16:58:00Z; Point observations between 16:58 and 17:00 UTC.

Prototype support: [Receive](receive.html), [Transfer review](send.html), [Activity](activity.html), [Access](permissions.html), [Empty and failure states](states.html).
