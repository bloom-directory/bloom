# Signing candidate acceptance

The current five default Petals are Polymarket, Hyperliquid, Enso, NEAR
Intents and Feedback. The detailed historical route inventory is
all-petal-route-coverage-2026-10-19.json; its recorded revisions and limits
remain unchanged. Current implementation/verification is recorded in the
workspace's shared/pm80-clear-signing-verification-2026-10-20.md.

| Petal | Acceptance boundary |
| --- | --- |
| Polymarket | CLOB authentication on begin; deposit-wallet exact batch on continue; installed route/account provenance |
| Hyperliquid | Full delegated action witness reaches host and Broker reconstruction; readable cancellation IDs |
| Enso | Bounded Weiroll reading, exact payload constraints, durable refresh floor; destination status explicitly unverified |
| NEAR Intents | Native/ERC-20 source payload identifies actual sender/network/recipient/amount; destination claims remain unverified |
| Feedback | Installed package has no signing or outbox capability |

Predecessor evidence is preserved at its immutable original commit:

- [Safe candidate, 2026-10-17](https://github.com/bloom-directory/bloom/blob/28b480c3e8f19e3ff53057543d2f84dd0d7d0881/tests/evidence/safe-candidate-2026-10-17.json)
- [Venice login candidate, 2026-10-18](https://github.com/bloom-directory/bloom/blob/28b480c3e8f19e3ff53057543d2f84dd0d7d0881/tests/evidence/venice-login-candidate-2026-10-18.json)

These historical runs do not verify a changed candidate or prove venue
settlement. No funded route is part of decoding acceptance.
