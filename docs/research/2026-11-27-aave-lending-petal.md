# Research: an Aave v3 lending Petal, and Push by Aave Labs

**Date:** 2026-11-27
**Status:** research note, not a design decision. Nothing here is implemented.
**Audience:** whoever scopes `bloom-petal-aave`.

This note answers two questions. Can Bloom expose Aave v3 lending as a Petal
in the same shape as the existing Morpho Petal, and can Bloom integrate with
Push, Aave Labs' Euro-to-stablecoin ramp. The short answers: yes, cleanly, by
copying the Morpho Petal's trust boundary; and not through any API today,
because Push has no public developer surface and its customer agreement is
written for a natural person tapping buttons in the Aave iOS app.

Sources are linked inline. Facts marked *(verified live)* were checked against
the public Aave GraphQL endpoint or the Push website on the date above. Facts
marked *(not verified)* could not be confirmed and need checking before they
carry weight.

---

## 1. What Aave offers an integrator

### 1.1 The public GraphQL API

`https://api.v3.aave.com/graphql` is a public GraphQL endpoint and playground
([docs](https://aave.com/docs/aave-v3/getting-started/graphql)). The bare
root URL returns an empty 200. No API key or sign-in is needed *(verified
live: unauthenticated POSTs succeed)*. There is no mutation type; every
operation, including transaction building, is a GraphQL `query`
*(verified live via introspection)*.

Operations relevant to a lending Petal *(verified live)*:

| Purpose | Query |
|---|---|
| Discovery | `chains`, `markets`, `market`, `reserve`, `usdExchangeRates`, `supplyAPYHistory`, `borrowAPYHistory` |
| Positions | `userSupplies`, `userBorrows`, `userMarketState`, `userTransactionHistory`, `userRewards` |
| Transaction building | `supply`, `withdraw`, `borrow`, `repay`, `collateralToggle`, `userSetEmode`, `approveBorrowCreditDelegation`, `permitTypedData` |
| Safety | `healthFactorPreview`, `hasProcessedKnownTransaction`, `creditDelegateeAllowance` |

Request shapes *(verified live via introspection)*:

- `SupplyRequest`, `BorrowRequest`, `RepayRequest`: `market` (EvmAddress),
  `amount`, `sender`, optional `onBehalfOf`, `chainId`.
- `WithdrawRequest`: `market`, `amount`, `sender`, optional `recipient`,
  `chainId`.
- `amount` is `{ erc20: { currency, value: { exact | max } } }` or
  `{ native: ... }`. Repay and withdraw accept `max: true`
  ([repay](https://aave.com/docs/aave-v3/markets/repay.md),
  [withdraw](https://aave.com/docs/aave-v3/markets/withdraw.md)).
- The `market` argument is the Pool proxy address. For Base the API reports
  `AaveV3Base` at `0xA238Dd80C259a72e81d7e4664a9801593F98d1c5`, which is the
  Pool in the address book *(verified live, see 1.3)*.

Every transaction builder returns the union `ExecutionPlan`:

- `TransactionRequest { to, from, data, value, chainId, operation }` *(verified
  live)*. This is exactly the shape of `bloom:tx/outbox` `evm-transaction`
  (`to`, `value-wei`, `data-hex`), so the API output drops into Bloom's outbox
  without transformation.
- `ApprovalRequired { approval, originalTransaction, reason, requiredAmount,
  currentAllowance }`. The client sends `approval` first and
  `originalTransaction` after it mines. This is the same two-step sequence the
  Morpho and Enso Petals already implement.
- `InsufficientBalanceError { required, available }`.

Permit path: reserves expose `permitSupported` and `permitTypedData` returns
EIP-712 typed data so supply or repay can run as one transaction. Signing
EIP-712 would require `bloom:sign` and a signing intent. The Morpho Petal
deliberately declares no `bloom:sign`; a first Aave release should do the
same and accept the extra approval transaction.

Chains *(verified live)*: 22 markets. Mainnets: Ethereum (1), Arbitrum (42161),
Avalanche (43114), Base (8453), BSC (56), Celo, Gnosis (100), Linea, Metis,
Optimism (10), Polygon (137), Scroll, Soneium, Sonic, zkSync, Plasma, Ink,
Mantle, MegaETH, X Layer, Monad. One testnet: Base Sepolia (84532). The
intersection with Bloom's built-in chain registry
(`crates/bloom-proto/src/config.rs`, `default_chains`) is Ethereum, Base,
Arbitrum, Optimism, Polygon, BSC, Avalanche, Gnosis and Linea. Base Sepolia would need a
chain entry before it can serve as an acceptance environment.

Not verified: rate limits (none documented), the `@aave/client` npm licence
(npm returned 403), and the full Aave MCP tool inventory (its tools page 404s).

### 1.2 Pool contract surface

From the [Pool docs](https://aave.com/docs/aave-v3/smart-contracts/pool.md):

```solidity
supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)
withdraw(address asset, uint256 amount, address to) returns (uint256)
borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)
repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) returns (uint256)
repayWithATokens(address asset, uint256 amount, uint256 interestRateMode) returns (uint256)
setUserUseReserveAsCollateral(address asset, bool useAsCollateral)
setUserEMode(uint8 categoryId)
getUserAccountData(address user) view returns (totalCollateralBase, totalDebtBase, availableBorrowsBase, currentLiquidationThreshold, ltv, healthFactor)
```

Points that constrain a Petal:

- `interestRateMode` must be `2` (variable). Stable rate is gone.
- `supply` and `repay` need an ERC-20 allowance on the Pool;
  `supplyWithPermit` and `repayWithPermit` exist but need EIP-712.
- `withdraw` and `repay` accept `type(uint256).max` for "all".
- The Pool is a proxy. The docs say to resolve it from
  `PoolAddressesProvider.getPool()` rather than hard-coding it.
- `POOL_REVISION()` is 10 on V3.6 and 11 on V3.7; isolation mode was removed
  in V3.7 and `isInIsolationMode` is deprecated in the API
  ([overview](https://aave.com/docs/aave-v3/overview.md)).
- Native ETH goes through a `WrappedTokenGateway`, with a separate
  credit-delegation approval for native borrows. A first release can require
  WETH and skip the gateway.

### 1.3 Canonical addresses

The address book is
[bgd-labs/aave-address-book](https://github.com/bgd-labs/aave-address-book)
*(fetched from `main` on the date above)*:

| Market | PoolAddressesProvider | Pool |
|---|---|---|
| Ethereum | `0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e` | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` |
| Base | `0xe20fCBdBfFC4Dd138cE8b2E6FBb6CB49777ad64D` | `0xA238Dd80C259a72e81d7e4664a9801593F98d1c5` |
| Arbitrum | `0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb` | `0x794a61358D6845594F94dc1DB02A252b5b4814aD` |
| Base Sepolia | `0xE4C23309117Aa30342BFaae6c95c6478e0A4Ad00` | `0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27` |

A Petal should pin the **PoolAddressesProvider** per chain id (the way the
Morpho Petal pins factories in `deployment.rs`) and read `getPool()` at
runtime, failing closed on an unknown chain id.

### 1.4 Risk checks the docs require before a write

- Supply: reserve not `isFrozen` or `isPaused`, `userState.suppliable > 0`,
  `supplyInfo.supplyCapReached` false
  ([supply](https://aave.com/docs/aave-v3/markets/supply.md)).
- Borrow: same frozen/paused checks, `userState.borrowable.amount.value > 0`,
  `borrowInfo.borrowCapReached` false
  ([borrow](https://aave.com/docs/aave-v3/markets/borrow.md)).
- Health factor below 1 is liquidatable; at or below 0.95 the whole debt is
  liquidatable. HF is `null` until the user has a borrow
  ([health factor](https://aave.com/docs/aave-v3/markets/health-factor.md)).
- `healthFactorPreview` returns `before` and `after` for a proposed supply,
  borrow, repay or withdraw. The MCP docs say to never skip the preview before
  a borrow or withdraw ([mcp](https://aave.com/docs/mcp.md)).
- Disabling collateral or withdrawing reverts on-chain if it would drop HF
  below the threshold, so the chain is the final guard, but a Petal should
  refuse earlier with a readable reason.

### 1.5 Terms of service

From [aave.com/terms-of-service](https://aave.com/terms-of-service) (first
40k characters read verbatim, remainder summarised):

- Section 1.4 and 5.4: use through an AI agent is use by the person; they must
  keep spending limits and approval requirements and a way to stop it. Bloom's
  owner-approval outbox is a direct fit.
- Section 7.1: the developer-tools licence is personal and non-commercial;
  commercial use "may require" a separate licence. Whether a Bloom catalog
  Petal counts needs a decision.
- Section 7.4: API keys may be required and rate limits set in future.
- Section 6(f) and 6(g): automated access only as permitted, no scraping, no
  competing product.
- Section 2.3: a restricted-jurisdiction list applies to the Services.
- Section 9.1: Aave's tools never sign; a proposed transaction takes effect
  only when the user signs it.

---

## 2. How an Aave Petal fits Bloom

### 2.1 Copy the Morpho Petal's trust boundary

`~/Bloom/bloom-petal-morpho` is the template. Its manifest declares
`bloom:http`, `bloom:store`, `bloom:chain`, `bloom:tx.outbox` and
`bloom:vfs.read`, and **no** `bloom:sign`. Deposits and withdrawals are
ordinary EVM transactions staged through the outbox and approved by the owner.
Its README states the rule an Aave Petal should inherit: the indexer supplies
listings and APYs and is never an authority; every value that money depends on
is read from the chain; write targets are authenticated against pinned
official contracts.

Applied to Aave:

- `[[net.allow]]`: `api.v3.aave.com`, `POST`, `/graphql` only.
- Discovery and APYs come from the API. Balances, allowances, decimals,
  `getUserAccountData`, `getReserveData` and the Pool address come from
  `bloom:chain` reads.
- **Calldata is built locally** with `alloy` `sol-types` against the pinned
  provider's `getPool()`, as Morpho does for ERC-4626. The API's
  `TransactionRequest` could be used instead, but then the Petal must decode
  and verify `to`, selector, asset, amount and `onBehalfOf` against the
  caller's request before staging, and the money path becomes dependent on the
  indexer being reachable and honest. Local encoding is less code and a
  smaller trust surface. `healthFactorPreview` stays useful as an advisory
  shown in `plan.md`.
- Approvals are exact-amount, target the Pool, and are sequenced before the
  supply or repay with a mined-success dependency, exactly as Morpho's
  `action.rs` does. USDT-style tokens need the allowance reset step.
- Simulate every step before staging (`eth_call` through `bloom:chain`, as
  Morpho's `erc4626::simulate_transaction` does).

### 2.2 Wallet policy

Machine refuses an outbox transaction whose `to` is not in the wallet policy's
allowed destinations. `crates/bloom-proto/src/petal_destinations.rs` gives
each catalog Petal a `petal:<name>` entry per chain, matched only against what
that Petal staged. An Aave Petal needs `petal:aave` entries on the chains it
supports, and a place in `SETUP_PETALS` if it is to be offered by `bloom
init`. Listing the Pool address itself is wrong for the reason the file
explains: the Pool's `withdraw(asset, amount, to)` can send funds anywhere, so
any staged call to it would pass.

### 2.3 Proposed route tree

Mirrors Morpho so agents already trained on one Petal can operate the other.

```text
/petals/aave/
  status.json                                  indexer health, supported chains
  [chain]/markets/                             reserves with supply/borrow APY, caps, frozen/paused, LTV, LT
  [chain]/markets/[asset].json                 one reserve, from chain + API
  [chain]/positions/[wallet]/[index]/positions.json
                                               supplies, borrows, HF, LTV, LT, availableBorrows, e-mode
  [chain]/actions/[wallet]/[index]/[id]/draft.json    read, write: create a draft
  [chain]/actions/[wallet]/[index]/[id]/plan.md       current step's plan, with HF before/after
  [chain]/actions/[wallet]/[index]/[id]/status.json   steps joined with outbox state
  [chain]/actions/[wallet]/[index]/[id]/confirm       write: confirm the current step
```

Draft body: `{"action": "supply"|"withdraw"|"borrow"|"repay"|"set_collateral",
"asset": "0x...", "amount": "100" | "max", ...}`. Unknown fields and unknown
actions are refused, not defaulted.

### 2.4 Release scoping

Two releases, as Morpho did:

1. **Earn**: `supply`, `withdraw`, `set_collateral`, positions, markets. No
   liquidation risk arises from supply alone unless the account already has
   debt, so the only HF check is on `withdraw` and on disabling collateral.
2. **Borrow**: `borrow`, `repay`, `set_emode`. Add an HF floor in the Petal
   (for example refuse any borrow or withdraw whose previewed `after` HF is
   below a documented minimum such as 1.5 unless the body opts out
   explicitly), liquidation-price reporting per collateral, and a clear
   AGENTS.md warning that variable-rate debt accrues and that the owner must
   watch HF between ceremonies.

Testing: Base Sepolia (84532) is the only Aave testnet. Bloom needs a chain
entry and a faucet-funded account for acceptance. Development signing requires
the Triad developer provenance enrolment described in
`docs/petals/authoring-petals.md`.

---

## 3. Push by Aave Labs

### 3.1 What it is *(verified live from push.co)*

- Operator: **Push Virtual Assets Ireland Limited**, company 751166,
  Dublin. Authorised by the Central Bank of Ireland under MiCA, reference
  C528869, for exchange of crypto-assets for funds and for other
  crypto-assets. Passported across the EEA except Bulgaria
  ([customer agreement](https://www.push.co/user-agreement/eu/ie)).
- Product: buy and sell stablecoins against Euro, no Push fees or spreads,
  Push usually covers gas. Push acts as principal counterparty. Non-custodial:
  stablecoins are delivered to the user's own wallet
  ([home](https://www.push.co/eu/ie), [FAQ](https://www.push.co/faq/eu/ie)).
- Supported asset today: **USDC on Arbitrum only** (FAQ).
- Access today: **the Aave App on iOS only** (FAQ). Live in 17 countries
  (Austria, Belgium, Denmark, Estonia, Finland, France, Germany, Ireland,
  Italy, Latvia, Lithuania, Netherlands, Norway, Poland, Portugal, Spain,
  Sweden), with the rest of the EEA permitted by the agreement.
- Payments: open banking through Plaid B.V. Bank authorisation happens in the
  user's own banking app.
- Onboarding: full KYC including a video "Live Check", tax identification
  number, and a payment account in the user's sole name.

### 3.2 Developer surface

There is none that is public. The agreement's definitions mention "software
development kit (SDK)" and "application programming interfaces (APIs)" as part
of the App, and section 12 defines **Integrators** as third-party
self-custodial wallet applications "that have integrated with Push", naming
only the Aave App. There is no developer page, no docs, no sandbox, no pricing
and no self-serve signup on push.co. Integration is a partnership with Push
Ireland, not an API key.

### 3.3 Terms that constrain an agent-driven integration

- Section 1.1(A) and 1.2(D): the customer must be a natural person acting on
  their own behalf, not for or on behalf of another person.
- Section 3.3: "All instructions in relation to the Push Account must come
  from you as the named account holder."
- Section 3.1: one account per customer, registered through the App.
- Section 4.8: a confirmed buy or sell is irrevocable.
- Unlike Aave's own terms, the Push agreement says nothing about AI agents or
  automated software acting for the customer. An agent staging a fiat
  purchase would be, at best, untested ground under section 3.3.

### 3.4 What Bloom can realistically do with Push

1. **Now: document the manual ramp.** Push delivers USDC on Arbitrum to any
   wallet address the user names. An Aave Petal's AGENTS.md (or a
   `/petals/aave/onramp.md` route) can tell an EEA user to buy USDC in the
   Aave App with the Bloom wallet's `address.evm` as the destination, then
   watch for arrival with Bloom's existing balance watch, then supply it.
   That is the whole "integration" available today and it costs nothing.
2. **Later: ask Aave Labs for Integrator access.** The agreement proves an
   SDK and APIs exist for wallet apps. Bloom is a self-custodial wallet, which
   is exactly the Integrator category. The ask would be for the Bloom owner to
   complete KYC and link a bank in Push's own flow, with Bloom only receiving
   the stablecoins. Even then, the fiat leg (Plaid bank consent, Push
   confirmation) cannot be driven from the VFS, so the Petal would at most
   deep-link or display a Push session for the human to finish.
3. **Not a fit:** a Petal that holds Push credentials and places buy or sell
   orders autonomously. It conflicts with section 3.3, with the natural-person
   eligibility rule, and with Bloom's own rule that wallet-sensitive input
   belongs in a ceremony, not a Petal store.

---

## 4. Open questions before building

- Does a Bloom catalog Petal need a commercial licence under Aave ToS 7.1?
- Should the Petal build calldata locally (recommended) or verify the API's
  `TransactionRequest`? Decide before writing `action.rs`.
- Which chains in release 1? Base and Arbitrum cover the Push ramp (Arbitrum
  USDC) and Bloom's most-used L2.
- Is e-mode in scope for release 2, or deferred? It changes LTV and the
  liquidation threshold for the whole account.
- Does Bloom want a `base-sepolia` chain in the default registry for Petal
  acceptance tests, or only in the dev harness config?

## 5. Pages read

Aave: docs home, llms.txt, getting-started/graphql, getting-started/typescript,
markets/data, markets/supply, markets/borrow, markets/repay,
markets/withdraw, markets/positions, markets/health-factor,
smart-contracts/pool, smart-contracts/pool-addresses-provider, overview,
mcp.md, terms-of-service. Live GraphQL: `chains`, schema introspection,
`markets(chainIds: [8453])`. Address book: `AaveV3Ethereum.sol`,
`AaveV3Base.sol`, `AaveV3Arbitrum.sol`, `AaveV3BaseSepolia.sol`.

Push: push.co/eu/ie, /faq/eu/ie, /legal/eu/ie, /user-agreement/eu/ie.

Bloom: `docs/petals/authoring-petals.md`, `docs/examples-domain/05-defi.md`,
`docs/architecture/Default Wallet Policy.md`,
`crates/bloom-proto/src/petal_destinations.rs`,
`crates/bloom-proto/src/defi_policy.rs`, `crates/bloom-proto/src/config.rs`,
`~/Bloom/petal/wit/route/deps/{tx/outbox,chain/chain,sign-v0.2/sign}.wit`,
`~/Bloom/bloom-petal-morpho` (manifest, README, AGENTS.md, `route/src`).
