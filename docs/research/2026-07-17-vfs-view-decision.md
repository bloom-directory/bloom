# Issue 114: VFS view decision

Status: design audit complete; implementation should proceed behind explicit coverage
and lifecycle contracts.

## Decision

Keep the six proposed views and do not add a generic “portfolio provider” or Petal
protocol yet:

| View | User question | Canonical input |
|---|---|---|
| Portfolio | What do I own, and where? | `PortfolioSnapshot` |
| Next Moves | What needs my attention? | `NextMovesSnapshot` |
| Receive | Where can funds safely arrive? | `ReceiveSnapshot` |
| Send | Who am I paying, and what will be signed? | staged transaction + interpretation |
| Activity | What happened? | canonical lifecycle/evidence projection |
| Permissions & Security | Who can act, and how is my key protected? | authority/custody inventory |

Each view is read-only and server-owned. JSON is the agent contract, Markdown is the
universal fallback, and script-free HTML is an optional presentation of the same
snapshot. Formats share `snapshot_id` and `as_of_ms`; none creates a signing or
recovery path.

## Facts that constrain the design

- ERC-20 gives Bloom `balanceOf` and transfer/approval primitives, but no owner-to-token
  enumeration. Portfolio coverage must therefore be explicitly partial unless a
  configured indexer proves more ([ERC-20](https://eips.ethereum.org/EIPS/eip-20)).
- Polymarket's current-position response includes current value, PnL, redeemability,
  slug, and end date. The current Rust type omits several of these, so a typed adapter
  change is required before redemption or deadline signals are trustworthy
  ([current positions API](https://docs.polymarket.com/api-reference/core/get-current-positions-for-a-user)).
- Hyperliquid API-wallet queries and permissions belong to the master/subaccount, not
  the agent address; remote authorization and Bloom's local executor state must remain
  separate ([API wallets](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)).
- Hyperliquid Bridge2's direct deposit credits the account that sends native Arbitrum
  USDC and has a five-USDC minimum. Bridge2 also supports permit-based deposit-on-behalf,
  but Bloom does not expose that sender-bound flow today. V0 must not publish the shared
  bridge as a generic Receive address; a future permit route needs its own exact,
  sender-bound review ([Bridge2](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/bridge2)).
- EIP-7702 delegates can execute with the delegated account's authority. Unknown
  delegation should be shown as an explicit finding, never collapsed into a reassuring
  security score ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)).

## Falsification cases the implementation must pass

1. The same EVM owner on two chains remains two receive routes and two balance scopes.
2. An unknown or unpriced token remains visible without inflating `priced_net_value_usd`.
3. An API-wallet agent address is never mistaken for the Hyperliquid master account.
4. A direct Bridge2 self-deposit is not rendered as an incoming address; a future
   permit flow is shown only with sender, credited account, asset, minimum, and expiry.
5. A Next Moves item disappears when its underlying pending/risk condition clears.
6. ENS resolution changes between preparation and approval create a new exact signing
   review; the old interpretation is not silently reused.
7. Polymarket value, PnL, redeemability, and deadline survive normalization without
   counting cost basis or position notional twice.
8. An unknown EIP-7702 delegate is a concrete coverage/finding entry, not “secure.”
9. Incoming dust never becomes a saved contact or send suggestion.

## Implementation order

1. Fixture-driven snapshot models, renderers, coverage/error semantics, and a shared
   short-lived cache.
2. Portfolio adapters and renderers.
3. Receive routes with chain, asset, provenance, and sender-bound constraints.
4. Activity's canonical lifecycle/evidence projection.
5. Next Moves rules over Activity, Portfolio, and capability state.
6. Send/AddressBook with chain-qualified contacts, exact decoding, ENS, and simulation.
7. Permissions & Security with partial authority inventory and recovery ceremonies.

The ordering is deliberate: Next Moves cannot be reliable until Activity exposes one
canonical action lifecycle, and Send/Permissions must never bypass the existing outbox,
policy, passkey, or Sealed Approval boundaries.

## Deliberate V0 partials

Token discovery, third-party history ranges, venue availability, unknown on-chain
approvals, and host HTML support are reported as coverage—not hidden behind “complete.”
Multicall, hosted portfolio indexers, generic Petal portfolio plugins, prices, and chain
status are follow-on work, not prerequisites for the first six views.
