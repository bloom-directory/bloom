# Issue 114: VFS Receive view

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Build Receive as a directory of verified, chain-qualified destinations:

```text
/wallets/<wallet>/receive.json   canonical routes for agents
/wallets/<wallet>/receive.md     universal human-readable fallback
/wallets/<wallet>/receive.html   optional rich, self-contained view
```

The overview must make the user choose a network and purpose before emphasizing a QR
code. A bare EVM address is not a complete receive instruction: the same 20-byte owner
address can appear on many chains, while venue wallets may accept only one asset on one
chain.

A "receive route" means Bloom can identify the destination, network, purpose, and asset
constraints well enough for another wallet to send safely. It is not merely every
address Bloom knows. The agent does not populate these files; Bloom renders all three
from one typed, read-only `ReceiveSnapshot`.

## The important distinction

Receive should contain only destinations that an external sender can use.

- **Wallet account:** the owner EOA on a specific configured chain. It can receive the
  chain's native asset and tokens, but Bloom must not imply that every possible token is
  discoverable or supported by the portfolio view.
- **Venue deposit wallet:** a user-specific address with explicit provenance and asset
  rules. Bloom currently has this for a verified Polymarket deposit wallet on Polygon.
- **Funding workflow:** an action that must originate from the Bloom wallet. This is not
  a receive destination.

Hyperliquid belongs to the third category. Its Arbitrum bridge credits the account that
*sent* native USDC to the shared bridge contract; handing that bridge address to another
sender would credit the other sender, not the intended Bloom wallet
([Hyperliquid Bridge2](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/bridge2)).
The Receive page should therefore say “fund through Bloom's Hyperliquid deposit flow,”
not display the bridge as the wallet's deposit address. That workflow belongs in the
Send/action surface.

## V0 route model

A minimal JSON shape is enough:

```json
{
  "schema": "bloom.receive.v1",
  "snapshot_id": "...",
  "wallet": "alice",
  "as_of_ms": 1784217600000,
  "routes": [
    {
      "id": "eip155:8453:owner",
      "kind": "wallet_account",
      "status": "ready",
      "purpose": "receive_to_wallet",
      "account_id": "eip155:8453:0x1234...abcd",
      "address": "0x1234...aBcD",
      "chain": {
        "name": "base",
        "display_name": "Base Mainnet",
        "chain_id": 8453
      },
      "asset_policy": {
        "native_symbol": "ETH",
        "known_assets_path": "/chains/base/tokens/known.json",
        "discovery_complete": false
      },
      "provenance": "wallet_owner",
      "warnings": []
    }
  ],
  "non_receive_workflows": [],
  "coverage": [],
  "errors": []
}
```

Use [CAIP-10](https://standards.chainagnostic.org/CAIPs/caip-10) account IDs and
[CAIP-19](https://standards.chainagnostic.org/CAIPs/caip-19) asset IDs internally so
chain identity is never inferred from an address or symbol. Continue displaying the
full EIP-55 checksum address; the checksum catches many transcription errors but does
not identify a chain ([ERC-55](https://eips.ethereum.org/EIPS/eip-55)).

Each route needs:

- stable ID, wallet, purpose, and destination kind;
- full checksummed address plus chain name and numeric chain ID;
- `ready`, `blocked`, or `unavailable` status with a plain reason;
- exact accepted assets and minimums when the route is constrained;
- provenance, verification time, and freshness when the address is derived or fetched;
- wallet kind, including a warning when this is watch-only and Bloom cannot spend;
- coverage and errors, so a missing venue route is not mistaken for “no route exists.”

The Markdown and HTML should group routes by purpose, then chain. Mainnet, testnet, and
local chains need unmistakable labels. The top-level page should not present one route
as a universal default.

## QR behavior

Bloom already exposes `address.qr.{png,svg}`, but those QR codes contain only the raw
owner address. Keep them for compatibility and label them **chain-agnostic**.

For a new Receive widget:

- Never show a QR without the full text address, network, and asset beside it.
- Only promote a QR after the route is `ready` and the network is explicit.
- For an exact native-asset request, prefer an
  [ERC-681](https://eips.ethereum.org/EIPS/eip-681) URI containing the chain ID.
- An ERC-20 ERC-681 request targets the token contract and needs recipient and amount
  parameters; do not pretend a generic address QR is a token-specific request.
- Treat ERC-3770's human-readable chain prefix as optional display text, not canonical
  identity or a universally supported scanner format
  ([ERC-3770](https://eips.ethereum.org/EIPS/eip-3770)).
- Render the exact QR payload as text for inspection. A QR is a transport, not proof
  that its destination is authentic.

An amount-specific payment-request builder may be useful later, but it is not needed for
the first read-only view.

## Venue rules

### Polymarket

Only show the current direct Polygon deposit wallet as `ready` when persisted onboarding
state says the live factory address was resolved and `fundable=true`. A local CREATE2
estimate must remain `blocked`, with no prominent QR or copy affordance. Include Polygon
chain ID, the accepted pUSD contract identity, wallet role, state provenance, and
`updated_ms`.

Polymarket's newer Bridge API can later add source-chain-specific deposit addresses. If
integrated, Bloom must fetch the supported assets and current minimum for the selected
source chain and track deposit status; the upstream list changes over time
([Polymarket deposits](https://docs.polymarket.com/trading/bridge/deposit),
[supported assets](https://docs.polymarket.com/trading/bridge/supported-assets)). It is a
useful extension, not a V0 dependency.

### Hyperliquid

Do not expose Bridge2 as a receive route. Put a non-receive notice in the overview with
the existing staged funding entry point. The current implementation already enforces
native Arbitrum USDC, a 5 USDC minimum, and confirmation through the normal outbox.

## What exists and what is missing

Bloom already has most V0 inputs:

- [`wallets.rs`](../../crates/bloom-vfs/src/handlers/wallets.rs) exposes the checksummed
  owner address, raw-address QR images, wallet kind, configured chains, and
  `addresses.json`.
- `addresses.json` includes a persisted Polymarket role address with `source` and
  `fundable`.
- [`ChainSpec`](../../crates/bloom-proto/src/chain.rs) supplies chain name, display name,
  chain ID, native symbol, and decimals.
- [`hyperliquid.rs`](../../crates/bloom-proto/src/hyperliquid.rs) and the DeFi handler
  already distinguish a valid sender-bound Hyperliquid deposit from a bad direct send.

The gaps are small:

- `addresses.json` does not chain-qualify the owner or Polymarket role and omits the
  venue's accepted asset identity.
- The current QR payload contains no network or asset context.
- There is no route-level `ready/blocked` contract or one shared snapshot for JSON,
  Markdown, and HTML.
- Polymarket bridge addresses, live supported assets, minimums, and deposit status are
  not integrated; keep them out until all four are available together.

## Suggested implementation sequence

1. Add a versioned `ReceiveSnapshot` and pure JSON/Markdown/HTML renderers to the wallet
   handler. V0 uses only local keystore, chain config, and persisted onboarding state.
2. Generate one owner route per configured chain and one Polymarket route only when
   persisted state exists. Represent invalid or unverified venue state as blocked, not
   absent or usable.
3. Extend role metadata with CAIP identifiers, chain ID, accepted asset, provenance,
   verification time, and route status. Keep the old address and raw QR paths compatible.
4. Add optional chain-specific native-payment QR payloads; never generate token-payment
   requests without an exact token contract and amount.
5. Test two chains sharing one owner address, obvious testnet labeling, watch wallets,
   a blocked Polymarket estimate, a verified Polymarket destination, Hyperliquid never
   appearing as a receive address, and identical snapshot IDs across formats.

V0 is ready when a user cannot mistake an owner address for a venue deposit wallet,
cannot mistake one EVM network for another, and never sees an unverified or sender-bound
funding address presented as safe to receive funds.
