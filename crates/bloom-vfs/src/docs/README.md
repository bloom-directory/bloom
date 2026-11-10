# Bloom virtual filesystem

Route reference. Rules are in the mount's `AGENTS.md`; procedures are in
[examples.md](./examples.md) and [wallets.md](./wallets.md).

## Top-level routes

| Path | Purpose |
|---|---|
| `AGENTS.md`, `CLAUDE.md` | Identical operator instructions |
| `next.md` | Actions and projections needing attention |
| `chains/` | Configured EVM chain reads |
| `wallets/` | Public wallet/account projections, policy, transaction outboxes |
| `petals/` | Installed packages and their instructions |
| `requests/` | Planned, authority-gated paid HTTP requests |
| `cards/` | Saved card management and approval status, when Checkout is configured |
| `travelers/` | Saved traveler management, when Checkout is configured |
| `checkout/` | Private shopping, payment requests and history, when Checkout is configured |
| `outbox/` | Central action projections and correlation records |
| `simulate/` | EVM dry-run sessions; never broadcasts |
| `status/` | Daemon, chain, backend, and update status |
| `watch/` | Registered read watches and history |
| `ens/`, `prices/` | ENS resolution and price-provider reads |
| `addressbook/` | Named public addresses |
| `tools/` | Pure encoding, hashing, address, ABI, and unit helpers |
| `docs/` | Route reference, examples, installed-Petal index |
| `petal-key-requests/`, `petal-signing-requests/` | Broker-backed Petal request projections |

`chains/` is EVM-only. Solana status lives under
`status/chains/<solana-chain>/`; account reads live under
`wallets/<wallet>/<n>/chains/<solana-chain>/`. Discover installed applications
under `petals/`.

## Reads

Representative paths, relative to the mount:

| Data | Path |
|---|---|
| EVM chain identity/head | `chains/<chain>/chain_id`, `chains/<chain>/head/number` |
| EVM block/receipt | `chains/<chain>/blocks/<number>/full.json`, `chains/<chain>/tx/<hash>/receipt.json` |
| EVM address balance | `chains/<chain>/addresses/<address>/balance.json` |
| Token grammar and holdings | `chains/<chain>/addresses/<address>/tokens/{README.md,known.json}` |
| Token balance | `chains/<chain>/addresses/<address>/tokens/<contract>/balance.json` |
| NFT kind/owner | `chains/<chain>/contracts/<contract>/nft/{kind,owner_of/<token-id>}` |
| ENS / price | `ens/<name>/address`, `prices/spot/eth.usd` |
| Wallet identity | `wallets/<wallet>/{kind,projection.json,accounts.json}` |
| Account keys | `wallets/<wallet>/<n>/{account.json,address.evm,address.sol,public_key}` |
| Account funds on every chain | `wallets/<wallet>/<n>/holdings.json` |
| Solana account | `wallets/<wallet>/<n>/chains/<solana-chain>/{address,balance,balance.raw,balance.json}` |
| Solana status | `status/chains/<chain>/{status.json,slot,block_height}` |

Braces abbreviate separate leaves. Delegated sessions are under
`wallets/<wallet>/<n>/sessions/`; Petal routes name the wallet and account,
for example `petals/enso/intents/<wallet>/<n>/new`.

## Writes

| Operation | Route / procedure |
|---|---|
| Register wallet | `wallets/new`; [wallet creation](./examples.md#creating-a-wallet), [wallets.md](./wallets.md) |
| Recover wallet | `wallets/recover`; [recovery](./examples.md#recovering-a-wallet) |
| EVM transaction | `wallets/<wallet>/0/chains/<chain>/outbox/new.tx`; [Anvil workflow](./examples.md#local-anvil-transaction) |
| Solana transaction | Same outbox shape with strict JSON; [Solana workflow](./examples.md#solana-account-aware-reads-and-transfer) |
| Update policy | `wallets/<wallet>/policy.json`; [policy workflow](./examples.md#updating-wallet-policy) |
| Reusable authority | `wallets/<wallet>/sealed-approvals/` |
| Petal operation | Package-defined `<wallet>/<index>` routes; [installed package workflow](./examples.md#installed-petal-workflow) |
| Paid HTTP | `requests/`; inspect plan, wallet, payment protocol, cap, approval, and receipt |
