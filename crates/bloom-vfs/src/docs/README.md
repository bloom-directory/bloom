# Bloom virtual filesystem

This is the route reference for the mounted operator interface. Read the
mount's `AGENTS.md` for action-selection and recovery rules, and
[examples.md](./examples.md) for complete procedures. Contributor setup lives
in the repository's `DEVELOPMENT.md`.

Work from a scratch directory outside the mount and set its actual location:

```sh
BLOOM="<bloom-vfs-mount>"
ls "$BLOOM"
cat "$BLOOM/AGENTS.md"
cat "$BLOOM/next.md"
```

Keep scratch files outside the mount. Discover configured wallets, chains, and
Petals before choosing paths; their names and availability vary by installation.

## Top-level routes

| Path | Purpose |
|---|---|
| `AGENTS.md`, `CLAUDE.md` | Identical operator instructions |
| `next.md` | Actions and projections needing attention |
| `chains/` | Configured EVM chain reads |
| `wallets/` | Public wallet/account projections, policy, transaction outboxes |
| `petals/` | Installed packages and their instructions |
| `requests/` | Planned, authority-gated paid HTTP requests |
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

Public projections and metadata do not authorize a transaction. Chain, balance,
ENS, price, and status leaves can contact configured providers, consume quota,
and disclose the queried public identifier. Petal reads follow the package's
capabilities and network policy. Listing wallet accounts and reading their
addresses do not call chain RPC; read balance leaves explicitly.

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
| Solana account | `wallets/<wallet>/<n>/chains/<solana-chain>/{address,balance,balance.raw,balance.json}` |
| Solana status | `status/chains/<chain>/{status.json,slot,block_height}` |

Braces above abbreviate separate leaves, not action selectors. Match the
intended Solana key's full fingerprint and derivation path in `accounts.json`
to its `number`, then use that number as `<n>`. Address and balance leaves
refer only to that account; never select by list position.

Numbered accounts live at `wallets/<wallet>/<n>/`: read `account.json` to
verify the keys, then use `chains/<chain>/outbox/` beneath that account to
stage and inspect its transactions. Use the explicit `0` account path for the
initial account.
Address, QR, and public-key files exist only beneath a numbered account.
Delegated sessions live beneath the numbered account at
`sessions/<petal>/<key-slot>/`; installed Petals are mounted only at
`petals/<petal>/`. See the mount `AGENTS.md` for account creation, session
status, and revocation rules.

## Writes and authority

Every write is an operation: it may stage work, start a ceremony, consume
reusable authority, or broadcast. Inspect the exact action before confirmation,
and inspect the result before retrying. A timeout does not prove that a
transaction was not submitted.

| Operation | Route / procedure |
|---|---|
| Register wallet | `wallets/new`; [wallet creation](./examples.md#creating-a-wallet) |
| Recover wallet | `wallets/recover`; [recovery](./examples.md#recovering-a-wallet) |
| EVM transaction | `wallets/<wallet>/0/chains/<chain>/outbox/new.tx`; [Anvil workflow](./examples.md#local-anvil-transaction) |
| Solana transaction | Same outbox shape with strict JSON; [Solana workflow](./examples.md#solana-account-aware-reads-and-transfer) |
| Update policy | `wallets/<wallet>/policy.json`; [policy workflow](./examples.md#updating-wallet-policy) |
| Reusable authority | `wallets/<wallet>/sealed-approvals/` |
| Petal operation | `petals/<name>/`; [installed package workflow](./examples.md#installed-petal-workflow) |
| Paid HTTP | `requests/`; inspect plan, wallet, payment protocol, cap, approval, and receipt |

Wallet registration is asynchronous and does not create a local wallet.
Read `wallets/registrations/<petname>/status.json`, verify `requested_name`,
complete the human ceremony, then check `COMPLETED` and `result.json`.
Mnemonic and raw-key input stays in the Broker-hosted browser ceremony.
Recovery ID and secret input likewise stays in the Browser ceremony; start it
with only the wallet name at `wallets/recover`, then inspect
`wallets/recoveries/<petname>/status.json`.

For a transaction requiring fresh approval, inspect the same action's
`approval_challenge.json`, verify its identity and expiry, and retry its exact
`retry_path` only after the human approves. Read the resulting state and
receipt before reporting success; never restage merely because a pending path
disappeared.

Broker enforces Sealed Approval scope, expiry, limits, counters, and revocation.
Machine and Petals cannot mint or broaden that authority. For
`policy.json` updates, Broker runs `policy.validate_update` before the
ceremony and `policy.commit_update` on the authorized retry. Reuse the
**exact same proposed bytes**, then verify the committed policy and terminal
update status.
