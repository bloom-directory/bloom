# Bloom virtual filesystem

Bloom exposes public chain data and authority-gated operations as a mounted
filesystem. This document describes the live operator interface. For Bloom
development, use the repository's `DEVELOPMENT.md` instead.

All examples run from a normal scratch directory outside the mount and address
the mount through a single quoted variable, so any mountpoint works:

```sh
BLOOM="<bloom-vfs-mount>"
ls "$BLOOM"
cat "$BLOOM/AGENTS.md"
cat "$BLOOM/next.md"
```

Keep scratch files in that working directory, never inside the mount. Do not
prepend `/bloom` to paths unless that is the mountpoint on this machine.

## Discover the live surface

Always list before acting. Configured chains, wallets, and installed Petals vary
between machines.

```sh
ls "$BLOOM"
ls "$BLOOM/chains/"
ls "$BLOOM/wallets/"
cat "$BLOOM/docs/petals.md"
```

The daemon mounts these top-level surfaces:

| Path | Purpose |
|---|---|
| `AGENTS.md`, `CLAUDE.md` | Identical agent operating contract |
| `next.md` | Current actions and projections needing attention |
| `chains/` | Configured EVM chain reads |
| `wallets/` | Public wallet projections, accounts, policy, and transaction outboxes |
| `petals/` | Installed application packages and their local documentation |
| `requests/` | Planned and authority-gated paid HTTP requests |
| `outbox/` | Central action projections and correlation records |
| `simulate/` | EVM dry-run sessions; never broadcasts |
| `status/` | Daemon, chain, backend, and update status |
| `watch/` | Registered read watches and their history |
| `ens/` | ENS resolution and records |
| `prices/` | Configured price-provider reads |
| `addressbook/` | Named public addresses |
| `tools/` | Pure encoding, hashing, address, ABI, and unit helpers |
| `docs/` | This reference, examples, and installed-Petal index |
| `petal-key-requests/` | Broker-backed Petal public-key request projections |
| `petal-signing-requests/` | Broker-backed Petal signing request projections |

`chains/` is EVM-only. Solana has no `chains/` subtree: chain status lives
under `status/chains/<solana-chain>/` and account reads live under
`wallets/<wallet>/chains/<solana-chain>/`.

There is no native `defi/intents` or Hyperliquid application route. Those
workflows are installed Petals and appear under `petals/<name>/`.

## Read classes

Not every read has the same operational cost:

- Wallet projections, staged plans, receipts, and metadata are local public
  projections.
- Chain, balance, ENS, price, and status paths may contact configured providers.
  These reads do not sign or broadcast, but can consume quota and disclose the
  queried public identifier to the provider.
- Petal reads obey that package's declared capabilities and network policy.
  Read its `README.md` and `AGENTS.md` first.

Directory listing should remain discovery-only. In particular, listing wallet
accounts does not fan out to chain RPC. Read balance or status leaves explicitly
when current network state is needed.

## Chain reads

Discover each configured chain rather than assuming an installation default:

```sh
ls "$BLOOM/chains/"
ls "$BLOOM/chains/<chain>/"
cat "$BLOOM/chains/<chain>/chain_id"
cat "$BLOOM/chains/<chain>/head/number"
```

Representative EVM reads:

```sh
cat "$BLOOM/chains/ethereum/head/number"
cat "$BLOOM/chains/ethereum/blocks/<number>/full.json"
cat "$BLOOM/chains/ethereum/tx/<hash>/receipt.json"
cat "$BLOOM/chains/ethereum/addresses/<address>/balance.json"
```

Representative Solana reads. Status and account data live outside `chains/`:

```sh
cat "$BLOOM/status/chains/<solana-chain>/status.json"
cat "$BLOOM/status/chains/<solana-chain>/slot"
cat "$BLOOM/status/chains/<solana-chain>/block_height"
cat "$BLOOM/wallets/<wallet>/chains/<solana-chain>/accounts/<full-fingerprint>/balance.json"
```

Solana status deliberately reports `slot` and `block_height`; it does not
invent EVM block-number or finality semantics.

## Wallets and accounts

Wallet directories are public projections from Broker and Signer authority:

```sh
cat "$BLOOM/wallets/<wallet>/projection.json"
cat "$BLOOM/wallets/<wallet>/accounts.json"
cat "$BLOOM/wallets/<wallet>/address"
cat "$BLOOM/wallets/<wallet>/addresses.json"
cat "$BLOOM/wallets/<wallet>/policy.json"
```

`address` is the canonical primary address only when that concept is
unambiguous. Account-aware operations use the exact public-key fingerprint and
derivation path from `accounts.json`. Never select by projection order.

For Solana multi-account wallets, use the full fingerprint:

```sh
cat "$BLOOM/wallets/<wallet>/chains/<solana-chain>/accounts/<full-fingerprint>/address"
cat "$BLOOM/wallets/<wallet>/chains/<solana-chain>/accounts/<full-fingerprint>/balance.raw"
cat "$BLOOM/wallets/<wallet>/chains/<solana-chain>/accounts/<full-fingerprint>/balance.json"
```

The chain-level Solana balance alias fails closed when several compatible
children exist.

## Creating a wallet

Writing a requested petname starts asynchronous passkey registration:

```sh
printf 'main\n' > "$BLOOM/wallets/new"
cat "$BLOOM/wallets/registrations/main/status.json"
```

The initial write does not create a local wallet. The projection is keyed by
the requested petname and includes `requested_name`, `ceremony_url`, and
`ceremony_state`. Forward the URL to the human passkey holder. Poll the same
`status.json`; after `COMPLETED`, read:

```sh
cat "$BLOOM/wallets/registrations/main/result.json"
cat "$BLOOM/wallets/main/projection.json"
```

Before ceremony acceptance, cancel with:

```sh
printf 'cancel\n' > "$BLOOM/wallets/registrations/main/cancel"
```

Mnemonic and raw-key input belongs only in the Broker-hosted ceremony. Never
write it into the mount or pass it through the shell.

## Transaction lifecycle

Native transaction surfaces use stage, inspect, authorize, retry, and verify:

```sh
printf 'send 0.01 ETH to 0x...\n' \
  > "$BLOOM/wallets/<wallet>/chains/<chain>/outbox/new.tx"
ls "$BLOOM/wallets/<wallet>/chains/<chain>/outbox/pending/"
cat "$BLOOM/wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/intent.json"
cat "$BLOOM/wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/plan.md"
echo y > "$BLOOM/wallets/<wallet>/chains/<chain>/outbox/pending/<exact-id>/confirm"
```

Use the exact identifier whose intent and plan you inspected. Do not use a
wildcard, infer the newest entry, or rely on sequence ordering.

If fresh authorization is required, the confirm write can return permission
denied after creating `approval_challenge.json`. Read it from the same exact
action, verify its wallet, action identity, intent, expiry, and `retry_path`,
and forward its ceremony URL to the human. After approval, retry only that path.
Do not restage.

Terminal entries move under `sent/` or `failed/`. Read the receipt and
reconciliation projections before reporting success. A transport timeout is not
proof that broadcast failed.

## Reusable authority

Sealed Approvals are Broker-owned reusable authority:

```sh
ls "$BLOOM/wallets/<wallet>/sealed-approvals/"
cat "$BLOOM/wallets/<wallet>/sealed-approvals/active.json"
cat "$BLOOM/wallets/<wallet>/capabilities/active.json"
```

Broker enforces scope, expiry, limits, counters, and revocation. Machine and
Petals only project or request use of that authority. Read the exact approval
before relying on it; never infer authority from a cached capability name.

## Updating wallet policy

`wallets/<wallet>/policy.json` is a canonical public projection. Replacing it
starts a Broker ceremony:

```sh
cat "$BLOOM/wallets/<wallet>/policy.json" > proposed-policy.json
cp proposed-policy.json "$BLOOM/wallets/<wallet>/policy.json"
cat "$BLOOM/wallets/<wallet>/policy-updates/latest/status.json"
cat "$BLOOM/wallets/<wallet>/policy-updates/latest/approval_challenge.json"
```

`proposed-policy.json` stays in the scratch directory outside the mount. Broker
first performs `policy.validate_update`. After the human completes the
ceremony, retry the **exact same proposed bytes** so Broker can perform
`policy.commit_update`. Then verify both the committed `policy.json` and the
terminal update status. Editing or reformatting the proposal between these
steps creates a different request.

## Tokens, NFTs, ENS, and tools

Self-describing token routes expose their local grammar:

```sh
ls "$BLOOM/chains/<chain>/addresses/<address>/tokens/"
cat "$BLOOM/chains/<chain>/addresses/<address>/tokens/README.md"
cat "$BLOOM/chains/<chain>/addresses/<address>/tokens/known.json"
cat "$BLOOM/chains/<chain>/addresses/<address>/tokens/<contract>/balance.json"
```

Representative NFT and utility reads:

```sh
cat "$BLOOM/chains/<chain>/contracts/<contract>/nft/kind"
cat "$BLOOM/chains/<chain>/contracts/<contract>/nft/owner_of/<token-id>"
cat "$BLOOM/ens/<name>/address"
cat "$BLOOM/prices/spot/eth.usd"
cat "$BLOOM/tools/keccak/hello"
```

## Petals and paid requests

Installed Petals are dynamic. Discover them and follow package-local guidance:

```sh
cat "$BLOOM/docs/petals.md"
cat "$BLOOM/petals/<name>/README.md"
cat "$BLOOM/petals/<name>/AGENTS.md"
ls "$BLOOM/petals/<name>/"
```

Petals cannot create or broaden signing authority. Their actions must resolve
through Broker authorization and Signer custody, with central correlation under
`outbox/` where applicable.

Paid HTTP operations live under `requests/` and can consume funds or reusable
authority. Inspect the exact request plan, wallet, payment protocol, maximum
amount, approval projection, and receipt. Vendor-specific examples belong in
the installed package or request documentation, not in this stable route index.

## More examples

Read `docs/examples.md` for complete mount-relative walkthroughs.
