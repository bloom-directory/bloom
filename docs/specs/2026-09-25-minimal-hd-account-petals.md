# HD accounts in explicit Petal routes

Status: revised implementation contract, 2026-09-28. Supersedes the root-prefixed
layout and special account-zero storage described in earlier drafts.

## Decisions

- Where a Petal selects `[wallet]`, it now selects `[wallet]/[index]`.
- Public routes remain public and unscoped. Account-dependent routes explicitly
  include the pair in their own route tree.
- No `[account] aware` manifest flag and no automatic account-zero fallback.
- No synthetic `/petals/<petal>/wallets/<wallet>/<index>/` root for every Petal.
- The core `/wallets/<wallet>/<index>/` tree is unchanged.
- All numbered accounts use the same private-store scheme, including zero.
- Existing account-zero Petal settings and disposable sessions need not migrate.
  Wallet custody, core outboxes and records needed to recover funds are not deleted.
- Updated packages must be released and pinned before the actual Bloom release.
  Unupdated packages are incompatible; do not add a compatibility interpreter.

## Paths

Representative paths (wallet `alice`, index `1`):

| Petal | Account-dependent route | Public route |
| --- | --- | --- |
| Enso | `intents/alice/1/new` | `meta/` |
| Near Intents | `swaps/alice/1/new` | `tokens.json` |
| Polymarket | `obligations/alice/1/status.json` | public market data |
| Hyperliquid | `testnet/agent_sessions/alice/1/new.json` | `testnet/mids.json` |
| Tolly | `wallets/alice/1/buy.json` | `markets.json` |

Each path is below `/petals/<petal>/`. Account-specific venue preferences remain
under `settings/alice/1/venue.toml`. Service credentials are Petal-wide:
Enso and Near Intents expose `settings/api-key` and `settings/status.json`;
Polymarket exposes `settings/enso-api-key` for its Enso key and router address.
Hyperliquid uses `<network>/{exchange,agent_sessions}/<wallet>/<index>/`.
Other existing wallet-dependent Petal routes insert
`[index]` immediately after `[wallet]`. Captures named `[account]` that represent
public on-chain addresses retain their existing meaning; they do not select an HD
account. Public address queries do not acquire signing authority.

## Host routing and authority

The host matches the installed route index directly. It resolves the captured
wallet/index pair through the current authenticated numbered-account projection.
An index is a canonical nonnegative u32 decimal: no leading zeros, signs, or
unallocated accounts. Ambiguous or incomplete operation selectors fail closed.
Wallet and account ancestor directories list the existing authenticated inventory.
Grouping directories may exist before the full pair is selected, without gaining
account authority.

Machine injects trusted `bloom.wallet` and `bloom.account` parameters after route
matching. Request bodies and other guest parameters cannot replace them. Petals
construct links from explicit wallet/index values, without `bloom.route_prefix` or
legacy-path projection. Cache/dispatch identities retain the selected account.
Navigation may use the existing bounded projection cache; authorization reads
remain live and Broker revalidates exact key ownership.

All signing, derivation, staging, outbox confirmation and account-bound VFS
access retain selected-account checks. Public routes cannot select a signing
wallet through their body or silently use account zero. Authority binds the exact
key fingerprint and KeyRef, never a list position or an arbitrary supplied address.
Petal-to-Petal calls remain denied, including reads with side effects and calls
within the same account; this avoids reentrant router locks and unbounded recursion.

## Storage and upgrade boundary

For every selected account, the private store is keyed by package hash, wallet
name and account number. Index zero follows the same rule as every other index.
There is no shared-account-zero store, fallback read, overlay, or schema migration
adapter. No additional authority call is introduced per KV access.

Petal-wide service settings use explicit `[store].shared_keys` declarations, with
exact fully namespaced keys such as `secrets/credentials/enso-api-key`. These keys
resolve to the same package-level store from both account-selected and public
routes. Namespace permissions and secret classification still apply. All other
keys retain their normal invocation scope; account credentials, sessions and
trading state are not shared. There is no search or fallback between stores and
no copying of previously account-scoped settings. Public routes do not gain
account or signing authority by accessing shared settings.

Existing signed same-lineage package succession remains the mechanism for carrying
forward these new stores between compatible future package releases. It does not
translate legacy wallet-wide records into account-zero records. Legacy files are
left untouched; no automatic cleanup deletes old state. Uniform account-zero
partitions start empty when only legacy package-level settings exist.

Before activating a release, reconcile or finish pending funded work using the
currently installed package. Retain recovery records for unresolved deposits,
withdrawals, orders, approvals and claims. Resetting settings is acceptable;
stranding an externally funded operation is not. This is a release prerequisite,
not a new automatic migration subsystem. Custody and core transaction history are
unchanged. Review each Petal's release notes for the state it needs to recover work.

Wallet names and account numbers must not be reused for a different owner.
Existing Signer allocation and wallet-name rules remain unchanged by this work.

## Packages and release process

Update Enso, Near Intents, Polymarket, Hyperliquid and Tolly through their existing
release workflows, then update Machine's exact archive/package/source/tooling
pins and signing-route declarations to those actual artifacts. Publish no invented
pins and do not ship the new host while its defaults still resolve old packages.
Other legacy Petals remain excluded until separately updated; updating most Petals
before rollout is planned, not permission to silently run old contracts.

Machine and Broker ship together where the loaded catalog includes signed
lineage-only records. Such records carry update identity, not signing authority.
Signer and the SDK ABI do not need changes. Explicit route components can use the
existing SDK parameter accessors. This change does not introduce a new release
process or require deploying the future filesystem from bloom#255.

The PRs are ready for review. Release pinning must be completed before rollout.
Local candidate builds and package artifacts are permitted; public releases and
merging remain separate actions. The installed acceptance environment is not reset by a
source-code update.

## Validation

- Build/check/package every changed Petal with its pinned SDK/tooling; run its
  unit tests, strict lint and route architecture checks.
- Verify discovery and direct paths for two wallets, indices zero and one;
  reject malformed/unallocated selectors and the removed synthetic layout.
- Verify account-zero/account-one/other-wallet storage isolation and no legacy
  account-zero fallback; retain signed successor-store isolation checks.
- Write service settings once and verify access from multiple accounts; verify
  their public read surfaces redact secrets and other private keys remain isolated.
- Reject body-selected authority on public routes, cross-account VFS/outbox
  actions, mismatched persisted sessions and nested Petal calls.
- Run Machine formatting, workspace lint/tests, affected daemon/VFS tests,
  provenance/package checks and real triad tests for changed authority boundaries.
- Exercise built Petals against the new Machine, including account-one staging
  and signing on local chains. Keep test paths below `~/code/bloom`.
- Record precise revisions and limitations. Earlier live bridging tests used the
  previous root layout and do not prove this new routing implementation.
