# Minimal HD-account support for Petals

Date: 2026-09-25

Status: revised proposal (pragmatic revision)
Primary issue: [PM #65](https://github.com/bloom-directory/pm/issues/65)

This revision supersedes the earlier versions of this document, the
[account-scoped proposal](2026-09-25-account-scoped-petals.md), and the design
parts of both reviews ([first](2026-09-25-minimal-hd-account-petals-review.md),
[transparent](2026-09-25-transparent-hd-account-petals-review.md)). The source
findings in those reviews still apply where cited below.

The earlier goal of running every Petal byte-for-byte unchanged is dropped. It
needed a host translation layer ("logical account 0", compatibility aliases,
wallet-name tombstones) and still could not support Tolly. This design makes a
small, mostly identical change to each bundled Petal and keeps host work
mechanical.

## 1. Decisions

- Every Petal operation runs under exactly one selected wallet account:
  `/petals/<petal>/wallets/<wallet>/<n>/<operation>`.
- Unprefixed legacy paths are removed. `/petals/<petal>/intents/alice/new` no
  longer exists; `/petals/<petal>/wallets/alice/0/intents/new` replaces it.
- The wallet name appears once. The host removes the Petal's `[wallet]` route
  segment and supplies it from the selected wallet.
- The core `/wallets/<wallet>/<n>/` tree is unchanged. Petals are not mounted
  beneath it.
- The existing account plumbing (`PetalRouter::for_account`,
  `dispatch_for_account`, trusted `bloom.wallet`/`bloom.account` params and
  `[account] aware = true`) is reused rather than duplicated.
- One store per invocation, chosen once. No per-KV authority checks.
- Bundled Petals get a small change and a normal release. No SDK ABI change and
  no new manifest field.

## 2. VFS layout

```text
/
├── wallets/                                   core wallet tree, unchanged
│   └── alice/
│       ├── 0/  address.evm, chains/…, outbox/…, sessions/…
│       └── 1/  …
│
└── petals/
    ├── enso/
    │   ├── README.md  AGENTS.md                     Petal documents only
    │   └── wallets/                                 host: wallets in the authenticated projection
    │       └── alice/                               host: accounts that exist
    │           ├── 0/                               account 0: existing store
    │           └── 1/                               account 1: own store
    │               ├── README.md  meta/
    │               ├── settings/
    │               │   ├── api-key                  configured per account
    │               │   ├── status.json
    │               │   └── wallets/venue.toml       ← settings/wallets/[wallet]/venue.toml
    │               └── intents/                     ← intents/[wallet]/$index
    │                   ├── new  latest
    │                   └── <id>/  plan.md  confirm  status.json  receipt.json …
    │
    ├── near/wallets/alice/1/
    │   ├── settings/  meta/  tokens.json
    │   └── swaps/  new  latest  <id>/{quote.json, confirm, refresh, …}
    │
    ├── polymarket/wallets/alice/1/
    │   ├── settings/  relayer.json  enso-api-key  venue.toml
    │   ├── account/  trade/  fund/  withdraw/  positions/  redeem/ …
    │   └── obligations.json                         ← obligations/[wallet].json
    │
    ├── hyperliquid/wallets/alice/1/
    │   ├── asset_ids.md  …
    │   └── <network>/
    │       ├── exchange/  order.json  cancel.json  withdrawals/<nonce>.json …
    │       └── agent_sessions/  new.json  <session>/{order.json, stop, receipts/…}
    │
    └── tolly/wallets/alice/1/
        ├── markets.json  quote/  tokens/  status.json
        ├── buy.json  sell.json  launch.json         ← Tolly's wallets/[wallet]/ tree removed;
        └── positions.json  operations/<id>.json       these routes read bloom.wallet (§5.1)
```

| Directory | Listing supplied by |
|---|---|
| `/petals/<p>/` | Host: `wallets/` plus the existing Petal documents |
| `/petals/<p>/wallets/` | Host: wallets in the authenticated projection |
| `/petals/<p>/wallets/<w>/` | Host: that wallet's existing account numbers |
| `…/<n>/` | The Petal's root `$index` |
| A directory that previously contained `[wallet]` | The Petal's `<dir>/[wallet]/$index`, with `wallet` = selected |
| Everything deeper | The Petal's original route, with its original path |

Wallet and account directories are synthesised from existing public inventory
and have no authority effects. Non-aware Petals appear only under `…/0/` (§5).

## 3. Routing

### 3.1 Prefix

The host parses `wallets/<w>/<n>/` immediately below the Petal mount. `<n>` must
be canonical decimal (no sign, no leading zeros except `0`) and fit `u32`. The
wallet and account must exist in the authenticated wallet projection. The host
builds `AccountPetalContext` from that projection. Unknown wallets, unknown
accounts and missing signing families fail; nothing falls back to another
account.

`wallets` is reserved only in the external mount view, i.e. directly below
`/petals/<petal>/`. That view contains nothing but `wallets/` and the Petal
documents, so no package route can conflict with it. Inside the scoped package
view (below `…/<n>/`) the package's own routes are exposed as-is. A
root-level dynamic capture such as Hyperliquid's `[network]` is likewise only
ever matched inside the scoped view.

### 3.2 Scoped route view

Computed once per installed package hash from its immutable route index:

1. For each route with a `[wallet]` directory segment, remove that segment:
   `intents/[wallet]/[id]/plan.md` → `intents/[id]/plan.md`.
2. A `[wallet]` filename capture becomes a file named after its parent:
   `obligations/[wallet].json` → `obligations.json`.
3. Routes without `[wallet]` are exposed unchanged.
4. A directory whose dynamic child was `[wallet]` takes its listing from
   `<dir>/[wallet]/$index`. The old `<dir>/$index`, which listed wallet names,
   is not exposed.
5. Any new collision introduced by projection between exposed paths or
   patterns makes install fail with the conflicting routes named. Existing
   static/dynamic overlaps retain their original route specificity; projection
   must not reject ordinary pre-existing `latest` versus `[id]` routes.
6. A route with more than one `[wallet]` segment makes install fail.

Simulation against the route indexes of all eight currently pinned release
archives (Enso, Near, Polymarket, Hyperliquid, Tolly before the §5.1 change,
Gasless, Privacy Pools and Venice x402; archive hashes checked against the
pins) found at most one `[wallet]` per route. Implementation validation preserves
existing static/dynamic precedence (for example Enso `latest` beside `[id]`)
and rejects collisions introduced by the projection. Rule 4 collapses paired
wallet-list indexes; rule 2 handles Polymarket's filename capture.

### 3.3 Dispatch

For lookup, read, list and write:

1. Match the path below `…/<n>/` against the scoped view.
2. Reconstruct the original package-relative path by reinserting the selected
   wallet where `[wallet]` was.
3. Call the existing `dispatch_for_account` with that original path.

The route ID, route parameters (including `wallet`), component and package
provenance are the originals. The guest sees the path it always saw. There are
no aliases: each operation has exactly one external spelling.

## 4. Invocation context

`dispatch_for_account` already appends host-owned trusted params and rejects any
caller-supplied `bloom.*` param. Add one:

| Param | Example | Purpose |
|---|---|---|
| `bloom.wallet` | `alice` | existing |
| `bloom.account` | `1` | existing |
| `bloom.route_prefix` | `wallets/alice/1/` | new; Petal-relative base for emitted links |

The same context drives store selection (§6), signing owner resolution (§7) and
nested guest VFS authorization.

### 4.1 Nested guest VFS isolation (required work)

Today `authorize_guest_vfs_path` (`crates/bloom-daemon/src/lib.rs:462`) is a
static function of the path alone and has no selected-account context. It
blocks ceremony projections, but otherwise a guest may address any wallet and
account. That must change.

Enforce it in the Petal VM, not the daemon. The selected account is already in
`StoreData.sign_context` and available through `trusted_account()`
(`crates/bloom-petals/src/vm.rs:1580`). Add one path check, in the style of the
runner's `deny_apps_subtree`, at each guest VFS call site in `vm.rs` (lookup,
read, list and write) before the call reaches the `PetalHost`. The `PetalHost`
trait and the daemon are unchanged.

- Under `wallets/…`, allow only `wallets/<selected wallet>/<selected n>/…`.
  Deny other wallets and other accounts of the same wallet.
- Deny every guest call under `petals/…`, including calls to itself or another
  Petal under the same wallet and account. Retain the runner's
  `deny_apps_subtree` alongside the VM check. Petal-to-Petal calls remain
  unsupported: re-entering a Petal can deadlock on the shared effect lock, and
  recursive dispatch has no supported depth limit.
- A guest invocation without an account context is denied every `wallets/…` and
  `petals/…` path.
- Existing daemon denials (ceremony projections, owner-only controls) stay.
- Public chain observations keep their existing capability policy.

The guest ABI is unchanged; this is host-side enforcement only.

The typed host-only context proposed earlier is not needed: trusted params
already cannot be forged by the caller, and the guest reading them is intended.

## 5. Petal changes

Each of the five default-eligible Petals (Enso, Near, Polymarket, Hyperliquid,
and Tolly) gets the same small change. Gasless, Privacy Pools and Venice x402
remain excluded: their retired host APIs are a separate migration, explicitly
outside this work. Catalog presence does not imply runtime compatibility.
These three Petals are incompatible with the new Bloom until separately
updated: they do not declare account awareness and still use removed wallet
paths and/or retired host interfaces. They receive no lineage carry-forward
support in this release. Their unchanged branches are not completed migrations.

Each supported Petal changes as follows:

1. Set `[account] aware = true`.
2. Read the account from `bloom.account` instead of hard-coding
   `wallets/<wallet>/0/…` or storing `account.number = 0`.
3. Build emitted paths and links as `bloom.route_prefix` + the route path with
   the wallet segment removed. Add one SDK helper for this if none exists.
4. Update README/AGENTS documentation to the scoped paths.

| Petal | Specific items |
|---|---|
| Enso | README absolute paths |
| Near | Follow-up references (`route/src/workflow.rs:415-443`); replace the old wallet-root `kind` read with numbered-account-compatible validation |
| Polymarket | Follow-up references (`route/src/account_views.rs:68-105`); `obligations.json` rename in docs |
| Hyperliquid | None beyond 1–4. Venue `[account]` captures are unrelated and unchanged |
| Tolly | See §5.1 |

Enso additionally hard-codes `wallets/{wallet}/0/address.evm`, which item 2
covers. No pinned release sets `[account] aware` today.

Line anchors are from the source snapshots in the transparent review.

### 5.1 Tolly

Tolly keeps its own wallet tree (`wallets/[wallet]/…`), which duplicates the
host's wallet selection. It is removed rather than projected:

- Move `wallets/[wallet]/{buy.json, sell.json, launch.json, positions.json,
  operations/…}` to the package root without a `[wallet]` segment. These
  routes take the wallet from `bloom.wallet` and the account from
  `bloom.account`. There is no `wallets/` directory in Tolly any more.
- Drop `wallets/$index` and its `list_wallets` listing. The root `$index` lists
  the moved entries.
- Keep the wallet ID in Tolly's store keys. Account 0's store is shared across
  wallets (§6), so the wallet prefix is still what separates them there.
- Emit the confirm/recovery paths (`route/src/tx.rs:91-104`, `ops.rs:384-386`,
  `swap.rs:968`) as the real account's core outbox path,
  `wallets/<w>/<n>/chains/arc/outbox/pending/<id>/confirm`, and Tolly's own
  follow-ups with `bloom.route_prefix`.

This is the model any Petal can adopt: a route without `[wallet]` that reads
`bloom.wallet` needs no host projection. The `[wallet]` projection (§3.2)
remains for the other Petals so their change stays small.

Unlike the other Petals, this Tolly release does not work on the current
Machine, which supplies no `bloom.wallet` to unscoped routes. It is released
through the normal process but pinned only in the Machine release (§11). No
minimum-host-version mechanism exists, so an early manual install on an older
Machine loses Tolly's wallet routes; say so in its release notes.

A non-aware Petal (including any third-party Petal) runs only under `…/0/`, as
the router already enforces. Its routes move to the scoped path; any absolute
paths it emits still point at the removed legacy layout until it is updated.

## 6. Storage

| Invocation | Store |
|---|---|
| `…/wallets/<w>/0/…` | The existing store for the package hash (unchanged; shared by every wallet's account 0) |
| `…/wallets/<w>/<n>/…`, n > 0 | A separate store keyed by (package hash, wallet, account number) |

- The account-n store lives in a sibling root, not beneath a listable legacy
  tree: `data-accounts/<package hash>/<account digest>/`, where
  `<account digest>` is a versioned digest of (wallet, n). Grouping by package
  hash lets carry-forward (§6.1) copy a package's account stores in one step.
- The key is not an owner-key fingerprint. An account's families are fixed at
  creation (Signer allocates EVM and Solana together in one ceremony and cannot
  add one later), but retirement is per key, so an account can lose its EVM or
  Solana key while the other remains. A fingerprint-derived key would move the
  store when that happens. Account numbers are never reused within a wallet
  (`derivation_registry::next_account_number` takes the maximum over live
  keys, EVM tombstones and Solana allocations), so (wallet, n) is stable.
- Every KV operation (get/put/put-new/list/delete/delete-if-value and secrets)
  uses the selected store. There is no overlay, no shared-read list and no
  fallback to account 0.
- The store is chosen once per invocation from the resolved context. There are
  no Broker or Signer calls and no sidecar reads per KV operation.
- The wallet is identified by name, because that is the only wallet identity
  Signer exposes (the BIP-39 `wallet_seed_ref` is the wallet name). A new
  wallet reusing a deleted name therefore reaches the old account-n stores,
  exactly as account 0 already does (§9). Wallet-name non-reuse in Signer fixes
  both. Re-importing a seed under the same name reaches the same stores.
- Settings and API keys are configured separately per account.

### 6.1 Package upgrades

Private state is partitioned by package hash, so today every Petal release
starts with an empty store. The
[carry-forward spec](2026-09-25-petal-state-carry-forward.md) fixes this for
releases in an authenticated lineage: on first use of a successor package that
lists its predecessor in its signed lineage record, the predecessor's account-0
and account-n partitions are copied to it. It ships in the same Machine release
as this feature, or earlier (§11).

Delegated-key sessions are not carried. Install already refuses to replace a
package while its sessions are active unless forced, and that rule is unchanged.

## 7. Authority fixes

These are real correctness issues, independent of routing:

- Signing, key derivation and transaction staging resolve the exact owner
  KeyRef from the selected account through existing owner-resolution
  machinery. Guest-supplied sub-keys must have that parent.
- EVM staging deduplication must match selected sender and owner before
  reusing a pending request. Identical requests from accounts 0 and 1 create
  distinct pending operations. Land this separately and first.
- For n > 0, include the canonical account identity in delegated-key state,
  custody operation, stop and execution/audit IDs. Account-0 IDs are unchanged.
- Parent retirement blocks further scoped operations. It does not revoke
  existing delegated children; use existing stop controls for that.
- Lost responses preserve possible-signature state as today.

No new policy, budgets or job system.

## 8. Removing legacy paths

- The router serves only the Petal documents and `wallets/` at each Petal root.
  Old paths return not-found. A redirect or hint in the error message is
  optional and not required.
- Update in-repo references: `README.md`, `EXAMPLES.md`, `docs/petals/`,
  `docs/examples-domain/`, `crates/bloom/tests/cli.rs`,
  `crates/bloom-daemon/src/lib.rs`, `scripts/local-mainnet-integration.sh`,
  `scripts/test-fixtures/fake-triad-dev-launcher.sh` and the Hyperliquid
  Harbor eval. Historical specs and reviews stay as written.
- Update the `PetalRouter::for_account` doc comment, which currently states that
  no VFS mount uses it.
- An unchanged installed package keeps its account-0 private state, reached
  through `…/wallets/<w>/0/`. Upgrading to a successor release carries it
  forward (§6.1).

## 9. Accepted limitations

- Removing only the `[wallet]` segment leaves one awkward path:
  `enso/…/<n>/settings/wallets/venue.toml`. Renaming it is optional follow-up
  work.
- Account 0 keeps the existing shared store, including its historical
  cross-wallet logical-prefix behaviour and exposure to a reused wallet name.
  Wallet-name non-reuse in Signer is not part of this feature; it can be done
  later as a small independent change.
- Settings and API keys are duplicated per account.
- An n > 0 store, like account 0's, is exposed to a reused wallet name.
- Removing legacy paths breaks external scripts and agents that use them.
- Each bundled Petal needs a release and a default-Petal pin bump.
- Delegated-key sessions must be stopped before a Petal upgrade and recreated
  afterwards, as today (§6.1).

## 10. Open questions

None. The earlier question (can an account gain a signing family later?) is
answered in §6: no, but it can lose one, so stores are keyed by account number.

## 11. Release

Use the existing release strategy and gates. The Petal releases must be ready
before the Machine change ships, so that removing legacy paths never leaves a
bundled Petal emitting broken links or lacking HD support.

1. Machine: EVM deduplication fix (§7). Independent; can ship any time.
2. Bundled Petals: prepare and release the §5 change through the normal Petal
   process. Each release must also work on the current Machine: when
   `bloom.route_prefix` is absent, emit today's legacy links; when
   `bloom.account` is absent, use account 0. This makes the Petal releases safe
   to publish before Machine, and lets someone install them early. Tolly is
   the exception (§5.1): its release requires the new Machine and is only
   pinned by step 3. Each release's lineage record must list the currently
   pinned hash in `predecessor_package_hashes` so its state carries forward.
3. Machine: state carry-forward (if not already shipped), scoped routing,
   store selection, nested VFS isolation (§4.1), remaining authority fixes and
   legacy path removal, shipped in one release together with the default-Petal
   pin bump to the step-2 releases, through the existing pin/lockfile process.
   Load and verify the successor catalog records in the executing daemon
   before activating those pins. If that requires a restart, complete it first.
   Missing or invalid release information leaves the previous package active;
   it must not let the successor write a fresh store before carry-forward is
   authorised. See the carry-forward spec §4.1.

The installer catalog must cover all five compatible Petals, including those
without signing permissions, and retain the predecessor metadata used for
carry-forward. This requires the narrow Broker API catalog-shape update described
in the carry-forward spec §8; it does not change signing authorization or Signer.
An older Broker rejects the expanded catalog. Ship the updated Broker and
Machine together in the compatible triad bundle, with their exact dependency
and compatibility pins updated through the existing release process.

Rollback of Machine cannot rebind account-n data to account 0 or replay newer
operations with legacy IDs.

## 12. Acceptance tests

1. The scoped route view builds for all five default-eligible Petals. Tolly exposes no
   `wallets/` directory of its own. Collision and
   multiple-`[wallet]` fixtures fail install with the routes named.
2. Two wallets × accounts 0 and 1 against each bundled Petal verify: address,
   actual signer, KV/secrets/settings isolation, emitted links resolving within
   the same account, and Tolly's confirm flow completing on account 1.
3. Identical EVM transactions from accounts 0 and 1 create distinct pending
   operations.
4. Escape attempts fail: unknown wallet or account, non-canonical `<n>`, and
   non-aware Petals under `<n>` > 0.
5. Nested guest VFS isolation (§4.1), for each of lookup, read, list and write:
   a guest on alice/1 is denied `wallets/bob/…`, `wallets/alice/0/…` and
   every `petals/…` path (including `petals/<p>/wallets/alice/1/…`), and is allowed its own
   `wallets/alice/1/…`. A guest invocation with no account context is denied
   all `wallets/…` and `petals/…` paths. Rejection occurs before nested dispatch,
   including writes and side-effecting reads, so the effect lock is not re-entered.
6. Upgrade behaviour (§6.1): upgrading from the current bundled Petal release to
   the step-2 release on the new Machine keeps account-0 settings, API keys and
   records, reached through `…/wallets/<w>/0/`. Pending core outbox items can
   still be inspected and confirmed or abandoned through `/wallets/<w>/<n>/`.
   Legacy paths return not-found. The carry-forward spec's own tests also apply.
7. Step-2 Petal releases other than Tolly run on the current Machine with
   legacy paths and legacy links (backward-compatibility check for §11).
8. Real EVM and Solana owner-signing fixtures pass on account 1, through a real
   Machine, Broker and Signer. No such test exists today: Signer's tests
   allocate account 1 without signing, and `solana_multi_account` uses a
   fixture Broker. Extend `scripts/test-bip39-import-transfer.sh` to create
   account 1 and sign from it. Do not infer delegated Solana support from owner
   signing.
9. Follow `TESTING.md` and the existing release checks.
