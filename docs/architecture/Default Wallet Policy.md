# Default Wallet Policy

**Status:** design proposal based on the implementation as of 2026-09-14
**Audience:** Bloom engineers, Petal authors, and implementation agents

A new Bloom user should go from installing Bloom to using their Petals by
approving one default policy. From then on, Bloom behaves like any other
wallet: every swap, trade, and token approval asks for the owner's approval.

This design changes only the `bloom` repository. Broker, Signer, and every
Petal stay as they are.

The normative security and wire contracts remain
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).

## The experience

```text
bloom init  (once)
  -> setup menu        choose Petals: Hyperliquid, Polymarket
                       review Polymarket's daily limit
  -> installs          the chosen Petals, pinned by Bloom's catalog
  -> saves             the choices in Bloom's config

bloom wallet new main  (or bloom wallet import main)
  -> ceremony 1        creates the wallet
  -> ceremony 2        signs the default policy for main
  -> applies           each chosen Petal's settings

using a Petal
  -> each transaction  the owner approves it, like a normal wallet
  -> over a limit      the Petal refuses before the owner is asked

later: add, update, or remove a Petal
  -> one policy update ceremony
  -> an update resets that Petal's settings, and Bloom says so
```

Today the same setup takes a creation ceremony plus one policy ceremony for
each Petal, each interrupting the first operation that needs it.

## Decisions

Agreed on 2026-09-14:

1. **Only the `bloom` repository changes.** Broker, Signer, and Petal
   repositories are untouched.
2. **`bloom init` opens a setup menu** where the user chooses their Petals.
   It offers Hyperliquid and Polymarket, and Enso once it is fixed.
3. **Bloom's setup decides the defaults.** The menu suggests each Petal's
   settings, and the user can change them.
4. **The default policy is for the first wallet, `main`.** Other wallets
   start with today's empty policy.
5. **The owner signs the default policy right after the wallet is created or
   imported,** in the same command. That is two ceremonies. Signing inside
   the creation ceremony would need Broker and Signer changes.
6. **Each transaction is approved like a normal wallet transaction.** The
   policy makes the Petals usable. It does not approve swaps, trades, token
   approvals, or spending allowances.
7. **Each Petal defines and enforces its own limits.** Broker does not track
   spending, and the wallet policy only allows the chosen Petals.
8. **Polymarket uses its existing settings:** trading turned on, with a daily
   limit of 100 pUSD.
9. **Petal settings do not survive an update.** Bloom tells the user when an
   update reset a Petal's limits.
10. **`bloom init` runs once.** Afterwards users add, update, or remove
    Petals.
11. **Enso is fixed separately.** Its current release reads a policy file the
    triad no longer serves, so it cannot run on the triad. Once a fixed
    release is pinned, the menu offers it, with its route rules in Enso's own
    settings.

## Why it does not work today

| Area | What happens now |
|---|---|
| Wallet creation | The create and import ceremony writes a policy that allows no Petals |
| First use of each Petal | Machine proposes a policy update for that one package, fails the operation with `POLICY_APPROVAL_REQUIRED`, and the owner signs a policy ceremony before retrying |
| `bloom wallet new` | Returns the ceremony URL immediately. Nothing follows up once the owner completes it ([bloom#199](https://github.com/bloom-directory/bloom/issues/199)) |
| `bloom init` | Installs the Petals in `[petals] preinstalled` without asking anything. The CLI has no interactive prompts |
| Petal changes | `bloom petals install` and `bloom petals uninstall` change installed packages but never propose a policy change |
| Polymarket | Trading is off until its `settings/<wallet>/venue.toml` sets `enabled = true` |

## Design

### 1. The setup menu

`bloom init` shows a menu when run in a terminal:

1. **Choose Petals.** Hyperliquid and Polymarket, both selected by default.
2. **Review settings.** Show Polymarket's suggested daily limit, 100 pUSD,
   and let the user change it.
3. **Confirm.** Install the chosen Petals and save the choices in Bloom's
   config.

The chosen Petals are the existing `[petals] preinstalled` list. Their
settings are saved beside it, for example:

```toml
[petals]
preinstalled = ["hyperliquid", "polymarket"]

[[petals.setup.polymarket.settings]]
path = "settings/{wallet}/venue.toml"
body = """
enabled = true
max_daily_usd = "100"
"""
```

Machine writes each saved body through the Petal's own settings route, so
Bloom never interprets a Petal's settings format.

Bloom's built-in catalog (`crates/bloom/src/github_source.rs`) holds the
suggested settings next to each pinned release, including the values the
menu asks about. Scripts and packaged installs get the same result without a
terminal through a non-interactive form that accepts the suggestions.

### 2. The default policy

The default policy uses today's wallet policy format. Setup fills in the
chosen Petals:

```json
{
  "wallet_id": "main",
  "maximum_approval_lifetime_ms": 2592000000,
  "allowed_petal_packages": [
    "a564d9559a70520995e550df685f74d3ee26af6fbb16facc08de2745bf5ec693",
    "aa1c50d3443f4c1a710d0ce93a70a65d196fd5842d241e0f78260c8a019d811c"
  ],
  "allowed_destinations": [],
  "required_verifiers": []
}
```

- **`allowed_petal_packages`** lists each chosen Petal by the exact hash
  Bloom's catalog pins: Polymarket v0.1.4 and Hyperliquid v0.1.5.
- **Everything else** keeps the current defaults: approvals last at most 30
  days, and destinations and verifiers start empty.

### 3. Signing it right after creation

`bloom wallet new main` and `bloom wallet import main`:

1. Launch the creation ceremony, as today.
2. Wait for it to complete by polling ceremony status. The Machine's Broker
   client already has `ceremony_status`.
3. Stage the default policy through the existing policy update flow, the same
   one `bloom wallet update-policy` and `bloom wallet commit-policy` use.
4. Wait for that ceremony, then commit the policy.
5. Write each chosen Petal's saved settings, such as Polymarket's
   `settings/main/venue.toml`.

If the owner stops the command or lets the policy ceremony expire, the
wallet still exists. The first Petal operation then proposes the whole
default policy, not just its own package: `ensure_petal_eligibility` builds
its proposal from the chosen Petals instead of one package
(`policy_with_package`). Machine writes the saved settings once that policy
commits.

### 4. Every transaction is approved

Once the policy is signed, the chosen Petals pass the package check, and
approvals work exactly as they do today:

- Each swap, trade, token approval, and Polymarket onboarding step asks the
  owner to approve it in a ceremony.
- Polymarket checks its own settings before asking for a signature, so a buy
  that would pass the daily limit is refused before the owner is asked.

Polymarket's existing daily limit counts buys from its trade receipts over
the last 24 hours. It does not count sells, and it has no total limit.

### 5. Adding, updating, and removing Petals

| User action | Policy change proposed for `main` | Petal settings |
|---|---|---|
| Add a Petal with `bloom petals install` | Allow its package hash | Write Bloom's suggested settings, if it is a catalog Petal |
| Update a Petal by installing a newer release | Replace the old package hash with the new one | Reset. Bloom tells the user, and offers to write the saved settings again |
| Remove a Petal with `bloom petals uninstall` | Remove its package hash | Removed with the package |

Updates reset settings because a Petal's stored state, including its
settings and trade receipts, is kept under its package hash
(`crates/bloom-petals/src/private_store.rs`). The notice names the Petal and
what was reset, for example: "Polymarket was updated to v0.1.5. Its settings,
including its 100 pUSD daily limit, were reset."

Each change is one policy update ceremony. Changes waiting at the same time
merge into one proposal, as Machine already reconciles pending proposals.

Today `bloom init` also updates outdated catalog Petals
(`ensure_preinstalled_petals`), and nothing else does. Because setup runs
once, updating to the release a newer Bloom pins becomes a user action on
the same update path.

## What still asks the owner

- **Setup:** the creation ceremony and the default policy ceremony.
- **Every transaction:** each swap, trade, token approval, Polymarket
  onboarding step, and Hyperliquid owner action.
- **Hyperliquid sessions:** a key-derivation ceremony and an approval
  ([bloom#171](https://github.com/bloom-directory/bloom/issues/171)).
- **Petal changes:** one policy update ceremony each.

## Security properties

- Setup only proposes. Nothing is allowed until the owner signs the policy
  ceremony.
- The policy allows exactly the package hashes it lists. A different or
  tampered build does not match.
- Signing the policy grants no signing authority. Every signature still
  needs an approval the owner gave for that transaction.
- Petal limits live in each Petal's settings, not the signed policy. Any
  client that can write those settings, including an agent using the mount,
  can change them. They catch mistakes and runaway agents early; the owner's
  approval of each transaction remains the check that matters.
- Broker, Signer, and the ceremony pages are unchanged, so this adds no new
  authority path.

## Deferred

These need other repositories and are out of scope:

| Improvement | Repository |
|---|---|
| Sign the policy inside the creation ceremony, for one ceremony in total | bloom-broker, bloom-signer |
| Count Polymarket sells, add a total limit, and reset a count when its limit changes | bloom-petal-polymarket |
| Keep Petal settings across updates | The stable installation slot in [Petal derived keys and package succession](./Petal%20derived%20key%20succession.md) |
| Run Enso on the triad, with route rules in its own settings | bloom-petal-enso, tracked separately |
| Create Hyperliquid sessions with fewer ceremonies | [bloom#171](https://github.com/bloom-directory/bloom/issues/171) |

## Implementation plan

All in the `bloom` repository:

- **Setup** (`crates/bloom`, `crates/bloom-proto`): the `bloom init` menu and
  its non-interactive form, suggested settings in the catalog, and saved
  choices in config.
- **Wallet creation** (`crates/bloom`): wait for the creation ceremony, then
  stage, wait for, and commit the default policy, and write Petal settings.
- **First use** (`crates/bloom-machine-client`, `crates/bloom-vfs`): propose
  the whole default policy from `ensure_petal_eligibility`, then write Petal
  settings after it commits.
- **Petal changes** (`crates/bloom`): propose policy updates from
  `bloom petals install`, newer releases, catalog updates, and
  `bloom petals uninstall`, and show the reset notice.

### Tests

- The menu and its non-interactive form save the same config.
- `bloom wallet new main` runs two ceremonies, commits a policy allowing
  exactly the chosen packages, and writes Polymarket's settings.
- After setup, Polymarket and Hyperliquid operations no longer return
  `POLICY_APPROVAL_REQUIRED`.
- A Polymarket buy over the daily limit is refused before approval.
- If the policy ceremony is skipped, the first Petal operation proposes the
  whole default policy.
- Adding, updating, and removing a Petal propose the expected policy change,
  and an update shows the reset notice.
- An end-to-end run on the developer triad: `bloom init`, then
  `bloom wallet new main` with two ceremonies, then a Polymarket order that
  needs only its own transaction approval.

## Related documents

- [Wallet Architecture](./Wallet.md)
- [Sealed Approvals](./Sealed%20Approvals.md)
- [Petal derived keys and package succession](./Petal%20derived%20key%20succession.md)
