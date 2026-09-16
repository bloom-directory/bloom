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
  -> setup menu        choose which Petals main's policy allows: Polymarket,
                       Hyperliquid, Enso, NEAR Intents, Tolly
                       review Polymarket's daily buy limit
  -> saves             the choices in Bloom's config
  -> installs          Bloom's canonical Petals, pinned by its catalog
  -> writes            each chosen Petal's settings

bloom wallet new main  (or bloom wallet import main)
  -> ceremony 1        creates the wallet
  -> ceremony 2        signs the default policy for main

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
   It offers Bloom's canonical Petals: Polymarket, Hyperliquid, Enso, NEAR
   Intents, and Tolly. Bloom installs all of them for every home; the menu
   chooses which ones `main`'s policy allows.
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
9. **Petal settings do not survive an update.** Bloom keeps the setup choices
   in its config, writes them again after an update, and says so.
10. **`bloom init` runs once.** Afterwards users add, update, or remove
    Petals.
11. **Enso is offered, and fixed separately.** The default policy allows
    Enso, but its v0.1.3 release reads `wallets/<wallet>/address`, which the
    account-layout change removed (addresses now live at
    `wallets/<wallet>/<n>/address.evm`), and then `wallets/<wallet>/policy.toml`
    and `addresses.json`, which the triad does not serve. On a local triad a
    swap intent is refused with `backend: invalid`. The pinned NEAR Intents,
    Polymarket, and Tolly releases read the same retired address path, so
    their wallet actions fail the same way until those Petals move to the new
    layout.
12. **Tolly needs writes enabled.** Choosing Tolly sets
    `[petals.runtime.tolly.values] tolly_writes = "enabled"`, keeping a value
    the owner already set. Each buy, sell, or launch is still confirmed by the
    owner.

## Why it does not work today

| Area | What happens now |
|---|---|
| Wallet creation | The create and import ceremony writes a policy that allows no Petals |
| First use of each Petal | Machine proposes a policy update for that one package, fails the operation with `POLICY_APPROVAL_REQUIRED`, and the owner signs a policy ceremony before retrying |
| `bloom wallet new` | Returns the ceremony URL immediately. Nothing follows up once the owner completes it ([bloom#199](https://github.com/bloom-directory/bloom/issues/199)) |
| `bloom init` | Installs Bloom's canonical Petals without asking anything. The CLI has no interactive prompts |
| Petal changes | `bloom petals install` and `bloom petals uninstall` change installed packages but never propose a policy change |
| Polymarket | Trading is off until its `settings/<wallet>/venue.toml` sets `enabled = true` |

## Design

### 1. The setup menu

`bloom init` shows a menu when run in a terminal:

1. **Choose Petals.** Polymarket, Hyperliquid, Enso, NEAR Intents, and Tolly,
   all selected by default.
2. **Review settings.** Show Polymarket's suggested daily buy limit, 100
   pUSD, and let the user change it. Only positive amounts are accepted.
3. **Confirm.** Save the choices in Bloom's config, install Bloom's canonical
   Petals, and write each chosen Petal's settings.

Bloom installs its canonical Petals (`DEFAULT_PETALS` in
`crates/bloom/src/github_source.rs`) for every home and ignores the legacy
`[petals] preinstalled` setting. Setup records each chosen Petal under
`[petals.setup]`, with the values the menu asked about, and the default
policy proposes exactly these Petals. A chosen Petal that needs a runtime
value before it can act gets it under `[petals.runtime]`:

```toml
[petals.runtime.tolly.values]
tolly_writes = "enabled"

[petals.setup.enso]

[petals.setup.hyperliquid]

[petals.setup.near-intents]

[petals.setup.polymarket.values]
max_daily_usd = "100"

[petals.setup.tolly]
```

The policy uses the installed package hash for each chosen name, so a Petal
installed another way, such as the local builds the developer triad installs,
is still proposed when chosen.

Bloom's built-in catalog (`crates/bloom/src/github_source.rs`) holds each
Petal's settings template next to its pinned release. For Polymarket that is
`settings/{wallet}/venue.toml` with `enabled = true` and the daily limit.
Bloom substitutes the saved values, falling back to the catalog's
suggestions, and writes the result through the Petal's own settings route,
so it never interprets a Petal's settings format.

The menu runs only on first-time setup, when `bloom init` finds no config,
and only in a terminal. Scripts, packaged installs, and later runs of
`bloom init` skip it and use the config as it is, with the catalog's
suggestions for any value not saved.

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
2. Ask Machine every two seconds where the default policy stands, through the
   `wallet_default_policy` Machine command, until the wallet exists or its
   creation ceremony expires.
3. Machine proposes every chosen, installed Petal together through the
   wallet's existing policy operation, the same pending-proposal flow the
   mounted `wallets/<wallet>/policy.json` uses. The command prints that
   ceremony's URL once.
4. Once the owner completes the ceremony, the next check commits the policy,
   and the command reports that `main` now allows the chosen Petals.

Petal settings are not written here: `bloom init` already wrote them.

If the owner stops the command, or the policy ceremony expires, the wallet
still exists:

- **`bloom wallet default-policy main`** picks up where the command stopped.
  It shows a ceremony that is still open, or opens a new one after expiry.
  The Broker reports an expired ceremony as awaiting the owner until asked to
  act on it, so Machine cancels a proposal past its expiry and proposes again.
  A waiting command never announces a ceremony that has already expired.
- **Several commands can wait on the same wallet.** Only one updates its
  policy at a time; a command that finds the wallet's policy lock held checks
  again on its next poll instead of failing.
- **The first Petal operation on `main`** also proposes the whole default
  policy, not just its own package. `ensure_petal_eligibility` adds the
  chosen Petals to its proposal for the default-policy wallet.

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
| Update a Petal by installing a newer release | Replace the old package hash with the new one | Written again from the saved choices, and Bloom says so |
| Remove a Petal with `bloom petals uninstall` | Remove its package hash | Removed with the package |

An update resets a Petal's settings because its stored state, including its
settings and trade receipts, is kept under its package hash
(`crates/bloom-petals/src/private_store.rs`). Bloom still has the owner's
choices in its config, so it writes them again and says so, for example:
"Polymarket was updated, which reset its settings; re-applied max_daily_usd
= 100". Trade receipts are not restored, so Polymarket's daily count starts
again after an update.

Catalog Petals are installed and updated in two places: `bloom init`
(`ensure_preinstalled_petals`) and every `bloom serve` start
(`petal_provisioning::provision`). Both write the saved settings for a
Petal they install or update. `bloom init` prints the message, and
`bloom serve` logs it as `petal.setup_settings_written`.

Each change is one policy update ceremony. Changes waiting at the same time
merge into one proposal, as Machine already reconciles pending proposals.

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
| Enso reads its route rules from its own settings instead of `policy.toml`, so its swaps work on the triad | bloom-petal-enso |
| Create Hyperliquid sessions with fewer ceremonies | [bloom#171](https://github.com/bloom-directory/bloom/issues/171) |

## Implementation plan

All in the `bloom` repository. The first part is built; proposals from Petal
changes come next.

**Built**

- **Setup** (`crates/bloom/src/default_policy.rs`, `crates/bloom-proto`):
  the `bloom init` menu and its non-interactive form, settings templates in
  the catalog, and choices saved under `[petals.setup]`. Settings are
  written through each Petal's route by `bloom init`, and again whenever
  `bloom init` or `bloom serve` installs or updates a chosen Petal.
- **Wallet creation** (`crates/bloom`): `bloom wallet new main` and
  `bloom wallet import main` wait for the wallet, then walk the owner
  through the default policy with the `wallet_default_policy` Machine
  command. `bloom wallet default-policy` resumes it.
- **Policy proposal** (`crates/bloom-vfs`, `crates/bloom-machine-client`,
  `crates/bloom-daemon`): `ensure_petal_packages_allowed` proposes several
  packages through the wallet's existing policy operation, and
  `ensure_petal_eligibility` adds the chosen Petals for `main`.

**Next**

- **Petal changes** (`crates/bloom`): propose policy updates from
  `bloom petals install`, newer releases, and `bloom petals uninstall`.

### Tests

Automated:

- The menu offers Bloom's five canonical Petals, records declines, rejects
  invalid limits, and accepts the suggestions at the end of input. The
  scripted form chooses every canonical Petal, keeps existing values, and
  enables Tolly's writes unless the owner already set that value.
- Chosen Petals round-trip through `config.toml`, and an edited value that
  is not a positive amount cannot change a Petal's settings file.
- The wait announces each ceremony once, stops when the policy is applied,
  never announces a ceremony that has already expired, and polls quietly
  while another command holds the wallet's policy lock.
- One policy ceremony allows every chosen package, and packages are added
  once, in order. An expired proposal, including one the Broker still reports
  as awaiting the owner, is replaced by a new ceremony
  (`crates/bloom-vfs/tests/triad_policy_update.rs`).
- Catalog provisioning reports an update separately from a fresh install.

Manual, on the developer triad:

- `bloom wallet new main` runs two ceremonies and commits a policy allowing
  exactly the chosen packages, and `bloom wallet default-policy main`
  resumes after an interruption.

Next part:

- Adding, updating, and removing a Petal propose the expected policy change.

## Related documents

- [Wallet Architecture](./Wallet.md)
- [Sealed Approvals](./Sealed%20Approvals.md)
- [Petal derived keys and package succession](./Petal%20derived%20key%20succession.md)
