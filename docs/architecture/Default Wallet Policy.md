# Default Wallet Policy

**Status:** design proposal, updated for the implementation on 2026-10-30
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
  -> persona           choose Institutional, Trader or Degen for main
                       (`bloom init --persona degen` chooses without asking)
  -> setup menu        choose which Petals main's policy allows: Polymarket,
                       Hyperliquid, Enso, NEAR Intents, Feedback
                       review Polymarket's daily buy limit, suggested by the persona
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
  -> an update preserves that Petal's settings and trade receipts
```

Today the same setup takes a creation ceremony plus one policy ceremony for
each Petal, each interrupting the first operation that needs it.

## Decisions

Agreed on 2026-09-14:

1. **Only the `bloom` repository changes.** Broker, Signer, and Petal
   repositories are untouched.
2. **`bloom init` opens a setup menu** where the user chooses their Petals.
   It offers Bloom's canonical Petals: Polymarket, Hyperliquid, Enso, NEAR
   Intents, and Feedback. Bloom installs all of them for every home; the menu
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
   spending, and the wallet policy only allows the chosen Petals and, for
   Degen, its `erc20:any-recipient` entry (decision 15).
8. **Polymarket uses its existing settings:** trading turned on, with a daily
   limit of 100 pUSD.
9. **Petal settings survive an update.** Signed package lineage carries a
   Petal's settings and receipts to its successor release (section 5). Bloom
   writes setup's values after an update only when `main`'s account does not
   exist yet, so nothing the owner wrote is replaced.
10. **`bloom init` runs once.** Afterwards users add, update, or remove
    Petals. Setup is recorded when it finishes, so a run that was
    interrupted, or a config `bloom serve` created first, still gets setup
    on the next `bloom init`.
11. **Enso owns its own route rules.** Bloom writes no Enso settings. The
    pinned Enso v0.1.6 keeps per-account rules at
    `settings/<wallet>/<index>/venue.toml` and ships defaults covering the 13
    chains it supports, so a fresh wallet can swap without a setup write. The
    owner can replace those rules through Enso's own route. Bloom's part is
    decision 13: allowing Enso's router as a destination on each of those
    chains.

    Enso's shipped rules allow at most 100 bps of slippage and do not require
    calldata verification, because Enso cannot yet prove a route's receiver or
    minimum output; each plan still reports both as warnings. Enso v0.1.6's
    shipped rules name BNB Chain `bnb` while Bloom names it `bsc`, so they
    refuse `bsc` routes until they use Bloom's name. Its token-symbol table
    covers every chain it supports except Arc, where an intent needs `0x`
    token addresses.
12. **Feedback needs no setup settings or destination allowance.** It is the
    fifth canonical Petal, replacing retired Tolly. Setup does not enable any
    Petal's runtime writes.
13. **Chosen Petals' fixed contracts become allowed destinations.** Machine
    refuses any outbox transaction whose `to` address is not in the wallet
    policy's `allowed_destinations`, and an empty list refuses all of them, so
    allowing a Petal without its contracts leaves it installed but gated. Each
    catalog entry lists the fixed contracts its Petal transacts with, and the
    default policy proposes them in the same ceremony as the packages —
    including the ceremony a chosen Petal opens on its own first use while
    `main`'s policy is still the one wallet creation installed. After that a
    Petal's own request adds only its package, and a destination it needs is
    added with `bloom wallet update-policy`:
    - Enso: its router on every chain its shipped rules allow — one address
      on Arbitrum, Avalanche, Base, BNB Chain, Ethereum, Gnosis, HyperEVM,
      Optimism, and Polygon, a second on Linea, and a third shared by Arc,
      Robinhood Chain, and Tempo. Each address is Enso's published deployment,
      checked with `eth_getCode`, and never taken from a quote.
    - NEAR Intents: `petal:near-intents` on Arbitrum, Avalanche, Base, BNB
      Chain, Ethereum, Gnosis, Optimism, and Polygon (decision 14).
    - Polymarket: pUSD, native USDC, USDC.e, and Enso Router V2 on Polygon,
      for funding its deposit wallet. A swap's exact approval goes to the
      input token, so each token an owner can fund from needs its own entry;
      native USDC is included because it is what a Polygon wallet normally
      holds.

    Destinations that change per transaction cannot be listed ahead of time,
    such as the token contract for a swap from a token the catalog does not
    list. Those still need a policy update. A transaction staged before such a
    change keeps its denial, because policy is evaluated once at staging, so
    create a fresh request afterwards rather than confirming the old one.
14. **A Petal may be trusted with every destination it calls.** NEAR Intents deposits
    go to a fresh address for every quote, signed by the 1Click API, so no
    address can be listed in advance. Its catalog entries are
    `petal:near-intents` on the chains it supports, and Machine accepts the
    destination of a transaction that Petal staged, matching the entry against
    the `petal_id` recorded on the outbox entry. This is a broad grant for any
    transaction that Petal stages on those chains, including arbitrary
    calldata and token approvals. It is not restricted to deposits or
    verified quotes. Petals stage raw transactions: for an ERC-20 transfer,
    Machine checks the token contract's `to` address, not the recipient
    encoded in its calldata. This entry does not decode or restrict that
    recipient.

    What that does not do: it covers only that Petal, only on the chains
    listed, and only for transactions it staged. A different Petal, or a
    transaction the owner stages by hand, still matches the listed addresses.
    Every transaction is still an approval the owner signs, and deleting the entry
    gates the Petal again.

    What it does not change: whether the Petal's package is allowed at all.
    That is a separate gate, and it runs later rather than earlier. The
    destination check, including this entry, is evaluated once at staging;
    the package check happens at confirm, where `evm_tx_confirm` calls
    `ensure_petal_eligibility` and refuses with a pending policy proposal if
    the hash is absent from `allowed_petal_packages`. So a Petal whose
    package the wallet has not allowed can still cause an outbox entry to be
    staged against a `petal:` entry naming it — it simply cannot confirm it,
    and nothing is signed or broadcast. This decision neither adds that check
    nor relaxes it.

    What the pinned release (v0.1.4) enforces: the deposit address comes from
    a quote whose signature the Petal verifies, the quote must echo the
    request's amount, assets, slippage and recipient, refunds go to the
    wallet, and slippage is at most 1000 bps. It has no input cap, and the
    payout recipient is whatever the request names, which need not be the
    wallet. A per-wallet venue policy that caps the input and pins the payout
    to the wallet is in
    [bloom-petal-near#11](https://github.com/bloom-directory/bloom-petal-near/pull/11),
    not yet released. Machine does not independently enforce any of these
    quote or deposit constraints. The owner is trusting that Petal's logic for every
    destination it calls on those chains; all other applicable policy checks
    and each transaction's owner approval remain required.
15. **`bloom init` asks for a persona for `main`.** Institutional (the
    default, also accepted as `custodian`), Trader or Degen is saved as
    `[persona]` in Bloom's config. `bloom init --persona <name>` chooses
    without asking and replaces a saved choice; otherwise only first setup
    asks, and a home without one behaves as Institutional. Choosing one
    grants nothing by itself, and every transaction is still approved by the
    owner (decision 6):
    - **Institutional** keeps everything above.
    - **Trader** and **Degen** suggest Polymarket daily buy limits of 1,000
      and 10,000 pUSD rather than 100 during first setup: their pUSD token
      quantities, not a price. That daily limit is all a persona sets here:
      no per-action cap and no session length. The saved `[persona]` still
      records `window_secs`, which only bloom#377 reads. The owner can
      change the suggestion, and a saved value is kept.
    - **Degen** also adds
      `{"chain": "evm-1", "destination": "erc20:any-recipient"}`, and the same
      on `evm-137`, for configured Ethereum and Polygon. Only that
      `evm-<chain id>` spelling counts: the same string under a Bloom chain
      name, such as `ethereum`, opts in to nothing. It is required like a
      chosen Petal's destinations, and is the only addition here that does not
      come from a Petal. Machine then stages the wallet's own canonical
      ERC-20 transfer of a token in Bloom's curated table
      (`bloom_proto::tokens`) to any recipient on those chains. Only the
      exact-transaction path uses it, never a Petal, and a token outside the
      table still needs its recipient listed, because any contract can answer
      `decimals()` and run its own code under the `transfer` selector. Broker
      checks no destination on that exact approval, so the owner's approval
      of each transfer is the check. Until bloom-broker#112 is pinned, the
      policy ceremony shows the entry as written.

    A persona chosen later does not reach back. On a home whose setup already
    ran, `bloom init --persona` saves it and says that the Petal limits from
    setup are unchanged. Degen's entry is proposed only while `main`'s policy
    is still the one wallet creation installed; otherwise
    `bloom wallet default-policy main` reports it missing, with the entries
    to add through `bloom wallet update-policy`. Leaving Degen does not
    remove the entry, because Bloom never removes one: that command reports
    what the policy still allows beyond the saved persona, and how to remove
    it. Machine reads the persona from the config each time it proposes. A
    saved persona that no longer parses or validates is set aside with a
    warning, so Machine still starts and `bloom init --persona` can replace
    it.

    Reusable Trader and Degen sessions come from section 6. With bloom#377
    and bloom-broker#112, an approved Degen session can also sign those
    transfers within its token limits.

## Why it does not work today

| Area | What happens now |
|---|---|
| Wallet creation | The create and import ceremony writes a policy that allows no Petals |
| First use of each Petal | Machine proposes a policy update for that one package, fails the operation with `POLICY_APPROVAL_REQUIRED`, and the owner signs a policy ceremony before retrying |
| `bloom wallet new` | Returns the ceremony URL immediately. Nothing follows up once the owner completes it ([bloom#199](https://github.com/bloom-directory/bloom/issues/199)) |
| `bloom init` | Installs Bloom's canonical Petals without asking anything. The CLI has no interactive prompts |
| Petal changes | `bloom petals install` and `bloom petals uninstall` change installed packages but never propose a policy change |
| Polymarket | Trading is off until its `settings/<wallet>/<index>/venue.toml` sets `enabled = true` |

## Design

### 1. The setup menu

`bloom init` shows a menu when run in a terminal:

1. **Choose a persona** (decision 15): Institutional, the default, Trader or
   Degen. `--persona` answers this without asking; without a terminal,
   first setup records Institutional.
2. **Choose Petals.** Polymarket, Hyperliquid, Enso, NEAR Intents, and Feedback,
   all selected by default.
3. **Review settings.** Show Polymarket's suggested daily buy limit, 100
   pUSD, or 1,000 for Trader and 10,000 for Degen, and let the user change it.
   Only positive amounts are accepted.
4. **Confirm.** Save the choices in Bloom's config, install Bloom's canonical
   Petals, and write each chosen Petal's settings. A settings write that
   fails is reported and setup continues; that Petal refuses to act until its
   settings exist.

Bloom installs its canonical Petals (`DEFAULT_PETALS` in
`crates/bloom/src/github_source.rs`) for every home and ignores the legacy
`[petals] preinstalled` setting. Setup records each chosen Petal under
`[petals.setup]`, with the values the menu asked about, and the default
policy proposes exactly these Petals. Canonical setup does not add runtime
write switches. The persona is recorded under `[persona]`; Institutional is
stored by its legacy name, `custodian`:

```toml
[persona]
schema_version = 2
preset = "custodian"
window_secs = 0

[petals.setup.enso]

[petals.setup.hyperliquid]

[petals.setup.near-intents]

[petals.setup.polymarket.values]
max_daily_usd = "100"

[petals.setup.feedback]
```

The policy uses the installed package hash for each chosen name, so a Petal
installed another way, such as the local builds the developer triad installs,
is still proposed when chosen.

Bloom's built-in catalog (`crates/bloom/src/github_source.rs`) holds each
Petal's settings template next to its pinned release. For Polymarket that is
`settings/{wallet}/0/venue.toml` with `enabled = true` and the daily limit.
Bloom substitutes the saved values, falling back to the catalog's
suggestions, and writes the result through the Petal's own settings route,
so it never interprets a Petal's settings format.

The menu runs only on first-time setup and only in a terminal. Setup is
recorded by `setup_complete = true` under `[petals]`, saved together with
the choices once the menu finishes; a config file on its own proves nothing,
because `bloom serve` creates one too, and an interrupted menu saves nothing.
An empty `[petals.setup]` is not the marker either: declining every Petal is
a valid choice. Scripts and packaged installs record the catalog's
suggestions instead of asking. Later runs of `bloom init` see the marker and
use the config as it is, with the catalog's suggestions for any value not
saved.

Setup also runs once on a config that predates the marker, such as a home
upgraded from v0.3.x or one set up by an earlier build. Choices it already
records are the suggestions: the menu suggests a Petal only if it was chosen
and each value as saved, and the non-interactive form keeps them unchanged,
so a declined Petal stays declined. With no recorded choices every Petal is
suggested. Setup never replaces settings the owner may already hold, and
writes its own only while the Petal stores nothing for them. An
uninstall keeps a Petal's private data under its package hash, so a
reinstall of the same release finds the owner's settings and keeps them; a
different release starts empty and receives setup's settings. For a
Petal that was already installed and is unchanged, `bloom init` writes setup
settings only when Machine reports that `main`'s account does not exist. If
the account exists, or its existence cannot be read (for example because
Broker is down), it writes nothing, clears any pending retry for that Petal,
and prints the exact settings and the command that would apply them. A
later `bloom init` still finishes a write that an interrupted setup queued
(section 3).

### 2. The default policy

The default policy uses today's wallet policy format. Setup fills in the
chosen Petals:

```json
{
  "wallet_id": "main",
  "maximum_approval_lifetime_ms": 2592000000,
  "allowed_petal_packages": [
    "07fdcc9841c88de8fe1d0b4526bc01deac004c1c7dec202e2c8d7443300f22af",
    "6eb2065e8558f3761399fcb0516731a600fdb0b49974c8ed0808abd38fde7db4"
  ],
  "allowed_destinations": [
    { "chain": "polygon", "destination": "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb" },
    { "chain": "polygon", "destination": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359" },
    { "chain": "polygon", "destination": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174" },
    { "chain": "polygon", "destination": "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf" }
  ],
  "required_verifiers": []
}
```

- **`allowed_petal_packages`** lists each chosen Petal by the exact hash
  Bloom's catalog pins: Hyperliquid v0.1.7 and Polymarket v0.1.8.
- **`allowed_destinations`** lists the fixed contracts each chosen Petal
  transacts with (decision 13), from Bloom's catalog only; an edited config
  cannot add any. Existing destinations are kept. Only a wallet's first
  policy is proposed, so a destination added to the catalog later reaches an
  existing wallet only through `bloom wallet update-policy`, or through a
  flow that sets `owner_just_chose` (section 3). If a chosen Petal's install
  record cannot be read, the first proposal stops with an error rather than
  leave that Petal out: once a first policy commits, nothing would add it
  back.
- **Everything else** keeps the current defaults: approvals last at most 30
  days, and verifiers start empty.

### 3. Signing it right after creation

`bloom wallet new main` and `bloom wallet import main`:

1. Launch the creation ceremony, as today.
2. Ask Machine every two seconds where the default policy stands, through the
   `wallet_default_policy` Machine command, until the wallet exists or its
   creation ceremony expires. A Broker refusal that may clear up when the
   same request is made again (unavailable, rate-limited or over quota, for
   example while another ceremony for the wallet is open) is waited out
   within the same deadline rather than ending the command. The command says
   once that it is waiting, and if the deadline passes it names the refusal
   and what to wait for before running it again.
3. Machine proposes every chosen, installed Petal together through the
   wallet's existing policy operation, the same pending-proposal flow the
   mounted `wallets/<wallet>/policy.json` uses. The command prints that
   ceremony's URL once.
4. Once the owner completes the ceremony, the next check commits the policy,
   and the command reports that `main` now allows the chosen Petals.

When the choices are saved, before anything is installed, setup queues a
retry marker for each settings write it is about to make, so a `bloom init`
that stops part-way still writes them later. It queues only what the run
itself would write (section 1): a Petal that is not installed yet, or one
already installed while `main`'s account is known not to exist. For an
installed Petal whose account exists or cannot be checked, it clears any
marker instead. On a new home `main` does not exist when `bloom init` runs,
so its settings write is refused and the marker stays. The first check after
`main` appears writes the settings: the wallet-creation flow's, `bloom wallet
default-policy main`, a rerun of `bloom init` once `main` exists, or `bloom
serve`, which checks every 30 seconds while a write is queued, so a `main`
an agent creates by writing `wallets/new` gets them too. A rerun of `bloom
init` covers a home where `main` already existed, so no wallet creation
follows; a rerun that updates the Petal instead keeps the settings it
carries, clears the marker and prints the command (section 1). A queued
write that fails stays queued, and a command that stops on an applied or
changed policy names the command that retries it. It writes them only while
the Petal stores nothing for them: for Polymarket, no
`state/settings/main/venue.toml` in account 0's partition of its private
store (its SDK's `state` namespace plus its own key), pinned with the
release. What the route reads cannot decide this, because
Polymarket reads its built-in `enabled = false` and `allow_neg_risk = true`
default both when nothing is stored and when the owner saved exactly that.
The route's handler makes the check and the write one step: the Petal router
holds that Petal's write lock alone while it checks the store, as a run of
the route would open it (after carrying a replaced release's data forward),
and writes through the route, while ordinary writes to the Petal share the
lock, so an owner's edit made meanwhile is never replaced. The VFS
holds only the lock every ordinary write holds, so the route's callbacks can
write elsewhere through it. If writes to the Petal keep running for two
seconds, the check gives up and the marker stays for the next one. Anything
else there may be the owner's, so it stays: Machine clears the marker and
logs the command that would apply setup's choice.

The key is pinned for one release, so setup writes only when the installed
package hash is the catalog's pinned hash. Another release under the same
name, such as a fork or a newer release the catalog has not pinned, may store
its settings elsewhere, where the check could not see them, so Machine keeps
what it holds, clears the marker and prints the manual command. After a
write, Machine asks once more and expects the key to be stored now. If the
second write would also go ahead, the key is not where the release stores its
settings and the check protects nothing: Machine reports
`petal_settings_unprotected` (logged as
`petal.setup_settings_key_not_stored`), clears the marker so it does not
retry, and the end-to-end test fails on that log event.

If the owner stops the command, or the policy ceremony expires, the wallet
still exists:

- **`bloom wallet default-policy main`** picks up where the command stopped.
  It shows a ceremony that is still open, or opens a new one after expiry.
  The Broker reports an expired ceremony as awaiting the owner until asked to
  act on it, so Machine cancels a proposal past its expiry and proposes again.
  A waiting command never announces a ceremony that has already expired.
  It proposes only while `main`'s policy is still the one wallet creation
  installed. Once any change has been committed, it reports which chosen
  Petals the policy does not allow and proposes nothing, so a Petal or
  destination the owner removed is never proposed again. A flow that has just
  recorded the owner's choice, such as browser onboarding, sets
  `owner_just_chose` on the `wallet_default_policy` command to propose that
  choice anyway; the CLI never sets it.
- **Several commands can wait on the same wallet.** Only one updates its
  policy at a time; a command that finds the wallet's policy lock held checks
  again on its next poll instead of failing.
- **The first Petal operation on `main`** also proposes the whole default
  policy, not just its own package. `ensure_petal_eligibility` adds the
  chosen Petals to its proposal for the default-policy wallet. "First" is
  read from the Broker's policy version: wallet creation installs the
  restrictive policy at version 1 and every committed change increments it,
  so a policy the owner has changed, including one the owner emptied of every
  Petal, is never treated as new and gets only the requested package.

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
| Update a Petal by installing a newer release | Replace the old package hash with the new one | Preserved through the signed package lineage; initial settings are written only when the wallet is known not to exist |
| Remove a Petal with `bloom petals uninstall` | Remove its package hash | Kept on disk under the package hash; a reinstall of the same release finds them, and setup leaves them as they are |

An update carries settings and trade receipts forward through the signed
package lineage (`crates/bloom-petals/src/private_store.rs`). Bloom preserves
these values when the wallet already exists, including settings written
through the Petal after setup. If Broker cannot establish whether the wallet
exists, Bloom leaves the settings untouched. Setup choices remain in Bloom's
config; the owner can explicitly apply them later.

Catalog Petals are installed and updated in two places: `bloom init`
(`ensure_preinstalled_petals`) and every `bloom serve` start
(`petal_provisioning::provision`). A fresh install receives the saved settings
when the Petal stores nothing for them, which holds unless the same release
was installed before and its settings kept. An update receives them
only when the default wallet is known not to exist, and on the same terms.
`bloom init` prints the outcome, and `bloom serve` logs it.

Each change is one policy update ceremony. Changes waiting at the same time
merge into one proposal, as Machine already reconciles pending proposals.

### 6. Persona sessions

Two draft stacks add reusable session approvals for the persona chosen at
`bloom init` (decision 15). Neither is merged, and this design does not
depend on them: section 4 holds until they land.

- [bloom#352](https://github.com/bloom-directory/bloom/pull/352) adds browser
  onboarding for an existing wallet and bounded sessions, with
  [bloom-broker#100](https://github.com/bloom-directory/bloom-broker/pull/100),
  [bloom-signer#68](https://github.com/bloom-directory/bloom-signer/pull/68)
  and
  [bloom-petal-polymarket#19](https://github.com/bloom-directory/bloom-petal-polymarket/pull/19).
  Trader suggests 100 pUSD per action and 1,000 per rolling day for 24
  hours; Degen suggests 1,000 per action and 10,000 per rolling day for
  seven days. These are nominal amounts, not a USD valuation or a maximum
  loss. Automatic coverage is limited to eligible Polymarket BUYs. Explicit
  transfer sessions, native and canonical ERC-20, cover Ethereum, Polygon and
  local chain 31337, to recipients the policy lists as `evm-<chain id>`
  destinations, which this design does not propose. Every other action keeps
  exact approval, and several scopes can need separate activation ceremonies.
- [bloom#377](https://github.com/bloom-directory/bloom/pull/377), built on
  bloom#352's Machine commits, replaces those limits with recurring
  per-token allowances: Trader per rolling 24 hours, Degen per rolling seven
  days. It pins
  [bloom-broker#112](https://github.com/bloom-directory/bloom-broker/pull/112),
  which builds on bloom-broker#100,
  [bloom-signer#81](https://github.com/bloom-directory/bloom-signer/pull/81),
  which does not build on bloom-signer#68, and
  [petal#52](https://github.com/bloom-directory/petal/pull/52). It uses
  [bloom-petal-polymarket#26](https://github.com/bloom-directory/bloom-petal-polymarket/pull/26);
  neither stack pins a Polymarket PR, and both still install v0.1.6. With
  bloom-broker#112, a Degen session also covers the any-recipient ERC-20
  transfers in decision 15.

This design follows bloom#377: its persona names, config (`[persona]` and
`bloom_proto::persona`, schema 2) and Degen policy entry. bloom#352 calls
Institutional "Custodian": `--persona custodian` also works, and the config
saves `preset = "custodian"` either way. bloom#352 saves `[persona]` as
schema 1, with configurable dollar limits, and the two schemas cannot share a
home. bloom#352 refuses to load a config whose `[persona]` is schema 2. This
design sets a schema 1 persona aside as Institutional, with a warning, and
drops it at the next config save. bloom#377 already replaces schema 1 with
these types, so bloom#352 takes them when it rebases. The contract between
this design and those stacks:

- **The policy stays the boundary.** A persona session is a reusable Sealed
  Approval with its own token allowances. It adds no package or destination
  and is usable only within what this policy already allows. The persona's
  own entry, Degen's `erc20:any-recipient`, comes from this default policy.
  Activation for Polymarket is refused until Polymarket is in the signed
  policy, so the default policy is applied first. Choosing a persona grants
  nothing on its own. bloom#377's recurring allowances also need the
  policy's maximum approval lifetime at its standing value
  (`STANDING_APPROVAL_POLICY_LIFETIME_MS`). This design never proposes that.
  bloom#377 adds it to the same default-policy proposal for Trader and Degen
  (`standing`). Rebased, the lifetime also belongs in the check that finds
  the policy already allowed, so it stays one ceremony. Only a wallet whose
  default policy committed without it needs another, which onboarding
  proposes with `owner_just_chose`.
- **A policy change ends persona sessions.** A session and its budget are
  bound to the policy version and digest they were approved under. Any later
  policy commit stops them signing:
  - a per-Petal proposal from section 5;
  - a Petal update's new package hash;
  - an owner's `bloom wallet update-policy`.

  The owner then re-activates. Re-activation is a new reviewed approval with a
  fresh budget, so a daily limit restarts after each policy change and
  re-review.
- **A fresh choice is proposed explicitly.** Browser onboarding saves the
  owner's Petal selection and then applies it through `wallet_default_policy`.
  Once the wallet's policy has changed since creation, that command proposes
  only with `owner_just_chose` set. Without it the owner sees which Petals
  are not allowed, and nothing is proposed. bloom#352 and bloom#377 predate
  this rule and propose at any policy version. Rebased, their
  `WalletDefaultPolicy { name }` no longer compiles: onboarding must set
  `owner_just_chose` only right after it saves the selection. It should
  preselect from `[petals.setup]` while the policy is still the one creation
  installed, and from what the current policy allows after that. Inside Machine
  this is `AfterPolicyChange::Propose` rather than a `bool`, so another flag
  passed in its place, such as bloom#377's `standing`, does not compile;
  `standing` stays a separate argument.
- **The persona's entry is for `main`.** Onboarding can pick any existing
  wallet. For a wallet other than `main`, the command proposes the chosen
  Petals but not Degen's `erc20:any-recipient` entry, so a Degen session on
  that wallet cannot cover those transfers until the owner adds the entry.
  bloom#377 proposes the entry for whichever wallet onboarding picks;
  rebased on this design, that narrows to `main`.
- **The persona is read when it is used.** Machine reads `[persona]` from the
  config each time it proposes a default policy, not once at startup, so a
  persona that browser onboarding saves on a running Machine is the one
  proposed.
- **Two limits; the lower applies.** Polymarket's `max_daily_usd`, written by
  setup, is enforced by the Petal before it asks for a signature. A persona
  session's token allowance is enforced by Broker and Signer. They are
  independent, and a buy must pass both. First setup suggests the Polymarket
  limit from the persona (decision 15), so it starts at Trader's or Degen's
  pUSD quantity rather than 100. These are the daily values bloom#352 writes,
  with no per-action cap. Under bloom#377, Degen's 10,000 pUSD is a seven-day
  allowance, so the session's limit is the stricter one. A persona chosen
  after setup leaves the saved limit alone, so a Trader session activated
  later is still capped by the limit setup wrote: 100 pUSD under
  Institutional, if Polymarket was chosen. If it was not, setup wrote nothing
  and Polymarket refuses buys until its settings exist.
- **Destination chain names differ.** This policy names a Petal's destinations
  by Bloom chain name, such as `polygon`. Typed persona sessions for native and
  ERC-20 transfers match destinations named `evm-<chain id>`, such as
  `evm-137`, and Degen's entry already uses that naming. The catalog
  destinations proposed here authorize Petal transactions, not typed session
  transfers, which need destinations of their own.
- **Pending settings.** This design records a pending setup setting as an empty
  marker file, `pending-petal-settings/<name>`. bloom#352, and bloom#377 on
  top of it, write a versioned journal entry at the same path that binds the
  package hash, the settings and the config revision. On a home upgraded
  from this design they keep the empty marker and then refuse it ("legacy
  setup obligation has no frozen package/config revision"), so they must
  migrate or reconcile these markers. A build of this design on a home
  bloom#352 used treats their entry as its own marker: it writes
  `[petals.setup]`'s values for that Petal and deletes the entry, or leaves
  an empty marker if the write fails.
- **Versions.** The sessions need Broker and Signer changes that are not
  merged, and each accepts exactly one protocol minor: bloom-signer#68 only
  Broker–Signer 1.7, and bloom-broker#100 only Machine–Broker 1.8. The pinned
  Broker and Signer speak Machine–Broker 1.7 and Broker–Signer 1.6, so
  bloom#352's stack ships bloom-signer#68, bloom-broker#100 (which pins it)
  and Machine as one Triad release. Broker master has since moved on: it
  already uses Machine–Broker 1.8 for bloom-broker#103, which
  bloom-broker#100 does not contain, and it refuses declared debits on
  Polymarket order approvals. Rebased, bloom-broker#100 needs a new minor and
  a check of those debits against Broker's own rebuild, as bloom-broker#112
  has; otherwise Broker refuses every bloom-petal-polymarket#19 order.
  bloom#377's pins speak Broker–Signer 1.8 and Machine–Broker 1.10.
  Polymarket coverage also needs a published Polymarket package that
  declares its debits to Broker. None does yet: v0.1.6, v0.1.8 (pinned here)
  and v0.2.0 declare none for any signature.
  bloom-petal-polymarket#19 adds them for bloom#352, and
  bloom-petal-polymarket#26, which contains it, for bloom#377; both conflict
  with main. This design keeps the current Broker, Signer and Polymarket pins
  until then. Bloom
  defines the `erc20:any-recipient` string
  (`bloom_proto::policy::ERC20_ANY_RECIPIENT`) until it can use
  bloom-broker#112's `bloom_broker_api::ERC20_ANY_RECIPIENT`; the two must
  stay equal.

## What still asks the owner

- **Setup:** the creation ceremony and the default policy ceremony.
- **Every transaction:** each swap, trade, token approval, Polymarket
  onboarding step, and Hyperliquid owner action. This design has no persona
  sessions. With bloom#352 or bloom#377, one can cover some of these
  (section 6), such as an eligible Polymarket BUY, or with bloom#377 and
  bloom-broker#112 a Degen ERC-20 transfer.
- **Hyperliquid sessions:** a key-derivation ceremony and an approval
  ([bloom#171](https://github.com/bloom-directory/bloom/issues/171)).
- **Petal changes:** one policy update ceremony each.

## A starting profile, not a cage

The Petals chosen during setup are an installation profile: a safe default
that makes a new wallet usable in one ceremony. It is deliberately the
narrowest thing that works — the chosen packages and the fixed contracts they
transact with, plus Degen's `erc20:any-recipient` entry (decision 15), and
nothing else.

It is a starting point, not a fixed set. Owners can narrow or widen it later
through the ordinary policy ceremony (`bloom wallet update-policy`), add or
remove Petals, and replace each Petal's own settings through that Petal's
routes. Bloom never removes a restriction the owner put in place: proposals
only add, every change is a ceremony the owner signs, and a package or
destination the owner removed is not proposed again behind a later request
(see decision 13 and `first_proposal` in `ensure_policy_allows`).

## Security properties

- Setup only proposes. Nothing is allowed until the owner signs the policy
  ceremony.
- The policy allows exactly the package hashes it lists. A different or
  tampered build does not match.
- Allowed destinations are addresses pinned in Bloom's source and shown in
  the policy ceremony, never taken from a quote or a Petal at runtime. There
  are two exceptions, both pinned in Bloom's source and neither an address:
  a `petal:<name>` entry (decision 14), which names the Petal, and Degen's
  `erc20:any-recipient` (decision 15). The second lifts Machine's recipient
  check for the wallet's own curated ERC-20 transfers. Broker checks no
  destination on an exact approval, so the owner's approval of each transfer
  is the recipient check.
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
| Keep Petal settings across updates outside a signed package lineage | The stable installation slot in [Petal derived keys and package succession](./Petal%20derived%20key%20succession.md) |
| Accept Bloom's `bsc` chain name so BNB Chain routes work | bloom-petal-enso |
| Create Hyperliquid sessions with fewer ceremonies | [bloom#171](https://github.com/bloom-directory/bloom/issues/171) |
| Agree one chain naming for Petal policy destinations and typed persona sessions | bloom, bloom-broker ([bloom-broker#100](https://github.com/bloom-directory/bloom-broker/pull/100), [bloom-broker#112](https://github.com/bloom-directory/bloom-broker/pull/112)) |
| Migrate pending setup-settings markers to versioned journals | bloom ([bloom#352](https://github.com/bloom-directory/bloom/pull/352)) |

## Implementation plan

All in the `bloom` repository. The first part is built; proposals from Petal
changes come next.

**Built**

- **Setup** (`crates/bloom/src/default_policy.rs`, `crates/bloom-proto`):
  the `bloom init` menu and its non-interactive form, settings templates in
  the catalog, and choices saved under `[petals.setup]` together with a
  queued settings write for each chosen Petal setup will write. Settings are
  written through
  each Petal's route by `bloom init`, and by `bloom serve` when it installs a
  chosen Petal. An update keeps the settings its signed package lineage
  carries. A queued write that cannot be made yet is retried once `main`'s
  account exists, by wallet creation, `bloom wallet default-policy`, a rerun
  of `bloom init` or `bloom serve`, and only while nothing is stored.
- **Wallet creation** (`crates/bloom`): `bloom wallet new main` and
  `bloom wallet import main` wait for the wallet, then walk the owner
  through the default policy with the `wallet_default_policy` Machine
  command. `bloom wallet default-policy` resumes it.
- **Policy proposal** (`crates/bloom-vfs`, `crates/bloom-machine-client`,
  `crates/bloom-daemon`): `ensure_petal_packages_allowed` proposes several
  packages through the wallet's existing policy operation, and
  `ensure_petal_eligibility` adds the chosen Petals for `main`.
- **Personas** (`crates/bloom-proto/src/persona.rs`, `crates/bloom`,
  `crates/bloom-tx`, `crates/bloom-vfs/src/planning.rs`): the persona
  question and `--persona`, Polymarket's suggested limit, Degen's
  `erc20:any-recipient` entry and staging exemption, and the report of a
  missing or leftover entry.

**Next**

- **Petal changes** (`crates/bloom`): propose policy updates from
  `bloom petals install`, newer releases, and `bloom petals uninstall`.

### Tests

Automated:

- The menu offers Bloom's five canonical Petals, records declines, rejects
  invalid limits, and accepts the suggestions at the end of input. On a
  config with earlier choices it suggests exactly those choices and saved
  values. The scripted form chooses every canonical Petal on a fresh config,
  keeps earlier choices (declines included) and values on an existing one,
  and leaves runtime values unchanged.
- `bloom init` on an existing config with a declined Petal and a custom cap
  keeps both.
- The settings decision writes for a Petal just installed, and for one
  already installed or updated only when `main`'s account is reported
  absent. An existing account, or an account read that fails for any reason
  other than "not found", keeps the owner's settings. The integrated path
  (`init` against a live projection, with Broker up and down) is checked on
  a developer triad, not in CI.
- Every setup write goes in only while the Petal stores nothing for it: a
  reinstalled Petal's surviving settings, settings the owner saved as the
  exact default, and an owner's write made during the check all stay. A direct VFS write during a paused
  check lands after it, a check's own callbacks and other writes can write
  through the VFS meanwhile, and a check gives up untouched while writes to
  its key keep running (`crates/bloom-vfs/src/router.rs`). The Petal router
  checks the key in the route's account partition and holds the Petal alone
  for it (`crates/bloom-petals/src/router.rs`).
- A queued write that fails stays queued and is reported with the command
  that retries it; one whose retry cannot be recorded says so and gives the
  manual command. `bloom serve` makes a queued write once `main` exists.
- Setup queues exactly the writes an uninterrupted run would make, before
  `setup_complete` is saved; an interrupted `bloom init` leaves them queued
  (`crates/bloom/tests/cli.rs`). A rerun finishes a queued write once
  `main` exists, and says how to make it when Broker cannot tell.
- The wallet read and the policy step wait out Broker refusals that may
  clear up (unavailable, rate-limited, over quota) and end on any other
  error. The wait says once why it is polling, and its final message names
  what to wait for.
- Chosen Petals round-trip through `config.toml`, and an edited value that
  is not a positive amount cannot change a Petal's settings file.
- The wait announces each ceremony once, stops when the policy is applied,
  never announces a ceremony that has already expired, and polls quietly
  while another command holds the wallet's policy lock.
- One policy ceremony allows every chosen package, and packages are added
  once, in order. A chosen Petal whose install record cannot be read stops
  the first proposal instead of being left out of it. An expired proposal, including one the Broker still reports
  as awaiting the owner, is replaced by a new ceremony
  (`crates/bloom-vfs/tests/triad_policy_update.rs`).
- Catalog provisioning reports an update separately from a fresh install.
- Each persona's menu choice, `--persona` and Polymarket suggestion; Degen's
  entry on configured chains and for `main` only; an unusable saved persona
  set aside; staging that passes only the wallet's own curated ERC-20
  transfer with the entry; and the planner honouring the entry only under
  `evm-<chain id>`.

Manual, on the developer triad:

- `bloom wallet new main` runs two ceremonies and commits a policy allowing
  exactly the chosen packages. `bloom wallet default-policy main` then
  reports it applied without a new ceremony, finishes a queued settings
  write without replacing the owner's, and proposes nothing once the owner
  has changed the policy (`scripts/test-default-policy-e2e.sh`).
- A chosen Petal's first signed action on `main` asks only for that
  action's approval, while a wallet without the default policy is first
  asked to allow the Petal's package.

Next part:

- Adding, updating, and removing a Petal propose the expected policy change.

## Related documents

- [Wallet Architecture](./Wallet.md)
- [Sealed Approvals](./Sealed%20Approvals.md)
- [Petal derived keys and package succession](./Petal%20derived%20key%20succession.md)
- Persona onboarding and bounded sessions: [bloom#352](https://github.com/bloom-directory/bloom/pull/352), with [bloom-broker#100](https://github.com/bloom-directory/bloom-broker/pull/100), [bloom-signer#68](https://github.com/bloom-directory/bloom-signer/pull/68) and [bloom-petal-polymarket#19](https://github.com/bloom-directory/bloom-petal-polymarket/pull/19)
- Recurring token allowances and Degen's any-recipient transfers: [bloom#377](https://github.com/bloom-directory/bloom/pull/377), with [bloom-broker#112](https://github.com/bloom-directory/bloom-broker/pull/112), [bloom-signer#81](https://github.com/bloom-directory/bloom-signer/pull/81), [bloom-petal-polymarket#26](https://github.com/bloom-directory/bloom-petal-polymarket/pull/26) and [petal#52](https://github.com/bloom-directory/petal/pull/52)
