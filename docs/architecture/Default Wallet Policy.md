# Default Wallet Policy

**Status:** design proposal, updated for the implementation on 2026-10-30;
decisions 16 to 21, agreed on 2026-11-03, supersede parts of decisions 4 and 15
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

later: switch a wallet's persona  (bloom wallet persona <wallet> <persona>)
  -> setup menu        choose that wallet's Petals again, from the new
                       persona's suggestions
  -> resets            each chosen Petal's limits to the new persona's
  -> one ceremony      replaces the wallet's policy with what the new
                       setup allows
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
   start with today's empty policy, until their owner chooses a persona for
   one (decision 17).
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
   exist yet, or when a write setup queued earlier is still waiting, and in
   both cases only while nothing is stored, so nothing the owner wrote is
   replaced.
10. **`bloom init` runs once.** Afterwards users add, update, or remove
    Petals. Setup is recorded when it finishes, so a run that was
    interrupted, or a config `bloom serve` created first, still gets setup
    on the next `bloom init`.
11. **Enso owns its own route rules.** Bloom writes no Enso settings. The
    pinned Enso v0.1.7 keeps per-account rules at
    `settings/<wallet>/<index>/venue.toml` and ships defaults covering the 12
    chains it supports, by Bloom's chain names, so a fresh wallet can swap
    without a setup write. The
    owner can replace those rules through Enso's own route. Bloom's part is
    decision 13: allowing Enso's router as a destination on each of those
    chains.

    Enso's shipped rules allow at most 100 bps of slippage and do not require
    calldata verification. Same-chain routes carry Router V2 receiver and
    minimum-output checks; cross-chain routes stay unverified and are reported
    as warnings. Where its token-symbol table has no entry for a chain, an
    intent names tokens by `0x` address.
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
      Optimism, and Polygon, a second on Linea, and a third shared by
      Robinhood Chain and Tempo. Each address is Enso's published deployment,
      checked with `eth_getCode`, and never taken from a quote. Enso v0.1.7
      dropped Arc, so its router there is not proposed.
    - NEAR Intents: `petal:near-intents` on Arbitrum, Avalanche, Base, BNB
      Chain, Ethereum, Gnosis, Optimism, and Polygon (decision 14).
    - Polymarket: `petal:polymarket` on Polygon (decision 14). It funds its
      deposit wallet with a direct pUSD transfer to that wallet, or an Enso
      swap after an exact approval, all staged as calls to the token
      contracts and the Enso router. Machine takes a contract call's `to` as
      its recipient, so listing those contracts would let any Petal, or the
      agent, transfer or approve pUSD, USDC or USDC.e to anyone with a raw
      call. The entry trusts only what Polymarket itself stages there.

    Destinations that change per transaction cannot be listed ahead of time,
    such as the token contract for a swap from a token the catalog does not
    list. Those still need a policy update. A transaction staged before such a
    change keeps its denial, because policy is evaluated once at staging, so
    create a fresh request afterwards rather than confirming the old one.
14. **A Petal may be trusted with every destination it calls.** NEAR Intents deposits
    go to a fresh address for every quote, signed by the 1Click API, so no
    address can be listed in advance. Its catalog entries are
    `petal:near-intents` on the chains it supports; Polymarket's is
    `petal:polymarket` on Polygon, because its funding calls token contracts
    (decision 13). Machine accepts the
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

    What the pinned release (v0.1.5, as v0.1.4) enforces: the deposit address comes from
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
    default, also accepted as `custodian`), Trader or Degen is saved with
    `main`'s setup (decision 17). `bloom init --persona <name>` chooses
    without asking at first setup; afterwards a switch is a fresh start
    (decision 18). A wallet without one behaves as Institutional. Choosing one
    grants nothing by itself, and every transaction is still approved by the
    owner (decision 6):
    - **Institutional** keeps everything above.
    - **Trader** and **Degen** suggest Polymarket daily buy limits of 1,000
      and 10,000 pUSD rather than 100 during first setup: their pUSD token
      quantities, not a price. Besides that daily limit, a persona sets the
      approval lifetime (decision 19); no per-action cap and no session
      length. The saved persona still records `window_secs`, which only
      bloom#377 uses; this design checks only that it matches the preset.
      The owner can change the suggestion, and a saved value is kept until
      the persona is switched (decision 18).
    - **Degen** also adds
      `{"chain": "evm-1", "destination": "erc20:any-recipient"}`, and the same
      on `evm-137`, for configured Ethereum and Polygon. Only that
      `evm-<chain id>` spelling counts: the same string under a Bloom chain
      name, such as `ethereum`, opts in to nothing. It is required like a
      chosen Petal's destinations, and is the only addition here that does not
      come from a Petal. Machine then stages the wallet's own canonical
      ERC-20 transfer of a token in Bloom's curated policy list
      (`bloom_proto::policy::ANY_RECIPIENT_TOKENS`) to any recipient on those
      chains. That list stands in until Petals declare their tokens
      (decision 20). It covers chains 1, 10, 137, 8453 and 42161, so an
      owner-written entry works the same way on the other three, such as
      `evm-8453` for Base, although bloom-broker#112's sessions cover only
      chains 1, 137 and 31337. Only the
      exact-transaction path uses it, never a Petal, and a token outside the
      list still needs its recipient listed, because any contract can answer
      `decimals()` and run its own code under the `transfer` selector. A
      Petal cannot pass its transfer off as the wallet's own: Bloom refuses a
      Petal's VFS write to a wallet's `outbox/new.tx`, so a Petal stages only
      with its own staging call, which records it as the origin. Broker
      checks no destination on the wallet's own exact EVM approval, which
      carries no claim, so the owner's approval of each transfer is the only
      recipient check. The pinned Broker includes bloom-broker#103, so the
      approval page decodes the transfer and names its recipient
      (decision 21). Until bloom-broker#112 is pinned, the policy ceremony
      shows the entry as written.

    A persona chosen later is a fresh start for that wallet (decision 18):
    its setup runs again, its limits reset and its policy is replaced. Machine
    reads the persona from the config each time it proposes. A saved persona
    that no longer parses or validates is set aside with a warning, so Machine
    still starts and the owner can choose one again.

    Reusable Trader and Degen sessions come from section 6. With bloom#377
    and bloom-broker#112, an approved Degen session can also sign those
    transfers within its token limits.

Agreed on 2026-11-03 with the author of bloom#352 and bloom#377:

16. **Persona limits are token amounts.** A persona's limits are amounts of
    the tokens the wallet's Petals use, counted by Broker (bloom#377 and
    bloom-broker#112), not dollar values the owner sets. bloom#352's
    configurable dollar limits are dropped, so Bloom needs no price feed and
    ships no pricing API key.
17. **Personas are per wallet.** The owner chooses a persona together with
    the wallet it is for. Each wallet keeps its own setup: its persona, the
    Petals its policy allows, and their limits, under
    `[setup.wallets.<wallet>]` in Bloom's config. `bloom init` sets up
    `main`'s; `bloom wallet persona <wallet> <persona>` sets up any other
    wallet's, or switches one (decision 18). Degen's entry and the approval
    lifetime are proposed for the wallet the persona was chosen for.
18. **Switching persona is a fresh start for that wallet.** Personas are
    chosen mainly at first setup. Switching one starts that wallet's setup
    over, in one command:
    - the owner chooses the wallet's Petals again, starting from the new
      persona's suggestions rather than earlier choices;
    - the wallet's policy is replaced, in one ceremony, by exactly what the
      new setup allows: the chosen Petals, their destinations, the
      persona's entries, and its approval lifetime (decision 19). Anything
      else is removed, including Degen's entry when leaving Degen and
      recipients the owner added by hand, and the ceremony shows what
      changes. The policy's required verifiers and clear-signing setting
      are kept, since setup never chooses them, except the legacy
      clear-signing rules the pinned Broker (bloom-broker#103,
      Machine–Broker 1.8) refuses to sign under: the replacement drops
      them, as that Broker requires;
    - once the owner approves that ceremony, the new setup is saved and
      every chosen Petal's limits reset to the new persona's values,
      replacing what the owner saved, since the owner asked to start over.

    Nothing changes before the owner approves: Machine holds the new setup
    as a waiting switch (`pending-persona/<wallet>.toml`). A switch the owner
    refuses, or that expires, ends with nothing changed and is not proposed
    again; so does one whose proposal Broker refuses outright, with a
    refusal the same request cannot get past and that left nothing behind.
    `bloom wallet default-policy <wallet>` resumes one still waiting.
    Once the owner approves, the switch applies within seconds: the command
    waiting for it applies it, or, with none waiting, `bloom serve` does,
    so its limit reset comes right after the approval rather than over
    values the owner set later.

    Starting another switch cancels the earlier one's ceremony, so only the
    latest choice can commit. Machine proposes a switch and records its
    proposal in one step, so the later switch always finds the earlier
    one's proposal to cancel. If the owner had already approved the earlier
    one, Broker cannot cancel it and it commits: Machine applies it first and
    says so, then proposes the new one. A switch the owner approved also
    applies when what Machine would propose now differs from what it
    proposed, for example because a chosen Petal updated or a chain was
    configured meanwhile; the report then names what its policy does not
    allow instead of claiming it, and an updated Petal asks for its new
    release on its next signed action. A command changes a waiting switch
    only while it still holds the one it read, so it never overwrites,
    clears or applies a newer one. Setup's other rules do not apply to a
    switch: it is proposed whatever the policy's version, it removes
    entries, and it writes limits over stored settings.

    Broker keeps one live ceremony per wallet. While a switch's ceremony, or
    any other policy change's, is open, a Petal operation is pointed at it:
    told that the change does not allow the operation, and that the owner
    must approve or refuse it first. Once that ceremony is no longer open,
    as while the owner's approval is being verified, the committed policy is
    still the wallet's, and a Petal it allows proceeds.
19. **Trader and Degen approvals can last until revoked.** bloom#377's
    reusable permissions need the policy's maximum approval lifetime at
    bloom-broker#112's `STANDING_APPROVAL_POLICY_LIFETIME_MS`. A Trader or
    Degen policy asks for it in the same ceremony as the rest of the
    persona's policy: the first policy of a new wallet, or the replacement in
    decision 18. An Institutional policy keeps the 30 days wallet creation
    installs. On the pinned Broker and Signer the lifetime only lifts
    Broker's cap: the pinned Signer still refuses a Sealed Approval longer
    than 90 days, and a Petal-scoped key may last as long as its own scope
    asks (Hyperliquid's asks for one day). The pinned Broker's ceremony shows
    the lifetime as a very large number of hours; bloom-broker#112 shows it
    as until revoked.
20. **Degen's tokens are the ERC-20s its Petals declare.** Degen's
    any-recipient rule covers only ERC-20s that the wallet's Petals declare.
    The owner can still list specific recipients, such as their own external
    wallet. How a Petal declares its tokens, in its package or per
    transaction as petal#52 does, is still open; until it is settled,
    Bloom's curated policy list (`bloom_proto::policy::ANY_RECIPIENT_TOKENS`)
    stands in. It is deliberately not Broker's much longer shared list, which
    Machine resolves symbols from: any contract can answer `decimals()` and run
    its own code under the `transfer` selector, so only a token reviewed for
    this counts as a standard transfer.
21. **The owner always sees the recipient.** Degen's entry needs a Broker
    that decodes an ERC-20 transfer and shows its recipient
    (bloom-broker#103). The pinned Broker, `b6c27339` at Machine–Broker 1.8,
    includes it, so a Degen transfer's approval page names the recipient
    (decision 15).

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
`[petals] preinstalled` setting. Setup records each chosen Petal in the
wallet's setup, `[setup.wallets.main.petals]` for `bloom init`, with the
values the menu asked about, and the default policy proposes exactly these
Petals. Canonical setup does not add runtime
write switches. Saving the choices rewrites `config.toml` in full: comments
and keys this build does not know are dropped, and anything it migrates on
load, such as the Polygon RPC defaults, is written out. The
persona is recorded beside them (decision 17); Institutional is
stored by its legacy name, `custodian`:

```toml
[setup]
complete = true

[setup.wallets.main.persona]
schema_version = 2
preset = "custodian"
window_secs = 0

[setup.wallets.main.petals.enso]

[setup.wallets.main.petals.hyperliquid]

[setup.wallets.main.petals.near-intents]

[setup.wallets.main.petals.polymarket.values]
max_daily_usd = "100"

[setup.wallets.main.petals.feedback]
```

`bloom wallet persona <wallet> <persona>` writes another wallet's setup the
same way, under `[setup.wallets.<wallet>]` (decision 18).

`[setup]` is a top-level table, not part of `[petals]`: a Bloom release
refuses unknown keys under `[petals]` but ignores an unknown top-level table,
so a home this setup ran on still starts if its owner goes back to a release.
A release never rewrites an existing config, so `[setup]` survives the
downgrade, and nothing runs setup again after it. Earlier builds of this
design saved `main`'s choices under `[petals]`, then in `[setup] petals` with
a top-level `[persona]`; each still loads as `main`'s setup, and the next
`bloom init` moves it to `[setup.wallets.main]`, so a release can then start
too.

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
recorded by `complete = true` under `[setup]`, saved together with the
choices once the menu finishes; a config file on its own proves nothing,
because `bloom serve` creates one too, and an interrupted menu saves nothing.
An empty `[setup.wallets.main]` is not the marker either: declining every Petal is
a valid choice. A `bloom init` run without a terminal records the catalog's
suggestions instead of asking. A packaged install runs Machine as a service,
which holds the home, so `bloom init` cannot run there and no setup is
recorded: `bloom wallet new main` then proposes nothing and says to choose a
persona with `bloom wallet persona main <persona>`, which works through the
running Machine. Later runs of `bloom init` see the marker and
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
    "05fa377aa2b2df95a87a21ba58733e95b145d3f10c6a297ebcf969dfc5f8e08b",
    "036cce365ff7cfe5c3e35754fc4c15097576c6251eb2277b890cdae673b234fd"
  ],
  "allowed_destinations": [
    { "chain": "polygon", "destination": "petal:polymarket" }
  ],
  "required_verifiers": []
}
```

- **`allowed_petal_packages`** lists each chosen Petal by its installed
  package hash. On an up-to-date home that is the hash Bloom's catalog pins:
  Hyperliquid v0.1.10 and Polymarket v0.2.1. A home still updating proposes
  the release it runs. Until proposals from Petal changes are built
  (section 5), the Petal's first signed action after the update opens a
  policy ceremony that allows the new hash (`ensure_petal_eligibility`).
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
   ceremony's URL once. The default policy is proposed only once every
   chosen Petal is installed, so the owner approves it in one ceremony. For a
   wallet created first, while one is still installing after Machine
   started, Machine proposes nothing: the command names the missing Petals
   and says to run `bloom wallet default-policy <wallet>` once they are
   installed, or to restart Bloom if one stays missing, and `bloom wallet
   new` adds that creating the wallet once `bloom petals ls` lists them gets
   the policy in the same step. The wallet keeps the policy creation
   installed, so that command then proposes the whole default policy. A
   change already proposed is settled first: one still waiting for the
   owner is reported with its ceremony link, naming a missing Petal it
   allows as allowed but not installed, and one the owner approved meanwhile
   commits, so an approval is never hidden or left uncommitted while a
   Petal is missing. A
   policy that has changed since creation is never proposed this way, so
   for it a missing Petal is only named alongside what the policy allows
   or lacks. A persona switch likewise starts only with every chosen Petal
   installed; otherwise nothing changes and the command says to run it
   again. A switch's proposal can still be made later, after a chosen
   Petal was uninstalled, and then leaves it out, so Machine records which
   Petals the proposal included and describes the switch's ceremony by
   that record, not by what is installed now. A Petal uninstalled while a
   switch waits for approval is named once it is approved: as
   allowed but not installed when the approved policy allows its catalog
   release, otherwise with `bloom wallet default-policy <wallet>` to run
   once it is installed, which then says how to add it.
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
`main` appears writes the settings: the wallet-creation flow's or `bloom
wallet default-policy main` once every chosen Petal is installed (until then
both stop before writing), a rerun of `bloom init` once `main` exists, or
`bloom serve`, which checks every 30 seconds while a write is queued, so a `main`
an agent creates by writing `wallets/new` gets them too. A rerun of `bloom
init` covers a home where `main` already existed, so no wallet creation
follows. A rerun or `bloom serve` that updates the Petal makes a queued
write too, while nothing is stored, and otherwise keeps the settings the
update carries (section 5). A queued write that fails stays queued, and a
command that stops on an applied or changed policy names the command that
retries it. A write waiting for its Petal's update is reported apart, with
what makes it: the update `bloom serve` tries when it starts and `bloom init`
when it runs. It writes them only while
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

The key is pinned with the releases checked to store settings there
(`releases` in the catalog's settings template): Polymarket v0.2.1, the
catalog's release, and v0.1.6, v0.1.8 and v0.2.0, which earlier Bloom
releases installed and a home may still run while it updates. v0.2.0 moved to
a newer Petal SDK, whose `state` namespace and `venue_config_key` are
unchanged; v0.2.1 changes neither.
Setup writes only when the installed package hash is one of them, and the
signed lineage carries a write made to an earlier one forward to v0.2.1.
Another release under the same name, such as a fork or a newer
release whose key nobody has checked, may store its settings elsewhere, where
the check could not see them, so Machine keeps what it holds and clears the
marker. `bloom init` prints the manual command; a queued retry only logs it
(`petal.setup_settings_preserved`). After a
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
the last 24 hours; since v0.1.8 it counts each buy's amount plus the most its fee can
be. It does not count sells, and it has no total limit.

### 5. Adding, updating, and removing Petals

| User action | Policy change proposed for `main` | Petal settings |
|---|---|---|
| Add a Petal with `bloom petals install` | Allow its package hash | Write Bloom's suggested settings, if it is a catalog Petal |
| Update a Petal by installing a newer release | Replace the old package hash with the new one | Preserved through the signed package lineage; initial settings are written only when the wallet is known not to exist, or when a write setup queued earlier is waiting, and only while nothing is stored |
| Remove a Petal with `bloom petals uninstall` | Remove its package hash | Kept on disk under the package hash; a reinstall of the same release finds them, and setup leaves them as they are |

An update carries settings and trade receipts forward through the signed
package lineage (`crates/bloom-petals/src/private_store.rs`). Bloom preserves
these values when the wallet already exists, including settings written
through the Petal after setup. If Broker cannot establish whether the wallet
exists, Bloom leaves the settings untouched. Setup choices remain in Bloom's
config; the owner can explicitly apply them later.

Catalog Petals are installed and updated in two places: `bloom init`
(`ensure_preinstalled_petals`) and every `bloom serve` start
(`petal_provisioning::provision_and_retry`). `bloom serve` installs them after it is
ready, so Petal code can be running, such as setup writing Polymarket's
settings right after `bloom wallet new`. The Petal store refuses to change a
Petal's package while that Petal's code runs (bloom#328). Each Petal has its
own gate, so another Petal's calls, MCP resource reads included, never hold
up an install, and a first install, which no call can be running, goes in at
once; an uninstall is refused while any Petal's code runs. MCP resource
reads check that a Petal route's read does not act under that Petal's gate
rather than Machine's Petal mutation lock. A parameterized route counts as
acting until a lookup evaluates it, so an MCP read looks such a route up
first, as `bloom vfs stat` would; a read refused under the gate, because the
package changed after the first check, gets the same "not an inert
resource" error as one refused before it ran. When an install is refused, Machine
tries it again after one second, doubling the wait up to one minute and
staying there while it runs. A retry downloads and stages the package, then
takes Machine's Petal mutation lock in turn, as listing and managing Petals
do, and queues for its turn to activate for up to 3 seconds by the clock:
that Petal's calls already running finish, and its calls that start
meanwhile wait behind it (`PetalStore::activation_permit_waiting`). So
agents calling a Petal back to back, even several at once or through MCP,
cannot starve its update, and none of that Petal's calls waits on it for
more than those 3 seconds plus the activation itself. A Petal listing or
other install waits only for its turn at the mutation lock, which any
install or build holds while it runs. If the Petal's running calls outlast that, it lets them go
and tries again in its next round. A retry first checks that the Petal's
installed package is still the one its earlier attempt found: if the owner
installed, updated or uninstalled it meanwhile, the retry stops and leaves
it as they made it. A release file that fails to download is
tried again on the same schedule, six times, about a minute in all; a
failed check of what was downloaded, such as its checksum, is not, since
another attempt cannot change it. Any other failure, or a download that
still fails, waits for the next start, so the log says to restart
Bloom: `bloom init` cannot open a running home, and installing from a
Petal's repository builds a different package from the one the catalog
pins. An install cancelled because Machine is stopping says only that.
Opening the store removes staging directories an earlier Machine left
behind, such as one killed mid-install, once they are an hour old. A fresh install
receives the saved settings
when the Petal stores nothing for them, which holds unless the same release
was installed before and its settings kept. An update receives them
only when the default wallet is known not to exist, and on the same terms.
A write setup queued earlier is setup's own choice, not a new one, so an
update by either makes it, again only while nothing is stored; while Broker
cannot say whether `main` exists, it stays queued.
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

This design follows bloom#377: its persona names, persona type
(`bloom_proto::persona`, schema 2) and Degen policy entry, stored per wallet
(decision 17) rather than in bloom#377's top-level `[persona]`, which still
loads as `main`'s. bloom#352 calls
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
  (`STANDING_APPROVAL_POLICY_LIFETIME_MS`), which this design now proposes
  for Trader and Degen in the same ceremony as the rest of the persona's
  policy (decision 19), so bloom#377's `standing` argument is no longer
  needed. The first proposal carries it, including one a Petal's own use
  opens, but only the default-policy path requires it, so a Petal's use
  never opens a ceremony just for the lifetime. The default-policy report
  names a missing lifetime ("approvals last until revoked") beside missing
  Petals and the persona's entry.
- **A policy change ends persona sessions.** A session and its budget are
  bound to the policy version and digest they were approved under. Any later
  policy commit stops them signing:
  - a per-Petal proposal from section 5;
  - a Petal update's new package hash;
  - an owner's `bloom wallet update-policy`.

  The owner then re-activates. Re-activation is a new reviewed approval with a
  fresh budget, so a daily limit restarts after each policy change and
  re-review.
- **A persona choice is a fresh start.** Browser onboarding sends the
  wallet, the persona and the owner's Petal selection in one
  `wallet_persona` command. Machine holds that setup as a waiting switch
  and proposes it as the wallet's replacement policy; once the owner
  approves, Machine saves the setup and resets the chosen Petals' limits
  (decision 18). Waiting for that ceremony is an ordinary
  `wallet_default_policy`, which reports `switch_ended` if the owner refused
  it or it expired.
- **A fresh choice is proposed explicitly.** A flow that only adds to the
  policy, without switching persona, applies the owner's Petal selection
  through `wallet_default_policy`.
  Once the wallet's policy has changed since creation, that command proposes
  only with `owner_just_chose` set. Without it the owner sees which Petals
  are not allowed, and nothing is proposed. bloom#352 and bloom#377 predate
  this rule and propose at any policy version. Rebased, their
  `WalletDefaultPolicy { name }` no longer compiles: onboarding must set
  `owner_just_chose` only right after it saves the selection. It should
  preselect from the wallet's `[setup.wallets.<wallet>.petals]` while the policy is still the one creation
  installed, and from what the current policy allows after that. Inside Machine
  this is `AfterPolicyChange::Propose` rather than a `bool`, so another flag
  passed in its place does not compile.
- **The persona's entry is for its wallet.** Onboarding can pick any
  existing wallet, and the persona, Degen's `erc20:any-recipient` entry and
  the lifetime are proposed for the wallet it was chosen for (decision 17).
- **A setup is read when it is used.** Machine reads a wallet's setup from
  the config each time it proposes that wallet's policy, not once at
  startup, so a setup saved on a running Machine is the one proposed.
- **Two limits; the lower applies.** Polymarket's `max_daily_usd`, written by
  setup, is enforced by the Petal before it asks for a signature. A persona
  session's token allowance is enforced by Broker and Signer. They are
  independent, and a buy must pass both. First setup suggests the Polymarket
  limit from the persona (decision 15), so it starts at Trader's or Degen's
  pUSD quantity rather than 100. These are the daily values bloom#352 writes,
  with no per-action cap. Under bloom#377, Degen's 10,000 pUSD is a seven-day
  allowance, so the session's limit is the stricter one. A persona switch
  resets the limit to the new persona's once its policy is approved
  (decision 18). If Polymarket was not chosen, setup wrote nothing and
  Polymarket refuses buys until its settings exist.
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
  bloom#352 used treats their entry as its own marker. A queued retry writes
  `main`'s chosen values while nothing is stored under the settings key,
  and deletes the entry. It deletes it without writing when settings are
  already stored or the installed release is one setup does not know. It
  leaves it when the retry fails, and while the installed release is an
  earlier one the catalog release updates from but whose settings live
  elsewhere, such as Polymarket v0.1.5; the update then makes the write. A
  setup write never touches the Petal's `last_error.json`, which reports an
  agent's own writes. A first-setup `bloom init` overwrites it
  with an empty marker when it queues that Petal, and deletes it when it
  does not.
- **Versions.** The sessions need Broker and Signer changes that are not
  merged, and each accepts exactly one protocol minor: bloom-signer#68 only
  Broker–Signer 1.7, and bloom-broker#100 only Machine–Broker 1.8. The pinned
  Broker (`b6c27339`) and Signer (`3f880d7`) speak Machine–Broker 1.8 and
  Broker–Signer 1.6, so bloom#352's stack ships bloom-signer#68,
  bloom-broker#100 (which pins it) and Machine as one Triad release. The
  pinned Broker uses Machine–Broker 1.8 for bloom-broker#103, which
  bloom-broker#100 does not contain. It also requires exact approval for
  every Polymarket class it rebuilds (orders, relayer batches, onboarding)
  and refuses any declared debit, destination or fee on them. Rebased,
  bloom-broker#100 needs a new minor, bloom-broker#112's exemption for
  budgeted order sessions, and its check of order debits against Broker's
  own rebuild; otherwise Broker refuses every bloom#352 BUY session and every
  bloom-petal-polymarket#19 order.
  bloom#377's pins speak Broker–Signer 1.8 and Machine–Broker 1.10.
  Polymarket coverage also needs a published Polymarket package that
  declares its debits to Broker. None does yet: v0.1.6 to v0.2.1
  (pinned here) declare none for any signature.
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
(see decision 13 and `first_proposal` in `ensure_policy_allows`). The one
exception is a persona switch the owner asks for, which replaces the
wallet's policy with its new setup (decision 18), again in a ceremony the
owner signs.

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
  destination on that exact EVM approval, which carries no claim, so the
  owner's approval of each transfer is the only recipient check. The pinned
  Broker's approval page decodes the transfer and names the recipient
  (decision 21).
- A Petal cannot stage a transaction as the wallet's own. Bloom refuses a
  Petal's VFS write to a wallet's `outbox/new.tx`; a Petal stages with its
  own staging call, which records it as the origin, so a rule for the
  wallet's own transfers, such as Degen's entry, never applies to it.
- The Petal identity that a `petal:` entry matches is asserted by the daemon
  and is not re-verified at the policy layer. `ExecutionOrigin::petal_id` is
  built in bloom-daemon as `petal:` followed by the route's `petal_root`,
  carried into `AddressContext::staged_by_petal`, and `petal_destination_entry`
  in bloom-tx's policy engine compares it against the allowlist without
  rechecking where it came from. Whoever controls how Bloom builds a route's
  `PetalRouteContext` therefore owns that claim. Two things bound it: the name
  is validated when the package is read (`validate_petal_name`, ASCII
  alphanumeric plus `-` and `_`), and the comparison is exact rather than
  case-insensitive, so an unexpected name is denied rather than over-matched.
  Every transfer still needs the owner's ceremony.
- A persona switch removes entries only through a ceremony that shows the
  replacement policy, and nothing of it, its limits included, applies until
  the owner approves (decision 18). Like any policy proposal, a local
  client could request one; the ceremony is the gate.
- On the pinned Broker, a Trader or Degen policy lifts Broker's cap on how
  long one approval may last (decision 19). Signer still caps each Sealed
  Approval at 90 days, and each is still one the owner signs.
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
| Create Hyperliquid sessions with fewer ceremonies | [bloom#171](https://github.com/bloom-directory/bloom/issues/171) |
| Agree one chain naming for Petal policy destinations and typed persona sessions | bloom, bloom-broker ([bloom-broker#100](https://github.com/bloom-directory/bloom-broker/pull/100), [bloom-broker#112](https://github.com/bloom-directory/bloom-broker/pull/112)) |
| Migrate pending setup-settings markers to versioned journals | bloom ([bloom#352](https://github.com/bloom-directory/bloom/pull/352)) |

## Implementation plan

All in the `bloom` repository. The first part is built; proposals from Petal
changes come next.

**Built**

- **Setup** (`crates/bloom/src/default_policy.rs`, `crates/bloom-proto`):
  the `bloom init` menu and its non-interactive form, settings templates in
  the catalog, and choices saved under `[setup]` together with a
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
- **Personas** (`crates/bloom-proto`: `persona.rs`, `config.rs`,
  `policy.rs`, `tokens.rs`; `crates/bloom`, `crates/bloom-daemon`,
  `crates/bloom-tx`, `crates/bloom-vfs`): the persona
  question and `--persona`, Polymarket's suggested limit, Degen's
  `erc20:any-recipient` entry and staging exemption, and the report of a
  missing or leftover entry.
- **Per-wallet personas and the switch** (`crates/bloom-proto`:
  `config.rs`, `persona.rs`, `policy.rs`; `crates/bloom`,
  `crates/bloom-daemon`, `crates/bloom-vfs`): each wallet's setup under
  `[setup.wallets.<wallet>]`, read from disk on each proposal; the
  `wallet_persona` Machine command and `bloom wallet persona`, which hold a
  wallet's new setup as a waiting switch, propose the replacement policy
  (`ensure_policy_replaced`) once, and on approval save the setup and reset
  its Petals' limits; Machine's atomic config writes; and Trader's and
  Degen's standing lifetime in their first proposal (decisions 17 to 19).

**Next**

- **Petal changes** (`crates/bloom`): propose policy updates from
  `bloom petals install`, newer releases, and `bloom petals uninstall`.

### Tests

Automated:

- The menu offers Bloom's five canonical Petals, records declines, rejects
  invalid limits, and accepts the suggestions at the end of input. On a
  config with earlier choices it suggests exactly those choices and saved
  values. The scripted form chooses every canonical Petal on a fresh config,
  keeps earlier choices (declines included) and values on an existing one.
  The choices are saved outside `[petals]`, so a Bloom release still loads
  the config, and choices an earlier build saved under `[petals]` still
  load; `bloom init` moves them even when setup does not run again.
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
  checks the key in the route's account partition, holds the Petal alone
  for it, and leaves the agent's `last_error.json` record alone when the
  write fails (`crates/bloom-petals/src/router.rs`).
- A queued write that fails stays queued and is reported with the command
  that retries it; one whose retry cannot be recorded says so and gives the
  manual command. `bloom serve` makes a queued write once `main` exists, and
  an update, by `bloom serve` or a `bloom init` rerun, makes one rather than
  dropping it. A write waiting for its Petal's update is reported apart,
  without the retry command, which cannot make it.
- Setup queues exactly the writes an uninterrupted run would make, before
  `[setup] complete` is saved; an interrupted `bloom init` leaves them queued
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
  An install refused because that Petal's code was running is reported as busy and
  tried again, with a doubling wait capped at one minute, until it goes in
  or Machine stops; a failed download is tried again six times, and a failed
  checksum is not. A retry stops once the owner has installed, updated or
  uninstalled that Petal since the attempt it retries, and a retry queues
  for its turn to activate; serve hands each round's results on, so setup's
  settings follow whichever round installs a Petal. Any other failure says to restart Bloom, and a
  cancellation does not (`crates/bloom/src/petal_provisioning.rs`). While a
  Petal's code runs, a plain install of it is refused at once; with a
  retrying install queued, a call to that Petal starting after it waits
  behind it for no longer than its limit, it activates as soon as the
  running call ends, and it stops when cancelled or past its limit. Another
  Petal's calls neither hold up an install nor wait behind one, and an MCP
  resource read holds up no install. Callers that hold the Petal mutation
  lock back to back cannot keep a plain or retrying install from it
  (`crates/bloom-daemon/src/ipc.rs`). Under an inert read, a route whose read
  acts is refused under its Petal's gate, including after a package change
  that makes it act, and is reported as refused for acting; a setup write's
  stored check waits while that Petal's package changes
  (`crates/bloom-petals/src/router.rs`). An MCP read of a route not yet
  evaluated looks it up first, and any refusal for acting gets the same
  error (`crates/bloom-daemon/src/ipc.rs`).
  The store refuses a package change during a Petal call with a typed busy
  error (`crates/bloom-petals/src/runner.rs`), refuses an install that holds a permit
  for another Petal, keeps every held gate when it forgets idle ones, and
  removes abandoned staging when opened (`crates/bloom-petals/src/store.rs`).
  A real failed `curl` download is marked for retry
  (`crates/bloom/src/github_source.rs`).
- With a chosen Petal not installed, Machine proposes no default policy
  while one could be proposed: for a setup the owner just chose, before
  Broker is asked, and otherwise while the policy is the one creation
  installed. A change already waiting for the owner is reported with its
  ceremony instead, naming a missing Petal it allows as allowed, and one the
  owner approved commits (`crates/bloom/src/default_policy.rs`,
  `crates/bloom-vfs/tests/triad_policy_update.rs`). The command names the
  missing Petals and what to run without calling it skipped; a persona switch starts nothing and records no waiting
  switch. A switch records the Petals its proposal included, and its
  ceremony lists them; a Petal it left out but installed since is named as
  not installed when it was proposed, never as not installed now or as
  changed, and a record or status with fields a build does not know still
  reads. After a switch, a missing Petal its policy
  allows is named as allowed, and one it does not is named with
  `bloom wallet default-policy`.
  The new status carries the list, and the others are unchanged on the
  wire.
- A queued write goes into Polymarket v0.1.6, v0.1.8 and v0.2.0 as well as
  the catalog's v0.2.1, which store settings under the same key. On v0.1.5, an
  earlier release whose route differs, it stays queued for the update; any
  other release gets nothing. The catalog bump test lists all four and
  checks each is the catalog release or one it updates from.
- Enso's router is proposed on exactly the 12 chains pinned Enso v0.1.7
  allows. Polymarket's entry is `petal:polymarket`, and a call to pUSD staged
  by another Petal or by hand is refused under it
  (`crates/bloom-tx/src/policy_engine.rs`).
- A Petal's VFS write to a wallet's `outbox/new.tx` is refused before it
  reaches the VFS, while its reads and other writes are not
  (`crates/bloom-petals/src/runner.rs`).
- Each wallet keeps its own setup, and the three layouts earlier builds
  wrote load as `main`'s and move on save (`crates/bloom-proto/src/config.rs`).
- A persona switch proposes exactly the new setup's packages, destinations
  and lifetime at any policy version, keeps the required verifiers, commits
  in one ceremony, and proposes nothing for a policy that already matches; a
  Trader or Degen first proposal carries the standing lifetime, which the
  default-policy path requires (`crates/bloom-vfs/tests/triad_policy_update.rs`).
- A switch accepts only canonical Petals with valid values and known
  settings; on approval it resets their limits over stored settings, drops
  `main`'s queued write for each Petal whose reset went in, and reports a
  failed write with its command. A waiting switch is kept apart from the
  config; concurrent setup saves keep every wallet; a config save is atomic
  and keeps its permissions; and the wait reports a switch applied or ended.
  A switch is proposed once, not again after it is refused or expires, and
  a later switch cancels the earlier one's ceremony; one the owner already
  approved, which Broker cannot cancel, reads as committed, and so does an
  approved switch whose request changed since, whose report names what its
  policy does not allow. Ending a switch leaves a newer one in place, and
  only Broker's refusal of the switch's own proposal, with no retry and no
  effect, ends a switch never proposed; a failure to talk to Broker, or
  around the proposal, does not. While another change's ceremony is open, a
  Petal is pointed at it and told it does not allow the operation; once it
  is not open, a Petal the committed policy allows proceeds
  (`crates/bloom-vfs/tests/triad_policy_update.rs`). The legacy
  clear-signing rules are dropped only for a Broker with bloom-broker#103,
  and advice to edit a policy that keeps them says to drop them too. A
  config saved through a symbolic link keeps the link, unless its target
  cannot be replaced, and a save's sibling is never more readable than the
  config.
  The first proposal reads the wallet's setup from disk each time.
  `bloom init --persona` on a set-up home changes nothing and names
  `bloom wallet persona`.
- Each persona's menu choice, `--persona` and Polymarket suggestion; Degen's
  entry on configured chains and for the wallet it was chosen for; an
  unusable saved persona set aside; staging that passes only the wallet's own curated ERC-20
  transfer with the entry; and the planner honouring, and the leftover
  report counting, the entry only under `evm-<chain id>`.

Manual, on the developer triad:

- `bloom wallet new main` runs two ceremonies and commits a policy allowing
  exactly the chosen packages. `bloom wallet default-policy main` then
  reports it applied without a new ceremony, finishes a queued settings
  write without replacing the owner's, and proposes nothing once the owner
  has changed the policy (`scripts/test-default-policy-e2e.sh`).
- `bloom wallet persona main <persona>` changes nothing before the owner
  approves, then replaces the policy and resets the limits; a later switch
  supersedes one still waiting; and a switch approved with no command
  waiting applies, reported by the next switch or applied by `bloom serve`
  (`scripts/test-persona-switch-e2e.sh`).
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
