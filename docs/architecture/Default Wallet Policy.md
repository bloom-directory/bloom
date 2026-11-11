# Default Wallet Policy

**Status:** implemented in `feat/default-policy-core`. Personas, persona
switching and Petal settings written from setup follow in
`feat/default-policy`, after bloom-broker#112 and bloom#377.
**Audience:** Bloom engineers, Petal authors, and implementation agents

A new Bloom user should go from installing Bloom to using their Petals by
approving one policy. Without it, a new wallet's policy allows no Petal, so
each Petal's first use opens its own approval. From then on nothing changes:
every transaction still asks for the owner's approval.

This changes only the `bloom` repository. Broker, Signer and every Petal stay
as they are. The normative security and wire contracts remain
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).

## The experience

```text
bloom init  (once)
  -> setup menu        choose which Petals main's policy allows: Polymarket,
                       Hyperliquid, Enso, NEAR Intents, Feedback
  -> saves             the choices as [setup.wallets.main.petals] in config.toml
  -> installs          Bloom's catalog Petals, pinned by its catalog

bloom wallet new main  (or bloom wallet import main)
  -> wallet ceremony   as today
  -> default policy    once every chosen Petal is installed: one ceremony
                       that allows all of them, printed once
```

Without a terminal, `bloom init` chooses every Petal setup offers. A home
created before setup existed, or a packaged install that never runs
`bloom init`, has no choices, and nothing is proposed for it.

## Rules

1. **Only proposals.** Setup and the default policy grant nothing. The policy
   still changes through the owner's ceremony, and Broker remains the only
   authority. Labels Machine prints ("approve the policy for main to allow
   ...") are never authority.
2. **One approval, for the whole setup.** The default policy is proposed only
   once every chosen Petal is installed. While one is missing, Machine
   proposes nothing and names it, so the owner never approves part of the
   setup and then needs a second ceremony.
3. **Only while the wallet has the policy creation installed.** That policy
   is at Broker version 1 (`CREATION_POLICY_VERSION`). Once the owner
   commits any change, Bloom never proposes the setup again, so nothing the
   owner removed comes back. `bloom wallet default-policy` then reports what
   the policy lacks and how to add it.
4. **A Petal's first use carries the setup.** While the wallet still has its
   creation policy, a Petal's own policy proposal also allows the Petals
   chosen at setup, so whichever comes first, the owner approves one policy.
   If a chosen Petal is missing then, the use proposes nothing and fails with
   `DEFAULT_POLICY_WAITING`, naming it: its proposal would carry the setup
   without that Petal, and once approved, the policy would no longer be the
   creation one, so the missing Petal would never be proposed. Machine passes
   that error to the Petal as a backend error, not a denial, so the Petal
   shows the agent its text, and logs it.
5. **Only setup's Petals.** Only the Petals setup offers
   (`bloom_proto::config::SETUP_PETALS`) are proposed or waited for. A config
   naming any other, as only a hand edit or a Petal since dropped from the
   catalog can, is ignored with a warning, since no release installs it and
   waiting for it would never end.
6. **Safe is installed, never chosen.** Broker refuses Safe's signature unless
   the policy allows exact destinations on its chain, and Machine refuses its
   execution unless the policy lists the owner's own Safe. Setup can propose
   neither, so the owner allows Safe with their own policy change. A test
   makes every future catalog Petal take the same decision: offered with its
   destinations, offered as needing none, or left out with a reason.

## Design

### Setup

`[setup]` is a top-level table, not part of `[petals]`: a Bloom release
refuses unknown keys under `[petals]` but ignores an unknown top-level table,
so a home setup ran on still starts with an older Bloom. `complete` records
that setup finished, so declining every Petal stays a valid, remembered
choice. Each chosen Petal is a table
(`[setup.wallets.main.petals.polymarket]`) so later per-Petal choices fit
without changing the layout.

### The request

For a wallet, Machine reads its setup from the config on disk, not the copy
loaded at startup, and resolves each chosen Petal's installed package from the
Petal store. The request is every installed chosen Petal's package plus the
destinations its transactions need, from Bloom's own table
(`bloom_proto::petal_destinations`), never from config. Polymarket and NEAR
Intents are allowed through Petal-scoped entries (`petal:polymarket`,
`petal:near-intents`): the policy engine lets a transaction through to a
destination the Petal chose only when the Petal that staged it is the one the
entry names. Listing their token contracts instead would let any Petal, or
the agent, move those tokens anywhere with a raw call.

### Proposing and waiting

`bloom wallet new main` runs the wallet ceremony, then asks Machine every two
seconds where the default policy stands (`wallet_default_policy`), until the
wallet exists or its ceremony expires. Broker refusals that may clear up
(unavailable, rate-limited, over quota) are waited out within the same
deadline. Machine reconciles any change already proposed first, so one the
owner approved commits and one still waiting is reported with its link, then
proposes the default policy through the wallet's existing policy operation.
The command prints the ceremony link once.

A waiting change is described as the default policy only when it is the
current policy with nothing added but the default policy (`adds_only`). Any
other change, such as an agent's proposal of the default policy plus a
destination of its own, or Bloom's own proposal while a chosen Petal is
missing, is reported as "a policy change is waiting" at its link, so the
owner is never told something else is the default policy. A Petal's own use
still waits on such a change, since its one ceremony covers that Petal.

Broker owns a ceremony's expiry: it retires an expired one when Machine next
reads its status, and Machine never judges expiry by its own clock. Once a
waiting command has announced a ceremony, it asks Machine only to settle and
report (`observe_only`). If that ceremony ends without approval, the command
stops and says so, rather than handing an owner who left the link a new one
every few minutes. `bloom wallet default-policy main` picks up where a
stopped command left off.

### Catalog installs

Machine installs the catalog Petals as it starts, while agents may already be
calling them. Each Petal has its own execution gate, so one Petal's running
code never holds up another's install. An install refused because that Petal
was busy is retried, starting at one second and backing off to once a minute,
queuing briefly for its turn so calls arriving back to back cannot starve it.
A failed download is retried six times. A retry stops if the owner installed,
updated or uninstalled that Petal meanwhile, so it never undoes their change.
MCP resource reads do not take the install lock.

## Tests

- `crates/bloom/src/default_policy.rs`: the setup menu and its non-interactive
  form, the request (missing Petals named, others ignored), which statuses the
  wait prints, never announcing an expired or replacement ceremony, another
  change reported without being called the default policy, and Broker
  outages waited out.
- `crates/bloom-vfs/tests/triad_policy_update.rs`: proposals against a Broker
  fixture, reconciliation, the first proposal carrying the setup, waiting for
  a missing chosen Petal, an agent's superset change, and a failed policy read
  never guessed at.
- `crates/bloom-daemon`: the setup Machine reads, and the wait reaching a
  Petal as a backend error.
- `crates/bloom/src/petal_provisioning.rs`, `crates/bloom-petals`: retries,
  per-Petal gates and queueing.
- `scripts/test-default-policy-e2e.sh`: the whole flow on a developer triad
  with the catalog Petals.

## Related documents

- [Wallet architecture and account identity](./Wallet.md)
- [Triad process architecture](../specs/2026-07-23-triad-process-architecture.md)
