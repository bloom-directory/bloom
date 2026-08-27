# Solana mainnet-beta canary: design and threat model

**Status:** implemented, pre-review. Not yet independently reviewed.
**Scope:** one bounded, single-transaction mainnet-beta transfer for the purpose
of exercising Bloom's mainnet broadcast and reconciliation path once.

## Why this exists

Bloom's Solana support is exercised end to end on a local validator and on
public devnet. Neither proves the mainnet path, because mainnet-beta is refused
outright — which is the correct default and stays the default. The gap this
closes is narrow: does the broadcast/reconcile path behave on the real network,
once, for an amount whose loss is acceptable.

The alternative considered and rejected for full coverage was a
read/sign/simulate-only rehearsal (handoff §9 option 1). It preserves the guard
untouched but never sends, so it cannot exercise broadcast, signature-based
reconciliation, or the ambiguous-response path — the three things most worth
testing before real funds move at any larger scale.

Explicitly rejected: a generic `allow_broadcast = true` exception. That would
turn a config typo into a mainnet send and is precisely the failure mode the
existing guard exists to prevent.

## What the ordinary build does, unchanged

Four independent refusals, none of which are weakened by this work:

1. **Config validation** (`bloom-proto::config`) rejects a Solana chain that
   enables broadcast while declaring the pinned mainnet-beta genesis.
2. **Daemon boot** (`admit_solana_chain`) performs a *live* `getGenesisHash`
   and refuses to construct a transfer engine for a mainnet-beta cluster,
   regardless of what the chain is named.
3. **Broadcast client** (`SolanaClient::verify_genesis`) checks live genesis
   again immediately before the client is used to send.
4. **Transfer engine** (`SolanaTransferEngine::broadcast`) enforces the
   per-value caps described below.

Gates 1–3 already existed. Gate 4 is new and only ever narrows.

## What the canary adds

A separate, non-default compile-time capability (`mainnet-canary`) that lets
those gates consult an out-of-band authorization. Layered defences, in the
order an attacker or an accident would meet them:

| Defence | Effect |
| --- | --- |
| Compile-time feature, off by default | Production binaries contain no code that can enable mainnet-beta. `authorization_at` is a function returning `None`. |
| Build-time artifact label | The feature alone does not compile. `BLOOM_MAINNET_CANARY_ARTIFACT` must also be set, so `--all-features` and every release path fail loudly rather than silently producing a capable binary. |
| Out-of-band authorization | The authorization is a file named by `BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION`, never a config key. No `config.toml` spelling enables mainnet. |
| Artifact binding | The authorization carries the SHA-256 of the binary it was issued for and is refused by any other binary. |
| Typed acknowledgement | The operator must reproduce a canonical sentence containing every bound value. Editing any value invalidates the acknowledgement written for the old one. |
| Exact-match caps | One wallet, one key fingerprint, one source, one destination, one exact amount, a fee ceiling, and a live-read balance ceiling. |
| Expiry | A wall-clock deadline, re-checked at boot and at send. |
| Single-use ledger | `create_new` on a sibling `.spent` file, claimed *before* the send. |

Broker policy, semantic verification, and the human approval ceremony are
untouched and still run exactly as on devnet. The canary decides only whether
mainnet-beta is reachable at all; everything downstream still has to agree.

## Threat model

**An operator misconfigures a chain.** Config validation still refuses unless a
canary-capable binary holds an authorization naming that chain. A production
binary refuses regardless of the file, and this is tested directly.

**A release accidentally ships the capability.** The build fails. CI asserts
that `--all-features` is refused, that the feature alone is refused, that both
refusals cite the label variable, and that a labelled build succeeds.

**An authorization is reused against a newer binary.** Refused: the artifact
hash will not match.

**An authorization is quietly re-pointed** at a larger amount or a different
destination. Refused: the acknowledgement no longer matches the canonical
sentence for the edited values.

**The amount is reduced** rather than raised. Still refused. The amount is
compared for equality, not as a ceiling, because a smaller debit is still not
the transfer the operator was shown.

**The account is funded above the agreed budget.** Refused at send: the balance
is read live rather than trusted from staging time, because the loss budget is a
claim about the account now.

**The response is lost and the outcome is ambiguous.** The single use is claimed
*before* the send, so a crash or timeout leaves the canary spent. This is
deliberate: an automatic retry is the one behaviour that could double-send real
funds. The outcome is recovered by reconciling the deterministic signature, not
by resending.

**Two processes race.** `create_new` admits exactly one claimant.

**The clock is wrong.** Expiry is a coarse backstop, not a primary control; the
exact-match caps and the single-use ledger do not depend on the clock.

## Residual risks

- The canary artifact is a real capability. Anyone who can both build it with
  the label and write an authorization file bound to that artifact can move the
  authorized amount to the authorized destination — and nothing else.
- The genesis constant remains the root of trust for cluster identity. It is
  pinned and independently verified, but a compromised constant would defeat
  identity checking; that risk predates this work and is unchanged.
- This document and the implementation share an author. Per handoff §9 the
  threat model and the code require an independent reviewer, which has **not**
  happened yet.

## Test coverage

- 11 unit tests over the authorization's decisions, run in **both** build
  configurations.
- 2 integration tests driving the real environment variable into the real guard
  via a re-exec, asserting that a production build refuses even when handed a
  valid authorization, and that a canary build refuses a wrong chain, a wrong
  artifact, and an expired window.
- 4 CI build gates over the packaging refusals.

Not yet covered, and required before the canary is used a second time or at any
larger amount: destination substitution and cap violations exercised through the
full engine against a live cluster, restart mid-broadcast, and production
release-bundle rejection of a canary artifact.
