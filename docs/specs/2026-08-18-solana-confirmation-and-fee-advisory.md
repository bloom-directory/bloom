# Solana confirmation and fee advisory (the `BumpScanner` analogue)

**Status:** core expiry handling implemented; early dwell/congestion advisory
remains deferred.

**Mirrors:** `bloom-tx/src/bump_scanner.rs` in role only — the *mechanism* is
designed from Solana's actual fee and freshness model, not EVM's.

## Why EVM's `BumpScanner` does not transfer

EVM's scanner detects a stuck tx by two triggers — *basefee* (`current_basefee
> original_max_fee * (100 + pct) / 100`) and *dwell* (still pending after
`stuck_after`) — and writes advisory `bump.tx` / `cancel.tx` artefacts. The
bump is meaningful because Ethereum txs are **nonce-replaceable**: resubmitting
the same `(from, nonce)` with a higher fee *replaces* the stuck tx.

Solana has neither a basefee auction nor nonce replacement:

- **No nonce.** There is no `(from, nonce)` to reissue. A transaction is
  content-addressed by its message bytes; changing anything (including the
  blockhash) changes the message, which changes the signature. A "bump" is a
  *new transaction requiring a new signature* — and therefore a new approval
  on Bloom's side.
- **No basefee.** Fees are `base (5,000 lamports/signature) + priority fee`.
  Priority is expressed as a *compute-unit price* (micro-lamports per compute
  unit) via a `SetComputeUnitPrice` instruction, not an auction the miner
  clears. There is no market floor to track.
- **Hard freshness deadline.** Every tx carries a recent blockhash and a
  `lastValidBlockHeight`. Past that height the tx is *permanently* invalid —
  it will never land no matter how long it sits in an RPC queue. This is the
  Solana analogue of EVM's nonce gap / dropped-tx, and it is the primary
  "stuck" condition.

## What "stuck" means on Solana

A sent transfer is stuck when, without a confirmed `receipt.json`, one of:

1. **Blockhash expiring** — `current_block_height` approaches (or has passed)
   the staged `lastValidBlockHeight`. The tx can no longer be confirmed.
2. **Dwell without confirmation** — the tx was sent long ago (relative to the
   cluster's normal confirmation latency) and no signature status is visible,
   indicating it was dropped from RPC queues before any leader processed it.
3. **Congestion** — the tx is landing slowly because the staged priority fee
   (compute-unit price) is below the cluster's current market rate, so leaders
   repeatedly skip it in favour of higher-priced txs.

## The advisory mechanism

A `SolanaConfirmationAdvisor` scans `sent/<id>/` entries that are unmined
(no `receipt.json`), mirroring `BumpScanner`'s posture exactly: **it writes
advisory artefacts only; it never broadcasts and never signs.**

For each stuck entry it writes, next to the entry:

| Artefact | Content |
|---|---|
| `restage_advice.json` | machine-readable: `kind: "restage"`, `replaces` (entry id), `reason` (`blockhash_expiring` \| `dwell` \| `congested`), the staged `destination`/`lamports`/`fee_payer`, the current blockheight vs `lastValidBlockHeight`, and an advisory `priority_fee_micro_lamports_per_cu` (see below) |
| `restage.md` | operator-facing text: *"this transfer's blockhash expires at height N (now M); restage with a fresh blockhash to retry — this requires a new signature and approval"* |

The advice is deliberately **not** a stage-able intent (unlike the EVM
`bump.tx`'s aspirational direction): restaging requires a fresh blockhash
*and* a new signature, both of which demand operator (and owner-approval)
participation through the normal stage → approve → sign path. There is no
safe automatic retry.

### Priority-fee advisory (the "bump" component)

When the trigger is congestion, the advisor suggests a compute-unit price
derived from Solana's own fee signal, not an EVM-style percentage bump:

- read `getRecentPrioritizationFees` (recent per-compute-unit priority fees
  actually paid by landed txs) when the node supports it;
- take a high percentile (e.g. p75–p90) of the recent window, floored at the
  staged price, and capped by the operator-configured
  `max_priority_fee_micro_lamports_per_cu`;
- record the quoted number as an **asserted** observation (it is a network
  reading, never verifier-proven), and render it as such in the advisory.

This mirrors EVM's *role* (bounded, operator-capped fee advice) while using
Solana's actual price signal. If `getRecentPrioritizationFees` is unavailable
or the node is a local validator, the advisor omits the price component and
reports only the blockhash/dwell trigger.

### Implemented freshness and restaging behavior

`SolanaOutbox::sweep_expired` moves unsigned pending entries past `expires_ms`
to `failed` with status `expired`. Signed pending entries remain visible so a
lost RPC response cannot be misreported as failure. Signing and broadcast
also query the current blockheight and refuse an expired message.

For an expired pending entry, writing non-empty content to `restage` creates a
new immutable stage with the same destination and lamports but a fresh
blockhash and fee quote. The old entry becomes `failed/expired` and links to
the replacement through `restage_advice.json`; approval and signature state
are not reused. A sent-but-unobserved signature is reconciled to a terminal
failed receipt once current height exceeds `lastValidBlockHeight`, rather than
remaining unreconciled forever.

## Trigger thresholds (frozen defaults, operator-tunable)

| Trigger | Default |
|---|---|
| Blockhash-expiring margin | advise when `current_height >= lastValidBlockHeight - 32` (~half the ~150-slot recent-blockhash window) |
| Dwell | advise after 60 s unconfirmed (`stuck_after`), matching `BumpScanner`'s dwell spirit |
| Scan interval | 30 s |

## Out of scope / deferred

- Auto-restage or auto-approve (a new message requires a new signature and
  violate the "construction code cannot change destination/amount without
  invalidating the signature" invariant).
- Durable nonce accounts / offline signing (the v1 message is legacy,
  single-signer, System Program transfer).
- Estimating compute units for the transfer beyond the verifier-pinned shape.
