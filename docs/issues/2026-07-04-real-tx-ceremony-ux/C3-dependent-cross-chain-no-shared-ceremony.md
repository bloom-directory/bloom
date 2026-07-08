# C3 — dependent cross-chain flows cannot share one ceremony

**Severity:** Medium · **Category:** Architectural
**Observed:** 2026-07-04, during a real mainnet USDC bridge (Base → Polygon)
followed by a USDC → pUSD fund, both through a passkey-gated wallet.

---

## What happened

A two-leg cross-chain sequence — (1) bridge USDC from Base to Polygon, then
(2) swap the arrived USDC for pUSD on Polygon — required **two separate passkey
ceremonies**, one per broadcast. This is inherent (one ceremony per broadcast is
the baseline). But the reason a single ceremony **cannot** cover both legs is
structural: the second leg's outbox id does not exist until the first leg
settles on the destination chain, and bloom's policy-session mechanism can only
authorize exact ids that are enumerated and signed for at ceremony time.

So even though bloom already implements a multi-tx-one-ceremony primitive
(policy sessions via `confirm-batch --policy-session` and the `SessionStore`),
it cannot help a **dependent** sequence — one where leg N+1 cannot even be
staged until leg N settles.

## Sequence to hit it

```
# Leg 1: bridge USDC Base → Polygon (defi intent)
bloom vfs write /defi/intents/<wallet>/new --data '{"intent":"swap 7 usdc to usdc","chain":"base","destination_chain":"polygon"}'
# → stages outbox tx <base-id> on Base
bloom wallet confirm <wallet> base <base-id> --text y
# → ceremony #1 → broadcast → relay delivers USDC to Polygon EOA

# Leg 2: swap arrived USDC → pUSD on Polygon
bloom polymarket fund <wallet> --target-pusd 6.9 --max-spend 6.976 --from-token <poly-usdc>
# → stages outbox tx <poly-id> on Polygon  (id unknown until leg 1 settled)
bloom wallet confirm <wallet> polygon <poly-id> --text y
# → ceremony #2 (cannot be covered by ceremony #1's session)
```

The `<poly-id>` did not exist when ceremony #1 ran, so it could not have been
allowlisted. There is no way to pre-authorize "the eventual Polygon swap" at
ceremony #1 time.

## Evidence

### The `ActiveSession` allowlist is exact chain-qualified ids

`crates/bloom-tx/src/session.rs:22-39`:

```rust
/// A live, bounded authorization minted by one ceremony.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub id: SessionId,
    pub wallet: String,
    /// Chain ids this session may authorize.
    pub chains: BTreeSet<u64>,
    /// Unix-ms expiry; confirms at or after this are not covered.
    pub expires_ms: u128,
    /// Total spend cap in micro-USD across the session.
    pub max_micro_usd: i128,
    /// Micro-USD already debited by authorized confirms.
    pub spent_micro_usd: i128,
    /// Exact **chain-qualified** outbox ids this session may broadcast, keyed
    /// `"{chain_id}:{outbox_id}"`. Outbox ids are unique only within a chain, so
    /// qualifying by chain prevents a same-id tx on another listed chain from
    /// being authorized by a session minted for a different chain's tx.
    pub allowed_pending_ids: BTreeSet<String>,
}
```

The chain-qualified keying helper — `session.rs:42-44`:

```rust
pub fn pending_key(chain_id: u64, outbox_id: &str) -> String {
    format!("{chain_id}:{outbox_id}")
}
```

### `authorize_and_debit` requires exact id membership

`crates/bloom-tx/src/session.rs:110-149` — the coverage check is a single AND of
five predicates, evaluated per session:

```rust
pub fn authorize_and_debit(
    &self, wallet: &str, chain_id: u64, pending_id: &str,
    tx_micro_usd: Option<i128>, value_moving: bool, now_ms: u128,
) -> Option<(SessionId, i128)> {
    let key = pending_key(chain_id, pending_id);
    let mut guard = self.inner.write();
    for s in guard.values_mut() {
        if s.wallet != wallet
            || s.expires_ms <= now_ms
            || !s.chains.contains(&chain_id)
            || !s.allowed_pending_ids.contains(&key)   // ← exact membership
        {
            continue;
        }
        // ... debit under cap ...
        return Some((s.id.clone(), debit));
    }
    None
}
```

The five predicates: (1) wallet matches, (2) not expired, (3) chain in set,
(4) **exact `"{chain_id}:{pending_id}"` in allowlist**, (5) cumulative USD
under cap. A session miss is not an error — the caller falls back to per-tx
authorization (`tx_engine.rs:1376-1403`), which for a passkey wallet means a
fresh ceremony.

### Minting requires non-empty exact ids and a Hardened ceremony

`crates/bloom-vfs/src/handlers/wallets.rs:416-468` — the mint descriptor:

```rust
#[derive(serde::Deserialize)]
struct Descriptor {
    max_usd: f64,
    ttl_secs: u64,
    #[serde(default)]
    pending_ids: Vec<PendingId>,   // ← {chain_id, id} pairs
};
...
if d.pending_ids.is_empty() || d.ttl_secs == 0 || d.max_usd <= 0.0 {
    return Err(HandlerError::invalid(
        "policy-session requires non-empty pending_ids ({chain_id,id} pairs), \
         ttl_secs > 0, and max_usd > 0",
    ));
}
```

You **cannot** mint a session with a budget + expiry alone — `pending_ids` must
be non-empty. The `allowed_pending_ids` is built by mapping each supplied
`(chain_id, id)` through `pending_key`. There is no wildcarding and no
post-hoc growth: the set is frozen at mint time.

The mint is gated behind a Hardened-assurance Sealed Approval
(`wallets.rs:621-657`, `AssuranceLevel::Hardened` at `wallets.rs:631`), meaning
the WebAuthn assertion must carry `user_verified=true`. The human signs over the
literal descriptor JSON — the exact ids, cap, and TTL are what is reviewed in
the browser.

### No plan/flow/descriptor binding exists anywhere

Search of `crates/bloom-tx` for `plan|flow|descriptor|leg|sequence|dependent`:
the words `plan`, `flow`, `descriptor`, `leg`, `sequence`, `dependent` do not
appear in `session.rs` at all. Only `allowlist` appears, and it always refers to
`allowed_pending_ids` (the exact-id set). The only fields bounding a session are
the five in the struct above: `wallet`, `chains`, `expires_ms`, `max_micro_usd`
(+ `spent_micro_usd`), `allowed_pending_ids`. There is no `plan_id`, no
`flow_id`, no per-leg descriptors, no "cap + expiry without id list" mode.

(`tx_engine.rs:2416` and `reconcile.rs:7` mention "dependent same-chain tx" but
that is about **nonce ordering** within the outbox — whether a dependent tx may
broadcast before its predecessor confirms. It has nothing to do with
`SessionStore` authorization and does not relax the exact-id check.)

### `confirm-batch --policy-session` is NOT a SessionStore mint

`bloom wallet confirm-batch --policy-session` (`main.rs:2197-2353`) does not
insert anything into `SessionStore`. It builds one aggregate `CeremonyIntent`
("Authorize Batch Transaction Session") covering every tx in the batch
(`main.rs:2240-2302`), then for each `(chain, id)` runs `confirm_once()`; on
`BroadcastApprovalRequired` it calls `sign_outbox_sealed_approval_if_challenged`
per-tx (`main.rs:2322-2341`). It batches per-tx grants behind one **review**
ceremony — but it still requires every `(chain, id)` to be known up front (it's
a batch of already-staged txs), so it cannot help a dependent sequence either.

## Why it happens

The `SessionStore` was designed around a security property stated in its module
doc (`session.rs:9-12`):

> The store lives on the `TxEngine` (where confirms are authorized) — **not** on
> the keystore's unlocked-signer cache, which has an unbounded lifetime. A
> session therefore expires independently and can never resurrect a locked key.

The exact-id allowlist is the maximally safe authorization envelope: a session
can broadcast **only** what was enumerated and signed for at ceremony time, up
to the signed dollar cap, before the signed expiry. Nothing about an
un-enumerated id — not even one staged seconds later by the same wallet — can
slip through. Combined with the `SignerCache` (also in-memory, also per-grant),
this means one ceremony unlocks a bounded, fully-specified set of broadcasts.

The constraint this imposes on dependent flows: a leg whose outbox id is not
known at ceremony time cannot be covered. In a cross-chain bridge, the
destination-leg tx cannot be staged until the source-leg settles and the relay
delivers (minutes later), so its id does not exist when the source-leg ceremony
runs. The two ceremonies are therefore unavoidable under the current model.

This is the tradeoff the design chose: **safety over ergonomics for dependent
sequences**. The exact-id allowlist makes it impossible for an agent to broaden
a session's scope after the fact (no descriptor creep, no wildcard exhaustion),
but it also makes it impossible to pre-authorize a flow whose legs materialize
dynamically.

## Impact

- **Every dependent multi-leg flow pays one ceremony per leg.** A cross-chain
  bridge + swap = 2 ceremonies. A longer chain (bridge → swap → stake → …) =
  one per broadcast. Each ceremony requires human presence (browser WebAuthn).

- **The cost is amplified by C1/C4.** When `polymarket fund` ran its own
  ceremony AND required a separate sealed-approval confirm, a single-leg flow
  cost two ceremonies — see companion code fix. With C1/C4 fixed, a
  single-leg flow is back to one ceremony, but multi-leg dependent flows still
  cannot collapse.

- **The ceremony cannot be deferred to flow-completion.** Because the
  `SignerCache` is in-memory and the session is exact-id, there is no mechanism
  to obtain one human approval and let the engine broadcast legs as they become
  ready over minutes/hours.

- **Sessions do not survive daemon restart** (`SessionStore` is in-memory,
  `session.rs` is `Arc<RwLock<HashMap<...>>>`; `petal_host.rs:48`: "the daemon
  process restarts (cache is in-memory only)"). A restart mid-flow invalidates
  any session, forcing re-ceremony for remaining legs.

## What would need planning

This is recorded as a design issue, not a bug. Any change to allow dependent
flows to share a ceremony would need to answer hard questions:

- **What can a leg bind to instead of an exact id?** Chain + token + receiver +
  max amount? A route hash? A plan/flow identifier?
- **How is the total cap enforced?** Cumulative USD across legs (current model)
  vs per-leg caps vs both.
- **What are the partial-failure semantics?** If leg 1 broadcasts but leg 2's
  route expires, does the session remain valid for a re-staged leg 2? What if
  leg 1 succeeds but leg 2 is never staged?
- **How to prevent descriptor over-permissioning?** A descriptor like "any tx
  on Polygon up to $7" is convenient but far broader than "this exact outbox
  id." Where is the line?
- **Expiry vs settlement time.** Cross-chain relay settlement takes minutes;
  the session TTL must accommodate it without becoming a long-lived broad
  authority.
