# C10 — EVM batch ceremony infrastructure exists but is not wired in

**Severity:** High · **Category:** Architectural / Functional
**Observed:** 2026-07-04, inferred from code analysis during the real-tx ceremony
UX review. Confirmed by tracing the sealed-approval ceremony, signer cache, and
`confirm-batch` paths end-to-end.

---

## What happened

`bloom wallet confirm-batch` with `--policy-session` on a passkey wallet
presents itself as a single-ceremony operation:

```
passkey confirm-batch requires --policy-session so the one ceremony is explicit
```

(`main.rs:2237`). But the code actually runs **one WebAuthn ceremony per
transaction**. For a batch of N pre-staged txs, the user performs N passkey
ceremonies. The "one ceremony" language is aspirational — the code does not
deliver it.

This is not a missing feature: the infrastructure for one-ceremony-many-signatures
already exists in the sealed-approval subsystem. It is simply not connected to
the batch command path.

## Why it happens

### The batch loop calls the ceremony per tx

`confirm-batch` (`main.rs:2306-2346`) iterates over the staged txs and, for
each one that is challenged, calls `sign_outbox_sealed_approval_if_challenged`:

```rust
for (chain, id) in refs {
    let confirm_once = || { d.tx_engine.confirm(...) };
    let staged = match confirm_once().await {
        Err(TxEngineError::BroadcastApprovalRequired(reason)) if passkey_wallet => {
            sign_outbox_sealed_approval_if_challenged(
                &d, &wallet, &chain, &id, approval_intent.clone(),  // ← per-tx call
            ).await?;
            confirm_once().await?
        }
        ...
    };
}
```

Each call to `sign_outbox_sealed_approval_if_challenged` reads **that tx's own**
`approval_challenge.json` (per-tx `intent_hash`, per-tx `action_id`) and calls
`run_sealed_approval_ceremony` (`main.rs:3070`), which **unconditionally**
launches a new WebAuthn assertion:

```rust
// sealed_ceremony.rs:31-35
let (assertion, signer) = keystore
    .sealed_approval_ceremony_with_intent(&wallet, &unsigned, intent)
    .await?;
```

There is no check for an existing live grant or cached signer before launching
the ceremony. Each ceremony mints a **new grant** with its own `grant_id`.

### The action kind is `Confirm` — one-shot by design

Each tx's sealed action uses `EvmSealedActionKind::Confirm`, which is one-shot
(`bloom-auth-api/src/lib.rs:1496-1498`):

```rust
fn is_one_shot(self) -> bool {
    matches!(self, Self::Confirm | Self::Replace | Self::Cancel)
}
```

One-shot actions are **forced** to `max_signatures: 1` (`lib.rs:1696-1699`):

```rust
if self.action_kind.is_one_shot() && self.daemon_terms.max_signatures != 1 {
    return Err(AuthApiError::InvalidSubject(
        "EVM one-shot actions must allow exactly one signature".into(),
    ));
}
```

So each grant is exhausted after one `sign_hash` call, the cached signer is
dropped (`petal_host.rs:455-458`), and the next tx needs a fresh ceremony.

## The infrastructure for batch IS already built

Three components were designed for one-ceremony-many-signatures, but the batch
command does not use them:

### 1. `EvmSealedActionKind::OwnerSessionUse` — not one-shot

`bloom-auth-api/src/lib.rs:1479-1498`:

```rust
pub enum EvmSealedActionKind {
    Confirm,
    Replace,
    Cancel,
    OwnerSessionUse,  // ← NOT one-shot
}

fn is_one_shot(self) -> bool {
    matches!(self, Self::Confirm | Self::Replace | Self::Cancel)
    // OwnerSessionUse is excluded → can have max_signatures > 1
}
```

`OwnerSessionUse` can carry `max_signatures > 1` — the validation at line 1696
does not fire for it. Test code confirms this works
(`lib.rs:4292`: `subject.action_kind = EvmSealedActionKind::OwnerSessionUse`,
`lib.rs:4302`: `max_signatures: 10`).

### 2. `SignerCache` — caches the decrypted signer across `sign_hash` calls

`crates/bloom-keystore/src/petal_host.rs:49-97`:

```rust
pub struct SignerCache { ... }

impl SignerCache {
    pub fn get(&self, grant_id: &str) -> Option<Arc<PrivateKeySigner>> { ... }
    pub fn insert(&self, grant_id: String, signer: Arc<PrivateKeySigner>, ...) { ... }
    pub fn drop_on_completion(&self, grant_id: &str) { ... }
}
```

After `run_sealed_approval_ceremony` completes, the decrypted signer is cached
(`sealed_ceremony.rs:52-57`):

```rust
signer_cache.insert(
    grant.grant_id.clone(),
    signer,
    wallet.clone(),
    grant.expiry_ms,
);
```

### 3. `sign_hash` reuses the cached signer without a ceremony

`petal_host.rs:405-407`:

```rust
let signer = if let Some(cache) = &self.signer_cache {
    if let Some(cached) = cache.get(&grant.grant_id) {
        cached  // ← no WebAuthn ceremony; signer reused
    } else { ... }
};
```

And the signer is **only dropped** when all signatures are consumed
(`petal_host.rs:455-458`):

```rust
if updated_grant.consumed_signature_count >= updated_grant.max_signatures
    && let Some(cache) = &self.signer_cache
{
    cache.drop_on_completion(&grant.grant_id);
}
```

### What a true batch path would look like

1. Stage **one** `OwnerSessionUse` sealed action with `max_signatures = N`,
   referencing all N txs by id/chain/hash.
2. Run **one** ceremony → mints one grant → caches the signer.
3. For each tx: `PetalHost::sign_hash` with the same `grant_id` → cache hit →
   sign without ceremony → `consume_signature` decrements the counter.
4. After the Nth signature, `drop_on_completion` cleans up.

The sealed-approval ceremony, grant minting, signer caching, signature
consumption, and audit logging all already work. Only the batch command path
doesn't use them.

## The alternative batch path (`unlock-once-sign-many`) is broken by `417b830`

Before the sealed-approval migration, Polymarket onboarding demonstrated a
different one-ceremony-many-signatures pattern:

1. `unlock_passkey_with_intent(wallet, Some(intent))` — one WebAuthn ceremony
   that decrypts and caches the `PrivateKeySigner`.
2. `KeystoreSigner::new(d.keystore.signer(&wallet)?)` — retrieves the cached
   signer.
3. `onboarder.run(&signer)` — signs ~10 messages (deploy, approvals,
   credential mint, sync) reusing the cached key.

This is the "unlock-once-sign-many" pattern. It works because
`unlock_passkey_with_intent` caches the decrypted key and `signer()` returns
it.

But commit `417b830` ("Guard passkey wallet signer access",
`lib.rs:857-866`) made `Keystore::signer()` **refuse** passkey wallets:

```rust
pub fn signer(&self, name: &str) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
    let info = self.info_unverified(name)?;
    if info.kind == WalletKind::PasskeyGated {
        return Err(KeystoreError::Signer(
            "passkey wallet signing requires a Sealed Approval grant via PetalHost::sign_hash"
                .into(),
        ));
    }
    self.cached_signer(name)
}
```

The replacement (`PetalHost::sign_hash`) returns a `SealedSignature` (base64
ECDSA + `intent_hash`), not an `Arc<PrivateKeySigner>`. The callers that use
`KeystoreSigner` (`polymarket.rs:565,1162,2683,2837,2962`, `main.rs:4305`)
expect an `Arc<PrivateKeySigner>` and cannot consume `SealedSignature` without
a redesign.

So `417b830` is a **half-completed migration**: it gated `signer()` for passkey
wallets but migrated zero callers and provided no public bridge from
`SealedSignature` to the `PrivateKeySigner`-based signing APIs that the
Polymarket and Hyperliquid commands depend on.

### Affected commands (all broken for passkey after `417b830`)

| Call site | Command | Uses `signer()`? | Passkey status |
|---|---|---|---|
| `polymarket.rs:565` | `polymarket order`, `polymarket sell` | yes | **BROKEN** |
| `polymarket.rs:1162` | `polymarket onboard` | yes | **BROKEN** |
| `polymarket.rs:2683` | `polymarket redeem` | yes | **BROKEN** |
| `polymarket.rs:2837` | `polymarket withdraw-pusd` | yes | **BROKEN** |
| `polymarket.rs:2962` | `polymarket revoke-approvals` | yes | **BROKEN** |
| `main.rs:4305` | `hl order` | yes | **BROKEN** |

Only `polymarket fund` survives — it uses the EVM outbox path (sealed-approval
grants via `tx_engine.confirm`), not `keystore.signer()`.

## Impact

- **Batch EVM operations require N ceremonies.** A 5-tx batch (e.g., approve +
  swap + transfer + stake + claim) requires 5 passkey ceremonies. This defeats
  the purpose of `confirm-batch` — the user could just as easily run `confirm`
  five times.

- **The "one ceremony" UX promise is broken.** `confirm-batch` with
  `--policy-session` explicitly claims to be a single ceremony
  (`main.rs:2237,2251`). It is not. A user who trusts this message will be
  surprised by the second, third, ... ceremony prompt.

- **`417b830` blocks the only working batch pattern.** The unlock-once-sign-many
  pattern (used by onboarding) was the only path that delivered true
  one-ceremony-many-signatures for passkey wallets. By gating `signer()`,
  `417b830` cut it off without providing a replacement. The intended replacement
  (`PetalHost::sign_hash`) exists but returns a different type that callers
  can't consume.

- **All non-EVM-outbox signing is broken for passkey.** Until the callers are
  migrated from `Keystore::signer()` to `PetalHost::sign_hash` (or a public
  bridge is added), Polymarket orders, onboarding, redeem, withdraw, revoke, and
  Hyperliquid orders all hard-fail for passkey wallets.

## Summary of the two gaps

| Gap | Root cause | Fix complexity |
|---|---|---|
| `confirm-batch` does N ceremonies | batch loop uses per-tx `Confirm` (one-shot) instead of one `OwnerSessionUse` grant with `max_signatures = N` | Medium — restructure the batch path to stage one `OwnerSessionUse` action, reuse the grant_id |
| `417b830` breaks unlock-once-sign-many | `signer()` refuses passkey; callers not migrated to `PetalHost::sign_hash` | Medium — either revert the gate, expose `cached_signer()` publicly as a bridge, or migrate all 6 callers to the `SealedSignature` API |
