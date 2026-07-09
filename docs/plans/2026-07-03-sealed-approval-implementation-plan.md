# Sealed Approval Implementation Plan (Parallel-Agent Edition)

**Status:** superseded for status tracking — see **[`2026-07-03-auth-hardening-pr-finish-plan.md`](2026-07-03-auth-hardening-pr-finish-plan.md)** for the current operative checklist
**Date:** 2026-07-03 (superseded 2026-07-03)
**Spec:** `docs/specs/2026-07-02-sealed-approval.md` (definitive target)
**Branch baseline:** `auth-architecture-hardening` @ `5181169`
**Owner goal (acceptance):** transactions can be executed from every Petal
component — `/requests` (x402/MPP), Polymarket, Hyperliquid, and EVM wallet tx —
with an **identical UX and security flow**: one passkey ceremony per action,
same file layout, same verification spine, grant-gated signing everywhere.

> **Note:** This document is kept for context on the parallel-agent dispatch
> history. Do **not** treat its §1 "Current state" table, "Missing / violating"
> list, or its unfinished milestone bullets as the source of truth — those are
> now stale. The current PR completion checklist lives in
> `2026-07-03-auth-hardening-pr-finish-plan.md`, and the current code inventory
> lives in that plan's Workstream 0 (Baseline Audit) section.

---

## 1. Current state (audited 2026-07-03)

> **Stale.** Use the finish plan's Workstream 0 + the updated Legacy Inventory
> in [`2026-07-03-auth-hardening-pr-finish-plan.md`](2026-07-03-auth-hardening-pr-finish-plan.md)
> for current status.

Solid and reusable (do NOT rebuild):

| Piece | Anchor |
|---|---|
| Intent hashing (BLAKE3 + `bloom.intent.v1`, full hex, per-field binding tests) | `crates/bloom-auth-api/src/lib.rs:107-118` |
| Challenge/nonce lifecycle, transactional burn, restart-safe replay denial | `crates/bloom-auth/src/lib.rs:648-843` |
| Central staging store (`sealed_intents` + `auth_entries`, shared by all venues) | `crates/bloom-auth/src/lib.rs:340-381` |
| WebAuthn verification, UV-for-hardened, counter persistence | `crates/bloom-keystore/src/passkey.rs` |
| Central `/outbox` VFS (pending/sent/failed, `latest` by staging time) | `crates/bloom-vfs/src/handlers/outbox.rs` |
| Deterministic `action_id` allocation + collision guard | `crates/bloom-auth/src/lib.rs:263-338,1313-1321` |
| Ceremony server hardening (token, origin, timeout, PRF zeroize) | `crates/bloom-keystore/src/passkey.rs:481-723,1698` |
| Legacy markers removed to test-only; production fails closed | `crates/bloom-daemon/src/ipc.rs:436,464,477` |
| Rule taxonomy start (`PolicyRuleClass {Hard, Soft, Informational}`) | `crates/bloom-proto/src/policy.rs:905-1007` |
| Authority-expansion classifier for policy edits | `crates/bloom-proto/src/policy.rs:519-661` |

Missing / violating (the work):

1. **No grant layer.** `SealedApprovalGrant`, `DaemonGrantTerms`,
   `PetalPolicySnapshot` do not exist. After approval verification every venue
   signs via a raw cached keystore signer (`wallets.rs:1307`,
   `bloom-polymarket/src/order.rs:417`, `bloom-hyperliquid/src/lib.rs:247`).
2. **Two ceremonies per action.** PRF unlock (`ipc.rs:402`) and approval
   assertion (`ipc.rs:570` → `passkey.rs:1719`, no PRF salt) are separate
   WebAuthn prompts. Spec §11.5 requires one.
3. **No Petal identity.** Only `executor_id`; no `petal_id`/`petal_digest`/
   `petal_version`, no placeholder constants.
4. **Challenge preimage missing fields** (§5.7): `wallet`, `petal_digest`,
   `daemon_terms_digest`, `petal_policy_digest`, `policy_version`.
5. **`write_unlocked` still exists** (`ipc.rs:297,361-510`; 7 CLI call sites).
6. **Local/passphrase wallets still creatable/unlockable**; no
   `migrate-local-to-passkey`; `SignerKind::Password` satisfies Standard
   assurance (`bloom-auth-api/src/lib.rs:44-56`).
7. **Raw unlocked signer cache** (`passkey.rs:1704-1707`) — on §5.4's
   forbidden list.
8. **No sessions/autonomy/budget code.** `StandingSession`,
   `SessionBudgetLedger`, `AutonomyPolicy` allow/deny sets, owner-signing
   sessions, denial strings: all absent (commits `ccaae3b`/`0f9ca2d` were
   docs-only). `LimitsPolicy` (policy.rs:399-438) has the four USD caps only.
9. **Single-credential keystore layout** — no `credentials/<id>/wrapped_dek`,
   no wallet DEK (§10).
10. **`wallet-policy` Petal missing**; policy writes go straight through
    `keystore.write_policy` (`wallets.rs:818`).
11. **`bloom-chain`/`pipe` signers present** (isolated but not hard-disabled).
12. **"Layer-B" terminology** survives in comments (`passkey.rs:1712`,
    `bloom-vfs/src/auth.rs`, `wallets.rs`).
13. **Tests**: spec §12 items 16–18, 20–28 uncovered (subject code absent).

---

## 2. Execution model

### Phases and parallelism

```text
Phase 0  (1 agent, sequential)      Schema & contract freeze
Phase 1  (5 agents, parallel)       Core services on frozen contracts
Phase 2a (1 agent)                  Reference venue conversion: EVM tx
Phase 2b (5 agents, parallel)       Remaining venues + wallet-policy petal
Phase 3  (2 agents, mostly serial)  Legacy deletion, integration, acceptance
```

Rules:

- **Contract freeze:** Phase 0 lands first and defines every shared type.
  Phase 1+ agents build against those types and MUST NOT modify
  `bloom-auth-api` except additive test code. Contract change requests go back
  to a single owner (serialize them).
- **File ownership:** each workstream has an exclusive write-set (below). An
  agent needing a change outside its set writes a `// TODO(ws-X)` note and
  reports it instead of editing.
- **Worktree isolation:** run parallel agents in separate git worktrees;
  merge in the stated order; rebase later workstreams on earlier merges.
- **Merge order:** WS-0 → (WS-A, WS-B, WS-C, WS-D, WS-E in any order) →
  WS-F (EVM) → (WS-G…WS-K in any order) → WS-L → WS-M.
- Every workstream ships its own unit tests; Phase 3 owns cross-cutting e2e.

### File-ownership matrix

| WS | Owns (write) | Reads only |
|---|---|---|
| 0 | `bloom-auth-api`, `bloom-auth` (schema/migrations) | — |
| A | `bloom-auth` (grant store), `bloom-daemon` (grant service, sign_hash) | auth-api |
| B | `bloom-keystore/src/passkey.rs` (ceremony), ceremony HTML/JS | auth-api |
| C | `bloom-keystore` (layout, DEK, credentials/) | auth-api |
| D | `bloom-proto/src/policy.rs` (autonomy, taxonomy) | — |
| E | new `crates/bloom-sessions` (+ small `bloom-auth` tables) | auth-api, proto |
| F | `bloom-tx`, `bloom-vfs/handlers/wallets.rs` | daemon grant API |
| G | `bloom-vfs/handlers/requests.rs`, `bloom-paid-http`, `bloom-paid-x402`, `bloom-paid-mpp` | grant API |
| H | `bloom-polymarket`, `bloom-vfs/handlers/polymarket.rs` | grant API |
| I | `bloom-hyperliquid`, `bloom-vfs/handlers/hyperliquid.rs`, `bloom-proto/src/hyperliquid_session.rs` | grant API, sessions |
| J | `bloom-defi`, `bloom-vfs/handlers/defi.rs` | grant API |
| K | new `wallet-policy` petal module, policy-write path in `wallets.rs` (coordinate with F) | grant API, proto |
| L | `bloom-daemon/src/ipc.rs` deletions, `bloom/src/main.rs`, `bloom-keystore` local-wallet removal, `bloom/src/commands/pipe.rs` | everything |
| M | `crates/bloom-it`, `crates/bloom/tests`, docs | everything |

---

## 3. Phase 0 — WS-0: Schema & contract freeze (BLOCKING)

**Spec:** §2, §5.7, §6, §9 (shapes), §11.10. **Crates:** `bloom-auth-api`, `bloom-auth`.

Tasks:

1. **Petal identity on the canonical header.** Extend `CanonicalIntentHeader`
   (`bloom-auth-api/src/lib.rs:60-105`): replace `executor_id` with `petal_id`,
   add `petal_digest`, `petal_version`, `executor_kind`
   (`first_party | wasm`), `expires_ms`. Because the canonical schema changes,
   **bump the domain tag to `bloom.intent.v2`** (§5.2) and update the schema
   string. Update all per-field binding tests; add binding tests for each new
   field.
2. **Placeholder digest constants** (§11.10) in one module, e.g.
   `bloom_auth_api::petal_identity`:
   `first-party-placeholder:evm-wallet:v0`, `paid-http`, `polymarket`,
   `hyperliquid`, `defi`, `wallet-policy` — each with the mandated TODO
   ("temporary, not a tamper-evidence boundary; replace with reproducible
   build/source digests before dynamic Petals get grants"). Provide
   `is_placeholder_digest()` so audit/status output can label them.
3. **`DaemonGrantTerms`** `{max_ttl_secs, max_signatures, allowed_sign_intents,
   assurance, extra}` with fail-closed unknown-required-`extra` semantics.
   No `require_attestation` field. Canonical serialization +
   `daemon_terms_digest()` (collision-resistant, domain-tagged).
4. **`PetalPolicySnapshot`** `{policy_version, wallet, petal_id, petal_digest,
   caps, hard_rules, step_up_rules, config, budget_state, session_scope}` with
   canonical bytes + `petal_policy_digest()`. `caps`/`config` as typed-value
   maps so venue crates can project their existing policy types into it.
5. **SealedAction record.** Grow the sealed record (today
   `CanonicalEnvelope` + `SealedIntentRecord`) to carry `plan`,
   `policy_checks`, `daemon_terms`, `petal_policy`, `petal_policy_digest`,
   `policy_version` under schema `bloom.sealed_action.v1`. Keep
   `CanonicalEnvelope` as the intent-hash preimage; the SealedAction wraps it.
6. **`ApprovalChallenge`** (`bloom.approval_challenge.v1`): extend
   `ChallengeRecord` (`lib.rs:452-460`) with `schema`, `wallet`, `petal_id`,
   `petal_digest`, `daemon_terms_digest`, `petal_policy_digest`,
   `policy_version`. Recompute the WebAuthn challenge as
   `BLAKE3("bloom.approval.v1", canonical(ApprovalChallenge))` over the FULL
   §5.7 preimage. Add per-field challenge-binding tests (§12 item 18).
7. **`SignedApproval`**: rename `Approval.signer_kind` →
   `signer_transport: "browser_webauthn" | "native_ctap2"`; **delete
   `Password` from the satisfying set** (assurance is enforced from
   authenticator flags only); add `petal_id`, `petal_digest`,
   `daemon_terms_digest`, `petal_policy_digest`, `policy_version`. Verification
   must require byte-equality of all daemon-issued values (§5.7 step 10).
8. **`SealedApprovalGrant`** type + **`GrantStore` trait** (in-memory only):
   fields per §6.4; constructor enforces `expiry_ms = min(now+120s,
   approval.expiry_ms)`; at most one live grant per
   `(wallet, action_id, petal_id, petal_digest)`; methods
   `mint / consume_signature / revoke / revoke_all_for_wallet / get_active`;
   **no serde derives on the grant** (compile-level "never persisted"). Add a
   compile test asserting `SealedApprovalGrant: !Serialize`.
9. **Signing attestation envelope**: `SigningAttestation {schema, petal_id,
   intent, facts: map}` with per-`(petal_id, intent)` schema registry hooks.
10. **DB migrations** (`bloom-auth`): add petal/digest/policy columns to
    `auth_entries` and `sealed_intents` (or a `sealed_actions` table);
    migration is destructive-safe (old pending entries become void — staged
    actions are re-stageable by design).
11. **Reconcile leftovers:** delete or clearly deprecate
    `StandingAuthorityGrant` (`lib.rs:324-334`) and fold `ApprovalCaps` into
    `DaemonGrantTerms` so there is exactly one grant model.

**Done when:** workspace compiles; all existing auth tests pass with new
fields; new binding/digest tests pass; `cargo doc` on the two crates renders
the full §6 data model.

**Status after WS-0 review fixes (2026-07-03):** WS-0 contracts are ready for
Phase 1 agents to build against.

- `SignedApproval` now serializes as the §6.3 production approval record:
  required `credential_id` plus `webauthn_assertion`; the old serializable
  test-signature enum is no longer part of `approval.json`.
- Challenge issuance and approval consumption now require a stored
  `SealedAction`; `sealed_action_json = NULL` rows fail closed, and persisted
  `auth_entries` digest/policy metadata must match the recomputed sealed action
  before a challenge is issued or consumed.
- `SealedAction::validate()` rejects wrong `CanonicalIntentHeader.schema`
  values (`bloom.intent_header.v2` is required).
- Sealed-action `expires_ms` is still intentionally enforced by WS-A's
  atomic verify-at-use path. Do not reopen this as a WS-0 gap unless WS-A
  decides challenge issuance should also clamp to sealed expiry.
- Verification run: `cargo test -p bloom-auth-api -p bloom-auth`, targeted
  `cargo test -p bloom-keystore passkey::approval_uv_tests`, and
  `cargo check -p bloom-auth-api -p bloom-auth -p bloom-keystore -p bloom-daemon
  -p bloom-vfs -p bloom-tx`. Full `bloom-keystore` tests still have the known
  sandbox-dependent ceremony-gate permission failures at
  `passkey.rs:2056`; the approval verifier subset passes.

---

## 4. Phase 1 — parallel core workstreams

### WS-A: Grant service + attested `sign-hash` host API

**Spec:** §5.3, §5.8, §6.4, §8. **Owns:** `bloom-auth` (grant store impl), `bloom-daemon`.

1. Implement `InMemoryGrantStore` behind the WS-0 trait: `RwLock` state,
   expiry sweep, revoke-on-shutdown hook, zeroization of any per-grant key
   material (`zeroize` crate) on consume/expiry/revoke/failure.
2. **Atomic verify-at-use** (§5.8): a per-action async mutex keyed by
   `action_id` wrapping: load sealed action → verify approval (existing
   `consume_verified_approval_transactionally`, `bloom-auth/src/lib.rs:648`)
   → burn nonce → mint grant → execute → audit. No re-reads from VFS paths.
3. **Grant-minting gate for wallet-signing actions** (§2 "Signed approval"):
   minting requires the live ceremony channel to have delivered PRF output to
   daemon memory (interface consumed from WS-B). An `approval.json` that shows
   up without a live ceremony fails closed with a distinct error.
4. **Host signing API** in the daemon (used by first-party venue code now,
   WASM later): `seal_context()`, `get_policy()` (returns the sealed snapshot
   bytes only), `sign_hash(wallet, hash32, intent, attestation)`, `audit(event)`.
   `sign_hash` enforces the full §8 checklist: active grant, wallet match,
   intent_hash match, petal_id/digest match, expiry, count < max_signatures,
   `intent ∈ allowed_sign_intents`, attestation schema allowed, attestation
   satisfies snapshot. Every rejection is a distinct auditable error.
5. Central audit events for stage/challenge/verify/mint/sign/deny/expire/
   revoke, labeling placeholder digests via `is_placeholder_digest()`.
6. **Unit tests** (§12 items 16, 17, 18-grant, 22, 23, 24, 27-partial):
   wrong-petal, wrong-intent, expired-grant, over-count, disallowed intent
   string, digest mismatch, attestation-exceeds-policy, approval-without-
   ceremony fails closed, grant not serializable, concurrent same-action mint
   race yields one grant.

### WS-B: One-ceremony passkey path (assertion + PRF)

**Spec:** §4, §5.4, §11.5. **Owns:** `bloom-keystore/src/passkey.rs`, ceremony page assets.

1. New `run_sealed_approval_ceremony(wallet, unsigned_approval, intent,
   credentials) -> (ApprovalSignature, PrfOutput)`: single
   `navigator.credentials.get()` with `challenge = unsigned.challenge_hash()`
   AND `extensions.prf.evalByCredential[credential_id].first = prf_salt`;
   `userVerification: "required"` when `assurance == hardened`.
   Anchors: assertion-only path `passkey.rs:1719-1762`, PRF path
   `passkey.rs:1609-1710` — merge them.
2. Ceremony page: offer all non-revoked credentials (or pinned one), resolve
   responding `credential_id` from the assertion, select matching `prf.salt`
   (per-credential once WS-C lands; single-credential until then), POST
   `{assertion, prf_output}` to the ceremony server. Keep existing hardening
   (token, origin, single-submission, timeout: `passkey.rs:481-723`).
3. PRF output goes to daemon memory only; zeroize immediately after
   DEK-unwrap/wrap-key derivation (pattern at `passkey.rs:1697-1703`). Never
   in `approval.json`, VFS, logs, or CLI stdio — add a serialization-boundary
   test (§12 item 16): grep-style assertion that `PrfOutput` is `!Serialize`
   and the ceremony response struct never reaches a VFS write.
4. **Delete the persistent unlocked-signer cache as the signing source**:
   the ceremony hands `(assertion, prf_output)` to the caller (WS-A mints the
   grant and holds decrypted key material behind it). Keep a thin
   deprecation shim only until WS-L removes the callers.
5. Tests: single-prompt returns both artifacts; UV enforced for hardened;
   revoked credential rejected; counter regression rejected; ceremony replay
   (second POST) rejected; daemon restart mid-ceremony invalidates it.

### WS-C: Multi-passkey credential layout + wallet DEK

**Spec:** §10. **Owns:** `bloom-keystore` (layout, creation, re-key).

1. Target layout: `wallet/{kind,address,pubkey,encrypted.key,policy.toml,
   policy.toml.sig,credentials/<credential_id>/{passkey.json,prf.salt,
   wrapped_dek,label,created_ms,revoked_ms}}`. Wallet key encrypted once by a
   random `wallet_dek`; each credential wraps the DEK with its PRF output.
2. Migration: on first unlock of a legacy single-credential wallet, unwrap via
   the old path and rewrite into the new layout (one-time, atomic, logged).
3. Creation flow per §10 steps 1–7 (generate key, prf.salt, WebAuthn
   registration with PRF, wrapped_dek, initial signed policy, recovery
   ceremony).
4. Add/remove/replace passkey as **authority-changing sealed actions**
   (`assurance = hardened`) — expose keystore primitives; the staging wiring
   itself lands with WS-K/F. Removing the last credential requires the
   explicit recovery ceremony.
5. Tests (§12 item 19): per-credential unwrap, revoked-credential rejection,
   add-credential round-trip, last-credential guard, legacy migration.

### WS-D: Policy — autonomy shape + hard/step-up taxonomy

**Spec:** §5.6, §9, §9.1. **Owns:** `bloom-proto/src/policy.rs`.

1. **`AutonomyPolicy`** full parse (§9.1): `enabled` (default false),
   micro-USD caps (reuse `parse_decimal_micro`, policy.rs:440-469),
   `require_passkey_above_usd`, allow/deny sets for assets, destinations,
   surfaces, action_kinds (deny wins). TOML shape per spec example.
2. **Taxonomy completion**: rename/extend `PolicyRuleClass::Soft` →
   `StepUp { ceiling: Option<...> }` (keep `Informational`, `Hard`); emit
   `rule_id, rule_class, outcome, message, step_up_ceiling` in
   `PolicyCheck` for plan/challenge rendering; step-up approvals may exceed
   only step-up rules and only to their ceiling.
3. **System vs wallet hard rules**: system rules compiled/daemon-configured,
   not removable by wallet policy; weakening a wallet hard rule classifies as
   `policy_hard_rule_change` requiring `hardened` + explicit diff (extend the
   classifier at policy.rs:519-661).
4. Pure-function evaluation entry point:
   `evaluate_autonomy(policy, action_facts, budget_view) -> AutonomyDecision`
   evaluated **before** any Petal-specific policy; surface policy can narrow,
   never widen.
5. Tests (§12 items 20-hard-rules, part of 24): disabled-by-default, deny-wins,
   ceiling enforcement, system-rule immunity, hard-rule-weakening
   classification.

### WS-E: Sessions & budget ledger

**Spec:** §7.3, §9.2, §11.8-scaffold, §11.9. **Owns:** new `crates/bloom-sessions`.

1. Implement §9.2 records verbatim: `StandingSession` (kinds
   `delegated_credential | owner_signing | service_auth`; statuses
   `active|expired|revoked|orphaned|halted|stale`), `SessionScope`,
   `SessionBudgetLedger`, `SessionUseRequest`, `SessionUseReceipt`.
2. Durable store (SQLite alongside the auth store) for **non-secret**
   metadata/caps/counters only, owner-only file perms, outside the VFS.
   Owner-signing key material lives in an in-memory registry keyed by
   `session_id` — process-local, zeroized on revoke/expiry/shutdown; sessions
   whose signer is gone become `orphaned` on daemon start.
3. **Transactional budget accounting**: per-(wallet, ledger) lock;
   `reserve(amount) -> reservation_id` before sign/dispatch; caps count
   `reserved + spent`; `commit(reservation)` / `release(reservation)`;
   conservative reconciliation hooks (retry/replace/drop/fail/reorg → halt or
   fail closed when reconciliation is unavailable).
4. **Cross-Bloom ledger**: one wallet-level ledger (windows: day/week/month,
   micro-USD) that all surfaces debit — the autonomy evaluation view WS-D
   consumes.
5. **Deterministic denial strings** as an error enum whose `Display` is
   exactly: `session_orphaned_requires_reapproval`,
   `session_budget_exhausted`, `session_scope_mismatch` (+
   `session_expired`, `session_revoked`, `session_halted`).
6. One live session per `(wallet, venue, network)`; frozen scope at mint;
   `stale_since_ms` surfacing for fail-stale types.
7. Tests (§12 items 25, 26, parts of 23/24): reservation concurrency (two
   concurrent uses cannot exceed a daily cap), release-on-failure, orphan on
   restart, freeze-at-mint (later policy edit doesn't widen), denial-string
   exactness.

---

## 5. Phase 2a — WS-F: Reference conversion, EVM wallet tx (SERIAL)

**Spec:** §11.2, §11.4; order per §13 step 5. **Owns:** `bloom-tx`,
`bloom-vfs/src/handlers/wallets.rs`. **Depends:** WS-A, WS-B, WS-D.

This is the template every other venue copies. Convert
tx confirm/replace/cancel end-to-end:

1. Staging (already central via `CentralOutboxProjection`,
   `bloom-tx/src/outbox.rs:317`) now seals `petal_id = "evm-wallet"`,
   placeholder digest, `daemon_terms` (`allowed_sign_intents =
   ["evm.tx.sign"]`, `max_signatures = 1`), and a `PetalPolicySnapshot`
   projected from `PolicyCaps`/allow-deny/budget (`bloom-proto/src/policy.rs`,
   `bloom-tx/src/policy_engine.rs`).
2. Confirm path: replace `keystore.signer()` +
   `build_signed_raw_tx(&PrivateKeySigner)` (`wallets.rs:1286-1345`,
   `tx_engine.rs:1512-1569`) with: one ceremony (WS-B) → verify + mint grant
   (WS-A) → render tx **from sealed canonical bytes** → `sign_hash` with an
   EVM attestation `{amount, asset, destination, chain_id, action_kind,
   fee_facts}` → broadcast → audit → grant consumed.
3. Autonomy fast path: in-policy actions consult WS-D/WS-E
   (autonomy + active bounded authority) instead of prompting; out-of-policy
   or no-authority actions stage for fresh Sealed Approval.
4. **e2e test** (extend `crates/bloom-it/tests/anvil_e2e.rs`): stage → single
   ceremony (mock authenticator) → grant → broadcast on anvil; plus denial
   e2e: expired grant, wrong petal, replayed approval.

**Done when:** no code path in `bloom-tx`/`wallets.rs` can reach a
`PrivateKeySigner` without an active grant, and the anvil e2e passes with
exactly one ceremony.

---

## 6. Phase 2b — parallel venue conversions

Each agent copies the WS-F pattern. Common per-venue checklist:

- petal identity + placeholder digest sealed into every action;
- `DaemonGrantTerms.allowed_sign_intents` with venue intent strings;
- `PetalPolicySnapshot` projected from the existing venue policy type;
- all signing through `sign_hash` + venue attestation schema;
- venue dirs remain projections; no venue approval files;
- venue e2e test with mocked endpoints proving one-ceremony flow + denials.

### WS-G: `/requests` — paid HTTP x402/MPP

Anchors: `requests.rs:427-519`, `bloom-paid-x402` (`KeystoreX402PaymentSigner`).
Extra tasks: allocate central action_ids via the projection/`action_id_map`
instead of using `request_id` directly (parity with EVM; mapping survives
restart, §11.3); MPP session deposits become sealed actions; autonomy fast
path for sub-threshold x402 (`$0.01` case, §2 "Autonomy") consuming WS-D/WS-E.
Intents: `x402.payment.sign`, `mpp.deposit.sign`.

### WS-H: Polymarket

Anchors: `polymarket.rs:2119-2147`, `bloom-polymarket/src/{relayer.rs:220,
order.rs:417,signer.rs:36}`.
Extra tasks: **batch onboarding** — `intent_hash` commits to the ordered step
list; `max_signatures =` step count; per-step `allowed_sign_intents`
(`polymarket.order.v2`, `polymarket.onboarding.approve`, …); no step
substitution after approval (§5.9). Snapshot from
`bloom-proto/src/polymarket_policy.rs` incl. CLOB/Gamma endpoints and geoblock
as a **hard rule**.

### WS-I: Hyperliquid

Anchors: `hyperliquid.rs:1849,1903-1926`, `bloom-hyperliquid/src/lib.rs:232-303`,
`bloom-proto/src/hyperliquid_session.rs`.
Extra tasks: `approveAgent` mints a **delegated-credential StandingSession**
(WS-E) — migrate `HyperliquidSession` risk tracking into
`SessionScope`/ledger or bridge it; agent-key ops check frozen session caps +
central audit; `usdSend`/withdraw = value-moving sealed actions
(`hyperliquid.approve_agent`, `hyperliquid.usd_send`, `hyperliquid.order`).

### WS-J: DeFi

Anchor: `bloom-vfs/src/handlers/defi.rs`, `bloom-defi`.
Tasks: DeFi route execution stages its **own** sealed action
(`petal_id = "defi"`, route facts in canonical subject) rather than riding the
EVM outbox implicitly; snapshot from `defi_policy.rs`; intent `defi.route.sign`.

### WS-K: `wallet-policy` first-party Petal (§11.7)

Owns the policy-write path (coordinate file handoff with WS-F on `wallets.rs`).
Tasks: VFS writes to `policy.toml` stage a `policy_update` sealed action
(`authority_change = true`; hardened when expanding per WS-D classifier); plan
shows the diff + expansion analysis; execution reads **sealed proposed policy
bytes**, signs `policy.toml.sig` via `sign_hash` (intent
`wallet_policy.sign` in `allowed_sign_intents`), atomically installs
`policy.toml` + sig; direct `keystore.write_policy` (`wallets.rs:818`) becomes
unreachable from user input. Re-key/add-passkey actions (WS-C primitives) are
staged through this petal too.

### WS-E2 (joins Phase 2b): EVM owner-signing sessions (§11.8)

**Depends:** WS-E, WS-F. One hardened ceremony mints an
`evm_owner_signing_session` with frozen scope `{wallet, chain_id,
token_contract, recipient, rolling 24h window, max_amount, allowed_method =
ERC20.transfer, max_fee_policy, ttl, fail_safe}`; owner signer held in-memory
behind the session registry; session-use requests bind `session_id` (no fresh
approval.json), enforce exact token/recipient/chain/method/fee/cap before each
signature, reserve-then-commit budget, audit every attempt; deny paths return
WS-E denial strings. Tests: the full §12 item 23 matrix (100 USDC/day happy
path; wrong token/recipient/chain, over-budget, expired, restarted, orphaned,
revoked all deny).

---

## 7. Phase 3 — deletion, integration, acceptance

### WS-L: Legacy deletion (SERIAL — after all venues are grant-gated)

**Spec:** §3.1-3.3, §10, §11.1, §11.6.

1. Delete `write_unlocked`: IPC dispatch (`ipc.rs:297`), `do_write_unlocked`
   (`ipc.rs:361-510`), all 7 CLI call sites (`main.rs:1397,1583,2042,3300,
   3880,3943,4107`). The plain `write` path + venue handlers now carry the
   flow.
2. Remove the keystore unlocked-signer cache and `Keystore::unlock`-for-signing;
   remove local wallet creation (`create_local`), passphrase flags/prompts
   (`resolve_new_wallet_passphrase`, `--allow-passphrase-wallet`), Argon2
   wrap path. Keep read-only local-wallet **detection** that fails closed with
   the migration message.
3. Implement `bloom wallet migrate-local-to-passkey <old> <new>` (may require
   old passphrase locally; creates a passkey wallet; never preserves
   passphrase signing).
4. `bloom-chain`/`pipe`: hard-disable signing (compile-out feature or
   startup-fatal guard) per §11.6.
5. Terminology sweep: purge "Layer-B" comments (`passkey.rs:1712`,
   `bloom-vfs/src/auth.rs`, `wallets.rs`), rename internals to Sealed
   Approval vocabulary (§15).
6. Delete deprecation shims from WS-B/WS-0 (`StandingAuthorityGrant`, old
   `ApprovalCaps` aliases).

### WS-M: Acceptance test suite + docs (partially parallel with WS-L)

1. **Per-venue uniform-flow e2e** (the owner's acceptance test, automated):
   for each of EVM, requests, Polymarket, Hyperliquid — stage → verify
   identical `/outbox/pending/<id>/` file set → **exactly one** ceremony
   (assert single authenticator invocation) → grant-gated signature →
   `status.json`/`result.json`/central audit written. One parameterized
   harness, four venue fixtures, mocked venue endpoints + mock authenticator.
2. Close remaining §12 items not owned by earlier workstreams: 20 (marker
   absence asserted against production paths), 21 (PRF serialization
   boundary), 22 (reconciliation freeze/revoke — post-execution receipts vs
   attestations, from §9 "Post-execution reconciliation"), 27 (placeholder
   labeling in audit/status), 28 (documented trust-boundary test).
3. Cross-Bloom autonomy e2e (§12 item 24): low-value x402 executes with zero
   prompts under policy+session+budget; denies on disabled/exhausted/blocked/
   no-authority.
4. Docs: update `EXAMPLES.md`, `QUICKSTART.md`, `README.md`, venue docs to
   Sealed Approval terminology; delete/supersede `proposed_auth_architecture.md`
   (fold any still-relevant rationale into the spec).

---

## 8. Kickoff summary

| Wave | Agents | Workstreams |
|---|---|---|
| 1 | 1 | WS-0 (contract freeze) |
| 2 | 5 | WS-A, WS-B, WS-C, WS-D, WS-E |
| 3 | 1 | WS-F (EVM reference) |
| 4 | 6 | WS-G, WS-H, WS-I, WS-J, WS-K, WS-E2 |
| 5 | 2 | WS-L, WS-M |

Per-agent brief template: *objective; spec sections; owned files; read-only
anchors; task list; interface consumed/produced; tests to ship; done-criteria;
"do not modify" list.* All of these are enumerated in §§3–7 above — each
workstream section is written to be handed to an agent verbatim, together
with the spec file and this plan's §1 anchors.

Global done-criteria = spec §12 items 1–28 all green + the per-venue
uniform-flow e2e (WS-M task 1) passing for all four venues.
