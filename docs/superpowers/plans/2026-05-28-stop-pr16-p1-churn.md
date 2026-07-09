# Stop the PR #16 P1 Churn — Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the `chatgpt-codex-connector[bot]` from filing a fresh P1 on every push to PR #16 by sweeping each bug *class* to completion and consolidating the duplicated codepaths that keep regenerating bugs — instead of patching one flagged site at a time.

**Architecture:** The bot re-reviews the entire 96k-line diff on every push, so per-site fixes just surface the next instance of the same class. Investigation (2026-05-28) found the bot's ~29 findings collapse into 5 classes, of which **3 are already ~90% swept** by prior fixes. The remaining churn comes from: (1) unchecked/saturating arithmetic still left in `petal_executor.rs`; (2) three parallel "validate + charge" codepaths (mempool admission / proposal selection / block execution) that disagree; (3) stale per-command access-mode tracking in the PTB executor; (4) proposer/round/pol_round validation duplicated across 11 functions. Eliminate the classes structurally, gate every future push behind a local review, and split the PR so the review surface is bounded.

**Tech Stack:** Rust workspace (`crates/bloom-chain-node`, `crates/bloom-chain-consensus`, `crates/bloom-script`), `cargo test`, GitHub PR #16 (`feat/petals` → `master`).

---

## Scope Check

Phases 1–4 touch independent subsystems and are each independently landable — which is exactly what Phase 6 (split the PR) exploits. Execute them in any order, but land each as its own bounded PR so the bot has a small surface per review. Phases 5–6 are process changes that apply to all of them.

## File Map

| Subsystem | Files | Responsibility in this plan |
|---|---|---|
| Arithmetic sweep | `crates/bloom-chain-node/src/petal_executor.rs` | Convert remaining raw `+`/`saturating_*` on fuel/balances to checked ops with explicit reject |
| Admission↔execution parity | `crates/bloom-chain-consensus/src/mempool.rs`, `crates/bloom-chain-node/src/node.rs`, `crates/bloom-chain-node/src/consensus_driver.rs`, `crates/bloom-chain-node/src/petal_executor.rs` | One shared "would this tx be admitted/charged?" predicate used by all three paths |
| PTB script type/access | `crates/bloom-script/src/validator.rs`, `crates/bloom-script/src/executor.rs` | Reset access mode per Move command; type Publish outputs |
| Consensus round validation | `crates/bloom-chain-node/src/consensus_driver.rs`, `crates/bloom-chain-node/src/node.rs`, `crates/bloom-chain-consensus/src/state_machine.rs`, `crates/bloom-chain-consensus/src/engine.rs`, `crates/bloom-chain-consensus/src/validator_set.rs` | One `validate_proposer_and_round` helper shared by all paths |

---

## Phase 1: Finish the arithmetic sweep (`petal_executor.rs`)

**Why this phase:** `consensus_driver.rs`, `node.rs`, `mempool.rs`, and `bloom-dex-math` are already fully checked. `petal_executor.rs` is the only file with raw/saturating arithmetic left — it is the bot's next guaranteed P1. Sweep all of it in one commit.

**Files:**
- Modify: `crates/bloom-chain-node/src/petal_executor.rs`
- Test: `crates/bloom-chain-node/tests/` (add a unit test module or extend existing executor tests)

**Remaining sites (verified 2026-05-28):**
- `petal_executor.rs:150` — `DEPLOY_PETAL_BASE_FUEL + (len as u64 / DEPLOY_PETAL_BYTES_PER_FUEL)` — raw `+` on deploy fuel.
- `petal_executor.rs:783` — `(gas_budget as u128).saturating_mul(gas_price)` — reservation, silently caps at `u128::MAX`.
- `petal_executor.rs:794` — `pre_value.saturating_sub(reservation)` — silent underflow to 0 (also repeated at 904, 965, 1003, 1043 in revert paths).
- `petal_executor.rs:798, 1094, 1224` — `version.saturating_add(1)` / `obj.version += 1` — unchecked version increment.
- `petal_executor.rs:1084` — `(charged_fuel as u128).saturating_mul(gas_price)` — burnt fee, silent cap.
- `petal_executor.rs:1085` — `reservation.saturating_sub(burnt)` — refund, silent cap.
- `petal_executor.rs:1090` — `cur_value.saturating_add(refund)` — refund credit, silent cap at `u128::MAX`.

**Design note:** `reservation = gas_budget * gas_price` is the value every downstream `saturating_*` derives from. Compute it ONCE with `checked_mul` at the point the PTB envelope is validated; if it overflows, fail validation (no-op receipt, `fuel_used = 0`) so the tx is rejected rather than silently capped. Then the debit/refund chain can keep `saturating_sub` safely (operands are already bounded by a non-overflowing reservation) OR be promoted to `checked_sub` with an `expect` documenting the invariant. Pick checked + `expect("reservation bounds debit")` so the bot sees an explicit guard.

- [ ] **Step 1: Write the failing test — overflowing deploy fuel**

```rust
#[test]
fn deploy_fuel_for_bytes_does_not_overflow() {
    // usize::MAX bytes must not wrap u64; expect saturation at u64::MAX, not panic/wrap.
    let f = deploy_fuel_for_bytes(usize::MAX);
    assert_eq!(f, u64::MAX);
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p bloom-chain-node deploy_fuel_for_bytes_does_not_overflow`
Expected: FAIL (debug: arithmetic overflow panic; release: wrong value).

- [ ] **Step 3: Make `deploy_fuel_for_bytes` checked**

```rust
fn deploy_fuel_for_bytes(len: usize) -> u64 {
    let per_byte = (len as u64) / DEPLOY_PETAL_BYTES_PER_FUEL;
    DEPLOY_PETAL_BASE_FUEL.saturating_add(per_byte)
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cargo test -p bloom-chain-node deploy_fuel_for_bytes_does_not_overflow`
Expected: PASS.

- [ ] **Step 5: Hoist reservation to a single checked computation**

Replace the per-site `(gas_budget as u128).saturating_mul(gas_price)` at line 783 (and the matching revert-path sites) with a single value computed at PTB validation time. Where the PTB envelope is validated (`validate_ptb` / executor gas plumbing), add:

```rust
let reservation = (gas_budget as u128)
    .checked_mul(gas_price)
    .ok_or(PtbError::BuiltinFailed { reason: "gas reservation overflow".into() })?;
```

Thread `reservation` into the debit/refund block instead of recomputing. On the `Err`, return the existing no-op/failed `ExecOutput` (fuel_used = 0, success = false, write_set = None) so the tx is rejected — matching how the non-PTB path already rejects overflow in `consensus_driver.rs:728`.

- [ ] **Step 6: Promote version increments to checked**

At lines 798, 1094, 1224 replace `version.saturating_add(1)` / `version += 1` with:

```rust
obj.version = obj.version
    .checked_add(1)
    .expect("object version must not overflow u64");
```

- [ ] **Step 7: Add a regression test for reservation overflow rejection**

```rust
#[test]
fn ptb_with_overflowing_reservation_is_rejected_not_capped() {
    // Construct a SubmitPtb whose gas_budget * gas_price > u128::MAX.
    // Expect: ExecOutput { success: false, fuel_used: 0, write_set: None } (rejected),
    // NOT a silently-capped u128::MAX reservation.
    // (Use the existing executor test harness / fixture builders in this crate.)
}
```

- [ ] **Step 8: Run the full crate test suite**

Run: `cargo test -p bloom-chain-node`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/bloom-chain-node/src/petal_executor.rs crates/bloom-chain-node/tests/
git commit -m "Use checked arithmetic for all petal_executor fee/fuel math"
```

---

## Phase 2: Consolidate the three "validate + charge" codepaths

**Why this phase:** This is the single largest churn source. Three paths independently decide whether a tx is valid/chargeable and disagree:
- **Admission** — `mempool.rs::Mempool::admit()` (L58-170) + `precheck_submit_ptb()` (L339-370). Bypasses gas-payer balance for `SubmitPtb`; allows future nonces.
- **Selection** — `node.rs::build_proposal_block_from_candidates()` (L1344-1407). Trial-executes and silently drops txs that admission let through.
- **Execution** — `consensus_driver.rs::try_apply_block_state_transitions()` (L589-899) + `petal_executor.rs::execute_tx_impl()` (L509-1161). Strict next-nonce, validates gas-payer, charges fees.

Every "admit X but execution rejects X" and "admission checks sender, execution charges gas_payer" P1 is an instance of this divergence. A shared predicate makes them agree by construction.

**Files:**
- Create: `crates/bloom-chain-consensus/src/tx_admission.rs` (shared predicate + types)
- Modify: `crates/bloom-chain-consensus/src/mempool.rs:58-170,339-370`
- Modify: `crates/bloom-chain-node/src/node.rs:1344-1407`
- Modify: `crates/bloom-chain-node/src/consensus_driver.rs:589-899`
- Test: `crates/bloom-chain-consensus/tests/tx_admission.rs`, extend `crates/bloom-chain-consensus/tests/mempool.rs`

**Target interface (the contract all three paths share):**

```rust
/// Read-only view of the chain state a tx is judged against.
pub trait BalanceView {
    fn nonce(&self, addr: &Address) -> u64;
    fn loom_balance(&self, addr: &Address) -> u128;
}

pub enum AdmitOutcome {
    Ok,
    Reject(AdmitReject), // structured reason: Nonce, InsufficientBalance, EnvelopeInvalid, IntrinsicFuel, Overflow
}

/// The ONE place that answers "would this tx be accepted and chargeable?".
/// Used by mempool admission, proposal selection, and as the precondition
/// gate in block execution. `strict_nonce=false` for gossip admission
/// (allow future nonces); `true` for selection/execution.
pub fn check_admissible(
    tx: &SignedTx,
    view: &dyn BalanceView,
    strict_nonce: bool,
) -> AdmitOutcome;
```

Key correctness requirements this predicate centralizes (from the divergence table in the investigation):
1. Sender derivation (`Address::from_pubkey_bytes` == `tx.sender`).
2. Nonce: `strict_nonce` ⇒ `tx.nonce == current + 1`; else `tx.nonce >= current + 1`.
3. Balance: `DeployPetal` ⇒ check **sender**; `SubmitPtb` ⇒ check **`ptb.gas_payer`** (not outer sender) for `gas_budget * gas_price` (checked_mul).
4. Removed native transfer txs are rejected by the retired selector before admission.
5. Envelope caps: `tx.max_fuel >= ptb.gas_budget`, `tx.fee_per_unit >= ptb.gas_price`.
6. All arithmetic checked (no `saturating_add` admitting an overflowing reservation).

- [ ] **Step 1: Write the characterization test that pins parity (failing)**

This is the test that, once green, makes the whole class go away. It asserts admission and execution never disagree.

```rust
// crates/bloom-chain-consensus/tests/tx_admission.rs
#[test]
fn admission_accepts_iff_execution_would_charge() {
    // For a matrix of txs (Transfer over/under balance, SubmitPtb with
    // coinless sender but funded gas_payer, zero-fee, overflowing reservation,
    // future nonce), assert: check_admissible(strict=true) == Ok
    // IFF block execution produces a positive-fuel charged receipt.
    // Drive execution through try_apply_block_state_transitions on a 1-tx block.
}
```

- [ ] **Step 2: Run it, verify it fails to compile**

Run: `cargo test -p bloom-chain-consensus admission_accepts_iff_execution_would_charge`
Expected: FAIL — `check_admissible` / `tx_admission` module does not exist yet.

- [ ] **Step 3: Extract the predicate from current execution logic**

Create `crates/bloom-chain-consensus/src/tx_admission.rs` with `BalanceView`, `AdmitOutcome`, `AdmitReject`, and `check_admissible`. Lift the checks from `consensus_driver.rs:603-780` (sender/nonce/max-fee/balance) and `mempool.rs:339-370` (envelope precheck) into it verbatim, using `checked_mul`/`checked_add` throughout. Register `mod tx_admission;` in the crate root.

- [ ] **Step 4: Run the parity test, verify it passes against the extracted predicate**

Run: `cargo test -p bloom-chain-consensus admission_accepts_iff_execution_would_charge`
Expected: PASS (the test now drives `check_admissible` and a real execution and they agree).

- [ ] **Step 5: Route mempool admission through the predicate**

In `mempool.rs::admit()` replace the inline balance/nonce/envelope checks (L88-152) and `precheck_submit_ptb()` body with a single `check_admissible(tx, view, /*strict_nonce=*/ false)` call, mapping `AdmitReject` to the existing `AdmitError` variants. Keep replace-by-fee (L154-160) as-is.

- [ ] **Step 6: Route proposal selection through the predicate**

In `node.rs::build_proposal_block_from_candidates()` (L1344-1407), call `check_admissible(tx, &trial_state, /*strict_nonce=*/ true)` as a fast pre-filter before the trial execution, so selection drops the same txs execution would reject — for the same reason. Keep the trial-execute as the final authority.

- [ ] **Step 7: Make execution use the predicate as its precondition gate**

In `consensus_driver.rs::try_apply_block_state_transitions()` replace the hand-inlined sender/nonce/balance/envelope checks (L603-780) with `check_admissible(tx, &state, true)`; on `Reject`, emit the existing no-op receipt (fuel_used=0) and continue. Charging logic stays where it is.

- [ ] **Step 8: Run all three crates' tests**

Run: `cargo test -p bloom-chain-consensus -p bloom-chain-node`
Expected: PASS, including the parity test and existing mempool/consensus tests.

- [ ] **Step 9: Commit**

```bash
git add crates/bloom-chain-consensus/src/tx_admission.rs crates/bloom-chain-consensus/src/mempool.rs crates/bloom-chain-node/src/node.rs crates/bloom-chain-node/src/consensus_driver.rs crates/bloom-chain-consensus/tests/
git commit -m "Share one tx-admissibility predicate across mempool, selection, and execution"
```

---

## Phase 3: Finish PTB validator/executor type & access-mode tracking

**Why this phase:** SplitCoins/MergeCoins/MakeMoveVec already record precise types, and the signer-index bounds check already exists (`validator.rs:441-450`) — the bot's claim there was unfounded, so do **not** churn it. Two real gaps remain:
- `executor.rs:439` updates a borrow row's `access_mode` when an object appears in a Move command, but never **resets** it for commands where the object is absent. A later `TransferObjects` consume-check (`executor.rs:609`) then reads a **stale** mode.
- `validator.rs:298` records Publish outputs as `vec![None, None]` (untyped). Downstream uses already error via `resolve_required_use_type`, so this is lower priority — type it only if the bot files it.

**Files:**
- Modify: `crates/bloom-script/src/executor.rs:432-454,604-622`
- Modify (only if flagged): `crates/bloom-script/src/validator.rs:298`
- Test: `crates/bloom-script/tests/` (executor access-mode tests)

- [ ] **Step 1: Write the failing test — read-then-transfer must be denied**

```rust
#[test]
fn transfer_after_readonly_load_is_denied() {
    // PTB: command 0 calls a Move fn taking the persistent object as ReadOnly;
    // command 1 is TransferObjects on that same object id.
    // Expect: PtbError::AccessDenied (object was never loaded with Consume).
    // Today this can pass because the borrow row's access_mode is stale.
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p bloom-script transfer_after_readonly_load_is_denied`
Expected: FAIL (transfer wrongly succeeds).

- [ ] **Step 3: Reset access mode per command and track granted authority**

In `executor.rs` make the consume-check authoritative rather than reliant on the last-seen mode. Two viable shapes — pick the smaller diff:
  - (a) Before processing each Move command's args, reset every persistent borrow row's `access_mode` to its loaded/default mode, then apply only that command's declared modes (so `executor.rs:439`'s update is scoped to the current command); or
  - (b) Track a separate `consumed_authority: HashSet<ObjectId>` set only when an object is loaded with `AccessMode::Consume`, and gate `TransferObjects` (`executor.rs:609`) on membership instead of the live `row.access_mode`.

Implement (b) — it is explicit and the bot can see the invariant. Insert the `Consume` recording in the arg-loading loop (L432-454) and change the L609 condition to check the set.

- [ ] **Step 4: Run it, verify it passes; add the mutate-then-read ordering test too**

```rust
#[test]
fn mutate_then_readonly_same_object_is_consistent() {
    // command 0: Mutate; command 1: ReadOnly. Both must reflect their own
    // declared mode, not the first-seen mode.
}
```

Run: `cargo test -p bloom-script transfer_after_readonly_load_is_denied mutate_then_readonly_same_object_is_consistent`
Expected: PASS.

- [ ] **Step 5: Run the full script crate suite**

Run: `cargo test -p bloom-script`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/bloom-script/src/executor.rs crates/bloom-script/tests/
git commit -m "Track consume authority explicitly for TransferObjects access checks"
```

---

## Phase 4: Consolidate proposer/round/pol_round validation

**Why this phase:** The individual round-change bugs are already fixed (bounded proposer loop at `consensus_driver.rs:341-345`, `pol_round < proposal_round` guard, `block_response_header_round` rejecting `None`, late-polka recording, prevote-recheck-on-resume). But the logic lives in **11 functions** that each re-derive proposer/round independently — so the *next* edit in any one of them re-opens the class. Collapse them onto one helper so there is a single place to be correct.

**Files:**
- Create: `crates/bloom-chain-consensus/src/round_validation.rs`
- Modify: `crates/bloom-chain-node/src/consensus_driver.rs:341-353,493-505`
- Modify: `crates/bloom-chain-node/src/node.rs:1440-1503`
- Modify: `crates/bloom-chain-consensus/src/state_machine.rs:415-457`
- Reference: `crates/bloom-chain-consensus/src/validator_set.rs:90-94` (`proposer_for`), `engine.rs:142-179` (`maybe_propose`)

**Target interface:**

```rust
pub struct RoundJudgment {
    pub proposer_ok: bool,
    pub header_round: u32, // resolved from pol_round when set, else proposal round
}

/// Single entry point for "is this proposer valid for this block, and what
/// round does its header belong to?". `apply_window` selects bounded-window
/// acceptance (apply path) vs exact-round match (proposal/state-machine path).
pub fn judge_proposer_round(
    height: u64,
    header_proposer: Address,
    proposal_round: u32,
    pol_round: i32,
    validator_set: &ValidatorSet,
    apply_window: bool,
) -> Result<RoundJudgment, RoundError>;
```

- [ ] **Step 1: Write characterization tests pinning current behavior (failing to compile)**

```rust
// crates/bloom-chain-consensus/tests/round_validation.rs
#[test]
fn reproposed_block_uses_pol_round_for_header() { /* pol_round=2,proposal=5 => header_round=2 */ }
#[test]
fn pol_round_ge_proposal_round_is_rejected() { /* pol_round=5,proposal=5 => Err */ }
#[test]
fn apply_window_accepts_proposer_from_any_round_up_to_commit_round() { /* bounded by validator_set.len() */ }
#[test]
fn proposal_path_requires_exact_round_proposer() { /* apply_window=false => exact match only */ }
```

- [ ] **Step 2: Run, verify they fail to compile**

Run: `cargo test -p bloom-chain-consensus round_validation`
Expected: FAIL — `round_validation` module absent.

- [ ] **Step 3: Implement `judge_proposer_round` by lifting existing logic**

Create `round_validation.rs` combining: the bounded-window proposer check (`consensus_driver.rs:341-345`), the exact-round check (`consensus_driver.rs:493-505`, `state_machine.rs:423-426`), and the header-round resolution / `pol_round < proposal_round` guard (`node.rs:1440-1449`). Register the module.

- [ ] **Step 4: Run the characterization tests, verify they pass**

Run: `cargo test -p bloom-chain-consensus round_validation`
Expected: PASS.

- [ ] **Step 5: Redirect each call site to the helper**

Replace the inline logic at `consensus_driver.rs:341-353` (apply, `apply_window=true`), `consensus_driver.rs:493-505` (proposal, `apply_window=false`), `state_machine.rs:423-426` (`apply_window=false`), and the `pol_round` guard in `node.rs:1440-1449` with `judge_proposer_round(...)` calls. Leave `proposer_for`, `maybe_propose`, and the polka-recording in `state_machine.rs` (different concern) untouched.

- [ ] **Step 6: Run consensus + node suites**

Run: `cargo test -p bloom-chain-consensus -p bloom-chain-node`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/bloom-chain-consensus/src/round_validation.rs crates/bloom-chain-node/src/consensus_driver.rs crates/bloom-chain-node/src/node.rs crates/bloom-chain-consensus/src/state_machine.rs
git commit -m "Consolidate proposer/round/pol_round validation into one helper"
```

---

## Phase 5: Gate every push behind a local review (find the batch before the bot does)

**Why this phase:** Right now the bot drives the audit — you fix one comment, push, get the next. Flip it: run the same review locally, sweep the whole batch, push once. This is what makes pushes converge instead of ping-pong.

- [ ] **Step 1: Run the local correctness review on the touched crates**

Invoke `/code-review high` (or `ultra` for the multi-agent cloud pass) scoped to the current diff. Treat every finding as a *class* — when it names one site, grep for siblings and fix them all in the same commit.

- [ ] **Step 2: Run the security review**

Invoke `/security-review`. The consensus/PTB code is the high-risk surface (fund minting, fee bypass, round-change safety) — this is where the bot's P1s cluster.

- [ ] **Step 3: Resolve findings by class, then run the full workspace suite**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 4: Push once per phase, not once per finding**

Only push after Steps 1-3 are clean for that phase. Each push should retire a whole class, so the bot's re-review of that area finds nothing new.

---

## Self-Review

- **Spec coverage:** All 5 investigated bug classes are addressed — arithmetic (Phase 1), admission/execution parity (Phase 2), PTB type/access (Phase 3), consensus rounds (Phase 4); plus process (Phases 5-6). The CI/test-gate class is covered by Phase 6 PR D.
- **Already-fixed, do-not-touch:** signer-index check (`validator.rs:441-450`), SplitCoins/MergeCoins/MakeMoveVec typing, the bounded proposer loop, and the checked arithmetic already in `consensus_driver.rs`/`mempool.rs`/`node.rs`/`bloom-dex-math` — flagged here so a worker doesn't re-churn them.
- **Type consistency:** `check_admissible`/`BalanceView`/`AdmitOutcome` (Phase 2) and `judge_proposer_round`/`RoundJudgment` (Phase 4) are referenced with the same names at every call site.
- **Known approximation:** Phases 2 & 4 are refactors of existing logic, so steps cite exact source line ranges to lift from rather than reproducing hundreds of lines of final code; the characterization tests (Steps 1-4 of each) pin behavior so the refactor is safe.
