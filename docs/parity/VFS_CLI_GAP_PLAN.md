# VFS/CLI Gap Plan

Date: 2026-06-28

This plan ranks the gaps identified in
`docs/parity/VFS_CLI_PARITY_LEDGER.md`. The ranking favors agent/product value
first, then implementation risk. Value-moving workflows must use shared
execution logic; VFS handlers may parse path/body input, but must not duplicate
signing, posting, policy, geoblock, lock, receipt, or broadcast logic.

## 0. Implemented: Polymarket fund request confirm via foreground VFS CLI

Goal: execute a funding request staged through `/polymarket/fund/<wallet>/new`
through a VFS-shaped confirm path.

User story: an agent stages a pUSD funding request, reads the durable plan, then
asks the owner to run one foreground VFS write that executes that exact request.

Exact CLI behavior matched:

```bash
bloom polymarket fund <wallet> --request <id> [--dry-run] [--confirm-risk]
```

Exact VFS path and body:

```bash
bloom vfs write /polymarket/fund/<wallet>/<id>/confirm \
  --unlock-wallet <wallet> \
  --data confirm

bloom vfs write /polymarket/fund/<wallet>/<id>/confirm \
  --unlock-wallet <wallet> \
  --data '{"confirm":true,"dry_run":true,"confirm_risk":true}'
```

Shared core function to call:

- `commands::polymarket::fund_from_request`, which calls
  `commands::polymarket::fund`, `TxEngine::stage`, and `TxEngine::confirm`.

Safety invariants:

- request id rejects traversal;
- unlock wallet must match path wallet;
- request body must affirm confirmation;
- fund core re-reads live pUSD balance and live route quotes;
- fund core enforces onboarding/deposit-wallet owner binding;
- route policy, EVM policy, outbox review, passkey/local unlock, broadcast, and
  request executed marking stay in the shared CLI funding path;
- mounted/IPC handler advertises the path for discovery but refuses execution
  with foreground CLI guidance, because the signer ceremony must live in the
  signing process.

Tests added:

- CLI parser tests for ack body, structured JSON body, wallet mismatch, and
  unrelated path ignoring;
- VFS handler test proving a staged fund request exposes `confirm`, renders
  guidance, and refuses direct handler execution with foreground-unlock text.

Docs updated:

- Polymarket VFS README string;
- `docs/polymarket-integration.md`;
- `EXAMPLES.md`;
- `QUICKSTART.md`.

Rollback/non-goals:

- rollback by removing the CLI intercept and VFS `confirm` discoverability;
- does not implement mounted daemon signing;
- does not implement Polymarket trade draft confirm.

## 1. Implemented: Polymarket trade draft confirm/post via foreground VFS CLI

Goal: add a writable confirmation path for order and sell-to-close drafts.

User story: an agent creates a draft through
`/polymarket/trade/<wallet>/new`, reviews `drafts/<id>/plan.md`, and asks the
owner to confirm by writing to a VFS path rather than switching to a separate
`polymarket confirm` command.

Exact CLI behavior to match:

```bash
bloom polymarket confirm <wallet> <draft-id> [--confirm-risk]
```

Exact proposed VFS path and body:

```bash
bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm \
  --unlock-wallet <wallet> \
  --data confirm

bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm \
  --unlock-wallet <wallet> \
  --data '{"confirm":true,"confirm_risk":true}'
```

Shared core function called:

- `commands::polymarket::confirm`, which loads the durable draft and calls the
  existing internal `execute` path used by `bloom polymarket confirm`.
- VFS path/body parsing stays in the command layer; the mounted VFS handler only
  exposes discovery/help and refuses direct execution with foreground CLI
  guidance.

Safety invariants preserved:

- stale draft refusal;
- geoblock behavior identical to CLI;
- policy re-check from current policy;
- order lock around confirm/post/receipt writes;
- sell-to-close holdings preflight;
- passkey/local unlock with exact Polymarket order review intent;
- CLOB post rejection/ambiguous reconciliation behavior unchanged;
- receipt/audit artifacts identical to CLI.

Tests added:

- parser/routing tests for confirm path and body;
- mounted VFS handler discovery/read/refusal test for `drafts/<id>/confirm`;
- subprocess parity smoke test proving `bloom polymarket confirm` and
  `bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm
  --unlock-wallet <wallet> --data confirm` share the same durable missing-draft
  refusal before network/signing work.

Docs updated:

- Polymarket VFS README string;
- `docs/parity/VFS_CLI_PARITY_LEDGER.md`;
- `docs/polymarket-integration.md`;
- `EXAMPLES.md`;
- `QUICKSTART.md`;
- `README.md`.

Rollback/non-goals:

- rollback by removing the VFS dispatch and keeping CLI confirm only;
- do not add a second order signer/poster;
- do not weaken geoblock, stale-draft, policy, lock, or receipt guarantees.
- mounted/IPC handler execution remains intentionally unsupported because the
  signer ceremony must live in the foreground process.

## 2. Next: Polymarket risk-reducing VFS actions

Goal: expose cancel, redeem, revoke approvals, and possibly pUSD withdraw
through VFS action paths when their shared cores are extractable.

User story: an agent can discover and execute operational safety actions from
the same `/polymarket` namespace used for positions and account state.

Exact CLI behavior to match:

```bash
bloom polymarket cancel <wallet> <order-id>
bloom polymarket redeem <wallet> <slug> [--dry-run]
bloom polymarket revoke-approvals <wallet> [--dry-run]
bloom polymarket withdraw-pusd <wallet> <amount|all> [--dry-run]
```

Exact proposed VFS paths and bodies:

```text
/polymarket/orders/<wallet>/<order-id>/cancel
/polymarket/redeem/<wallet>/<slug>/{plan.md,confirm}
/polymarket/approvals/<wallet>/revoke/{plan.md,confirm}
/polymarket/withdraw/<wallet>/pusd/{plan.md,confirm}
```

Body: `confirm`, `y`, or JSON/TOML with `confirm=true`, `dry_run`, and
`confirm_risk` where the underlying command supports risk acknowledgement.

Shared core function to call:

- Extract reusable service functions from the existing CLI implementations.
- Keep `submit_and_confirm_wallet_batch` as the shared relayer batch helper.

Safety invariants:

- cancel remains risk-reducing and geoblock warning-only;
- redeem refuses before Data API marks a position redeemable unless dry-run;
- revoke verifies allowances/operators are zero after confirmation;
- withdraw checks deposit-wallet pUSD balance;
- all owner-signed relayer operations use passkey/local unlock and order lock.

Tests to add:

- mocked relayer/Data/CLOB tests for success and refusal cases;
- dry-run artifact tests;
- post-confirm state verification tests;
- no-secret-leak tests.

Docs to update:

- `docs/polymarket-integration.md`;
- `/polymarket/README.md`;
- examples for risk-reducing actions.

Rollback/non-goals:

- do not implement these as raw tx writes;
- do not add VFS paths until shared execution functions exist.

## 3. Wallet outbox replace/cancel parity audit

Goal: make pending transaction cancellation/replacement explicit across CLI and
VFS, or document the intentional surface split.

User story: after staging a transaction, an agent can cancel or replace it
without manually editing outbox files.

Exact CLI behavior to match:

- To be confirmed from current command inventory; no dedicated user-facing
  command was found in the initial pass.

Exact proposed VFS path and body:

```text
/wallets/<wallet>/chains/<chain>/outbox/pending/<id>/cancel
/wallets/<wallet>/chains/<chain>/outbox/pending/<id>/replace
```

Shared core function to call:

- `TxEngine` / `Outbox` cancel and replacement helpers, if present.

Safety invariants:

- only pending, unbroadcast entries can be cancelled directly;
- replacement must preserve nonce safety and policy gates;
- no unrelated outbox entries are modified.

Tests to add:

- pending-only cancel;
- replacement policy re-check;
- nonce dependency behavior.

Docs to update:

- wallet outbox docs and agentic wallet docs.

Rollback/non-goals:

- do not expose filesystem deletes as the control plane.

## 4. Hyperliquid exact CLI/VFS golden matrix

Goal: turn the current broad Hyperliquid support into a precise parity matrix
with Track A golden tests.

User story: benchmark authors can select only Hyperliquid workflows that both
CLI and VFS can execute with equivalent capabilities.

Exact CLI behavior to match:

- `bloom hyperliquid` read/action commands in `crates/bloom/src/main.rs`.

Exact proposed VFS path and body:

- Existing `/hyperliquid/<network>/...` reads and action/session paths.

Shared core function to call:

- Existing `bloom_hyperliquid` client, signer, session, and policy helpers.

Safety invariants:

- scoped agent keys are not treated as owner wallets;
- session TTL/caps/close behavior is preserved;
- owner recovery paths remain owner-signed.

Tests to add:

- CLI/VFS golden tests over mocked Info/Exchange endpoints.

Docs to update:

- `docs/hyperliquid-integration.md`;
- parity ledger.

Rollback/non-goals:

- do not broaden Hyperliquid trading semantics during the audit.

## 5. Petal and chain execution parity

Goal: decide whether petal/chain execution should have first-class VFS action
parity or remain CLI/IPC oriented.

User story: an agent can discover whether petal install/run and chain submit are
safe benchmark candidates instead of inferring parity from adjacent read paths.

Exact CLI behavior to match:

```bash
bloom petals install|run|ls|name|uninstall ...
bloom chain init|run-validator|submit|query|call|pipe ...
bloom pipe <expr> --signer <hex> --gas-payer <hex>
```

Exact proposed VFS path and body:

- Do not propose until product direction is decided.

Shared core function to call:

- petal store/runtime and chain command helpers if parity is required.

Safety invariants:

- no raw secret upload through VFS;
- no validator admin action through a mounted namespace without explicit local
  operator intent;
- PTB signing/gas-payer checks unchanged.

Tests to add:

- only after the product decision.

Docs to update:

- parity ledger and benchmark plans.

Rollback/non-goals:

- excluded from current implementation phase.
