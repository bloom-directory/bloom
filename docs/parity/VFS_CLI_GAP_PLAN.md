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

## 2. Implemented: Polymarket risk-reducing VFS actions

Goal: expose cancel, redeem, revoke approvals, and pUSD withdraw through VFS
action paths. Cancel executes directly (no signing); the three owner-signed
actions follow the foreground-confirm pattern.

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
/polymarket/trade/<wallet>/orders/<order-id>/cancel              # direct handler exec (no unlock)
/polymarket/redeem/<wallet>/<slug>/{plan.md,confirm}             # foreground confirm
/polymarket/revoke-approvals/<wallet>/request/{plan.md,confirm}  # foreground confirm
/polymarket/withdraw/<wallet>/pusd/{plan.md,confirm}             # foreground confirm
```

Path convention keeps `<wallet>` immediately after `/polymarket` and an id slot
throughout, matching fund (`/polymarket/fund/<wallet>/<id>/...`) and trade
(`/polymarket/trade/<wallet>/drafts/<id>/...`). Resting CLOB orders live under
the trade namespace. `revoke-approvals` and `withdraw` are singleton actions, so
their id slot is the literal `request` / `pusd` segment.

Body: `confirm`, `y`, or JSON/TOML with `confirm=true` and optional
`confirm_risk`. `dry_run` is **rejected on `/confirm`** (confirm is execute);
the dry-run representation is the read-side `plan.md`. `cancel` accepts only the
ack body (`confirm`/`y`/`yes`); it takes no `--unlock-wallet` and no risk fields.

Execution shapes:

- `cancel` runs **directly in the mounted VFS handler** (like `new` paths) because
  it uses stored CLOB credentials and performs no owner signing.
- `redeem`, `revoke-approvals`, and `withdraw-pusd` follow the **foreground
  confirm** pattern established by fund/trade-confirm: the mounted handler
  advertises the path and renders guidance but refuses direct execution, because
  the signer ceremony must live in the foreground process.

Shared core function to call:

- Extract reusable service functions (`redeem_service`, `revoke_approvals_service`,
  `withdraw_pusd_service`, `cancel_service`) from the existing CLI
  implementations; CLI handlers delegate to them.
- Keep `submit_and_confirm_wallet_batch` as the shared relayer batch helper.
- The post-confirm on-chain verification loop in `revoke_approvals` (re-reading
  allowances and `isApprovedForAll` after the batch lands) must stay **inside**
  `revoke_approvals_service` so CLI and VFS cannot diverge on the safety check.

Safety invariants:

- cancel remains risk-reducing and geoblock warning-only;
- redeem refuses before Data API marks a position redeemable unless dry-run;
- revoke verifies allowances/operators are zero after confirmation;
- withdraw checks deposit-wallet pUSD balance;
- all owner-signed relayer operations use passkey/local unlock and order lock.

Tests added:

- CLI parser tests for redeem/revoke-approvals/withdraw-pusd confirm bodies (ack,
  JSON, TOML, wallet mismatch, unconfirmed, ignore-other; withdraw also rejects
  bare ack and missing amount);
- VFS handler test proving all three owner-signed surfaces advertise `confirm`,
  render guidance, and refuse direct handler execution; and that cancel
  advertises, renders guidance, and executes in-handler (failing on a durable
  pre-network gate rather than refusing);
- CLI subprocess parity smoke tests proving `bloom polymarket
  redeem|revoke-approvals|withdraw-pusd` and the matching
  `bloom vfs write .../confirm --unlock-wallet` paths share the same durable
  refusal (missing wallet) before any network/signing work; plus a
  test that withdraw confirm rejects a bare ack.

Docs updated:

- `docs/polymarket-integration.md`;
- `/polymarket/README.md`;
- `EXAMPLES.md`;
- `QUICKSTART.md`;
- `docs/parity/VFS_CLI_PARITY_LEDGER.md` (cancel/redeem/revoke/withdraw rows
  flipped to `parity`).

Rollback/non-goals:

- do not implement these as raw tx writes;
- do not add VFS paths until shared execution functions exist.

## 3. Implemented: Wallet outbox replace/cancel parity

Goal: make pending transaction cancellation/replacement explicit across CLI and
VFS.

User story: after staging a transaction, an agent can cancel or replace it
without manually editing outbox files.

Exact CLI behavior matched:

```bash
bloom wallet cancel <wallet> <chain> <id> [--text y] [--passphrase <passphrase>]
bloom wallet replace <wallet> <chain> <id> --intent '<replacement-intent>' [--passphrase <passphrase>]
```

`replace` reads the replacement intent from stdin when `--intent` is omitted.

Exact VFS path and body:

```text
/wallets/<wallet>/chains/<chain>/outbox/pending/<id>/cancel
/wallets/<wallet>/chains/<chain>/outbox/pending/<id>/replace
```

Shared core function called:

- the dedicated CLI commands dispatch through `write_unlocked` to the same VFS
  paths;
- `WalletsHandler::write_outbox` calls `TxEngine::cancel` and
  `TxEngine::replace_with_intent`;
- IPC/mount classify `cancel` and `replace` as wallet-signer writes, so the
  signer ceremony stays in the foreground/unlocked path.

Safety invariants:

- only pending, unbroadcast entries can be cancelled directly;
- replacement must preserve nonce safety and policy gates;
- no unrelated outbox entries are modified.

Tests added / existing coverage:

- CLI help smoke for first-class `wallet cancel` / `wallet replace`;
- existing `TxEngine` tests cover same-nonce replacement/cancel broadcast
  attempts, broadcast gates, policy gates, and marker artefacts;
- existing VFS tests cover `confirm`/`replace`/`cancel` control-file
  discoverability and write semantics.

Docs updated:

- parity ledger row flipped to `parity`.

Rollback/non-goals:

- do not expose filesystem deletes as the control plane.
- `confirm` body `cancel` remains local cancellation of an unbroadcast pending
  entry; the explicit `cancel` file/command submits a same-nonce network
  cancellation.

## 4. Audited: Hyperliquid exact CLI/VFS matrix

Goal: replace the old broad Hyperliquid parity row with exact current-state
classifications.

### 4.0.1 Read surfaces — parity

CLI:

```bash
bloom hyperliquid account <user> [--network <network>]
bloom hyperliquid spot-state <user> [--network <network>]
bloom hyperliquid open-orders <user> [--network <network>]
bloom hyperliquid fills <user> [--network <network>]
bloom hyperliquid funding <user> <coin> [--start-time <ms>] [--end-time <ms>] [--network <network>]
bloom hyperliquid book <coin> [--network <network>]
bloom hyperliquid candles <coin> <interval> <start-ms> <end-ms> [--network <network>]
bloom hyperliquid metadata --kind <perp|perp-contexts|spot|spot-contexts|mids> [--network <network>]
bloom hyperliquid test-reads <user> [--coin <coin>] [--network <network>]
```

VFS:

```text
/hyperliquid/<network>/{mids,perp_meta,perp_contexts,predicted_fundings,spot_meta,spot_contexts}.json
/hyperliquid/<network>/users/<account>/{clearinghouse,spot_state,open_orders,frontend_open_orders,fills,portfolio,rate_limit,extra_agents}.json
/hyperliquid/<network>/users/<account>/funding/<coin>.json
/hyperliquid/<network>/books/<coin>.json
/hyperliquid/<network>/candles/<coin>/<interval>.json
/hyperliquid/<network>/recent_trades/<coin>.json
/hyperliquid/<network>/asset_contexts/<coin>.json
/hyperliquid/<network>/funding_history/<coin>.json
```

Classification: `parity` / `track_a` under mocked Info endpoints. The CLI reads
call `bloom_hyperliquid::HyperliquidClient` directly; the VFS handler exposes
the same Info API families as files.

### 4.0.2 Owner exchange writes — VFS-only generic surface

VFS:

```text
/hyperliquid/<network>/exchange/<wallet>/order.json
/hyperliquid/<network>/exchange/<wallet>/cancel.json
/hyperliquid/<network>/exchange/<wallet>/schedule_cancel.json
/hyperliquid/<network>/exchange/<wallet>/update_leverage.json
/hyperliquid/<network>/exchange/<wallet>/raw_signed.json
```

Classification: `vfs_only` / `track_b`, intentionally. These are advanced
generic signed exchange writes. The CLI does not expose broad owner-signed
order/cancel/update commands because the recommended product path is bounded
agent sessions with policy/TTL/cap enforcement. Add dedicated CLI commands only
if product direction changes; do not infer this as an unresolved parity defect.

### 4.0.3 Agent sessions — parity

CLI:

```bash
bloom hyperliquid session create <wallet> [--id <id>] [--agent-name <name>] [--vault-address <addr>] [--network <network>]
bloom hyperliquid session status <wallet> <id> [--network <network>]
bloom hyperliquid session audit <wallet> <id> [--network <network>]
bloom hyperliquid session stop <wallet> <id> [--network <network>]
bloom hyperliquid session cancel-all <wallet> <id> [--network <network>]
bloom hyperliquid session close-all <wallet> <id> [--network <network>]
```

VFS:

```text
/hyperliquid/<network>/agent_sessions/<wallet>/new.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/status.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/session.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/audit.jsonl
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/last_response.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/order.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/cancel.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/schedule_cancel.json
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/stop
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/cancel_all
/hyperliquid/<network>/agent_sessions/<wallet>/<id>/close_all
```

Classification: `parity` for the CLI-exposed lifecycle commands under a running
daemon, because the CLI dispatches through the same VFS IPC paths. Session
`order.json` / `cancel.json` / `schedule_cancel.json` remain VFS-native action
sinks for agents inside the bounded session.

### 4.0.4 Live post-only smoke — excluded

CLI:

```bash
bloom hyperliquid test-post-only-cancel ... --danger-accept-live-orders
```

Classification: `cli_only` / `exclude`. This is an operator smoke test with a
danger flag and live-order cleanup logic, not a product workflow to mirror in
VFS.

Rollback/non-goals:

- do not broaden Hyperliquid trading semantics during the audit;
- do not add generic owner-signed CLI exchange commands unless product direction
  changes;
- keep owner recovery paths disabled unless they are routed through Sealed
  Approval host signing, and keep session actions scoped to the approved
  ephemeral API wallet.

## 4.1. Audited: Hyperliquid USD send parity already wired

Finding: the ledger's previous `cli_only` / `gap` classification for
Hyperliquid USD send was stale.

Exact CLI behavior:

```bash
bloom hyperliquid send-asset <wallet> <destination> <amount> --network <network>
```

Exact VFS path and body:

```text
/hyperliquid/<network>/exchange/<wallet>/send_asset.json
```

The CLI dispatches through plain IPC to the same VFS path with a JSON body
containing `destination` and `amount`. If the first write returns permission
denied, the daemon has written `approval_challenge.json`; the CLI opens its
`ceremony_url`, waits for grant-mode approval, then retries the same write. The
VFS handler runs `HyperliquidHandler::submit_usd_send`, which:

- requires configured wallet `[hyperliquid]` policy with `transfer_cap_usd`;
- parses the amount exactly to micro-USDC for cap evaluation;
- stages a sealed `usdSend` action and signs the Hyperliquid hash through
  PetalHost only while the grant is active;
- submits through the Hyperliquid exchange endpoint;
- persists the response to `last_response.json`.

Classification: `parity` / `track_a` under mocked exchange endpoints. This is
owner-authority by design; agent-session keys cannot authorize Hyperliquid
`usdSend`, so Bloom uses Sealed Approval host signing rather than wallet
unlocking.

## 4.2. Implemented: Polymarket builder-key list/revoke VFS parity

Goal: expose builder API key inspection and revocation through the Polymarket
VFS without exposing builder secrets.

Exact CLI behavior matched:

```bash
bloom polymarket builder-keys list <wallet>
bloom polymarket builder-keys revoke <wallet> [key]
```

Exact VFS path and body:

```text
/polymarket/builder-keys/<wallet>/keys.json
/polymarket/builder-keys/<wallet>/revoke
```

`revoke` accepts `confirm`, `y`, or JSON/TOML with `confirm=true` and optional
`key = "<builder-key-id>"`.

Shared core behavior:

- CLI and VFS both use stored CLOB credentials and
  `ClobClient::{list_builder_api_keys,revoke_builder_api_key}`;
- both delete local `builder_creds.json` when the revoked key matches the stored
  Bloom builder key;
- VFS `keys.json` returns key IDs/status metadata only, never secret or
  passphrase material.

Safety invariants:

- builder keys are relayer submission auth only and cannot move funds;
- revoke requires an explicit confirmation body;
- key IDs reject path traversal characters;
- no wallet owner signature is required, so revoke may execute inside the
  mounted handler like CLOB order cancel.

Tests added:

- VFS body parser tests for bare confirm, JSON/TOML keyed revoke, unconfirmed
  body rejection, and unsafe key-id rejection.

Rollback/non-goals:

- do not expose builder secrets/passphrases through VFS;
- do not create builder keys through VFS outside onboarding.

## 5. Audited: Petal, chain, and pipe execution split

Goal: make the product split explicit so petal install/run, chain admin/submit,
and pipe expression workflows are not mistaken for unresolved Track C parity
gaps.

User story: an agent can discover which petal/chain/pipe workflows are safe
benchmark candidates without inferring parity from adjacent read paths.

CLI surfaces:

```bash
bloom petals install|run|ls|name|uninstall ...
bloom chain init|run-validator|submit|query|call|pipe ...
bloom pipe <expr> --signer <hex> --gas-payer <hex>
```

VFS surfaces:

```text
/petals/... discovery/read endpoints
/petals/.pipe                         # executable shim: exec bloom chain pipe "$@"
/tx/new
/tx/<id>/cmd
/tx/<id>/signer
/tx/<id>/gas-payer
/tx/<id>/status
/tx/<id>/commit
/tx/<id>/abort
```

Classification:

- petal install/name/uninstall are `cli_only` / `track_b`: mutating local plugin
  management remains CLI-oriented;
- petal run is `hybrid_required` / `track_b`: VFS exposes endpoint discovery and
  chain petal surfaces, while broad local execution parity is intentionally
  deferred;
- chain node admin and raw submit are `cli_only` / `exclude`: validator
  lifecycle, xDSA keys, config, and raw transaction submission stay with local
  operator CLI commands;
- chain reads are VFS-compatible and remain `track_b` until an exact read matrix
  is selected;
- pipe/PTB execution is `parity` for the staged PTB substrate:
  `bloom pipe::lower_and_build` and VFS `TxHandler` both drive
  `bloom_ptb_builder::PtbSession`, and daemon-mounted `tx/<id>/commit` uses the
  injected `PtbSubmitter` for gas selection/sign/submit. The expression-language
  parser itself remains a CLI frontend and does not need a duplicate VFS parser.

Shared core already in use:

- `bloom_ptb_builder::PtbSession` for command append, validation, unsigned PTB
  build, status, and receipt projection;
- `bloom pipe::lower_and_build` lowers expression syntax to the same command
  lines a VFS client writes into `tx/<id>/cmd`;
- `TxHandler::commit_ndjson` renders the same canonical PTB/command NDJSON and
  appends submitter receipt lines when mounted in the daemon.

Safety invariants:

- no raw secret upload through VFS;
- no validator admin action through a mounted namespace without explicit local
  operator intent;
- PTB signing/gas-payer checks unchanged.

Tests to keep/add:

- existing pipe lower/build tests;
- existing tx handler session tests;
- add a golden test only when the benchmark suite is assembled: lower a pipe
  expression to command lines, stage those lines through `tx/<id>/cmd`, and
  assert the unsigned PTB digest plus command receipt projection match.

Docs to update:

- parity ledger and benchmark plans.

Rollback/non-goals:

- do not add a VFS expression parser unless product direction changes;
- do not expose validator admin or raw submit through mounted VFS paths.
