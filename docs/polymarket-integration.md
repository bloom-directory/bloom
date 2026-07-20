# Polymarket Integration

**Status (2026-06-13): implemented; live entry and exit completed.** Bloom's
tradeable path is deposit-wallet mode: it creates/loads CLOB creds, creates a
builder API key with CLOB L2 auth, uses that key for relayer
`POLY_BUILDER_*` auth, deploys or verifies the deposit wallet, funds pUSD into
that wallet, syncs `signatureType = 3` buying power, then places POLY_1271
orders with the deposit wallet as maker/funder. See
`crates/bloom-polymarket/`, `crates/bloom-vfs/src/handlers/polymarket.rs`, and
`crates/bloom/src/commands/polymarket.rs`.

**Live verification (2026-06-13):** one capped Polygon mainnet passkey run
completed onboard -> fund -> trade -> exit -> withdraw; `obligations` then
reported no open positions. This records that the path works end-to-end, not an
instruction to trade.

**Trading facts enforced by KATs in `crates/bloom-polymarket/src/order.rs`:**

- CLOB signs the order struct:
  `Order(salt,maker,signer,tokenId,makerAmount,takerAmount,side,signatureType,timestamp,metadata,builder)`.
- EIP-712 domain is `"Polymarket CTF Exchange"`, version `"2"` for normal and
  neg-risk exchanges; only verifying contract differs.
- `salt` is a JSON number <= 2^53-1; `timestamp` is unix milliseconds;
  `metadata`/`builder` are zero `bytes32` unless builder attribution is
  explicitly enabled.
- New-user orders use deposit-wallet `signatureType = 3` (POLY_1271). EOA-maker
  orders are not the default path.
- Bloom refuses to trade unless `GET /version` reports order version `2`.

## Runtime Modes

- `bloom vfs cat/ls` runs a fresh in-process daemon per invocation; good for
  reads and single writes.
- DeFi sessions are file-backed under `~/.bloom/defi/`; `bloom serve` is useful
  but not required to keep swap sessions alive.
- Prefer self-contained blocking commands for agent flows:
  `onboard`, `fund`, `order --dry-run`, `confirm`, `sell`, `cancel`,
  `obligations`, `redeem`, `withdraw-pusd`, and `revoke-approvals`.
- The runtime integration is mounted by default. Set `enabled = false` in the
  runtime configuration's `[polymarket]` table to disable the entire VFS
  surface.
- Separately, wallet policy enables trading by default. Set `enabled = false`
  in the wallet policy's `[polymarket]` table to disable trading, or add caps
  and allow/deny lists to constrain it.
- Funding requests staged under `polymarket/fund/<wallet>/new` can be executed
  with `bloom vfs write /polymarket/fund/<wallet>/<id>/confirm --unlock-wallet
  <wallet> --data confirm`; this dispatches to the same funding engine as
  `bloom polymarket fund <wallet> --request <id>`.
- Drafts and receipts are durable and read-only under
  `polymarket/trade/<wallet>/{drafts,receipts}/...`; draft confirmation can be
  executed with `bloom vfs write
  /polymarket/trade/<wallet>/drafts/<id>/confirm --unlock-wallet <wallet>
  --data confirm`, which dispatches to the same order engine as
  `bloom polymarket confirm <wallet> <id>`.
- Risk-reducing and exit actions now have VFS parity. Redeem, revoke-approvals,
  and pUSD withdraw are owner-signed, so the mounted handler advertises the path
  and refuses direct execution; confirm through the foreground CLI VFS path:
  `bloom vfs write /polymarket/redeem/<wallet>/<slug>/confirm --unlock-wallet
  <wallet> --data confirm`,
  `bloom vfs write /polymarket/revoke-approvals/<wallet>/request/confirm
  --unlock-wallet <wallet> --data confirm`, and
  `bloom vfs write /polymarket/withdraw/<wallet>/pusd/confirm --unlock-wallet
  <wallet> --data '{"confirm":true,"amount":"<amount|all>"}'`. Each dispatches to
  the same core as `bloom polymarket redeem|revoke-approvals|withdraw-pusd`; print
  the plan first with the CLI `--dry-run` flag. pUSD withdraw requires an
  explicit `amount` in the body (the path carries no amount slot).
- Cancel is risk-reducing and uses stored CLOB credentials (no owner signing), so
  it executes directly in the VFS — no foreground ceremony is needed:
  `bloom vfs write /polymarket/trade/<wallet>/orders/<order-id>/cancel --data
  confirm`, dispatching to the same cancel core as
  `bloom polymarket cancel <wallet> <order-id>`.
- Passkey/WebAuthn proves user presence, not transaction content. Bloom opens a
  local browser review page and prints a matching review hash; this is a local
  consistency check, not a hardware trusted display.
- Scoped run capabilities are the next auth milestone and remain tracked in the
  active plan queue.

## Funding And Approvals

- Deposit-wallet pUSD buying power must be live in the deposit wallet. EOA
  balances and stale onboard status are not enough.
- Onboarding grants pUSD/CTF approvals through relayer wallet batches; remove
  them with `bloom polymarket revoke-approvals <wallet>` when done.
- Enso swap funding refuses while `[defi] require_calldata_verification = true`
  if receiver/min-output cannot be verified from calldata or simulation.
- Current same-chain funding performs a receiver calldata consistency check: it
  asserts the deposit wallet address is present in `tx.data`. This is not
  ABI-field verification and not a malicious-Enso defense.
- Cross-chain receiver and min-output remain quote-only until simulation
  min-output and destination settlement checks land. Dependent actions must wait
  for settlement proof.
- One-shot CLI order flows must not send Polymarket heartbeats.
- Bloom never attaches a nonzero builder fee code unless the user explicitly
  opts into fee attribution. Builder API keys are relayer auth, not fee codes.

## Credential Taxonomy

| Credential | Created by | Authenticates | Authority |
|---|---|---|---|
| CLOB API creds (`creds.json`) | Bloom via L1 wallet signature | CLOB trading/account requests | requests only; orders still need owner signature |
| Builder API key (`builder_creds.json`) | Bloom via CLOB L2 | Relayer submission HMAC | submission only; wallet batches still carry owner signature |
| Relayer API key | User at polymarket.com | Optional relayer submission override | manual fallback only |

A builder code is a separate fee-attribution `bytes32` order field. Do not call
all of these "API keys"; name the key type and authority.

Secrets live under the Bloom home dir or env, never in code/VCS. VFS surfaces
must redact `secret`, `passphrase`, auth headers, and signatures.

## Architecture

Polymarket uses three APIs on Polygon:

| API | Serves |
|---|---|
| Gamma | markets, events, search |
| Data | positions, trades, activity, open interest |
| CLOB | books/prices plus authed orders/cancels/balances |
| Relayer | gasless deposit-wallet deploy and wallet batches |

Orders are off-chain CLOB messages, not EVM transactions. They do not flow
through the `bloom-tx` outbox; Polymarket policy, geoblock, signing, receipts,
and audit live in the Polymarket command/handler path.

Deposit-wallet relayer operations also bypass the outbox. Funding transfers may
reuse the DeFi/wallet path when they are real EVM transfers.

The owner EOA signs:

1. CLOB L1 auth for API creds.
2. Relayer `Batch` EIP-712 for deposit-wallet calls.
3. CLOB orders with `signatureType = 3`, POLY_1271 / ERC-7739 wrapped.

## Onboarding State

Onboarding is idempotent and resumable from per-wallet account artifacts:

1. derive deterministic deposit-wallet address;
2. deploy or verify the wallet;
3. fund pUSD into the deposit wallet;
4. approve pUSD/conditional-token spend through relayer batch;
5. mint or load CLOB creds;
6. sync CLOB balance/allowance buying power.

Deploy must reach the relayer confirmed state before approvals. Approval state
is checked on-chain. Cred files are stored mode `0600`; VFS returns only
redacted status.

## Trading Flow

Read surfaces expose markets, books, prices, search, positions, activity,
portfolio, and open orders with short cache TTLs where appropriate.

Write flow is stage -> review -> confirm:

- create draft from JSON/NL intent;
- resolve market/token/book and build final order facts;
- run policy, geoblock, balance/allowance, and holdings preflights;
- render plan/draft;
- confirm revalidates, signs, posts to CLOB, writes receipt, and audits.

Sells preflight current holdings. Cancels do not require wallet unlock and are
never geoblocked.

## Safety Gates

- Geoblock check before any order; never document or build bypasses.
- `[polymarket]` policy enablement, caps, price limits, and allow/deny lists.
- Binary YES/NO markets only.
- Live CLOB balance/allowance before buys; holdings before sells.
- Fresh market/book revalidation immediately before signing/posting.
- Passkey foreground review for value-moving signatures unless a future scoped
  capability authorizes the exact action and the signer is already available.
- Audit records for onboarding submits, credential mints, confirms, cancels,
  withdraws, redeems, and approval revocation.

## Live Wire-Verification Runbook

Mocks and KATs prove deterministic bytes; one capped live run proves the live
CLOB/relayer accept them. Prefer Amoy if available; otherwise use a small
Polygon mainnet amount.

Prerequisites:

- geoblock returns `blocked:false`;
- owner EOA has gas and pUSD or swap-fundable balance;
- passkey wallets run in the foreground;
- wallet policy has small Polymarket caps;
- Polygon broadcast is enabled;
- choose a liquid binary market that can be entered and exited.

Steps:

1. `bloom polymarket onboard <w> [--target-pusd 3 --max-spend <native>]`
2. Optional VFS funding flow:
   `bloom vfs write /polymarket/fund/<w>/new --data '{"target_pusd":"3","max_spend":"0.1"}'`
   then `bloom vfs write /polymarket/fund/<w>/<id>/confirm --unlock-wallet <w> --data confirm`
3. `bloom polymarket order <w> <slug> yes <usd> --max-price <p> --dry-run`
4. `bloom vfs write /polymarket/trade/<w>/drafts/<draft-id>/confirm --unlock-wallet <w> --data confirm`
5. Exit with `sell` or `cancel` if it rested; `cancel` also works via VFS at
   `/polymarket/trade/<w>/orders/<order-id>/cancel` (direct, no unlock).
6. `redeem` only after Data API reports `redeemable:true`; also confirmable via
   `/polymarket/redeem/<w>/<slug>/confirm --unlock-wallet <w>`.
7. `withdraw-pusd <w> all`; also via
   `/polymarket/withdraw/<w>/pusd/confirm --unlock-wallet <w> --data '{"confirm":true,"amount":"all"}'`.
8. `revoke-approvals <w>` and confirm allowances are zero; also via
   `/polymarket/revoke-approvals/<w>/request/confirm --unlock-wallet <w> --data confirm`.

Capture relayer/CLOB requests and responses during the run, but canonicalize
before committing fixtures: remove auth headers, API keys, passphrases,
signatures, real owner/deposit addresses, order/tx ids, timestamps, and any
other secret or wallet-identifying data.

Exact-byte assertions belong only on deterministic test-key bodies. Live HTTP
capture fixtures should assert status and critical fields we parse, so wire
drift becomes a failing test without committing secrets.

Abort rules:

- Onboarding stops mid-way: re-run `onboard`; it resumes and waits at funding if
  pUSD is missing.
- Ambiguous order: do not retry blindly; inspect receipts/open orders, then
  cancel if needed.
- Leftover exposure: sell/cancel, withdraw pUSD, then revoke approvals.
