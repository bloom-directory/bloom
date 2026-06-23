# 2026-06-23 - Local Petal Plugins v1 Closeout

## Scope

This closeout covers branch `feat/local-petal-plugins` against
`docs/superpowers/specs/2026-06-22-local-petal-plugins-design.md`.

The shipped slice is off-chain only: local, content-addressed WASM petals with
embedded local manifests, default-deny host capabilities, private per-petal
storage, daemon-mediated HTTP/signing, VFS dispatch through `apps/<mount>`, CLI
and IPC install/list surfaces, SDK exports, example local petals, and the
Polymarket local petal.

No consensus, chain VM, staking, scoring, zk, or on-chain petal path was part of
this scope.

## Milestone Status

| Milestone | Status | Primary Evidence |
| --- | --- | --- |
| Manifest schema, embed, extract, validate | Complete | `bloom-petal-manifest` local schema, custom-section extraction, install validation, manifest tests |
| Runtime capabilities | Complete | `bloom-petals` local host imports for `vfs_*`, `http_fetch`, `sign_hash`, and `store_*`; daemon redirect revalidation; private store tests |
| Handler dispatch, router, CLI/IPC, consent | Complete | `PetalVm::dispatch`, `PetalRouter`, `apps/` mount, local install/list IPC, CLI install/list/read smoke |
| SDK | Complete | `bloom-petal-sdk`, `bloom-petal-sdk-macros`, `#[bloom_petal_sdk::petal]`, export contract smoke |
| Misc tool petals | Complete | `misc-tools` and `portfolio` compiled WASM router smokes |
| Polymarket port | Complete for v1 graduation | compiled Polymarket router smoke covers market/search/positions/account/onboarding/funding/buy/sell/reconcile/cancel/redaction paths |

## Review Findings

| Slice | What review caught | Resolution |
| --- | --- | --- |
| Runtime HTTP redirects | Cross-origin redirects could replay author headers or non-bodyless request bodies; malformed redirect targets lacked audit coverage | Fixed by manual bounded redirect handling, target revalidation, header/body stripping rules, and denial/error audit tests |
| Local app onboarding/status | CLI polling could exit on stale `last_error` or stale `fund` status after spawning async local onboarding | Fixed with pre-write status snapshots, post-write change gating, bounded polling, and persisted `status_updated_ms` |
| SDK entry macro | `#[petal]` did not resolve aliased SDK crates hygienically; compiled export contract was not asserted | Fixed with `proc-macro-crate` resolution and a real compiled-WASM export-table smoke |
| Polymarket relayer onboarding | Relayer error bodies could echo secret-like material; top-level onboarding failures could leave stale in-flight state | Fixed with response-body redaction, best-effort private failure persistence, and smoke coverage for echoed builder secrets |
| Readiness probes | Fund/approval previews were over-tightened by live readiness requirements; deployment proof could rely on stale address contract state | Fixed by separating persisted factory resolution from refreshed posting readiness and probing the deposit-wallet proxy implementation slot |
| Factory-resolved deposit wallet | Approval previews could trust inconsistent persisted `fundable: true` without a live factory source | Fixed by requiring `source: live_factory_resolved` for fundability and warning suppression |
| Sell posting | Chain method-read staged bodies could collide; post-time sell evidence could go stale; Data API holdings were too authoritative | Fixed with nonce-scoped method leaves, post-time sell preflight recomputation, and chain/CLOB balances as authoritative sell guards |
| Parity metadata | First smoke only checked read/write shape, not parsed graduation fields | Fixed with JSON assertions and write-denial coverage; final metadata now reports `ready_for_graduation` |
| Ambiguous POST reconciliation | Contradictory duplicate fields and whitespace/unparseable order ids could pass matching | Fixed by rejecting alias contradictions, whitespace order ids, and unparseable checked aliases |
| Cancel/GTC | Missing GTC coverage, unmatched GTC exposure handling, and partial local cancel idempotency gaps | Fixed with GTC posting/cancel smoke coverage, exposure-safe handling, and idempotent private receipt transitions |
| Buy posting | Raw response leakage, post-error leakage, ambiguous persistence, receipt-audit ordering, and stale review input risks | Fixed before push; final follow-up found no concrete findings |
| Public VFS redaction | Initial sweep missed draft files, pre-cancel receipts, `prices.json`, public hints, `search/*`, `trades.json`, and `activity.json` | Fixed by expanding the fixture-backed redaction sweep across representative public Polymarket paths and forbidden tokens |
| Final branch audit | Polymarket self-reported `draft_not_graduated`; review evidence was only in PR/subagent history | Fixed by marking the local Polymarket parity surface `ready_for_graduation` and adding this tracked closeout |

## Validation

Passed on the final branch audit:

- `cargo fmt --check`
- `git diff --check`
- `cargo test -p bloom-petal-manifest`
- `cargo test -p bloom-petal-sdk`
- `cargo test -p bloom-petals`
- `cargo test -p bloom-daemon`
- `cargo test -p bloom local_petal_install_prints_consent_and_serves_under_apps`
- `cargo test -p bloom-local-petal-misc-tools --test router_smoke`
- `cargo test -p bloom-local-petal-portfolio --test router_smoke`
- `cargo test -p bloom-local-petal-polymarket --lib`
- `cargo check -p bloom-local-petal-polymarket --target wasm32-wasip1`
- `cargo check -p bloom-local-petal-misc-tools --target wasm32-wasip1`
- `cargo check -p bloom-local-petal-portfolio --target wasm32-wasip1`
- `cargo test -p bloom-local-petal-polymarket --test router_smoke`
- `cargo check -p bloom`
- `cargo test -p bloom`
- `cargo test -p bloom-polymarket`
- `cargo check -p bloom-polymarket --target wasm32-wasip1 --no-default-features`

## Secret and On-Chain Audit

Public Polymarket VFS reads are swept for private CLOB credentials, builder
credentials, API keys/passphrases, raw echoed signatures, raw CLOB response-body
fields, and echoed signature payloads. Private credential and receipt details
remain in the per-petal private store.

The branch does not touch consensus, chain VM, on-chain petal execution, Move,
contracts, or staking/scoring code. The only chain-adjacent diff is off-chain
VFS helper plumbing in `crates/bloom-vfs/src/handlers/chains.rs` for
nonce-scoped staged method body leaves, used by local Polymarket read probes.

## Accepted Deviations

- The local VM linker still exposes the legacy unversioned `bloom` import module
  for existing local command petals. New local handler petals are validated to
  reject reserved `bloom` imports, and the SDK emits `bloom.v1` imports.
- V1 manifests strictly accept only `provides.kind = "vfs"`. Future `stream`
  and `rpc` provider kinds require parser/schema additions, but the manifest and
  dispatch shape reserve the extension point.
- Dynamic response `ttl_hint_ms` is parsed in the dispatch ABI, while the
  current VFS handler trait primarily exposes manifest endpoint cache hints.
  This keeps the response field ABI-stable for later trait support without
  changing v1 routing semantics.
- Install consent is printed by the CLI after successful local install parsing
  and before normal use of the installed app. There is not yet an interactive
  pre-install approval prompt.
- GTD order posting remains deferred because the native Polymarket handler also
  rejects GTD orders; this is not a native-parity blocker.
