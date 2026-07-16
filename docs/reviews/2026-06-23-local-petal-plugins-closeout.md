# 2026-06-23 - Local Petal Plugins Closeout

## Scope

This closeout covers branch `feat/local-petal-plugins` against
`docs/superpowers/specs/2026-06-22-local-petal-plugins-design.md`.

The surviving post-merge slice is off-chain only: local, content-addressed Petal
packages with `petal.toml`, default-deny host capabilities, private per-petal
storage, daemon-mediated HTTP, VFS dispatch through `petals/<mount>`, and CLI/IPC
install/list surfaces. Signing imports are intentionally disabled in the daemon
until they are wired through Sealed Approval grants.

No consensus, chain VM, staking, scoring, zk, or on-chain petal path was part of
this scope.

## Milestone Status

| Milestone | Status | Primary Evidence |
| --- | --- | --- |
| Package schema and validation | Complete | `bloom-petals` `petal.toml` package validation, deterministic `.petal.tar`, route-index, and package install tests |
| Runtime capabilities | Complete | `bloom-petals` local host imports for VFS, HTTP, and private store; daemon redirect revalidation; signing fail-closed until Sealed Approval wiring exists |
| Handler dispatch, router, CLI/IPC, consent | Complete | `PetalVm::dispatch`, `PetalRouter`, `petals/` mount, local install/list IPC, CLI install/list/read smoke |
| GitHub source install | Complete | Trusted `bloom-directory/*` source clone/build/install path with remote-source parity coverage |
| Polymarket app path | Complete for this branch | Polymarket route package/source install and onboarding status routing through `/petals/polymarket/...` |

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
- `cargo test -p bloom-petals`
- `cargo test -p bloom-daemon`
- `cargo test -p bloom --test cli v2_app_cli_build_install_list_and_vfs_read_happy_path`
- `cargo test -p bloom --test cli petals_install_rejects_untrusted_owner_and_raw_remote_wasm`
- `cargo check -p bloom`
- `cargo test -p bloom`
- `cargo test -p bloom-polymarket`

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
