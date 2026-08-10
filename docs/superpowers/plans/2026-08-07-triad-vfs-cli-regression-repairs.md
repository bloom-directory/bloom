# Triad VFS and CLI Regression Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the approved VFS metadata, wallet sink, daemon-only CLI, and phantom lookup regressions without changing ceremony or approval protocols.

**Architecture:** Keep VFS behavior in `WalletsHandler`, route runtime CLI work through the existing daemon IPC endpoint, and extend IPC only with typed, narrow operations required by current CLI commands. Preserve documented workflows and remove one-shot fallbacks rather than introducing replacement local execution paths.

**Tech Stack:** Rust 2024, Tokio Unix sockets, JSON-RPC 2.0, Clap, serde, cargo test.

---

### Task 1: Advertise `new.tx` as writable

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/wallets.rs`

- [ ] Add a test that lists a wallet chain outbox and asserts `new.tx` has mode `0o644`.
- [ ] Run the focused test and observe the current `0o444` failure.
- [ ] Change `outbox_dir_entries()` to construct a writable file entry.
- [ ] Run the focused wallet handler tests and verify they pass.
- [ ] Commit only this fix and its test as `fix(vfs): advertise wallet outbox sink as writable`.

### Task 2: Route Petal CLI operations through daemon IPC

**Files:**
- Modify: `crates/bloom/src/main.rs`
- Modify: `crates/bloom-daemon/src/ipc.rs`
- Modify: `crates/bloom/tests/cli.rs`
- Modify additional focused Petal IPC files only if required by the existing typed API.

- [ ] Add tests proving `petals ls`, install, uninstall, and build work while `serve` owns the home lock and fail against an explicit missing endpoint.
- [ ] Run the focused CLI tests and observe lock acquisition or endpoint-bypass failures.
- [ ] Reuse existing `petals.*` IPC methods and add the narrow build RPC required to eliminate local execution.
- [ ] Remove Petal command home-lock acquisition and in-process daemon construction from client dispatch.
- [ ] Verify focused daemon IPC and CLI Petal tests.
- [ ] Commit only this change as `fix(cli): proxy petal commands through daemon IPC`.

### Task 3: Restore the plain-name wallet registration sink

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/wallets.rs`
- Modify: registration examples in `crates/bloom-vfs/src/docs/`, `QUICKSTART.md`, `EXAMPLES.md`, and `docs/examples-domain/03-wallets-simulate-watch.md` only where necessary to describe the existing registration projection honestly.

- [ ] Replace the JSON-body registration test with a plain-name test and add rejection coverage for empty, unsafe, and JSON bodies.
- [ ] Run the focused test and observe the JSON-deserialization failure.
- [ ] Parse a trimmed UTF-8 wallet name and feed it into the unchanged Broker custody preparation path.
- [ ] Make the readable `wallets/new` help advertise the plain-name body.
- [ ] Align examples with the petname-keyed registration directories and status fields supplied by the updated base branch without changing the Broker operation process.
- [ ] Run wallet registration and embedded-documentation tests.
- [ ] Commit only this change as `fix(vfs): restore plain-name wallet registration sink`.

### Task 4: Make the CLI a strict daemon proxy

**Files:**
- Modify: `crates/bloom/src/main.rs`
- Modify: `crates/bloom-daemon/src/ipc.rs`
- Modify: `crates/bloom-daemon/src/lib.rs` where a running-daemon service seam is required.
- Modify: `crates/bloom/tests/cli.rs`
- Modify: `docs/architecture/Interaction Modes.md`

- [ ] Add source and integration tests proving every command family except `init` and `serve` contacts the configured IPC endpoint, rejects a missing explicit endpoint, and never acquires the home lock or constructs a fallback daemon.
- [ ] Add output tests for request creation and wallet staging over IPC.
- [ ] Run the focused tests and observe current direct-local/direct-Broker successes and missing output.
- [ ] Route VFS, request, wallet, audit, status, ceremony, operation, update, Petal, and remaining runtime commands through typed daemon IPC; remove fallback branches.
- [ ] Remove or daemonize static one-shot commands so `init` and `serve` are the only commands that execute without a running daemon.
- [ ] Preserve client-side presentation and explicit output-file writes only after authoritative daemon responses.
- [ ] Document the daemon-only CLI rule and failure behavior in Interaction Modes.
- [ ] Run CLI and daemon IPC suites.
- [ ] Commit only this change as `refactor(cli): require daemon IPC for all commands`.

### Task 5: Reject phantom outbox artifacts

**Files:**
- Modify: `crates/bloom-vfs/src/handlers/wallets.rs`

- [ ] Add a test showing lookup succeeds for real artifacts and virtual pending controls but returns `NotFound` for an absent filename.
- [ ] Run the focused test and observe the phantom lookup success.
- [ ] Validate artifact existence in `lookup_outbox` while retaining the four virtual pending controls.
- [ ] Run focused wallet handler tests.
- [ ] Commit only this change as `fix(vfs): reject phantom wallet outbox artifacts`.

### Final verification

- [ ] Run formatting and workspace tests.
- [ ] Confirm the only accepted baseline failure is `tests::exact_petal_approval_is_owner_only_and_retries_the_frozen_payload_after_activation` with `PROVENANCE_MISMATCH`.
- [ ] Review the complete branch against this plan and the approved exclusions.
