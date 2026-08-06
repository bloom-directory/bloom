# Wallet Projection Refresh Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move wallet projection boot refresh into the long-lived serve lifecycle and make `/next.md` refresh projections explicitly without sacrificing degraded operation.

**Architecture:** Daemon construction remains side-effect free with respect to Broker projection refresh. `spawn_background_tasks` launches the existing audited best-effort refresh, while the VFS root dynamic rendering API becomes asynchronous so `/next.md` can use the live-first, stale-cache-fallback projection reader directly.

**Tech Stack:** Rust, Tokio, async-trait, Cargo tests

---

### Task 1: Pin the lifecycle behavior

**Files:**
- Modify: `crates/bloom-daemon/src/lib.rs`

- [ ] Add a failing structural regression proving `from_home_inner` does not launch `spawn_wallet_projection_refresh`.
- [ ] Add a failing asynchronous regression proving `spawn_background_tasks` launches the projection refresh.
- [ ] Run the focused daemon tests and confirm the expected failures.
- [ ] Move the refresh launch from `from_home_inner` to `spawn_background_tasks`.
- [ ] Run the focused tests and confirm they pass.

### Task 2: Make `/next.md` projection handling explicit

**Files:**
- Modify: `crates/bloom-vfs/src/router.rs`
- Modify: `crates/bloom-daemon/src/lib.rs`

- [ ] Add a failing test proving `/next.md` calls `list_wallets` before rendering.
- [ ] Change root dynamic renderers to return an asynchronous future and await it from `Vfs::read`.
- [ ] Change `/next.md` to render from `list_wallets().await`, retaining its stale and unavailable output.
- [ ] Run the focused test and confirm it passes.

### Task 3: Regression verification

**Files:**
- Verify: `crates/bloom-vfs/src/router.rs`
- Verify: `crates/bloom-daemon/src/lib.rs`

- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo test -p bloom-vfs`.
- [ ] Run `cargo test -p bloom-daemon`.
- [ ] Run `git diff --check` and inspect the final diff and status.
- [ ] Leave all implementation changes uncommitted.
