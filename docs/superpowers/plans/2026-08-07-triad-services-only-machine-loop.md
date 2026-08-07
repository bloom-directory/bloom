# Triad Services-Only Machine Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a foreground `--services-only` launcher mode that keeps Session Sentinel, Signer, and Broker alive while a developer rebuilds and restarts Machine independently.

**Architecture:** Extend the existing triad launcher rather than introducing a second orchestration path. The launcher will share enrollment, config, Petal, environment-file, and service startup logic with full mode, then branch after Machine preparation: services-only mode publishes service readiness and supervises its owned children; full mode continues to start and probe Machine exactly as before.

**Tech Stack:** Bash 3.2-compatible shell, Rust integration contract tests, Markdown documentation, Cargo test/build tooling.

---

### Task 1: Lock the services-only launcher contract with failing tests

**Files:**
- Modify: `crates/bloom-it/tests/triad_release.rs`
- Test: `crates/bloom-it/tests/triad_release.rs`

- [ ] **Step 1: Write failing contract tests**

Add tests beside the existing `triad_developer_launcher_*` tests which load
`scripts/triad-dev-launch.sh` and assert these exact contracts:

```rust
#[test]
fn triad_developer_launcher_can_leave_machine_developer_managed() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(launcher.contains("--services-only) services_only=1; shift ;;"));
    assert!(launcher.contains("--services-only cannot be combined with --mount"));
    assert!(launcher.contains("if [ \"$services_only\" -eq 1 ]; then"));
    assert!(launcher.contains("Bloom triad services are ready; Machine is developer-managed."));
    assert!(launcher.contains("supervise_services"));
}

#[test]
fn triad_developer_launcher_exports_debug_machine_on_path() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(launcher.contains("bloom_bin_dir=\"$(cd \"$(dirname \"$bloom_bin\")\" && pwd -P)\""));
    assert!(launcher.contains("printf 'export PATH=%q:\"$PATH\"\\n' \"$bloom_bin_dir\""));
}

#[test]
fn triad_developer_launcher_owns_only_its_service_processes() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(launcher.contains("trap cleanup EXIT INT TERM HUP"));
    assert!(launcher.contains("for pid in \"$machine_pid\" \"$broker_pid\" \"$signer_pid\" \"$session_pid\""));
    assert!(launcher.contains("rm -f -- \"$ready_file\""));
    assert!(launcher.contains("die \"$label exited while supervising triad services\""));
}
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
cargo test -p bloom-it --test triad_release triad_developer_launcher_
```

Expected: the existing launcher tests pass and the new tests fail because
`--services-only`, `PATH` export, `HUP`, ready-file cleanup, and service
supervision are absent.

- [ ] **Step 3: Commit only after the implementation turns the tests green**

The tests and implementation belong in one behavior commit so the branch never
contains a commit whose test suite intentionally fails.

### Task 2: Implement services-only parsing, environment, and lifecycle

**Files:**
- Modify: `scripts/triad-dev-launch.sh`
- Test: `crates/bloom-it/tests/triad_release.rs`

- [ ] **Step 1: Parse and validate the mode before side effects**

Initialize and parse the flag:

```bash
services_only=0

case "$1" in
  --services-only) services_only=1; shift ;;
esac
```

After argument parsing and required-path validation, reject a requested mount:

```bash
if [ "$services_only" -eq 1 ] && [ -n "$mount_dir" ]; then
  die "--services-only cannot be combined with --mount"
fi
```

Reject an existing ready-file path before installing cleanup traps, just as the
launcher rejects an existing Machine socket:

```bash
if [ -e "$ready_file" ] || [ -L "$ready_file" ]; then
  die "ready file path already exists: $ready_file"
fi
```

- [ ] **Step 2: Export the selected debug build on PATH**

After validating the selected binaries, canonicalize the Machine binary's
directory and binary path:

```bash
bloom_bin_dir="$(cd "$(dirname "$bloom_bin")" && pwd -P)"
bloom_bin="${bloom_bin_dir}/$(basename "$bloom_bin")"
```

Add this line to the generated `triad.env`, preserving the sourcing terminal's
current `PATH`:

```bash
printf 'export PATH=%q:"$PATH"\n' "$bloom_bin_dir"
```

- [ ] **Step 3: Make cleanup cover terminal closure and readiness state**

At the start of `cleanup`, remove the exact caller-supplied ready file:

```bash
rm -f -- "$ready_file"
```

Install the cleanup handler for terminal hangup as well:

```bash
trap cleanup EXIT INT TERM HUP
```

When disabling traps inside cleanup, include `HUP`:

```bash
trap - EXIT INT TERM HUP
```

- [ ] **Step 4: Add portable foreground service supervision**

Add a Bash 3.2-compatible supervisor after the existing readiness helpers:

```bash
supervise_services() {
  while :; do
    for label in session signer broker; do
      case "$label" in
        session) pid="$session_pid" ;;
        signer) pid="$signer_pid" ;;
        broker) pid="$broker_pid" ;;
      esac
      if ! kill -0 "$pid" 2>/dev/null; then
        tail -n 80 "${log_dir}/${label}.log" >&2 || true
        die "$label exited while supervising triad services"
      fi
    done
    sleep 0.25
  done
}
```

- [ ] **Step 5: Branch after shared Machine preparation**

After config normalization and Petal installation, but before constructing
`machine_args`, add:

```bash
if [ "$services_only" -eq 1 ]; then
  printf 'ready\n' > "$ready_file"
  printf '%s\n' \
    'Bloom triad services are ready; Machine is developer-managed.' \
    "  source ${env_file}" \
    "  cd ${repo_root}" \
    '  cargo build -p bloom --no-default-features --features mount,triad-dev-harness' \
    '  bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"'
  supervise_services
fi
```

Because `supervise_services` does not return normally, the existing Machine
startup/probe/mount path is unreachable in services-only mode and unchanged in
full mode.

- [ ] **Step 6: Run focused tests and syntax validation**

Run:

```bash
bash -n scripts/triad-dev-launch.sh
cargo test -p bloom-it --test triad_release triad_developer_launcher_
```

Expected: shell syntax succeeds and all launcher contract tests pass.

- [ ] **Step 7: Commit the behavior**

```bash
git add scripts/triad-dev-launch.sh crates/bloom-it/tests/triad_release.rs
git commit -m "feat(dev): run triad services without Machine"
```

### Task 3: Document the two-terminal Machine loop

**Files:**
- Modify: `docs/local-mainnet-integration.md`

- [ ] **Step 1: Add services-only launch instructions**

Add a focused subsection after the existing VFS-only launch instructions with
this workflow:

```bash
scripts/triad-dev-launch.sh \
  --services-only \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

Then document the second terminal:

```bash
source /tmp/bloom-triad-logs/triad.env
cargo build -p bloom --no-default-features --features mount,triad-dev-harness && \
  bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"
```

State explicitly that `triad.env` prepends the selected debug binary directory
to `PATH`, the launcher remains in the foreground, `Ctrl-C` tears down only the
owned services, and Machine must be stopped in its own terminal.

- [ ] **Step 2: Check the documentation diff**

Run:

```bash
git diff --check -- docs/local-mainnet-integration.md
```

Expected: no whitespace errors.

- [ ] **Step 3: Commit the documentation**

```bash
git add docs/local-mainnet-integration.md
git commit -m "docs: explain split triad development loop"
```

### Task 4: Verify the complete branch and update the pull request

**Files:**
- Verify: `scripts/triad-dev-launch.sh`
- Verify: `crates/bloom-it/tests/triad_release.rs`
- Verify: `docs/local-mainnet-integration.md`
- Verify: all files changed relative to `origin/triad-architecture`

- [ ] **Step 1: Run formatting, syntax, focused tests, and the feature build**

Run:

```bash
cargo fmt --check
bash -n scripts/triad-dev-launch.sh
cargo test -p bloom-it --test triad_release triad_developer_launcher_
cargo build -p bloom --no-default-features --features mount,triad-dev-harness
```

Expected: every command succeeds.

- [ ] **Step 2: Run regression suites for the affected triad integration**

Run:

```bash
cargo test -p bloom-it --test triad_release
```

Expected: all `triad_release` tests pass.

- [ ] **Step 3: Verify repository state**

Run:

```bash
git diff --check origin/triad-architecture...HEAD
git status -sb
```

Expected: no tracked changes remain and only the pre-existing untracked
`.DS_Store` and `dist/` entries are present.

- [ ] **Step 4: Push the branch**

```bash
git push origin agent/macos-vfs-dev-fixes
```

Expected: the remote branch advances to the local head.

- [ ] **Step 5: Read and update the PR body using `gh`**

Run:

```bash
gh pr view 149 --repo bloom-directory/bloom --json body,url,baseRefName,headRefName
gh pr edit 149 --repo bloom-directory/bloom --body-file /tmp/bloom-pr-149-body.md
```

Preserve the existing summary and testing information, add the services-only
development workflow, and mark only checklist items supported by completed
local evidence. Do not mark external review, CI, or deployment items complete
unless GitHub or the performed verification proves them.

- [ ] **Step 6: Confirm the PR head and mergeability**

Run:

```bash
gh pr view 149 --repo bloom-directory/bloom \
  --json url,state,mergeable,mergeStateStatus,headRefOid,body,statusCheckRollup
```

Expected: the PR points to the pushed commit and GitHub reports no merge
conflict after recalculation.
