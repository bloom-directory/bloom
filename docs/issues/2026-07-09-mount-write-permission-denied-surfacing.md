# Mount layer must reliably surface VFS `PermissionDenied` on writes

**Severity:** High · **Category:** Correctness / Agent UX
**GitHub:** bloom-directory/bloom#77
**Observed:** 2026-07-06, during a Hyperliquid mainnet validation run. The agent
mounted Bloom at `/Users/joshua/bloom`, read state through the mount, but
deliberately routed all *writes* through `target/debug/bloom vfs write ...`
instead of the mounted path — see
`~/.codex/sessions/2026/07/06/rollout-2026-07-06T16-54-28-019f3823-578a-7d92-9dae-eef9b9022474.jsonl`
lines 6083/6089/6091 ("`bloom vfs write` gives cleaner error handling and
avoids NFS write semantics").

---

## 1. Problem statement

`bloom-vfs` handlers correctly return `HandlerError::PermissionDenied` when a
write stages a Sealed Approval challenge instead of completing (e.g. a
Hyperliquid `usdSend`, or a wallet `policy.toml` update — see §3.3). The
mount adapter (`crates/bloom-mount/src/adapter.rs`) correctly *maps* that
error type: `map_err` (adapter.rs:187-198) turns
`HandlerError::PermissionDenied` into `FsError::PermissionDenied`. At the
type level, the plumbing is right.

The bug is about *when* that mapping runs, not what it produces. Because the
adapter buffers NFS `WRITE` chunks and, for the common write path, defers the
actual `vfs.write()` call until a later `COMMIT` (or a subsequent `read()`),
the `WRITE` RPC that the client's `write(2)` syscall is waiting on returns
**success** before the VFS has been asked anything. The real
`PermissionDenied` — and the side effect that produced it (a staged
challenge file) — only happens later, asynchronously, at a point the
original writing process usually isn't watching anymore.

Net effect: a shell command like

```
printf '%s' "$body" > /bloom/wallets/minnow/policy.toml
```

can exit `0` even though nothing was durably written and a Sealed Approval
challenge now needs a human ceremony. The only reliable way to observe the
denial today is to re-read a status/challenge file afterward and infer what
happened, or to bypass the mount and call `bloom vfs write` directly (a
single synchronous IPC round-trip — see §3.1). That's the workaround already
in production use, and it defeats the point of mounting Bloom as a
filesystem.

## 2. Desired semantics and protocol bound

1. Target: a mounted-filesystem write that results in VFS `PermissionDenied`
   should fail at the user-visible `write(2)`/`close(2)` operation with a clear
   permission error (`EACCES`), for the common case of a single write body
   delivered in one open/write/close cycle.
2. It must never look like success merely because a challenge file was
   staged as a side effect of the attempted write.
3. Ordinary writable paths (policy-free writes, `Entry::writable_file`
   targets that actually succeed) must keep working exactly as they do
   today — no regression in the happy path.
4. Protocol bound discovered during implementation: for `Unstable` NFS writes,
   Bloom cannot safely prove that an offset-0 contiguous prefix is the final
   file. The safe implementation therefore preserves data correctness and
   surfaces `PermissionDenied` on sync-stable `WRITE`, explicit `COMMIT`,
   NFS `CLOSE`, or read. The close path is the important fix for ordinary
   shell redirects and agent open/write/close flows.

## 2.1 Resolution implemented in PR #92

The fix adds a small `CloseSupport` extension to the `bloom-directory/embednfs`
fork and calls it from the NFS `CLOSE` operation before open-state teardown.
`BloomFs` implements that hook by routing close through the same whole-file
`flush_path` used by `COMMIT` and read repair. As a result, buffered
`Unstable` writes are still not flushed early based on unsafe EOF guesses, but
a normal mounted open/write/close sequence now returns `FsError::PermissionDenied`
from close when the VFS handler stages a challenge and denies the write.

## 3. Current behavior

### 3.1 The clean path: daemon IPC / `bloom vfs write`

`crates/bloom-daemon/src/ipc.rs:373-379`:

```rust
async fn do_write(&self, params: &Value) -> Result<(), HandlerError> {
    ...
    if write_path_uses_wallet_signer(&path) {
        return Err(HandlerError::PermissionDenied);
    }
    let bytes = parse_write_bytes(params)?;
    self.vfs.write(&path, &bytes).await
}
```

One call, one `Result`, returned synchronously as the JSON-RPC response.
`HandlerError::PermissionDenied` becomes JSON-RPC error `-32007` at
`ipc.rs:1387`. There is no buffering and no asynchronous second phase — this
is exactly why the agent's transcript calls it "cleaner error handling."

### 3.2 The mount path: buffered writes, deferred flush

`BloomFs::write` (`adapter.rs:1000-1103`) buffers each NFS `WRITE` chunk into
a per-path `WriteBuffer` (`adapter.rs:286-375`) keyed by `VfsPath`. The
buffer tracks filled byte ranges and is "complete" once they form a
contiguous `[0, len)` prefix. What happens to a complete buffer depends on
the **requested `WriteStability`**:

```rust
// adapter.rs:1058-1067 (pre-fix)
let needs_eager_flush = matches!(
    requested,
    WriteStability::DataSync | WriteStability::FileSync
) && buf.is_complete();
let payload = if needs_eager_flush {
    Some(map.remove(&path).expect("just observed").bytes)
} else {
    None
};
```

- **`DataSync` / `FileSync` requested, buffer complete** → `payload` is
  `Some`, and further down (`adapter.rs:1090-1094`) `self.vfs.write(&path,
  &payload).await.map_err(map_err)?` runs *inline inside the `WRITE` RPC
  handler*. If the handler returns `PermissionDenied`, it propagates
  correctly to the RPC's `FsResult`. **This case is already correct.**

- **`Unstable` requested, buffer complete** (the common case — see §4) →
  `payload` stays `None`. The handler goes to the `actual_stability =
  WriteStability::Unstable` branch and returns
  `Ok(WriteResult { written: len, stability: Unstable })`
  **without ever calling `self.vfs.write`.** The buffered bytes just sit in
  `write_buffers`. The client's `write(2)` has already "succeeded" and the
  permission decision hasn't been made yet.

The deferred `vfs.write()` for an `Unstable`-buffered file only happens on:

- **`COMMIT`** — `CommitSupport::commit` (`adapter.rs:1218-1237`) calls
  `flush_path`, which calls `self.vfs.write(...).map_err(map_err)?`
  (`adapter.rs:588-601`). This *does* return `FsError::PermissionDenied`
  correctly to the `COMMIT` RPC — but by the time `COMMIT` arrives, the
  writing process has typically already called `close(2)` and moved on.
  Whether that process (or the shell around it) ever observes a `COMMIT`
  failure depends entirely on the local NFS client's write-back semantics,
  which is largely outside Bloom's control and varies by platform (the
  validation run mounted on macOS at `/Users/joshua/bloom`; macOS's and
  Linux's NFS clients differ in how reliably `close(2)`/`fsync(2)` block on
  and propagate a deferred `COMMIT` result).
- **A subsequent `read()`** of the same path (`adapter.rs:961`, via
  `flush_path`) — only useful if the agent happens to re-read the file it
  just wrote.
- **Nothing else.** The doc comment on `BloomFs` (`adapter.rs:474-477`)
  claims a third trigger — an idle timer (`WRITE_IDLE_FLUSH`,
  `adapter.rs:68`) that flushes abandoned buffers — but grepping the crate
  shows `WRITE_IDLE_FLUSH` is only read inside `drop_stale_buffer`
  (`adapter.rs:606-617`), which *discards* a stale buffer on the next
  `read()`, and there is no `tokio::time` interval anywhere in
  `bloom-mount` that drives a background flush. **The idle-timer trigger
  described in the doc comment does not exist.** A write that is never
  `COMMIT`ted and never read back can sit buffered indefinitely, or be
  silently dropped (never reaching `vfs.write` at all) the next time
  something reads that path after `WRITE_IDLE_FLUSH` (5s) has elapsed.

### 3.3 The existing narrow workaround, and what it does *not* cover

`mount_write_path_uses_wallet_signer` (`adapter.rs:131-184`) already
special-cases a hardcoded list of paths (`wallets/*/sign/*`, outbox
`cancel`/`replace`, Hyperliquid `agent_sessions/*/new.json`,
`agent_sessions/*/*/orphan_cancel_all|orphan_close_all`, and
`exchange/*/order.json|cancel.json|schedule_cancel.json|update_leverage.json|send_asset.json`)
and denies them **unconditionally, before ever calling `vfs.write`**, in
`flush_path` (line 590), the eager-write branch of `write()` (line 1091),
and `create()` (line 1130). For exactly these paths, a mounted write is
already deterministic — always denied — so they don't exhibit the "looks
successful" symptom.

But the same function's own comment (`adapter.rs:176-181`) explicitly
carves out an exception:

```rust
// policy.toml and policy-session/new writes flow through to the VFS
// wallets handler, which stages a first-party Sealed Approval for passkey
// wallets (challenge + grant-gated install/mint) and writes local policy
// immediately. They no longer route through the disabled write_unlocked
// re-sign lane, so the mount must forward them to `vfs.write` rather than
// deny on flush.
```

And indeed, `crates/bloom-vfs/src/handlers/wallets.rs` has exactly the
"stage a side effect, then deny" shape this issue is about:

- `write_wallet_policy_update` (`wallets.rs:659`) stages a policy-change
  challenge and returns `Err(HandlerError::PermissionDenied)`
  (`wallets.rs:730`).
- The `policy-session/new` handler stages a session challenge and returns
  `Err(HandlerError::PermissionDenied)` (`wallets.rs:656`, `wallets.rs:981`).

Both are confirmed **not** in the mount's denylist
(`mount_classifier_forwards_handler_owned_sealed_approval_writes`,
`adapter.rs:1406-1432`, asserts `/wallets/minnow/policy.toml` and
`/wallets/minnow/policy-session/new` are *not* denied at the mount layer).
So a mounted write to `/wallets/<wallet>/policy.toml` that stages a
challenge is, **today, on `master`, fully exposed** to the buffering
ambiguity described in §3.2: if the kernel sends it as an `Unstable` write
(the common case), the `WRITE` RPC returns success and the real
`PermissionDenied` only surfaces on a later `COMMIT` — if it surfaces at
all.

The wallet-signer denylist is a targeted patch for a handful of paths the
mount author knew about in advance. It is not, and cannot be, a general
solution: every current or future VFS handler that independently decides to
stage-then-deny (Polymarket onboarding — see
`docs/issues/2026-07-08-polymarket-onboard-challenge-lifecycle.md` — future
petals, etc.) would need someone to remember to add its exact path shape to
`adapter.rs`, permanently duplicating business logic that belongs in the
handler, into the transport layer.

### 3.4 `create()` / zero-byte writes

`create()` (`adapter.rs:1105-1146`) issues an actual zero-byte
`self.vfs.write(&child, &[])` (line 1133) when a client does `open(O_CREAT)`
on a path that doesn't yet exist, and does correctly check
`mount_write_path_uses_wallet_signer` first. For *data-independent* denials
this works fine — the real error comes back at `create()` time.

For *data-dependent* stage-then-deny handlers (e.g. Hyperliquid's
`prepare_usd_send_pending_sealed`, which parses a JSON action body before
deciding whether to stage a challenge), the zero-byte payload sent by
`create()` is not representative of the real write that follows: it may
fail JSON parsing and return `HandlerError::Invalid` instead of
`PermissionDenied`, or (depending on the handler) simply succeed as a
harmless empty write. Either way, `create()`'s result does not reliably
predict what the real content `WRITE` will do. This is an inherent property
of a whole-file, content-dependent write API, not something the mount
adapter can fully paper over — the fix in §5 makes sure the *real* content
write (the one that actually matters) reliably surfaces its true result;
`create()`'s zero-byte pre-check should not be treated as authoritative by
callers or by future mount-layer changes.

## 4. NFS write lifecycle analysis

`write(2)` on the client maps to one or more NFS `WRITE` RPCs, each carrying
a requested `WriteStability` (`UNSTABLE`, `DATA_SYNC`, `FILE_SYNC`).
Buffered/cached writes are typically sent as `UNSTABLE`; the client later
sends `COMMIT` to make them durable, usually triggered by `close(2)` or
`fsync(2)` — but *when* and *whether* that `COMMIT`'s result round-trips
back to the original writer is a client/kernel implementation detail, not
something the NFS protocol guarantees is visible to the calling process.

Two facts bound how often Bloom actually sees a write split across multiple
`WRITE` RPCs:

- The mount is configured with `wsize=65536` on every platform
  (`crates/bloom-mount/src/lib.rs:197-209`, `build_mount_opts`).
- `MAX_WRITE_BUFFER_BYTES` is 8 MiB, sized, per its own doc comment
  (`adapter.rs:38-42`), to be "large enough for any plausible
  JSON/TOML/EIP-712 body" — but real Bloom write bodies (policy TOML,
  Hyperliquid order JSON, EIP-712 payloads) are almost always well under 64
  KiB.

So many real writes through this mount likely arrive as exactly one `WRITE`
RPC whose payload already forms a complete file. The catch is that the server
cannot safely prove that from the first offset-0 `WRITE`: the same prefix shape
can also be chunk 1 of a larger sequential write. §5 therefore fixes only the
cases where the boundary is knowable without guessing, and leaves purely
sequential `Unstable` streams COMMIT-driven.

## 5. Implementation plan

### 5.1 Primary fix: flush when the buffer boundary is knowable

The root cause is in `BloomFs::write` (`adapter.rs:1058-1061`): eager flush is
gated only on synchronous `requested` stability, so a common `Unstable`
single-RPC write can return success before the VFS handler has seen the body.
The initial one-line fix considered for this issue was "flush whenever
`buf.is_complete()`", but implementation showed that `is_complete()` only means
"the currently received ranges form a contiguous prefix", not "the client is
done writing this file". NFS `WRITE` does not carry a final-chunk marker.

```rust
// Before (adapter.rs:1058-1067):
let needs_eager_flush = matches!(
    requested,
    WriteStability::DataSync | WriteStability::FileSync
) && buf.is_complete();
let payload = if needs_eager_flush {
    Some(map.remove(&path).expect("just observed").bytes)
} else {
    None
};

// After:
let payload = if buf.should_flush_after_write(requested) {
    Some(map.remove(&path).expect("just observed").bytes)
} else {
    None
};
```

`should_flush_after_write` is intentionally narrower than `is_complete()`:

- `DataSync` / `FileSync` still flush as before when contiguous.
- `Unstable` writes never flush from `WRITE` alone. They wait for `COMMIT` or
  a later read, because neither a contiguous prefix nor a gap becoming
  contiguous proves final file size.

Everything downstream of the payload extraction (`adapter.rs:1070-1103`) is
still the right propagation path:

- The `DataSync`/`FileSync`-requested-but-incomplete rejection
  (`adapter.rs:1070-1078`, returns `FsError::Unsupported`) is unaffected —
  it only fires when `payload` is `None`, which still only happens for a
  genuinely incomplete buffer.
- `actual_stability` still becomes `requested` whenever `payload.is_some()`
  (line 1080-1088) — flushing eagerly always satisfies whatever durability
  the kernel asked for, since the data is now applied.
- The real `vfs.write` call and its `map_err(map_err)?` propagation
  (`adapter.rs:1090-1094`) is unchanged — it already turns
  `HandlerError::PermissionDenied` into `FsError::PermissionDenied` and
  returns it as the `WRITE` RPC's error for sync-stable writes, and as the
  `COMMIT`/read error for `Unstable` writes.

This makes `PermissionDenied` (and any other `HandlerError`) observable at
the `WRITE` RPC — and therefore at the client's `write(2)` — only for
sync-stable writes. It deliberately does not try to guess that any `Unstable`
prefix is final, because doing so can persist partial files for ordinary
multi-chunk writes.

Sequential `Unstable` chunk streams still flush on `COMMIT`, because the
protocol gives Bloom no way to tell chunk 1 of N from a complete file at the
time chunk 1 arrives. A future full solution for single-RPC `Unstable`
denials needs either a handler-level preflight/dry-run API or a mount/client
contract that provides the final file size before the first `WRITE` is
accepted.

### 5.2 Keep `mount_write_path_uses_wallet_signer` unchanged

Leave `adapter.rs:131-184` as-is. It becomes redundant-for-correctness once
§5.1 lands (those paths will now also correctly surface `PermissionDenied`
through the general path), but it still provides a real property worth
keeping: those specific signer-consuming paths are refused **before any
side effect occurs at all**, with no `WriteBuffer` bookkeeping and no
dependency on buffer completion. Treat it as defense-in-depth, not as the
mechanism this issue is fixing.

### 5.3 `create()` / zero-byte writes

No code change recommended beyond §5.1. Document (in the `create()` doc
comment) that a successful zero-byte `create()` is not a guarantee that a
subsequent content write to the same path will succeed, for handlers whose
write-time decision depends on the payload. This is a one-comment
documentation fix, not a behavior change.

### 5.4 Fix or remove the stale idle-timer doc claim

`adapter.rs:474-477` documents an idle-timer flush trigger that does not
exist (§3.2). After §5.1 lands, boundary-known completions can flush inline,
but sequential `Unstable` buffers still rely on COMMIT because the adapter
cannot infer final size. A genuinely incomplete buffer that a client abandons
mid-transfer (drops the missing prefix) already degrades gracefully via
`drop_stale_buffer` discarding it on the next unrelated `read()` of that
path, or leaking (bounded, since it's capped by `MAX_WRITE_BUFFER_BYTES`
per path and paths are finite) until the mount is torn down. Recommend
updating the doc comment to describe reality accurately (drop-on-stale-read
as the only cleanup path today) rather than implementing an actual
background timer — out of scope for this fix; file as a follow-up if the
memory-pinning risk is judged to matter in practice.

## 6. Testing plan

All new tests below live in `crates/bloom-mount/src/adapter.rs`'s existing
`#[cfg(test)] mod tests` (`adapter.rs:1240+`), following the file's
established pattern (`RecordingHandler`, `fake_ctx()`,
`Vfs::builder().mount(...)`).

### 6.1 New test handler: stage-then-deny

Add a handler that models the real "stage a side effect, then deny" shape
used by `wallets::write_wallet_policy_update` and
`hyperliquid::prepare_usd_send_pending_sealed` (§3.3), so the test proves
both halves: the side effect happens, *and* the filesystem-level result is
still `PermissionDenied`.

```rust
/// Models a handler that stages a side effect (e.g. writing an
/// `approval_challenge.json`) before unconditionally denying the write —
/// the same shape as `wallets::write_wallet_policy_update` and
/// `hyperliquid::prepare_usd_send_pending_sealed`.
#[derive(Default)]
struct ChallengeStagingHandler {
    staged: parking_lot::Mutex<Vec<Vec<u8>>>,
}

impl ChallengeStagingHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn staged_count(&self) -> usize {
        self.staged.lock().len()
    }
}

#[async_trait]
impl Handler for ChallengeStagingHandler {
    async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
        if p.is_root() {
            return Ok(Entry::dir(""));
        }
        match p.first() {
            Some("challenge") => Ok(Entry::writable_file("challenge")),
            _ => Err(HandlerError::NotFound(p.to_string_path())),
        }
    }
    async fn write(&self, p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match p.first() {
            Some("challenge") => {
                self.staged.lock().push(data.to_vec());
                Err(HandlerError::PermissionDenied)
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }
    async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if p.is_root() {
            Ok(vec![Entry::writable_file("challenge")])
        } else {
            Err(HandlerError::NotADir(p.to_string_path()))
        }
    }
}
```

### 6.2 Core regression test — sync-stable write denial

```rust
/// A sync-stable write that stages a side effect and denies must fail the WRITE
/// RPC itself, not silently buffer and succeed.
#[tokio::test]
async fn file_sync_write_surfaces_permission_denied_immediately() {
    let handler = ChallengeStagingHandler::new();
    let vfs = Vfs::builder().mount("stage", handler.clone()).build();
    let fs = BloomFs::new(vfs);
    let ctx = fake_ctx();
    let dir = fs.lookup(&ctx, &BloomHandle::Root, "stage").await.unwrap();
    let challenge = fs.lookup(&ctx, &dir, "challenge").await.unwrap();

    let err = fs
        .write(
            &ctx,
            &challenge,
            0,
            Bytes::from_static(b"{\"action\":\"usdSend\"}"),
            WriteStability::FileSync,
        )
        .await
        .unwrap_err();

    assert_eq!(err, FsError::PermissionDenied);
    assert_eq!(
        handler.staged_count(),
        1,
        "the side effect (challenge staging) must still have happened"
    );
}
```

### 6.3 Multi-chunk `Unstable` write — denial surfaces on `COMMIT`

Per the correction in §5.1, no `Unstable` `WRITE` carries enough information to
prove final file size. Multi-chunk `Unstable` writes remain COMMIT-driven.

```rust
#[tokio::test]
async fn multi_chunk_unstable_write_denies_on_commit() {
    let handler = ChallengeStagingHandler::new();
    let vfs = Vfs::builder().mount("stage", handler.clone()).build();
    let fs = BloomFs::new(vfs);
    let ctx = fake_ctx();
    let dir = fs.lookup(&ctx, &BloomHandle::Root, "stage").await.unwrap();
    let challenge = fs.lookup(&ctx, &dir, "challenge").await.unwrap();

    // First chunk: tail first, buffer incomplete, must still succeed at the RPC level.
    let r = fs
        .write(&ctx, &challenge, 5, Bytes::from_static(b"1}"), WriteStability::Unstable)
        .await
        .unwrap();
    assert_eq!(r.stability, WriteStability::Unstable);
    assert_eq!(handler.staged_count(), 0);

    // Second chunk makes the current buffer contiguous, but this still is not
    // an EOF/final-size signal.
    let r = fs
        .write(&ctx, &challenge, 0, Bytes::from_static(b"{\"a\":"), WriteStability::Unstable)
        .await
        .unwrap();
    assert_eq!(r.stability, WriteStability::Unstable);
    assert_eq!(handler.staged_count(), 0);

    let cs = fs.commit_support().expect("commit support enabled");
    let err = cs.commit(&ctx, &challenge, 0, 7).await.unwrap_err();
    assert_eq!(err, FsError::PermissionDenied);
    assert_eq!(handler.staged_count(), 1);
}
```

### 6.4 Existing tests that must be updated

Out-of-order and sequential chunk tests must continue to flush on `COMMIT`;
otherwise the adapter would persist a partial file as soon as it sees a
contiguous prefix that later grows.

The fix changes *when* a buffered write flushes, which two existing tests
assert on directly:

- `buffered_chunks_flush_on_commit` (`adapter.rs:1485-1529`) keeps asserting
  `recorder.write_count() == 0` immediately after sequential `Unstable`
  chunks land. Its comment should explain that a contiguous prefix is not a
  final-file signal.
- `buffered_chunks_tolerate_out_of_order` (`adapter.rs:1534-1568`) keeps
  asserting `recorder.write_count() == 0` before `COMMIT`; even an
  out-of-order contiguous prefix is not a final-file signal.
- Add `sequential_non_4k_chunks_wait_for_commit` so the adapter does not
  regress into treating only 4 KiB sequential chunks as ambiguous.
- Add `out_of_order_prefix_completion_waits_for_commit_until_tail_arrives` so
  the adapter does not regress into flushing an out-of-order prefix before a
  later tail arrives.

These tests' *coalescing* guarantee (many `WRITE` RPCs → exactly one
`vfs.write` call with the correctly reassembled payload) still holds and
should remain the primary assertion.

### 6.5 Non-regression: eager `FileSync`/`DataSync` path unaffected

`file_sync_write_flushes_eagerly` and `data_sync_write_flushes_eagerly`
(`adapter.rs:1579-1632`) exercise the branch this fix touches; run them
unmodified as regression coverage that single-chunk sync writes still flush
and still echo back the requested stability.

### 6.6 Non-regression: incomplete + sync-requested still rejected

`incomplete_sync_write_is_rejected_instead_of_downgraded`
(`adapter.rs:1634-1656`) and `oversize_write_rejects_fbig`
(`adapter.rs:1661-1679`) don't depend on the stability gate this fix
removes and should pass unmodified — include them in the PR's test run as
explicit non-regression evidence.

### 6.7 Manual / integration test for real `printf ... > mounted_path`

`cargo test` can't exercise a real kernel NFS mount without root (Linux) or
admin (macOS) — see the existing caveat in
`crates/bloom-mount/src/server.rs:319-330`. Add a `#[ignore]`-gated
integration test (new file, e.g.
`crates/bloom-mount/tests/write_permission_denied.rs`) that:

1. Builds a `Vfs` with a `ChallengeStagingHandler`-equivalent mount.
2. Calls `serve_nfs` against a real temp directory.
3. Shells out to `sh -c "printf '%s' '$body' > $mount/stage/challenge"`.
4. Asserts the shell command exits non-zero and/or its captured stderr
   mentions permission denial.
5. Unmounts via the returned handle.

Document this as a manual QA recipe in the PR description too (exact
`printf`/mount path), since CI may not run the `#[ignore]`d test by
default.

### 6.8 Hyperliquid-path coverage

Don't attempt real Hyperliquid/mainnet calls from this test suite. The
`ChallengeStagingHandler` tests in §6.2/§6.3 model the stage-side-effect then
`PermissionDenied` shape at the mount-adapter level. If deeper
Hyperliquid-specific coverage is wanted, it belongs in
`crates/bloom-vfs/src/handlers/hyperliquid.rs`'s own test module against its
existing mocked client, not here.

## 7. Risks

- **Single-RPC `Unstable` denial remains protocol-limited.** Without an EOF
  marker or expected final size, the adapter cannot safely distinguish a
  complete small file from the first chunk of a larger sequential write. The
  safe fix preserves write correctness and only surfaces `PermissionDenied`
  during `WRITE` for sync-stable requests.
- **Double-apply on client retransmission.** If an NFS client resends an
  already-acknowledged `WRITE` (rare, but possible on lossy transports),
  the buffer for that path was already removed on first completion, so the
  retransmit starts a fresh buffer and could call `vfs.write` a second time
  with the same bytes. This is a pre-existing risk today for the
  `FileSync`/`DataSync` eager path (unchanged by this fix) and is bounded
  by handler idempotency, not something this change introduces net-new.
- **`create()` zero-byte pre-check remains non-authoritative** for
  data-dependent handlers (§3.4/§5.3) — documented, not eliminated. Callers
  that need a true pre-flight permission check should keep using
  `bloom vfs write` with the real payload, or a dedicated dry-run surface if
  one is added later (out of scope here).
- **Idle-timer doc/behavior mismatch** (§5.4) is flagged but intentionally
  left as a documentation fix + optional follow-up, not bundled into this
  fix, to keep the change minimal and reviewable.

## 8. Acceptance criteria

1. `crates/bloom-mount/src/adapter.rs`: the eager-flush condition in
   `BloomFs::write` uses `should_flush_after_write`, which flushes sync-stable
   writes without guessing that any `Unstable` prefix is final.
2. New tests in §6.2 and §6.3 pass, proving a sync-stable denial and an
   `Unstable` COMMIT denial both surface `FsError::PermissionDenied` at the
   correct protocol boundary, while the handler's staged side effect is still
   recorded exactly once.
3. Existing tests updated per §6.4 pass with corrected assertions; §6.5 and
   §6.6 pass unmodified.
4. `mount_classifier_forwards_handler_owned_sealed_approval_writes`
   (`adapter.rs:1406-1432`) continues to pass unmodified — the wallet-signer
   denylist is untouched.
5. Manual recipe (§6.7): the ignored real-mount test documents the desired
   shell redirect shape, but it may self-skip on platforms where the kernel
   mount blocks or the caller lacks mount privileges.
6. No change to behavior for ordinary successful writes to writable paths
   (`getattr_writable_file_is_0644`,
   `mount_write_rejects_signer_consuming_paths`,
   `mount_create_rejects_signer_consuming_paths` all continue to pass
   unmodified).

## 9. Out of scope

- Implementing a real background idle-flush timer (§5.4) — file separately
  if warranted.
- A generic pre-flight/dry-run write-permission-check API for handlers.
- Changing `mount_write_path_uses_wallet_signer`'s path list.
- Any change to `crates/bloom-daemon/src/ipc.rs` (§3.1 already works
  correctly and needs no change).
