# C2 — serve-socket cannot reach the passkey ceremony

**Severity:** High · **Category:** Functional / Design
**Observed:** 2026-07-04, during a real mainnet USDC bridge + Polymarket fund
run through a passkey-gated wallet on the sealed-approval demo branch.

---

## What happened

When `bloom serve` (the long-running daemon) is running, a passkey-wallet
broadcast cannot be completed through its Unix-domain JSON-RPC socket. Two
distinct failure modes were observed:

1. **Plain VFS write to `…/pending/<id>/confirm`** → JSON-RPC error
   `-32007 "permission denied"`. No approval challenge is surfaced to the
   caller, and no ceremony is offered.

2. **`bloom wallet confirm <wallet> <chain> <id>`** (which routes through the
   socket when serve is up) → JSON-RPC error
   `-32008 "unsupported: write_unlocked is disabled for passkey wallets; stage
   a Sealed Approval action and sign through PetalHost::sign_hash"`.

The passkey ceremony (the browser-based WebAuthn flow that decrypts the wallet
key and mints a Sealed Approval grant) is **only reachable via the in-process
foreground CLI with `bloom serve` stopped**. Stopping serve and re-running
`bloom wallet confirm` succeeds: it runs the ceremony, obtains the grant,
broadcasts, and returns the tx hash.

## Sequence to hit it

```
# 1. serve is running
bloom serve &

# 2a. plain VFS confirm write → fails
bloom vfs write /wallets/<wallet>/chains/<chain>/outbox/pending/<id>/confirm --data y
# → -32007 permission denied

# 2b. wallet confirm (routes through socket) → fails
bloom wallet confirm <wallet> <chain> <id> --text y
# → -32008 write_unlocked is disabled for passkey wallets

# 3. stop serve, retry in foreground → succeeds
# (kill serve)
bloom wallet confirm <wallet> <chain> <id> --text y
# → browser ceremony → broadcast → tx hash
```

## Evidence

### The `-32008` gate: `write_unlocked` hard-rejected for passkey

`crates/bloom-daemon/src/ipc.rs:135-145`:

```rust
const PASSKEY_WRITE_UNLOCKED_DISABLED: &str = "write_unlocked is disabled for passkey wallets; \
stage a Sealed Approval action and sign through PetalHost::sign_hash";

fn reject_passkey_write_unlocked(kind: WalletKind) -> Result<(), HandlerError> {
    if kind == WalletKind::PasskeyGated {
        return Err(HandlerError::Unsupported(
            PASSKEY_WRITE_UNLOCKED_DISABLED.into(),
        ));
    }
    Ok(())
}
```

Invoked inside `do_write_unlocked` at `ipc.rs:397-400`:

```rust
match info.kind {
    WalletKind::PasskeyGated => {
        reject_passkey_write_unlocked(info.kind)?;
    }
    _ => { keystore.unlock(wallet, passphrase.unwrap_or(""))... }
```

`HandlerError::Unsupported` → `-32008` at `ipc.rs:1447`:

```rust
HandlerError::Unsupported(s) => (-32008, format!("unsupported: {s}")),
```

The CLI routes `wallet confirm` through the socket first (`main.rs:2029-2044`,
`try_ipc`), and a `-32008` error response surfaces as `Err` — the in-process
fallback is only reached when the socket is absent/stale (`NotFound` /
`ConnectionRefused`).

### The `-32007` path: the typed ceremony signal is destroyed at the VFS boundary

The IPC `write` gate (`write_path_uses_wallet_signer`, `ipc.rs:690-776`)
deliberately lets `confirm` through to the VFS wallets handler (it only forces
`cancel`/`replace` onto `write_unlocked`). So a plain confirm write reaches
`tx_engine.confirm(...)` → `ensure_action_authorized` (`tx_engine.rs:1394`) →
`ensure_sealed_outbox_approval` (`tx_engine.rs:2567`).

For a passkey wallet with no active grant and no `approval.json`, the engine
writes `approval_challenge.json` to disk (`tx_engine.rs:2694-2700`) and returns:

```rust
Err(TxEngineError::BroadcastApprovalRequired(format!(
    "outbox confirm requires signed Sealed Approval; wrote {} in {}; \
     rerun the foreground confirm/write command with the passkey wallet ...",
    OUTBOX_APPROVAL_CHALLENGE_FILE, entry.dir.display(),
)))
```
(`tx_engine.rs:2714-2718`)

But the wallets handler **discards the reason string** and downgrades the typed
error to opaque `PermissionDenied` (`crates/bloom-vfs/src/handlers/wallets.rs:2126-2134`):

```rust
TxEngineError::BroadcastApprovalRequired(_) => HandlerError::PermissionDenied,
```

And `PermissionDenied` → bare `-32007 "permission denied"` (`ipc.rs:1445`).
The challenge file was written on the daemon's disk, but the IPC response
carries no path, no nonce, no intent hash — the socket client cannot discover
where it is or act on it.

### The ceremony is foreground-only by construction

The ceremony orchestrator `run_sealed_approval_ceremony`
(`crates/bloom-daemon/src/sealed_ceremony.rs:21-73`) is called from **exactly
one site in the entire codebase**: the CLI at `main.rs:3070`, inside
`sign_outbox_sealed_approval_if_challenged` (`main.rs:3006-3087`). No daemon
IPC handler references it.

The IPC dispatch table (`ipc.rs:294-358`) exposes these methods:

```
version, chains, shutdown, lookup, read, write, write_unlocked,
sign_hash, wallet.sign_policy, list,
petals.install, petals.run, petals.list, petals.resolve, petals.name, petals.uninstall
```

There is no `ceremony.*`, `sealed_approval.*`, or `browser.*` method. The only
signing method over the socket is `sign_hash` (`ipc.rs:318-321`), which is the
**consumer** of a grant + cached signer, not a producer of one.

The browser step itself — `auth_ceremony` (`passkey.rs:436-536`) — binds a local
TCP listener on `127.0.0.1:{CEREMONY_PORT}` (`passkey.rs:479`) and opens
`http://localhost:{port}/?t=...` in the system browser (`passkey.rs:488-504`).
The RP ID is `"localhost"` (`passkey.rs:66,274`); origin checks hard-require
`http://localhost:{port}` (`passkey.rs:643-660`). This is only meaningful in an
interactive process sharing the user's desktop session.

### The bridge that DOES cross the socket: the SignerCache

What IS reachable over the socket is signing with an **already-obtained** grant.
The ceremony populates an in-memory `SignerCache`
(`crates/bloom-keystore/src/petal_host.rs:49-109`) at `sealed_ceremony.rs:52-58`,
keyed by `grant_id`. Subsequent `sign_hash` IPC calls read
`cache.get(&grant.grant_id)` (`petal_host.rs:405-425`) and sign without
re-running a ceremony. So the model is:

```
ceremony (in-process, once) → grant + SignerCache entry → many sign_hash calls (over socket)
```

The daemon can **consume** a grant but cannot **produce** one.

## Why it happens

This is a deliberate architectural property, not an oversight. Three structural
facts combine:

1. **The dispatch table has no ceremony method.** The daemon's IPC surface
   cannot open a browser or run WebAuthn. `write_unlocked` (which would unlock
   + sign in one round-trip) is hard-rejected for passkey because the decrypted
   EVM key must never be transported across the socket (`ipc.rs:163-165`: "The
   daemon remains the single writer; the client only requests the ceremony").

2. **The ceremony is intrinsically local + browser-mediated.** A background
   daemon has no defined way to open a browser on the owning user's interactive
   desktop session. The `localhost` RP ID and origin checks make the WebAuthn
   contract meaningful only from the foreground process.

3. **The typed signal is destroyed at the VFS boundary.** Even though the
   engine writes `approval_challenge.json` and returns a rich
   `BroadcastApprovalRequired(reason)` naming the file, the wallets handler
   discards the reason and returns opaque `-32007`. So even a sophisticated
   socket client (e.g. an agent) cannot discover the challenge, and there is no
   IPC method to consume a signed `approval.json` even if it could.

The security rationale is explicit in the codebase: the passkey wallet's
decrypted key must never exist in a context the socket controls, and the
ceremony model requires human presence (WebAuthn `user_verified=true` for
Hardened assurance). Gating `policy-session/new` onto the same ceremony lane
(`ipc.rs:732-739`) carries the same rationale: "an agent cannot silently mint a
broad batch-signing session."

## Impact

- **Agent/automation flows for passkey wallets are blocked under `bloom serve`.**
  Any agent relying on the long-running daemon for passkey-wallet broadcasts
  hits a dead end. The only working path is stopping serve and running the
  foreground CLI — which requires a human at the machine for every broadcast.

- **The error messages are not actionable.** A socket client sees `-32007
  "permission denied"` with no indication that a challenge file was written, no
  path to it, and no instruction. The `-32008` message at least names the
  alternative (`PetalHost::sign_hash`), but neither tells the caller "stop serve
  and run the foreground CLI."

- **QUICKSTART §6 overstates the serve path.** The doc implies direct VFS
  `confirm` writes work under serve for any wallet (the example uses a
  passphrase wallet, with no passkey carve-out). See companion code fix C8.

- **The SignerCache is in-memory only** (`petal_host.rs:48`: "the daemon process
  restarts (cache is in-memory only)"). So even the one-ceremony-then-many-sign
  model does not survive a daemon restart — each restart requires a fresh
  foreground ceremony.
