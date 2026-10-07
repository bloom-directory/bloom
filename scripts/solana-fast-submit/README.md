# Bounded Solana approval-to-confirm helper

This opt-in Python 3 helper removes the chat/agent round trip between an owner's approval and confirmation of one already-prepared Solana transfer. It does not stage, initiate approval, restage, extend blockhash validity, or retry a write. Machine, Broker and Signer retain their existing authority checks. No Rust, release pin, installer, or production default changes are included.

## Use

Only after the owner has authorized this exact transfer, staging and the initial confirm have produced its approval challenge, and the intended Machine endpoint has been verified:

```sh
python3 scripts/solana-fast-submit/submit.py \
  --bloom /absolute/path/to/reviewed/bloom \
  --connect unix:/absolute/path/to/intended/machine.sock \
  --entry wallets/test-wallet/0/chains/solana-local/outbox/pending/EXACT_ID \
  --state-dir /absolute/path/to/private/persistent/submit-guards \
  --execute
```

Paths and EXACT_ID are intentionally non-runnable placeholders. Start the listener before delivering the existing ceremony URL. Do not run another confirmer concurrently. Without explicit `--execute`, it refuses to run.

1. Read the exact existing `bloom.solana-approval-challenge/1` via Machine IPC; validate wallet, chain, entry, action, approval ID, expiry and retry path.
2. Poll the sealed approval's live Broker-backed `status.json` via IPC, not a mount or cached challenge. Wait only for `PREPARED`/`AWAITING_CEREMONY`; proceed only on matching `ACTIVE`.
3. Fail closed on malformed/unknown states, identity mismatch, read failure, or deadline. Recheck wall expiry after status and before dispatch; cap waiting at 60 seconds with a monotonic clock. Poll gap is 250 ms plus read duration, not a guaranteed detection bound.
4. Persist/fsync the guard, then issue at most one `vfs write <exact-entry>/confirm` with `y\n`. Never retry after timeout or ambiguous response. Killing the CLI does not cancel daemon work already accepted.
5. Read the exact sent intent and validate identity/status. A `sent` result is **not finality**; verify the chain receipt separately.

The O_EXCL guard covers invocations using the same exact endpoint/entry strings and state directory. It is retained even after a read-only failure. Never delete it, change directories, or use endpoint aliases to evade it. It is not a global daemon lock and cannot prevent other programs from confirming. Full power-loss durability is not certified. Authority failures are not repaired with sudo, socket changes, or fallback signing.

## Verification

```sh
python3 -W error -m unittest discover -s scripts/solana-fast-submit -p test_submit.py -v
```

28 unit/subprocess tests cover exact identity/path binding, a wallet named `pending`, deadline boundaries, slow/failing/malformed transport, pre/post-dispatch fsync failures, concurrent O_EXCL ownership and restart refusal. The core script is byte-for-byte the real-service-tested helper (SHA-256 `c26278884dcad35b47961732eb0165d341e31a1840acdbcc4492aac6d3de8a57`).

[Public acceptance evidence](evidence/results.json) records three real isolated triad/local-validator trials using generated disposable identities and the supported software WebAuthn driver. Each observed live ACTIVE, issued one helper confirm, signed, submitted and returned a finalized transaction with `meta.err == null`. Same-entry restart exited 2 without another confirm. Per-trial finalized transactions and monotonic events are alongside the results. No real funds, imported user keys or production services were used.

Tested services: Machine `059f900b0f147c6b1ab5c924b71835129bfc2761`; Broker `23b7b687f62c7d78e2f80a6f3434dd2e28a16d66` (built before the evidence commit, identical executable source); Signer `bc88ad690757165ebf1978410ea5c7ec652215d3`. Optimized builds used `--locked` and the same-UID developer harness, not production principal isolation. Earlier exact-pin and phone trials used the prior helper and are not fresh phone acceptance of this revision.

Median observed ACTIVE-to-confirm was 8.895 ms; confirm call including signing/submission 109.075 ms; ACTIVE-to-sent-readback 120.794 ms. These are local-service phase measurements, not phone latency, finalization latency or a measured speedup. [Unrounded timings](evidence/timings.json) retain the three-trial values.

This is a reviewable helper, not approval for mainnet use or a signed production release. Physical-phone acceptance of the revised candidate and release/principal-isolation gates remain separate. No external helper can make an expired blockhash valid or resolve an ambiguous broadcast by retrying it.
