# Mounted Sealed Approval implementation plan

Target branch: `auth-architecture-hardening`

## A. Generic mounted ceremony runtime

- `crates/bloom-auth-api/src/lib.rs`
  - Add optional `ceremony_url` to `ApprovalChallenge` as projection metadata.
  - Keep `ceremony_url` out of `ApprovalChallenge::canonical_bytes()` / `challenge_hash()`.
  - Add deterministic local ceremony URL helper from `server_nonce` for the mounted daemon demo path.
- `crates/bloom-daemon/src/sealed_ceremony.rs` / daemon ceremony serving
  - Reuse the existing passkey ceremony, approval verifier, grant store, and signer cache for grant minting.
  - Add grant-only and grant+execute API wiring via the generic dispatcher.

## B. Challenge lifecycle and mounted denial contract

- `crates/bloom-auth/src/lib.rs`
  - Make `AuthStore::issue_challenge` idempotently return an existing unexpired nonce/expiry instead of rotating on retry.
- `crates/bloom-tx/src/tx_engine.rs`
  - Populate `approval_challenge.json` with `ceremony_url` before returning approval-required.
- `crates/bloom-vfs/src/handlers/wallets.rs`
  - Map EVM `BroadcastApprovalRequired` to `HandlerError::PermissionDenied` so mounted writes return EACCES after artifacts are written.
- `crates/bloom-mount/src/adapter.rs`
  - Keep raw signer paths pre-denied; allow Sealed Approval-aware confirm paths to reach VFS handlers so they can stage the challenge before denying.

## C. Generic sealed-action execution dispatcher

- Add a runtime dispatcher keyed by `petal_id`, `petal_digest`, `subject_kind`, and `action_kind`.
- Keep ceremony grant/execution mode generic: `grant` mints only; `grant+execute` mints and calls the dispatcher.
- Register ERC20/EVM wallet as the first executor rather than embedding EVM behavior in ceremony logic.

## D. Central outbox as canonical queue

- `crates/bloom-vfs/src/handlers/outbox.rs`
  - Add a safe helper for runtime-written action artifacts such as `approval_challenge.json`.
- `crates/bloom-tx/src/outbox.rs` and `crates/bloom-daemon/src/lib.rs`
  - Extend the central outbox projection to write pending artifacts and include Petal identity in status/projection output.
- Wallet projections continue mirroring `plan.md`, `approval_challenge.json`, `status.json`, `result.json`, and sent/failed transitions from the same action id.

## E. Execute from sealed bytes

- `crates/bloom-tx/src/tx_engine.rs`
  - Reuse existing EVM sealed subject, daemon terms, signing attestation, `PetalHost::sign_hash`, and broadcast code.
  - Add a hard sealed-vs-projection consistency check for transitional paths.

## F. ERC20 mounted manual demo harness

- Reuse `crates/bloom-it/tests/erc20_e2e.rs` and `scripts/acceptance.sh` assets.
- Add demo notes covering anvil, MockERC20 deploy, passkey wallet creation/import, funding, `bloom serve --mount`, VFS staging/confirm, ceremony URL, grant retry, grant+execute, balances, and outbox artifacts.

## G. Agent-facing docs

- `crates/bloom-vfs/src/docs/agent-guidance.md`
  - Document mounted confirm → permission denied → read `approval_challenge.json` → validate `action_id`/`expiry_ms` → open `ceremony_url` → choose mode → retry/inspect artifacts.

## H. Acceptance and regression tests

- `crates/bloom-auth-api`: URL projection and URL-excluded hash tests.
- `crates/bloom-auth`: challenge reuse/rotation tests.
- `crates/bloom-vfs` / `crates/bloom-mount`: permission-denied contract and projection visibility tests.
- `crates/bloom-daemon`: grant-only, grant+execute, restart-loses-grant, fake Petal dispatcher tests.
- `crates/bloom-it/tests/erc20_e2e.rs`: first real ERC20 manual/integration path.
