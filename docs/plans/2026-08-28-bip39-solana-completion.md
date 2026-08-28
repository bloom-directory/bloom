# BIP-39 + Solana: completion plan

**Date:** 2026-08-28
**Goal:** mainnet passkey transactions on Solana from a BIP-39 wallet, then land the work.
**Status:** active

## Where things actually stand

- All Signer / Broker / Machine working trees are **clean**. Nothing uncommitted.
- Every validation item in `BIP39_SOLANA_HANDOFF.md` is DONE: local-Agave stage → passkey → sign → broadcast → finalized receipt, two-account selection, independent SLIP-10 cross-check.
- Zero `TODO`/`FIXME`/`unimplemented!` in `bloom-solana`, `bloom-solana-tx`, or the daemon's Solana path.
- Mainnet is possible today with a `mainnet-canary` build + one authorization file
  (`docs/design/solana-mainnet-canary.md`). No process prerequisites.
- Unmerged PR stack: bloom #169 → #170 → #191; signer #4; broker #5 → #13 → #15 → #17.
  Machine pins signer `2ef153a` (on signer #4) and broker `ba25a02` (on broker #17).
- Legacy passkey → Triad migration (`2026-08-06` plan) is **already implemented** across all three repos despite the doc saying "Proposed".

## Phase 1 — First mainnet transaction (do this first; ~1 hour)

1. `BLOOM_MAINNET_CANARY_ARTIFACT=1 cargo build --release -p bloom --features mainnet-canary`; record `sha256sum target/release/bloom`.
2. Run Broker + Signer from their current pinned revs (same builds used for devnet).
3. Add `[solana_chains.solana-mainnet]` with `allow_broadcast = true` and a mainnet RPC.
4. Create/reuse a BIP-39 wallet, allocate a Solana child, note address + fingerprint + path.
5. Fund the address with the loss budget (e.g. 0.01 SOL).
6. Write the authorization JSON (template in the runbook), export `BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION`.
7. Stage the exact transfer, complete the passkey ceremony, broadcast, reconcile to `finalized`.
8. Repeat with a fresh authorization file for each additional transaction you want to try.

**Done when:** a finalized mainnet receipt exists in the outbox and the destination balance moved.

## Phase 2 — Fix whatever Phase 1 surfaces (only if needed)

Anything that breaks on real mainnet (RPC quirks, fee estimation, priority fees under
congestion, reconciliation latency) gets a targeted fix on `feat/solana-mainnet-canary`,
retested against local Agave with the three `#[ignore]` validator tests:

```sh
cargo test -p bloom-solana-tx --test local_validator -- --ignored
cargo test -p bloom-it --test solana_workflow -- --ignored
cargo test -p bloom-it --test solana_multi_account -- --ignored
```

If multi-transaction sessions become annoying, raise `MAX_TRANSACTIONS` in
`crates/bloom-proto/src/canary.rs` (and the shape test) — a one-line change.

## Phase 3 — Land the stack (housekeeping; ~half a day)

Merge bottom-up so pins always point at master commits:

1. **bloom-service-runtime** — already on master (`d4150dd`). Nothing to do.
2. **bloom-signer #4** (`feat/bip39-hd-wallets`) → master.
3. **bloom-broker** — #5 (BIP-39) → #13 (Solana verifier) → #15 (ceremony checkpoint) → #17 (Linux socket) → master. #15/#17 are small fixes; consider squashing them into one merge.
4. **bloom** — repin `Cargo.toml:133` (broker) and `crates/bloom-it/Cargo.toml:25` (signer) to the new master SHAs, `cargo update -p bloom-broker-api -p bloom-signer-derive`, then merge #169 → #170 → #191 into master.
5. CI notes already known: `triad_release` needs `TAR=bsdtar` on the Linux runner; four macOS installer tests need a macOS runner. Neither touches Solana code — don't block the merge on them; file them as follow-ups if red.

## Phase 4 — Doc truth-up (DONE 2026-08-28)

- Umbrella BIP-39 plan and legacy-passkey migration plan marked `implemented`.
- Solana architecture doc status updated; mainnet posture points at the canary doc.
- Canary runbook folded into `docs/design/solana-mainnet-canary.md` ("How to run one");
  `docs/operations/solana-mainnet-canary.md` and root `BIP39_SOLANA_HANDOFF.md` removed.
- Remaining: after the first mainnet transaction, note its signature in the architecture doc.

## Explicitly deferred (not needed for the goal)

- `SolanaConfirmationAdvisor` dwell/congestion scanner and `getRecentPrioritizationFees` advisory (`docs/specs/2026-08-18-solana-confirmation-and-fee-advisory.md`). Revisit only if Phase 1 shows transactions expiring under congestion.
- Durable nonce accounts / offline signing.
- SPL tokens, program calls, generic production mainnet switch.
- Legacy-profile move-funds workflow (umbrella plan Phase 4).
- Full release-verification matrix (umbrella plan Phase 5), WebAuthn PRF browser matrix.

## Order of operations

Phase 1 today. Phase 2 only if Phase 1 fails. Phases 3–4 whenever convenient; they do not gate anything.
