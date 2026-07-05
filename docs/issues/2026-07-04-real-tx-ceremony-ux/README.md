# Real-tx ceremony UX — design issues (2026-07-04)

**Scope:** UX/correctness issues observed while exercising the mounted
sealed-approval demo branch against real mainnet — a cross-chain USDC bridge
(Base → Polygon) followed by a USDC → pUSD fund for Polymarket trading, driven
through a passkey-gated wallet. This was an end-to-end real-funds run, not a
dry-run or unit test.

**What this directory is for:** larger-scale design questions that need
comprehensive planning or carry genuine tradeoffs. These are **not** bugs with
obvious fixes — those were filed as code changes on this same branch.

**Companion code fixes (non-controversial, on this branch):**

| ID | Issue | Status |
|---|---|---|
| C1 | `polymarket fund` double-ceremony (manual rerun) | code fix |
| C4 | `polymarket fund` cancels tx on sealed-approval handoff | code fix (same change as C1) |
| C5 | policy-config debt (`under_policy` + empty `[limits]`) surfaced only at broadcast | code fix |
| C6 | `/defi/intents/<wallet>/` "latest" not time-sorted | code fix |
| C8 | QUICKSTART overstates serve + passkey write path | code fix |

## Design issues that need planning

- **[C2 — serve-socket cannot reach the passkey ceremony](./C2-serve-socket-passkey-ceremony.md)**
  With `bloom serve` running, passkey-wallet broadcasts are structurally
  unreachable over the socket. The ceremony is foreground-only by construction.
  The controversy: should an unattended daemon be able to trigger a
  human-in-the-loop browser ceremony at all?

- **[C3 — dependent cross-chain flows cannot share one ceremony](./C3-dependent-cross-chain-no-shared-ceremony.md)**
  Policy sessions authorize by exact chain-qualified outbox id, so a dependent
  leg whose id isn't known until an earlier leg settles can't be covered by one
  ceremony. The controversy: exact-id allowlist (safe) vs descriptor/plan-scoped
  sessions (usable for dependent flows).

- **[C9 — the policy engine can only price native-token sends](./C9-policy-pricing-native-only.md)**
  USD valuation is gated on `value_wei > 0`, so ERC-20 transfers, approvals,
  NFT transfers, and contract calls (swaps) are all unpriced and Denied under
  `under_policy` autonomy. A richer ERC-20-capable oracle exists but is not
  wired into the policy path. This makes `under_policy` autonomy effectively
  limited to plain ETH/MATIC sends.

- **[C10 — EVM batch ceremony infrastructure exists but is not wired in](./C10-evm-batch-ceremony-not-wired.md)**
  `confirm-batch --policy-session` claims "one ceremony" but actually runs N
  per-tx ceremonies. The `OwnerSessionUse` action kind, `SignerCache`, and
  `max_signatures > 1` plumbing all exist for true one-ceremony-many-sigs, but
  the batch command doesn't use them. Additionally, `417b830` broke the only
  working batch pattern (unlock-once-sign-many) by gating `Keystore::signer()`
  for passkey wallets without migrating any callers.

## Redaction note

Per the repo's no-personal-wallets policy, all wallet aliases, addresses, and
transaction hashes from the real-funds run are redacted with placeholders
(`<passkey-wallet>`, `<owner-eoa>`, `<deposit-wallet>`, `<base-tx-hash>`).
Staged outbox ids and defi session ids are bloom-internal identifiers and do
not identify the developer.
