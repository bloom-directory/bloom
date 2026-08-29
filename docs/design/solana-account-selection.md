# Explicit derived-account selection

**Status:** accepted
**Resolves:** [bloom#169 review thread](https://github.com/bloom-directory/bloom/pull/169#discussion_r3824025189) (Finding R1)

## Problem

Wallet-level exact, exact-batch, and reusable signing select a key by
`wallet_id + CryptoSuite` alone. A BIP-39 wallet may hold several active
Ed25519 children, all of which match that pair, so the choice is ambiguous.

Two surfaces resolve that ambiguity by taking whichever child appears first in
the Broker projection:

- `resolve_solana_child` in the VFS wallet handler, which produces the fee
  payer and transfer source; and
- the `wallet address --profile solana` command.

List order is not a selection criterion. It is not stable, not
user-visible, and not bound to anything the user approved. A user who
allocated a second account and expects to spend from it can silently sign
from the first instead.

The prior local validation only demonstrated account 1 working after account 0
was *retired*. That proves the account lifecycle, not multi-account usability:
with both children active the flows are still ambiguous.

## Decision

Select a derived child by its **public-key fingerprint**, resolved through the
Broker projection and carried as the authenticated `KeyRef`.

The fingerprint is the right selector because it is what the identity fields
already bind. `SealedApprovalTerms::key_ref` and
`SignOperationIdentity::key_ref` carry the exact `KeyRef`, so an approval
issued for one account cannot authorise a signature from another. Selecting by
fingerprint means the thing the user names is the thing the approval binds,
with no translation step in between that could drift.

Rejected alternatives:

- **Account number** (`--account 1`). Reads naturally, but it is a derivation
  input, not an identity. Broker would have to map number to key, and that
  mapping is exactly the ambiguity being removed. It also cannot name a key
  whose derivation metadata is absent.
- **List index** (`--account-index 1`). Encodes the ordering defect as public
  interface.
- **Full `KeyRef` on the command line.** Unambiguous but unusable by hand.
  It stays the internal representation.

### Public interface

A short unique fingerprint prefix, matching how the repository already
addresses digests:

- `wallet address --profile solana --fingerprint <hex-prefix>`
- `new.tx` gains an optional `account_fingerprint` field:

  ```json
  { "destination": "…", "lamports": 1000, "account_fingerprint": "9f3c…" }
  ```

A prefix that matches no active child, or more than one, is an error naming
the candidates. Only a full-length fingerprint is accepted where the value is
persisted, so a stored selection can never be re-resolved to a different key.

### Omitted selector

Backward compatibility is retained only where it cannot be ambiguous:

- exactly one active compatible child — use it, as today;
- zero — fail, as today;
- two or more — **fail closed**, listing each candidate's fingerprint and
  derivation path so the user can name one.

Never choose the first.

### Validation

A selected key is accepted only if it is a member of the requested wallet, is
active, carries the requested derivation profile, key spec, and suite, and
matches Broker's public projection. `verified_signing_key` already enforces
membership, key spec, suite, and Broker confirmation for an explicitly passed
`KeyRef`; this work supplies the selector to it and adds the lifecycle and
derivation-profile checks at the Solana surfaces.

Selection itself lives in one place, `bloom_solana_tx::account`, rather than
once per surface. The VFS handler and the `wallet address` command had grown
the same first-match `.find(...)` independently, which is how they came to
disagree with the signing layer that already refused to guess.

A foreign, retired, tombstoned, unsupported-suite, or substituted key fails
before ceremony creation or signing.

### Durability

`StagedSolanaTransfer` gains the selected key's full fingerprint. Staging pins
it; confirmation, restage, restart, and reconciliation only ever read it. A
staged transfer whose stored fingerprint no longer resolves to an active,
matching child fails closed rather than falling back to resolution by order —
the message bytes were built for one fee payer and must not be signed by
another.

The message's `fee_payer` and the stored fingerprint must agree at every step.
That is checked, not assumed: `fee_payer` is derivable from the selected key,
so a disagreement means the record was altered.

### EVM

EVM behaviour is unchanged. Its wallets expose one child per suite today, so
the single-match path applies and no selector is required. The selector is
generic at the `verified_signing_key` layer, so an EVM surface can adopt the
same `--fingerprint` spelling when it grows multiple children, rather than
inventing a second convention.

## Required regressions

1. allocate two active Solana children and independently select and sign with
   each;
2. verify each signature against only its selected public key;
3. omit the selector with two active children — permanent ambiguity error
   listing both candidates;
4. substitute the selector after staging — identity validation fails;
5. retire one child — it can no longer be selected;
6. restart all three services and repeat selection;
7. EVM behaviour unchanged.

## Non-goals

Mainnet enablement, and any change to the Solana mainnet-beta broadcast guard.
