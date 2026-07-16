# Wallet Architecture

**Status:** target architecture for passkey wallets and Sealed Approval integration
**Audience:** Bloom engineers, Petal authors, and implementation agents

This document describes Bloom's wallet setup, passkey ceremony model, and
key-storage layout. It is written around the target **multi-passkey credential
layout + wallet DEK** architecture, even where the current codebase is still
migrating from the legacy single-credential layout.

## Decision Summary

- Bloom wallets that can hold funds are **passkey-gated by default**.
- A wallet is not bound to one browser credential. A wallet is controlled by a
  set of non-revoked passkey credentials.
- The wallet private key is encrypted by one random **wallet DEK**. Passkeys do
  not encrypt the wallet key directly.
- Each passkey credential has its own PRF salt and wraps the same wallet DEK.
- Adding, removing, replacing, or recovering credentials is an
  authority-changing Sealed Approval action and requires hardened assurance.
- The Sealed Approval ceremony for value-moving or authority-changing work is a
  single WebAuthn operation that returns both:
  1. a WebAuthn assertion over the sealed challenge; and
  2. PRF output used locally to unwrap the wallet DEK.
- PRF output, wallet DEK bytes, decrypted private key bytes, and grant-held
  signer material are never serialized to VFS, `approval.json`, logs, or CLI
  stdout.

## Concepts

**Wallet**

A named local identity with an owner address and policy. In the target model, a
fund-holding wallet stores encrypted signing material and one or more enrolled
passkey credentials. Watch-only wallets may exist for read-only views but cannot
sign.

**Wallet private key**

The secp256k1 key that owns EVM funds and any venue authority derived from that
owner key. Petals must not receive this key or a raw `PrivateKeySigner`; they
request bounded signatures through the Bloom Machine signing API.

**Wallet DEK**

A random data-encryption key generated at wallet creation. The wallet private
key is encrypted once under this DEK. The DEK is itself wrapped separately for
each passkey credential.

**Passkey credential**

A WebAuthn credential enrolled for the wallet. Each credential has its own PRF
salt and wrapped DEK record. Any non-revoked credential can unlock the wallet
DEK during an approved ceremony.

**Sealed Approval Grant**

A short-lived in-memory capability minted after a valid Sealed Approval
ceremony. It authorizes a single Petal to request up to a bounded number of
signatures, until a fixed expiry, through the Bloom Machine signing API. Within that
envelope the Petal may propose bytes to sign; the Bloom Machine enforces the
envelope but does not bind the bytes to the approval (see
[`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md)). It is not
persisted.

## Target On-Disk Layout

The target wallet directory is exactly:

```text
wallets/<wallet>/
  kind                         # "passkey" for fund-holding wallets
  address                      # checksummed owner address
  address.qr.png               # QR code address in PNG format 
  address.qr.svg               # QR code address in SVG format
  pubkey                       # owner public key
  encrypted.key                # wallet private key encrypted by wallet_dek
  policy.toml                  # wallet policy
  policy.toml.sig              # signature over policy.toml
  credentials/
    <credential_id>/
      passkey.json             # serialized WebAuthn credential metadata
      prf.salt                 # public 32-byte salt, hex/base64 encoded
      wrapped_dek              # wallet_dek encrypted/wrapped by PRF output
      label                    # user-facing credential label
      created_ms               # enrollment timestamp
      revoked_ms               # absent/empty when active
```

TODO: We need to decide if we want `chains` inside a wallet directory still. Currently it provides endpoints for `balance`, `nonce`, etc. Maybe we allow Petals to project into certain parts of the VFS? Maybe we put it behind a different Petal dir?

Properties:

- `encrypted.key` is wallet-scoped. It does not change when adding or removing
  a passkey unless the owner key itself is rotated.
- `credentials/<credential_id>/wrapped_dek` is credential-scoped. Adding a
  passkey adds a new credential directory and wrapped DEK for that credential.
- Revocation should set `revoked_ms` or move the credential to an auditable
  revoked state; it must not silently delete the only audit trail.
- Removing the last non-revoked credential is forbidden unless the user enters
  an explicit recovery ceremony that installs replacement authority.
- The VFS may expose safe metadata, but it must not expose `encrypted.key`,
  `wrapped_dek`, PRF output, decrypted DEK material, or raw key bytes.

## Wallet Creation

A plain VFS write such as:

```sh
echo alice > /bloom/wallets/new
```

means “create a passkey-gated wallet named `alice`”. It must not silently
create a passphrase wallet.

Target creation flow:

1. Validate the requested wallet name and fail if the wallet already exists.
2. Generate the owner private key.
3. Generate a random wallet DEK.
4. Encrypt the owner private key as `encrypted.key` under the wallet DEK.
5. Start a WebAuthn registration ceremony for the first passkey credential.
6. Generate a credential-specific `prf.salt` and request WebAuthn PRF output.
7. Wrap the wallet DEK with the PRF output and write
   `credentials/<credential_id>/wrapped_dek`.
8. Write `passkey.json`, `label`, `created_ms`, and an empty/absent
   `revoked_ms`.
9. Write the initial `policy.toml` and sign it with the freshly generated owner
   key before key material leaves process-local memory.
10. Atomically commit the wallet directory.
11. Present recovery material or recovery instructions in a foreground ceremony;
    never hide a recovery secret in logs or background output.

The wallet-creation registration ceremony is distinct from Sealed Approval for
later actions. Registration establishes wallet authority; Sealed Approval spends
or changes that authority for a specific sealed action.

## Sealed Approval Ceremony for Wallet Use

For a value-moving or authority-changing action, the ceremony is action-bound:

```text
Petal stages action
Bloom seals canonical action bytes
Bloom issues approval_challenge.json
browser performs WebAuthn get() with PRF for an enrolled credential
Bloom Machine verifies assertion and unwraps wallet DEK in memory
Bloom Machine mints a short-lived grant and caches only grant-scoped signer material
Petal signs or executes through Bloom Machine APIs under that grant
```

The browser ceremony must use one `navigator.credentials.get()` call for the
selected credential:

- `challenge` is the Sealed Approval challenge hash.
- PRF extension input is the selected credential's `prf.salt`.
- `userVerification` is required for hardened assurance.
- The responding `credential_id` selects the matching credential directory.
- Revoked credentials are rejected before any key unwrap.

The ceremony response contains WebAuthn assertion data and PRF output on the
trusted local ceremony channel. Only assertion data may become `approval.json`.
The PRF output is consumed to unwrap the wallet DEK and then zeroized.

## Key-Use Rules

Petals and VFS handlers must not use the wallet key directly.

Allowed path:

```text
active Sealed Approval Grant
  -> Bloom Machine enforces the grant envelope: wallet, Petal identity,
     signature count, expiry
  -> Petal provides a structured signing attestation describing the request
  -> Bloom Machine signs the hash the Petal presents and binds the attestation
  -> audit event records what the Petal claimed and that it was signed
```

The Bloom Machine does not verify that the signed hash matches the approved
action; within a live grant the acting Petal is trusted to request only
signatures consistent with what was approved. This trust boundary is described
in [`Bloom Machine + Petals.md`](./Bloom%20Machine%20+%20Petals.md).

Forbidden paths:

- raw `PrivateKeySigner` flowing into Petal code;
- any wallet signing outside an active Sealed Approval Grant, including a raw
  `/wallets/<wallet>/sign/{message,hash,typed_data}` surface;
- passphrase/password approvals satisfying Sealed Approval assurance;
- `write_unlocked` as a privileged passkey signing lane;
- marker files such as `.confirm_approved.json` or `review_approved.json`;
- persisting grants, PRF output, wallet DEK, or decrypted owner key bytes.

## Wallet Policy Editing (mounted, Sealed Approval)

For a passkey wallet, `policy.toml` is signed authorization state guarded by
`policy.toml.sig`. The first-party edit surface is the mounted VFS path
`/wallets/<wallet>/policy.toml`; editing it is a Sealed Approval action.

Flow:

1. The agent writes proposed policy bytes to `/wallets/<wallet>/policy.toml`.
   The write first passes the standard signed-policy check (`Keystore::info`),
   so a wallet whose current signature is already stale fails closed here and is
   never used as a baseline for a new edit.
2. Bloom stages a canonical `policy_update` Sealed Approval action whose subject
   carries the wallet, VFS path, current signed policy bytes, proposed policy
   bytes, and a normalized authority diff. The action id is bound to
   `blake3(old_policy)` and `blake3(proposed_policy)`; authority-expanding edits
   require hardened assurance.
3. With no live grant, the first write issues an `approval_challenge.json` (with
   a projected `ceremony_url`) and returns permission denied.
4. The challenge and a `status.json` view are reachable through the mount at
   `/wallets/<wallet>/policy-updates/pending/<action_id>/` (or via the
   `policy-updates/latest` symlink), so the agent never needs `BLOOM_HOME`
   access. These are read-only views: bounded challenge metadata and
   `ceremony_url` only — never the signed approval, grant, or key/PRF material.
5. Approval mints a one-shot grant. The grant is keyed to the sealed action id,
   which is bound to `blake3(proposed_policy)`, so only the exact approved
   proposed bytes can consume it — a retry with different bytes re-derives a new
   action id and finds no grant. On the approved retry Bloom also requires the
   current on-disk policy to still match the sealed baseline (otherwise it
   refuses and requires a fresh edit), signs through the host signer, writes
   `policy.toml.sig`, then installs `policy.toml` — the wallet is never left with
   a new policy lacking a matching signature.

Local (passphrase) wallets keep immediate policy writes with no ceremony.

Out of scope: direct edits to `BLOOM_HOME/keystore/<wallet>/policy.toml` are
unsupported by this flow. If such an edit breaks `policy.toml.sig`, the wallet
fails closed on every signed path and is not repaired here; recovery uses the
admin helper `bloom wallet sign-policy <wallet>`. `write_unlocked` remains
disabled as a passkey signing lane.

## Multi-Passkey Operations

Credential changes are authority changes. They must be staged as Sealed Approval
actions with `assurance = hardened` and clear user-facing plans.

### Add passkey

1. Stage `wallet.add_credential` for the wallet.
2. Require hardened Sealed Approval with an existing non-revoked credential or
   recovery ceremony.
3. Run WebAuthn registration for the new credential.
4. Unwrap the wallet DEK with the approving credential or recovery path.
5. Wrap the same wallet DEK for the new credential's PRF output.
6. Write the new credential directory atomically.
7. Audit the new credential id, label, timestamp, and approving action id.

### Revoke passkey

1. Stage `wallet.revoke_credential` with the target credential id and label.
2. Require hardened Sealed Approval.
3. Deny if revocation would leave zero non-revoked credentials and no recovery
   ceremony is being completed.
4. Set `revoked_ms` atomically.
5. Audit the revoked credential id and action id.

### Replace passkey

A replacement is an add followed by revoke, committed as one authority-changing
operation when possible. The wallet should never pass through a state with no
valid credential.

### Recover wallet authority

Recovery must be explicit, foreground, and high-friction. It may install a new
passkey set, but it must not silently export or print the wallet private key.
Recovery outputs must be auditable and must not create a passphrase signing lane
that bypasses Sealed Approval.

## Legacy Migration

Legacy single-credential wallets have approximately this layout:

```text
wallets/<wallet>/
  kind
  address
  pubkey
  encrypted.key        # encrypted directly from one credential PRF path
  prf.salt
  passkey.json
  policy.toml
  policy.toml.sig
```

Target migration is lazy and atomic:

1. On first successful unlock/ceremony for a legacy passkey wallet, detect the
   absence of `credentials/`.
2. Use the legacy PRF path to decrypt the owner key in memory.
3. Generate a fresh wallet DEK.
4. Re-encrypt the owner key under the wallet DEK into the target
   `encrypted.key` format.
5. Move the legacy credential into `credentials/<credential_id>/` with its
   `passkey.json`, `prf.salt`, and `wrapped_dek`.
6. Preserve policy files and wallet address/pubkey.
7. Commit by atomic rename and keep an owner-only migration backup until the new
   layout verifies.
8. Audit migration without logging key material.

Migration must be idempotent. If it fails midway, the wallet must remain usable
under either the old fully intact layout or the new fully committed layout, not
a mix.

## VFS and Documentation Contract

- `/wallets/new` creates passkey wallets by default.
- Passphrase/local/import wallets are legacy or explicit-danger flows and must
  require an unmistakable opt-in if they remain available during migration.
- `/wallets/<wallet>/kind` reports `passkey` for passkey-gated wallets.
- Credential metadata may be exposed through a future safe path such as
  `/wallets/<wallet>/credentials/`, but secret-bearing files are not VFS files.
- Mounted writes that need approval should write or expose
  `approval_challenge.json`, return permission denied, and let the user or
  agent follow the `ceremony_url` flow described in
  [`Sealed Approvals.md`](./Sealed%20Approvals.md).

## Current Implementation Notes

The current codebase does not yet fully match this target layout. In particular, the current passkey keystore path still uses
one wallet-level `passkey.json` and one wallet-level `prf.salt`, with no
`credentials/<credential_id>/wrapped_dek` directory and no wallet DEK fan-out
across multiple credentials.

That gap must be closed before Bloom can claim true multi-passkey wallet
support.
