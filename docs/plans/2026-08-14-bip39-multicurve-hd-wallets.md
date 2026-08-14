# BIP-39 Multi-Curve HD Wallets

**Status:** proposed

**Issue:** [bloom#163](https://github.com/bloom-directory/bloom/issues/163)

**Branch:** `feat/bip39-hd-wallets`

**Blocks:** [bloom#156](https://github.com/bloom-directory/bloom/issues/156)

## Goal

Make every newly created local Bloom wallet one deterministic wallet identity
with one Signer-owned BIP-39 root, one or more passkeys, and typed child
accounts for every supported key family. The normal UX exposes neither a
mnemonic nor individual private keys. Adding or replacing a passkey must not
change any chain address.

The first profiles are EVM secp256k1 through BIP-32/BIP-44 and Solana Ed25519
through hardened SLIP-10. BIP-39 provides portable recovery and Open Wallet
Standard compatibility, but Bloom retains the triad custody and approval model.

## Non-goals

- deriving the root or a chain key directly from a WebAuthn credential key or
  PRF output;
- adopting the OWS password vault, filesystem authority, API-token secret
  copies, or in-process policy boundary;
- exposing a mnemonic during routine creation, unlock, signing, or account
  allocation;
- arbitrary caller-selected derivation paths;
- threshold custody, hardware-wallet roots, social recovery, or automatic
  movement of funds from legacy addresses in the first release.

## Architectural decisions

### 1. Passkeys unlock the wallet; they are not the wallet root

Signer generates 256 bits of cryptographically random BIP-39 entropy. The
wallet key-encryption key (WKEK) encrypts the entropy and its root profile. Each
active WebAuthn credential evaluates its own PRF and independently wraps the
same WKEK, preserving the ratified multi-passkey construction in the triad
specification.

This separation is mandatory:

- WebAuthn PRF material is credential-specific;
- a new credential must unlock the existing wallet, not generate a new one;
- credential replacement and RP migration must not rotate on-chain addresses;
- a recovery factor must be able to re-wrap the existing WKEK;
- no chain should depend on a WebAuthn authenticator supporting raw signing.

The browser continues to HPKE-encrypt transient PRF output directly to Signer.
Broker forwards the envelope and independently binds the ceremony; Machine and
Petals never receive PRF output.

### 2. A wallet root is not a signable `KeyRef`

Replace the assumption that `root_key_ref` names one curve-specific signing key
with two explicit layers:

```text
WalletSeedRef
  profile: bip39-multicurve-v1
  encrypted entropy: Signer-only
  derivation registry: Signer authority

DerivedAccountRef / KeyRef
  root: WalletSeedRef
  derivation profile and allocated path
  key spec and crypto suites
  pinned public key fingerprint
  chain/account projections
```

Only derived accounts can satisfy a signing request. Neither Broker nor Machine
may select the root as a signing key. Signer verifies that the requested child,
path, suite, public key, policy, and wallet all refer to one registered entry.

Wallet projection may designate a primary account for legacy UX, but that is a
presentation choice rather than custody authority.

### 3. Profiles are versioned and exact

`bip39-multicurve-v1` uses:

- 256-bit BIP-39 entropy and the English 24-word encoding;
- the empty BIP-39 passphrase for the interoperable default profile;
- BIP-32 secp256k1 for EVM;
- hardened SLIP-10 Ed25519 for Solana;
- canonical, registry-allocated paths;
- CAIP-2 chain and CAIP-10 account identifiers at generic boundaries.

Initial paths:

| Family | Profile | Canonical account path |
|---|---|---|
| EVM | `bip44-evm-secp256k1-v1` | `m/44'/60'/<account>'/0/<index>` |
| Solana | `bip44-solana-slip10-ed25519-v1` | `m/44'/501'/<account>'/0'` |

The exact EVM account/index allocation policy must be frozen with migration
vectors before implementation. Solana derivation is hardened at every child
step. A future profile can add paths without silently changing v1.

### 4. Recovery is explicit custody authority

The default creation ceremony does not display the mnemonic. Users should add
a second passkey during onboarding when possible. Mnemonic export is an
explicit, high-assurance Broker-hosted custody ceremony whose exact terms name
the wallet, export format, destination mode, and consequences.

Import and recovery are separate ceremonies:

- **import** creates a new Bloom wallet from entered BIP-39 entropy and scans
  only supported versioned profiles;
- **recovery** unwraps an existing Bloom wallet using its recovery factor,
  registers a new passkey, re-wraps the same WKEK, then optionally revokes lost
  credentials;
- **export** returns the mnemonic only to the owner ceremony and never through
  Machine, VFS, CLI stdout, logs, audit events, or agent RPC.

An advanced non-empty BIP-39 passphrase mode is deferred. Adding one later
requires an explicit profile because losing or omitting the passphrase produces
a different wallet while the words still appear valid.

### 5. Agent authority remains bounded signing authority

Agents and Petals receive typed public child accounts plus scoped approval
capabilities. Bloom must never reproduce OWS's construction in which a bearer
token also decrypts a copy of the complete wallet secret. A compromised Machine
or Petal remains unable to export the seed or allocate arbitrary children.

## Durable model

Signer backup and restore must treat the following as one atomic wallet set:

- wallet ID and `WalletSeedRef`;
- encrypted BIP-39 entropy and root-profile version;
- root ciphertext fingerprint and WKEK wrapping metadata;
- every credential record and credential-specific wrapped WKEK;
- recovery record when enabled;
- derivation registry, including namespaces, allocations, tombstones, and next
  indices;
- every derived account's path, profile, key spec, public key/fingerprint,
  allowed suites, chain projections, and lifecycle state;
- canonical wallet policy, revocation state, audit sequence, and format
  versions.

Restore refuses new derivation when the registry is missing or inconsistent.
It must never reconstruct allocation state by scanning addresses and guessing.

## Contract changes

### Signer API

Add closed, versioned types equivalent to:

```text
WalletSeedProfile::Bip39MulticurveV1
DerivationProfile::Bip44EvmSecp256k1V1
DerivationProfile::Bip44SolanaSlip10Ed25519V1
WalletSeedRef
DerivedAccountDescriptor
DerivationNamespace
```

Extend backend capability discovery so a backend advertises root profiles,
derivation profiles, key specs, suites, backup/export support, and namespace
limits independently. The local backend supports v1. AWS KMS continues to
report deterministic seed derivation unsupported unless a future native design
meets the same contracts.

Signer owns these operations:

- create/import/restore/export/delete seed root;
- allocate/retire child account;
- derive public descriptor;
- activate through a credential or recovery wrap;
- exact-sign using a registered child;
- atomically back up/restore the root and registry.

### Broker API and ceremonies

Registration/import preparation selects an explicit wallet seed profile rather
than a curve-specific root key. Child allocation is an authority-changing
custody ceremony unless current policy contains an exact bounded allocation
budget.

Every authority-changing ceremony binds:

- wallet and seed profile;
- derivation profile and requested semantic role;
- namespace/account/index constraints;
- expected key spec and allowed suites;
- resulting public projection or its signer commitment;
- policy/revocation versions, replay identity, expiry, and audit purpose.

Broker fails closed on unsupported profiles, ambiguous roots, profile changes,
or a returned child that does not match the committed derivation request.

### Machine projection

Machine receives a public account collection rather than treating one
curve-specific root as the wallet:

```text
wallet
  identity
  accounts[]
    key_ref
    key_spec
    derivation profile/path
    public key/fingerprint
    chain-family projections
    CAIP accounts
    lifecycle state
```

Generic selection is by an exact typed account reference. Network selection
cannot silently choose a different key or allocate a path.

## Migration strategy

### Inventory gate

Before defining a migration algorithm, inspect the released local Signer format
and classify every existing wallet:

1. original seed entropy retained in a form suitable for the new profile;
2. only a BIP-32 master/extended secp256k1 key retained;
3. only a standalone secp256k1 private key retained;
4. imported/external backend whose key cannot participate in HD derivation.

Only class 1 can become standard BIP-39 multi-curve without changing its
cryptographic root, and only if provenance and exact seed semantics are known.
A BIP-32 extended key or secp256k1 scalar must not be treated as BIP-39 entropy
or a SLIP-10 seed.

### Compatibility behavior

- Existing wallets remain available as a versioned legacy-secp profile.
- Their current EVM address, `KeyRef`, approval bindings, policies, and audit
  lineage remain unchanged.
- An owner may create a new BIP-39 wallet and move funds explicitly, but Bloom
  does not silently transfer or alias authority.
- If an exact address-preserving migration is proven possible, it runs as a
  restart-safe custody ceremony with preflight backup, public-address equality
  checks, atomic commit, and an idempotent receipt.
- Solana enablement for a legacy wallet may require explicit wallet upgrade or
  a new BIP-39 wallet; it must not invent a Bloom-only cross-curve derivation.

## Work sequence

### Phase 0 — Freeze semantics and vectors

1. Ratify root/child terminology and remove the signable-root assumption from
   the wallet architecture and triad contracts.
2. Freeze BIP-39 word count, normalization, passphrase behavior, and validation
   errors.
3. Freeze EVM and Solana path profiles, namespace allocation, and CAIP mapping.
4. Record official BIP-39, BIP-32, and SLIP-10 vectors plus expected Ethereum
   and Solana public keys/addresses.
5. Record negative vectors: bad checksum/normalization, wrong passphrase,
   unhardened Ed25519 path, wrong curve/profile, altered path, duplicate
   allocation, tombstone reuse, and missing registry.
6. Complete the released-wallet inventory and choose explicit behavior for each
   legacy class.

Gate: all repositories consume identical canonical vectors and the migration
classification has no unknown wallet format.

### Phase 1 — Signer root and derivation primitives

1. Add zeroizing BIP-39 entropy generation/import and strict validation.
2. Encrypt the versioned root with the existing WKEK construction.
3. Implement BIP-32 secp256k1 and hardened SLIP-10 Ed25519 behind explicit
   derivation profiles.
4. Add an atomic derivation registry with namespace caps and permanent
   tombstones.
5. Produce canonical public descriptors and locally verify every signature.
6. Extend backup/restore/delete/rekey so the root, credentials, recovery record,
   registry, policies, and audit lineage remain one consistent set.

Gate: vectors, restart, backup/restore, corrupted registry, concurrency,
cross-profile denial, and zeroization-oriented tests pass.

### Phase 2 — Broker ceremonies and edges

1. Version registration/import around `WalletSeedProfile`.
2. Add child-allocation preparation, exact terms, Signer contribution, review,
   completion, replay, cancellation, and audit.
3. Add mnemonic import/export/recovery projections without allowing mnemonic
   bytes into general Broker logs or Machine APIs.
4. Preserve multi-passkey add/replace/remove semantics by wrapping the same WKEK.
5. Publish synchronized Broker/Signer API releases and cross-edge vectors.

Gate: two passkeys and the recovery factor independently unlock the same root;
all projected children remain byte-for-byte identical after restart and restore.

### Phase 3 — Default wallet UX and projections

1. Make `bip39-multicurve-v1` the default for new local wallets while requiring
   an explicit legacy option only where compatibility demands it.
2. Allocate the canonical initial EVM account during creation so existing
   EVM-first workflows remain simple.
3. Expose typed accounts and CAIP identifiers through Broker projection,
   Machine cache, VFS, and CLI.
4. Add second-passkey onboarding guidance and optional guarded recovery setup.
5. Ensure routine output never includes words, entropy, seed, WKEK, PRF output,
   or child private keys.

Gate: fresh-install creation, unlock, EVM signing, passkey replacement, export,
import, recovery, and loss-of-all-factors behavior pass end to end.

### Phase 4 — Legacy migration and compatibility

1. Ship legacy profile readers before changing the default.
2. Add migration preflight/reporting and only the proven address-preserving
   migrations from the inventory gate.
3. Test old backups, policies, approvals, restart states, and public projections
   against the new binaries.
4. Add OWS-compatible mnemonic/path import vectors without treating OWS files as
   Bloom authority.

Gate: no released wallet loses access or changes an existing address, and every
unsupported migration remains usable under an explicit legacy profile.

### Phase 5 — Release verification

Required checks:

- formatting, unit/integration tests, Clippy, locked builds, and release targets;
- cross-repository canonical vectors at exact pinned revisions;
- dependency/license/advisory review for BIP-39/BIP-32/SLIP-10 crates;
- browser matrix for WebAuthn PRF creation and assertion feature detection;
- multi-passkey, recovery, restart, backup/restore, rekey, and concurrency tests;
- audit proving no mnemonic/seed/PRF/private child enters Machine, Petals, logs,
  crash dumps, routine Broker state, or capability tokens;
- all EVM, Sealed Approval, outbox, Petal, packaging, and update regressions.

## First implementation slice

Start with a contract-and-vector vertical, not the mnemonic UI:

1. ratify `WalletSeedRef`, derived child metadata, and two v1 profiles;
2. add shared BIP-39/BIP-32/SLIP-10 golden vectors;
3. implement local Signer root generation and deterministic public derivation;
4. complete backup/restore plus registry round-trip;
5. integrate one Broker child-allocation ceremony and Machine projection;
6. prove the existing EVM flow can sign with the derived secp256k1 child.

Only then make the profile default or add mnemonic export. This proves the
custody boundary and compatibility path before exposing irreversible recovery
UX.

## Completion criteria

- new local wallets use one encrypted BIP-39 root by default;
- normal users manage passkeys, not individual chain private keys;
- every active passkey unlocks exactly the same root and child addresses;
- EVM and Solana accounts reproduce the ratified standard vectors;
- roots cannot sign and callers cannot choose arbitrary derivation paths;
- mnemonic import/export/recovery occur only through explicit custody
  ceremonies and never expose secrets to Machine or Petals;
- backup/restore includes the complete derivation and recovery authority set;
- existing wallets preserve their addresses and remain usable;
- a released and pinned Ed25519 child edge unblocks bloom#156.

## References

- [Triad process architecture](../specs/2026-07-23-triad-process-architecture.md)
- [Wallet architecture](../architecture/Wallet.md)
- [Open Wallet Standard core](https://github.com/open-wallet-standard/core)
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
