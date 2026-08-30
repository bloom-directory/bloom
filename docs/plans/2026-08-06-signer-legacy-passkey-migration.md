# Signer-Owned Legacy Passkey Migration Plan

**Date:** 2026-08-06

**Status:** Proposed

**Repositories:** `bloom`, `bloom-broker`, `bloom-signer`

**Normative baseline:** `docs/specs/2026-07-23-triad-process-architecture.md`

## 1. Objective

Allow an existing Bloom v1 passkey wallet to be imported into Triad custody by
using its existing passkey. The private wallet key and raw WebAuthn PRF output
must never be exposed to Machine, Broker, a terminal, an argument, an
environment variable, or an intermediate file.

Migration is a one-time conversion performed by Signer:

```text
legacy passkey envelope
  -- existing passkey assertion + PRF -->
Signer plaintext in guarded memory
  -- immediate atomic conversion -->
Triad WKEK custody
```

The result is an ordinary Triad wallet. Signing, credential management,
recovery, policy, and derivation use only the current Signer implementation
after conversion.

## 2. Decisions

1. Keep the WKEK design required by architecture section 13.2 and D-054.
2. Reuse `wallet.import_prepare`, `ceremony.complete`, `ceremony.status`,
   `ceremony.cancel`, and `custody.result`. Add no Machine/Broker or
   Broker/Signer RPC method.
3. Select the legacy path through the existing `expected_input_class` field,
   using a closed value such as `legacy_passkey_v1_prf`. Raw-key import remains
   a separate input class.
4. Machine may initiate migration using public metadata, but it must never open
   or copy the legacy wallet directory.
5. Broker hosts the browser ceremony and forwards only the existing raw proof
   and HPKE envelope. It never implements legacy decryption.
6. Signer is the only component that parses legacy credential/key records,
   receives the PRF output, decrypts the old envelope, or creates new custody.
7. Legacy format support is an import converter, not a second Signer backend.
   Signer never signs from, unlocks from, or falls back to a legacy record.
8. A successful import consumes its staged migration record. Retrying the same
   operation returns the durable result; it does not decrypt or import twice.
9. The original user-owned legacy directory is not silently deleted. After a
   successful conversion it is ignored by production Machine and may be
   explicitly archived or removed by the user. Signer's private staged copy is
   unlinked after the durable commit; the design does not claim physical secure
   erasure from flash storage.
10. Legacy `policy.toml` is not silently translated. The imported wallet starts
    with the current restrictive canonical policy, and any expansion uses the
    normal policy-update ceremony.

## 3. Supported legacy input

Support exactly the existing single-credential passkey layout:

```text
address
pubkey
kind                 # exactly "passkey"
encrypted.key        # PasskeyEncrypted v1
prf.salt             # exactly 32 bytes encoded as 64 lowercase/uppercase hex chars
passkey.json         # webauthn-rs Passkey, ES256/P-256 credential
```

`policy.toml`, `policy.toml.sig`, and review artifacts may be recorded in the
staging audit but are not authority inputs.

Reject rather than guess when:

- the kind, envelope version, cipher lengths, salt, credential, curve, or
  algorithm differs;
- a path is a symlink, special file, oversized file, or changes during staging;
- the source is not owned by the selected login user;
- the wallet name or public identity is malformed;
- the decrypted secp256k1 key does not reproduce both stored public key and
  address;
- the credential is not valid for RP ID `localhost` and origin
  `http://localhost:18734`;
- the operation, bundle digest, expected input class, or ceremony binding does
  not match exactly; or
- the destination wallet/address/credential is already registered
  inconsistently.

Do not depend on `bloom-keystore`, `bloom-auth`, the Machine repository, or
`webauthn-rs` legacy runtime code. Implement a small, deny-unknown-fields
parser for the one supported record version inside `bloom-signer`, using the
crypto dependencies Signer already owns plus BLAKE3 for the legacy KDF.

## 4. Staging boundary

The isolated Signer principal cannot safely discover arbitrary files in a
login user's home directory. Introduce a small administrative staging command
shipped by `bloom-signer`, for example:

```text
sudo bloom-signer-migrate stage \
  --uid <login-uid> \
  --wallet <legacy-name> \
  --source <user-home>/.bloom/keystore/<legacy-name>
```

The command:

1. resolves and validates the exact source directory without following links;
2. copies the bounded legacy files into a newly created Signer-owned pending
   directory using create-new/atomic-rename semantics;
3. validates and canonicalizes only public metadata;
4. computes a canonical bundle digest over every authority-bearing input;
5. allocates a migration operation ID;
6. writes a user-readable **public migration receipt** containing only the
   operation ID, wallet name, address, public key fingerprint, credential ID
   fingerprint, legacy format version, and bundle/terms digest; and
7. leaves the encrypted key and credential record readable only by Signer.

The tool does not request a passkey, decrypt the wallet, accept a private key,
or connect to Machine. Keep this as a small binary backed by Signer library
code; do not add substantial logic to either installation shell script.

For the same-UID developer harness, the same binary stages into the configured
developer Signer state directory without `sudo`. Tests use temporary roots.

## 5. Ceremony flow

### 5.1 Initiation

Add a CLI operation such as:

```text
bloom wallet migrate-passkey <public-migration-receipt>
```

Machine reads only the public receipt and calls the existing
`wallet.import_prepare` method with:

- the receipt's operation ID;
- `ceremony_kind = wallet_import`;
- `expected_input_class = legacy_passkey_v1_prf`; and
- `exact_terms_digest` from the receipt.

Machine does not validate legacy cryptography or inspect `~/.bloom/keystore`.
The mounted VFS may expose the same operation later, but it is not required for
the first implementation.

### 5.2 Prepare

When Signer receives this input class it loads the staged record by operation
ID and verifies the complete bundle and terms digest before preparing anything.
It converts the stored public credential into Signer's
`WebAuthnCredential`, preserving the credential ID, P-256 public key, PRF salt,
and signature counter. Because the historical record did not persist the user
handle separately, Signer reconstructs the exact legacy 16-byte UUID from the
wallet name using the historical BLAKE3/version/variant procedure; any user
handle returned by the authenticator must be absent or match it exactly.

Unlike raw-key import, this path does not create a new credential. Signer
prepares an assertion challenge for the existing credential and returns it
through the existing `SignerPreparedCustody` fields. The signed contribution
binds the operation, input class, destination wallet ID, review digest,
credential, Signer nonce, HPKE recipient, and expiry.

Broker independently checks the contribution and presents a specific review:

- this is conversion of an existing passkey wallet;
- exact wallet name, address, and public-key fingerprint;
- the existing passkey will remain the authority credential;
- legacy policy is not imported; and
- completion creates Triad WKEK custody and consumes the staged import.

### 5.3 Browser completion

The Broker page calls `navigator.credentials.get` with the Signer-provided
challenge, credential ID, and legacy PRF salt. It HPKE-encrypts only the raw PRF
output to Signer under the existing custody AAD and submits:

- the raw WebAuthn assertion; and
- the HPKE envelope containing a closed payload such as
  `{ "credential_prf": "..." }`.

The browser never receives `encrypted.key`; the private staging record remains
inside Signer's filesystem boundary.

### 5.4 Signer conversion

Signer performs the following order exactly:

1. Re-load and re-hash the staged bundle.
2. Verify ceremony, operation, input-class, expiry, nonce, and digest bindings.
3. Verify the WebAuthn assertion and UV against the staged credential before
   consuming the PRF output.
4. Open the HPKE payload and require exactly one 32-byte PRF output.
5. Derive the legacy wrap key with
   `blake3::derive_key("bloom passkey wrap key", prf_output)`.
6. Decrypt `PasskeyEncrypted v1` with ChaCha20-Poly1305 and AAD
   `bloom-keystore-passkey`.
7. Validate the resulting 32-byte secp256k1 key against both staged public
   projections.
8. Generate fresh WKEK, policy-signing key, recovery material, and current
   custody nonces inside Signer.
9. Create the current encrypted root, credential-specific WKEK wrap, backend
   enrollment, restrictive initial policy, public `KeyRef`, and custody result.
10. Commit all durable wallet, credential, backend, policy, operation, and audit
    effects through one crash-consistent commit protocol and durable commit
    marker. Nothing becomes publicly visible before that marker.
11. Zeroize the PRF output, legacy wrap key, plaintext private key, WKEK, and
    other temporary secrets on every success and error path.
12. Mark the staged record consumed and remove its private files only after the
    durable commit is recoverable through `custody.result`.

No partially imported wallet may become visible. Failure before commit leaves
the staged record retryable; failure after commit reconciles to the committed
result without re-running decryption.

## 6. Repository work

### 6.1 `bloom-signer`

- Add an isolated `legacy_passkey_v1` parser/decryptor module.
- Add pending/consumed migration staging records and the small staging binary.
- Teach `wallet.import_prepare` to branch on the closed input class:
  existing raw-key registration or staged legacy assertion.
- Reuse the existing HPKE, WebAuthn verification, WKEK custody, backend
  provisioning, policy, audit, operation-idempotency, and result machinery.
- Ensure only current WKEK custody is loaded during normal startup/signing.
- Add a fixture generated from the historical algorithm without importing the
  old Bloom crates.

### 6.2 `bloom-broker`

- Render the legacy migration review and existing-credential assertion options.
- Make the browser produce the PRF-only encrypted input for the legacy class.
- Keep Broker ignorant of legacy ciphertext and plaintext key material.
- Add completion/retry/cancel/status tests through existing methods.

### 6.3 `bloom`

- Add the explicit CLI entry point that consumes only the public staging
  receipt and invokes existing `wallet.import_prepare`.
- Do not restore `bloom-keystore`, legacy passkey crypto, credential parsing,
  private key types, or legacy directory access to Machine.
- Update local integration documentation to enroll an existing wallet through
  this conversion rather than requiring a raw key.
- Keep production Machine's MI-07 negative tests: ordinary startup and wallet
  projection paths must still never open legacy authority state.

### 6.4 Packaging

- Install the staging binary with the Signer artifacts.
- Give it only the explicit administrative invocation described above; do not
  add a daemon, privileged helper, background scan, or automatic home-directory
  traversal.
- Add only minimal invocation/documentation to the macOS and Linux packaging;
  installation scripts remain within their existing size constraints.

## 7. Specification amendments

Amend the normative documents before or with implementation:

1. Preserve the clean break for Machine and all legacy approval/session state.
2. Add one exception: Signer may perform an explicit, user-authorized,
   one-time import of the supported v1 passkey envelope into current WKEK
   custody.
3. State that this exception does not authorize Machine legacy reads, a legacy
   signing backend, silent startup migration, or permanent dual-format custody.
4. Add acceptance criteria for existing-credential migration, address
   preservation, atomic conversion, idempotent retry, and secret confinement.

The historical first-unlock migration plan is not reinstated literally:
Machine no longer owns unlock. Its intent is restored at the correct Signer
boundary.

## 8. Test plan

### Unit and vectors

- Parse one valid historical ES256 credential and v1 encrypted envelope.
- Legacy KDF/AEAD golden vector decrypts to the expected key.
- Wrong PRF, nonce, AAD, version, key length, curve, credential schema, address,
  or public key fails closed.
- Legacy user-handle reconstruction has a golden vector, and a mismatched
  assertion user handle is rejected.
- Parser rejects unknown fields, symlinks, special files, oversized inputs, and
  staging races.
- Secret-bearing types do not implement `Debug`, and zeroization/error-path
  tests cover every temporary secret.

### Signer integration

- Existing credential assertion plus PRF converts the fixture to WKEK custody.
- The resulting address and root `KeyRef` match the legacy wallet.
- Normal Sealed Approval and signing work after restart using only current
  custody files.
- Credential add/replace/recovery and Petal child derivation work after import.
- No legacy file is consulted after commit.
- Exact retry returns the same result; changed operation/digest/input fails.
- Crash before commit is retryable; crash after commit reconciles without a
  duplicate wallet/backend/policy.
- A destination collision and credential collision fail without mutation.

### Broker and end-to-end

- The review identifies migration and the policy reset precisely.
- Wrong origin, RP ID, challenge, credential, UV, counter, PRF, HPKE AAD,
  operation, or expiry fails.
- Cancel/status/result remain generic and work for the migration operation.
- Logs, error messages, audit rows, process arguments, environment, public
  receipt, Machine state, and Broker state contain no raw PRF or private key.
- Package test stages a historical fixture, completes a passkey ceremony,
  restarts all three services, signs through Broker, and proves the legacy
  source can be absent afterward.
- A manual macOS test converts a copy of an existing wallet before attempting
  any live transaction. The source wallet is never modified during this test.

### Regression

- Raw-key `wallet.import_prepare` remains functional and distinct.
- Fresh wallet registration is unchanged.
- All three repositories' unit, integration, Clippy, formatting, and packaging
  tests pass locally; GitHub CI is confirmation, not a polling dependency.

## 9. Work sequence

1. Amend the two normative specs and add acceptance criteria.
2. Land Signer's bounded legacy parser, golden vectors, and staging records.
3. Land the staging binary and public receipt.
4. Extend Signer's existing wallet-import ceremony branch and atomic commit.
5. Extend Broker review/browser behavior for the closed input class.
6. Add Bloom's public-receipt CLI initiation and documentation.
7. Run cross-repository unit and negative tests.
8. Run packaged macOS integration with a copied real wallet, then verify
   post-restart approval/signing and absence of legacy runtime reads.
9. Only after verification, document optional archival/removal of the original
   legacy directory.

## 10. Completion criteria

The work is complete only when:

- an existing v1 passkey wallet is converted without asking for or displaying
  its raw private key;
- the existing passkey authorizes the conversion;
- the imported wallet preserves its address and can sign after full restart;
- only Signer handles the legacy ciphertext, PRF output, and plaintext key;
- the durable result contains only current WKEK custody;
- Machine still contains no legacy keystore/signing implementation and never
  opens the source directory;
- Broker contains no legacy decryption or private-key handling;
- replay, mismatch, tamper, crash, and partial-commit tests fail closed; and
- the original wallet remains untouched until the user explicitly chooses to
  archive or remove it.
