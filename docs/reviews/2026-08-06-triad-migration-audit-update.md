## Executive summary

Most previously reported triad migration regressions are now fixed, including the original Hyperliquid signing break, root-key selection, atomic Petal batch signing, Polymarket policy ownership, operation cancellation, and integration-state isolation.

However, the migration still leaves two user-visible paths stranded:

1. The documented mounted wallet-registration workflow does not match the implemented VFS contract.
2. Exact Petal operations become unrecoverable under the same identity after their five-minute approval state expires.

There is also one low-severity contract pin drift and one AWS multi-key concern requiring runtime confirmation.

## Confirmed regressions

### Medium — Mounted wallet-registration instructions cannot complete

- **User-visible symptom:** Following the mounted documentation causes the initial write to fail. Even if JSON is supplied, the documented status and cancellation paths return not found.
- **Previously working behavior:** `/wallets/new` accepted a simple wallet name and synchronously created a Machine-owned wallet.
- **Exact triad change that caused or exposed it:** Wallet creation became an asynchronous Broker custody ceremony identified by a random operation ID.
- **End-to-end call path:**

  `printf 'main\n' > wallets/new` → handler attempts JSON deserialization → invalid request.

  With valid JSON → Broker prepares ceremony → Machine stores `<random-operation-id>.json` → documentation attempts `registrations/main/...` → not found.

- **Concrete file and line references:**
  - JSON is mandatory: `crates/bloom-vfs/src/handlers/wallets.rs:384`.
  - A random operation ID is generated: `crates/bloom-vfs/src/handlers/wallets.rs:416`.
  - Only operation-ID directories and `status.json`, `result.json`, and `cancel` exist: `crates/bloom-vfs/src/handlers/wallets.rs:1840`.
  - Agent guidance still uses a plain name, `registrations/main`, and a nonexistent `ceremony_url` leaf: `crates/bloom-vfs/src/docs/agent-guidance.md:47`.
  - The embedded README repeats the same invalid workflow: `crates/bloom-vfs/src/docs/README.md:129`.
  - Domain examples do likewise: `docs/examples-domain/03-wallets-simulate-watch.md:15`.
- **Why existing tests failed to catch it:** The handler test uses correct JSON and discovers the operation ID by listing `registrations`. Documentation tests merely assert that the text contains `wallets/registrations/` and `status.json`; `crates/bloom-vfs/src/router.rs:573` explicitly enshrines the incorrect `<name>` terminology.
- **Smallest appropriate fix:** Correct all mounted examples to write the documented JSON schema, list `wallets/registrations`, select the operation whose `status.json.requested_name` matches, and read the URL from `status.json`. Document the `cancel` confirmation values explicitly.
- **Focused regression test:** Execute every documented registration command against the real handler and prove preparation, operation discovery, status read, cancellation, and result recovery.

### Medium — Expired exact Petal approvals cannot be restaged under the same action identity

- **User-visible symptom:** If an exact signing ceremony is not completed within five minutes, retrying the same Hyperliquid or Polymarket action continues to fail with “stage a new action.” For deterministic Petal operations, the “new action” resolves to the same expired Machine state.
- **Previously working behavior:** Legacy signing did not leave a Machine-owned deterministic approval record permanently blocking the same payload.
- **Exact triad change that caused or exposed it:** Machine now owns exact Petal approval orchestration and persists it under a deterministic request ID.
- **End-to-end call path:** Petal exact signing → deterministic request ID from package, route, wallet, class, hash, and claim → state written with five-minute expiry → expiry passes → retry produces the same request ID and state path → Machine rejects it before contacting Broker.
- **Concrete file and line references:**
  - Request identity is deterministic: `crates/bloom-daemon/src/lib.rs:455`.
  - Scalar state receives a fixed TTL: `crates/bloom-vfs/src/exact_signing.rs:250`.
  - Scalar retry fails without renewal: `crates/bloom-vfs/src/exact_signing.rs:283`.
  - Batch signing has the same behavior: `crates/bloom-vfs/src/exact_signing.rs:438` and `:464`.
  - The owner projection is read-only, so it provides no retirement or renewal operation: `crates/bloom-vfs/src/handlers/petal_signing_requests.rs:174`.
  - Polymarket deliberately drops an expired hint but resubmits the same prepared payload and deterministic claim: `../bloom-petal-polymarket/route/src/approval.rs:90`.
- **Why existing tests failed to catch it:** Exact scalar and batch tests cover preparation, active approval, retry, tamper rejection, and URL confidentiality, but never advance beyond the persisted Machine expiry.
- **Smallest appropriate fix:** When an identity-matching state has expired, atomically retire it and prepare fresh approval/signing operation IDs with a new TTL. Do not relax payload, claim, provenance, or exact-selector comparisons.
- **Focused regression test:** Prepare scalar and batch operations, advance beyond expiry, retry identical bytes, and assert that a fresh Broker approval is prepared while altered bytes still fail.

### Low — Bloom remains pinned to the obsolete Petal contract revision

- **User-visible symptom:** `bloom petals build` reports the WIT digest from the old hash-signing contract even when validating a v0.4 payload-signing component.
- **Previously working behavior:** Bloom and the canonical Petal SDK used the same contract revision and therefore reported the same WIT tree.
- **Exact triad change that caused or exposed it:** Petal moved its canonical WIT to `bloom:sign/signing@0.4.0`, but Bloom added host support manually without updating its `bloom-petal-contract` pin.
- **End-to-end call path:** `bloom petals build` → `bloom_petals::package::contract_wit_digest()` → pinned `bloom-petal-contract` commit `4f6fb57` → obsolete WIT digest.
- **Concrete file and line references:**
  - Bloom still pins Petal commit `4f6fb57`: `Cargo.toml:123`.
  - The build command prints that dependency’s digest: `crates/bloom/src/main.rs:2535`.
  - The current Petal contract declares signing v0.4 and key derivation: `../petal/src/lib.rs:8`.
  - Its current WIT is the approval-safe payload/batch interface: `../petal/wit/route/deps/sign-v0.4/sign.wit:1`.
- **Why existing tests failed to catch it:** Bloom’s host-shape tests validate its hand-written v0.4 parser/linker, not that `contract_wit_digest()` comes from the same revision as public SDK consumers.
- **Smallest appropriate fix:** Update Bloom’s Petal contract pin and lockfile to `42bd25589ff721ce14f43f21e9eaf702bfbc42e5`.
- **Focused regression test:** Assert Bloom’s reported contract digest and signing interface equal those from the SDK revision used to build Hyperliquid and Polymarket.

## Likely regressions requiring runtime confirmation

### Medium — Valid multi-key AWS wallets may become undiscoverable

- **User-visible symptom if confirmed:** After enrolling a second independent KMS key, `wallet.get_public` fails with `KEYREF_MISMATCH`, which would also strand CLI/VFS projection and exact signing.
- **Previously working behavior:** The normative architecture permits an AWS wallet to enroll multiple independent KMS keys because AWS KMS does not support hierarchical derivation.
- **Exact triad change that caused or exposed it:** The new Signer key-role projection labels every non-derived key as `WalletRoot`, while Broker requires exactly one root.
- **End-to-end call path:** Second independent KMS enrollment → `key.list_public` returns two non-derived keys → Signer classifies both as wallet roots → Broker `unique_wallet_root` rejects the wallet → Machine cannot project or sign for it.
- **Concrete file and line references:**
  - The normative spec permits multiple independent KMS keys: `docs/specs/2026-07-23-triad-process-architecture.md:469`.
  - Signer classifies solely from `derivation.is_some()`: `../bloom-signer/crates/bloom-signer/src/service.rs:720`.
  - Broker rejects multiple roots: `../bloom-broker/crates/bloom-broker/src/service.rs:1392`.
- **Why existing tests failed to catch it:** Root-role tests cover one root plus one derived key and deliberately verify that two projected roots fail. They do not cover multiple independent AWS keys with one explicitly designated wallet root.
- **Evidence still missing:** A production-shaped test enrolling two independent AWS KMS KeyRefs into one wallet and then calling `wallet.get_public`.
- **Smallest likely fix:** Persist explicit wallet-root identity rather than deriving authority role from the presence or absence of a derivation path.
- **Focused regression test:** One root plus independent KMS signing keys must remain projectable, while zero or multiple explicitly designated roots fail closed.

## Checked and not regressed

- Signer exposes explicit root/derived roles; Broker projects `root_key_ref`; Machine selects and verifies it rather than relying on key ordering.
- Exact Petal signing now uses payload-bearing Broker/Signer requests, Machine-owned exact approval state, and owner-only ceremony URLs.
- Petal SDK v0.4 provides scalar and atomic ordered-batch signing without exposing launch secrets.
- Hyperliquid pins SDK `42bd255`, uses exact payload signing, and retains random application agent keys only in its private Petal store.
- Polymarket pins the same SDK, uses atomic payload batches, validates returned signatures, and keeps venue settings in Petal-owned storage rather than interpreting Broker policy.
- Hyperliquid and Polymarket are absent from production defaults until compatible releases exist. Current defaults are Near Intents and Enso.
- The integration runner preserves canonical `~/.bloom` Machine configuration and packages, uses a disposable Machine overlay, and keeps developer Broker/Signer state under `~/.bloom/triad-dev`.
- Broker `operation.cancel` is now exposed through the Machine client and both Bloom CLIs with the intended pre-acceptance semantics.
- The actual wallet-registration handler correctly rejects secret input and supports status, result, and cancellation once the operation ID is known.
- `bloom-service-runtime` remains neutral; changes since Bloom’s pinned revision are test/CI-only.
- Near Intents does not use legacy signing authority; its random-byte use is ordinary application randomness.

## Verification performed

Passed locally:

- Petal workspace tests.
- Hyperliquid: 19 tests.
- Polymarket: 83 tests.
- `bloom-service-runtime`: 54 tests.
- Bloom v0.4 contract-shape and confidentiality tests.
- Bloom exact approval retry test.
- Mounted registration handler test.
- Triad authority fixture tests.
- Preinstalled-Petal configuration test.
- Broker and Signer root-role tests.
- Machine operation-cancellation test.
- Local integration runner regression suite.

## Prioritized remediation order

1. Renew or safely retire expired exact-signing state.
2. Correct the mounted registration documentation and add executable documentation coverage.
3. Update Bloom’s Petal contract pin and digest.
4. Run the multi-key AWS projection test; only change root metadata if it reproduces the predicted failure.

The main Hyperliquid/SDK/Polymarket migration is now sound. The remaining issues are narrower, but the first two are genuine user-facing recovery and discoverability failures.
