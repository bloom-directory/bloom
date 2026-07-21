# Pre-installed Petals and Native Polymarket Removal

**Status:** Implementation specification
**Date:** 2026-07-20
**Primary PR:** bloom-directory/bloom#107

## Summary

Bloom will support a defined list of Petals that are provisioned as part of the
normal initialization lifecycle. Polymarket will be the first default
pre-installed Petal. Once that replacement is proven available, Bloom will
remove its duplicate native Polymarket crate, CLI commands, root VFS handler,
daemon-owned venue state, and venue-specific signing path.

The PR branch will be reconstructed on current `master` rather than conventionally
rebased. Its historical merge base predates the squash merge of the Petal
platform, so replaying the complete branch produces a misleading changeset and
dozens of false conflicts.

## Goals

1. Make PR #107 show only changes that are not already present on `master`.
2. Preserve the Bloom-side host functionality required by the parity-capable
   external Polymarket Petal, including resilient signing workflows.
3. Provision the external Polymarket Petal automatically during Bloom
   initialization.
4. Make the default pre-installed set explicit and persistently configurable.
5. Remove the duplicate native Polymarket implementation without removing the
   wallet policy schema consumed by the Petal.
6. Preserve safe, deterministic, idempotent, and reviewable installation
   behavior.

## Non-goals

- A general third-party marketplace or automatic update service.
- Silently upgrading or replacing a Petal that the operator installed
  explicitly.
- Performing network installation during every `Daemon::from_home` call or
  every read-only CLI invocation.
- Retaining compatibility aliases for `bloom polymarket` or `/polymarket`.
- Publishing a release or tag in the external Petal repository as part of this
  PR. The built-in entry may pin the immutable parity merge commit until a
  release tag is available.

## Branch reconstruction

Reconstruct `feat/remove-polymarket-native` from current `origin/master` and
force-update it with `--force-with-lease` so PR #107 and its discussion remain
intact.

Port only the logical work represented by:

- `47efcdf` — Polymarket Petal parity host support;
- `fba690d` — resilient Petal signing workflows;
- `37131ea` — native Polymarket removal.

The Petal platform and documentation have diverged since those commits. Port
behavior against current APIs instead of mechanically accepting historical
file versions. Regenerate derived files such as `Cargo.lock`.

The resulting commit sequence should be reviewable:

1. required Petal host parity and signing behavior;
2. default pre-installed Petal provisioning;
3. removal of native Polymarket and documentation migration.

## Configuration

Extend `PetalsConfig` with an explicit list:

```toml
[petals]
preinstalled = ["polymarket"]
```

Semantics:

- The local default contains `polymarket`.
- An explicitly configured empty list is a persistent opt-out.
- Names must resolve through Bloom's built-in pre-installed catalog; unknown
  names are rejected during configuration validation.
- Existing `petals.runtime.<name>` endpoint and value overrides remain
  independent of whether a Petal is pre-installed.
- The wallet policy `[polymarket]` schema remains supported.
- Native `[polymarket]` daemon integration configuration is removed with the
  native integration.

## Built-in catalog

Define a small typed catalog in the Bloom CLI implementation. Each entry
contains:

- stable catalog name;
- trusted GitHub repository URL;
- immutable Git commit;
- immutable release tag and archive filename;
- expected Petal mount/name;
- expected package hash when a stable reproducible hash is available.

The initial `polymarket` entry points to
`bloom-directory/bloom-petal-polymarket` at the parity-capable merge commit
`e2e898b69046c9f5d905dd2cd66b3a57ef195542` and its repository-owned `v0.1.3`
release. A newer immutable release may replace that pin only through a reviewed
catalog update that names its exact source commit and artifact.

The catalog also contains the NEAR Intents Petal at
`bloom-directory/bloom-petal-near` release `v0.1.0`. It is available for an
explicit `petals.preinstalled = ["near-intents"]` configuration but is not part
of the default set.

The catalog is deliberately not arbitrary user-controlled source execution.
Manual `bloom petals install` remains the interface for other trusted sources.

## Provisioning lifecycle

Provision configured pre-installed Petals during `bloom init`. If `bloom serve`
can create a fresh home without initialization, it must either run the same
provisioning preflight or fail with an actionable instruction to run
`bloom init`; it must not silently serve a default configuration that promises
Polymarket while omitting it.

Provisioning must:

1. Load and validate the configured pre-installed names.
2. Inspect authoritative installed Petal ownership records.
3. Do nothing when the expected Petal is already installed.
4. Refuse to silently overwrite a differently sourced or differently versioned
   Petal with the same mount name; report the mismatch and remediation.
5. Download the checksum and provenance-verified archive from the Petal
   repository's exact catalogued release. Bloom must not build a default Petal
   from source during setup.
6. Verify the release tag, archive checksum, Petal name, source repository and
   commit, Petal tooling commit, package hash, endpoint bindings, and installed
   provenance before reporting success.
7. Be safe to rerun after success or a partial acquisition failure.

Normal daemon construction, status commands, VFS reads, and tests that create a
temporary `HomeDir` must not unexpectedly access the network.

The `bloom-directory/petal` repository owns the canonical packaging command and
reusable release workflow. Each Petal repository invokes that workflow from a
thin, immutable-pin workflow and publishes its own archive, `SHA256SUMS`, and
`petal-release.json`. Bloom's release workflow builds only Bloom binaries.

Installing Bloom therefore does not require a local Rust toolchain. A
downloaded Petal archive must fail closed if its filename-bound checksum,
release manifest, package structure, Petal name, endpoint bindings, source
commit, tooling provenance, or recorded package provenance does not match the
catalog entry.

## Native Polymarket removal

After provisioning is implemented and tested:

- remove `crates/bloom-polymarket` from the workspace and dependency graph;
- remove `bloom polymarket ...`;
- remove the `/polymarket` VFS handler and daemon mount;
- remove daemon IPC/configuration/state paths owned solely by the native
  integration;
- remove the native first-party Polymarket signing/attestation exception;
- retain generic Petal HTTP, chain-read, storage, signing, transaction outbox,
  and Sealed Approval paths;
- retain the wallet Polymarket policy schema used by the external Petal;
- direct documentation and agent guidance to the installed route tree and
  `/petals/polymarket/meta/route-contract.json`.

The recently added native `[polymarket] enabled = false` opt-out is superseded
by `petals.preinstalled = []`. Loading an existing config must preserve that
legacy explicit opt-out when `petals.preinstalled` has not yet been set; an
explicit new pre-installed list takes precedence.

## User-visible behavior

For a fresh default home:

```sh
bloom init
bloom petals ls
bloom vfs cat /petals/polymarket/meta/route-contract.json
```

The list and route-contract read must show the installed external Petal without
a separate manual installation command.

The package's immutable operator and agent documents are also exposed directly
through the Petal mount:

```sh
bloom vfs cat /petals/polymarket/README.md
bloom vfs cat /petals/polymarket/AGENTS.md
```

These files come from the installed content-addressed package and are read-only;
they do not dispatch through Petal-supplied WASM routes.

For an opted-out home:

```toml
[petals]
preinstalled = []
```

`bloom init` must not install Polymarket, and subsequent initialization must
continue respecting the opt-out.

Installation failures must name the catalog entry, repository/ref, failure
stage, and a safe retry command. They must not claim initialization completed
with Polymarket available.

## Testing

Add deterministic tests covering:

- default configuration includes `polymarket`;
- explicit empty-list opt-out survives TOML round trips;
- unknown catalog names fail validation;
- reconciliation installs a missing catalog entry;
- reconciliation is idempotent;
- explicit opt-out performs no installation;
- an existing matching installation is retained;
- a conflicting existing owner/version is not overwritten;
- repository/release/ref/name/hash verification rejects mismatches;
- release checksum verification is bound to the expected archive name and
  rejects missing or tampered entries;
- release manifest verification rejects the wrong repository, source commit,
  tag, archive, package hash, or tooling provenance;
- a valid prebuilt archive installs without invoking a source build;
- package `README.md` and `AGENTS.md` are readable and immutable at the Petal
  mount root;
- failed installation is retryable and leaves no authoritative partial owner;
- initialization reports the pre-installed Petal;
- the Polymarket route contract is dispatchable after installation;
- native CLI parsing rejects `bloom polymarket`;
- the root VFS has no `/polymarket` handler;
- wallet `[polymarket]` policy still parses and enforces its constraints.

Normal test suites must use local fixtures or an injected installer and must
not depend on GitHub. Keep one ignored live-source contract test pinned to the
catalog ref.

## Verification

Before updating the PR:

```sh
cargo fmt --all -- --check
git diff --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
cargo test --workspace --doc --no-fail-fast
```

Also run the focused CLI, configuration, Petal, daemon, VFS, transaction, and
authentication suites affected by the port.

Use `git range-diff` and the GitHub PR changeset after the force-update to
confirm that the squash-merged Petal platform is no longer presented as new
work.

## Review gate

After implementation and primary verification, an adversarial sub-agent must
review the complete code changes and PR #107. The reviewer should be practical
and risk-focused, checking:

- the reconstructed delta is honest and minimal;
- CI commands and relevant focused tests pass;
- tests exercise failure and opt-out behavior rather than only happy paths;
- supply-chain pinning and provenance checks are meaningful;
- initialization cannot falsely report Polymarket as installed;
- operators can persistently opt out;
- native behavior is actually removed while wallet policy remains;
- no conflict marker, stale documentation, or accidental unrelated change
  remains.

Actionable findings must be fixed and re-verified before the goal is marked
complete.
