# External Petal Repositories and GitHub Source Installs

Status: draft requirements
Date: 2026-06-24
Scope: next stage of Petal development after the in-repo Polymarket example.

---

## 0. Summary

The Polymarket Petal should move out of `examples/local-petal-petals/` into a
separate GitHub repository named `bloom-petal-polymarket`.

Bloom should then be able to install Petals directly from trusted GitHub
source repositories:

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket
```

This stage is source-first. The GitHub repository is the distribution unit.
Bloom should not require or consume GitHub Release assets for Petal installs,
and it should not install raw `.wasm` blobs directly from a URL. Route artifacts
may still be generated locally during the install/build process, but generated
`.wasm` files are build output, not the published source-of-truth.

The initial trust model is deliberately simple: repositories under the trusted
GitHub organization are accepted as trusted source. Stronger provenance,
signatures, attestations, and third-party registries are deferred.

---

## 1. Goals

1. **Extricate Polymarket from Bloom.** Move the full Polymarket Petal source
   into `bloom-directory/bloom-petal-polymarket` and delete the in-repo
   Polymarket example/package sources.
2. **Install from GitHub source.** Extend the existing `bloom petals install`
   command so it accepts trusted GitHub repository URLs in addition to local
   Petal package directories and `.petal.tar` archives.
3. **Build locally from source.** Installing a GitHub Petal repository clones or
   fetches source, checks out a selected ref, builds the Petal package locally,
   validates it with the normal Petal package pipeline, and installs the resulting
   content-addressed package.
4. **Prefer tagged source.** By default, GitHub installs should resolve to the
   latest SemVer-like tag when the repository has tags. Installing the default
   branch should be explicit.
5. **Keep Petal-only semantics.** External Petal repos must produce Petal
   packages only. No v1 raw-WASM Petal support, compatibility dispatch, or
   legacy native handler delegation should be reintroduced.
6. **Preserve Polymarket parity.** The external Polymarket Petal must keep
   feature parity with the current Petal implementation before the in-repo example
   is removed.
7. **Make CI own the contract.** Bloom CI and the external Polymarket repo CI
   must prove that source installs, local source builds, package validation, and
   `/petals/polymarket` dispatch continue to work.

---

## 2. Non-goals

- Installing arbitrary raw `.wasm` files from GitHub.
- Relying on GitHub Release assets as the Petal distribution mechanism.
- A public Petal registry or search index.
- Cryptographic release signing, Sigstore, SLSA attestations, or package
  transparency logs.
- Supporting non-GitHub remote source providers in the first implementation.
- Supporting untrusted user-supplied build scripts without an explicit trust
  decision.
- Keeping an in-repo Polymarket example after the external repo is live.

---

## 3. Repository Creation

Implementation should create the repository with `gh`:

```sh
gh repo create bloom-directory/bloom-petal-polymarket --private --description "Polymarket Petal app for Bloom" --clone=false
```

If the intended visibility is public at launch, use `--public` instead of
`--private`. The implementation should not assume the repository already exists.

The repository should be initialized from the current in-repo source, preserving
history where practical but not at the cost of a complicated split. A clean
initial import is acceptable.

---

## 4. External Petal Repository Shape

The Polymarket repository root should be the Petal source root.

Required root files:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- `.gitignore`
- a build entrypoint declared by the source-build contract below

Recommended root layout:

```text
bloom-petal-polymarket/
  petal.toml
  README.md
  AGENTS.md
  .gitignore

  app/
    polymarket/
      ... generated route artifacts, ignored by git ...

  route/
    Cargo.toml
    Cargo.lock
    src/lib.rs
    wit/
      route.wit

  wit/
    ... checked-in Bloom/application WIT if needed ...

  scripts/
    build.sh
    validate.sh
```

Generated route components under `petal/polymarket/**/*.wasm` must not be
committed. They are local build output created during `bloom petals install`
and local development validation.

The repository should commit its route crate lockfile so source builds are
reproducible enough for this trust stage.

---

## 5. Source-Build Contract

Bloom needs a deterministic way to turn a trusted source repository into a v2
Petal package. The first implementation should use a package-declared build
command in `petal.toml`.

Example:

```toml
schema = "bloom.petal.package.v1"
name = "polymarket"

[source]
kind = "github"
repository = "bloom-directory/bloom-petal-polymarket"

[build]
command = "scripts/build.sh"
outputs = ["petal/polymarket"]
```

Rules:

- `build.command` is repository-relative.
- The command is executed from the repository root after checkout.
- The command must generate route artifacts under `petal/<name>/`.
- The command must not require network access beyond normal language package
  fetching unless documented in `README.md`.
- The command must fail if required tools are unavailable.
- After the command completes, Bloom runs the same Petal package build/validation
  pipeline used for local package directories.
- Bloom stores the normalized package hash and source provenance together.

For Polymarket, `scripts/build.sh` should replace the current
`external Petal `scripts/build.sh`` and should:

- build the route crate for `wasm32-unknown-unknown`;
- convert the core WASM route artifact into a component using `wasm-tools`;
- validate the component;
- copy it to all expected route paths under `petal/polymarket`;
- leave generated `.wasm` files ignored by git.

This build contract intentionally permits trusted source repositories to run
local build code. The first trust boundary is the GitHub organization, not an
untrusted package sandbox.

---

## 6. GitHub URL Install Behavior

The existing command should be extended:

```sh
bloom petals install <path-or-github-url>
```

Supported URL forms:

```text
https://github.com/bloom-directory/bloom-petal-polymarket
https://github.com/bloom-directory/bloom-petal-polymarket.git
git@github.com:bloom-directory/bloom-petal-polymarket.git
```

Ref selection:

- If `--ref <tag-or-sha>` is supplied, Bloom installs that ref.
- If no ref is supplied and the repository has SemVer-like tags, Bloom installs
  the latest tag.
- If no ref is supplied and the repository has no tags, Bloom must fail with a
  message telling the user to pass `--ref <branch-or-sha>` or publish a tag.
- Installing a branch such as `main` is allowed only through explicit `--ref`.

Recommended CLI:

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket --ref v0.1.0
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket --ref 0123456789abcdef
```

Install steps:

1. Parse the URL and reject unsupported hosts.
2. Verify the owner is trusted. For this stage, `bloom-directory` is trusted.
3. Resolve the ref according to the rules above.
4. Fetch source into a Bloom-controlled cache directory.
5. Record repository URL, owner, repo, requested ref, resolved commit SHA, and
   selected tag if any.
6. Run the repository build command.
7. Validate and install the resulting Petal package.
8. Print the consent summary, source provenance, resolved commit, package hash,
   and installed app root.

The install must fail closed. A failed clone, missing tag, missing build command,
build error, package validation error, or capability-policy violation must leave
the existing installed package state unchanged.

---

## 7. Provenance and Storage

Installed package metadata should record source provenance in addition to the
existing package hash and app metadata.

Minimum provenance fields:

```json
{
  "source_kind": "github",
  "url": "https://github.com/bloom-directory/bloom-petal-polymarket",
  "owner": "bloom-directory",
  "repo": "bloom-petal-polymarket",
  "requested_ref": "v0.1.0",
  "resolved_commit": "0123456789abcdef...",
  "selected_tag": "v0.1.0",
  "package_hash": "..."
}
```

`bloom petals ls` should show enough information to distinguish local installs
from GitHub source installs. A verbose/details mode can expose the full
provenance record if the existing listing is too compact.

The package hash remains the runtime identity. The source provenance explains
where the package came from and enables later update flows.

---

## 8. Polymarket Migration Requirements

The external `bloom-petal-polymarket` repo must provide all behavior currently
provided by the in-repo Polymarket Petal:

- market directory/index/list routes;
- market detail, book, price/midpoint/spread reads;
- search routes;
- positions, trades, and activity reads;
- onboarding begin/status/plan/approvals routes;
- account portfolio/orders routes;
- funding draft/status/request/plan routes;
- trade draft creation and review routes;
- order quote, policy check, review intent, post, receipt, and cancel flows;
- geoblock checks;
- CLOB credential derivation and builder API key support;
- relayer nonce/submit/transaction support;
- private petal-owned state and secret storage;
- Petal signing intents for CLOB auth, order signing, and relayer batches;
- v2 HTTP policy for Gamma, Data API, CLOB, Polymarket geoblock, and relayer
  endpoints;
- v2 host VFS reads/writes where currently required;
- atomic trade lock/idempotency behavior through Petal store operations.

The external Petal must not delegate to any legacy native
`polymarket/...` VFS handler and must not rely on source files under
`examples/local-petal-petals/`.

After external install support lands and the external repo passes parity checks,
remove:

- `examples/local-petal-petals/polymarket/`
- `examples/local-petal-petals/polymarket-route/`
- `external Petal `scripts/build.sh``

Do not replace them with a local Polymarket fixture. Bloom should treat
Polymarket as an external Petal.

---

## 9. CI and Acceptance

`bloom-petal-polymarket` CI should run:

- formatting for the route crate;
- route crate tests;
- route crate clippy;
- source build via `scripts/build.sh`;
- `bloom petals build .` using a checked-out Bloom CLI or released Bloom
  binary;
- package validation;
- a smoke install into a temporary Bloom home when feasible.

Bloom CI should add coverage for:

- installing a Petal from a trusted GitHub URL;
- default latest-tag resolution;
- explicit `--ref <tag>`;
- explicit `--ref <sha>`;
- rejecting unsupported GitHub owners;
- rejecting no-tag repositories without explicit `--ref`;
- rejecting raw `.wasm` URLs;
- rejecting repositories with no `petal.toml`;
- preserving existing installed state when remote build/validation fails;
- recording source provenance;
- serving an externally installed app through `/petals/<name>/`.

Acceptance should include a Polymarket source-install test. To avoid depending
on live GitHub state in normal unit tests, most tests should use a local bare
Git repository fixture or a mocked GitHub resolver. A smaller ignored or
acceptance test may exercise the real `bloom-directory/bloom-petal-polymarket`
repository after it exists.

The acceptance workflow path filters should include any Bloom-side GitHub
install code and should not rely on the deleted `examples/local-petal-petals/**`
paths for Polymarket coverage.

---

## 10. Security Model for This Stage

The first implementation trusts the `bloom-directory` GitHub organization to
publish Petal source. That means source build commands from trusted repos may
execute on the installing machine.

Required guardrails:

- only trusted owners are accepted by default;
- URL parsing must not allow host spoofing;
- branch installs must be explicit;
- install output must display the resolved commit before or during install;
- package validation remains mandatory after build;
- manifest capability policy remains mandatory at runtime;
- generated artifacts are still treated as untrusted and revalidated before
  dispatch;
- install failures must not mutate existing installed package state;
- raw remote `.wasm` installs are rejected.

Deferred hardening:

- signed tags/releases;
- package attestations;
- sandboxed source builds;
- allow-list configuration for additional owners;
- checksum-pinned source installs;
- update audits and rollback UI.

---

## 11. User Experience

Successful install should look roughly like:

```text
Resolving https://github.com/bloom-directory/bloom-petal-polymarket
Selected tag: v0.1.0
Resolved commit: 0123456789abcdef...
Building source package...
Validating Petal package...

Consent:
  Expose Polymarket market reads, onboarding, account views, funding drafts,
  and trade draft/post/cancel flows as a Petal.

Capabilities:
  bloom:http, bloom:store, bloom:sign, bloom:vfs.read, bloom:vfs.write

Installed:
  app: /petals/polymarket
  package hash: ...
  source: bloom-directory/bloom-petal-polymarket@v0.1.0
```

Failure messages should be specific:

- unsupported GitHub owner;
- no tags found, pass `--ref`;
- build command missing;
- build command failed;
- generated package failed Petal validation;
- manifest requests a denied capability or network path.

---

## 12. Implementation Plan

1. Create `bloom-directory/bloom-petal-polymarket` using `gh repo create`.
2. Import the current Polymarket package, route crate, WIT, and build script
   into the new repo.
3. Reshape paths so repo root is the package root and `scripts/build.sh` is the
   standard source-build entrypoint.
4. Add CI to the Polymarket repo proving source build and package validation.
5. Extend `bloom petals install` to parse GitHub URLs and resolve trusted refs.
6. Add source checkout/cache/provenance handling.
7. Add `petal.toml [build]` command support for trusted source installs.
8. Run the normal Petal package validation and install flow after source build.
9. Add Bloom tests for GitHub install behavior using local Git fixtures/mocks.
10. Add acceptance coverage for real Polymarket source install.
11. Delete the in-repo Polymarket example directories and build script.
12. Update docs/guides to describe source installs and the external Polymarket
    Petal.

---

## 13. Acceptance Criteria

This stage is complete when:

- `gh repo view bloom-directory/bloom-petal-polymarket` succeeds;
- the external repo contains the full Polymarket Petal source and no
  committed generated route `.wasm` files;
- the external repo CI builds and validates the Petal from source;
- `bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket`
  installs the latest tagged source version;
- `bloom petals install ... --ref <tag>` and `--ref <sha>` work;
- unsupported GitHub owners and raw `.wasm` URLs are rejected;
- installed package provenance records the GitHub repo and resolved commit;
- `/petals/polymarket` works from the externally installed Petal;
- all in-repo Polymarket example/package source is deleted;
- Bloom CI and acceptance pass without relying on `examples/local-petal-petals/polymarket*`.
