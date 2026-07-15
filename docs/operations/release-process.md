# Release process

## Overview

Releases can start from a `vX.Y.Z` tag push or from a manual workflow
dispatch. The `release.yml` workflow:

1. Validates the tag shape.
2. If the tag already exists, verifies that its commit already has
   workspace version `X.Y.Z`. If a manual run names a new tag, bumps
   `Cargo.toml` and `Cargo.lock`, commits the change, and creates the
   tag at that commit.
3. Mirrors the tagged commit to `release/vX.Y.Z`, then builds the exact
   commit SHA on four runners (Linux x86_64 + aarch64, macOS x86_64 +
   aarch64) with `--locked`.
4. Verifies the resulting binary's `bloom --version` matches the tag.
5. Verifies the tag still resolves to the built SHA, then creates a
   GitHub release `vX.Y.Z` with the four tarballs and a `SHA256SUMS`
   file. Sets `--latest` so GitHub's latest-release links follow it.

The floating `latest` git tag is intentionally NOT created by the
workflow. It is owned by the old (now-retired) branch-driven
`release.yml`. The legacy `Latest master build` release and the
`latest` tag are removed in the cleanup step below. GitHub's
`/releases/latest/download/...` route follows the release marked
latest; it does not require a git tag literally named `latest`.

## Local release (recommended for the first versioned release)

Run the first `vX.Y.Z` release locally so you can verify the build
before pushing the tag:

```bash
# 1. Decide on the version. For a first release from the existing
#    master at workspace version 0.1.0, this is likely 0.1.1 (a
#    small bump that signals "first proper release") or 0.2.0
#    (signals "now we have update checks + the workflow"). Pick
#    deliberately and document the choice in the PR description.
VERSION="0.1.1"

# 2. Bump the workspace version. `sed` is enough — every member
#    crate uses `version.workspace = true` and picks up the new
#    number at compile time. `cargo update --workspace` regens the
#    lockfile (only touches the 26 workspace member version fields,
#    no transitive dep churn — verified empirically).
sed -i -E "s/^version = \"[0-9]+\\.[0-9]+\\.[0-9]+\"/version = \"$VERSION\"/" Cargo.toml
cargo update --workspace

# 3. Sanity: diff is exactly Cargo.toml + Cargo.lock, ~52 lines.
git diff --stat

# 4. Build and verify the binary.
cargo build --release -p bloom --all-features --locked
./target/release/bloom --version    # must print "bloom $VERSION"

# 5. Commit, tag that exact commit, and push.
git add Cargo.toml Cargo.lock
git commit -m "release: v$VERSION"
git tag "v$VERSION"
git push origin master
git push origin "v$VERSION"
```

The tag push starts the workflow automatically. Because the tag
already points at the version-bumped commit, the prepare job makes no
new commit. The build jobs use that exact SHA, and the publish job
creates the `v$VERSION` release with the four tarballs and
`SHA256SUMS`.

## CI-only release (subsequent versions)

The workflow can also create the release commit and tag itself:

```bash
VERSION="0.1.2"
gh workflow run release.yml --ref master -f tag="v$VERSION"
```

For a new tag, the workflow starts from the repository's default
branch, creates `release: v$VERSION`, tags that new commit, and pushes
`release/v$VERSION`. The build and source archives therefore resolve
to the same commit. The release commit remains on the release branch;
use the local path above when the version bump should also live on
`master`.

If the requested tag already exists, a manual run is treated as a
retry. Its commit must already contain the matching workspace version;
the workflow never moves an existing release tag.

## Legacy cleanup (one-time, manual)

After the first `vX.Y.Z` release is published and marked latest,
GitHub's `/releases/latest` API and download routes point to it. The
legacy `Latest master build` release and floating `latest` git tag can
then be deleted as cleanup:

```bash
# 1. Delete the legacy release whose tag is literally "latest".
gh release delete latest --yes

# 2. Delete its floating git tag.
git push origin :refs/tags/latest
```

The stable `/releases/latest/download/...` URLs continue to work: they
follow the `vX.Y.Z` release marked latest, independently of the deleted
floating tag.

## Verifying the UpdateChecker

After the first versioned release, the daemon's `/status/update`
subtree should be meaningful. Verify from any machine running the
binary:

```bash
# First-run: no cache file → available=unknown, latest=empty.
bloom vfs cat /status/update/available    # → unknown\n
bloom vfs cat /status/update/latest       # → \n

# After 5 minutes (or after `bloom update check`): the snapshot
# should be populated.
bloom update check                         # prints snapshot as JSON, exit 0/1/2
bloom vfs cat /status/update/latest        # → e.g. "0.1.1\n"
bloom vfs cat /status/update/available     # → out_of_date | up_to_date
```

Before the first versioned release, GitHub may return the legacy tag
`latest`. That is a successful HTTP response but not semver, so
`bloom update check` reports `available: unknown` and exits 2 rather
than claiming the binary is up to date. An HTTP 404 means no eligible
published release exists yet.

## What is intentionally NOT in the workflow

- **`cargo install cargo-edit`**: not needed. `sed` is faster and
  doesn't need a fresh toolchain.
- **`--config 'package.version="X.Y.Z"'`**: doesn't exist in Cargo.
  Verified against the Cargo configuration reference.
- **A floating `latest` git tag**: removed during legacy cleanup. The
  versioned URL is canonical, while GitHub's latest-release URL remains
  a stable convenience alias.
- **Cross-compiled builds**: each runner builds natively (`cargo
  build --release` without `--target`), matching the previous
  workflow. Cross-compilation is a separate effort.
- **Windows builds**: intentionally out of scope. Historical commit
  `cce4250 remove Windows release builds` removed them; the current
  CI has no Windows tests.
- **`bloom update install`**: not implemented. Atomicity, macOS
  SIP/Gatekeeper, and Windows self-overwrite are unsolved. Users
  download a new release manually.
