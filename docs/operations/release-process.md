# Release process

## Overview

Releases are tag-driven. A `vX.Y.Z` push to a release branch triggers
the `release.yml` workflow, which:

1. Validates the tag shape.
2. Checks out the tag, bumps the workspace version to `X.Y.Z` in
   `Cargo.toml` and `Cargo.lock`, commits the change to a
   `release/vX.Y.Z` branch, and pushes that branch.
3. Builds the `bloom` binary on four runners (Linux x86_64 + aarch64,
   macOS x86_64 + aarch64) from the release branch with `--locked`.
4. Verifies the resulting binary's `bloom --version` matches the tag.
5. Creates a GitHub release `vX.Y.Z` with the four tarballs and a
   `SHA256SUMS` file. Sets `--latest` so the GitHub UI badge follows
   the highest semver tag.

The floating `latest` git tag is intentionally NOT created by the
workflow. It is owned by the old (now-retired) branch-driven
`release.yml`. The legacy `Latest master build` release and the
`latest` tag are removed in the cutover step below. **Until that
cutover, `/releases/latest/download/...` continues to work because
the legacy tag still exists and powers the download redirect.**

## Local release (recommended for the first cutover)

The first `vX.Y.Z` release after this workflow lands is the cutover.
Run it locally so you can verify the build before pushing the tag:

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

# 5. Commit + tag + push.
git add Cargo.toml Cargo.lock
git commit -m "release: v$VERSION"
git tag "v$VERSION"
git push origin master
git push --tags

# 6. Trigger the workflow. The `bump` job will see that the version
#    bump is already in master and is a no-op; the `build` matrix
#    will checkout `release/vX.Y.Z` (created by the bump job, or
#    left over from a previous run). If the bump job creates a new
#    release branch, the build will use that.
gh workflow run release.yml --ref master
```

The `publish` job will create the `v$VERSION` GitHub release with
`--latest` set, upload the four tarballs, and generate `SHA256SUMS`.

## CI-only release (subsequent versions)

After the first cutover, the workflow can run end-to-end on its own:

1. Bump the version locally and commit (or let the workflow do it via
   the `bump` job, which edits `Cargo.toml` and pushes a
   `release/vX.Y.Z` branch).
2. Push the `vX.Y.Z` tag to the `master` branch.
3. The `prepare` job validates the tag, the `bump` job updates
   `Cargo.toml` + `Cargo.lock` and pushes the release branch, the
   `build` matrix builds the four binaries, the `publish` job creates
   the release.

## Cutover (one-time, manual)

The legacy `Latest master build` release and the `latest` git tag
must be deleted so that `/releases/latest` (the API endpoint the
UpdateChecker hits) starts returning the highest `vX.Y.Z` release
instead of the floating one. After the first `vX.Y.Z` ships:

```bash
# 1. Delete the legacy release. This removes the API-side "latest"
#    so the next API call returns the highest vX.Y.Z.
gh release delete latest --yes

# 2. Delete the floating git tag. This is purely a download-side
#    cleanup — after this, /releases/latest/download/... will start
#    returning a 404 until you add a new git tag named "latest" (we
#    don't plan to; users should use the versioned URL).
git push origin :refs/tags/latest
```

**The cutover is irreversible from the UI side** (GitHub doesn't let
you restore a deleted release's UI badge). After this, the only
"latest" pointer is whichever `vX.Y.Z` release has `--latest` set,
which the workflow does by default.

## Verifying the UpdateChecker

After the cutover, the daemon's `/status/update` subtree should be
meaningful. Verify from any machine running the binary:

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

If `bloom update check` exits with `error: http 404`, the API is
returning 404 because (a) no `vX.Y.Z` release exists yet, or (b) the
release was created without `--latest`. Fix (a) by tagging a version;
fix (b) by running `gh release edit vX.Y.Z --latest`.

## What is intentionally NOT in the workflow

- **`cargo install cargo-edit`**: not needed. `sed` is faster and
  doesn't need a fresh toolchain.
- **`--config 'package.version="X.Y.Z"'`**: doesn't exist in Cargo.
  Verified against the Cargo configuration reference.
- **A floating `latest` git tag**: removed in the cutover. The
  versioned URL is the canonical source.
- **Cross-compiled builds**: each runner builds natively (`cargo
  build --release` without `--target`), matching the previous
  workflow. Cross-compilation is a separate effort.
- **Windows builds**: intentionally out of scope. Historical commit
  `cce4250 remove Windows release builds` removed them; the current
  CI has no Windows tests.
- **`bloom update install`**: not implemented. Atomicity, macOS
  SIP/Gatekeeper, and Windows self-overwrite are unsolved. Users
  download a new release manually.
