# Release process

## Overview

Releases start from a reviewed version-bump PR followed by a `vX.Y.Z` tag
push. The optional `propose-release.yml` workflow prepares the PR; it never
writes to the default branch, creates a stable tag, or publishes a release.
The `release.yml` workflow:

1. Validates the tag shape.
2. Verifies that the tagged commit is reachable from the default branch and
   already has workspace version `X.Y.Z`.
3. Builds the exact commit SHA on four runner platforms (Linux x86_64 +
   aarch64, macOS x86_64 + aarch64) with `--locked`, including both glibc
   and static musl artifacts for Linux aarch64.
4. Verifies the resulting binary's `bloom --version` matches the tag.
5. Verifies the tag still resolves to the built SHA, then creates a
   GitHub release `vX.Y.Z` with the five tarballs and a `SHA256SUMS`
   file. It advances GitHub's latest-release alias only when this version is
   at least as new as the current latest release; failures resolving that
   release abort publication rather than treating the result as empty.

The floating `latest` git tag is intentionally NOT created by the
workflow. It is owned by the old (now-retired) branch-driven
`release.yml`. The legacy `Latest master build` release and the
`latest` tag are removed in the cleanup step below. GitHub's
`/releases/latest/download/...` route follows the release marked
latest; it does not require a git tag literally named `latest`.

Linux aarch64 releases include two variants. Use
`bloom-linux-aarch64.tar.gz` on glibc distributions and
`bloom-linux-aarch64-musl.tar.gz` on Termux/Android, Alpine Linux, and
minimal Linux systems without glibc. The musl binary is statically linked.

## CI-proposed release

Configure a `RELEASE_PR_TOKEN` repository secret backed by a GitHub App token
or fine-grained token with Contents read/write and Pull requests read/write.
The token is needed because a PR created with `GITHUB_TOKEN` does not receive
the normal pull-request workflow events.

Run **Actions → Propose Release → Run workflow**, enter the next version
without the `v` prefix, and review the generated PR. The workflow updates only
`Cargo.toml` and the workspace metadata in `Cargo.lock`, and refuses to
upgrade unrelated external dependencies. After the PR is merged, push a tag
from the merge commit:

```bash
VERSION="0.1.1"
git switch master
git pull --ff-only origin master
test "$(sed -n -E 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/\1/p' Cargo.toml | head -n 1)" = "$VERSION"
git tag "v$VERSION"
git push origin "v$VERSION"
```

The tag push starts the release workflow. It verifies that the tag points to a
commit reachable from the default branch, that the tag and workspace version
agree, builds that immutable commit, and publishes the release only after all
build jobs pass.

Repository rules should require review before merging the proposal PR and
limit creation or update of `v*` tags to release maintainers. The release
workflow's write token is used only by the publish job for GitHub release
metadata and assets.

## Local release

Run the first `vX.Y.Z` release locally so you can verify the build
before pushing the tag:

```bash
# 1. Decide on the version. For a first release from the existing
#    master at workspace version 0.1.0, this is likely 0.1.1 (a
#    small bump that signals "first proper release") or 0.2.0
#    (signals "now we have update checks + the workflow"). Pick
#    deliberately and document the choice in the PR description.
VERSION="0.1.1"
BRANCH="release-prep/v$VERSION"
git switch master
git pull --ff-only origin master
git switch -c "$BRANCH"

# 2. Bump the workspace version. `sed` is enough — every member
#    crate uses `version.workspace = true` and picks up the new
#    number at compile time. `cargo check --workspace` refreshes only
#    the lockfile metadata required by the version change; it does not
#    proactively upgrade compatible transitive dependencies.
sed -i -E "s/^version = \"[0-9]+\\.[0-9]+\\.[0-9]+\"/version = \"$VERSION\"/" Cargo.toml
cargo check --workspace

# 3. Sanity: the diff is exactly Cargo.toml + Cargo.lock.
git diff -- Cargo.toml Cargo.lock

# 4. Build and verify the binary.
cargo build --release -p bloom --all-features --locked
./target/release/bloom --version    # must print "bloom $VERSION"

# 5. Commit the bump on a release-prep branch and open a PR. Do not
#    push directly to master; the default branch requires its status
#    checks to pass through a PR.
git add Cargo.toml Cargo.lock
git commit -m "release: v$VERSION"
git push -u origin "$BRANCH"
gh pr create --base master --head "$BRANCH" \
  --title "release: v$VERSION" \
  --body "Bump the workspace version for v$VERSION."

# 6. After that PR passes checks and is merged, update local master.
#    Rebuild so the tag is attached to the exact commit you tested
#    even if another PR merged in the meantime.
git switch master
git pull --ff-only origin master
test "$(sed -n -E 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/\1/p' Cargo.toml | head -n 1)" = "$VERSION"
cargo build --release -p bloom --all-features --locked
./target/release/bloom --version    # must print "bloom $VERSION"
git tag "v$VERSION"
git push origin "v$VERSION"
```

The tag push starts the workflow automatically. Because the tag already
points at the reviewed version-bumped commit, the build jobs use that exact
SHA and the publish job creates the `v$VERSION` release with the five
tarballs and `SHA256SUMS`. A manual `release.yml` run is available only to
retry an existing tag and never creates commits or tags.

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

To disable automatic daemon polling on a host while retaining explicit
checks, set `BLOOM_DISABLE_UPDATE_CHECK=1` in the service environment.

## What is intentionally NOT in the workflow

- **`cargo install cargo-edit`**: not needed. `sed` is faster and
  doesn't need a fresh toolchain.
- **`--config 'package.version="X.Y.Z"'`**: doesn't exist in Cargo.
  Verified against the Cargo configuration reference.
- **A floating `latest` git tag**: removed during legacy cleanup. The
  versioned URL is canonical, while GitHub's latest-release URL remains
  a stable convenience alias.
- **Cross-architecture builds**: each artifact is built on a runner with the
  matching CPU architecture. The release workflow selects explicit Rust
  targets, including musl on the native aarch64 runner, but does not emulate
  or cross-compile between CPU architectures.
- **Windows builds**: intentionally out of scope. Historical commit
  `cce4250 remove Windows release builds` removed them; the current
  CI has no Windows tests.
- **`bloom update install`**: not implemented. Atomicity, macOS
  SIP/Gatekeeper, and Windows self-overwrite are unsolved. Users
  download a new release manually.
