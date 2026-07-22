# Releasing bloom

How to cut a release. This document describes what the release machinery
**actually enforces** (the contract) and the **procedure** to follow. When the
two disagree, the contract wins — it is what runs in CI.

## TL;DR — the contract

A `vX.Y.Z` tag push starts the initial `Release` workflow run. An existing tag
can also be retried with the workflow's manual `workflow_dispatch` trigger by
entering the tag name in the Actions UI (`.github/workflows/release.yml:23-32`).
Both triggers run the complete `prepare`, `test`, `build` (4 native binaries),
and `publish` pipeline.

The `prepare` job enforces these hard gates
(`.github/workflows/release.yml:65-92`):

1. The tag name strictly matches `vX.Y.Z`, with numeric SemVer components.
2. The tag already exists in the repository and resolves to a commit. Manual
   dispatch does not create a missing tag.
3. The tagged commit is reachable from `master` (i.e. it is an ancestor of
   `origin/master`).
4. The workspace `version` in `Cargo.toml` at that commit equals the tag
   (`X.Y.Z`).

**No other release-eligibility policy is checked by the workflow.** In
particular, `release.yml` does **not** verify that:

- the bump arrived via a pull request,
- the new version is greater than the previous one (monotonicity),
- the release notes are non-empty.

Branch protection on `master` is what forces the version-bump to land via a
merged pull request — that requirement comes from GitHub, not from the workflow.
Direct pushes to `master` are not permitted.

## Procedure (only path)

The version bump must land on `master` via a merged PR, then the merge commit is
tagged.

The repository's `v*` tag rules must allow new tag creation while preventing
updates, deletion, and non-fast-forward changes. This permits each release tag
to be created once and keeps it immutable afterward. If **Restrict creations**
is enabled for `v*`, a repository administrator must disable it before the tag
can be pushed.

```sh
# 1. Branch off latest master and bump the workspace version.
git checkout master && git pull
git checkout -b release/v0.1.1          # use the version you are cutting
$EDITOR Cargo.toml                       # edit the single line under [workspace.package]
cargo check --workspace                  # refresh Cargo.lock so it matches
git add Cargo.toml Cargo.lock
git commit -m "release: v0.1.1"

# 2. Open the PR (branch protection requires a PR to land on master).
git push -u origin release/v0.1.1
gh pr create --title "release: v0.1.1" --body "Version bump for release."

# 3. Get the PR reviewed and merged.

# 4. After merge, tag the merge commit and push the tag.
git fetch origin
git tag v0.1.1 <merge-sha>               # pin the exact SHA, do not tag a moving ref
git push origin v0.1.1                   # this triggers the Release workflow
```

Prefer tagging an explicit `<merge-sha>` over `origin/master`. The
remote-tracking ref does not move between `git fetch` and `git tag`, but a fetch
can advance it past the release PR if other changes have already landed. Pinning
the reviewed merge SHA avoids accidentally tagging a later commit. (`prepare`
may not catch that mistake if the later commit retains the same workspace
version.)

## Alternative: the Propose Release workflow

`.github/workflows/propose-release.yml` automates step 1–2. Run it from the
Actions UI (workflow_dispatch) with the next version, and it opens the bump PR
for you. Two caveats:

- It requires the `RELEASE_PR_TOKEN` repository secret containing a
  fine-grained PAT with **Contents: read/write** and **Pull requests:
  read/write** access to this repository. PRs opened with the default
  `GITHUB_TOKEN` receive approval-required CI runs; the separate token lets CI
  run normally. Without it the workflow hard-fails
  (`.github/workflows/propose-release.yml:43-47`). A GitHub App requires a
  workflow change to mint a short-lived installation token rather than storing
  an installation token directly as this secret.
- Unlike the publish workflow, the **propose** workflow does enforce two extra
  rules:
  - the proposed version must be strictly greater than the current one
    (`.github/workflows/propose-release.yml:84-87`), and
  - the PR may change only `Cargo.toml` and `Cargo.lock`
    (`.github/workflows/propose-release.yml:118-123`).

Because these rules live only in the propose workflow, anyone who bypasses it
(e.g. by opening the bump PR by hand) can ship a version that is not monotonic.
The publish workflow will not catch it.

## Watching the release

- Actions → **Release**, or `gh run watch`.
- `prepare` prints the resolved tag, version, SHA, and workspace version.
- `build` asserts `bloom --version` matches the tag before staging artifacts
  (`.github/workflows/release.yml:169-179`).
- `publish` generates `SHA256SUMS` and marks the release `latest` only if its
  version is `>=` the current latest (`.github/workflows/release.yml:283-291`).
  The floating `latest` git tag in this repo is legacy and is **not** managed by
  the workflow.

## Gotchas

- **Tests run only after the tag is public.** The `test` job
  (`.github/workflows/release.yml:105`) runs on the tagged commit. If it fails,
  a public `vX.Y.Z` tag already exists with no (or partial) release. For a
  transient failure, rerun the failed Actions jobs or manually dispatch the
  `Release` workflow for the same tag. Do not delete or move a public release
  tag. If the failure requires a code change, merge the fix and cut a new
  version. To de-risk, let CI pass on the bump PR before tagging.
- **The release version has one source of truth.** Edit only the `version` under
  `[workspace.package]` in `Cargo.toml` (line 33). Dependency version
  constraints elsewhere in the file are unrelated to the bloom release
  version.
- **Versioning scheme.** This project follows semver. While `0.x`, a bump in the
  second component (`0.1.0` → `0.2.0`) is a minor/breaking-ish release; a bump
  in the third (`0.1.0` → `0.1.1`) is a patch. The propose workflow enforces
  strict increase; the publish workflow does not enforce monotonicity at all.
