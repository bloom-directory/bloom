# Releasing bloom

How to cut a release. This document describes what the release machinery
**actually enforces** (the contract) and the **procedure** to follow. When the
two disagree, the contract wins — it is what runs in CI.

## TL;DR — the contract

A release is published when, and only when, a `vX.Y.Z` tag is pushed to the
repository. That tag push triggers the `Release` workflow
(`.github/workflows/release.yml:23`), which then runs `prepare`, `test`,
`build` (4 native binaries), and `publish`.

The `prepare` job enforces exactly two hard gates
(`.github/workflows/release.yml:80-92`):

1. The tagged commit is reachable from `master` (i.e. it is an ancestor of
   `origin/master`).
2. The workspace `version` in `Cargo.toml` at that commit equals the tag
   (`X.Y.Z`).

**Nothing else is checked by the publish workflow.** In particular, `release.yml`
does **not** verify that:

- the bump arrived via a pull request,
- the new version is greater than the previous one (monotonicity),
- the release notes are non-empty.

Branch protection on `master` is what forces the version-bump to land via a
merged pull request — that requirement comes from GitHub, not from the workflow.
Direct pushes to `master` are not permitted.

## Procedure (only path)

The version bump must land on `master` via a merged PR, then the merge commit is
tagged.

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

Prefer tagging an explicit `<merge-sha>` over `origin/master`. If you tag
`origin/master` and another commit lands between your `fetch` and your `git tag`,
you will tag the wrong commit and `prepare` will reject it (the `Cargo.toml`
version at that SHA will not match the tag).

## Alternative: the Propose Release workflow

`.github/workflows/propose-release.yml` automates step 1–2. Run it from the
Actions UI (workflow_dispatch) with the next version, and it opens the bump PR
for you. Two caveats:

- It requires the `RELEASE_PR_TOKEN` repository secret (a GitHub App or
  fine-grained PAT). PRs opened with the default `GITHUB_TOKEN` do not run CI on
  themselves, so a separate token is used; without it the workflow hard-fails
  (`.github/workflows/propose-release.yml:42-46`).
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
  a public `vX.Y.Z` tag already exists with no (or partial) release, and the tag
  must be deleted/moved. To de-risk, let CI pass on the bump PR before tagging.
- **`Cargo.toml` has two `version = "0.x.y"` lines.** Only the one under
  `[workspace.package]` is the release version (line 33). The other is a
  dependency pin and must not be changed.
- **Versioning scheme.** This project follows semver. While `0.x`, a bump in the
  second component (`0.1.0` → `0.2.0`) is a minor/breaking-ish release; a bump
  in the third (`0.1.0` → `0.1.1`) is a patch. The propose workflow enforces
  strict increase; the publish workflow does not enforce monotonicity at all.
