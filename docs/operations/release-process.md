# Release process

## Current release contract

Bloom v0.2 releases contain signed triad bundles for **Linux x86_64** and
**macOS aarch64**. Each archive includes Machine (`bloom`), Broker, Signer,
`bloom-signer-migrate`, public configuration templates, and installers. The
published assets are:

- `bloom-triad-linux-x86_64.tar.gz` plus `.sha256`, `.sig`, and `.pub` sidecars;
- `bloom-triad-macos-aarch64.tar.gz` plus `.sha256`, `.sig`, and `.pub` sidecars.

Both platforms use the reviewed key at
[`packaging/triad/release/bloom-release-v1.pub`](../../packaging/triad/release/bloom-release-v1.pub).
The archive checksum signature uses the `bloom-release-archive-v1` SSHSIG
namespace; the internal manifest uses `bloom-release-payload-v1`. Obtain the
trusted key independently of the downloaded archive. A bundled `.pub` file
alone does not establish trust. The installers authenticate a private
root-owned snapshot against a separately provisioned, root-owned,
non-writable pin before changing services or installation state.

Production macOS uses the `macos-unix-principals` claim. Tart conformance is
optional manual validation: `MACOS_CONFORMANCE_REPORT.json`, `.sig`, and
`.pub` are not required release assets, signing inputs, or install prerequisites.
The guarded `macos-unix-principals-w0` claim remains for disposable testing.
See the [package contract](../../packaging/triad/release/README.md) for
verification, enrollment, upgrade, and custody-retention behavior.

## Prepare a reviewed version bump

Releases start from a version-bump PR followed by a `vX.Y.Z` tag on the reviewed
commit. The optional `propose-release.yml` workflow creates that PR; it never
writes to the default branch, tags a release, or publishes assets. Configure
`RELEASE_PR_TOKEN` as a fine-grained token with Contents and Pull requests
read/write permissions so the generated PR receives normal pull-request CI.
A GitHub App integration would instead need to mint its installation token in
the workflow.

Run **Actions → Propose Release → Run workflow** with the next version without
`v`. Review changes to `Cargo.toml`, workspace metadata in `Cargo.lock`, and
the Machine version in `packaging/triad/release/compatibility-v1.toml`. The
workflow refuses to upgrade unrelated external dependencies. The compatibility
matrix also pins the reviewed Broker and Signer source commits; changes to
those pins require review independently of the version bump.

After merging the PR, tag the reviewed commit and push that tag. The release
workflow requires the commit to be reachable from the default branch and both
the workspace and compatibility-matrix Machine version to equal the tag.
Repository rules should restrict creation and updates of `v*` tags to release
maintainers.

## Build and validate candidates

The local and CI entry point is:

```sh
packaging/triad/release.sh build linux --output-dir /tmp/bloom-linux-candidate
# On a separate Darwin arm64 host:
packaging/triad/release.sh build macos --output-dir /tmp/bloom-macos-candidate
```

Linux builds require a Linux x86_64 host; macOS builds require Darwin arm64.
By default the command uses `../bloom-broker` and `../bloom-signer`; explicit
`--broker-root` and `--signer-root` options select other checkouts. All three
source trees must be clean, including untracked files, and the authority
checkouts must match the committed compatibility pins. Builds use locked
Cargo dependencies and reject forbidden production Machine features.

The build validates versions, architecture, packaging and installer checks,
then assembles and verifies the bundle twice to prove deterministic output.
It emits `bloom-triad-test-unclaimed.tar.gz` and its three sidecars signed by
an ephemeral candidate key. Source-wide formatting, Clippy, and test suites
remain separate CI gates; a candidate build is not a full acceptance run.
Never replace this entry point with a single-binary `--all-features` build.

Before merging changes to the release workflow, dispatch the branch with
`dry_run=true`. That runs both candidate builds and uploads Actions artifacts,
while skipping production signing and GitHub publication. It does not create
commits or tags. Installing a candidate additionally requires a trusted
root-owned pin of its ephemeral key and the explicit
`BLOOM_ALLOW_TEST_UNCLAIMED=true` installer opt-in.

## Sign and publish

A `vX.Y.Z` tag push runs `release.yml`. A manual dispatch with `dry_run=false`
retries an existing tag; select that tag as the workflow ref as well. The run
must originate from the tagged commit and builds its exact source SHA, using
Linux x86_64 and `macos-15` arm64 runners.

After both candidate builds succeed, the protected `production-release`
environment supplies the release key only to the signing step. The isolated
`release.sh sign linux|macos` pass verifies candidate version, source revisions,
and target architecture without executing candidate-owned code. It replaces
the ephemeral inner signature, repacks deterministically, and signs the outer
checksum with a private key matching the reviewed public key. Both final
archives are verified against that pin before publication.

The publish job rechecks that the tag still names the built SHA, then publishes
both platforms together as a normal GitHub Release. A retry compares existing
assets byte for byte, rejects unexpected or changed assets, and uploads only
missing assets. The current retry path marks the release latest; maintainers
should account for that when retrying an older tag. GitHub's
`/releases/latest/download/...` routes follow the release marked latest and do
not need a floating `latest` Git tag.

Linux aarch64/musl and macOS x86_64 single-binary archives from the older
pipeline are not outputs of the current triad workflow. Windows builds are
also outside this workflow.
