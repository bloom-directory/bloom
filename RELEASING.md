# Releasing Bloom

The maintained contract is [the release process](docs/operations/release-process.md).
Use it together with the [triad package contract](packaging/triad/release/README.md)
and the workflow and release driver checked into the commit being released.

## Procedure

1. Prepare and review the version-bump PR. Update the workspace version in
   `Cargo.toml`, workspace package records in `Cargo.lock`, and the Machine
   version in `packaging/triad/release/compatibility-v1.toml`. The optional
   **Propose Release** workflow creates this PR; it never tags or publishes.
   Keep reviewed source and Petal pins unless a separate change validates them.
2. Require normal PR CI and acceptance evidence appropriate to the changes.
   Dispatch **Release** on the proposed branch with `dry_run=true` to build
   candidates for Linux x86_64, Linux aarch64, and macOS aarch64. Candidate
   signatures use ephemeral keys; production signing and publication are skipped.
3. Merge the reviewed release PR into the default branch. Record its exact merge
   SHA. Tag that SHA, rather than a moving branch ref, and push the tag:

   ```sh
   git fetch origin
   git tag vX.Y.Z <reviewed-merge-sha>
   git push origin vX.Y.Z
   ```

   Use the release-maintainer permissions allowed by the repository's tag
   rules. Do not disable tag protections or move/delete a published version tag.
4. Watch **Release**. It requires an existing `vX.Y.Z` tag whose commit is
   reachable from the default branch, matching workspace and matrix versions,
   and locked Broker/Signer source revisions. It rebuilds all three candidates
   from the tagged source; earlier dry-run artifacts are not promoted.
5. Approve the protected `production-release` environment when GitHub requests
   review. The isolated signing job uses `TRIAD_RELEASE_SIGNING_KEY`, checks it
   against the reviewed public key, replaces candidate signatures, and verifies
   the final archives before publishing.
6. Verify the published assets independently using
   `packaging/triad/release/bloom-release-v1.pub`. Expect three triad archives,
   each with `.sha256`, `.sig`, and `.pub` sidecars (12 assets). Verify both the
   outer archive checksum signature and the internal payload manifest. Include
   feature changes, upgrade caveats, and known issues in the public release
   notes; the workflow supplies only generic artifact/verification notes.
7. Coordinate website guide updates and verify the live setup script selects
   the new stable release and uses the reviewed key. It discovers the release
   tag dynamically; do not add a floating `latest` Git tag.

The previous v0.3.0 and v0.3.1 releases used lightweight version tags on their
reviewed merge commits. Artifact authentication uses SSHSIG, with namespaces
`bloom-release-archive-v1` and `bloom-release-payload-v1`; this does not imply
an independently signed Git tag or Apple code signing/notarization.

## Retrying a release

A manual dispatch with `dry_run=false` retries an **existing** tag. Select that
same tag as the workflow ref and provide it as the `tag` input. Retries execute
that tag's workflow and driver, recheck its SHA, reject changed/unexpected assets,
and upload only missing assets. Never replace an immutable tag to incorporate a
fix; prepare a new version instead.

The current retry path also marks the release latest and overwrites its body
with generic notes. Avoid inadvertently promoting an older release, and restore
curated release notes after a successful retry.
