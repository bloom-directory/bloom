# PM80 candidate evidence, 2026-10-20

These are snapshots from isolated candidate verification, not release approvals.
The [verification record](pm80-clear-signing-verification-2026-10-20.md) contains
the finding matrix, tested revisions, commands, limits and unmet gates. Its
workspace source is `shared/pm80-clear-signing-verification-2026-10-20.md`.
The [settlement follow-up](pm80-settlement-follow-up-2026-10-20.md) preserves
the excluded tracker and its unresolved acceptance criteria.

`sha256.json` binds the captured artifacts. Successful test/build logs use
deterministic gzip compression. The pin and workspace-doctor logs intentionally
retain their blocked/baseline results; they are not green release checks.
No wallet stores, enrollment identities or credential files are included.

The parent [package candidate record](../pm80-package-candidates.json) contains
Machine-composed hashes and generated authority routes. These are prepared
candidate inputs, not published immutable release-catalog entries. Local
activation does not substitute for trusted GitHub package provenance.

## Actual process check

Build Machine with `cargo build --locked -p bloom --no-default-features --features
mount,triad-dev-harness`; build Broker/Signer with their `triad-dev-harness`
feature. Use the exact source revisions recorded in the verification record.
Set absolute binary paths in `BLOOM_PM80_MACHINE_BIN`, `BLOOM_PM80_BROKER_BIN`,
`BLOOM_PM80_RELEASED_MACHINE_BIN`, `BLOOM_PM80_RELEASED_BROKER_BIN` and
`BLOOM_PM80_SIGNER_BIN`, then run:

```sh
python3 scripts/test-mixed-release-processes.py
```

This starts a compatible pair and both released/candidate combinations with
fresh disposable enrollment, separate ports/state and the unchanged Signer.
Both mixed pairs must explicitly refuse `broker.readiness` with
`UNSUPPORTED_VERSION`, before any policies, grants, approvals, operations or
ceremonies exist. It retains directories instead of recursively deleting them
and stops only its recorded service handles. Source/feature and production
containment limits are recorded alongside binary hashes in
`mixed-process-results.json` and `logs/*dev-build.log.gz`.

## Browser preview

The generated `ui/enso-shortcut.json` comes from Broker's reader tests. Regenerate
with `BLOOM_UI_FIXTURE_DIR` set when running `cargo test --locked -p
bloom-evm-clear-signing` in the Broker checkout. With playwright-core available
and Chromium installed, run Machine's helper:

```sh
BLOOM_BROKER_ROOT=/absolute/broker \
BLOOM_UI_FIXTURE_DIR=/absolute/generated-fixtures \
node scripts/test-clear-signing-preview.mjs
```

Optional `PLAYWRIGHT_MODULE` selects an already installed module;
`CHROMIUM_BIN` selects the executable. It renders the real Broker assets with
fixture transport at 390px and 1280px, checks primary summaries and expanded
overflow, and records screenshots/results. It does not connect to a live
ceremony, approve an operation or represent physical-owner acceptance.

## Ownership transfer and CI follow-up

`ci-after-takeover.json` records the first checks after all five existing PR
writer claims were transferred and their candidates published. Broker,
Signer and all three Petals passed. Machine's packaging tests still expected
Broker state floor 2, and their tamper replacement did not alter the new
floor-3 record. `logs/ci-packaging-failure.log.gz` preserves that failure.
The correction checks the component-specific state floors and ensures a
floor-3-to-2 tamper actually changes the record before testing rejection.
The standalone compatibility test passes locally. The corrected PR head
needs its own CI; this historical snapshot is not acceptance of a later head.
