# PM80 verification index

These records are candidate evidence, not release approval or proof of the
final service/package combination.

The complete historical handoffs, logs, original checksums and PR descriptions
are preserved at immutable Machine commit
[4c830f154dc7fdfadac94094e3016448150e4eee](https://github.com/bloom-directory/bloom/tree/4c830f154dc7fdfadac94094e3016448150e4eee/tests/evidence/pm80).
Every removed log/handoff was compared byte-for-byte with that published
snapshot before removal. Its original sha256.json remains available there.
The local manifest covers only the retained files. No wallet stores,
enrollment identities or credential files are included.

Current executable coverage lives with its owning source:

- Broker's ordinary clear-signing tests consume shared Weiroll vectors and
  check rendered runtime selectors. Its encoder CI runs the pinned Solidity
  implementation against those same vectors.
- Broker's released-policy-upgrade CI explicitly runs the plain and legacy
  external-store signing regression, then checks released-reader rollback.
- Machine's ordinary client/VFS tests check the shared legacy authority diff
  and stage it through policy.json without changing the signed baseline.
- Machine's compiled signing producer CI builds pinned Polymarket/Hyperliquid
  components, checks pending-batch preservation and status projection, and
  compares emitted witness/preimage/hash to Broker's fixture. This captures
  actual components; it does not prove installer-to-signing authorization.

The retained process and UI records identify historical binaries and fixture
limits. Reproduce the mixed-process check with scripts/test-mixed-release-processes.py
and the fixture preview with scripts/test-clear-signing-preview.mjs.
Neither proves production containment or physical-owner acceptance.
Package hashes in ../pm80-package-candidates.json are historical candidates,
not immutable release archives or final catalog authority.

The current workspace closure record is
shared/pm80-follow-up-implementation-2026-10-20.md. Settlement and artwork
expansion remain excluded. Independent reviews, specific merge approvals,
landed pins, immutable packages/catalog, final Linux/macOS conformance and an
authorized owner demonstration remain separate gates.
