## Summary

<!-- What does this PR do and why? -->

## Checklist

Every item must be checked before merge (enforced by the `checklist-complete`
status check). If an item does not apply, check it and write `N/A` in place
of the link or after the item.

- [ ] Tests added or updated for behavior changes
- [ ] Architecture docs (`docs/architecture/`) updated if contracts or
      behavior changed
- [ ] Sealed Approval invariants respected (no signing outside a grant or
      bounded capability, no PRF/grant persistence, execution from sealed
      bytes) — see `docs/architecture/Sealed Approvals.md`
- [ ] Agent Documentation updated (`crates/bloom-vfs/src/docs/agent-guidance.md`
      and affected Petal READMEs) — see
      `docs/architecture/Agent-native Documentation.md`