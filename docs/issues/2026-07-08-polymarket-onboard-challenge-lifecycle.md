# Polymarket onboarding challenge lifecycle

## Context

PR #76 projects `approval_challenge.json` through
`/polymarket/onboard/<wallet>/approval_challenge.json` after a sealed approval
challenge is staged.

That projection is useful for mounted VFS workflows: the user can discover and
read the exact challenge that needs a foreground ceremony.

## Open decision

Decide whether the challenge file should remain visible after `approval.json`
is written or after the corresponding grant is minted.

## Options

- Keep the file visible until another challenge replaces it. This preserves a
  simple audit/debug artifact, but stale challenges may confuse mounted users.
- Remove or hide the file once approval succeeds. This makes the VFS surface
  reflect only currently actionable work, but needs a clear cleanup point across
  daemon and foreground CLI paths.

## Recommendation

Prefer hiding or deleting stale challenges after grant minting, if the grant
store can be checked cheaply from the handler. Otherwise, document the file as
an audit artifact and add a test that it intentionally remains visible.
