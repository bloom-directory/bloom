# Policy Browser Editor

Editing full `policy.toml` inside the passkey signing ceremony is too fragile:
the page has to explain policy, edit TOML, validate it, refresh the review
hash, and complete WebAuthn before timeout.

Keep the review page focused on plain-language policy summary, review hash,
autonomy mode, and approve/reject. Full policy editing should be a separate
local flow opened from the review page.

## Editor Requirements

- Pause or restart signing after edits instead of racing WebAuthn timeout.
- Validate every save with the real `bloom_proto::Policy` parser.
- Show validation errors beside the relevant field or line.
- Save a draft, then return to a fresh review page with a new hash.
- Prefer schema-aware controls for common fields before raw TOML.
- Put search/navigation here, not in the ceremony. Browser search is only a
  navigation aid; server-side policy parsing remains the validity boundary.

Minimum fields: approval mode, DeFi enablement, chains, receivers, routers,
route verification, Polymarket enablement/caps, and native value cap.

## Tests

- Handler tests for valid and invalid edited policies.
- Browser tests for save success, save failure, hash refresh, and WebAuthn
  review gating after returning from edit.
- Regression test that stale tabs cannot approve an older hash after an edit.

Rollout: keep the review page's autonomy toggle as the only in-page edit until
the separate editor has validation and browser coverage.
