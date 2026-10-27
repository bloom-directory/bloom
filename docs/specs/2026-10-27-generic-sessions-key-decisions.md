# Reusable permission decisions — 2026-10-27

The owner replaced the earlier USD proposal with recurring token allowances. The [full specification](2026-10-26-generic-evm-svm-sessions.md) is authoritative for this candidate.

- Broker accounts in raw token units. Remove price providers, quotes, assumed pegs, nominal conversion and cross-token USD budgets.
- Default allowances are independent per Petal, exact account, network and token identity. Reviewed routes share usage.
- Trader uses rolling 24-hour limits; Degen uses rolling seven-day limits. Permissions persist until revoked; windows restore capacity without replacement grants.
- Institutional retains individual approval. Preserve existing venue settings separately from Broker presets.
- Reuse Sealed Approvals, versioned effects, reservation/recovery journals and revocation. Native gas and transfer amounts require explicit raw-unit limits.
- Local wallet locking remains enforced. An explicit passkey rearm resumes unchanged standing authority without resetting counters or accounting.
- Generic Petal/Machine economic declarations remain trusted. Preserve native transfer verification, mandatory Polymarket BUY witnesses and stronger existing approval profiles.
- Signer keeps custody and structural backstops; add no token economics there.
- The first automatic convenience scope remains Polymarket BUY. Other certified Petal/native scopes use explicit selections; unsupported actions retain owner review.
- Defer simulation, a verifier framework, on-chain token approvals and compatibility with old unshipped USD grants. Retain historical audit/recovery data and use fresh isolated dev state.
