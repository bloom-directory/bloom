# Confirm denied or failed

**Permission denied**: the owner must approve. Show the human the ceremony
link from the error, then confirm again in the same turn: through the CLI or
MCP it waits for their approval and sends. Repeat if it times out, until the
link expires. On a mount it does not wait: read `approval_challenge.json`,
check its wallet, action, intent and expiry, and follow its `next`. For
`expired`, `cancelled` or `refused`, tell the human.

**Input/output error**: read the entry's `policy_check.json` (in
`failed/<id>/` if it moved).

- `deny` is final. If the entry is still in `pending/`, write `cancel` to its
  `confirm` file, then report the refusal.
- `warn` keeps it pending. Show the human the warning and write `confirm` to
  `confirm.override` only if they accept it.
- Otherwise read `last_error.json`. `kind: policy_approval_required` means
  the owner must first allow that Petal through the ceremony link in `error`.

Do not restage while an approval is pending, or because a pending path
disappeared: list `sent/` and `failed/` first.

An entry a Petal staged is confirmed where that Petal's README says, and that
confirm never waits for approval: retry it there once the owner approves.
Identify an entry by its `intent.json` and `plan.md`, never by position.

When a Petal stages a canonical ERC-20 `transfer(address,uint256)` with no
native value, to a token Bloom lists, the plan names token, amount and
recipient, and the destination checked is that recipient, not the token
contract. It passes if the wallet's policy allows the recipient or the Petal
itself (`petal:<name>`). The check runs at staging: if the owner allows it
afterwards, the next stage returns the old entry and its confirm fails; stage
again after that. Such a call must be exactly 68 bytes with a zero-padded
address word, or staging refuses it.
