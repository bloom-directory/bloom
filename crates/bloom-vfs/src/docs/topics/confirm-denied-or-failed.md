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
