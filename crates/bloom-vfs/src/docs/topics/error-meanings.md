# What an error means

An error alone does not show whether an earlier operation completed.

- **No such file or directory**: the path is absent now. An entry that left
  `pending/` moved to `sent/` or `failed/`.
- **Permission denied**: on a confirm, see `confirm-denied-or-failed.md`.
  Read-only targets also deny.
- **Operation not permitted**: policy or a safety check refused it. Do not
  change policy, switch accounts, remount a read-only route or try another
  interface to get around it.
- **Input/output error**: on an outbox confirm, see
  `confirm-denied-or-failed.md`.

A Petal route that refuses says why in the error itself, as
`permission denied: <name> Petal: <reason>`. That is the Petal's refusal, not
a ceremony: it never carries a link, and the reason is what to act on
(which approval is missing, which policy forbids it, what the venue
rejected). A write's reason is also kept in `petals/<name>/last_error.json`;
check its `path` and `at_ms` match your write; no record means no
information, not success. A Petal write denied with no ceremony link: report
the route and error rather than reinstalling, switching accounts or dropping
fields.

A Petal operation that needs a policy change answers
`POLICY_APPROVAL_REQUIRED` with a `ceremony_url` and status path. If that
ceremony expires unapproved, retry the operation: Broker retires the expired
ceremony and Machine answers with a new `ceremony_url`. Never give the owner an
expired URL. If the answer says another policy change is waiting, its link is
for that change, which does not allow the operation: Broker opens one ceremony
per wallet at a time, so tell the owner to approve or refuse it, then retry.
`DEFAULT_POLICY_WAITING` means a Petal the owner chose during setup is still
installing, and the wallet's first policy allows every chosen Petal at once:
retry once `docs/petals.md` lists it. If it stays missing, tell the owner to
restart Bloom, or to leave it out of setup.
