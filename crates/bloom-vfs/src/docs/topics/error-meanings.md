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

A refused Petal write leaves its reason in `petals/<name>/last_error.json`.
Check its `path` and `at_ms` match your write; no record means no
information, not success. A Petal write denied with no ceremony link: report
the route and error rather than reinstalling, switching accounts or dropping
fields.
