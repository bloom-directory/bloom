# Sending by file writes

On a mount, or through `bloom vfs write`, the outbox is files under
`wallets/<wallet>/<n>/chains/<chain>/outbox/`.

1. Stage once: write the body to `new.tx`, or to a Petal's `new` (its
   README). A Petal's entry is confirmed where its README says, and that
   confirm never waits for approval: retry it there once the owner approves.
2. The new entry is in `pending/`. Identify it by its `intent.json` and
   `plan.md`, never by wildcard, sequence number, `latest` or position.
3. Write `confirm` to the entry's `confirm` file. If the human asked only to
   prepare it, stop and report the entry.
4. If confirm fails, see `confirm-denied-or-failed.md`.
5. The result is in `sent/<id>/` or `failed/<id>/`.

`bloom vfs write` to `new.tx` and to `confirm` prints what
`bloom wallet stage` and `bloom wallet confirm` print.
