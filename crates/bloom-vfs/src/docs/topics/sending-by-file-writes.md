# Sending by file writes

The outbox is files under `wallets/<wallet>/<n>/chains/<chain>/outbox/`.

1. Stage once: write the body to `new.tx`, or to a Petal's `new` (its
   README). A Petal's entry is confirmed where its README says, and that
   confirm never waits for approval: retry it there once the owner approves.
2. The new entry is `pending/<id>/`, and `latest` links to the entry staged
   last. Check its `intent.json` and `plan.md` are yours before you confirm.
3. Write `y` to the entry's `confirm` file. If the human asked only to
   prepare it, stop and report the entry.
4. If confirm fails, see `confirm-denied-or-failed.md`.
5. The result is in `sent/<id>/` or `failed/<id>/`.
