# Cancel, replace and unknown signing

To discard an entry never sent for signing, write `cancel` to its `confirm`
file. On EVM the entry's own `cancel` file instead signs a same-nonce
replacement and needs its own approval.

If a signature may exist, even with no hash recorded, Bloom keeps the entry
and its `last_error.json` says how to reconcile it. Never delete a signing
record or reuse a nonce to force a fresh attempt. A `failed/` entry with
`signing_unknown.json` may still be signed (an older Bloom released it):
follow its `next` before staging that payment again.

**"signing outcome unknown; it may already be signed"**: retry the identical
request (same bytes, same operation id). Never rebuild it under a new id or
rebroadcast until the first attempt is known not to have landed.

On Solana, reconcile an ambiguous send by its signature. A `sent` entry with
`unresolved.md` and no receipt is not proof of failure: show the owner its
signature and restage only if they confirm it did not land.
